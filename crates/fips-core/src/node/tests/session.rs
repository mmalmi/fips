//! End-to-end session establishment tests.

use super::*;
use crate::config::RoutingMode;
use crate::node::session::EndToEndState;
use crate::node::session_wire::FSP_COMMON_PREFIX_SIZE;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, generate_random_edges, lock_large_network_test,
    process_available_packets, run_tree_test, run_tree_test_with_mtus, verify_tree_convergence,
};
use crate::protocol::{SessionAck, SessionDatagram, SessionReceiverReport, SessionSetup};
use crate::tree::{ParentDeclaration, TreeCoordinate};

mod direct_endpoint;
mod discovery_tun;
mod entry_basics;
mod forwarded_edge;
mod graph_fallback;
mod handshake_timeout;
mod mtu_exceeded;
mod mtu_notification;
mod multihop_pmtud;
mod purge_idle;
mod resend_rekey_large;
mod route_metrics;
mod tun_outbound_core;
mod tun_outbound_tail;

// ============================================================================
// Unit tests: SessionEntry data structure
// ============================================================================

/// Drain packets until quiescent (2 consecutive idle rounds).
async fn drain_to_quiescence(nodes: &mut [TestNode]) {
    let mut idle_rounds = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets(nodes).await;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 2 {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }
}

async fn wait_for_session_established(
    nodes: &mut [TestNode],
    index: usize,
    peer: &NodeAddr,
    timeout: Duration,
    context: &str,
) {
    tokio::time::timeout(timeout, async {
        loop {
            if nodes[index]
                .node
                .get_session(peer)
                .is_some_and(|entry| entry.is_established())
            {
                return;
            }

            process_available_packets(nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{context}: session did not establish"));
}

fn run_large_stack_async_test<F, Fut>(name: &'static str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("large-stack test runtime")
                .block_on(test());
        })
        .expect("spawn large-stack test");

    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
}

async fn recv_endpoint_event_while_draining(
    nodes: &mut [TestNode],
    rx: &mut EndpointEventReceiver,
    timeout: Duration,
    context: &str,
) -> NodeEndpointEvent {
    tokio::time::timeout(timeout, async {
        loop {
            tokio::select! {
                event = rx.recv() => {
                    return event.unwrap_or_else(|| panic!("{context}: endpoint event channel closed"));
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    process_available_packets(nodes).await;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{context}: endpoint data should not time out"))
}

fn expect_single_endpoint_data_event(
    event: NodeEndpointEvent,
) -> crate::node::EndpointDataDelivery {
    match event {
        NodeEndpointEvent { mut messages, .. } if messages.len() == 1 => {
            messages.pop().expect("one endpoint data message")
        }
        NodeEndpointEvent { messages, .. } => {
            panic!("expected one endpoint data message, got {}", messages.len())
        }
    }
}

async fn send_endpoint_data_via_dataplane(
    node: &mut Node,
    remote: PeerIdentity,
    payload: Vec<u8>,
) -> Result<(), NodeError> {
    let dest_addr = *remote.node_addr();
    node.handle_endpoint_data_batch_no_established_flush(
        crate::node::NodeEndpointDataBatch::from_payloads(
            remote,
            vec![
                crate::node::EndpointDataPayload::from_packet_payload(payload)
                    .expect("test endpoint payload"),
            ],
            None,
        )
        .expect("one-packet endpoint data batch"),
    )
    .await;
    if node
        .get_session(&dest_addr)
        .is_some_and(|entry| entry.is_established())
        && node.find_next_hop(&dest_addr).is_some()
    {
        node.flush_pending_packets(&dest_addr).await;
    }
    Ok(())
}

fn enqueue_tun_packet_via_dataplane(nodes: &mut [TestNode], index: usize, packet: Vec<u8>) {
    nodes[index]
        .tun_outbound_tx
        .try_send(packet)
        .expect("enqueue TUN outbound packet");
}

async fn send_tun_packet_via_dataplane(nodes: &mut [TestNode], index: usize, packet: Vec<u8>) {
    enqueue_tun_packet_via_dataplane(nodes, index, packet);
    process_available_packets(nodes).await;
}

async fn recv_tun_packet_while_draining(
    nodes: &mut [TestNode],
    rx: &crate::upper::tun::TunRx,
    timeout: Duration,
    context: &str,
) -> Vec<u8> {
    tokio::time::timeout(timeout, async {
        loop {
            match rx.try_recv_packet() {
                Ok(packet) => return packet.as_slice().to_vec(),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    panic!("{context}: TUN receiver disconnected");
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }

            process_available_packets(nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{context}: TUN packet should not time out"))
}

async fn process_available_packets_for_node(node: &mut TestNode) -> usize {
    process_available_packets(std::slice::from_mut(node)).await
}

async fn wait_process_packets_for_node(nodes: &mut [TestNode], index: usize) -> usize {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets_for_node(&mut nodes[index]).await;
        if count > 0 {
            return count;
        }
    }
    0
}

fn drop_queued_packets_for_node(node: &mut TestNode) -> usize {
    let mut dropped = 0;
    while node.packet_rx.try_recv().is_ok() {
        dropped += 1;
    }
    dropped
}

async fn wait_drop_queued_packets_for_node(node: &mut TestNode) -> usize {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let dropped = drop_queued_packets_for_node(node);
        if dropped > 0 {
            return dropped;
        }
    }
    0
}

/// Build a minimal valid IPv6 packet with given source and destination addresses.
fn build_ipv6_packet(
    src: &crate::FipsAddress,
    dst: &crate::FipsAddress,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut packet = vec![0u8; 40 + payload.len()];
    // Version (6) + traffic class high nibble
    packet[0] = 0x60;
    // Payload length (u16 BE)
    packet[4] = (payload_len >> 8) as u8;
    packet[5] = (payload_len & 0xff) as u8;
    // Next header: 59 = No Next Header
    packet[6] = 59;
    // Hop limit
    packet[7] = 64;
    // Source address (bytes 8-23)
    packet[8..24].copy_from_slice(src.as_bytes());
    // Destination address (bytes 24-39)
    packet[24..40].copy_from_slice(dst.as_bytes());
    // Payload
    packet[40..].copy_from_slice(payload);
    packet
}

fn make_reply_learned_node_with_tree_peer() -> Node {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *peer_identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();

    let our_addr = *node.node_addr();
    let peer_coords = TreeCoordinate::from_addrs(vec![peer_addr, our_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, our_addr, 1, 2000),
        peer_coords,
    );
    assert!(
        node.is_tree_peer(&peer_addr),
        "fixture peer must be a tree peer"
    );
    node
}

fn insert_initiating_session(node: &mut Node, dest: &Identity) {
    insert_initiating_session_for(node, *dest.node_addr(), dest.pubkey_full());
}

fn insert_established_session(node: &mut Node, dest: &Identity) {
    let session = make_noise_session(node.identity(), dest);
    let entry = crate::node::session::SessionEntry::new(
        *dest.node_addr(),
        dest.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    node.sessions.insert(*dest.node_addr(), entry);
}

fn insert_initiating_session_for(
    node: &mut Node,
    dest_addr: NodeAddr,
    dest_pubkey: secp256k1::PublicKey,
) {
    let handshake =
        crate::noise::HandshakeState::new_initiator(node.identity().keypair(), dest_pubkey);
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        dest_pubkey,
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );
    node.sessions.insert(dest_addr, entry);
}

fn add_direct_peer_for_identity(node: &mut Node, identity: &Identity) {
    let peer_identity = crate::PeerIdentity::from_pubkey_full(identity.pubkey_full());
    node.peers.insert(
        *identity.node_addr(),
        crate::peer::ActivePeer::new(peer_identity, LinkId::new(99), 2000),
    );
}

fn has_outbound_handshake_to(node: &Node, dest_addr: &NodeAddr) -> bool {
    node.peers.connection_values().any(|conn| {
        conn.is_outbound()
            && conn
                .expected_identity()
                .map(|identity| identity.node_addr() == dest_addr)
                .unwrap_or(false)
    })
}

/// Helper: complete a Noise IK handshake and return the initiator's NoiseSession.
fn make_noise_session(
    our_identity: &Identity,
    remote_identity: &Identity,
) -> crate::noise::NoiseSession {
    use crate::noise::HandshakeState;

    let mut initiator =
        HandshakeState::new_initiator(our_identity.keypair(), remote_identity.pubkey_full());
    let mut responder = HandshakeState::new_responder(remote_identity.keypair());

    // Set epochs for both sides (required for handshake message encryption)
    let mut init_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut init_epoch);
    initiator.set_local_epoch(init_epoch);
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    responder.set_local_epoch(resp_epoch);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    initiator.into_session().unwrap()
}

/// Build an MtuExceeded inner payload (35 bytes: flags + dest + reporter + mtu LE).
///
/// `handle_mtu_exceeded` receives the payload after the dispatcher strips
/// the FSP prefix and msg_type byte, so the test wire is just the body.
fn build_mtu_exceeded_inner(dest: &NodeAddr, reporter: &NodeAddr, mtu: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(35);
    buf.push(0x00); // flags (reserved)
    buf.extend_from_slice(dest.as_bytes());
    buf.extend_from_slice(reporter.as_bytes());
    buf.extend_from_slice(&mtu.to_le_bytes());
    buf
}

/// Build a PathMtuNotification body (2 bytes: path_mtu LE).
fn build_path_mtu_notification_body(mtu: u16) -> Vec<u8> {
    mtu.to_le_bytes().to_vec()
}

/// Insert an Established session and matching dataplane FSP owner.
fn install_established_session_with_mmp(node: &mut Node, remote: &Identity) {
    let session = make_noise_session(node.identity(), remote);
    let remote_addr = *remote.node_addr();
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.mark_established(1000);
    node.sessions.insert(remote_addr, entry);
    ensure_dataplane_fsp_owner_for_test(node, remote_addr);
}

fn session_timestamp_echo_for(rtt_ms: u32) -> u32 {
    let now_ms = Node::now_ms();
    (now_ms.wrapping_sub(1_000) as u32).saturating_sub(rtt_ms)
}
