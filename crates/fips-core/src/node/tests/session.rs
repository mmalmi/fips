//! End-to-end session establishment tests.

use super::*;
use crate::config::RoutingMode;
use crate::node::session::EndToEndState;
use crate::node::session_wire::FSP_COMMON_PREFIX_SIZE;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, lock_large_network_test, process_available_packets, run_tree_test,
    run_tree_test_with_mtus, verify_tree_convergence,
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
mod remote_restart;
mod resend_rekey_large;
mod retransmit_harness;
mod route_metrics;
#[cfg(feature = "sim-transport")]
mod sim_harness;
mod tun_outbound_core;
mod tun_outbound_tail;
#[cfg(feature = "webrtc-transport")]
mod webrtc_upgrade;

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

fn session_wait_snapshot(nodes: &[TestNode], index: usize, peer: &NodeAddr) -> String {
    let source = *nodes[index].node.node_addr();
    let describe = |entry: &crate::node::SessionEntry| {
        format!(
            "established={},initiating={},awaiting_msg3={},resends={},handshake_payload={},rekey={}",
            entry.is_established(),
            entry.is_initiating(),
            entry.is_awaiting_msg3(),
            entry.resend_count(),
            entry.handshake_payload().is_some(),
            entry.has_rekey_in_progress(),
        )
    };
    let session = nodes[index].node.get_session(peer).map(describe);
    let reciprocal = nodes
        .iter()
        .find(|node| node.node.node_addr() == peer)
        .and_then(|node| node.node.get_session(&source))
        .map(describe);
    let pending = nodes[index]
        .node
        .pending_session_traffic
        .has_traffic_for(peer);
    let deferred = nodes
        .iter()
        .enumerate()
        .filter_map(|(node_index, node)| {
            let count = node.node.deferred_dataplane_control_turns.len();
            (count > 0).then_some((node_index, count))
        })
        .take(16)
        .collect::<Vec<_>>();
    let queued_packets = nodes
        .iter()
        .enumerate()
        .filter_map(|(node_index, node)| {
            let count = node.packet_rx.queued_packets_for_test();
            (count > 0).then_some((node_index, count))
        })
        .take(16)
        .collect::<Vec<_>>();
    format!(
        "source={source}, peer={peer}, session={session:?}, reciprocal={reciprocal:?}, pending={pending}, deferred_control={deferred:?}, queued_packets={queued_packets:?}"
    )
}

async fn wait_for_session_established(
    nodes: &mut [TestNode],
    index: usize,
    peer: &NodeAddr,
    timeout: Duration,
    context: &str,
) {
    let checkpoint_at = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut checkpoint = None;
    let result = tokio::time::timeout(timeout, async {
        loop {
            if nodes[index]
                .node
                .get_session(peer)
                .is_some_and(|entry| entry.is_established())
            {
                return;
            }
            if checkpoint.is_none() && tokio::time::Instant::now() >= checkpoint_at {
                checkpoint = Some(session_wait_snapshot(nodes, index, peer));
            }

            process_available_packets(nodes).await;
            if nodes[index]
                .node
                .get_session(peer)
                .is_some_and(|entry| entry.is_established())
            {
                return;
            }

            run_session_retransmit_work(nodes).await;
            process_available_packets(nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if result.is_err() {
        let final_snapshot = session_wait_snapshot(nodes, index, peer);
        let route = nodes[index]
            .node
            .find_next_hop(peer)
            .map(|next_hop| *next_hop.node_addr());
        panic!(
            "{context}: session did not establish: checkpoint={checkpoint:?}, final={final_snapshot}, route={route:?}",
        );
    }
}

async fn wait_for_session_rekey_complete(
    nodes: &mut [TestNode],
    index: usize,
    peer: &NodeAddr,
    timeout: Duration,
    context: &str,
) {
    tokio::time::timeout(timeout, async {
        loop {
            if nodes[index].node.get_session(peer).is_some_and(|entry| {
                entry.is_established()
                    && !entry.has_rekey_in_progress()
                    && entry.pending_new_session().is_none()
            }) {
                return;
            }

            run_session_retransmit_work(nodes).await;
            process_available_packets(nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{context}: session rekey did not complete"));
}

fn settle_session_handshake_retransmits(
    nodes: &mut [TestNode],
    left_index: usize,
    left_peer: &NodeAddr,
    right_index: usize,
    right_peer: &NodeAddr,
) {
    nodes[left_index]
        .node
        .sessions
        .get_mut(left_peer)
        .expect("left session should exist")
        .clear_handshake_payload();
    nodes[right_index]
        .node
        .sessions
        .get_mut(right_peer)
        .expect("right session should exist")
        .clear_handshake_payload();
}

async fn wait_for_session_state_for_node<F>(
    nodes: &mut [TestNode],
    index: usize,
    peer: &NodeAddr,
    context: &str,
    predicate: F,
) where
    F: Fn(&crate::node::session::SessionEntry) -> bool,
{
    let mut processed_turns = 0usize;
    for _ in 0..20 {
        if nodes[index].node.get_session(peer).is_some_and(&predicate) {
            return;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
        processed_turns = processed_turns
            .saturating_add(process_available_packets_for_node(&mut nodes[index]).await);
    }

    let session = nodes[index].node.get_session(peer);
    panic!(
        "{context}: session state did not arrive (processed turns: {processed_turns}, established: {}, initiator: {}, handshake payload: {}, rekey enabled: {}, rekey: {}, pending: {})",
        session.is_some_and(|entry| entry.is_established()),
        session.is_some_and(|entry| entry.is_initiator()),
        session.is_some_and(|entry| entry.handshake_payload().is_some()),
        nodes[index].node.config.node.rekey.enabled,
        session.is_some_and(|entry| entry.has_rekey_in_progress()),
        session.is_some_and(|entry| entry.pending_new_session().is_some()),
    );
}

pub(super) fn run_large_stack_async_test<F, Fut>(name: &'static str, test: F)
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

async fn run_session_retransmit_work(nodes: &mut [TestNode]) {
    // Synthetic nodes have no independent RX loops, so mirror the session
    // maintenance each live node would run on its own fast timer.
    let now_ms = Node::now_ms();
    for node in nodes {
        node.node.resend_pending_session_handshakes(now_ms).await;
        node.node.resend_pending_session_msg3(now_ms).await;
        node.node.check_pending_lookups(now_ms).await;
    }
}

pub(super) async fn recv_endpoint_event_while_draining(
    nodes: &mut [TestNode],
    rx: &mut EndpointEventReceiver,
    timeout: Duration,
    context: &str,
) -> NodeEndpointEvent {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match rx.try_recv() {
            Ok(event) => return event,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                panic!("{context}: endpoint event channel closed");
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
        }

        if tokio::time::Instant::now() >= deadline {
            let snapshots = nodes
                .iter()
                .enumerate()
                .map(|(index, node)| {
                    let sessions = node
                        .node
                        .sessions
                        .iter()
                        .map(|(peer, entry)| {
                            format!(
                                "{peer}:established={},initiating={},awaiting_msg3={},resends={},handshake_payload={}",
                                entry.is_established(),
                                entry.is_initiating(),
                                entry.is_awaiting_msg3(),
                                entry.resend_count(),
                                entry.handshake_payload().is_some(),
                            )
                        })
                        .collect::<Vec<_>>();
                    let pending = node
                        .node
                        .pending_session_traffic
                        .destinations()
                        .map(|peer| peer.to_string())
                        .collect::<Vec<_>>();
                    format!(
                        "node={index}, sessions={sessions:?}, pending={pending:?}, deferred_control={}",
                        node.node.deferred_dataplane_control_turns.len(),
                    )
                })
                .collect::<Vec<_>>();
            panic!("{context}: endpoint data should not time out: {snapshots:#?}");
        }
        run_session_retransmit_work(nodes).await;
        process_available_packets(nodes).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn recv_service_event_while_draining(
    nodes: &mut [TestNode],
    rx: &mut EndpointServiceEventReceiver,
    timeout: Duration,
    context: &str,
) -> NodeEndpointServiceEvent {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match rx.try_recv() {
            Ok(event) => return event,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                panic!("{context}: service event channel closed");
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
        }

        assert!(
            tokio::time::Instant::now() < deadline,
            "{context}: service datagram should not time out"
        );
        run_session_retransmit_work(nodes).await;
        process_available_packets(nodes).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub(super) fn expect_single_endpoint_data_event(
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

pub(super) async fn send_endpoint_data_via_dataplane(
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

async fn send_service_datagram_via_dataplane(
    node: &mut Node,
    remote: PeerIdentity,
    source_port: u16,
    destination_port: u16,
    payload: Vec<u8>,
) {
    let dest_addr = *remote.node_addr();
    node.handle_endpoint_data_batch_no_established_flush(
        crate::node::NodeEndpointDataBatch::from_payloads(
            remote,
            vec![
                crate::node::EndpointDataPayload::from_service_datagram(
                    source_port,
                    destination_port,
                    payload,
                )
                .expect("test service datagram payload"),
            ],
            None,
        )
        .expect("one-packet service datagram batch"),
    )
    .await;
    if node
        .get_session(&dest_addr)
        .is_some_and(|entry| entry.is_established())
        && node.find_next_hop(&dest_addr).is_some()
    {
        node.flush_pending_packets(&dest_addr).await;
    }
}

fn enqueue_tun_packet_via_dataplane(nodes: &mut [TestNode], index: usize, packet: Vec<u8>) {
    nodes[index]
        .tun_outbound_tx
        .try_send(packet)
        .expect("enqueue TUN outbound packet");
}

pub(super) async fn send_tun_packet_via_dataplane(
    nodes: &mut [TestNode],
    index: usize,
    packet: Vec<u8>,
) {
    enqueue_tun_packet_via_dataplane(nodes, index, packet);
    process_available_packets(nodes).await;
}

pub(super) async fn recv_tun_packet_while_draining(
    nodes: &mut [TestNode],
    rx: &crate::upper::tun::TunRx,
    timeout: Duration,
    context: &str,
) -> Vec<u8> {
    try_recv_tun_packet_while_draining(nodes, rx, timeout)
        .await
        .unwrap_or_else(|| panic!("{context}: TUN packet should not time out"))
}

async fn try_recv_tun_packet_while_draining(
    nodes: &mut [TestNode],
    rx: &crate::upper::tun::TunRx,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match rx.try_recv_packet() {
            Ok(packet) => return Some(packet.as_slice().to_vec()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("TUN receiver disconnected");
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }

        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        run_session_retransmit_work(nodes).await;
        process_available_packets(nodes).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn process_available_packets_for_node(node: &mut TestNode) -> usize {
    process_available_packets(std::slice::from_mut(node)).await
}

async fn wait_process_packets_for_node(nodes: &mut [TestNode], index: usize) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets_for_node(&mut nodes[index]).await;
        if count > 0 {
            return count;
        }
        if tokio::time::Instant::now() >= deadline {
            return 0;
        }
    }
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
pub(super) fn build_ipv6_packet(
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
    entry.set_remote_supports_direct_fsp_transport(true);
    node.sessions.insert(remote_addr, entry);
    ensure_dataplane_fsp_owner_for_test(node, remote_addr);
}

fn session_timestamp_echo_for(rtt_ms: u32) -> u32 {
    let now_ms = Node::now_ms();
    (now_ms.wrapping_sub(1_000) as u32).saturating_sub(rtt_ms)
}
