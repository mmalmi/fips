use super::*;
use crate::PeerIdentity;
use crate::transport::{LinkDirection, TransportAddr, packet_channel};
use crate::utils::index::SessionIndex;
use std::time::Duration;

mod acl;
#[cfg(not(feature = "host-ble-transport"))]
mod ble;
mod bloom;
mod bloom_poison;
mod bootstrap;
mod decrypt_failure;
mod disconnect;
mod discovery;
#[cfg(target_os = "linux")]
mod ethernet;
mod forwarding;
mod handshake;
mod routing;
mod session;
mod spanning_tree;
mod tcp;
mod unit;
mod websocket;

pub(super) fn make_node() -> Node {
    let config = Config::new();
    Node::new(config).unwrap()
}

pub(super) fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

pub(super) fn make_peer_identity() -> PeerIdentity {
    let identity = Identity::generate();
    PeerIdentity::from_pubkey(identity.pubkey())
}

pub(super) fn seed_dataplane_fmp_srtt_for_test(node: &mut Node, peer_addr: NodeAddr, srtt_ms: u64) {
    let peer_session_elapsed_ms = node
        .get_peer(&peer_addr)
        .expect("dataplane FMP SRTT seed needs an active peer")
        .session_elapsed_ms();
    assert!(node.sync_dataplane_fmp_owner(&peer_addr));
    let srtt_ms = u32::try_from(srtt_ms).expect("test SRTT fits u32");
    let now_ms = Node::now_ms().saturating_add(u64::from(srtt_ms) + 1);
    let timestamp_echo = peer_session_elapsed_ms.saturating_add(1);
    let report = crate::mmp::ReceiverReport {
        highest_counter: 1,
        cumulative_packets_recv: 1,
        cumulative_bytes_recv: 128,
        timestamp_echo,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 1,
        interval_bytes_recv: 128,
    };
    node.dataplane
        .process_fmp_mmp_receiver_report(&peer_addr, &report, now_ms, std::time::Instant::now())
        .expect("dataplane FMP receiver report should process");
}

pub(super) fn seed_dataplane_fmp_rx_for_test(node: &mut Node, peer_addr: NodeAddr, age: Duration) {
    assert!(node.sync_dataplane_fmp_owner(&peer_addr));
    node.dataplane
        .record_authenticated_fmp_mmp_receive(
            crate::dataplane::DataplaneAuthenticatedFmpMmpReceive::new(
                peer_addr,
                1,
                100,
                64,
                false,
                false,
                std::time::Instant::now() - age,
            ),
        )
        .expect("dataplane FMP receive bookkeeping should record");
}

fn populate_all_coord_caches(nodes: &mut [spanning_tree::TestNode]) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let all_coords: Vec<(NodeAddr, crate::tree::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for tn in nodes.iter_mut() {
        for (addr, coords) in &all_coords {
            if addr != tn.node.node_addr() {
                tn.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }
}

pub(super) fn ensure_dataplane_fsp_owner_for_test(node: &mut Node, dest_addr: NodeAddr) {
    node.dataplane.register_owner_if_missing(
        crate::dataplane::OwnerId::fsp_node(dest_addr),
        crate::dataplane::OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_mmp(node.config.node.session_mmp.clone(), true),
    );
}

pub(super) fn seed_dataplane_fsp_data_sent_for_test(
    node: &mut Node,
    dest_addr: NodeAddr,
    next_hop: NodeAddr,
    now_ms: u64,
) {
    ensure_dataplane_fsp_owner_for_test(node, dest_addr);
    assert!(node.dataplane.record_fsp_data_sent(
        dest_addr,
        next_hop,
        512,
        crate::dataplane::ActivityTick::new(now_ms),
    ));
}

pub(super) fn seed_dataplane_fsp_data_rx_for_test(
    node: &mut Node,
    source_addr: NodeAddr,
    previous_hop: NodeAddr,
    now_ms: u64,
) {
    ensure_dataplane_fsp_owner_for_test(node, source_addr);
    let body_len = 512;
    assert!(
        node.dataplane
            .record_authenticated_fsp_session(
                crate::dataplane::DataplaneAuthenticatedFspSession::new(
                    source_addr,
                    previous_hop,
                    crate::protocol::SessionMessageType::EndpointData.to_byte(),
                    body_len,
                    crate::dataplane::FspReceiveSync {
                        counter: 2,
                        received_k_bit: false,
                        timestamp: 0,
                        plaintext_len: crate::node::session_wire::FSP_INNER_HEADER_SIZE + body_len,
                        ce_flag: false,
                        path_mtu: u16::MAX,
                        spin_bit: false,
                    },
                    Some(crate::dataplane::ActivityTick::new(now_ms)),
                    std::time::Instant::now(),
                ),
            )
            .is_some()
    );
}

/// Create a PeerConnection with a completed Noise IK handshake.
///
/// Returns (connection, peer_identity) where the connection is outbound,
/// in Complete state, with session, indices, and transport info set.
pub(super) fn make_completed_connection(
    node: &mut Node,
    link_id: LinkId,
    transport_id: TransportId,
    current_time_ms: u64,
) -> (PeerConnection, PeerIdentity) {
    let peer_identity_full = Identity::generate();
    make_completed_connection_for_identity(
        node,
        link_id,
        transport_id,
        current_time_ms,
        &peer_identity_full,
    )
}

pub(super) fn make_completed_connection_for_identity(
    node: &mut Node,
    link_id: LinkId,
    transport_id: TransportId,
    current_time_ms: u64,
    peer_identity_full: &Identity,
) -> (PeerConnection, PeerIdentity) {
    // Must use from_pubkey_full to preserve parity for ECDH
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());

    // Create outbound connection
    let mut conn = PeerConnection::outbound(link_id, peer_identity, current_time_ms);

    // Run initiator side of handshake
    let our_keypair = node.identity.keypair();
    let msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, current_time_ms)
        .unwrap();

    // Run responder side to generate msg2
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), current_time_ms);
    let peer_keypair = peer_identity_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, current_time_ms)
        .unwrap();

    // Complete initiator handshake
    conn.complete_handshake(&msg2, current_time_ms).unwrap();

    // Set indices and transport info
    let our_index = node.index_allocator.allocate().unwrap();
    conn.set_our_index(our_index);
    conn.set_their_index(SessionIndex::new(42));
    conn.set_transport_id(transport_id);
    conn.set_source_addr(TransportAddr::from_string("127.0.0.1:5000"));

    (conn, peer_identity)
}
