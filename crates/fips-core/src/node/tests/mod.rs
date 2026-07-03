use super::*;
use crate::PeerIdentity;
use crate::transport::{LinkDirection, TransportAddr, packet_channel};
use crate::utils::index::SessionIndex;
use std::time::Duration;

mod acl;
#[cfg(target_os = "linux")]
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

pub(super) fn make_node() -> Node {
    let config = Config::new();
    Node::new(config).unwrap()
}

#[allow(dead_code)]
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
            &peer_addr,
            1,
            100,
            64,
            false,
            false,
            std::time::Instant::now() - age,
        )
        .expect("dataplane FMP receive bookkeeping should record");
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
