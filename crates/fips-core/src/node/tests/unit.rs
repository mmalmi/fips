use super::*;
use crate::discovery::nostr::{BootstrapEvent, NostrDiscovery};
use crate::node::wire::{Msg1Header, build_msg2};
use crate::peer::{ActivePeer, ActivePeerSession, PromotionResult};
use crate::transport::ReceivedPacket;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportHandle, packet_channel};

mod config_capacity_classifiers;
mod endpoint_events;
mod link_registry_rx;
mod liveness_reconnect;
mod liveness_window;
mod node_lifecycle;
mod path_mtu;
mod promotion_paths;
mod registries_core;
mod rekey;
mod retry_basics;
mod retry_paths;
mod session_registry;
mod update_peers_core;
mod update_peers_paths;

fn refresh_configured_peer_cache_for_test(node: &mut Node) {
    node.configured_peers = ConfiguredPeerLookup::from_config(&node.config);
}

fn make_test_fmp_session(
    local: &Identity,
    peer: &Identity,
    local_epoch: [u8; 8],
    peer_epoch: [u8; 8],
) -> crate::noise::NoiseSession {
    make_test_fmp_session_pair(local, peer, local_epoch, peer_epoch).0
}

fn make_test_fmp_session_pair(
    local: &Identity,
    peer: &Identity,
    local_epoch: [u8; 8],
    peer_epoch: [u8; 8],
) -> (crate::noise::NoiseSession, crate::noise::NoiseSession) {
    let mut initiator =
        crate::noise::HandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
    let mut responder = crate::noise::HandshakeState::new_responder(peer.keypair());
    initiator.set_local_epoch(local_epoch);
    responder.set_local_epoch(peer_epoch);
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    (
        initiator.into_session().unwrap(),
        responder.into_session().unwrap(),
    )
}

fn make_active_test_peer(
    node: &Node,
    peer_full: &Identity,
    transport_id: TransportId,
    link_id: LinkId,
    remote_addr: TransportAddr,
    our_index: SessionIndex,
    their_index: SessionIndex,
) -> ActivePeer {
    let session = make_test_fmp_session(&node.identity, peer_full, [0x01; 8], [0x02; 8]);
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        ActivePeerSession {
            session,
            our_index,
            their_index,
            transport_id,
            current_addr: remote_addr,
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x02; 8]),
        },
    )
}

fn arm_test_fmp_rekey(peer: &mut ActivePeer, rekey_our_index: SessionIndex) {
    let remote = Identity::generate();
    let local = Identity::generate();
    let handshake =
        crate::noise::HandshakeState::new_initiator(local.keypair(), remote.pubkey_full());
    peer.set_rekey_state(handshake, rekey_our_index, vec![0xAB; 64], 0);
}

/// Helper: spawn a UdpTransport with the given mtu, started and operational.
async fn make_udp_transport_with_mtu(id: u32, mtu: u16) -> TransportHandle {
    let (packet_tx, _packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(id);
    let mut udp = UdpTransport::new(
        transport_id,
        Some(format!("udp{}", id)),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(mtu),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    TransportHandle::Udp(udp)
}

fn npub_for_test() -> String {
    Identity::generate().npub()
}

fn peer_identity_for_outbound_refresh_owner(node: &Node) -> (Identity, PeerIdentity) {
    loop {
        let identity = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        if node.identity.node_addr() < peer_identity.node_addr() {
            return (identity, peer_identity);
        }
    }
}

fn peer_identity_for_outbound_refresh_loser(node: &Node) -> (Identity, PeerIdentity) {
    loop {
        let identity = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        if node.identity.node_addr() > peer_identity.node_addr() {
            return (identity, peer_identity);
        }
    }
}

fn seed_dataplane_fsp_control_rx_for_test(
    node: &mut Node,
    source_addr: NodeAddr,
    previous_hop: NodeAddr,
    now_ms: u64,
) {
    ensure_dataplane_fsp_owner_for_test(node, source_addr);
    assert!(
        node.dataplane
            .record_authenticated_fsp_session(
                crate::dataplane::DataplaneAuthenticatedFspSession::new(
                    source_addr,
                    previous_hop,
                    crate::protocol::SessionMessageType::SenderReport.to_byte(),
                    0,
                    crate::dataplane::FspReceiveSync {
                        counter: 1,
                        received_k_bit: false,
                        timestamp: 0,
                        plaintext_len: crate::node::session_wire::FSP_INNER_HEADER_SIZE,
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

fn auto_connect_peer(npub: String, addr: &str) -> crate::config::PeerConfig {
    crate::config::PeerConfig {
        npub,
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", addr)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    }
}

fn inject_dummy_peers(node: &mut Node, count: usize) {
    for i in 0..count {
        let identity = make_peer_identity();
        let addr = *identity.node_addr();
        let peer = ActivePeer::new(identity, LinkId::new((i + 1) as u64), 0);
        node.peers.insert(addr, peer);
    }
}
