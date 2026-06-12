use super::*;
use crate::discovery::nostr::{BootstrapEvent, NostrDiscovery};
use crate::node::wire::{
    EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, Msg1Header, build_encrypted,
    build_established_header, build_msg2,
};
use crate::peer::{ActivePeer, PromotionResult};
use crate::transport::ReceivedPacket;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportHandle, packet_channel};
use std::sync::Arc;

mod config_capacity_classifiers;
mod connected_udp_lifecycle;
mod endpoint_events;
mod fmp_worker;
mod link_registry_rx;
mod liveness_reconnect;
mod liveness_window;
mod node_lifecycle;
mod path_mtu;
mod peer_runtime_receive;
mod peer_runtime_route;
mod promotion_paths;
mod registries_core;
mod rekey;
mod retry_basics;
mod retry_paths;
mod session_registry;
mod update_peers_core;
mod update_peers_paths;

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

fn seal_test_fmp_packet(
    sender: &mut crate::noise::NoiseSession,
    receiver_idx: SessionIndex,
    plaintext: &[u8],
    k_bit: bool,
) -> Vec<u8> {
    let flags = if k_bit { FLAG_KEY_EPOCH } else { 0 };
    let counter = sender.current_send_counter();
    let header = build_established_header(receiver_idx, counter, flags, plaintext.len() as u16);
    let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
    build_encrypted(&header, &ciphertext)
}

#[allow(clippy::too_many_arguments)]
fn make_active_test_peer(
    node: &Node,
    peer_full: &Identity,
    peer_identity: PeerIdentity,
    transport_id: TransportId,
    link_id: LinkId,
    remote_addr: TransportAddr,
    our_index: SessionIndex,
    their_index: SessionIndex,
) -> ActivePeer {
    let session = make_test_fmp_session(&node.identity, peer_full, [0x01; 8], [0x02; 8]);
    ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        session,
        our_index,
        their_index,
        transport_id,
        remote_addr,
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    )
}

fn arm_test_fmp_rekey(peer: &mut ActivePeer, rekey_our_index: SessionIndex) {
    let remote = Identity::generate();
    let local = Identity::generate();
    let handshake =
        crate::noise::HandshakeState::new_initiator(local.keypair(), remote.pubkey_full());
    peer.set_rekey_state(handshake, rekey_our_index, vec![0xAB; 64], 0);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn make_test_connected_udp_pair(
    transport_id: TransportId,
) -> (
    Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
    crate::transport::udp::peer_drain::PeerRecvDrain,
) {
    let peer_udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind peer udp");
    let peer_socket_addr = peer_udp.local_addr().expect("peer udp local addr");
    let socket = Arc::new(
        crate::transport::udp::connected_peer::ConnectedPeerSocket::open(
            "127.0.0.1:0".parse().unwrap(),
            peer_socket_addr,
            1 << 20,
            1 << 20,
        )
        .expect("connected peer socket"),
    );
    let (packet_tx, _packet_rx) = packet_channel(16);
    let drain = crate::transport::udp::peer_drain::PeerRecvDrain::spawn(
        socket.clone(),
        transport_id,
        peer_socket_addr,
        packet_tx,
        None,
    )
    .expect("connected peer drain");
    (socket, drain)
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
