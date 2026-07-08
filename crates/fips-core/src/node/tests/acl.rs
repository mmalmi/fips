use super::*;
use crate::ReceivedPacket;
use crate::config::{NostrDiscoveryPolicy, PeerConfig};
use crate::node::acl::{PeerAclContext, PeerAclReloader};
use crate::node::wire::{build_msg1, build_msg2};
use crate::peer::{ActivePeer, PeerConnection};
use crate::utils::index::SessionIndex;
use std::path::PathBuf;
use std::time::Duration;

fn make_acl_node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::new(Config::new()).unwrap();
    node.peer_acl = PeerAclReloader::with_paths(
        dir.path().join("peers.allow"),
        dir.path().join("peers.deny"),
    );
    (dir, node)
}

fn allow_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("peers.allow")
}

fn deny_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("peers.deny")
}

#[test]
fn test_system_files_disabled_uses_memory_only_acl() {
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    let mut node = Node::new(config).unwrap();

    let status = node.peer_acl_status();
    assert_eq!(status.allow_file, "");
    assert_eq!(status.deny_file, "");
    assert_eq!(status.effective_mode, "default_open");
    assert!(!status.enforcement_active);
    assert!(!node.reload_peer_acl());
}

#[test]
fn configured_only_discovery_rejects_nonconfigured_peer() {
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    let node = Node::new(config).unwrap();
    let stranger = Identity::generate();

    let result = node.authorize_peer(
        &PeerIdentity::from_pubkey_full(stranger.pubkey_full()),
        PeerAclContext::InboundHandshake,
        TransportId::new(1),
        &TransportAddr::from_string("127.0.0.1:9000"),
    );

    assert!(matches!(result, Err(NodeError::AccessDenied(_))));
}

#[test]
fn configured_only_discovery_allows_configured_peer() {
    let peer = Identity::generate();
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.peers = vec![PeerConfig {
        npub: peer.npub(),
        ..PeerConfig::default()
    }];
    let node = Node::new(config).unwrap();

    let result = node.authorize_peer(
        &PeerIdentity::from_pubkey_full(peer.pubkey_full()),
        PeerAclContext::InboundHandshake,
        TransportId::new(1),
        &TransportAddr::from_string("127.0.0.1:9000"),
    );

    assert!(result.is_ok());
}

#[test]
fn open_discovery_rejects_new_nonconfigured_inbound_peer_at_cap() {
    let active = Identity::generate();
    let stranger = Identity::generate();
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.open_discovery_max_pending = 1;
    let mut node = Node::new(config).unwrap();
    let active_identity = PeerIdentity::from_pubkey_full(active.pubkey_full());
    node.peers.insert(
        *active_identity.node_addr(),
        ActivePeer::new(active_identity, LinkId::new(1), 0),
    );

    let result = node.authorize_peer(
        &PeerIdentity::from_pubkey_full(stranger.pubkey_full()),
        PeerAclContext::InboundHandshake,
        TransportId::new(1),
        &TransportAddr::from_string("127.0.0.1:9000"),
    );

    assert!(matches!(result, Err(NodeError::AccessDenied(_))));
}

#[test]
fn open_discovery_counts_inflight_nonconfigured_handshakes_at_cap() {
    let inflight = Identity::generate();
    let stranger = Identity::generate();
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.open_discovery_max_pending = 1;
    let mut node = Node::new(config).unwrap();
    let inflight_identity = PeerIdentity::from_pubkey_full(inflight.pubkey_full());
    node.peers.insert_connection(
        LinkId::new(1),
        PeerConnection::outbound(LinkId::new(1), inflight_identity, 0),
    );

    let result = node.authorize_peer(
        &PeerIdentity::from_pubkey_full(stranger.pubkey_full()),
        PeerAclContext::InboundHandshake,
        TransportId::new(1),
        &TransportAddr::from_string("127.0.0.1:9000"),
    );

    assert!(matches!(result, Err(NodeError::AccessDenied(_))));
}

#[test]
fn open_discovery_allows_configured_inbound_peer_at_cap() {
    let active = Identity::generate();
    let configured = Identity::generate();
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.open_discovery_max_pending = 1;
    config.peers = vec![PeerConfig {
        npub: configured.npub(),
        ..PeerConfig::default()
    }];
    let mut node = Node::new(config).unwrap();
    let active_identity = PeerIdentity::from_pubkey_full(active.pubkey_full());
    node.peers.insert(
        *active_identity.node_addr(),
        ActivePeer::new(active_identity, LinkId::new(1), 0),
    );

    let result = node.authorize_peer(
        &PeerIdentity::from_pubkey_full(configured.pubkey_full()),
        PeerAclContext::InboundHandshake,
        TransportId::new(1),
        &TransportAddr::from_string("127.0.0.1:9000"),
    );

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_outbound_connect_denied_by_denylist() {
    let (dir, mut node) = make_acl_node();
    let denied = Identity::generate();
    std::fs::write(deny_path(&dir), format!("{}\n", denied.npub())).unwrap();
    node.reload_peer_acl();

    let result = node
        .initiate_connection(
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:9000"),
            PeerIdentity::from_pubkey_full(denied.pubkey_full()),
        )
        .await;

    assert!(matches!(result, Err(NodeError::AccessDenied(_))));
    assert_eq!(node.link_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 0);
}

#[tokio::test]
async fn test_inbound_msg1_denied_by_acl() {
    let (dir, mut node_b) = make_acl_node();
    let node_a = make_node();

    std::fs::write(deny_path(&dir), format!("{}\n", node_a.npub())).unwrap();
    node_b.reload_peer_acl();

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let mut conn_a = PeerConnection::outbound(LinkId::new(1), peer_b_identity, 1000);
    let noise_msg1 = conn_a
        .start_handshake(node_a.identity.keypair(), node_a.startup_epoch, 1000)
        .unwrap();
    let wire_msg1 = build_msg1(SessionIndex::new(7), &noise_msg1);
    let packet = ReceivedPacket::with_timestamp(
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:5000"),
        crate::transport::PacketBuffer::new(wire_msg1),
        1000,
    );

    node_b.handle_msg1(packet).await;

    assert_eq!(node_b.peer_count(), 0);
    assert_eq!(node_b.connection_count(), 0);
    assert_eq!(node_b.link_count(), 0);
}

#[tokio::test]
async fn test_outbound_msg2_denied_after_acl_reload() {
    let (dir, mut node_a) = make_acl_node();
    let node_b = make_node();
    let transport_id = TransportId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5001");
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());

    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a, peer_b_identity, 1000);
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let noise_msg1 = conn_a
        .start_handshake(node_a.identity.keypair(), node_a.startup_epoch, 1000)
        .unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id);
    conn_a.set_source_addr(remote_addr.clone());

    let link_a = Link::connectionless(
        link_id_a,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a
        .links
        .insert_addr((transport_id, remote_addr.clone()), link_id_a);
    node_a.peers.insert_connection(link_id_a, conn_a);
    node_a
        .pending_outbound
        .insert((transport_id, our_index_a.as_u32()), link_id_a);

    let mut conn_b = PeerConnection::inbound(LinkId::new(2), 1000);
    let responder_epoch = [0x11; 8];
    let noise_msg2 = conn_b
        .receive_handshake_init(
            node_b.identity.keypair(),
            responder_epoch,
            &noise_msg1,
            1000,
        )
        .unwrap();
    let our_index_b = SessionIndex::new(9);
    let wire_msg2 = build_msg2(our_index_b, our_index_a, &noise_msg2);

    std::fs::write(deny_path(&dir), format!("{}\n", node_b.npub())).unwrap();
    assert!(node_a.reload_peer_acl());

    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        remote_addr,
        crate::transport::PacketBuffer::new(wire_msg2),
        1100,
    );
    node_a.handle_msg2(packet).await;

    assert_eq!(node_a.peer_count(), 0);
    assert_eq!(node_a.connection_count(), 0);
    assert_eq!(node_a.link_count(), 0);
    assert!(node_a.pending_outbound.is_empty());
}

#[tokio::test]
async fn test_outbound_connect_not_denied_by_allowlist_miss() {
    let (dir, mut node) = make_acl_node();
    let denied = Identity::generate();
    let allowed = Identity::generate();
    std::fs::write(allow_path(&dir), format!("{}\n", allowed.npub())).unwrap();
    node.reload_peer_acl();

    let result = node
        .initiate_connection(
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:9000"),
            PeerIdentity::from_pubkey_full(denied.pubkey_full()),
        )
        .await;

    assert!(!matches!(result, Err(NodeError::AccessDenied(_))));
}
