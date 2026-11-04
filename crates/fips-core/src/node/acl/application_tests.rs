use super::*;
use crate::Identity;
use crate::config::{Config, PeerAdmissionConfig, PeerConfig, TcpConfig, WebSocketConfig};
use crate::transport::{TransportHandle, packet_channel};
use std::time::Duration;

#[tokio::test]
async fn application_policy_covers_operator_websocket_without_nostr_discovery() {
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey_full(identity.pubkey_full());
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.peer_admission.configured_only = true;
    assert!(!config.node.discovery.nostr.enabled);
    let mut node = Node::new(config).unwrap();
    let id = TransportId::new(1);
    let address = TransportAddr::from_string("ws://127.0.0.1:9123/fips");
    let (tx, _rx) = packet_channel(8);
    let transport = crate::transport::websocket::WebSocketTransport::new(
        id,
        None,
        WebSocketConfig {
            seed_urls: vec![address.to_string()],
            ..Default::default()
        },
        tx,
        node.identity(),
    );
    node.transports
        .insert(id, TransportHandle::WebSocket(Box::new(transport)));
    for context in [
        PeerAclContext::OutboundConnect,
        PeerAclContext::OutboundHandshake,
        PeerAclContext::InboundHandshake,
    ] {
        assert!(node.authorize_peer(&peer, context, id, &address).is_err());
    }
    node.update_peers(vec![PeerConfig {
        npub: peer.npub(),
        ..Default::default()
    }])
    .await
    .unwrap();
    assert!(
        node.authorize_peer(&peer, PeerAclContext::OutboundConnect, id, &address)
            .is_ok()
    );
    node.update_peer_admission(PeerAdmissionConfig {
        configured_only: true,
        denied_npubs: vec![peer.npub()],
    })
    .await
    .unwrap();
    assert!(
        node.authorize_peer(&peer, PeerAclContext::OutboundConnect, id, &address)
            .is_err()
    );
    let before = node.config.node.peer_admission.clone();
    assert!(
        node.update_peer_admission(PeerAdmissionConfig {
            configured_only: false,
            denied_npubs: vec!["invalid".into()],
        })
        .await
        .is_err()
    );
    assert_eq!(node.config.node.peer_admission, before);
}

#[tokio::test]
async fn application_revocation_retires_ready_tcp_preparation_before_noise() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = TransportAddr::from_socket_addr(listener.local_addr().unwrap());
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    let mut node = Node::new(config).unwrap();
    let id = TransportId::new(1);
    let (tx, _rx) = packet_channel(8);
    let mut tcp = crate::transport::tcp::TcpTransport::new(id, None, TcpConfig::default(), tx);
    tcp.start_async().await.unwrap();
    node.transports.insert(id, TransportHandle::Tcp(tcp));
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey_full(identity.pubkey_full());
    node.initiate_connection(id, remote.clone(), peer)
        .await
        .unwrap();
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(node.pending_connects.len(), 1);
    assert_eq!(node.connection_count(), 0);
    node.update_peer_admission(PeerAdmissionConfig {
        configured_only: false,
        denied_npubs: vec![peer.npub()],
    })
    .await
    .unwrap();
    node.poll_pending_connects().await;
    assert!(node.pending_connects.is_empty());
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 0);
    assert_eq!(node.index_allocator.count(), 0);
    let mut bytes = [0; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        n, 0,
        "revoked preparation must close without emitting Noise msg1"
    );
    for transport in node.transports.values_mut() {
        transport.stop().await.unwrap();
    }
}
