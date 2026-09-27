//! Ready carrier rejection releases its preparation before Noise allocation.
use super::*;
use crate::config::TcpConfig;
use crate::node::acl::PeerAclReloader;
use crate::transport::{ConnectionState, tcp::TcpTransport};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn ready_tcp_preparation_rechecks_acl_before_allocating_noise() {
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    let mut node = Node::new(config).unwrap();
    let result = AssertUnwindSafe(exercise(&mut node)).catch_unwind().await;
    for transport in node.transports.values_mut() {
        transport.stop().await.unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn exercise(node: &mut Node) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = TransportAddr::from_socket_addr(listener.local_addr().unwrap());
    let transport_id = TransportId::new(1);
    let (tx, _rx) = packet_channel(8);
    let mut tcp = TcpTransport::new(transport_id, None, TcpConfig::default(), tx);
    tcp.start_async().await.unwrap();
    let stats = tcp.stats().clone();
    node.transports
        .insert(transport_id, TransportHandle::Tcp(tcp));
    let peer = make_peer_identity();
    node.initiate_connection(transport_id, remote.clone(), peer)
        .await
        .unwrap();
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    // Observe actual readiness before changing the ACL.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(
                node.transports
                    .get(&transport_id)
                    .unwrap()
                    .connection_state(&remote),
                ConnectionState::Connected
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actual outbound TCP carrier must connect");
    assert_eq!(stats.snapshot().pool_outbound, 1);
    assert_eq!(node.pending_connects.len(), 1);
    let link = node.pending_connects[0].link_id;
    assert_pending_owner(node, link, transport_id, &remote, &peer);

    // The request was allowed at dial time; a changed ACL rejects the ready
    // carrier before any Noise state/index or wire request can be installed.
    let acl = tempfile::tempdir().unwrap();
    let allow = acl.path().join("peers.allow");
    let deny = acl.path().join("peers.deny");
    std::fs::write(&allow, "").unwrap();
    std::fs::write(&deny, peer.npub()).unwrap();
    node.peer_acl = PeerAclReloader::with_paths(allow, deny);
    assert!(
        node.authorize_peer(
            &peer,
            PeerAclContext::OutboundConnect,
            transport_id,
            &remote
        )
        .is_err()
    );

    tokio::time::timeout(Duration::from_secs(1), node.poll_pending_connects())
        .await
        .expect("ready carrier rejection must finish");
    assert!(
        node.pending_connects.is_empty(),
        "successful retirement must release its exact pending owner together with the carrier"
    );
    assert_eq!(node.links.len(), 0);
    assert!(node.links.lookup_addr(transport_id, &remote).is_none());
    assert!(node.peers.connection_is_empty());
    assert!(node.pending_outbound.is_empty());
    assert_eq!(node.index_allocator.count(), 0);
    assert_eq!(stats.snapshot().pool_outbound, 0);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .expect("rejected carrier must reach EOF")
            .unwrap(),
        0,
        "no Noise request may precede the rejection close"
    );
    // Ordinary maintenance after completed cleanup neither revives a stale
    // preparation nor double-removes the physical pool entry.
    node.poll_pending_connects().await;
    assert!(node.pending_connects.is_empty());
    assert_eq!(node.links.len(), 0);
    assert_eq!(stats.snapshot().pool_outbound, 0);
}

fn assert_pending_owner(
    node: &Node,
    link: LinkId,
    transport: TransportId,
    remote: &TransportAddr,
    identity: &PeerIdentity,
) {
    assert_eq!(node.pending_connects.len(), 1);
    let pending = &node.pending_connects[0];
    assert_eq!(pending.link_id, link);
    assert_eq!(pending.transport_id, transport);
    assert_eq!(&pending.remote_addr, remote);
    assert_eq!(pending.peer_identity.node_addr(), identity.node_addr());
    assert!(pending.address_resolution.is_none());
    assert_eq!(node.links.len(), 1);
    assert_eq!(node.links.lookup_addr(transport, remote), Some(link));
    assert!(node.peers.connection_is_empty());
    assert!(node.pending_outbound.is_empty());
    assert_eq!(node.index_allocator.count(), 0);
}

#[tokio::test]
async fn failed_websocket_preparations_release_transport_state_and_keep_retry() {
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    let mut node = Node::new(config).unwrap();
    let result = AssertUnwindSafe(rejected_websocket_attempts(&mut node))
        .catch_unwind()
        .await;
    for transport in node.transports.values_mut() {
        transport.stop().await.unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn rejected_websocket_attempts(node: &mut Node) {
    use crate::config::WebSocketConfig;
    use crate::transport::websocket::WebSocketTransport;
    use tokio::io::AsyncWriteExt;

    let transport_id = TransportId::new(1);
    let (tx, _rx) = packet_channel(8);
    let mut websocket = WebSocketTransport::new(
        transport_id,
        None,
        WebSocketConfig::default(),
        tx,
        node.identity(),
    );
    websocket.start_async().await.unwrap();
    node.transports.insert(
        transport_id,
        TransportHandle::WebSocket(Box::new(websocket)),
    );
    // Reserve distinct real endpoints before making attempts so address reuse
    // cannot hide retention across failures at different destinations.
    let mut listeners = Vec::new();
    for _ in 0..3 {
        listeners.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let mut retired = Vec::new();
    for listener in listeners {
        let remote =
            TransportAddr::from_string(&format!("ws://{}/fips", listener.local_addr().unwrap()));
        let peer = make_peer_identity();
        node.config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "websocket",
            remote.to_string(),
        ));
        node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
        node.initiate_connection(transport_id, remote.clone(), peer)
            .await
            .unwrap();
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    node.transports[&transport_id].connection_state(&remote),
                    ConnectionState::Failed(_)
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the real HTTP upgrade must fail before node cleanup");
        let link = node.pending_connects[0].link_id;
        assert_pending_owner(node, link, transport_id, &remote, &peer);
        tokio::time::timeout(Duration::from_secs(1), node.poll_pending_connects())
            .await
            .unwrap();
        assert!(node.pending_connects.is_empty());
        assert_eq!(node.links.len(), 0);
        assert!(node.peers.connection_is_empty());
        assert!(node.pending_outbound.is_empty());
        assert_eq!(node.index_allocator.count(), 0);
        let retry = node.retry_pending.get(peer.node_addr()).unwrap();
        assert_eq!(retry.peer_config.addresses[0].addr, remote.to_string());
        retired.push(remote);
        for remote in &retired {
            assert_eq!(
                node.transports[&transport_id].connection_state(remote),
                ConnectionState::None,
                "failed preparation must retire transport state after scheduling retry"
            );
        }
    }
}
