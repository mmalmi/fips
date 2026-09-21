//! Physical preparation cleanup retains its owner through a cancelled close.
use super::*;
use crate::config::TcpConfig;
use crate::node::acl::PeerAclReloader;
use crate::transport::{ConnectionState, tcp::TcpTransport};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn cancelled_preparation_retirement_retries_exact_owner_and_closes_tcp() {
    exercise_with_cleanup(true).await;
}

#[tokio::test]
async fn ready_tcp_preparation_rechecks_acl_before_allocating_noise() {
    exercise_with_cleanup(false).await;
}

async fn exercise_with_cleanup(cancel_close: bool) {
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    let mut node = Node::new(config).unwrap();
    let result = AssertUnwindSafe(exercise(&mut node, cancel_close))
        .catch_unwind()
        .await;
    for transport in node.transports.values_mut() {
        transport.stop().await.unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn exercise(node: &mut Node, cancel_close: bool) {
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
    // Observe actual readiness before taking the pool lock. A locked pool
    // reports Connecting, so this does not pretend a locked poll sees Ready.
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

    if cancel_close {
        let guard = match node.transports.get(&transport_id).unwrap() {
            TransportHandle::Tcp(tcp) => tcp.test_pool_guard().await,
            _ => unreachable!(),
        };
        // Exercise the production close phase directly. The separate test
        // below proves that the real ready-poll ACL branch reaches cleanup.
        let mut close = Box::pin(node.retire_connection_preparation(link));
        assert!(futures::poll!(close.as_mut()).is_pending());
        drop(close);
        assert_pending_owner(node, link, transport_id, &remote, &peer);
        assert_eq!(stats.snapshot().pool_outbound, 1);
        drop(guard);
        tokio::time::timeout(
            Duration::from_secs(1),
            node.retire_connection_preparation(link),
        )
        .await
        .expect("same owned retirement must resume after cancellation");
    } else {
        tokio::time::timeout(Duration::from_secs(1), node.poll_pending_connects())
            .await
            .expect("ready carrier rejection must finish without a held pool lock");
    }
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
