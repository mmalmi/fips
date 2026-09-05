use super::*;
use crate::transport::{TransportHandle, udp::UdpTransport};
use crate::{Config, Identity};

fn make_node() -> Node {
    Node::new(Config::new()).unwrap()
}
fn make_peer_identity() -> PeerIdentity {
    PeerIdentity::from_pubkey(Identity::generate().pubkey())
}

#[tokio::test]
async fn udp_hostname_dial_prepares_address_before_installing_handshake() {
    let (mut node, transport_id, receiver, target) = udp_hostname_fixture(None).await;
    let peer = make_peer_identity();
    node.config.peers.push(crate::config::PeerConfig::new(
        peer.npub(),
        "udp",
        target.to_string(),
    ));
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    node.initiate_connection(transport_id, target.clone(), peer)
        .await
        .unwrap();
    assert!(
        node.peers.connection_is_empty(),
        "hostname resolution must finish before allocating a Noise handshake"
    );
    assert_eq!(node.pending_connects.len(), 1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !node.pending_connects.is_empty() {
            node.poll_pending_connects().await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("local hostname resolution must complete");
    let mut packet = [0; 1500];
    let bytes = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut packet))
        .await
        .expect("resolved UDP target must receive Msg1")
        .unwrap();
    assert!(bytes > 0);
    let connection = node.peers.connection_values().next().unwrap();
    assert!(
        connection
            .source_addr()
            .unwrap()
            .as_str()
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .is_ok()
    );
    assert_eq!(
        node.links
            .lookup_addr(transport_id, connection.source_addr().unwrap()),
        Some(connection.link_id()),
    );
    let link_id = connection.link_id();
    let numeric_addr = connection.source_addr().unwrap().clone();
    node.initiate_connection(transport_id, target.clone(), peer)
        .await
        .unwrap();
    assert!(
        node.pending_connects.is_empty(),
        "resolved hostname must still deduplicate before Msg2"
    );
    assert_eq!(node.peers.connection_len(), 1);
    assert!(node.rearm_pending_outbound_handshake_on_path(
        peer.node_addr(),
        transport_id,
        &target,
        Node::now_ms()
    ));
    assert_eq!(
        node.configured_path_priority(peer.node_addr(), transport_id, &numeric_addr),
        Some(node.config.peers[0].addresses[0].priority)
    );
    node.cleanup_stale_connection(link_id, Node::now_ms()).await;
    assert!(node.links.lookup_addr(transport_id, &target).is_none());
    node.initiate_connection(transport_id, target, peer)
        .await
        .unwrap();
    assert_eq!(
        node.pending_connects.len(),
        1,
        "a later dial must resolve the configured hostname again"
    );
}

#[tokio::test]
async fn numeric_udp_dial_keeps_immediate_handshake() {
    let (mut node, transport_id, receiver, _) = udp_hostname_fixture(None).await;
    node.initiate_connection(
        transport_id,
        TransportAddr::from_string(&receiver.local_addr().unwrap().to_string()),
        make_peer_identity(),
    )
    .await
    .unwrap();
    assert!(node.pending_connects.is_empty());
    assert_eq!(node.peers.connection_len(), 1);
}

#[tokio::test]
async fn udp_hostname_preparation_retries_a_failed_first_send() {
    // The transport resolves normally, then refuses a Msg1 larger than its MTU.
    let (mut node, transport_id, _receiver, target) = udp_hostname_fixture(Some(64)).await;
    let peer = make_peer_identity();
    node.config.peers.push(crate::config::PeerConfig::new(
        peer.npub(),
        "udp",
        target.to_string(),
    ));
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    node.initiate_connection(transport_id, target.clone(), peer)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !node.pending_connects.is_empty() {
            node.poll_pending_connects().await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(node.peers.connection_is_empty());
    assert_eq!(node.links.len(), 0);
    assert_eq!(node.index_allocator.count(), 0);
    assert!(node.retry_pending.contains_key(peer.node_addr()));
    assert_eq!(
        node.retry_pending
            .get(peer.node_addr())
            .unwrap()
            .peer_config
            .addresses[0]
            .addr,
        target.to_string()
    );
}

#[test]
fn udp_hostname_preparation_cannot_block_liveness_and_expires() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()
                .unwrap()
                .block_on(stalled_udp_hostname_preparation());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn stalled_udp_hostname_preparation() {
    let (mut node, transport_id, receiver, target) = udp_hostname_fixture(None).await;
    let peer = make_peer_identity();
    node.config.peers.push(crate::config::PeerConfig::new(
        peer.npub(),
        "udp",
        target.to_string(),
    ));
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    // Occupy this isolated runtime's only blocking worker. Tokio's real system
    // resolver stays queued until release, without altering host DNS settings.
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let blocker = tokio::task::spawn_blocking(move || {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
    });
    started_rx.await.unwrap();
    tokio::time::pause();
    for _ in 0..2 {
        tokio::time::timeout(
            Duration::from_millis(100),
            node.initiate_connection(transport_id, target.clone(), peer),
        )
        .await
        .expect("unresolved hostname must not block a dial turn")
        .unwrap();
    }
    assert_eq!(
        node.pending_connects.len(),
        1,
        "duplicate dials share preparation"
    );
    for _ in 0..3 {
        tokio::time::timeout(Duration::from_millis(100), node.poll_pending_connects())
            .await
            .expect("DNS must not block the liveness tick");
        assert_eq!(node.pending_connects.len(), 1);
        assert!(node.peers.connection_is_empty());
        tokio::time::advance(Duration::from_secs(2)).await;
    }
    tokio::time::advance(Duration::from_secs(
        node.config.node.rate_limit.handshake_timeout_secs,
    ))
    .await;
    node.poll_pending_connects().await;
    assert!(node.pending_connects.is_empty());
    assert!(node.peers.connection_is_empty());
    assert_eq!(node.links.len(), 0);
    assert!(node.retry_pending.contains_key(peer.node_addr()));
    assert_eq!(node.config.peers[0].addresses[0].addr, target.to_string());
    drop(release_tx);
    blocker.await.unwrap();
    assert!(
        receiver.try_recv(&mut [0; 1500]).is_err(),
        "expired preparation must not send Msg1"
    );
}

async fn udp_hostname_fixture(
    mtu: Option<u16>,
) -> (Node, TransportId, tokio::net::UdpSocket, TransportAddr) {
    let mut node = make_node();
    let localhost = tokio::net::lookup_host("localhost:0")
        .await
        .unwrap()
        .next()
        .unwrap();
    let receiver = tokio::net::UdpSocket::bind(localhost).await.unwrap();
    let (packet_tx, _packet_rx) = packet_channel(8);
    let transport_id = TransportId::new(1);
    let mut transport = UdpTransport::new(
        transport_id,
        None,
        crate::config::UdpConfig {
            bind_addr: Some(localhost.to_string()),
            mtu,
            ..Default::default()
        },
        packet_tx,
    );
    transport.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));
    let target = TransportAddr::from_string(&format!(
        "localhost:{}",
        receiver.local_addr().unwrap().port()
    ));
    (node, transport_id, receiver, target)
}
