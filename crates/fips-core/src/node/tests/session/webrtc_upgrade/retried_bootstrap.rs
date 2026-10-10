use super::*;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn retried_websocket_bootstrap_starts_direct_upgrade_after_authentication() {
    run_large_stack_async_test("retried-bootstrap-upgrade", || async {
        let mut nodes = vec![
            make_dual_transport_node(fixed_identity(6, 0x03)).await,
            make_dual_transport_node(fixed_identity(1, 0x02)).await,
        ];
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode]) {
    let target = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let rtc_addr = identity_transport_addr(nodes[1].node.identity());
    let mut config = test_peer_config(
        target.npub(),
        nodes[1].addr.to_string(),
        rtc_addr.to_string(),
    );
    config.connect_policy = ConnectPolicy::AutoConnect;
    config.auto_reconnect = true;
    nodes[0].node.config.peers = vec![config.clone()];
    nodes[0].node.configured_peers = ConfiguredPeerLookup::from_config(&nodes[0].node.config);
    let mut retry = crate::node::retry::RetryState::new(config);
    retry.retry_count = 1;
    nodes[0]
        .node
        .retry_pending
        .insert(*target.node_addr(), retry);

    // Use the real retry path: it defers RTC until WSS provides a route and
    // suppresses duplicate dials for the normal Noise handshake timeout.
    nodes[0].node.process_pending_retries(Node::now_ms()).await;
    assert!(
        nodes[0]
            .node
            .retry_pending
            .get(target.node_addr())
            .unwrap()
            .retry_after_ms
            > Node::now_ms() + 20_000
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            for node in nodes.iter_mut() {
                node.node.poll_pending_connects().await;
            }
            process_available_packets(nodes).await;
            if nodes[0].node.get_peer(target.node_addr()).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("retried real WebSocket adjacency authenticates");
    assert!(
        nodes[0]
            .node
            .retry_pending
            .get(target.node_addr())
            .is_none_or(|retry| retry.retry_after_ms <= Node::now_ms()),
        "authenticated fallback must release the completed handshake suppression deadline"
    );
    nodes[0].node.poll_nostr_discovery().await;
    nodes[0].node.process_pending_retries(Node::now_ms()).await;
    // A real locally gathered offer proves the direct upgrade was started,
    // not merely that a timer or a priority changed.
    let _offer = take_webrtc_signal(&mut nodes[0].node).await;
    assert_eq!(
        nodes[0]
            .node
            .transports
            .get(&TransportId::new(WEBRTC_TRANSPORT_NUMBER))
            .unwrap()
            .connection_state(&rtc_addr),
        ConnectionState::Connecting
    );
}
