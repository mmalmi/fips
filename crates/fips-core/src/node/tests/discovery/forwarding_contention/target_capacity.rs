use super::*;

#[test]
fn original_payload_crosses_a_full_expired_target_table() {
    run_large_stack_async_test("lookup-capacity", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..4 {
            nodes.push(make_test_node().await);
        }
        nodes.sort_by_key(|node| *node.node.node_addr());
        let result = AssertUnwindSafe(exercise_capacity(&mut nodes))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise_capacity(nodes: &mut [TestNode]) {
    setup(nodes).await;
    let before = owners(nodes);
    let relay = *nodes[1].node.node_addr();
    let target = *nodes[2].node.node_addr();
    // Seed the real production limiter through normal admission, not synthetic
    // timestamps or altered limits. The payload then uses real UDP, discovery,
    // FSP establishment and the relay's production RX loop.
    for i in 0..4096u32 {
        let mut bytes = [0xA5; 16];
        bytes[..4].copy_from_slice(&i.to_le_bytes());
        let noise_target = NodeAddr::from_bytes(bytes);
        bytes[..4].copy_from_slice(&(10_000 + i / 256).to_le_bytes());
        let ingress = NodeAddr::from_bytes(bytes);
        assert_ne!(noise_target, target);
        assert!(
            nodes[1]
                .node
                .discovery_forward_limiter
                .should_forward(&ingress, &noise_target)
        );
    }
    assert_eq!(nodes[1].node.discovery_forward_limiter.len(), 4096);
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(2100) {
        turn(nodes).await;
    }
    assert_eq!(nodes[1].node.discovery_forward_limiter.len(), 4096);
    let actor = rx_loop::Transit::start(&mut nodes[1]).await;
    let result = AssertUnwindSafe(traffic(nodes, relay, false))
        .catch_unwind()
        .await;
    actor.restore(&mut nodes[1]).await;
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "the 60-second idle expiry cannot rescue this test"
    );
    assert_eq!(
        owners(nodes),
        before,
        "existing carriers must not reconnect"
    );
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
