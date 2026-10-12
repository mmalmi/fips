//! Routine key rotation waits for recent authenticated neighbor traffic.
use super::*;

#[test]
fn routine_fmp_rekey_waits_for_fresh_neighbor_traffic() {
    run_large_stack_async_test("quiet-neighbor-rekey", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        nodes.sort_by_key(|node| std::cmp::Reverse(*node.node.node_addr()));
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode]) {
    setup(nodes).await;
    drain_to_quiescence(nodes).await;
    let returning = *nodes[0].node.node_addr();
    let middle = *nodes[1].node.node_addr();
    let silent = *nodes[2].node.node_addr();
    nodes[1].node.config.node.heartbeat_interval_secs = 1;
    nodes[1].node.config.node.link_dead_timeout_secs = 3;
    nodes[1].node.config.node.rekey.enabled = true;
    nodes[1].node.config.node.rekey.after_secs = 1;
    nodes[1].node.config.node.rekey.after_messages = u64::MAX;
    for address in [returning, silent] {
        nodes[1]
            .node
            .peers
            .get_mut(&address)
            .unwrap()
            .set_rekey_jitter_secs_for_test(0);
    }
    let allocated = nodes[1].node.index_allocator.count();
    assert!(nodes[1].node.pending_outbound.is_empty());

    // Stop receiving real UDP traffic through more than one heartbeat period,
    // while keeping both peers below the configured dead timeout.
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    nodes[1].node.check_rekey().await;
    assert!(
        [returning, silent]
            .iter()
            .all(|address| { !nodes[1].node.get_peer(address).unwrap().rekey_in_progress() }),
        "routine rekey must not give silent neighbors a new handshake grace period"
    );
    assert_eq!(nodes[1].node.index_allocator.count(), allocated);
    assert!(nodes[1].node.pending_outbound.is_empty());

    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    nodes[0]
        .node
        .send_dataplane_fmp_link_plaintext(&middle, &heartbeat, false)
        .await
        .unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(2), nodes[1].packet_rx.recv())
        .await
        .expect("fresh encrypted heartbeat reaches its real UDP neighbor")
        .unwrap();
    assert_eq!(packet.remote_addr, nodes[0].addr);
    process_dataplane_packet(&mut nodes[1], packet).await;
    nodes[1].node.check_rekey().await;
    assert!(
        nodes[1]
            .node
            .get_peer(&returning)
            .unwrap()
            .rekey_in_progress()
    );
    assert!(!nodes[1].node.get_peer(&silent).unwrap().rekey_in_progress());
    let fresh_peer = nodes[1].node.get_peer(&returning).unwrap();
    assert!(nodes[1].node.pending_outbound.contains_key(&(
        nodes[1].transport_id,
        fresh_peer.rekey_our_index().unwrap().as_u32(),
    )));
    assert_eq!(nodes[1].node.index_allocator.count(), allocated + 1);

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    nodes[1].node.check_link_heartbeats().await;
    assert!(
        nodes[1].node.get_peer(&silent).is_none(),
        "unresponsive neighbor must leave at the original silence deadline"
    );
    assert!(
        nodes[1].node.get_peer(&returning).is_some(),
        "authenticated return traffic permits ordinary rotation without losing the peer"
    );
}
