use super::*;

// Use real Noise/UDP frames. Other queued handshake copies are fixture setup,
// not re-submitted packets; the selected established frame is submitted once.
async fn announcement(nodes: &mut [TestNode], payload: &[u8], deadline: Instant) -> ReceivedPacket {
    let root = *nodes[0].node.node_addr();
    let child = *nodes[1].node.node_addr();
    nodes[1]
        .node
        .send_dataplane_fmp_link_plaintext(&root, payload, false)
        .await
        .unwrap();
    loop {
        let packet = tokio::time::timeout_at(deadline, nodes[0].packet_rx.recv())
            .await
            .expect("real announcement must arrive before the fixture deadline")
            .unwrap();
        if announced_tree(&nodes[0], &child, &packet)
            .is_some_and(|announce| announce.encode().unwrap() == payload)
        {
            return packet;
        }
    }
}

async fn prepare(nodes: &mut [TestNode]) -> Vec<u8> {
    nodes.sort_by_key(|node| *node.node.node_addr());
    Box::pin(complete_direct_handshake(nodes, 0, 1)).await;
    let child = *nodes[1].node.node_addr();
    let payload = nodes[1]
        .node
        .build_tree_announce()
        .unwrap()
        .encode()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let packet = announcement(nodes, &payload, deadline).await;
    let selected = SelectedFrame::new(child, &packet);
    let node = &mut nodes[0].node;
    let mut queues = Queues::take(node);
    let mut turn = authenticated_turn(node, &mut queues, &selected, packet, deadline).await;
    Box::pin(node.process_dataplane_control_ingress(&mut turn)).await;
    Box::pin(node.drain_deferred_dataplane_control_turns()).await;
    queues.restore(node);
    assert!(
        nodes[0]
            .node
            .tree_state()
            .peer_declaration(&child)
            .is_some()
    );
    payload
}

async fn authenticated_turn(
    node: &mut Node,
    queues: &mut Queues,
    selected: &SelectedFrame,
    packet: ReceivedPacket,
    deadline: Instant,
) -> DataplaneLiveNodeTurn {
    tokio::time::timeout_at(deadline, async {
        let mut turn = queues.pump(node, Some(packet), 64).await;
        while !selected.present_in(&turn) {
            // Setup is independent of the completion policy under test, so a
            // negative policy control fails at its intended assertion below.
            Box::pin(node.process_dataplane_control_ingress(&mut turn)).await;
            Box::pin(node.drain_deferred_dataplane_control_turns()).await;
            tokio::task::yield_now().await;
            turn = queues.pump(node, None, 64).await;
        }
        turn
    })
    .await
    .expect("real selected frame must authenticate before the fixture deadline")
}

#[tokio::test]
async fn admitted_frame_and_stale_wake_do_not_complete_handler_fence() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let result = AssertUnwindSafe(async {
        let payload = prepare(&mut nodes).await;
        let child = *nodes[1].node.node_addr();
        let deadline = Instant::now() + Duration::from_secs(3);
        let packet = announcement(&mut nodes, &payload, deadline).await;
        let selected = SelectedFrame::new(child, &packet);
        let node = &mut nodes[0].node;
        let stale = node.stats().tree.stale;
        let mut queues = Queues::take(node);
        // The production zero-crypto turn admits the real frame but cannot
        // authenticate it, making the observation gap deterministic.
        let mut initial = queues.pump(node, Some(packet), 0).await;
        assert!(initial.has_activity());
        assert_eq!(initial.summary().dispatched(), 0);
        assert!(initial.fmp_link_ingress().is_empty());
        node.dataplane.readiness_notify().notify_one();
        assert!(
            node.dataplane
                .readiness_notify()
                .notified()
                .now_or_never()
                .is_some()
        );
        assert!(
            !finish(node, &selected, &mut initial, deadline).await,
            "admission and an advisory wake must not complete the selected handler fence"
        );
        assert_eq!(node.stats().tree.stale, stale);
        assert!(
            tokio::time::timeout_at(
                deadline,
                complete(node, &mut queues, &selected, initial, deadline)
            )
            .await
            .unwrap()
        );
        queues.restore(node);
        assert_eq!(
            node.stats().tree.stale,
            stale + 1,
            "the selected fresh encrypted duplicate must finish the ordinary stale handler once"
        );
    })
    .catch_unwind()
    .await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn another_authenticated_frame_does_not_complete_selected_fence() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let result = AssertUnwindSafe(async {
        let payload = prepare(&mut nodes).await;
        let child = *nodes[1].node.node_addr();
        let deadline = Instant::now() + Duration::from_secs(3);
        let other_packet = announcement(&mut nodes, &payload, deadline).await;
        let packet = announcement(&mut nodes, &payload, deadline).await;
        let other = SelectedFrame::new(child, &other_packet);
        let selected = SelectedFrame::new(child, &packet);
        assert_ne!(other.counter, selected.counter);
        let node = &mut nodes[0].node;
        let stale = node.stats().tree.stale;
        let mut queues = Queues::take(node);
        let mut turn = authenticated_turn(node, &mut queues, &other, other_packet, deadline).await;
        assert!(
            !finish(node, &selected, &mut turn, deadline).await,
            "a different authenticated counter must not complete the selected handler fence"
        );
        assert_eq!(node.stats().tree.stale, stale + 1);
        queues.restore(node);
        assert!(process_frame(node, child, packet, deadline).await);
        assert_eq!(node.stats().tree.stale, stale + 2);
    })
    .catch_unwind()
    .await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn matching_handler_at_deadline_is_not_on_time() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let result = AssertUnwindSafe(async {
        let payload = prepare(&mut nodes).await;
        let child = *nodes[1].node.node_addr();
        let deadline = Instant::now() + Duration::from_secs(3);
        let packet = announcement(&mut nodes, &payload, deadline).await;
        let selected = SelectedFrame::new(child, &packet);
        let node = &mut nodes[0].node;
        let stale = node.stats().tree.stale;
        let mut queues = Queues::take(node);
        let mut turn = authenticated_turn(node, &mut queues, &selected, packet, deadline).await;
        assert!(
            !finish(node, &selected, &mut turn, Instant::now()).await,
            "matching handler completion at or after the deadline must not pass"
        );
        queues.restore(node);
        assert_eq!(node.stats().tree.stale, stale + 1);
    })
    .catch_unwind()
    .await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
