use super::*;

#[test]
fn original_payload_crosses_busy_peers_protected_reply_slots() {
    run_large_stack_async_test("lookup-reply-capacity", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..4 {
            nodes.push(make_test_node().await);
        }
        nodes.sort_by_key(|node| *node.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode]) {
    setup(nodes).await;
    let relay = *nodes[1].node.node_addr();
    let target = *nodes[2].node.node_addr();
    let mut busy = Vec::new();
    // The real UDP/Noise links carry the payload. Completed Noise fixtures
    // supply 128 authenticated peers within the unchanged default limits.
    // The loaded seed uses 300; either inventory exposes the 64-slot floor.
    for index in 3..128 {
        let node = &mut nodes[1].node;
        let link = LinkId::new(1_000 + index as u64);
        let (connection, identity) =
            make_completed_connection(node, link, TransportId::new(999), Node::now_ms());
        node.add_connection(connection).unwrap();
        node.promote_connection(link, identity, Node::now_ms())
            .unwrap();
        if busy.len() < 100 {
            busy.push(
                *node
                    .peers
                    .values()
                    .find(|p| p.link_id() == link)
                    .unwrap()
                    .node_addr(),
            );
        }
    }
    assert_eq!(nodes[1].node.peers.len(), 128);
    let began = Instant::now();
    let mut protected = Vec::new();
    // Model pending, already-forwarded requests using normal bounded admission
    // and protection, not synthetic records or changed deadlines. No protected
    // return path may be sacrificed to admit the quiet peer's real payload.
    for attempt in 0..64u64 {
        for (index, peer) in busy.iter().enumerate() {
            let id = 10_000 + attempt * 100 + index as u64;
            let node = &mut nodes[1].node;
            let admitted = node.recent_requests.record_request(
                id,
                *peer,
                target,
                Node::now_ms(),
                crate::node::RecentDiscoveryRequestLimits::new(4096, node.peers.len()),
            );
            if admitted.accepted() {
                node.recent_requests.protect(id);
                protected.push(id);
            }
        }
    }
    let reserved = nodes[1].node.recent_requests.len();
    assert!(reserved <= 4096);
    let _source_io = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut target_io = nodes[2].node.attach_endpoint_data_io(8).unwrap();
    let actor = rx_loop::Transit::start(&mut nodes[1]).await;
    let destination = PeerIdentity::from_pubkey_full(nodes[2].node.identity().pubkey_full());
    let payload = b"quiet peer amid protected reply reservations";
    send_endpoint_data_via_dataplane(&mut nodes[0].node, destination, payload.to_vec())
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut delivered = false;
    while Instant::now() < deadline {
        turn(nodes).await;
        if let Ok(event) = target_io.event_rx.try_recv() {
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                payload
            );
            delivered = true;
            break;
        }
    }
    actor.restore(&mut nodes[1]).await;
    assert!(
        began.elapsed() < Duration::from_secs(9),
        "expiry cannot rescue this test"
    );
    assert!(
        protected
            .iter()
            .all(|id| nodes[1].node.recent_requests.contains_key(id)),
        "already admitted reply paths must be retained"
    );
    assert!(nodes[0].node.get_peer(&relay).unwrap().is_healthy());
    eprintln!(
        "reply reservations: reserved={reserved}, delivered={delivered}, target_received={}",
        nodes[2].node.stats().discovery.req_target_is_us
    );
    assert!(
        delivered,
        "busy peers cannot reserve the quiet peers' reply-path share"
    );
}
