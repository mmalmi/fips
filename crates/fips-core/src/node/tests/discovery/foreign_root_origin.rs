//! A correlated signature proves the target's statement, not its current tree.
use super::*;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    send_endpoint_data_via_dataplane,
};

#[tokio::test]
async fn foreign_root_origin_response_preserves_working_established_route() {
    let _guard = lock_large_network_test().await;
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    verify_tree_convergence(&nodes);
    let root = *nodes[0].node.tree_state().root();
    // Choose a non-root endpoint as target so its former self-root view is
    // foreign to this real three-node tree. We inject that signed view at the
    // response handler, not a claimed delayed UDP flight or topology event.
    let (source, destination) = if *nodes[2].node.node_addr() == root {
        (2, 0)
    } else {
        (0, 2)
    };
    let target = *nodes[destination].node.node_addr();
    let transit = *nodes[1].node.node_addr();
    let remote = PeerIdentity::from_pubkey_full(nodes[destination].node.identity().pubkey_full());
    let transit_peer = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let mut receive = nodes[destination].node.attach_endpoint_data_io(8).unwrap();
    nodes[source]
        .node
        .register_identity(target, remote.pubkey_full());
    nodes[source]
        .node
        .set_endpoint_source_route(remote, Some(transit_peer))
        .unwrap();
    let accepted_before = nodes[source].node.stats().discovery.resp_accepted;
    nodes[source]
        .node
        .maybe_initiate_route_query_lookup(&target)
        .await;
    let discovery_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let node = &nodes[source].node;
        let discovery_complete = node.stats().discovery.resp_accepted > accepted_before
            && !node.pending_lookups.contains_key(&target)
            && node
                .coord_cache()
                .get(&target, Node::now_ms())
                .is_some_and(|coords| coords.node_addr() == &target && coords.root_id() == &root);
        if discovery_complete {
            break;
        }
        if tokio::time::Instant::now() >= discovery_deadline {
            cleanup_nodes(&mut nodes).await;
            panic!("setup must complete a real signed current-root discovery");
        }
        process_available_packets(&mut nodes).await;
        for node in &mut nodes {
            node.node.check_bloom_state().await;
            node.node.check_pending_lookups(Node::now_ms()).await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    send_endpoint_data_via_dataplane(&mut nodes[source].node, remote, vec![1])
        .await
        .unwrap();
    let first = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut receive.event_rx,
        Duration::from_secs(5),
        "establish native route before stale response",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(first).payload.as_slice(),
        &[1]
    );
    // Cache metadata can legitimately differ from the target's later signed
    // declaration. Preserve the exact usable source entry observed after real
    // delivery, not an evolving destination-side snapshot.
    let working_coords = nodes[source]
        .node
        .coord_cache()
        .get(&target, Node::now_ms())
        .unwrap()
        .clone();
    assert_eq!(working_coords.node_addr(), &target);
    assert_eq!(working_coords.root_id(), &root);
    let epoch = nodes[source]
        .node
        .get_session(&target)
        .unwrap()
        .session_start_ms();
    assert!(
        nodes[source]
            .node
            .dataplane_application_route_ready(&target)
    );
    assert_eq!(
        nodes[source].node.dataplane.fsp_owner_next_hop(&target),
        Some(transit)
    );

    // Issue a real request, but do not advance any peer until the foreign-root
    // response is handled. Correlation is production-generated, and the actual
    // target signs its stale self-root view; proof validation is not bypassed.
    assert_eq!(nodes[source].node.initiate_lookup(&target, 8).await, 1);
    let request_id = nodes[source]
        .node
        .pending_lookups
        .last_origin_request_id(&target)
        .unwrap();
    let stale_coords = TreeCoordinate::from_addrs(vec![target]).unwrap();
    assert_ne!(stale_coords.root_id(), &root);
    let proof_data = LookupResponse::proof_bytes(request_id, &target, &stale_coords);
    let response = LookupResponse::new(
        request_id,
        target,
        stale_coords,
        nodes[destination].node.identity().sign(&proof_data),
    );
    assert!(remote.verify(&proof_data, &response.proof));
    let proof_failures = nodes[source].node.stats().discovery.resp_proof_failed;
    nodes[source]
        .node
        .handle_lookup_response(&transit, &response.encode()[1..])
        .await;
    // Freeze these observations before normal packets can repair the cache.
    let preserved_coords = nodes[source]
        .node
        .coord_cache()
        .get(&target, Node::now_ms())
        == Some(&working_coords);
    let preserved_application_route = nodes[source]
        .node
        .dataplane_application_route_ready(&target);
    let preserved_carrier =
        nodes[source].node.dataplane.fsp_owner_next_hop(&target) == Some(transit);
    let rejected_proof = nodes[source].node.stats().discovery.resp_proof_failed != proof_failures;

    let payload = b"fresh payload after stale signed response".to_vec();
    send_endpoint_data_via_dataplane(&mut nodes[source].node, remote, payload.clone())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut delivered = Vec::new();
    while delivered.is_empty() && tokio::time::Instant::now() < deadline {
        process_available_packets(&mut nodes).await;
        for node in &mut nodes {
            node.node.check_bloom_state().await;
            node.node.check_pending_lookups(Node::now_ms()).await;
        }
        while let Ok(event) = receive.event_rx.try_recv() {
            delivered.extend(
                event
                    .messages
                    .into_iter()
                    .map(|message| message.payload.as_slice().to_vec()),
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let same_session = nodes[source]
        .node
        .get_session(&target)
        .unwrap()
        .session_start_ms()
        == epoch;
    cleanup_nodes(&mut nodes).await;

    assert!(
        !rejected_proof,
        "fixture must pass real target-signature validation"
    );
    assert!(
        preserved_coords,
        "a correlated foreign-root response replaced usable current-root coordinates"
    );
    assert!(
        preserved_application_route,
        "stale coordinates disabled established application egress"
    );
    assert!(
        preserved_carrier && same_session,
        "the working carrier and FSP session must remain"
    );
    assert_eq!(
        delivered,
        vec![payload],
        "fresh native payload must arrive once"
    );
}
