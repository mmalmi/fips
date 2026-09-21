//! Handler controls for foreign-root responses; native payload uses the sibling regression.
use super::*;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    send_endpoint_data_via_dataplane,
};

async fn signed_response(
    node: &mut Node,
    identity: &Identity,
    from: NodeAddr,
    request_id: u64,
    coords: TreeCoordinate,
) {
    let target = *identity.node_addr();
    let proof_data = LookupResponse::proof_bytes(request_id, &target, &coords);
    let mut response = LookupResponse::new(request_id, target, coords, identity.sign(&proof_data));
    response.path_mtu = 1280;
    node.handle_lookup_response(&from, &response.encode()[1..])
        .await;
}

#[tokio::test]
async fn foreign_root_indirect_response_keeps_empty_cache_recovery_pending() {
    let mut node = make_node();
    let identity = Identity::generate();
    let target = *identity.node_addr();
    let from = make_node_addr(0xAA);
    let root = *node.tree_state().root();
    let foreign = TreeCoordinate::from_addrs(vec![target]).unwrap();
    assert_ne!(foreign.root_id(), &root);
    node.register_identity(target, identity.pubkey_full());
    seed_pending_lookup(&mut node, target, 720);
    node.discovery_backoff.record_failure(&target);
    let failures = node.discovery_backoff.failure_count(&target);
    let fips = crate::FipsAddress::from_node_addr(&target);
    assert!(failures > 0 && node.path_mtu_lookup_get(&fips).is_none());

    signed_response(&mut node, &identity, from, 720, foreign).await;
    assert!(node.coord_cache().get(&target, Node::now_ms()).is_none());
    assert!(node.pending_lookups.matches_origin_request(&target, 720));
    assert_eq!(node.discovery_backoff.failure_count(&target), failures);
    assert_eq!(node.stats().discovery.resp_accepted, 0);
    assert_eq!(node.stats().discovery.resp_proof_failed, 0);
    assert!(node.path_mtu_lookup_get(&fips).is_none());

    let usable = TreeCoordinate::from_addrs(vec![target, root]).unwrap();
    signed_response(&mut node, &identity, from, 720, usable.clone()).await;
    assert_eq!(
        node.coord_cache().get(&target, Node::now_ms()),
        Some(&usable)
    );
    assert!(!node.pending_lookups.contains_key(&target));
    assert_eq!(node.discovery_backoff.failure_count(&target), 0);
    assert_eq!(node.stats().discovery.resp_accepted, 1);
    assert_eq!(node.path_mtu_lookup_get(&fips), Some(1280));
}

#[tokio::test]
async fn foreign_root_direct_response_completes_without_overwriting_current_coords() {
    native_direct_response(false).await;
}

#[tokio::test]
async fn foreign_root_direct_response_keeps_bound_indirect_recovery_pending() {
    native_direct_response(true).await;
}

async fn native_direct_response(bound_indirect: bool) {
    let _guard = lock_large_network_test().await;
    // The origin has genuine authenticated direct and relay alternatives. The
    // relay also reaches the target, so the explicit binding is a valid path.
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2), (0, 2)], false).await;
    verify_tree_convergence(&nodes);
    let root = *nodes[0].node.tree_state().root();
    let target_index = if *nodes[1].node.node_addr() == root {
        2
    } else {
        1
    };
    let relay_index = 3 - target_index;
    let target = *nodes[target_index].node.node_addr();
    let relay = *nodes[relay_index].node.node_addr();
    let target_peer =
        PeerIdentity::from_pubkey_full(nodes[target_index].node.identity().pubkey_full());
    let relay_peer =
        PeerIdentity::from_pubkey_full(nodes[relay_index].node.identity().pubkey_full());
    let usable = nodes[target_index].node.tree_state().my_coords().clone();
    assert_eq!(usable.root_id(), &root);
    let foreign = TreeCoordinate::from_addrs(vec![target]).unwrap();
    assert_ne!(foreign.root_id(), &root);
    assert!(nodes[0].node.get_peer(&target).unwrap().can_send());
    assert!(nodes[0].node.get_peer(&relay).unwrap().can_send());
    assert!(
        nodes[relay_index]
            .node
            .get_peer(&target)
            .unwrap()
            .can_send()
    );
    nodes[0]
        .node
        .register_identity(target, target_peer.pubkey_full());
    let accepted_before = nodes[0].node.stats().discovery.resp_accepted;
    seed_pending_lookup(&mut nodes[0].node, target, 723);
    {
        let (origin, others) = nodes.split_at_mut(1);
        signed_response(
            &mut origin[0].node,
            others[target_index - 1].node.identity(),
            target,
            723,
            usable.clone(),
        )
        .await;
    }
    assert_eq!(
        nodes[0].node.stats().discovery.resp_accepted,
        accepted_before + 1
    );
    assert!(!nodes[0].node.pending_lookups.contains_key(&target));
    let cached = nodes[0]
        .node
        .coord_cache()
        .get(&target, Node::now_ms())
        .unwrap()
        .clone();
    assert_eq!(cached.node_addr(), &target);
    assert_eq!(cached.root_id(), &root);
    assert_eq!(
        cached.node_addrs().collect::<Vec<_>>(),
        usable.node_addrs().collect::<Vec<_>>()
    );
    // LookupResponse carries address-only coordinates, omitting the tree
    // declaration's sequence/timestamp metadata. The invariant below preserves
    // the exact decoded source entry, after a correlated response succeeded.
    let usable = cached;
    assert_eq!(
        nodes[0]
            .node
            .find_next_hop(&target)
            .map(|peer| *peer.node_addr()),
        Some(target)
    );
    if bound_indirect {
        // This is native source-binding coverage, not a financial fixture.
        nodes[0]
            .node
            .set_endpoint_source_route(target_peer, Some(relay_peer))
            .unwrap();
    }
    let expected_hop = if bound_indirect { relay } else { target };
    assert_eq!(
        nodes[0]
            .node
            .find_next_hop(&target)
            .map(|peer| *peer.node_addr()),
        Some(expected_hop)
    );
    seed_pending_lookup(&mut nodes[0].node, target, 721);
    nodes[0].node.discovery_backoff.record_failure(&target);
    let failures = nodes[0].node.discovery_backoff.failure_count(&target);
    let accepted = nodes[0].node.stats().discovery.resp_accepted;
    {
        let (origin, others) = nodes.split_at_mut(1);
        signed_response(
            &mut origin[0].node,
            others[target_index - 1].node.identity(),
            target,
            721,
            foreign,
        )
        .await;
    }
    let preserved_coords =
        nodes[0].node.coord_cache().get(&target, Node::now_ms()) == Some(&usable);
    let pending = nodes[0]
        .node
        .pending_lookups
        .matches_origin_request(&target, 721);
    let remaining_failures = nodes[0].node.discovery_backoff.failure_count(&target);
    let accepted_delta = nodes[0].node.stats().discovery.resp_accepted - accepted;
    let proof_failures = nodes[0].node.stats().discovery.resp_proof_failed;
    let selected_hop = nodes[0]
        .node
        .find_next_hop(&target)
        .map(|peer| *peer.node_addr());
    cleanup_nodes(&mut nodes).await;

    assert!(
        preserved_coords,
        "foreign direct response must not replace usable tree coordinates"
    );
    assert_eq!(
        selected_hop,
        Some(expected_hop),
        "response must respect explicit routing authority"
    );
    assert_eq!(proof_failures, 0);
    if bound_indirect {
        assert!(
            pending,
            "direct reply cannot finish repair for a bound indirect application route"
        );
        assert_eq!(remaining_failures, failures);
        assert_eq!(accepted_delta, 0);
    } else {
        assert!(
            !pending,
            "a genuine selected direct route can complete without shared-root coordinates"
        );
        assert_eq!(remaining_failures, 0);
        assert_eq!(accepted_delta, 1);
    }
}

#[tokio::test]
async fn foreign_root_reply_learned_response_still_completes() {
    let mut node = make_node();
    node.config.node.routing.mode = RoutingMode::ReplyLearned;
    let identity = Identity::generate();
    let target = *identity.node_addr();
    let from = make_node_addr(0xAA);
    let foreign = TreeCoordinate::from_addrs(vec![target]).unwrap();
    assert_ne!(foreign.root_id(), node.tree_state().root());
    node.register_identity(target, identity.pubkey_full());
    seed_pending_lookup(&mut node, target, 722);
    node.discovery_backoff.record_failure(&target);

    signed_response(&mut node, &identity, from, 722, foreign.clone()).await;
    assert_eq!(
        node.coord_cache().get(&target, Node::now_ms()),
        Some(&foreign)
    );
    assert!(!node.pending_lookups.contains_key(&target));
    assert_eq!(node.discovery_backoff.failure_count(&target), 0);
    assert_eq!(node.stats().discovery.resp_accepted, 1);
    assert_eq!(node.stats().discovery.resp_proof_failed, 0);
    assert_eq!(
        node.learned_routes
            .active_handshake_route(&target, Node::now_ms()),
        Some(from)
    );
}

#[tokio::test]
async fn foreign_root_relay_response_cannot_displace_working_direct_session() {
    let _guard = lock_large_network_test().await;
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2), (0, 2)], false).await;
    verify_tree_convergence(&nodes);
    let root = *nodes[0].node.tree_state().root();
    let target_index = if *nodes[1].node.node_addr() == root {
        2
    } else {
        1
    };
    let relay_index = 3 - target_index;
    let target = *nodes[target_index].node.node_addr();
    let relay = *nodes[relay_index].node.node_addr();
    let remote = PeerIdentity::from_pubkey_full(nodes[target_index].node.identity().pubkey_full());
    let source = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let mut source_receive = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut target_receive = nodes[target_index].node.attach_endpoint_data_io(8).unwrap();
    assert!(nodes[0].node.get_peer(&target).unwrap().can_send());
    assert!(nodes[0].node.get_peer(&relay).unwrap().can_send());
    send_endpoint_data_via_dataplane(&mut nodes[0].node, remote, vec![9])
        .await
        .unwrap();
    let outbound = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut target_receive.event_rx,
        Duration::from_secs(5),
        "establish actual direct session before relay response",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(outbound)
            .payload
            .as_slice(),
        &[9]
    );
    send_endpoint_data_via_dataplane(&mut nodes[target_index].node, source, vec![10])
        .await
        .unwrap();
    let returning = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut source_receive.event_rx,
        Duration::from_secs(5),
        "fresh actual direct return before relay response",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(returning)
            .payload
            .as_slice(),
        &[10]
    );
    let epoch = nodes[0]
        .node
        .get_session(&target)
        .unwrap()
        .session_start_ms();
    assert_eq!(
        nodes[0].node.dataplane.fsp_owner_next_hop(&target),
        Some(target)
    );
    assert_eq!(
        nodes[0]
            .node
            .find_next_hop(&target)
            .map(|peer| *peer.node_addr()),
        Some(target)
    );
    assert!(
        nodes[0]
            .node
            .session_direct_path_has_recent_data_return(&target, Node::now_ms())
    );
    assert!(
        !nodes[0]
            .node
            .session_direct_path_degradation_active(&target, Node::now_ms())
    );

    // Model an absent/expired coordinate entry explicitly; direct application
    // delivery does not require it. A normal recovery lookup remains pending
    // while the already-proven direct session can still carry data.
    nodes[0].node.coord_cache_mut().remove(&target);
    let fips = crate::FipsAddress::from_node_addr(&target);
    let mtu_before = nodes[0].node.path_mtu_lookup_get(&fips);
    nodes[0]
        .node
        .maybe_initiate_path_recovery_lookup(&target)
        .await;
    let request_id = nodes[0]
        .node
        .pending_lookups
        .last_origin_request_id(&target)
        .expect("native path-recovery lookup must issue a correlated request");
    assert!(nodes[0].node.pending_lookups.is_path_recovery(&target));
    let failures_before = nodes[0].node.discovery_backoff.failure_count(&target);
    let accepted_before = nodes[0].node.stats().discovery.resp_accepted;
    let foreign = TreeCoordinate::from_addrs(vec![target]).unwrap();
    assert_ne!(foreign.root_id(), &root);
    // Inject only the signed response handler event from the authenticated
    // relay. No normal queued response may repair the state before sampling.
    {
        let (origin, others) = nodes.split_at_mut(1);
        signed_response(
            &mut origin[0].node,
            others[target_index - 1].node.identity(),
            relay,
            request_id,
            foreign,
        )
        .await;
    }
    let owner_preserved = nodes[0].node.dataplane.fsp_owner_next_hop(&target) == Some(target);
    let selected_preserved = nodes[0]
        .node
        .find_next_hop(&target)
        .map(|peer| *peer.node_addr())
        == Some(target);
    let session_preserved = nodes[0]
        .node
        .get_session(&target)
        .unwrap()
        .session_start_ms()
        == epoch;
    let degraded = nodes[0]
        .node
        .session_direct_path_degradation_active(&target, Node::now_ms());
    let pending = nodes[0]
        .node
        .pending_lookups
        .matches_origin_request(&target, request_id)
        && nodes[0].node.pending_lookups.is_path_recovery(&target);
    let cache_empty = nodes[0]
        .node
        .coord_cache()
        .get(&target, Node::now_ms())
        .is_none();
    let failures_after = nodes[0].node.discovery_backoff.failure_count(&target);
    let accepted_after = nodes[0].node.stats().discovery.resp_accepted;
    let proof_failures = nodes[0].node.stats().discovery.resp_proof_failed;
    let mtu_after = nodes[0].node.path_mtu_lookup_get(&fips);
    cleanup_nodes(&mut nodes).await;

    assert!(
        owner_preserved && selected_preserved && session_preserved,
        "foreign relay response must preserve the working direct FSP route"
    );
    assert!(
        !degraded,
        "foreign-root relay statement cannot establish indirect application recovery"
    );
    assert!(
        pending,
        "unusable relay response must leave the original repair request pending"
    );
    assert!(cache_empty);
    assert_eq!(failures_after, failures_before);
    assert_eq!(accepted_after, accepted_before);
    assert_eq!(proof_failures, 0);
    assert_eq!(
        mtu_after, mtu_before,
        "unusable relay response must not change the path MTU"
    );
}
