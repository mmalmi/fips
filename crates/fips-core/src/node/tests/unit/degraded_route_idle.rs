use super::*;
use crate::protocol::LookupResponse;
use crate::tree::TreeCoordinate;

async fn degraded_session_with_fallback_owner() -> (Node, Identity, NodeAddr, u64) {
    let remote = Identity::generate();
    let fallback = Identity::generate();
    let alternate = Identity::generate();
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers = vec![
        auto_connect_peer(remote.npub(), "127.0.0.1:9"),
        auto_connect_peer(fallback.npub(), "127.0.0.1:10"),
        auto_connect_peer(alternate.npub(), "127.0.0.1:11"),
    ];
    let mut node = Node::new(config).unwrap();
    for transport in 1..=3 {
        node.transports.insert(
            TransportId::new(transport),
            make_udp_transport_with_mtu(transport, 1280).await,
        );
    }

    let remote_addr = *remote.node_addr();
    let fallback_addr = *fallback.node_addr();
    assert!(node.register_endpoint_identity(remote_addr, remote.pubkey_full()));
    for (identity, transport, link, our_index, their_index) in [
        (&remote, 1, 1, 1, 2),
        (&fallback, 2, 2, 3, 4),
        (&alternate, 3, 3, 5, 6),
    ] {
        let peer_addr = *identity.node_addr();
        let peer = make_active_test_peer(
            &node,
            identity,
            TransportId::new(transport),
            LinkId::new(link),
            TransportAddr::from_string(&format!("127.0.0.1:{}", 8 + transport)),
            SessionIndex::new(our_index),
            SessionIndex::new(their_index),
        );
        node.peers.insert(peer_addr, peer);
        assert!(node.sync_dataplane_fmp_owner(&peer_addr));
    }

    node.learn_reverse_route(remote_addr, fallback_addr);
    let mut session = SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            node.identity(),
            &remote,
            [0x71; 8],
            [0x72; 8],
        )),
        1_000,
        true,
    );
    session.mark_established(1_000);
    node.sessions.insert(remote_addr, session);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(fallback_addr),
        0,
    ));

    let now_ms = Node::now_ms();
    node.mark_session_direct_path_degraded(remote_addr, now_ms);
    node.schedule_active_direct_refresh_retry(remote_addr, now_ms);
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(fallback_addr),
        "fixture must carry the established session over a non-direct owner"
    );

    (node, remote, fallback_addr, now_ms)
}

async fn complete_pending_lookup(
    node: &mut Node,
    target_identity: &Identity,
    response_hop: NodeAddr,
) {
    let target = *target_identity.node_addr();
    let request_id = node
        .pending_lookups
        .last_origin_request_id(&target)
        .expect("lookup must carry a current origin request");
    let root = *node.tree_state().my_coords().root_id();
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();
    let proof_data = LookupResponse::proof_bytes(request_id, &target, &coords);
    let response = LookupResponse::new(
        request_id,
        target,
        coords,
        target_identity.sign(&proof_data),
    );

    node.handle_lookup_response(&response_hop, &response.encode()[1..])
        .await;
    assert!(
        !node.pending_lookups.contains_key(&target),
        "an accepted response must complete the pending lookup"
    );
}

async fn stop_transports(node: &mut Node) {
    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn degraded_route_retry_ticks_keep_a_healthy_fallback_owner_quiet() {
    let (mut node, remote, fallback_addr, now_ms) = degraded_session_with_fallback_owner().await;
    let remote_addr = *remote.node_addr();

    node.maybe_initiate_path_recovery_lookup(&remote_addr).await;
    assert!(node.pending_lookups.contains_key(&remote_addr));
    complete_pending_lookup(&mut node, &remote, fallback_addr).await;
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(fallback_addr),
        "the accepted response must retain the healthy fallback FSP owner"
    );
    assert!(node.dataplane_has_fmp_owner(&fallback_addr));
    assert!(
        node.peers
            .get(&fallback_addr)
            .expect("fallback peer")
            .is_healthy()
    );
    assert!(
        node.peers
            .get(&fallback_addr)
            .expect("fallback peer")
            .can_send()
    );
    assert!(
        !node
            .learned_routes
            .failed_next_hops(&remote_addr, now_ms)
            .contains(&fallback_addr)
    );

    let baseline = node.stats().discovery.req_initiated;
    let first_retry_at = node
        .retry_pending
        .get(&remote_addr)
        .expect("direct retry remains scheduled")
        .retry_after_ms;
    let retry_delay_ms = first_retry_at.saturating_sub(now_ms);
    assert!(
        retry_delay_ms > 61,
        "fixture needs distinct maintenance ticks before the direct retry is due"
    );
    assert!(
        !node
            .peers
            .get(&remote_addr)
            .expect("direct peer")
            .rekey_in_progress()
    );

    for tick in 1..=61 {
        let tick_ms = now_ms + retry_delay_ms * tick / 62;
        node.process_pending_retries(tick_ms).await;
        if node.pending_lookups.contains_key(&remote_addr) {
            complete_pending_lookup(&mut node, &remote, fallback_addr).await;
        }
    }

    node.process_pending_retries(first_retry_at).await;
    if node.pending_lookups.contains_key(&remote_addr) {
        complete_pending_lookup(&mut node, &remote, fallback_addr).await;
    }

    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline,
        "a healthy routed FSP owner must not restart discovery on every retry tick"
    );
    assert!(
        !node.pending_lookups.contains_key(&remote_addr),
        "a healthy fallback owner needs no concurrent lookup"
    );
    assert!(
        node.retry_pending.contains_key(&remote_addr),
        "suppressing repeated discovery must preserve the independent direct-path retry"
    );
    assert!(
        node.peers
            .get(&remote_addr)
            .expect("direct peer")
            .rekey_in_progress(),
        "the due direct-path retry must execute even while discovery stays quiet"
    );
    assert!(
        node.retry_pending
            .get(&remote_addr)
            .expect("direct retry remains scheduled")
            .retry_after_ms
            > first_retry_at,
        "the executed direct retry must schedule its next bounded probe"
    );
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn degraded_route_retry_starts_one_lookup_after_fallback_owner_loss() {
    let (mut node, remote, fallback_addr, now_ms) = degraded_session_with_fallback_owner().await;
    let remote_addr = *remote.node_addr();
    node.remove_dataplane_fmp_owner(&fallback_addr);
    let baseline = node.stats().discovery.req_initiated;

    node.process_pending_retries(now_ms).await;
    node.process_pending_retries(now_ms).await;

    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "fallback-owner loss must start exactly one bounded replacement lookup"
    );
    assert!(node.pending_lookups.contains_key(&remote_addr));
    assert!(
        node.retry_pending.contains_key(&remote_addr),
        "fallback recovery must not consume the direct-path retry"
    );
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn degraded_route_retry_rejects_unhealthy_or_quarantined_fallback_owners() {
    for quarantined in [false, true] {
        let (mut node, remote, fallback_addr, now_ms) =
            degraded_session_with_fallback_owner().await;
        let remote_addr = *remote.node_addr();
        if quarantined {
            node.learned_routes.quarantine_failed_next_hop(
                remote_addr,
                fallback_addr,
                now_ms,
                node.config.node.routing.learned_ttl_secs,
                node.config.node.routing.max_learned_routes_per_dest,
            );
        } else {
            node.peers
                .get_mut(&fallback_addr)
                .expect("fallback owner peer")
                .mark_stale();
        }
        let baseline = node.stats().discovery.req_initiated;

        node.process_pending_retries(now_ms).await;
        node.process_pending_retries(now_ms).await;

        assert_eq!(
            node.stats().discovery.req_initiated,
            baseline + 1,
            "an unusable fallback owner must start one bounded replacement lookup"
        );
        assert!(node.pending_lookups.contains_key(&remote_addr));
        stop_transports(&mut node).await;
    }
}
