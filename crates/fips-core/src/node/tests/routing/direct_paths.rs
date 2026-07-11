use super::*;

// === Local delivery ===

#[test]
fn test_routing_local_delivery() {
    let mut node = make_node();
    let my_addr = *node.node_addr();
    assert!(node.find_next_hop(&my_addr).is_none());
}

// === Direct peer ===

#[test]
fn test_routing_direct_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    let result = node.find_next_hop(&peer_addr);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer_addr);
}

#[test]
fn test_session_degraded_direct_peer_remains_route_without_fallback() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    node.mark_session_direct_path_degraded(peer_addr, Node::now_ms());

    let result = node.find_next_hop(&peer_addr).expect("direct route");
    assert_eq!(
        result.node_addr(),
        &peer_addr,
        "a healthy direct peer must remain the payload route when no fallback can carry traffic"
    );
}

#[test]
fn test_stale_direct_peer_stays_probeable_but_is_not_payload_route() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();
    node.get_peer_mut(&peer_addr)
        .expect("direct peer")
        .mark_stale();

    assert!(
        node.get_peer(&peer_addr).expect("direct peer").can_send(),
        "stale direct links stay sendable for heartbeats/reprobe"
    );
    assert!(
        !node.get_peer(&peer_addr).expect("direct peer").is_healthy(),
        "stale direct links are not healthy payload routes"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "a stale direct link with no fallback route must not blackhole payload"
    );
}

#[test]
fn test_reply_learned_prefers_live_mesh_route_over_stale_direct_peer() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let direct_link = LinkId::new(1);
    let (direct_conn, direct_id) =
        make_completed_connection(&mut node, direct_link, transport_id, 1000);
    let dest_addr = *direct_id.node_addr();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_id, 2000)
        .unwrap();
    node.get_peer_mut(&dest_addr).unwrap().mark_stale();

    let mesh_link = LinkId::new(2);
    let (mesh_conn, mesh_id) = make_completed_connection(&mut node, mesh_link, transport_id, 1000);
    let mesh_next_hop = *mesh_id.node_addr();
    node.add_connection(mesh_conn).unwrap();
    node.promote_connection(mesh_link, mesh_id, 2000).unwrap();
    node.learn_reverse_route(dest_addr, mesh_next_hop);

    let result = node.find_next_hop(&dest_addr).expect("mesh route");
    assert_eq!(
        result.node_addr(),
        &mesh_next_hop,
        "a stale direct NAT path must not hide a learned live mesh route"
    );
}

#[test]
fn test_reply_learned_prefers_live_mesh_route_over_session_degraded_direct_peer() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let direct_link = LinkId::new(1);
    let (direct_conn, direct_id) =
        make_completed_connection(&mut node, direct_link, transport_id, 1000);
    let dest_addr = *direct_id.node_addr();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_id, 2000)
        .unwrap();

    let mesh_link = LinkId::new(2);
    let (mesh_conn, mesh_id) = make_completed_connection(&mut node, mesh_link, transport_id, 1000);
    let mesh_next_hop = *mesh_id.node_addr();
    node.add_connection(mesh_conn).unwrap();
    node.promote_connection(mesh_link, mesh_id, 2000).unwrap();
    node.learn_reverse_route(dest_addr, mesh_next_hop);

    let direct = node.find_next_hop(&dest_addr).expect("direct route");
    assert_eq!(
        direct.node_addr(),
        &dest_addr,
        "healthy direct should still win before session loss marks it suspect"
    );

    node.mark_session_direct_path_degraded(dest_addr, Node::now_ms());

    let fallback = node.find_next_hop(&dest_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &mesh_next_hop,
        "session-degraded direct path must not hide learned fallback"
    );

    assert!(node.clear_session_direct_path_degraded(&dest_addr));
    let recovered = node.find_next_hop(&dest_addr).expect("direct route");
    assert_eq!(
        recovered.node_addr(),
        &dest_addr,
        "clearing degradation should make healthy direct eligible again"
    );
}

#[test]
fn test_reply_learned_moves_configured_static_direct_peer_when_session_degraded() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let direct_link = LinkId::new(1);
    let (direct_conn, direct_id) =
        make_completed_connection(&mut node, direct_link, transport_id, 1000);
    let dest_addr = *direct_id.node_addr();
    let dest_npub = direct_id.npub();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_id, 2000)
        .unwrap();
    node.config.peers.push(crate::config::PeerConfig::new(
        dest_npub,
        "udp",
        "127.0.0.1:5000",
    ));
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);

    let mesh_link = LinkId::new(2);
    let (mesh_conn, mesh_id) = make_completed_connection(&mut node, mesh_link, transport_id, 1000);
    let mesh_next_hop = *mesh_id.node_addr();
    node.add_connection(mesh_conn).unwrap();
    node.promote_connection(mesh_link, mesh_id, 2000).unwrap();
    node.learn_reverse_route(dest_addr, mesh_next_hop);

    let now_ms = Node::now_ms();
    node.mark_session_direct_path_degraded(dest_addr, now_ms);
    assert!(
        node.session_direct_path_is_degraded(&dest_addr, now_ms),
        "raw session degradation marker should remain visible"
    );
    assert!(
        node.session_direct_path_blocks_direct_payload(&dest_addr, now_ms),
        "session loss on a configured static UDP path should still block direct payload when fallback exists"
    );

    let fallback = node.find_next_hop(&dest_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &mesh_next_hop,
        "session loss on an explicit static path must not blackhole payload when a learned fallback is available"
    );
}

#[test]
fn test_reply_learned_keeps_configured_static_direct_peer_over_lower_cost_fallback() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let direct_link = LinkId::new(1);
    let (direct_conn, direct_id) =
        make_completed_connection(&mut node, direct_link, transport_id, 1000);
    let dest_addr = *direct_id.node_addr();
    let dest_npub = direct_id.npub();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_id, 2000)
        .unwrap();
    node.config.peers.push(crate::config::PeerConfig::new(
        dest_npub,
        "udp",
        "127.0.0.1:5000",
    ));
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);

    let mesh_link = LinkId::new(2);
    let (mesh_conn, mesh_id) = make_completed_connection(&mut node, mesh_link, transport_id, 1000);
    let mesh_next_hop = *mesh_id.node_addr();
    node.add_connection(mesh_conn).unwrap();
    node.promote_connection(mesh_link, mesh_id, 2000).unwrap();

    seed_dataplane_fmp_srtt_for_test(&mut node, dest_addr, 90);
    seed_dataplane_fmp_srtt_for_test(&mut node, mesh_next_hop, 5);
    node.learn_reverse_route(dest_addr, mesh_next_hop);

    {
        assert!(
            node.get_peer(&dest_addr).expect("direct peer").is_healthy()
                && node.active_peer_uses_configured_static_udp_path(&dest_addr),
            "fixture should model a healthy operator-configured direct UDP path"
        );
        assert!(
            node.dataplane_fmp_link_cost(&mesh_next_hop) < node.dataplane_fmp_link_cost(&dest_addr),
            "fixture should make the learned fallback look cheaper than direct"
        );
    }

    let route = node.find_next_hop(&dest_addr).expect("direct route");
    assert_eq!(
        route.node_addr(),
        &dest_addr,
        "a healthy operator-configured static UDP path must not silently move payload onto a learned fallback"
    );
}

#[test]
fn test_tree_routing_skips_session_degraded_direct_peer_for_payload() {
    let transport_id = TransportId::new(1);

    let (mut node, dest_addr, transit_addr) = (0..64)
        .find_map(|_| {
            let mut node = make_node();
            let my_addr = *node.node_addr();

            let link_a = LinkId::new(1);
            let (conn_a, id_a) = make_completed_connection(&mut node, link_a, transport_id, 1000);
            let peer_a = *id_a.node_addr();
            node.add_connection(conn_a).unwrap();
            node.promote_connection(link_a, id_a, 2000).unwrap();

            let link_b = LinkId::new(2);
            let (conn_b, id_b) = make_completed_connection(&mut node, link_b, transport_id, 1000);
            let peer_b = *id_b.node_addr();
            node.add_connection(conn_b).unwrap();
            node.promote_connection(link_b, id_b, 2000).unwrap();

            let (transit_addr, dest_addr) = if peer_a < peer_b {
                (peer_a, peer_b)
            } else {
                (peer_b, peer_a)
            };
            (transit_addr < my_addr).then_some((node, dest_addr, transit_addr))
        })
        .expect("generated fixture with peer root smaller than local node");

    let now_ms = Node::now_ms();

    // Tree topology:
    //   transit/root
    //      /      \
    //   self     dest
    //
    // The direct dest peer is the closest tree hop (distance 0), but once the
    // direct path is degraded it must not hide the next-best transit hop.
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(transit_addr, transit_addr, 1, now_ms),
        TreeCoordinate::root(transit_addr),
    );
    node.tree_state_mut().set_parent(transit_addr, 1, now_ms);
    node.tree_state_mut().recompute_coords();
    assert_eq!(
        node.tree_state().my_coords().root_id(),
        &transit_addr,
        "fixture should place the local node under the transit/root peer"
    );

    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, transit_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(dest_addr, transit_addr, 1, now_ms),
        dest_coords.clone(),
    );
    node.coord_cache_mut()
        .insert(dest_addr, dest_coords, now_ms);

    let direct = node.find_next_hop(&dest_addr).expect("direct route");
    assert_eq!(
        direct.node_addr(),
        &dest_addr,
        "healthy direct peer should win before path degradation"
    );

    node.mark_session_direct_path_degraded(dest_addr, now_ms);
    assert!(
        node.get_peer(&dest_addr)
            .expect("direct peer should remain tracked")
            .can_send(),
        "degraded direct path should remain probeable"
    );

    let fallback = node.find_next_hop(&dest_addr).expect("tree fallback route");
    assert_eq!(
        fallback.node_addr(),
        &transit_addr,
        "session-degraded direct path must not hide tree fallback"
    );
}

#[test]
fn test_reply_learned_prefers_lower_cost_fallback_over_slow_healthy_direct_peer() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let direct_link = LinkId::new(1);
    let (direct_conn, direct_id) =
        make_completed_connection(&mut node, direct_link, transport_id, 1000);
    let dest_addr = *direct_id.node_addr();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_id, 2000)
        .unwrap();

    let mesh_link = LinkId::new(2);
    let (mesh_conn, mesh_id) = make_completed_connection(&mut node, mesh_link, transport_id, 1000);
    let mesh_next_hop = *mesh_id.node_addr();
    node.add_connection(mesh_conn).unwrap();
    node.promote_connection(mesh_link, mesh_id, 2000).unwrap();

    seed_dataplane_fmp_srtt_for_test(&mut node, dest_addr, 90);
    seed_dataplane_fmp_srtt_for_test(&mut node, mesh_next_hop, 5);
    node.learn_reverse_route(dest_addr, mesh_next_hop);

    assert!(
        node.get_peer(&dest_addr).expect("direct peer").is_healthy(),
        "fixture should keep direct alive; this is route quality, not peer removal"
    );
    let fallback = node.find_next_hop(&dest_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &mesh_next_hop,
        "a much cheaper fallback route should beat a slow but healthy direct NAT path"
    );
}
