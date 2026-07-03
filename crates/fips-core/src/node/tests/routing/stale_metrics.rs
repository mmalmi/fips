use super::*;

#[tokio::test]
async fn test_stale_mmp_receiver_reports_do_not_change_route_choice() {
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

    let baseline = ReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 0,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
    .encode();
    node.handle_receiver_report(&dest_addr, &baseline[1..])
        .await;

    assert_eq!(
        node.find_next_hop(&dest_addr).map(|peer| *peer.node_addr()),
        Some(dest_addr),
        "healthy direct should initially hide learned fallback"
    );
    assert_eq!(
        node.dataplane_fmp_link_metrics(&dest_addr, std::time::Instant::now())
            .and_then(|metrics| metrics.srtt_ms),
        None,
        "counter-only baseline must not install a route-changing RTT"
    );
    let switches_before = node.stats().tree.parent_switches;

    // If accepted, this duplicate report's stale echo would inflate direct
    // link cost enough for the learned fallback to win.
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let duplicate_with_bogus_rtt = ReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 1,
        dwell_time: 0,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: 0,
        owd_trend: i32::MAX,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
    .encode();
    node.handle_receiver_report(&dest_addr, &duplicate_with_bogus_rtt[1..])
        .await;

    let regressed_with_bogus_goodput = ReceiverReport {
        highest_counter: 90,
        cumulative_packets_recv: 90,
        cumulative_bytes_recv: u64::MAX,
        timestamp_echo: 1,
        dwell_time: 0,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: 0,
        owd_trend: i32::MIN,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: 0,
        interval_packets_recv: u32::MAX,
        interval_bytes_recv: u32::MAX,
    }
    .encode();
    node.handle_receiver_report(&dest_addr, &regressed_with_bogus_goodput[1..])
        .await;

    assert_eq!(
        node.find_next_hop(&dest_addr).map(|peer| *peer.node_addr()),
        Some(dest_addr),
        "bogus stale MMP metrics must not move payload routing to fallback"
    );
    assert_eq!(
        node.stats().tree.parent_switches,
        switches_before,
        "ignored stale MMP metrics must not trigger parent reevaluation"
    );

    let direct_mmp = node
        .dataplane_fmp_link_metrics(&dest_addr, std::time::Instant::now())
        .expect("direct mmp");
    assert_eq!(
        direct_mmp.srtt_ms, None,
        "ignored stale reports must not install an RTT sample"
    );
    assert_eq!(
        direct_mmp.last_forward_loss_sample, None,
        "ignored stale reports must not leave a loss sample behind"
    );
    assert_eq!(
        direct_mmp.goodput_bps, 0.0,
        "ignored stale reports must not update goodput"
    );
    assert!(
        (node.dataplane_fmp_link_cost(&dest_addr) - 1.0).abs() < f64::EPSILON,
        "ignored stale reports must leave default direct link cost unchanged"
    );
}

#[test]
fn test_transit_prefers_adjacent_destination_over_learned_route_back_to_previous_hop() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let previous_link = LinkId::new(1);
    let (previous_conn, previous_id) =
        make_completed_connection(&mut node, previous_link, transport_id, 1000);
    let previous_hop = *previous_id.node_addr();
    node.add_connection(previous_conn).unwrap();
    node.promote_connection(previous_link, previous_id, 2000)
        .unwrap();

    let dest_link = LinkId::new(2);
    let (dest_conn, dest_id) = make_completed_connection(&mut node, dest_link, transport_id, 1000);
    let dest_addr = *dest_id.node_addr();
    node.add_connection(dest_conn).unwrap();
    node.promote_connection(dest_link, dest_id, 2000).unwrap();

    seed_dataplane_fmp_srtt_for_test(&mut node, dest_addr, 90);
    seed_dataplane_fmp_srtt_for_test(&mut node, previous_hop, 5);
    node.learn_reverse_route(dest_addr, previous_hop);

    let source_route = node.find_next_hop(&dest_addr).expect("source fallback");
    assert_eq!(
        source_route.node_addr(),
        &previous_hop,
        "source traffic may prefer a much cheaper learned fallback"
    );

    let transit_route = node
        .find_transit_next_hop(&dest_addr, &previous_hop)
        .expect("adjacent destination route");
    assert_eq!(
        transit_route, dest_addr,
        "a transit node must deliver to its adjacent healthy destination instead of looping back"
    );
}

#[test]
fn test_transit_rejects_learned_route_back_to_previous_hop() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let previous_link = LinkId::new(1);
    let (previous_conn, previous_id) =
        make_completed_connection(&mut node, previous_link, transport_id, 1000);
    let previous_hop = *previous_id.node_addr();
    node.add_connection(previous_conn).unwrap();
    node.promote_connection(previous_link, previous_id, 2000)
        .unwrap();

    let dest_addr = make_node_addr(0xDD);
    node.learn_reverse_route(dest_addr, previous_hop);

    let source_route = node.find_next_hop(&dest_addr).expect("learned route");
    assert_eq!(
        source_route.node_addr(),
        &previous_hop,
        "fixture should expose the learned route that would loop on transit"
    );
    assert!(
        node.find_transit_next_hop(&dest_addr, &previous_hop)
            .is_none(),
        "transit forwarding must not bounce a packet back to the peer it arrived from"
    );
}

// === No route ===

#[test]
fn test_routing_unknown_destination() {
    let mut node = make_node();
    let unknown = make_node_addr(99);
    assert!(node.find_next_hop(&unknown).is_none());
}

// === Bloom filter priority ===

#[test]
fn test_routing_bloom_filter_hit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create two peers
    let link_id1 = LinkId::new(1);
    let (conn1, id1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let peer1_addr = *id1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, id1, 2000).unwrap();

    let link_id2 = LinkId::new(2);
    let (conn2, id2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    let peer2_addr = *id2.node_addr();
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, id2, 2000).unwrap();

    // Set up tree: we are root, both peers are our children
    let peer1_coords = TreeCoordinate::from_addrs(vec![peer1_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer1_addr, my_addr, 1, 1000),
        peer1_coords,
    );
    let peer2_coords = TreeCoordinate::from_addrs(vec![peer2_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer2_addr, my_addr, 1, 1000),
        peer2_coords,
    );

    // Destination not directly connected — placed under peer1 in the tree
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer1_addr, my_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // Add dest to peer1's bloom filter only
    let peer1 = node.get_peer_mut(&peer1_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer1.update_filter(filter, 1, 3000);

    // Should route through peer1 (bloom filter hit, closer to dest)
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer1_addr);

    // Peer2 should NOT be selected (no filter hit)
    assert_ne!(result.unwrap().node_addr(), &peer2_addr);
}

#[test]
fn test_routing_bloom_filter_multiple_hits_tiebreak() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create three peers
    let mut peer_addrs = Vec::new();
    for i in 1..=3 {
        let link_id = LinkId::new(i);
        let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
        let addr = *id.node_addr();
        peer_addrs.push(addr);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, id, 2000).unwrap();
    }

    // Set up tree: we are root, all peers are our children (equidistant)
    for &addr in &peer_addrs {
        let coords = TreeCoordinate::from_addrs(vec![addr, my_addr]).unwrap();
        node.tree_state_mut()
            .update_peer(ParentDeclaration::new(addr, my_addr, 1, 1000), coords);
    }

    // Destination placed under the first peer (arbitrary — all peers are
    // equidistant from dest since dest is 2 hops from root via any child)
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addrs[0], my_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // Add dest to ALL peers' bloom filters
    for &addr in &peer_addrs {
        let peer = node.get_peer_mut(&addr).unwrap();
        let mut filter = BloomFilter::new();
        filter.insert(&dest);
        peer.update_filter(filter, 1, 3000);
    }

    // All peers have equal link_cost (1.0). peer_addrs[0] is closest to dest
    // (distance 1 vs distance 3 for the others). Self-distance check filters
    // peers that aren't strictly closer than us (our distance = 2).
    // peer_addrs[0] has distance 1 (passes), others have distance 3 (filtered).
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer_addrs[0]);
}

// === Greedy tree routing ===
