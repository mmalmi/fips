use super::*;

// ===== Main Convergence Test =====

/// Integration test: 100 nodes with random connectivity converge to a
/// consistent spanning tree with the correct root.
#[tokio::test]
async fn test_spanning_tree_convergence_100_nodes() {
    let _guard = lock_large_network_test().await;

    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, true).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

// ===== Topology Variant Tests =====

/// Ring topology: 5 nodes in a cycle.
#[tokio::test]
async fn test_spanning_tree_ring() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Star topology: node 0 connected to all others.
#[tokio::test]
async fn test_spanning_tree_star() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (0, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Linear chain: 0-1-2-3-4.
#[tokio::test]
async fn test_spanning_tree_chain() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Two disconnected components: nodes 0-2 and nodes 3-5.
#[tokio::test]
async fn test_spanning_tree_disconnected() {
    let edges: Vec<(usize, usize)> = vec![
        (0, 1),
        (1, 2), // component 1
        (3, 4),
        (4, 5), // component 2
    ];
    let mut nodes = run_tree_test(6, &edges, false).await;
    verify_tree_convergence_components(&nodes, &[vec![0, 1, 2], vec![3, 4, 5]]);
    cleanup_nodes(&mut nodes).await;
}

/// Tests that a node ignores a signed TreeAnnounce whose advertised root is not the smallest node_addr in the ancestry.
#[tokio::test]
async fn test_rejects_tree_announce_with_inconsistent_root() {
    // Start from a healthy 2-node tree so node B already has a normal, trusted
    // view of node A's coordinates.
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let a_addr = *nodes[0].node.node_addr();
    let current_root = *nodes[1].node.tree_state().root();
    let current_depth = nodes[1].node.tree_state().my_coords().depth();
    let peer_coords_before = nodes[1]
        .node
        .get_peer(&a_addr)
        .unwrap()
        .coords()
        .unwrap()
        .clone();
    let accepted_before = nodes[1].node.stats().tree.accepted;

    // Use two fixed synthetic ancestors so the forged path is explicit:
    // - fake_parent = 00000000000000000000000000000000
    // - fake_root   = 00000000000000000000000000000001
    //
    // The forged ancestry is therefore:
    //   [A, 000...000, 000...001]
    //
    // That makes 000...001 the advertised root because it is the final entry,
    // even though 000...000 is smaller and appears earlier in the path.
    let fake_parent = NodeAddr::from_bytes([0u8; 16]);
    let mut fake_root_bytes = [0u8; 16];
    fake_root_bytes[15] = 1;
    let fake_root = NodeAddr::from_bytes(fake_root_bytes);

    // Sign a fresh declaration from A. The 99/12345 values are just a newer
    // sequence/timestamp so the announce would be acceptable on freshness
    // grounds if its ancestry semantics were valid.
    let mut declaration = ParentDeclaration::new(a_addr, fake_parent, 99, 12345);
    declaration.sign(nodes[0].node.identity()).unwrap();

    let announce = TreeAnnounce::new(
        declaration,
        TreeCoordinate::new(vec![
            CoordEntry::new(a_addr, 99, 12345),
            CoordEntry::new(fake_parent, 98, 12344),
            CoordEntry::new(fake_root, 97, 12343),
        ])
        .unwrap(),
    );
    let encoded = announce.encode().unwrap();

    nodes[1]
        .node
        .handle_tree_announce(&a_addr, &encoded[1..])
        .await;

    // B should reject the malformed ancestry before mutating either its local
    // tree state or its cached view of peer A.
    assert_eq!(*nodes[1].node.tree_state().root(), current_root);
    assert_eq!(
        nodes[1].node.tree_state().my_coords().depth(),
        current_depth
    );
    assert_eq!(nodes[1].node.stats().tree.accepted, accepted_before);
    assert_eq!(
        nodes[1].node.get_peer(&a_addr).unwrap().coords().unwrap(),
        &peer_coords_before
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_parent_reeval_ignores_unmeasured_peer_costs() {
    let mut config = Config::new();
    config.node.tree.hold_down_secs = 0;
    config.node.tree.parent_hysteresis = 0.0;
    config.node.tree.reeval_interval_secs = 1;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let (current_conn, current_id) =
        make_completed_connection(&mut node, LinkId::new(1), transport_id, 1_000);
    let current_parent = *current_id.node_addr();
    node.add_connection(current_conn).unwrap();
    node.promote_connection(LinkId::new(1), current_id, 2_000)
        .unwrap();

    let (candidate_conn, candidate_id) =
        make_completed_connection(&mut node, LinkId::new(2), transport_id, 1_000);
    let unmeasured_candidate = *candidate_id.node_addr();
    node.add_connection(candidate_conn).unwrap();
    node.promote_connection(LinkId::new(2), candidate_id, 2_000)
        .unwrap();

    let root = make_node_addr(0);
    let intermediate = make_node_addr(1);
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(current_parent, intermediate, 1, 1_000),
        TreeCoordinate::from_addrs(vec![current_parent, intermediate, root]).unwrap(),
    );
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(unmeasured_candidate, root, 1, 1_000),
        TreeCoordinate::from_addrs(vec![unmeasured_candidate, root]).unwrap(),
    );
    node.tree_state_mut().set_parent(current_parent, 2, 1_000);
    node.tree_state_mut().recompute_coords();

    node.get_peer_mut(&current_parent)
        .expect("current parent peer")
        .mmp_mut()
        .expect("current parent mmp")
        .metrics
        .srtt
        .update(10_000);
    assert!(
        !node
            .get_peer(&unmeasured_candidate)
            .expect("candidate peer")
            .has_srtt(),
        "fixture should leave the candidate without RTT evidence"
    );

    let parent_before = *node.tree_state().my_declaration().parent_id();
    let switches_before = node.stats().tree.parent_switches;

    node.check_tree_state().await;

    assert_eq!(
        node.tree_state().my_declaration().parent_id(),
        &parent_before,
        "periodic parent re-eval must not treat an unmeasured peer as an artificially cheap parent"
    );
    assert_eq!(
        node.stats().tree.parent_switches,
        switches_before,
        "ignored unmeasured candidates must not be counted as parent switches"
    );
}

#[tokio::test]
async fn test_parent_reeval_ignores_fresh_bogus_metrics_without_valid_rtt() {
    let mut config = Config::new();
    config.node.tree.hold_down_secs = 0;
    config.node.tree.parent_hysteresis = 0.0;
    config.node.tree.reeval_interval_secs = 1;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let (current_conn, current_id) =
        make_completed_connection(&mut node, LinkId::new(1), transport_id, 1_000);
    let current_parent = *current_id.node_addr();
    node.add_connection(current_conn).unwrap();
    node.promote_connection(LinkId::new(1), current_id, 2_000)
        .unwrap();

    let (candidate_conn, candidate_id) =
        make_completed_connection(&mut node, LinkId::new(2), transport_id, 1_000);
    let bogus_candidate = *candidate_id.node_addr();
    node.add_connection(candidate_conn).unwrap();
    node.promote_connection(LinkId::new(2), candidate_id, 2_000)
        .unwrap();

    let root = make_node_addr(0);
    let intermediate = make_node_addr(1);
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(current_parent, intermediate, 1, 1_000),
        TreeCoordinate::from_addrs(vec![current_parent, intermediate, root]).unwrap(),
    );
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(bogus_candidate, root, 1, 1_000),
        TreeCoordinate::from_addrs(vec![bogus_candidate, root]).unwrap(),
    );
    node.tree_state_mut().set_parent(current_parent, 2, 1_000);
    node.tree_state_mut().recompute_coords();

    node.get_peer_mut(&current_parent)
        .expect("current parent peer")
        .mmp_mut()
        .expect("current parent mmp")
        .metrics
        .srtt
        .update(10_000);

    let parent_before = *node.tree_state().my_declaration().parent_id();
    let switches_before = node.stats().tree.parent_switches;

    let counter_baseline = ReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: u32::MAX - 10,
        dwell_time: 20,
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
    node.handle_receiver_report(&bogus_candidate, &counter_baseline[1..])
        .await;

    tokio::time::sleep(Duration::from_millis(1)).await;

    let fresh_bogus_delta = ReceiverReport {
        highest_counter: 300,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: u64::MAX,
        timestamp_echo: u32::MAX - 10,
        dwell_time: 20,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: u32::MAX,
        owd_trend: i32::MIN,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: u32::MAX,
        interval_packets_recv: 0,
        interval_bytes_recv: u32::MAX,
    }
    .encode();
    node.handle_receiver_report(&bogus_candidate, &fresh_bogus_delta[1..])
        .await;

    {
        let candidate = node.get_peer(&bogus_candidate).expect("candidate peer");
        let metrics = &candidate.mmp().expect("candidate mmp").metrics;
        assert!(
            !candidate.has_srtt(),
            "invalid RTT samples must not make the candidate parent-eligible"
        );
        assert_eq!(
            metrics.last_forward_loss_sample(),
            Some((200, 1.0)),
            "fixture should exercise a fresh severe-loss sample rather than a stale report"
        );
        assert!(
            metrics.goodput_bps() > 0.0,
            "fixture should exercise a fresh goodput sample rather than a stale report"
        );
    }

    node.check_tree_state().await;

    assert_eq!(
        node.tree_state().my_declaration().parent_id(),
        &parent_before,
        "fresh bogus metrics without valid RTT must not switch parent choice"
    );
    assert_eq!(
        node.stats().tree.parent_switches,
        switches_before,
        "fresh bogus metrics without valid RTT must not count as a parent switch"
    );
}
