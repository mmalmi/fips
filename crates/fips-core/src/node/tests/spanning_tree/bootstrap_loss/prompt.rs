//! Lost bootstrap must not require the five-second periodic repair interval.
use super::*;

#[tokio::test]
async fn measured_neighbors_repair_lost_bootstrap_before_periodic_refresh() {
    prompt_repair(false).await;
}

#[tokio::test]
async fn missing_root_repairs_via_stale_signed_disagreement_before_periodic_refresh() {
    prompt_repair(true).await;
}

/// Deliver the child's original self-root declaration, but lose every root
/// announcement, including the ordinary rate-limited disagreement response.
async fn discard_root_bootstrap(nodes: &mut [TestNode]) {
    let root = *nodes[0].node.node_addr();
    let child = *nodes[1].node.node_addr();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut quiet_since = Instant::now();
    let mut lost_encrypted = 0;
    let mut discarded_msg2 = 0;
    let mut observed_sent = nodes[0].node.stats().tree.sent;
    let mut lost_after_repush = 0;
    let (_empty_tx, mut empty_rx) = packet_channel(1);
    loop {
        while let Ok(packet) = nodes[1].packet_rx.try_recv() {
            let phase = CommonPrefix::parse(packet.data.as_slice()).unwrap().phase;
            assert!(matches!(phase, PHASE_ESTABLISHED | PHASE_MSG2));
            lost_encrypted += usize::from(phase == PHASE_ESTABLISHED);
            if observed_sent >= 2 {
                lost_after_repush += usize::from(phase == PHASE_ESTABLISHED);
            }
            quiet_since = Instant::now();
        }
        while let Ok(packet) = nodes[0].packet_rx.try_recv() {
            match CommonPrefix::parse(packet.data.as_slice()).unwrap().phase {
                // The real handshake helper already processed this queued copy.
                PHASE_MSG2 => discarded_msg2 += 1,
                PHASE_ESTABLISHED => {
                    process_dataplane_packet(&mut nodes[0], packet).await;
                }
                phase => panic!("unexpected bootstrap phase {phase}"),
            }
        }
        nodes[0].node.send_pending_tree_announces().await;
        // Flush completion/control work without consuming the child's lost
        // ingress. A successful send can precede UDP receive-task delivery.
        for node in nodes.iter_mut() {
            process_node_packets(&mut node.node, &mut empty_rx).await;
        }
        let sent = nodes[0].node.stats().tree.sent;
        if sent != observed_sent {
            observed_sent = sent;
            quiet_since = Instant::now();
        }
        if observed_sent >= 2
            && lost_encrypted >= 2
            && lost_after_repush > 0
            && nodes.iter().all(|node| {
                !node.node.dataplane.has_runnable_work()
                    && node.node.deferred_dataplane_control_turns.is_empty()
            })
            && discarded_msg2 > 0
            && !nodes[0]
                .node
                .get_peer(&child)
                .unwrap()
                .has_pending_tree_announce()
            && quiet_since.elapsed() >= Duration::from_millis(100)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "asymmetric bootstrap loss did not complete"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    eprintln!(
        "asymmetric loss premise: sent={observed_sent}, lost_encrypted={lost_encrypted}, lost_after_repush={lost_after_repush}, quiet_ms={}",
        quiet_since.elapsed().as_millis()
    );
    assert!(
        nodes[0]
            .node
            .tree_state()
            .peer_declaration(&child)
            .is_some()
    );
    assert_eq!(*nodes[1].node.tree_state().root(), child);
    assert!(nodes[1].node.tree_state().peer_declaration(&root).is_none());
    assert_eq!(nodes[1].node.stats().tree.received, 0);
    assert_eq!(nodes[1].node.stats().tree.accepted, 0);
    assert!(nodes.iter().all(|node| {
        node.node
            .peers
            .values()
            .all(|peer| !peer.has_pending_tree_announce())
    }));
}

async fn prompt_repair(asymmetric: bool) {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    nodes.sort_by_key(|node| *node.node.node_addr());
    let result = AssertUnwindSafe(async {
        for node in &nodes {
            assert_eq!(node.node.config.node.tree.announce_min_interval_ms, 500);
            assert_eq!(node.node.config.node.tree.announce_refresh_interval_secs, 5);
            assert_eq!(node.node.config.node.tree.reeval_interval_secs, 60);
        }
        Box::pin(complete_direct_handshake(&mut nodes, 0, 1)).await;
        let authenticated = edges(&nodes);
        let initial_sent_ms = nodes.iter().map(|node| node.node.peers.values()
            .next().unwrap().last_tree_announce_sent_ms()).collect::<Vec<_>>();
        if asymmetric {
            discard_root_bootstrap(&mut nodes).await;
        } else {
            discard_bootstrap(&mut nodes).await;
        }
        assert!(!synchronized(&nodes), "lost declaration is the premise");
        let stale_before = nodes[0].node.stats().tree.stale;
        let started = Instant::now();
        let mut next_tick = started + Duration::from_secs(1);
        let mut first_measured = None;
        let mut observed = sent_counts(&nodes);
        let mut timestamps = nodes.iter().map(|node| node.node.peers.values()
            .next().unwrap().last_tree_announce_sent_ms()).collect::<Vec<_>>();
        while started.elapsed() < Duration::from_millis(1_500) {
            process_available_packets(&mut nodes).await;
            // Drive the existing due-report and pending-announcement scheduler
            // seams. Neither creates an announcement merely because we call it.
            for node in &mut nodes {
                node.node.check_mmp_reports().await;
                node.node.send_pending_tree_announces().await;
            }
            if Instant::now() >= next_tick {
                production_tick(&mut nodes).await;
                next_tick += Duration::from_secs(1);
            }
            process_available_packets(&mut nodes).await;
            assert_eq!(edges(&nodes), authenticated, "repair replaced the authenticated edge");
            if measured(&nodes) && first_measured.is_none() {
                first_measured = Some(started.elapsed());
            }
            for (index, node) in nodes.iter().enumerate() {
                let sent = node.node.stats().tree.sent;
                if sent != observed[index] {
                    let timestamp = node.node.peers.values().next().unwrap()
                        .last_tree_announce_sent_ms();
                    assert_eq!(sent, observed[index] + 1, "tree repair burst");
                    assert!(timestamp.saturating_sub(timestamps[index]) >= 500,
                        "repair bypassed the existing per-neighbor rate limit");
                    assert!(timestamp.saturating_sub(initial_sent_ms[index]) < 5_000,
                        "periodic refresh cannot satisfy prompt repair");
                    observed[index] = sent;
                    timestamps[index] = timestamp;
                }
            }
            if synchronized(&nodes) && first_measured.is_some() { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let root = *nodes[0].node.node_addr();
        let child = *nodes[1].node.node_addr();
        let declarations = [
            nodes[0].node.tree_state().peer_declaration(&child).is_some(),
            nodes[1].node.tree_state().peer_declaration(&root).is_some(),
        ];
        let stale = nodes[0].node.stats().tree.stale - stale_before;
        eprintln!("prompt UDP repair asymmetric={asymmetric}: measured_ms={:?}, elapsed_ms={}, declarations={declarations:?}, synchronized={}, sent={observed:?}, stale_disagreement={stale}",
            first_measured.map(|time| time.as_millis()), started.elapsed().as_millis(), synchronized(&nodes));
        assert!(first_measured.is_some(), "real bidirectional MMP feedback must reach this boundary");
        assert!(synchronized(&nodes), "authenticated measured neighbors must repair missing declarations before the five-second refresh");
        if asymmetric {
            assert!(stale > 0, "repair must handle the child's unchanged signed self-root declaration");
        }
        verify_tree_convergence(&nodes);
    }).catch_unwind().await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
