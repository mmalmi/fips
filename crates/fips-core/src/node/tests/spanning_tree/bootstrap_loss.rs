//! Bootstrap loss must recover without a topology reset or synthetic repair.
use super::*;
use crate::node::wire::{CommonPrefix, PHASE_ESTABLISHED, PHASE_MSG2};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::time::Instant;

mod prompt;

#[tokio::test]
async fn lost_initial_udp_announcements_recover_with_one_authenticated_neighbor() {
    exercise(Case::LostBoth).await;
}

#[tokio::test]
async fn lost_child_udp_announcement_recovers_after_child_adopts_the_root() {
    exercise(Case::LostChild).await;
}

#[tokio::test]
async fn synchronized_udp_neighbors_bound_tree_refresh_traffic() {
    exercise(Case::Healthy).await;
}

#[tokio::test]
async fn udp_refresh_disable_and_stricter_peer_rate_limit_are_effective() {
    exercise(Case::RefreshControls).await;
}

#[derive(Debug)]
enum Case {
    LostBoth,
    LostChild,
    Healthy,
    RefreshControls,
}

#[derive(Debug, PartialEq, Eq)]
struct AuthenticatedEdge {
    peer: NodeAddr,
    link: LinkId,
    authenticated_at: u64,
}

fn edges(nodes: &[TestNode]) -> Vec<AuthenticatedEdge> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let remote = *nodes[1 - index].node.node_addr();
            assert_eq!(node.node.peers.len(), 1);
            assert!(node.node.peers.connection_is_empty());
            let peer = node.node.get_peer(&remote).expect("authenticated neighbor");
            assert!(peer.is_healthy() && peer.can_send());
            AuthenticatedEdge {
                peer: remote,
                link: peer.link_id(),
                authenticated_at: peer.authenticated_at(),
            }
        })
        .collect()
}

fn synchronized(nodes: &[TestNode]) -> bool {
    let root = nodes
        .iter()
        .map(|node| *node.node.node_addr())
        .min()
        .unwrap();
    nodes.iter().enumerate().all(|(index, node)| {
        let tree = node.node.tree_state();
        let remote = &nodes[1 - index].node;
        *tree.root() == root
            && tree
                .peer_coords(remote.node_addr())
                .is_some_and(|coords| coords == remote.tree_state().my_coords())
            && tree
                .peer_declaration(remote.node_addr())
                .is_some_and(|decl| {
                    decl.sequence() == remote.tree_state().my_declaration().sequence()
                })
            && !node
                .node
                .get_peer(remote.node_addr())
                .unwrap()
                .has_pending_tree_announce()
    })
}

fn measured(nodes: &[TestNode]) -> bool {
    nodes.iter().enumerate().all(|(index, node)| {
        node.node
            .dataplane_fmp_link_metrics(
                nodes[1 - index].node.node_addr(),
                std::time::Instant::now(),
            )
            .and_then(|metrics| metrics.srtt_ms)
            .is_some_and(|rtt| rtt > 0.0)
    })
}

async fn discard_bootstrap(nodes: &mut [TestNode]) {
    // The real handlers have completed their transport sends. UDP receive tasks
    // can still be delivering that flight; drain to a bounded quiet interval.
    // Discard Msg2 too: replaying the queued copy would bootstrap the peer again.
    let mut encrypted = [0usize; 2];
    let mut msg2 = 0;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut quiet_since = Instant::now();
    loop {
        let mut received = false;
        for (index, node) in nodes.iter_mut().enumerate() {
            while let Ok(packet) = node.packet_rx.try_recv() {
                received = true;
                match CommonPrefix::parse(packet.data.as_slice()).unwrap().phase {
                    PHASE_ESTABLISHED => encrypted[index] += 1,
                    PHASE_MSG2 => msg2 += 1,
                    phase => panic!("unexpected bootstrap phase {phase}"),
                }
            }
        }
        if received {
            quiet_since = Instant::now();
        }
        if encrypted.iter().all(|&count| count > 0)
            && msg2 > 0
            && quiet_since.elapsed() >= Duration::from_millis(100)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "initial UDP flight did not drain"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    for node in nodes {
        assert!(node.node.stats().tree.sent > 0, "real bootstrap was sent");
        assert_eq!(node.node.stats().tree.received, 0);
        assert_eq!(node.node.stats().tree.accepted, 0);
        assert_eq!(node.node.tree_state().peer_count(), 0);
        assert!(node.node.tree_state().is_root());
        assert!(
            node.node
                .peers
                .values()
                .all(|peer| !peer.has_pending_tree_announce()),
            "the lost successful send must not leave an artificial pending retry"
        );
    }
}

async fn production_tick(nodes: &mut [TestNode]) {
    for node in nodes {
        node.node.check_link_heartbeats().await;
        node.node.check_mmp_reports().await;
        node.node.check_tree_state().await;
    }
}

async fn discard_child_announcements(nodes: &mut [TestNode]) {
    let root = *nodes[0].node.node_addr();
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut next_tick = Instant::now() + Duration::from_secs(1);
    let mut encrypted = 0;
    let mut quiet_since = Instant::now();
    loop {
        // Only the child's ingress flight is lost. The root's real encrypted
        // announcement is delivered through the ordinary dataplane below.
        while let Ok(packet) = nodes[0].packet_rx.try_recv() {
            let phase = CommonPrefix::parse(packet.data.as_slice()).unwrap().phase;
            assert!(matches!(phase, PHASE_ESTABLISHED | PHASE_MSG2));
            encrypted += usize::from(phase == PHASE_ESTABLISHED);
            quiet_since = Instant::now();
        }
        let child = &mut nodes[1];
        process_node_packets(&mut child.node, &mut child.packet_rx).await;
        if *nodes[1].node.tree_state().root() == root
            && nodes[1].node.stats().tree.sent >= 2
            && encrypted >= 2
            && !nodes[1]
                .node
                .get_peer(&root)
                .unwrap()
                .has_pending_tree_announce()
            && quiet_since.elapsed() >= Duration::from_millis(100)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child announcement loss premise timed out"
        );
        if Instant::now() >= next_tick {
            production_tick(nodes).await;
            next_tick += Duration::from_secs(1);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(nodes[0].node.stats().tree.received, 0);
    assert_eq!(nodes[0].node.tree_state().peer_count(), 0);
    assert!(nodes[1].node.stats().tree.accepted > 0);
    assert_eq!(
        *nodes[1].node.tree_state().my_declaration().parent_id(),
        root
    );
    assert_eq!(nodes[1].node.tree_state().my_coords().depth(), 1);
}

fn sent_counts(nodes: &[TestNode]) -> Vec<u64> {
    nodes
        .iter()
        .map(|node| node.node.stats().tree.sent)
        .collect()
}

async fn verify_stricter_rate(
    nodes: &mut [TestNode],
    authenticated: &[AuthenticatedEdge],
    next_tick: &mut Instant,
) {
    let before = sent_counts(nodes);
    let mut observed = before.clone();
    let mut timestamps: Vec<_> = nodes
        .iter()
        .map(|node| {
            node.node
                .peers
                .values()
                .next()
                .unwrap()
                .last_tree_announce_sent_ms()
        })
        .collect();
    for node in nodes.iter_mut() {
        node.node.config.node.tree.announce_refresh_interval_secs = 1;
    }
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(6) {
        process_available_packets(nodes).await;
        if Instant::now() >= *next_tick {
            production_tick(nodes).await;
            *next_tick += Duration::from_secs(1);
        }
        assert_eq!(edges(nodes), authenticated);
        assert!(synchronized(nodes));
        for (index, node) in nodes.iter().enumerate() {
            let sent = node.node.stats().tree.sent;
            if sent != observed[index] {
                assert_eq!(sent, observed[index] + 1, "refresh burst on one edge");
                let timestamp = node
                    .node
                    .peers
                    .values()
                    .next()
                    .unwrap()
                    .last_tree_announce_sent_ms();
                assert!(
                    timestamp - timestamps[index] >= 2_000,
                    "one-second refresh bypassed the two-second peer rate limit"
                );
                observed[index] = sent;
                timestamps[index] = timestamp;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let counts: Vec<_> = observed
        .iter()
        .zip(before)
        .map(|(after, before)| after - before)
        .collect();
    assert!(
        counts.iter().all(|&count| count >= 2),
        "enabled refresh must send real frames"
    );
    eprintln!("UDP tree refresh1s/rate2s: six-second refresh counts {counts:?}");
}

async fn exercise(case: Case) {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    nodes.sort_by_key(|node| *node.node.node_addr());
    let result = AssertUnwindSafe(async {
        // This fixture changes handshake retry settings, but the handshake is
        // completed before the experiment. Tree/MMP timing remains production.
        for node in &nodes {
            assert_eq!(node.node.config.node.tick_interval_secs, 1);
            assert_eq!(node.node.config.node.tree.reeval_interval_secs, 60);
            assert_eq!(node.node.config.node.tree.announce_min_interval_ms, 500);
        }
        let controls = matches!(case, Case::RefreshControls);
        if controls {
            // Promotion copies this configured limit to the authenticated peer.
            for node in &mut nodes {
                node.node.config.node.tree.announce_refresh_interval_secs = 0;
                node.node.config.node.tree.announce_min_interval_ms = 2_000;
            }
        }
        Box::pin(complete_direct_handshake(&mut nodes, 0, 1)).await;
        let authenticated = edges(&nodes);
        match case {
            Case::LostBoth => discard_bootstrap(&mut nodes).await,
            Case::LostChild => discard_child_announcements(&mut nodes).await,
            Case::Healthy | Case::RefreshControls => {}
        }

        let started = Instant::now();
        let mut next_tick = started + Duration::from_secs(1);
        while started.elapsed() < Duration::from_secs(8) {
            process_available_packets(&mut nodes).await;
            assert_eq!(edges(&nodes), authenticated, "recovery replaced the edge");
            if synchronized(&nodes) && measured(&nodes) {
                break;
            }
            if Instant::now() >= next_tick {
                production_tick(&mut nodes).await;
                next_tick += Duration::from_secs(1);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            measured(&nodes),
            "real bidirectional MMP RTT must be available"
        );
        assert!(
            synchronized(&nodes),
            "one-neighbor tree must recover lost bootstrap within eight seconds"
        );
        verify_tree_convergence(&nodes);
        let encoded: Vec<_> = nodes
            .iter()
            .map(|node| node.node.build_tree_announce().unwrap().encode().unwrap().len())
            .collect();
        eprintln!(
            "UDP tree {case:?}: synchronized with real RTT after {:.3}s; encoded announcement bytes {encoded:?}",
            started.elapsed().as_secs_f64()
        );

        let sent = sent_counts(&nodes);
        let stable = Instant::now();
        let stable_secs = if controls { 6 } else { 3 };
        while stable.elapsed() < Duration::from_secs(stable_secs) {
            process_available_packets(&mut nodes).await;
            assert_eq!(edges(&nodes), authenticated);
            assert!(
                synchronized(&nodes),
                "stable tree changed without a carrier fault"
            );
            if Instant::now() >= next_tick {
                production_tick(&mut nodes).await;
                next_tick += Duration::from_secs(1);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let counts: Vec<_> = sent_counts(&nodes)
            .iter()
            .zip(sent)
            .map(|(after, before)| after - before)
            .collect();
        for &count in &counts {
            assert!(
                count <= u64::from(!controls),
                "synchronized peers may refresh periodically but must not echo every tick"
            );
        }
        eprintln!("UDP tree {case:?}: {stable_secs}s synchronized refresh counts {counts:?}");
        if controls {
            verify_stricter_rate(&mut nodes, &authenticated, &mut next_tick).await;
        }
    })
    .catch_unwind()
    .await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
