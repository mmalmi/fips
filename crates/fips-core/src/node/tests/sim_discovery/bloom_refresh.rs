//! Real encrypted refreshes retain pacing and cancellation ownership.
use super::*;
use crate::node::tests::session::run_large_stack_async_test;
use crate::node::tests::spanning_tree::process_available_packets;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn periodic_bloom_refresh_respects_debounce_and_does_not_cascade() {
    run(Case::Refresh);
}

#[test]
fn canceled_bloom_refresh_retains_selected_and_unvisited_updates() {
    run(Case::Cancellation);
}

#[test]
fn canceled_fast_bloom_turn_preserves_work_and_drains_bounded_data() {
    run(Case::FastCancellation);
}

#[test]
fn canceled_tree_turn_leaves_unvisited_bloom_immediately_due() {
    run(Case::TreeCancellation);
}

#[test]
fn anchor_filter_waits_for_delayed_recipient_acceptance() {
    run(Case::DelayedAnchor);
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Refresh,
    Cancellation,
    FastCancellation,
    TreeCancellation,
    DelayedAnchor,
}

fn run(case: Case) {
    run_large_stack_async_test("bloom-refresh", move || async move {
        let name = format!("bloom-refresh-{}-{case:?}", std::process::id());
        let network = SimNetwork::new(283);
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for address in ["root", "one", "two"] {
            let mut config = Config::new();
            config.node.system_files_enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.local.enabled = false;
            config.node.limits.max_peers = 2;
            config.node.limits.max_connections = 2;
            config.node.limits.max_links = 2;
            config.node.bloom.announce_refresh_interval_secs = 0;
            config.transports.sim = TransportInstances::Single(SimTransportConfig {
                network: Some(name.clone()),
                addr: Some(address.to_string()),
                auto_connect: Some(false),
                ..Default::default()
            });
            nodes.push(configured_discovering_node(config, address).await);
        }
        nodes.sort_by_key(|node| *node.node.node_addr());
        let result = AssertUnwindSafe(async {
            setup(&mut nodes).await;
            let owners = owners(&nodes);
            match case {
                Case::Refresh => unchanged(&mut nodes).await,
                Case::Cancellation => cancellation(&mut nodes, &network).await,
                Case::FastCancellation => fast_cancellation(&mut nodes, &network, false).await,
                Case::TreeCancellation => fast_cancellation(&mut nodes, &network, true).await,
                Case::DelayedAnchor => delayed_anchor(&mut nodes, &network).await,
            }
            assert_eq!(
                self::owners(&nodes),
                owners,
                "refresh preserves all Noise owners"
            );
        })
        .catch_unwind()
        .await;
        for node in &nodes {
            network.set_node_send_completion_delay(node.addr.as_str().unwrap(), 0);
        }
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

fn owners(nodes: &[TestNode]) -> Vec<(LinkId, Option<SessionIndex>, u64)> {
    [(0, 1), (1, 0), (0, 2), (2, 0)]
        .into_iter()
        .map(|(local, remote)| {
            let peer = nodes[local]
                .node
                .get_peer(nodes[remote].node.node_addr())
                .unwrap();
            (peer.link_id(), peer.our_index(), peer.authenticated_at())
        })
        .collect()
}

async fn turn(nodes: &mut [TestNode]) {
    process_available_packets(nodes).await;
    for node in nodes.iter_mut() {
        node.node.check_mmp_reports().await;
        node.node.check_tree_state().await;
        node.node.send_pending_tree_announces().await;
        node.node.check_bloom_state().await;
    }
    process_available_packets(nodes).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
}

async fn setup(nodes: &mut [TestNode]) {
    for remote in [1, 2] {
        let identity = PeerIdentity::from_pubkey_full(nodes[remote].node.identity().pubkey_full());
        let address = nodes[remote].addr.clone();
        let transport = nodes[0].transport_id;
        nodes[0]
            .node
            .initiate_connection(transport, address, identity)
            .await
            .unwrap();
    }
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    let until = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut settled = None;
    loop {
        turn(nodes).await;
        let ready = nodes[0].node.peers.len() == 2
            && [1, 2].into_iter().all(|leaf| {
                nodes[leaf]
                    .node
                    .get_peer(&ids[0])
                    .is_some_and(|peer| peer.may_reach(&ids[3 - leaf]))
            })
            && nodes.iter().all(|node| {
                *node.node.tree_state().root() == ids[0]
                    && node.node.peers.connection_is_empty()
                    && node.node.peers.iter().all(|(peer, active)| {
                        !node.node.bloom_state.needs_update(peer)
                            && !active.has_pending_tree_announce()
                    })
            });
        if ready {
            let since = settled.get_or_insert_with(tokio::time::Instant::now);
            if since.elapsed() >= Duration::from_millis(100) {
                break;
            }
        } else {
            settled = None;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "real Noise/tree/filter setup"
        );
    }
}

async fn anchor_filter(nodes: &mut [TestNode], sender: usize, remotes: &[usize]) {
    let before = nodes[sender].node.stats().bloom.sent;
    let sender_id = *nodes[sender].node.node_addr();
    let watermark = nodes[sender].node.bloom_state.sequence();
    for &remote in remotes {
        let peer = *nodes[remote].node.node_addr();
        nodes[sender].node.bloom_state.mark_update_needed(peer);
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    while nodes[sender].node.stats().bloom.sent < before + remotes.len() as u64
        || remotes.iter().any(|&remote| {
            nodes[remote]
                .node
                .get_peer(&sender_id)
                .unwrap()
                .filter_sequence()
                <= watermark
        })
    {
        turn(nodes).await;
        assert!(
            tokio::time::Instant::now() < until,
            "paced real anchor send and recipient acceptance"
        );
    }
}

async fn delayed_anchor(nodes: &mut [TestNode], network: &SimNetwork) {
    let sender = *nodes[0].node.node_addr();
    let watermark = nodes[0].node.bloom_state.sequence();
    for remote in [1, 2] {
        network.set_directed_link(
            nodes[0].addr.as_str().unwrap(),
            nodes[remote].addr.as_str().unwrap(),
            Some(SimLink {
                latency_ms: 400,
                ..SimLink::default()
            }),
        );
    }
    anchor_filter(nodes, 0, &[1, 2]).await;
    let received: Vec<_> = nodes[1..]
        .iter()
        .map(|node| node.node.get_peer(&sender).unwrap().filter_sequence())
        .collect();
    assert!(
        received.iter().all(|sequence| *sequence > watermark),
        "anchor baseline requires accepted delivery: watermark={watermark}, received={received:?}, sent={}, wire={:?}",
        nodes[0].node.stats().bloom.sent,
        network.stats(),
    );
}

async fn unchanged(nodes: &mut [TestNode]) {
    anchor_filter(nodes, 1, &[0]).await;
    let root = *nodes[0].node.node_addr();
    let leaf = *nodes[1].node.node_addr();
    let before: Vec<_> = nodes
        .iter()
        .map(|node| node.node.stats().bloom.sent)
        .collect();
    let peer = nodes[0].node.get_peer(&leaf).unwrap();
    let sequence = peer.filter_sequence();
    let filter = peer.inbound_filter().unwrap().clone();
    nodes[1]
        .node
        .config
        .node
        .bloom
        .announce_refresh_interval_secs = 1;
    nodes[1].node.bloom_state.set_update_debounce_ms(1_500);
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    while !nodes[1]
        .node
        .bloom_state
        .refresh_due(&root, Node::now_ms(), 1_000)
    {
        turn(nodes).await;
        assert!(tokio::time::Instant::now() < until);
    }
    nodes[1].node.check_bloom_state().await;
    assert_eq!(
        nodes[1].node.stats().bloom.sent,
        before[1],
        "refresh cannot bypass debounce"
    );
    assert!(nodes[1].node.bloom_state.needs_update(&root));
    while nodes[0].node.get_peer(&leaf).unwrap().filter_sequence() == sequence {
        turn(nodes).await;
        assert!(
            tokio::time::Instant::now() < until,
            "real refresh accepted with a fresh sequence"
        );
    }
    assert_eq!(nodes[1].node.stats().bloom.sent, before[1] + 1);
    assert_eq!(
        nodes[0].node.get_peer(&leaf).unwrap().inbound_filter(),
        Some(&filter)
    );
    nodes[1]
        .node
        .config
        .node
        .bloom
        .announce_refresh_interval_secs = 0;
    let quiet = tokio::time::Instant::now() + Duration::from_millis(1_600);
    while tokio::time::Instant::now() < quiet {
        turn(nodes).await;
    }
    assert_eq!(
        nodes[0].node.stats().bloom.sent,
        before[0],
        "unchanged receipt cannot cascade to other leaf"
    );
    assert_eq!(nodes[2].node.stats().bloom.sent, before[2]);
    assert_eq!(
        nodes[1].node.stats().bloom.sent,
        before[1] + 1,
        "disabled refresh stays quiet"
    );
    assert!(nodes.iter().all(|node| {
        node.node
            .peers
            .keys()
            .all(|peer| !node.node.bloom_state.needs_update(peer))
    }));
}

async fn cancellation(nodes: &mut [TestNode], network: &SimNetwork) {
    anchor_filter(nodes, 0, &[1, 2]).await;
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    let sequences: Vec<_> = [1, 2]
        .into_iter()
        .map(|leaf| {
            nodes[leaf]
                .node
                .get_peer(&ids[0])
                .unwrap()
                .filter_sequence()
        })
        .collect();
    nodes[0]
        .node
        .config
        .node
        .bloom
        .announce_refresh_interval_secs = 1;
    // Isolate cancellation at a due maintenance batch; real elapsed time supplies
    // eligibility, and the Sim completion fault acts after actual wire delivery.
    while ![1, 2].into_iter().all(|leaf| {
        nodes[0]
            .node
            .bloom_state
            .refresh_due(&ids[leaf], Node::now_ms(), 1_000)
    }) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let before = network.stats().packets_delivered;
    let sent = nodes[0].node.stats().bloom.sent;
    let source = nodes[0].addr.as_str().unwrap().to_owned();
    network.set_node_send_completion_delay(&source, 60_000);
    {
        let operation = nodes[0].node.check_bloom_state();
        tokio::pin!(operation);
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = &mut operation => panic!("send must await delayed completion"),
                _ = async {
                    while network.stats().packets_delivered == before {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                } => {}
            }
        })
        .await
        .expect("real encrypted refresh reaches one peer");
        // Drop the unfinished future as the production maintenance timebox does.
    }
    network.set_node_send_completion_delay(&source, 0);
    assert_eq!(network.stats().packets_delivered, before + 1);
    assert_eq!(
        nodes[0].node.stats().bloom.sent,
        sent,
        "incomplete send cannot commit history"
    );
    for peer in &ids[1..] {
        assert!(nodes[0].node.bloom_state.needs_update(peer));
        assert!(
            nodes[0]
                .node
                .bloom_state
                .refresh_due(peer, Node::now_ms(), 1_000)
        );
    }
    process_available_packets(nodes).await;
    assert_eq!(
        [1, 2]
            .into_iter()
            .filter(|leaf| {
                nodes[*leaf]
                    .node
                    .get_peer(&ids[0])
                    .unwrap()
                    .filter_sequence()
                    > sequences[*leaf - 1]
            })
            .count(),
        1,
        "only selected recipient saw the cancelled flight"
    );

    nodes[0].node.check_bloom_state().await;
    assert_eq!(
        nodes[0].node.stats().bloom.sent,
        sent + 2,
        "resume preserves both selected and unvisited work"
    );
    nodes[0].node.check_bloom_state().await;
    assert_eq!(
        nodes[0].node.stats().bloom.sent,
        sent + 2,
        "committed history prevents another refresh"
    );
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        process_available_packets(nodes).await;
        if [1, 2].into_iter().all(|leaf| {
            nodes[leaf]
                .node
                .get_peer(&ids[0])
                .unwrap()
                .filter_sequence()
                > sequences[leaf - 1]
        }) {
            break;
        }
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    for peer in &ids[1..] {
        assert!(!nodes[0].node.bloom_state.needs_update(peer));
        assert!(
            !nodes[0]
                .node
                .bloom_state
                .refresh_due(peer, Node::now_ms(), 1_000)
        );
    }
}

async fn fast_cancellation(nodes: &mut [TestNode], network: &SimNetwork, tree_first: bool) {
    anchor_filter(nodes, 0, &[1, 2]).await;
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    let sequences: Vec<_> = [1, 2]
        .into_iter()
        .map(|leaf| {
            nodes[leaf]
                .node
                .get_peer(&ids[0])
                .unwrap()
                .filter_sequence()
        })
        .collect();
    // Request an ordinary update after actual successful sends. No history or
    // clock is seeded; the existing debounce expires in real elapsed time.
    nodes[0]
        .node
        .bloom_state
        .mark_all_updates_needed(ids[1..].iter().copied());
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    while nodes[0]
        .node
        .bloom_state
        .pending_peers_due(Node::now_ms())
        .len()
        != 2
    {
        assert!(
            tokio::time::Instant::now() < until,
            "real successful-send debounce expires"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let source = nodes[0].addr.as_str().unwrap().to_owned();
    let sent = nodes[0].node.stats().bloom.sent;
    let tree_received: u64 = nodes[1..]
        .iter()
        .map(|node| node.node.stats().tree.received)
        .sum();
    nodes[0]
        .node
        .assert_canceled_routing_turn_drains_data(network, &source, tree_first)
        .await;
    process_available_packets(nodes).await;
    if tree_first {
        assert_eq!(
            nodes[1..]
                .iter()
                .map(|node| node.node.stats().tree.received)
                .sum::<u64>(),
            tree_received + 1,
            "the canceled tree frame is received by exactly one native peer"
        );
    } else {
        assert_eq!(
            [1, 2]
                .into_iter()
                .filter(|leaf| {
                    nodes[*leaf]
                        .node
                        .get_peer(&ids[0])
                        .unwrap()
                        .filter_sequence()
                        > sequences[*leaf - 1]
                })
                .count(),
            1,
            "the selected canceled frame is genuine; the other peer was unvisited"
        );
        let retry = nodes[0]
            .node
            .bloom_state
            .pending_update_deadline_ms()
            .unwrap();
        let until = tokio::time::Instant::now() + Duration::from_secs(2);
        while Node::now_ms() < retry {
            assert!(
                tokio::time::Instant::now() < until,
                "bounded fresh retry floor"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        nodes[0].node.send_due_filter_announces().await;
    }
    assert_eq!(nodes[0].node.stats().bloom.sent, sent + 2);
    assert_eq!(nodes[0].node.bloom_state.pending_update_deadline_ms(), None);
    nodes[0].node.send_due_filter_announces().await;
    assert_eq!(
        nodes[0].node.stats().bloom.sent,
        sent + 2,
        "no duplicate retry"
    );
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        process_available_packets(nodes).await;
        if [1, 2].into_iter().all(|leaf| {
            nodes[leaf]
                .node
                .get_peer(&ids[0])
                .unwrap()
                .filter_sequence()
                > sequences[leaf - 1]
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "both retained updates arrive"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
