use super::*;

pub(in crate::node::tests) async fn run_synthetic_node_work(nodes: &mut [TestNode]) {
    let now_ms = Node::now_ms();
    for tn in nodes.iter_mut() {
        tn.node.resend_pending_handshakes(now_ms).await;
        tn.node.send_pending_tree_announces().await;
        tn.node.send_pending_filter_announces().await;
    }
}

pub(in crate::node::tests) fn has_synthetic_pending_work(nodes: &[TestNode]) -> bool {
    nodes.iter().any(|tn| {
        !tn.node.peers.connection_is_empty()
            || tn.node.peers.iter().any(|(addr, peer)| {
                peer.has_pending_tree_announce() || tn.node.bloom_state.needs_update(addr)
            })
    })
}

pub(in crate::node::tests) async fn drain_synthetic_packets_until_idle(
    nodes: &mut [TestNode],
    max_rounds: usize,
    sleep_ms: u64,
) -> usize {
    let mut total = 0;
    let mut idle_rounds = 0;

    for _ in 0..max_rounds {
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        run_synthetic_node_work(nodes).await;

        let count = process_available_packets(nodes).await;
        total += count;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 3 && !has_synthetic_pending_work(nodes) {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }

    total
}

fn has_edge_filter_from(nodes: &[TestNode], receiver: usize, sender: usize) -> bool {
    let sender_addr = *nodes[sender].node.node_addr();
    nodes[receiver]
        .node
        .get_peer(&sender_addr)
        .and_then(|peer| peer.inbound_filter())
        .is_some_and(|filter| filter.contains(&sender_addr))
}

fn missing_edge_filters(nodes: &[TestNode], edges: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut missing = Vec::new();
    for &(i, j) in edges {
        if !has_edge_filter_from(nodes, i, j) {
            missing.push((j, i));
        }
        if !has_edge_filter_from(nodes, j, i) {
            missing.push((i, j));
        }
    }
    missing
}

async fn repair_missing_edge_filters(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
    verbose: bool,
) -> usize {
    let mut resent = 0;

    for attempt in 0..2 {
        let missing = missing_edge_filters(nodes, edges);
        if missing.is_empty() {
            break;
        }

        if verbose {
            eprintln!(
                "  Repairing {} missing synthetic edge filter direction(s), attempt {}",
                missing.len(),
                attempt + 1
            );
        }

        for (sender, receiver) in missing {
            let receiver_addr = *nodes[receiver].node.node_addr();
            nodes[sender]
                .node
                .bloom_state
                .mark_update_needed(receiver_addr);

            // The synthetic transport uses the real native crypto executor and
            // localhost UDP. Under the parallel full suite, both can stay busy
            // after packet_rx is momentarily empty, so an idle-round count is
            // not evidence that this particular announce reached its peer.
            // Send after the test debounce and wait for the receiver's actual
            // accepted filter state before moving to the next missing edge.
            tokio::time::sleep(Duration::from_millis(60)).await;
            if nodes[sender]
                .node
                .send_filter_announce_to_peer(&receiver_addr)
                .await
                .is_ok()
            {
                resent += 1;
            }

            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            while !has_edge_filter_from(nodes, receiver, sender)
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
                run_synthetic_node_work(nodes).await;
                let _ = process_available_packets(nodes).await;
            }
        }
    }

    let missing = missing_edge_filters(nodes, edges);
    if !missing.is_empty() && verbose {
        eprintln!(
            "  Directly injecting {} synthetic edge filter direction(s) after UDP repair",
            missing.len()
        );
    }
    for (sender, receiver) in missing {
        let sender_addr = *nodes[sender].node.node_addr();
        let receiver_addr = *nodes[receiver].node.node_addr();
        let encoded = nodes[sender]
            .node
            .build_filter_announce(&receiver_addr)
            .encode()
            .expect("synthetic FilterAnnounce should encode");
        nodes[receiver]
            .node
            .handle_filter_announce(&sender_addr, &encoded[1..])
            .await;
    }

    let remaining = missing_edge_filters(nodes, edges);
    if !remaining.is_empty() {
        let examples: Vec<String> = remaining
            .iter()
            .take(8)
            .map(|(sender, receiver)| format!("{}->{}", sender, receiver))
            .collect();
        eprintln!(
            "  Synthetic filter repair left {} missing edge direction(s): {}",
            remaining.len(),
            examples.join(", ")
        );
    }
    assert!(
        remaining.is_empty(),
        "synthetic topology did not establish every edge filter: {}",
        remaining
            .iter()
            .map(|(sender, receiver)| format!("{}->{}", sender, receiver))
            .collect::<Vec<_>>()
            .join(", ")
    );

    resent
}

pub(in crate::node::tests) async fn refresh_synthetic_filter_announces(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
    verbose: bool,
) -> usize {
    let mut total = 0;

    for _ in 0..4 {
        for tn in nodes.iter_mut() {
            tn.node.send_tree_announce_to_all().await;
        }
        total += drain_synthetic_packets_until_idle(nodes, 80, 10).await;
    }

    for _ in 0..4 {
        for tn in nodes.iter_mut() {
            let peers: Vec<NodeAddr> = tn.node.peers.keys().copied().collect();
            tn.node.bloom_state.mark_all_updates_needed(peers);
        }
        total += drain_synthetic_packets_until_idle(nodes, 80, 10).await;
    }

    total += repair_missing_edge_filters(nodes, edges, verbose).await;

    total
}
