use super::*;

fn edge_peer_state(nodes: &[TestNode], i: usize, j: usize) -> (bool, bool) {
    let j_addr = *nodes[j].node.node_addr();
    let i_addr = *nodes[i].node.node_addr();
    (
        nodes[i].node.get_peer(&j_addr).is_some(),
        nodes[j].node.get_peer(&i_addr).is_some(),
    )
}

fn missing_edge_handshakes(
    nodes: &[TestNode],
    edges: &[(usize, usize)],
) -> Vec<(usize, usize, bool, bool)> {
    let mut missing = Vec::new();
    for &(i, j) in edges {
        let (i_has_j, j_has_i) = edge_peer_state(nodes, i, j);
        if !i_has_j || !j_has_i {
            missing.push((i, j, i_has_j, j_has_i));
        }
    }
    missing
}

fn clear_edge_state(nodes: &mut [TestNode], from: usize, to: usize) {
    let transport_id = nodes[from].transport_id;
    let remote_addr = nodes[to].addr.clone();
    let remote_node_addr = *nodes[to].node.node_addr();

    nodes[from].node.remove_active_peer(&remote_node_addr);

    let stale_link_ids: Vec<LinkId> = nodes[from]
        .node
        .links
        .iter()
        .filter_map(|(link_id, link)| {
            (link.transport_id() == transport_id && link.remote_addr() == &remote_addr)
                .then_some(*link_id)
        })
        .collect();

    for link_id in stale_link_ids {
        if let Some(conn) = nodes[from].node.peers.remove_connection(&link_id)
            && let Some(idx) = conn.our_index()
        {
            nodes[from]
                .node
                .pending_outbound
                .remove(&(transport_id, idx.as_u32()));
            nodes[from]
                .node
                .deregister_session_index((transport_id, idx.as_u32()));
            let _ = nodes[from].node.index_allocator.free(idx);
        }
        nodes[from].node.remove_link(&link_id);
    }

    nodes[from]
        .node
        .links
        .remove_addr(&(transport_id, remote_addr));

    let live_connection_ids: std::collections::HashSet<LinkId> =
        nodes[from].node.peers.connection_keys().copied().collect();
    nodes[from]
        .node
        .pending_outbound
        .retain(|_, link_id| live_connection_ids.contains(link_id));
}

/// Repair synthetic test edges whose one-shot UDP handshake packet was dropped.
///
/// The large topology tests create 250 links by sending exactly one msg1 per
/// edge, bypassing the normal node reconnect timers. On slower CI runners that
/// burst can still drop a localhost UDP datagram, so retry only edges that did
/// not produce bidirectional peers before asserting tree/session behavior. The
/// retry path drains after each edge instead of sending a second burst, since
/// the repair is meant to remove harness pressure rather than recreate it.
pub(in crate::node::tests) async fn repair_missing_edge_handshakes(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
    verbose: bool,
) -> usize {
    let mut retries = 0;

    for attempt in 0..4 {
        let mut missing = missing_edge_handshakes(nodes, edges);

        if missing.is_empty() {
            break;
        }

        if attempt > 0 {
            let backoff_ms = 25 * (attempt as u64).min(8);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            let _ = drain_synthetic_packets_until_idle(nodes, 80, 10).await;
            missing = missing_edge_handshakes(nodes, edges);
            if missing.is_empty() {
                break;
            }
        }

        if verbose {
            eprintln!(
                "  Repairing {} missing/asymmetric synthetic edge handshake(s), attempt {}",
                missing.len(),
                attempt + 1
            );
        }

        for (i, j, _, _) in missing {
            if edge_peer_state(nodes, i, j) == (true, true) {
                continue;
            }

            for (from, to) in [(i, j), (j, i)] {
                let (i_has_j, j_has_i) = edge_peer_state(nodes, i, j);
                if i_has_j && j_has_i {
                    break;
                }

                // Asymmetric peers can preserve stale cross-connection/link
                // state on the side that did promote. Rebuild both directions
                // before each one-way retry so the handshake starts from one
                // consistent edge state instead of layering a cross-connection
                // on top of a stale half-edge.
                clear_edge_state(nodes, i, j);
                clear_edge_state(nodes, j, i);
                let _ = drain_synthetic_packets_until_idle(nodes, 20, 5).await;

                complete_direct_handshake(nodes, from, to).await;
                retries += 1;
                let _ = drain_synthetic_packets_until_idle(nodes, 120, 10).await;
            }
        }
    }

    let _ = drain_synthetic_packets_until_idle(nodes, 360, 10).await;

    let remaining = missing_edge_handshakes(nodes, edges);
    if !remaining.is_empty() {
        let examples: Vec<String> = remaining
            .iter()
            .take(8)
            .map(|(i, j, i_has_j, j_has_i)| {
                format!("{}-{} i_has_j={} j_has_i={}", i, j, i_has_j, j_has_i)
            })
            .collect();
        eprintln!(
            "  Synthetic handshake repair left {} missing/asymmetric edge(s): {}",
            remaining.len(),
            examples.join(", ")
        );
    }

    retries
}
