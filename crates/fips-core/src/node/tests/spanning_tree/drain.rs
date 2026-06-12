use super::*;

/// Process all currently available packets across all nodes.
///
/// Returns the number of packets processed.
pub(in crate::node::tests) async fn process_available_packets(nodes: &mut [TestNode]) -> usize {
    use crate::node::wire::{
        COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
    };

    let mut count = 0;
    for node in nodes.iter_mut() {
        while let Ok(packet) = node.packet_rx.try_recv() {
            if packet.data.len() < COMMON_PREFIX_SIZE {
                continue;
            }
            if let Some(prefix) = CommonPrefix::parse(&packet.data) {
                if prefix.version != FMP_VERSION {
                    continue;
                }
                match prefix.phase {
                    PHASE_MSG1 => node.node.handle_msg1(packet).await,
                    PHASE_MSG2 => node.node.handle_msg2(packet).await,
                    PHASE_ESTABLISHED => node.node.handle_encrypted_frame(packet).await,
                    _ => {}
                }
                count += 1;
            }
        }
    }
    count
}

/// Drain all packet channels across all nodes until quiescence.
///
/// Processes msg1, msg2, and encrypted frames (including TreeAnnounce)
/// through the appropriate handlers. Handles rate-limited TreeAnnounce
/// messages by waiting for the rate limit window to expire and then
/// flushing pending announces. Returns total packets processed.
///
/// If `verbose` is true, prints tree state snapshots after each phase.
pub(in crate::node::tests) async fn drain_all_packets(
    nodes: &mut [TestNode],
    verbose: bool,
) -> usize {
    let mut total = 0;

    // Phase 1: Fast drain — process packets as fast as they arrive.
    // This handles handshakes (msg1/msg2) and the first wave of TreeAnnounce.
    let mut idle_rounds = 0;
    for _round in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        run_synthetic_node_work(nodes).await;

        let count = process_available_packets(nodes).await;
        total += count;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 3 {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }

    if verbose {
        print_tree_snapshot(
            &format!("After handshakes + initial announces ({} packets)", total),
            nodes,
        );
    }

    // Phase 2: Rate-limit flush cycles. Each cycle waits for rate limits
    // to expire, flushes pending announces, processes resulting packets,
    // and repeats. Each cycle propagates the tree one hop further through
    // rate-limited paths. For a chain of depth D, we need D cycles.
    for flush in 0..20 {
        // Wait for rate limit window (500ms) to fully expire
        tokio::time::sleep(Duration::from_millis(550)).await;

        // Flush pending rate-limited handshakes, tree announces, and filter announces.
        run_synthetic_node_work(nodes).await;

        // Allow flushed packets to arrive
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Process the resulting packets. Processing may trigger new
        // parent switches → new announces, but those to the same peer
        // will be rate-limited again and caught by the next flush cycle.
        let mut flush_total = process_available_packets(nodes).await;

        // Do a few more quick rounds in case packet processing above
        // triggered non-rate-limited sends (to different peers)
        for _sub in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            run_synthetic_node_work(nodes).await;
            let count = process_available_packets(nodes).await;
            flush_total += count;
            if count == 0 {
                break;
            }
        }

        total += flush_total;
        if flush_total == 0 && !has_synthetic_pending_work(nodes) {
            break;
        }

        if verbose {
            print_tree_snapshot(
                &format!("After flush cycle {} ({} packets)", flush + 1, flush_total),
                nodes,
            );
        }
    }

    total
}

pub(in crate::node::tests) async fn drain_initial_handshake_burst(nodes: &mut [TestNode]) -> usize {
    let mut total = 0;
    let mut idle_rounds = 0;

    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        run_synthetic_node_work(nodes).await;

        let count = process_available_packets(nodes).await;
        total += count;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 3 {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }

    total
}
