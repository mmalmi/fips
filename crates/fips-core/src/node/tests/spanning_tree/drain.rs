use super::*;

/// Process all currently available packets across all nodes.
///
/// Returns the number of packets processed.
pub(in crate::node::tests) async fn process_available_packets(nodes: &mut [TestNode]) -> usize {
    let mut count = 0;
    for node in nodes.iter_mut() {
        while let Ok(packet) = node.packet_rx.try_recv() {
            count += process_packet_mover2_packet(node, packet).await;
        }
        count += process_packet_mover2_side_queues(node).await;
        count += drain_packet_mover2_completion_turns(node).await;
    }
    count
}

async fn process_packet_mover2_packet(node: &mut TestNode, packet: ReceivedPacket) -> usize {
    process_packet_mover2_turn(node, Some(packet), 64).await
}

async fn process_packet_mover2_side_queues(node: &mut TestNode) -> usize {
    process_packet_mover2_turn(node, None, 0).await
}

async fn drain_packet_mover2_completion_turns(node: &mut TestNode) -> usize {
    let mut count = 0usize;
    for _ in 0..8 {
        if node.node.packet_mover2.pending_aead_work() == 0
            && !node.node.packet_mover2.has_ready_aead_completions()
        {
            break;
        }
        let _ = node
            .node
            .packet_mover2
            .wait_for_aead_completion(Duration::from_millis(10))
            .await;
        count += process_packet_mover2_side_queues(node).await;
    }
    count
}

async fn process_packet_mover2_turn(
    node: &mut TestNode,
    first_packet: Option<ReceivedPacket>,
    packet_limit: usize,
) -> usize {
    let (_packet_tx, mut empty_packet_rx) = crate::transport::packet_channel(1);
    let (_endpoint_priority_tx, mut dummy_endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_tx, mut dummy_endpoint_rx) = tokio::sync::mpsc::channel(1);
    let (_tun_outbound_tx, mut dummy_tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (dummy_tun_tx, _dummy_tun_rx) = crate::upper::tun::write_channel();
    let (dummy_endpoint_tx, _dummy_endpoint_rx) = crate::node::EndpointEventSender::channel(1);

    let mut endpoint_priority_rx_slot = node.node.endpoint_priority_command_rx.take();
    let mut endpoint_rx_slot = node.node.endpoint_command_rx.take();
    let mut tun_outbound_rx_slot = node.node.tun_outbound_rx.take();

    let endpoint_priority_rx = match endpoint_priority_rx_slot.as_mut() {
        Some(rx) => rx,
        None => &mut dummy_endpoint_priority_rx,
    };
    let endpoint_rx = match endpoint_rx_slot.as_mut() {
        Some(rx) => rx,
        None => &mut dummy_endpoint_rx,
    };
    let tun_outbound_rx = match tun_outbound_rx_slot.as_mut() {
        Some(rx) => rx,
        None => &mut dummy_tun_outbound_rx,
    };
    let tun_tx = node.node.tun_tx.clone().unwrap_or(dummy_tun_tx);
    let endpoint_tx = node
        .node
        .endpoint_events
        .sender()
        .unwrap_or(dummy_endpoint_tx);

    let mut turn = node
        .node
        .drain_packet_mover2_turn_with_first(
            &mut empty_packet_rx,
            first_packet,
            packet_limit,
            endpoint_priority_rx,
            endpoint_rx,
            64,
            tun_outbound_rx,
            64,
            &tun_tx,
            &endpoint_tx,
            64,
        )
        .await;
    let had_activity = turn.has_activity();
    let processed = node
        .node
        .process_packet_mover2_control_ingress(&mut turn)
        .await;

    node.node.endpoint_priority_command_rx = endpoint_priority_rx_slot.take();
    node.node.endpoint_command_rx = endpoint_rx_slot.take();
    node.node.tun_outbound_rx = tun_outbound_rx_slot.take();

    usize::from(had_activity || processed > 0)
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
