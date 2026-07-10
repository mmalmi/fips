use super::*;

/// Process all currently available packets across all nodes.
///
/// Returns the number of packets processed.
pub(in crate::node::tests) async fn process_available_packets(nodes: &mut [TestNode]) -> usize {
    let mut count = 0;
    for node in nodes.iter_mut() {
        while let Ok(packet) = node.packet_rx.try_recv() {
            count += process_dataplane_packet(node, packet).await;
        }
        count += process_dataplane_side_queues(node).await;
    }
    count
}

async fn process_dataplane_packet(node: &mut TestNode, packet: ReceivedPacket) -> usize {
    process_dataplane_turn(node, Some(packet), 64).await
}

async fn process_dataplane_side_queues(node: &mut TestNode) -> usize {
    process_dataplane_turn(node, None, 0).await
}

async fn process_dataplane_turn(
    node: &mut TestNode,
    first_packet: Option<ReceivedPacket>,
    packet_limit: usize,
) -> usize {
    let (_packet_tx, mut empty_packet_rx) = crate::transport::packet_channel(1);
    let (_endpoint_tx, mut dummy_endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut dummy_tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (_fast_tx, mut dummy_fast_ingress_rx) = tokio::sync::mpsc::channel(1);
    let (dummy_endpoint_tx, _dummy_endpoint_rx) = crate::node::EndpointEventSender::channel(1);

    let mut endpoint_rx_slot = node.node.endpoint_data_rx.take();
    let mut tun_outbound_rx_slot = node.node.tun_outbound_rx.take();

    let endpoint_rx = match endpoint_rx_slot.as_mut() {
        Some(rx) => rx,
        None => &mut dummy_endpoint_rx,
    };
    let tun_outbound_rx = match tun_outbound_rx_slot.as_mut() {
        Some(rx) => rx,
        None => &mut dummy_tun_outbound_rx,
    };
    let endpoint_tx = node
        .node
        .endpoint_events
        .sender()
        .unwrap_or(dummy_endpoint_tx);

    let mut turn = {
        let mut dataplane_io = crate::node::handlers::rx_loop_dataplane_io(
            &mut empty_packet_rx,
            &mut dummy_fast_ingress_rx,
            endpoint_rx,
            tun_outbound_rx,
            &endpoint_tx,
        );
        node.node
            .drain_dataplane_turn_with_firsts(
                &mut dataplane_io,
                crate::dataplane::DataplaneLiveTurnFirsts {
                    raw_packet: first_packet,
                    ..Default::default()
                },
                crate::node::handlers::RxLoopDataplaneTurnLimits::new(packet_limit, 64, 64, 64),
            )
            .await
    };
    let mut active_turns = 0usize;
    let had_activity = turn.has_activity();
    let mut dispatched = turn.summary().dispatched();
    let processed = node.node.process_dataplane_control_ingress(&mut turn).await;
    if had_activity || processed > 0 {
        active_turns = active_turns.saturating_add(1);
    }

    for _ in 0..4 {
        if dispatched == 0 {
            break;
        }
        let notify = node.node.dataplane.readiness_notify();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), notify.notified()).await;

        let mut completion_turn = {
            let mut dataplane_io = crate::node::handlers::rx_loop_dataplane_io(
                &mut empty_packet_rx,
                &mut dummy_fast_ingress_rx,
                endpoint_rx,
                tun_outbound_rx,
                &endpoint_tx,
            );
            node.node
                .drain_dataplane_turn_with_firsts(
                    &mut dataplane_io,
                    crate::dataplane::DataplaneLiveTurnFirsts::default(),
                    crate::node::handlers::RxLoopDataplaneTurnLimits::new(0, 64, 64, 64),
                )
                .await
        };
        let completion_had_activity = completion_turn.has_activity();
        dispatched = completion_turn.summary().dispatched();
        let completion_processed = node
            .node
            .process_dataplane_control_ingress(&mut completion_turn)
            .await;
        if completion_had_activity || completion_processed > 0 {
            active_turns = active_turns.saturating_add(1);
        } else {
            break;
        }
    }

    node.node.endpoint_data_rx = endpoint_rx_slot.take();
    node.node.tun_outbound_rx = tun_outbound_rx_slot.take();

    active_turns
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
