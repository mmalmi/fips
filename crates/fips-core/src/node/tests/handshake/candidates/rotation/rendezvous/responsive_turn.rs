//! Existing fixture turn, with bounded diagnostic observations.
use super::*;

impl Observation {
    pub(super) async fn turn(&mut self, nodes: &mut [TestNode], ids: &[PeerIdentity]) {
        self.turn_with_endpoint_observer(nodes, ids, |_| {}).await;
    }

    pub(super) async fn turn_with_endpoint_observer(
        &mut self,
        nodes: &mut [TestNode],
        ids: &[PeerIdentity],
        mut observe: impl FnMut(&mut Self),
    ) {
        let mut turn_cost = turn_timing::Capture::new(
            self.started,
            nodes.len() == 20 || self.contact_turn_cost.is_some(),
        );
        if let Some(setup) = &mut self.initial_handshake {
            setup.drive(nodes).await;
        }
        if let Some(payloads) = &mut self.brief_payloads {
            payloads.observe(nodes, ids, self.started);
        }
        for original in &mut self.queued_originals {
            original.observe(nodes, ids, self.started);
        }
        self.timing.observe(nodes, ids, self.started, "turn-entry");
        let scheduled = self.maintenance.next();
        let due = self.maintenance.poll();
        if due.into_iter().any(|due| due) {
            if let Some(phase) = &mut self.contact_phase {
                phase.due(scheduled, self.maintenance.next(), due);
            }
            // Each node still performs one real maintenance turn per second.
            // All endpoints respond; no native request is held or lost.
            self.ticks += 1;
            for (cohort, ready) in due.into_iter().enumerate() {
                self.cohort_ticks[cohort] += usize::from(ready);
            }
            for (i, n) in nodes.iter_mut().enumerate() {
                if !due[i % 2] {
                    continue;
                }
                let before = turn_cost.snapshot(n, i, ids);
                let (_, polls) = turn_timing::measured(turn_cost.enabled(), async {
                    n.node.check_timeouts().await;
                    n.node.check_link_heartbeats().await;
                    let now = Node::now_ms();
                    n.node.resend_pending_handshakes(now).await;
                    n.node.resend_pending_rekeys(now).await;
                    n.node.resend_pending_session_handshakes(now).await;
                    n.node.resend_pending_session_msg3(now).await;
                    n.node.retry_pending_session_traffic().await;
                    n.node.check_mmp_reports().await;
                    n.node.check_session_mmp_reports().await;
                    n.node.check_rekey().await;
                    n.node.check_session_rekey().await;
                    n.node.check_discovery_work(now).await;
                    n.node.poll_pending_connects().await;
                    n.node.process_pending_retries(now).await;
                    let phase_poll = self
                        .contact_phase
                        .as_mut()
                        .and_then(|phase| phase.before_poll(i, &n.node, ids));
                    n.node.poll_transport_discovery().await;
                    if let (Some(phase), Some(before)) = (&mut self.contact_phase, phase_poll) {
                        phase.after_poll(before, &n.node, ids);
                    }
                    n.node.check_tree_state().await;
                    n.node.check_bloom_state().await;
                    n.node.send_pending_tree_announces().await;
                })
                .await;
                turn_cost.record(i, "periodic", before, turn_cost.snapshot(n, i, ids), polls);
            }
            self.incumbents(nodes, ids, None);
            for original in &mut self.queued_originals {
                original.observe(nodes, ids, self.started);
            }
            self.timing
                .observe(nodes, ids, self.started, "maintenance-completed");
            snapshot(
                nodes,
                ids,
                self.started,
                if self.post_deadline_diagnostic {
                    "post-deadline-diagnostic-maintenance"
                } else {
                    "responsive-maintenance"
                },
            );
        }
        // Production also wakes for these deadlines between periodic ticks.
        // Keep the existing policies; the manual fixture must not strand their
        // work until its next one-second maintenance observation.
        for (i, n) in nodes.iter_mut().enumerate() {
            let before = turn_cost.snapshot(n, i, ids);
            let (_, polls) = turn_timing::measured(turn_cost.enabled(), async {
                let now = Node::now_ms();
                if n.node
                    .discovery_work_deadline_ms()
                    .is_some_and(|due| due <= now)
                {
                    n.node.check_discovery_work(now).await;
                }
                if n.node
                    .dataplane
                    .fmp_report_deadline()
                    .is_some_and(|due| due <= std::time::Instant::now())
                {
                    n.node.check_mmp_reports().await;
                }
                if n.node
                    .pending_routing_announce_deadline_ms()
                    .is_some_and(|due| due <= Node::now_ms())
                {
                    n.node.send_pending_tree_announces().await;
                    n.node.send_due_filter_announces().await;
                }
            })
            .await;
            turn_cost.record(i, "due-work", before, turn_cost.snapshot(n, i, ids), polls);
        }
        for destination in 0..nodes.len() {
            for _ in 0..256 {
                let Ok(packet) = nodes[destination].packet_rx.try_recv() else {
                    break;
                };
                let msg1 = (destination < 2)
                    .then(|| Msg1Header::parse(packet.data.as_slice()))
                    .flatten();
                let incoming = msg1.is_some();
                let bridge = incoming && packet.remote_addr == nodes[1 - destination].addr;
                let before_packet = (destination < 2)
                    .then(|| (destination, pending_attempts(&nodes[destination].node, ids)));
                let bridge_msg2 = (destination < 2
                    && packet.remote_addr == nodes[1 - destination].addr)
                    .then(|| Msg2Header::parse(packet.data.as_slice()))
                    .flatten();
                let transport_id = packet.transport_id;
                let received_ms = packet.timestamp_ms;
                // Read only bounded local ownership; never retain/reorder a packet
                // or query a routing selector while correlating these responses.
                let response_owner = |node: &Node| {
                    let response = bridge_msg2.as_ref().unwrap();
                    let key = (transport_id, response.receiver_idx.as_u32());
                    let active = node.get_peer(ids[1 - destination].node_addr()).map(|peer| {
                        json!({"link":peer.link_id().as_u64(),
                            "our_index":peer.our_index().map(|index|index.as_u32()),
                            "their_index":peer.their_index().map(|index|index.as_u32())})
                    });
                    json!({"pending":pending_attempts(node,ids),
                        "exact_pending_link":node.pending_outbound.get(&key).map(|link|link.as_u64()),
                        "matched_pending_link":node.pending_outbound.match_msg2(key.0,key.1)
                            .map(|(_,link)|link.as_u64()),
                        "receiver_index_allocated":node.index_allocator.is_allocated(response.receiver_idx),
                        "active_bridge":active})
                };
                let msg2_before = bridge_msg2.as_ref().map(|_| {
                    (
                        self.started.elapsed().as_millis(),
                        response_owner(&nodes[destination].node),
                    )
                });
                if incoming {
                    if bridge {
                        self.bridge_msg1[destination] += 1;
                    }
                    let source = nodes
                        .iter()
                        .position(|node| node.addr == packet.remote_addr)
                        .unwrap();
                    eprintln!(
                        "responsive incoming Msg1: {}",
                        json!({"source":source,"receiver":destination,"bridge":bridge,
                            "post_deadline_diagnostic":self.post_deadline_diagnostic,
                            "sender_index":msg1.as_ref().map(|header|header.sender_idx.as_u32()),
                            "observed_ms":self.started.elapsed().as_millis(),"received_ms":packet.timestamp_ms,
                            "attempts_before":before_packet.as_ref().map(|(_,attempts)|attempts)})
                    );
                    snapshot(
                        nodes,
                        ids,
                        self.started,
                        if self.post_deadline_diagnostic {
                            "post-deadline-diagnostic-msg1-before"
                        } else {
                            "responsive-msg1-before"
                        },
                    );
                }
                let before = turn_cost.snapshot(&nodes[destination], destination, ids);
                let (_, polls) = turn_timing::measured(
                    turn_cost.enabled(),
                    crate::node::tests::spanning_tree::process_dataplane_packet_once(
                        &mut nodes[destination].node,
                        packet,
                    ),
                )
                .await;
                turn_cost.record(
                    destination,
                    "raw-packet",
                    before,
                    turn_cost.snapshot(&nodes[destination], destination, ids),
                    polls,
                );
                ready::observe_completed_turn(|| observe(self));
                if let Some(response) = bridge_msg2.as_ref() {
                    let (before_ms, before) = msg2_before.unwrap();
                    let after = response_owner(&nodes[destination].node);
                    eprintln!(
                        "responsive bridge Msg2: {}",
                        json!({"source":1-destination,"receiver":destination,
                            "post_deadline_diagnostic":self.post_deadline_diagnostic,
                            "sender_index":response.sender_idx.as_u32(),
                            "receiver_index":response.receiver_idx.as_u32(),
                            "received_ms":received_ms,
                            "observation_ms":[before_ms,self.started.elapsed().as_millis()],
                            "before":before,"after":after})
                    );
                }
                if incoming {
                    snapshot(
                        nodes,
                        ids,
                        self.started,
                        if self.post_deadline_diagnostic {
                            "post-deadline-diagnostic-msg1-after"
                        } else {
                            "responsive-msg1-after"
                        },
                    );
                }
                self.incumbents(nodes, ids, before_packet);
                if destination < 2 {
                    self.timing.observe_boundary(
                        &nodes[destination].node,
                        ids,
                        destination,
                        self.started,
                        "packet-completed",
                    );
                }
            }
            // Production wakes for completed crypto/control work even without
            // another raw frame; reuse the existing ordinary completion turn.
            let before = turn_cost.snapshot(&nodes[destination], destination, ids);
            let (_, polls) = turn_timing::measured(
                turn_cost.enabled(),
                crate::node::tests::spanning_tree::process_dataplane_completions(
                    &mut nodes[destination].node,
                ),
            )
            .await;
            turn_cost.record(
                destination,
                "completion",
                before,
                turn_cost.snapshot(&nodes[destination], destination, ids),
                polls,
            );
            ready::observe_completed_turn(|| observe(self));
            self.incumbents(nodes, ids, None);
        }
        caps_with_limits(nodes, self.capacity);
        if let Some(payloads) = &mut self.brief_payloads {
            payloads.observe(nodes, ids, self.started);
        }
        for original in &mut self.queued_originals {
            original.observe(nodes, ids, self.started);
        }
        if let Some(setup) = &mut self.initial_handshake {
            setup.observe(nodes);
        }
        turn_cost.finish();
        if let Some(contact) = &mut self.contact_turn_cost {
            contact.merge(&turn_cost);
        }
        self.last_turn_cost = Some(turn_cost);
    }
}
