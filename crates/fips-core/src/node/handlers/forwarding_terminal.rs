impl Node {
    pub(in crate::node) fn collect_deferred_session_forward_terminals(
        &mut self,
        turn: &mut crate::dataplane::DataplaneLiveNodeTurn,
    ) -> usize {
        let mut completed = 0usize;
        let receipts = turn.extract_transport_sent_receipts(|receipt| {
            receipt
                .send_token
                .is_some_and(|token| self.deferred_session_forwards.contains(token))
        });
        for receipt in receipts {
            let Some(send_token) = receipt.send_token else {
                continue;
            };
            let Some(next_hop_addr) = self.deferred_session_forwards.pending_next_hop(send_token)
            else {
                continue;
            };
            let result = if let Some(timestamp_ms) = receipt.fmp_timestamp_ms {
                let bytes_sent = receipt.payload_len;
                self.dataplane.record_fmp_mmp_send_result(
                    &next_hop_addr,
                    receipt.counter,
                    timestamp_ms,
                    bytes_sent,
                );
                let _ = self
                    .peers
                    .record_fmp_send_bookkeeping(&next_hop_addr, bytes_sent);
                let send_result: Result<usize, crate::transport::TransportError> = Ok(bytes_sent);
                self.note_local_send_outcome(&next_hop_addr, &send_result);
                Ok(())
            } else {
                Err(NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: "dataplane FMP timestamp missing".into(),
                })
            };
            completed = completed.saturating_add(usize::from(
                self.deferred_session_forwards.complete(send_token, result),
            ));
        }

        let output_drops = turn.extract_output_drops(|drop| {
            drop.send_token()
                .is_some_and(|token| self.deferred_session_forwards.contains(token))
        });
        for drop in output_drops {
            let Some(send_token) = drop.send_token() else {
                continue;
            };
            let Some(next_hop_addr) = self.deferred_session_forwards.pending_next_hop(send_token)
            else {
                continue;
            };
            let error = self.dataplane_fmp_output_drop_error(next_hop_addr, &drop);
            completed = completed.saturating_add(usize::from(
                self.deferred_session_forwards
                    .complete(send_token, Err(error)),
            ));
        }

        let drops = turn.extract_drops(|drop| {
            drop.send_token()
                .is_some_and(|token| self.deferred_session_forwards.contains(token))
        });
        for drop in drops {
            let Some(send_token) = drop.send_token() else {
                continue;
            };
            let Some(next_hop_addr) = self.deferred_session_forwards.pending_next_hop(send_token)
            else {
                continue;
            };
            let error = NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: format!("dataplane FMP packet dropped: {:?}", drop.reason()),
            };
            completed = completed.saturating_add(usize::from(
                self.deferred_session_forwards
                    .complete(send_token, Err(error)),
            ));
        }
        completed
    }

    pub(in crate::node) async fn finish_completed_session_forwards(&mut self) -> usize {
        let mut processed = 0usize;
        let mut failed_routes = std::collections::HashSet::new();
        while let Some(completed) = self.deferred_session_forwards.pop_completed() {
            let record_route_failure = claim_route_failure_once(
                &mut failed_routes,
                completed.forward.dest_addr,
                completed.forward.next_hop_addr,
                completed.result.is_err(),
            );
            self.finish_prepared_session_forward(
                completed.forward,
                completed.result,
                record_route_failure,
            )
            .await;
            processed = processed.saturating_add(1);
        }
        processed
    }

    async fn drain_one_deferred_session_forward_turn(&mut self) -> usize {
        let pending_before = self.deferred_session_forwards.pending_len();
        if pending_before == 0 {
            return self.finish_completed_session_forwards().await;
        }
        let turn = self
            .pump_dataplane_pending_outbound_firsts(
                crate::dataplane::DataplaneLiveOutboundFirsts {
                    collect_transport_sent_receipts: true,
                    ..Default::default()
                },
                0,
                0,
                pending_before.min(forwarding_submission_limit(
                    self.dataplane_transport_send_batch_packets,
                )),
            )
            .await;
        self.defer_dataplane_control_turn(turn);
        let processed = self.finish_completed_session_forwards().await;
        if self.deferred_session_forwards.pending_len() >= pending_before {
            self.wait_for_dataplane_completion().await;
        }
        processed
    }

    pub(in crate::node) async fn drain_deferred_session_forwards(&mut self) -> usize {
        let mut processed = self.finish_completed_session_forwards().await;
        while self.deferred_session_forwards.pending_len() > 0 {
            processed =
                processed.saturating_add(self.drain_one_deferred_session_forward_turn().await);
        }
        processed
    }

    pub(in crate::node) async fn abort_deferred_session_forwards(
        &mut self,
        reason: &'static str,
    ) -> usize {
        self.deferred_session_forwards.abort_pending(reason);
        self.finish_completed_session_forwards().await
    }
}
