impl Node {
    async fn queue_dataplane_unrouted_endpoint_batch(
        &mut self,
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        enqueued_at_ms: u64,
    ) {
        let dest_addr = *remote.node_addr();
        let dest_pubkey = remote.pubkey_full();
        self.register_identity(dest_addr, dest_pubkey);
        let _ = self
            .queue_dataplane_unrouted_endpoint_payloads(
                dest_addr,
                dest_pubkey,
                payloads,
                enqueued_at_ms,
            )
            .await;
    }

    async fn queue_dataplane_unrouted_endpoint_payloads(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
        enqueued_at_ms: u64,
    ) -> Result<(), NodeError> {
        if payloads.is_empty() {
            return Ok(());
        }

        match self.dataplane_outbound_session_state(&dest_addr) {
            OutboundSessionState::Established => {
                let route_available = self.find_next_hop(&dest_addr).is_some();
                if route_available && self.dataplane_has_fsp_owner(&dest_addr) {
                    if let Err(error) = self
                        .send_dataplane_cached_endpoint_payloads(
                            &dest_addr,
                            payloads,
                            enqueued_at_ms,
                        )
                        .await
                    {
                        tracing::debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            error = %error,
                            "Failed to send established endpoint data through dataplane"
                        );
                    }
                    return Ok(());
                }

                self.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
                    dest_addr,
                    payloads,
                    enqueued_at_ms,
                );
                if !route_available {
                    self.maybe_initiate_path_recovery_lookup(&dest_addr).await;
                }
                Ok(())
            }
            OutboundSessionState::Pending => {
                self.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
                    dest_addr,
                    payloads,
                    enqueued_at_ms,
                );
                let should_discover = self.config.node.routing.mode
                    == crate::config::RoutingMode::ReplyLearned
                    || self.find_next_hop(&dest_addr).is_none();
                if should_discover {
                    self.maybe_initiate_lookup(&dest_addr).await;
                }
                Ok(())
            }
            OutboundSessionState::Missing => {
                if self.find_next_hop(&dest_addr).is_none() {
                    self.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
                        dest_addr,
                        payloads,
                        enqueued_at_ms,
                    );
                    self.maybe_initiate_lookup(&dest_addr).await;
                    return Ok(());
                }

                match self.initiate_session(dest_addr, dest_pubkey).await {
                    Ok(()) => {}
                    Err(NodeError::SendFailed { node_addr, reason })
                        if node_addr == dest_addr && reason == "no route to destination" =>
                    {
                        self.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
                            dest_addr,
                            payloads,
                            enqueued_at_ms,
                        );
                        self.maybe_initiate_lookup(&dest_addr).await;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
                self.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
                    dest_addr,
                    payloads,
                    enqueued_at_ms,
                );
                Ok(())
            }
        }
    }

    pub(in crate::node) fn requeue_deferred_endpoint_data_batch(
        &mut self,
        batch: NodeEndpointDataBatch,
    ) {
        let (remote, payloads, _, enqueued_at_ms) = batch.into_parts();
        let dest_addr = *remote.node_addr();
        self.register_identity(dest_addr, remote.pubkey_full());
        self.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
            dest_addr,
            payloads,
            enqueued_at_ms,
        );
    }
}
