impl Node {
    pub(in crate::node) async fn handle_packet_mover2_deferred_endpoint_command(
        &mut self,
        command: NodeEndpointCommand,
    ) {
        self.handle_endpoint_data_command_no_established_flush(command)
            .await;
    }

    async fn queue_packet_mover2_unrouted_endpoint_send(
        &mut self,
        command: EndpointSendCommand,
    ) -> Result<(), NodeError> {
        let (send, _, enqueued_at_ms) = command.into_deferred_parts();
        let dest_addr = send.dest_addr();
        let dest_pubkey = send.dest_pubkey();
        self.register_identity(dest_addr, dest_pubkey);
        self.queue_packet_mover2_unrouted_endpoint_payloads(
            dest_addr,
            dest_pubkey,
            vec![send.into_payload()],
            enqueued_at_ms,
        )
        .await
    }

    async fn queue_packet_mover2_unrouted_endpoint_batch(
        &mut self,
        command: EndpointSendBatchCommand,
    ) {
        let (remote, payloads, _, enqueued_at_ms) = command.into_deferred_parts();
        let dest_addr = *remote.node_addr();
        let dest_pubkey = remote.pubkey_full();
        self.register_identity(dest_addr, dest_pubkey);
        let _ = self
            .queue_packet_mover2_unrouted_endpoint_payloads(
                dest_addr,
                dest_pubkey,
                payloads,
                enqueued_at_ms,
            )
            .await;
    }

    async fn queue_packet_mover2_unrouted_endpoint_payloads(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
        enqueued_at_ms: u64,
    ) -> Result<(), NodeError> {
        if payloads.is_empty() {
            return Ok(());
        }

        match self.packet_mover2_outbound_session_state(&dest_addr) {
            OutboundSessionState::Established => {
                let route_available = self.find_next_hop(&dest_addr).is_some();
                for payload in payloads {
                    self.queue_pending_endpoint_data_with_enqueued_at_ms(
                        dest_addr,
                        payload,
                        enqueued_at_ms,
                    );
                }
                if !route_available {
                    self.maybe_initiate_path_recovery_lookup(&dest_addr).await;
                }
                Ok(())
            }
            OutboundSessionState::Pending => {
                for payload in payloads {
                    self.queue_pending_endpoint_data_with_enqueued_at_ms(
                        dest_addr,
                        payload,
                        enqueued_at_ms,
                    );
                }
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
                    for payload in payloads {
                        self.queue_pending_endpoint_data_with_enqueued_at_ms(
                            dest_addr,
                            payload,
                            enqueued_at_ms,
                        );
                    }
                    self.maybe_initiate_lookup(&dest_addr).await;
                    return Ok(());
                }

                match self.initiate_session(dest_addr, dest_pubkey).await {
                    Ok(()) => {}
                    Err(NodeError::SendFailed { node_addr, reason })
                        if node_addr == dest_addr && reason == "no route to destination" =>
                    {
                        for payload in payloads {
                            self.queue_pending_endpoint_data_with_enqueued_at_ms(
                                dest_addr,
                                payload,
                                enqueued_at_ms,
                            );
                        }
                        self.maybe_initiate_lookup(&dest_addr).await;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
                for payload in payloads {
                    self.queue_pending_endpoint_data_with_enqueued_at_ms(
                        dest_addr,
                        payload,
                        enqueued_at_ms,
                    );
                }
                Ok(())
            }
        }
    }
}
