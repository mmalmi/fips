impl Node {
    pub(in crate::node) async fn handle_packet_mover2_deferred_endpoint_command(
        &mut self,
        command: NodeEndpointCommand,
    ) {
        self.handle_endpoint_data_command(command).await;
    }

    async fn queue_packet_mover2_unrouted_endpoint_send(
        &mut self,
        command: EndpointSendCommand,
    ) -> Result<(), NodeError> {
        let (send, _) = command.into_parts();
        let dest_addr = send.dest_addr();
        let dest_pubkey = send.dest_pubkey();
        self.register_identity(dest_addr, dest_pubkey);
        self.queue_packet_mover2_unrouted_endpoint_payloads(
            dest_addr,
            dest_pubkey,
            vec![send.into_payload()],
        )
        .await
    }

    async fn queue_packet_mover2_unrouted_endpoint_batch(
        &mut self,
        command: EndpointSendBatchCommand,
    ) {
        let (remote, payloads, _) = command.into_parts();
        let dest_addr = *remote.node_addr();
        let dest_pubkey = remote.pubkey_full();
        self.register_identity(dest_addr, dest_pubkey);
        let _ = self
            .queue_packet_mover2_unrouted_endpoint_payloads(dest_addr, dest_pubkey, payloads)
            .await;
    }

    async fn queue_packet_mover2_unrouted_endpoint_payloads(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
    ) -> Result<(), NodeError> {
        if payloads.is_empty() {
            return Ok(());
        }

        match self.sessions.outbound_session_state(&dest_addr) {
            OutboundSessionState::Established => {
                for payload in payloads {
                    self.queue_pending_endpoint_data(dest_addr, payload);
                }
                self.maybe_initiate_lookup(&dest_addr).await;
                Ok(())
            }
            OutboundSessionState::Pending => {
                for payload in payloads {
                    self.queue_pending_endpoint_data(dest_addr, payload);
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
                        self.queue_pending_endpoint_data(dest_addr, payload);
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
                            self.queue_pending_endpoint_data(dest_addr, payload);
                        }
                        self.maybe_initiate_lookup(&dest_addr).await;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
                for payload in payloads {
                    self.queue_pending_endpoint_data(dest_addr, payload);
                }
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn send_endpoint_data(
        &mut self,
        remote: crate::PeerIdentity,
        payload: Vec<u8>,
    ) -> Result<(), NodeError> {
        self.send_endpoint_data_send(crate::node::EndpointDataSend::new(
            remote,
            EndpointDataPayload::new(payload),
        ))
        .await
    }

    #[cfg(test)]
    async fn send_endpoint_data_send(
        &mut self,
        send: crate::node::EndpointDataSend,
    ) -> Result<(), NodeError> {
        let dest_addr = send.dest_addr();
        let dest_pubkey = send.dest_pubkey();
        self.register_identity(dest_addr, dest_pubkey);
        self.send_or_queue_endpoint_payload(dest_addr, dest_pubkey, send.into_payload())
            .await
    }

    #[cfg(test)]
    async fn send_or_queue_endpoint_payload(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payload: EndpointDataPayload,
    ) -> Result<(), NodeError> {
        match self.sessions.outbound_session_state(&dest_addr) {
            OutboundSessionState::Established => {
                match self.send_session_endpoint_data(&dest_addr, &payload).await {
                    Ok(()) => return Ok(()),
                    Err(error) if Self::session_send_needs_path_recovery(&error, &dest_addr) => {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            error = %error,
                            "Established endpoint-data session lost route; queueing payload and probing fallback"
                        );
                        self.queue_pending_endpoint_data(dest_addr, payload);
                        self.maybe_initiate_lookup(&dest_addr).await;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            OutboundSessionState::Pending => {
                self.queue_pending_endpoint_data(dest_addr, payload);
                let should_discover = self.config.node.routing.mode
                    == crate::config::RoutingMode::ReplyLearned
                    || self.find_next_hop(&dest_addr).is_none();
                if should_discover {
                    self.maybe_initiate_lookup(&dest_addr).await;
                }
                return Ok(());
            }
            OutboundSessionState::Missing => {}
        }

        if self.find_next_hop(&dest_addr).is_none() {
            self.queue_pending_endpoint_data(dest_addr, payload);
            self.maybe_initiate_lookup(&dest_addr).await;
            return Ok(());
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {}
            Err(NodeError::SendFailed { node_addr, reason })
                if node_addr == dest_addr && reason == "no route to destination" =>
            {
                self.queue_pending_endpoint_data(dest_addr, payload);
                self.maybe_initiate_lookup(&dest_addr).await;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        self.queue_pending_endpoint_data(dest_addr, payload);
        Ok(())
    }

    #[cfg(test)]
    fn session_send_needs_path_recovery(error: &NodeError, dest_addr: &NodeAddr) -> bool {
        matches!(
            error,
            NodeError::SendFailed { node_addr, reason }
                if node_addr == dest_addr && reason == "no route to destination"
        ) || error.is_local_route_unavailable()
    }

    /// Send app-owned endpoint bytes over an established session without DataPacket ports.
    #[cfg(test)]
    async fn send_session_endpoint_data(
        &mut self,
        dest_addr: &NodeAddr,
        payload: &EndpointDataPayload,
    ) -> Result<(), NodeError> {
        let prepared = self
            .prepare_session_endpoint_data(dest_addr, payload)
            .await?;
        self.send_prepared_session_endpoint_data(prepared).await
    }

    #[cfg(test)]
    async fn prepare_session_endpoint_data<'a>(
        &mut self,
        dest_addr: &'a NodeAddr,
        payload: &'a EndpointDataPayload,
    ) -> Result<PreparedEndpointSessionData<'a>, NodeError> {
        let meta = self
            .prepare_session_endpoint_meta(*dest_addr, payload.len())
            .await?;
        Ok(PreparedEndpointSessionData { meta, payload })
    }

    #[cfg(test)]
    async fn prepare_session_endpoint_meta(
        &mut self,
        dest_addr: NodeAddr,
        payload_len: usize,
    ) -> Result<PreparedEndpointSessionMeta, NodeError> {
        let _t = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::EndpointSendPrepare,
        );
        if payload_len > u16::MAX as usize - FSP_INNER_HEADER_SIZE {
            return Err(NodeError::SendFailed {
                node_addr: dest_addr,
                reason: "endpoint data payload too long".into(),
            });
        }

        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(&dest_addr, now_ms)
            .map_err(|error| error.into_node_error(dest_addr))?;
        let wants_coords = send_context.wants_coords();
        let timestamp = send_context.timestamp;

        let msg_type = SessionMessageType::EndpointData.to_byte();
        let inner_flags = send_context.inner_flags_byte();

        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(&dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire = FIPS_OVERHEAD as usize + coords_size + payload_len;
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                if let Err(e) = self.send_coords_warmup(&dest_addr).await {
                    debug!(dest = %self.peer_display_name(&dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before endpoint data");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        // Consume one warmup opportunity for either piggybacked coords or the
        // standalone warmup attempt, preserving the previous retry behavior.
        if wants_coords {
            self.sessions.consume_coords_warmup_packet(&dest_addr);
        }

        let flags = send_context.fsp_flags(include_coords);

        Ok(PreparedEndpointSessionMeta {
            dest_addr,
            now_ms,
            timestamp,
            msg_type,
            inner_flags,
            fsp_flags: flags,
            my_coords,
            dest_coords,
        })
    }

    #[cfg(test)]
    async fn send_prepared_session_endpoint_data(
        &mut self,
        prepared: PreparedEndpointSessionData<'_>,
    ) -> Result<(), NodeError> {
        if self
            .try_send_session_endpoint_data_pipelined(prepared.pipelined())
            .await?
        {
            return Ok(());
        }

        self.send_session_fsp_plan(prepared.fallback_plan()).await
    }

    #[cfg(test)]
    #[cfg(unix)]
    fn map_pipelined_endpoint_runtime_send_plan_error(
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        error: PipelinedEndpointRuntimeSendPlanError,
    ) -> NodeError {
        match error {
            PipelinedEndpointRuntimeSendPlanError::SendPlan(
                PipelinedEndpointSendPlanError::FmpPayloadTooLarge,
            ) => NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: "pipelined FMP payload too large".into(),
            },
            PipelinedEndpointRuntimeSendPlanError::SendPlan(
                PipelinedEndpointSendPlanError::FspPayloadTooLarge,
            ) => NodeError::SendFailed {
                node_addr: dest_addr,
                reason: "endpoint FSP payload too large".into(),
            },
            PipelinedEndpointRuntimeSendPlanError::RoutePeerMismatch {
                route_next_hop,
                peer_snapshot_addr,
            } => NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: format!(
                    "pipelined route peer mismatch: route {} peer snapshot {}",
                    route_next_hop, peer_snapshot_addr
                ),
            },
            PipelinedEndpointRuntimeSendPlanError::FmpPayloadMismatch {
                prepared_payload_len,
                plan_payload_len,
            } => NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: format!(
                    "pipelined FMP preparation payload mismatch: prepared {} plan {}",
                    prepared_payload_len, plan_payload_len
                ),
            },
        }
    }

    #[cfg(test)]
    #[cfg(unix)]
    fn map_pipelined_endpoint_peer_runtime_route_request_error(
        error: PipelinedEndpointPeerRuntimeRouteRequestError,
    ) -> NodeError {
        match error {
            PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr } => {
                NodeError::SendFailed {
                    node_addr: dest_addr,
                    reason: "no route to destination".into(),
                }
            }
            PipelinedEndpointPeerRuntimeRouteRequestError::FmpPreparation {
                next_hop_addr,
                error,
            } => Self::map_fmp_send_preparation_error(next_hop_addr, error),
        }
    }

    #[cfg(test)]
    #[cfg(unix)]
    fn map_pipelined_endpoint_runtime_send_attempt_error(
        error: PipelinedEndpointRuntimeSendAttemptError,
    ) -> NodeError {
        match error {
            PipelinedEndpointRuntimeSendAttemptError::FspReservation { dest_addr, error } => {
                Self::map_fsp_worker_send_reservation_error(dest_addr, error)
            }
            PipelinedEndpointRuntimeSendAttemptError::FmpReservation {
                next_hop_addr,
                error,
            } => Self::map_fmp_send_preparation_error(next_hop_addr, error),
        }
    }

    #[cfg(test)]
    #[cfg(unix)]
    fn map_pipelined_endpoint_runtime_send_error(
        error: PipelinedEndpointRuntimeSendError,
    ) -> NodeError {
        match error {
            PipelinedEndpointRuntimeSendError::TransportNotFound(transport_id) => {
                NodeError::TransportNotFound(transport_id)
            }
            PipelinedEndpointRuntimeSendError::Attempt(error) => {
                Self::map_pipelined_endpoint_runtime_send_attempt_error(error)
            }
        }
    }

    #[cfg(test)]
    #[cfg(unix)]
    fn map_pipelined_endpoint_peer_runtime_send_error(
        error: PipelinedEndpointPeerRuntimeSendError,
    ) -> NodeError {
        match error {
            PipelinedEndpointPeerRuntimeSendError::RuntimePlan {
                dest_addr,
                next_hop_addr,
                error,
            } => Self::map_pipelined_endpoint_runtime_send_plan_error(
                dest_addr,
                next_hop_addr,
                error,
            ),
            PipelinedEndpointPeerRuntimeSendError::RuntimeSend(error) => {
                Self::map_pipelined_endpoint_runtime_send_error(error)
            }
        }
    }

    #[cfg(test)]
    #[cfg(unix)]
    fn map_pipelined_endpoint_peer_runtime_send_request_error(
        error: PipelinedEndpointPeerRuntimeSendRequestError,
    ) -> NodeError {
        match error {
            PipelinedEndpointPeerRuntimeSendRequestError::Route(error) => {
                Self::map_pipelined_endpoint_peer_runtime_route_request_error(error)
            }
            PipelinedEndpointPeerRuntimeSendRequestError::Send(error) => {
                Self::map_pipelined_endpoint_peer_runtime_send_error(error)
            }
        }
    }

    #[cfg(test)]
    #[cfg(unix)]
    async fn execute_peer_runtime_endpoint_send(
        &mut self,
        send: PipelinedEndpointSend<'_>,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) -> Result<bool, PipelinedEndpointPeerRuntimeSendRequestError> {
        let source_addr = *self.node_addr();
        let default_ttl = self.config.node.session.default_ttl;
        PipelinedEndpointPeerRuntimeSendRequest::new(source_addr, send, default_ttl)
            .execute(self, workers)
            .await
    }

    #[cfg(test)]
    #[cfg(unix)]
    async fn try_send_session_endpoint_data_pipelined(
        &mut self,
        send: PipelinedEndpointSend<'_>,
    ) -> Result<bool, NodeError> {
        let Some(workers) = self.encrypt_workers.as_ref().cloned() else {
            return Ok(false);
        };

        let sent = self
            .execute_peer_runtime_endpoint_send(send, &workers)
            .await
            .map_err(Self::map_pipelined_endpoint_peer_runtime_send_request_error)?;

        Ok(sent)
    }

    #[cfg(test)]
    #[cfg(not(unix))]
    async fn try_send_session_endpoint_data_pipelined(
        &mut self,
        _send: PipelinedEndpointSend<'_>,
    ) -> Result<bool, NodeError> {
        Ok(false)
    }

}
