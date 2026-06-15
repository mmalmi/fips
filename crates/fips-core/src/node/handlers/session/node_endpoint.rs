impl Node {
    #[cfg(unix)]
    fn publish_endpoint_bulk_send_lease(
        &mut self,
        dest_addr: NodeAddr,
        route: &PipelinedEndpointPeerRuntimeRoute,
        batch_target: &PipelinedEndpointBatchTarget,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) {
        const ENDPOINT_BULK_SEND_LEASE_TTL: std::time::Duration =
            std::time::Duration::from_millis(50);

        let Some(runtime) = self.endpoint_bulk_send_runtime.as_ref().cloned() else {
            return;
        };
        let Some(fsp) = self
            .sessions
            .get(&dest_addr)
            .and_then(|entry| entry.endpoint_bulk_fsp_lease())
        else {
            runtime.invalidate(&dest_addr);
            return;
        };
        let next_hop_addr = route.next_hop_addr();
        let Some(fmp) = self.peers.endpoint_bulk_fmp_lease(&next_hop_addr) else {
            runtime.invalidate(&dest_addr);
            return;
        };
        let route_plan = route.route_plan_with_path_mtu(batch_target.path_mtu);
        let lease = crate::node::EndpointBulkSendLease::new(
            route_plan.source_addr,
            dest_addr,
            route_plan.next_hop_addr,
            route_plan.path_mtu,
            route_plan.default_ttl,
            route_plan.scheduling_weight,
            route_plan.direct_path_blocks_direct_payload,
            fsp,
            fmp,
            batch_target.send_target.clone().into_selected_send_target(),
            workers.clone(),
            ENDPOINT_BULK_SEND_LEASE_TTL,
        );
        runtime.publish(lease);
    }

    async fn handle_endpoint_send_batch_slow_path(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
    ) {
        for payload in payloads {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
            let _ = self
                .send_or_queue_endpoint_payload(dest_addr, dest_pubkey, payload)
                .await;
        }
    }

    #[cfg(unix)]
    async fn handle_established_endpoint_send_batch(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
    ) {
        let route = match self.resolve_peer_runtime_endpoint_route(dest_addr, Self::now_ms()) {
            Ok(route) => route,
            Err(_) => {
                self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
                    .await;
                return;
            }
        };

        let Some(workers) = self.encrypt_workers.as_ref().cloned() else {
            self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
                .await;
            return;
        };
        let mut prepared_sends = Vec::with_capacity(payloads.len().min(64));
        let mut use_reused_route = true;
        let batch_target = route.batch_target(&self.transports).await.ok().flatten();

        if let Some(batch_target) = batch_target.as_ref() {
            self.publish_endpoint_bulk_send_lease(dest_addr, &route, batch_target, &workers);
            self.handle_established_endpoint_send_batch_with_batch_target(
                dest_addr,
                dest_pubkey,
                payloads,
                &route,
                batch_target,
                &workers,
            )
            .await;
            return;
        }

        for payload in payloads {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);

            if !use_reused_route {
                PipelinedEndpointPreparedSend::commit_many(
                    std::mem::take(&mut prepared_sends),
                    self,
                    &workers,
                );
                let _ = self
                    .send_or_queue_endpoint_payload(dest_addr, dest_pubkey, payload)
                    .await;
                continue;
            }

            let prepared = match self
                .prepare_session_endpoint_data(&dest_addr, &payload)
                .await
            {
                Ok(prepared) => prepared,
                Err(error) if Self::session_send_needs_path_recovery(&error, &dest_addr) => {
                    PipelinedEndpointPreparedSend::commit_many(
                        std::mem::take(&mut prepared_sends),
                        self,
                        &workers,
                    );
                    debug!(
                        dest = %self.peer_display_name(&dest_addr),
                        error = %error,
                        "Established endpoint-data session lost route during batch preparation; queueing payload and probing fallback"
                    );
                    self.queue_pending_endpoint_data(dest_addr, payload);
                    self.maybe_initiate_lookup(&dest_addr).await;
                    use_reused_route = false;
                    continue;
                }
                Err(_) => {
                    PipelinedEndpointPreparedSend::commit_many(
                        std::mem::take(&mut prepared_sends),
                        self,
                        &workers,
                    );
                    use_reused_route = false;
                    continue;
                }
            };

            let prepared_send = self
                .prepare_peer_runtime_endpoint_send_with_route(prepared.pipelined(), &route)
                .await;

            match prepared_send {
                Ok(Some(prepared_send)) => {
                    prepared_sends.push(prepared_send);
                }
                Ok(None) => {
                    PipelinedEndpointPreparedSend::commit_many(
                        std::mem::take(&mut prepared_sends),
                        self,
                        &workers,
                    );
                    match self.send_session_fsp_plan(prepared.fallback_plan()).await {
                        Ok(()) => {}
                        Err(error)
                            if Self::session_send_needs_path_recovery(&error, &dest_addr) =>
                        {
                            drop(prepared);
                            debug!(
                                dest = %self.peer_display_name(&dest_addr),
                                error = %error,
                                "Established endpoint-data fallback send lost route during batch send; queueing payload and probing fallback"
                            );
                            self.queue_pending_endpoint_data(dest_addr, payload);
                            self.maybe_initiate_lookup(&dest_addr).await;
                            use_reused_route = false;
                        }
                        Err(_) => {
                            use_reused_route = false;
                        }
                    }
                }
                Err(error) if Self::session_send_needs_path_recovery(&error, &dest_addr) => {
                    drop(prepared);
                    PipelinedEndpointPreparedSend::commit_many(
                        std::mem::take(&mut prepared_sends),
                        self,
                        &workers,
                    );
                    debug!(
                        dest = %self.peer_display_name(&dest_addr),
                        error = %error,
                        "Established endpoint-data session lost route during batch send; queueing payload and probing fallback"
                    );
                    self.queue_pending_endpoint_data(dest_addr, payload);
                    self.maybe_initiate_lookup(&dest_addr).await;
                    use_reused_route = false;
                }
                Err(_) => {
                    PipelinedEndpointPreparedSend::commit_many(
                        std::mem::take(&mut prepared_sends),
                        self,
                        &workers,
                    );
                    use_reused_route = false;
                }
            }
        }

        PipelinedEndpointPreparedSend::commit_many(prepared_sends, self, &workers);
    }

    #[cfg(unix)]
    async fn handle_established_endpoint_send_batch_with_batch_target(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
        route: &PipelinedEndpointPeerRuntimeRoute,
        batch_target: &PipelinedEndpointBatchTarget,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) {
        let mut prepared_payloads = Vec::with_capacity(payloads.len());
        let mut payloads = payloads.into_iter();

        while let Some(payload) = payloads.next() {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
            match self
                .prepare_owned_session_endpoint_data(dest_addr, payload)
                .await
            {
                Ok(prepared) => prepared_payloads.push(prepared),
                Err((_, payload)) => {
                    let mut fallback_payloads = Vec::with_capacity(
                        prepared_payloads.len() + 1 + payloads.size_hint().0,
                    );
                    fallback_payloads.extend(
                        prepared_payloads
                            .into_iter()
                            .map(|prepared| prepared.payload),
                    );
                    fallback_payloads.push(payload);
                    fallback_payloads.extend(payloads);
                    self.handle_endpoint_send_batch_slow_path(
                        dest_addr,
                        dest_pubkey,
                        fallback_payloads,
                    )
                    .await;
                    return;
                }
            }
        }

        let prepared_sends = self.prepare_peer_runtime_endpoint_send_batch_with_batch_target(
            &prepared_payloads,
            route,
            batch_target,
        );

        match prepared_sends {
            Ok(Some(prepared_sends)) => {
                PipelinedEndpointPreparedSend::commit_many(prepared_sends, self, workers);
            }
            Ok(None) | Err(_) => {
                let fallback_payloads = prepared_payloads
                    .into_iter()
                    .map(|prepared| prepared.payload)
                    .collect();
                self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, fallback_payloads)
                    .await;
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn send_endpoint_data(
        &mut self,
        remote: crate::PeerIdentity,
        payload: Vec<u8>,
    ) -> Result<(), NodeError> {
        self.send_endpoint_data_send(EndpointDataSend::new(
            remote,
            EndpointDataPayload::new(payload),
        ))
        .await
    }

    async fn send_endpoint_data_send(&mut self, send: EndpointDataSend) -> Result<(), NodeError> {
        let dest_addr = send.dest_addr();
        let dest_pubkey = send.dest_pubkey();
        self.register_identity(dest_addr, dest_pubkey);
        self.send_or_queue_endpoint_payload(dest_addr, dest_pubkey, send.into_payload())
            .await
    }

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

    fn session_send_needs_path_recovery(error: &NodeError, dest_addr: &NodeAddr) -> bool {
        matches!(
            error,
            NodeError::SendFailed { node_addr, reason }
                if node_addr == dest_addr && reason == "no route to destination"
        ) || error.is_local_route_unavailable()
    }

    /// Send app-owned endpoint bytes over an established session without DataPacket ports.
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

    async fn prepare_owned_session_endpoint_data(
        &mut self,
        dest_addr: NodeAddr,
        payload: EndpointDataPayload,
    ) -> Result<PreparedOwnedEndpointSessionData, (NodeError, EndpointDataPayload)> {
        match self
            .prepare_session_endpoint_meta(dest_addr, payload.len())
            .await
        {
            Ok(meta) => Ok(PreparedOwnedEndpointSessionData { meta, payload }),
            Err(error) => Err((error, payload)),
        }
    }

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

    #[cfg(unix)]
    #[cfg_attr(not(test), allow(dead_code))]
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

    #[cfg(unix)]
    fn resolve_peer_runtime_endpoint_route(
        &mut self,
        dest_addr: NodeAddr,
        now_ms: u64,
    ) -> Result<PipelinedEndpointPeerRuntimeRoute, PipelinedEndpointPeerRuntimeRouteRequestError>
    {
        let source_addr = *self.node_addr();
        let default_ttl = self.config.node.session.default_ttl;
        PipelinedEndpointPeerRuntimeRouteRequest::new(source_addr, dest_addr, now_ms, default_ttl)
            .resolve(self)
    }

    #[cfg(unix)]
    #[cfg_attr(not(test), allow(dead_code))]
    async fn prepare_peer_runtime_endpoint_send_with_route(
        &mut self,
        send: PipelinedEndpointSend<'_>,
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
    ) -> Result<Option<PipelinedEndpointPreparedSend>, NodeError> {
        let Some(dispatch) = PipelinedEndpointPeerRuntimeSend::resolve_dispatch_with_route(
            runtime_route,
            send,
            &self.transports,
            &mut self.sessions,
            &mut self.peers,
        )
        .await
        .map_err(Self::map_pipelined_endpoint_peer_runtime_send_error)?
        else {
            return Ok(None);
        };

        Ok(Some(dispatch.into_prepared_send(None)))
    }

    #[cfg(unix)]
    fn prepare_peer_runtime_endpoint_send_batch_with_batch_target(
        &mut self,
        prepared: &[PreparedOwnedEndpointSessionData],
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
        batch_target: &PipelinedEndpointBatchTarget,
    ) -> Result<Option<Vec<PipelinedEndpointPreparedSend>>, NodeError> {
        PipelinedEndpointPeerRuntimeBatchSend::resolve_prepared_sends_with_batch_target(
            runtime_route,
            prepared.iter().map(|prepared| prepared.pipelined()),
            batch_target,
            &mut self.sessions,
            &mut self.peers,
        )
        .map_err(Self::map_pipelined_endpoint_peer_runtime_send_error)
    }

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

    #[cfg(not(unix))]
    async fn try_send_session_endpoint_data_pipelined(
        &mut self,
        _send: PipelinedEndpointSend<'_>,
    ) -> Result<bool, NodeError> {
        Ok(false)
    }

}
