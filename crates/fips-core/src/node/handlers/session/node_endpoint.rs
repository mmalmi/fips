#[cfg(unix)]
enum DirectFmpEndpointBatchResult {
    Ineligible(Vec<EndpointDataPayload>),
    Sent,
    Partial(Vec<EndpointDataPayload>),
}

impl Node {
    async fn handle_endpoint_send_batch_slow_path(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
    ) {
        let _batch_service = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::EndpointSendBatchSlowPath,
            payloads.len(),
        );
        for payload in payloads {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
            let _ = self
                .send_or_queue_endpoint_payload(dest_addr, dest_pubkey, payload)
                .await;
        }
    }

    #[cfg(unix)]
    fn try_handle_direct_fmp_endpoint_send_batch(
        &mut self,
        dest_addr: NodeAddr,
        payloads: Vec<EndpointDataPayload>,
        resolved_route: &PipelinedEndpointResolvedRoute,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) -> DirectFmpEndpointBatchResult {
        let batch_packets = payloads.len();
        if !resolved_route.route_plan.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            &payloads,
            direct_endpoint_fmp_only_enabled(),
        ) {
            crate::perf_profile::record_endpoint_direct_fmp_batch(0, batch_packets);
            return DirectFmpEndpointBatchResult::Ineligible(payloads);
        }

        let now_ms = Self::now_ms();
        let session_context = {
            let _t = crate::perf_profile::BatchTimer::start(
                crate::perf_profile::Stage::EndpointSessionPrep,
                payloads.len(),
            );
            match self.sessions.session_fsp_send_context(&dest_addr, now_ms) {
                Ok(context) => context,
                Err(_) => {
                    crate::perf_profile::record_endpoint_direct_fmp_batch(0, batch_packets);
                    return DirectFmpEndpointBatchResult::Ineligible(payloads);
                }
            }
        };
        if session_context.wants_coords() || !self.sessions.direct_endpoint_data_can_send(&dest_addr)
        {
            crate::perf_profile::record_endpoint_direct_fmp_batch(0, batch_packets);
            return DirectFmpEndpointBatchResult::Ineligible(payloads);
        }

        let _endpoint_send = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::EndpointSend,
            payloads.len(),
        );
        let _job_build = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::EndpointWorkerJobBuild,
            payloads.len(),
        );
        let next_hop_addr = resolved_route.route_plan.next_hop_addr;
        let selected_send_target = resolved_route.send_target().into_selected_send_target();
        let mut prepared_sends = Vec::with_capacity(payloads.len());
        let mut iter = payloads.into_iter();
        let mut remaining = Vec::new();

        while let Some(payload) = iter.next() {
            let Some(direct_fmp_payload_len) = DIRECT_ENDPOINT_FMP_PAYLOAD_PREFIX_LEN
                .checked_add(payload.len())
                .and_then(|len| u16::try_from(len).ok())
            else {
                remaining.push(payload);
                remaining.extend(iter);
                break;
            };
            let peer_snapshot = resolved_route
                .peer_snapshot
                .prepare_send_snapshot(false, direct_fmp_payload_len);
            if !peer_snapshot.fmp_worker_send_available() {
                remaining.push(payload);
                remaining.extend(iter);
                break;
            }
            let fmp_prepared = peer_snapshot.fmp_prepared();
            let fmp_reservation = match self
                .peers
                .reserve_peer_runtime_fmp_worker_send(&peer_snapshot)
            {
                Ok(Some(reservation)) => reservation,
                Ok(None) => {
                    remaining.push(payload);
                    remaining.extend(iter);
                    break;
                }
                Err(error) => {
                    debug!(
                        dest = %self.peer_display_name(&dest_addr),
                        error = ?error,
                        "Direct-FMP endpoint-data batch reservation stopped early; falling back for remaining payloads"
                    );
                    remaining.push(payload);
                    remaining.extend(iter);
                    break;
                }
            };

            debug_assert_eq!(fmp_prepared.payload_len, direct_fmp_payload_len);
            debug_assert_eq!(
                fmp_reservation.predicted_bytes,
                ESTABLISHED_HEADER_SIZE
                    + direct_fmp_payload_len as usize
                    + crate::noise::TAG_SIZE
            );
            let wire_capacity = fmp_reservation.predicted_bytes;
            let mut wire_buf = Vec::with_capacity(wire_capacity);
            wire_buf.extend_from_slice(&fmp_reservation.header);
            wire_buf.extend_from_slice(&fmp_prepared.timestamp_ms.to_le_bytes());
            wire_buf.push(LinkMessageType::DirectEndpointData.to_byte());
            wire_buf.extend_from_slice(payload.as_slice());
            debug_assert_eq!(
                wire_buf.len(),
                ESTABLISHED_HEADER_SIZE + direct_fmp_payload_len as usize
            );

            let payload_len = payload.len();
            let drop_on_backpressure = payload.drop_on_backpressure();
            prepared_sends.push(PipelinedEndpointPreparedSend {
                dest_addr,
                next_hop_addr,
                fmp_counter: fmp_reservation.counter,
                fmp_timestamp_ms: fmp_prepared.timestamp_ms,
                fmp_wire_capacity: wire_capacity,
                originated_bytes: 1 + payload_len + crate::noise::TAG_SIZE,
                session_bookkeeping: PipelinedEndpointSessionBookkeeping::DirectFmp {
                    payload_len,
                    now_ms,
                    next_hop: next_hop_addr,
                },
                worker_job: crate::node::encrypt_worker::FmpSendJob {
                    cipher: fmp_reservation.cipher,
                    counter: fmp_reservation.counter,
                    wire_buf,
                    fsp_seal: None,
                    send_target: selected_send_target.clone(),
                    endpoint_flow_dispatch_key: endpoint_flow_dispatch_key(payload.as_slice())
                        .map(|key| key.get()),
                    bulk_endpoint_data: true,
                    drop_on_backpressure,
                    scheduling_weight: resolved_route.route_plan.scheduling_weight,
                    queued_at: None,
                },
            });
        }

        drop(_job_build);
        let sent_packets = prepared_sends.len();
        crate::perf_profile::record_endpoint_direct_fmp_batch(sent_packets, remaining.len());
        PipelinedEndpointPreparedSend::commit_many(prepared_sends, self, workers);

        if remaining.is_empty() {
            DirectFmpEndpointBatchResult::Sent
        } else {
            DirectFmpEndpointBatchResult::Partial(remaining)
        }
    }

    #[cfg(unix)]
    async fn handle_established_endpoint_send_batch(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
    ) {
        let route = {
            let _t = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::EndpointRouteResolve,
            );
            match self.resolve_peer_runtime_endpoint_route(dest_addr, Self::now_ms()) {
                Ok(route) => route,
                Err(_) => {
                    self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
                        .await;
                    return;
                }
            }
        };

        let Some(workers) = self.encrypt_workers.as_ref().cloned() else {
            self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
                .await;
            return;
        };
        let resolved_route = match self
            .resolve_peer_runtime_endpoint_send_route(&route)
            .await
        {
            Ok(Some(resolved_route)) => resolved_route,
            Ok(None) => {
                self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
                    .await;
                return;
            }
            Err(error) => {
                debug!(
                    dest = %self.peer_display_name(&dest_addr),
                    error = %error,
                    "Established endpoint-data batch could not resolve worker send target; falling back"
                );
                self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
                    .await;
                return;
            }
        };
        let _batch_service = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::EndpointSendBatchFastPath,
            payloads.len(),
        );
        let payloads = match self.try_handle_direct_fmp_endpoint_send_batch(
            dest_addr,
            payloads,
            &resolved_route,
            &workers,
        ) {
            DirectFmpEndpointBatchResult::Sent => return,
            DirectFmpEndpointBatchResult::Partial(remaining) => {
                if !remaining.is_empty() {
                    self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, remaining)
                        .await;
                }
                return;
            }
            DirectFmpEndpointBatchResult::Ineligible(payloads) => payloads,
        };
        let mut prepared_sends = Vec::with_capacity(payloads.len().min(64));
        let mut use_reused_route = true;

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

            match self.prepare_peer_runtime_endpoint_send_with_resolved_route(
                prepared.pipelined(),
                &resolved_route,
            ) {
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
        let _t =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSessionPrep);

        if payload.len() > u16::MAX as usize - FSP_INNER_HEADER_SIZE {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "endpoint data payload too long".into(),
            });
        }

        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let wants_coords = send_context.wants_coords();
        let timestamp = send_context.timestamp;

        let inner_flags = send_context.inner_flags_byte();

        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire = FIPS_OVERHEAD as usize + coords_size + payload.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
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
            self.sessions.consume_coords_warmup_packet(dest_addr);
        }

        let flags = send_context.fsp_flags(include_coords);

        Ok(PreparedEndpointSessionData {
            dest_addr,
            payload,
            now_ms,
            timestamp,
            fsp_flags: flags,
            inner_flags,
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
    async fn resolve_peer_runtime_endpoint_send_route(
        &self,
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
    ) -> Result<Option<PipelinedEndpointResolvedRoute>, NodeError> {
        let _t = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::EndpointRuntimeDispatchPrep,
        );
        runtime_route
            .resolve_send_target(&self.transports)
            .await
            .map_err(Self::map_pipelined_endpoint_runtime_send_error)
    }

    #[cfg(all(unix, test))]
    async fn prepare_peer_runtime_endpoint_send_with_route(
        &mut self,
        send: PipelinedEndpointSend<'_>,
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
    ) -> Result<Option<PipelinedEndpointPreparedSend>, NodeError> {
        let dispatch = {
            let _t = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::EndpointRuntimeDispatchPrep,
            );
            PipelinedEndpointPeerRuntimeSend::resolve_dispatch_with_route(
                runtime_route,
                send,
                &self.transports,
                &mut self.sessions,
                &mut self.peers,
            )
            .await
            .map_err(Self::map_pipelined_endpoint_peer_runtime_send_error)?
        };
        let Some(dispatch) = dispatch else {
            return Ok(None);
        };

        Ok(Some(dispatch.into_prepared_send(None)))
    }

    #[cfg(unix)]
    fn prepare_peer_runtime_endpoint_send_with_resolved_route(
        &mut self,
        send: PipelinedEndpointSend<'_>,
        resolved_route: &PipelinedEndpointResolvedRoute,
    ) -> Result<Option<PipelinedEndpointPreparedSend>, NodeError> {
        let dispatch = {
            let _t = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::EndpointRuntimeDispatchPrep,
            );
            PipelinedEndpointPeerRuntimeSend::resolve_dispatch_with_resolved_route(
                resolved_route,
                send,
                &mut self.sessions,
                &mut self.peers,
            )
            .map_err(Self::map_pipelined_endpoint_peer_runtime_send_error)?
        };
        let Some(dispatch) = dispatch else {
            return Ok(None);
        };

        Ok(Some(dispatch.into_prepared_send(None)))
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
