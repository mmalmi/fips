impl SealedSessionFspSend {
    #[cfg(test)]
    fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    #[cfg(test)]
    fn counter(&self) -> u64 {
        self.counter
    }

    fn fsp_bookkeeping_input(&self) -> FspSendBookkeepingInput {
        match self.bookkeeping {
            SessionFspSendBookkeeping::Data {
                payload_len,
                now_ms,
            } => FspSendBookkeepingInput::data(
                payload_len,
                self.counter,
                self.timestamp,
                self.ciphertext_len,
                now_ms,
            ),
            SessionFspSendBookkeeping::Control => {
                FspSendBookkeepingInput::control(self.counter, self.timestamp, self.ciphertext_len)
            }
        }
    }

    fn into_datagram(
        self,
        source_addr: NodeAddr,
        ttl: u8,
    ) -> (SessionDatagram, FspSendBookkeepingInput) {
        let bookkeeping = self.fsp_bookkeeping_input();
        let datagram =
            SessionDatagram::new(source_addr, self.dest_addr, self.fsp_payload).with_ttl(ttl);
        (datagram, bookkeeping)
    }
}

impl SessionDatagramRuntimeRoute {
    fn new(
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        source_mmp_seeded: bool,
    ) -> Self {
        Self {
            dest_addr,
            next_hop_addr,
            path_mtu,
            source_mmp_seeded,
        }
    }

    #[cfg(test)]
    fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    fn next_hop_addr(&self) -> NodeAddr {
        self.next_hop_addr
    }

    #[cfg(test)]
    fn path_mtu(&self) -> u16 {
        self.path_mtu
    }

    #[cfg(test)]
    fn source_mmp_seeded(&self) -> bool {
        self.source_mmp_seeded
    }

    fn record_success(self, node: &mut Node, encoded_len: usize) {
        node.sessions
            .record_session_datagram_next_hop(&self.dest_addr, self.next_hop_addr);
        node.stats_mut().forwarding.record_originated(encoded_len);
    }

    fn record_failure(self, node: &mut Node) {
        node.record_route_failure(self.dest_addr, self.next_hop_addr);
    }
}

#[cfg(unix)]
fn direct_endpoint_fmp_only_enabled() -> bool {
    static VALUE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_direct_endpoint_fmp_only_enabled(
            std::env::var("FIPS_DIRECT_ENDPOINT_FMP_ONLY")
                .ok()
                .as_deref(),
        )
    })
}

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))]
fn parse_direct_endpoint_fmp_only_enabled(raw: Option<&str>) -> bool {
    let Some(raw) = raw.map(str::trim) else {
        return false;
    };
    matches!(
        raw.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(unix)]
impl PipelinedEndpointSendTarget {
    async fn resolve(
        udp: &crate::transport::udp::UdpTransport,
        prepared: &crate::node::FmpSendPreparation,
    ) -> Option<Self> {
        let socket_addr = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                match prepared.connected_socket.as_ref() {
                    Some(socket) => Some(socket.peer_addr()),
                    None => udp.resolve_for_off_task(&prepared.remote_addr).await.ok(),
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                udp.resolve_for_off_task(&prepared.remote_addr).await.ok()
            }
        }?;
        let socket = udp.async_socket()?;
        Some(Self {
            socket,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: prepared.connected_socket.clone(),
            socket_addr,
        })
    }

    fn into_selected_send_target(self) -> crate::node::encrypt_worker::SelectedSendTarget {
        crate::node::encrypt_worker::SelectedSendTarget::new(
            self.socket,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            self.connected_socket,
            self.socket_addr,
        )
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointDispatchPlan<'a> {
    #[cfg(test)]
    fn new(
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Option<Self> {
        Self::new_with_direct_fmp_opt_in(
            send,
            next_hop_addr,
            path_mtu,
            scheduling_weight,
            direct_path_blocks_direct_payload,
            direct_endpoint_fmp_only_enabled(),
        )
    }

    fn new_with_direct_fmp_opt_in(
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
        direct_fmp_opt_in: bool,
    ) -> Option<Self> {
        let fsp_payload_len = u16::try_from(send.inner_plaintext.len()).ok()?;
        let bulk_endpoint_data =
            send.fsp_flags & FSP_FLAG_CP == 0 && send.payload.bulk_endpoint_data();
        let drop_on_backpressure = next_hop_addr == *send.dest_addr
            && !direct_path_blocks_direct_payload
            && bulk_endpoint_data
            && send.payload.drop_on_backpressure();
        let direct_fmp_endpoint = Self::direct_fmp_endpoint_eligible(
            send,
            next_hop_addr,
            direct_path_blocks_direct_payload,
            bulk_endpoint_data,
            direct_fmp_opt_in,
        );

        Some(Self {
            dest_addr: *send.dest_addr,
            next_hop_addr,
            payload: send.payload,
            timestamp: send.timestamp,
            now_ms: send.now_ms,
            fsp_flags: send.fsp_flags,
            path_mtu,
            inner_plaintext_len: send.inner_plaintext.len(),
            fsp_payload_len,
            bulk_endpoint_data,
            drop_on_backpressure,
            direct_fmp_endpoint,
            scheduling_weight,
        })
    }

    fn direct_fmp_endpoint_eligible(
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        direct_path_blocks_direct_payload: bool,
        bulk_endpoint_data: bool,
        direct_fmp_opt_in: bool,
    ) -> bool {
        (direct_fmp_opt_in || send.payload.direct_fmp_endpoint_allowed())
            && next_hop_addr == *send.dest_addr
            && !direct_path_blocks_direct_payload
            && bulk_endpoint_data
            && send.fsp_flags & FSP_FLAG_CP == 0
            && send.my_coords.is_none()
            && send.dest_coords.is_none()
    }

    fn direct_fmp_payload_len(&self) -> Option<u16> {
        if !self.direct_fmp_endpoint {
            return None;
        }
        let len = DIRECT_ENDPOINT_FMP_PAYLOAD_PREFIX_LEN
            .checked_add(self.payload.len())?;
        u16::try_from(len).ok()
    }

    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        crate::node::FspWorkerSendReservationInput {
            flags: self.fsp_flags,
            payload_len: self.fsp_payload_len,
            path_mtu: self.path_mtu,
        }
    }

    fn fsp_bookkeeping_input(&self, fsp_counter: u64) -> FspSendBookkeepingInput {
        FspSendBookkeepingInput::data(
            self.payload.len(),
            fsp_counter,
            self.timestamp,
            self.inner_plaintext_len + crate::noise::TAG_SIZE,
            self.now_ms,
        )
        .with_next_hop(self.next_hop_addr)
    }

    fn direct_fmp_bookkeeping_input(&self) -> PipelinedEndpointSessionBookkeeping {
        PipelinedEndpointSessionBookkeeping::DirectFmp {
            payload_len: self.payload.len(),
            now_ms: self.now_ms,
            next_hop: self.next_hop_addr,
        }
    }

    fn into_worker_job(
        self,
        worker_wire: PipelinedEndpointWorkerWire,
        send_target: crate::node::encrypt_worker::SelectedSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> crate::node::encrypt_worker::FmpSendJob {
        worker_wire.into_job(
            send_target,
            self.bulk_endpoint_data,
            self.drop_on_backpressure,
            endpoint_flow_dispatch_key(self.payload.as_slice()).map(|key| key.get()),
            self.scheduling_weight,
            queued_at,
        )
    }
}

#[cfg(unix)]
impl PipelinedEndpointRoutePlan {
    fn new(
        source_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Self {
        Self {
            source_addr,
            next_hop_addr,
            path_mtu,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        }
    }

    fn direct_fmp_endpoint_batch_eligible(
        &self,
        dest_addr: NodeAddr,
        payloads: &[EndpointDataPayload],
        direct_fmp_opt_in: bool,
    ) -> bool {
        (direct_fmp_opt_in
            || payloads
                .iter()
                .all(EndpointDataPayload::direct_fmp_endpoint_allowed))
            && self.next_hop_addr == dest_addr
            && !self.direct_path_blocks_direct_payload
            && !payloads.is_empty()
            && payloads
                .iter()
                .all(EndpointDataPayload::bulk_endpoint_data)
    }

    fn build_send_plan<'a>(
        &self,
        send: &PipelinedEndpointSend<'a>,
    ) -> Result<PipelinedEndpointSendPlan<'a>, PipelinedEndpointSendPlanError> {
        PipelinedEndpointSendPlan::new(
            &self.source_addr,
            send,
            self.next_hop_addr,
            self.path_mtu,
            self.default_ttl,
            self.scheduling_weight,
            self.direct_path_blocks_direct_payload,
        )
    }
}

#[cfg(unix)]
impl PipelinedEndpointPeerRuntimeRoute {
    fn new(
        source_addr: NodeAddr,
        peer_snapshot: crate::node::PeerRuntimeRouteSnapshot,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Self {
        Self {
            source_addr,
            peer_snapshot,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        }
    }

    fn from_decision(
        source_addr: NodeAddr,
        default_ttl: u8,
        decision: crate::node::PeerRuntimeRouteDecision,
    ) -> Self {
        let (peer_snapshot, scheduling_weight, direct_path_blocks_direct_payload) =
            decision.into_parts();
        Self::new(
            source_addr,
            peer_snapshot,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        )
    }

    #[cfg(test)]
    fn next_hop_addr(&self) -> NodeAddr {
        self.peer_snapshot.node_addr()
    }

    fn transport_id(&self) -> crate::transport::TransportId {
        self.peer_snapshot.transport_id()
    }

    #[cfg(test)]
    fn default_ttl(&self) -> u8 {
        self.default_ttl
    }

    #[cfg(test)]
    fn scheduling_weight(&self) -> u8 {
        self.scheduling_weight
    }

    #[cfg(test)]
    fn direct_path_blocks_direct_payload(&self) -> bool {
        self.direct_path_blocks_direct_payload
    }

    fn route_plan(
        &self,
        transport: &crate::transport::TransportHandle,
    ) -> PipelinedEndpointRoutePlan {
        PipelinedEndpointRoutePlan::new(
            self.source_addr,
            self.peer_snapshot.node_addr(),
            self.peer_snapshot.path_mtu(transport),
            self.default_ttl,
            self.scheduling_weight,
            self.direct_path_blocks_direct_payload,
        )
    }

    async fn resolve_send_target(
        &self,
        transports: &std::collections::HashMap<
            crate::transport::TransportId,
            crate::transport::TransportHandle,
        >,
    ) -> Result<Option<PipelinedEndpointResolvedRoute>, PipelinedEndpointRuntimeSendError> {
        let transport_id = self.transport_id();
        let transport = transports
            .get(&transport_id)
            .ok_or(PipelinedEndpointRuntimeSendError::TransportNotFound(
                transport_id,
            ))?;
        let crate::transport::TransportHandle::Udp(udp) = transport else {
            return Ok(None);
        };

        let route_plan = self.route_plan(transport);
        let target_snapshot = self.peer_snapshot.prepare_send_snapshot(false, 0);
        let Some(send_target) =
            PipelinedEndpointSendTarget::resolve(udp, target_snapshot.fmp_prepared()).await
        else {
            return Ok(None);
        };

        Ok(Some(PipelinedEndpointResolvedRoute::new(
            route_plan,
            self.peer_snapshot.clone(),
            send_target,
        )))
    }

    #[cfg(test)]
    fn into_runtime_send_plan<'a>(
        self,
        send: &PipelinedEndpointSend<'a>,
        transport: &crate::transport::TransportHandle,
    ) -> Result<PipelinedEndpointRuntimeSendPlan<'a>, PipelinedEndpointRuntimeSendPlanError> {
        let route_plan = self.route_plan(transport);
        let send_plan = route_plan
            .build_send_plan(send)
            .map_err(PipelinedEndpointRuntimeSendPlanError::SendPlan)?;
        PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
            route_plan,
            send_plan,
            self.peer_snapshot,
        )
    }
}

#[cfg(unix)]
impl PipelinedEndpointResolvedRoute {
    fn new(
        route_plan: PipelinedEndpointRoutePlan,
        peer_snapshot: crate::node::PeerRuntimeRouteSnapshot,
        send_target: PipelinedEndpointSendTarget,
    ) -> Self {
        Self {
            route_plan,
            peer_snapshot,
            send_target,
        }
    }

    fn next_hop_addr(&self) -> NodeAddr {
        self.route_plan.next_hop_addr
    }

    fn send_target(&self) -> PipelinedEndpointSendTarget {
        self.send_target.clone()
    }

    fn runtime_send_plan<'a>(
        &self,
        send: &PipelinedEndpointSend<'a>,
    ) -> Result<PipelinedEndpointRuntimeSendPlan<'a>, PipelinedEndpointRuntimeSendPlanError> {
        let send_plan = self
            .route_plan
            .build_send_plan(send)
            .map_err(PipelinedEndpointRuntimeSendPlanError::SendPlan)?;
        PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
            self.route_plan,
            send_plan,
            self.peer_snapshot.clone(),
        )
    }
}

#[cfg(unix)]
impl PipelinedEndpointPeerRuntimeRouteRequest {
    fn new(source_addr: NodeAddr, dest_addr: NodeAddr, now_ms: u64, default_ttl: u8) -> Self {
        Self {
            source_addr,
            dest_addr,
            now_ms,
            default_ttl,
        }
    }

    fn resolve(
        self,
        node: &mut Node,
    ) -> Result<PipelinedEndpointPeerRuntimeRoute, PipelinedEndpointPeerRuntimeRouteRequestError>
    {
        let decision = node
            .resolve_peer_runtime_route_decision(&self.dest_addr, self.now_ms)
            .map_err(Self::map_route_decision_error)?;

        Ok(PipelinedEndpointPeerRuntimeRoute::from_decision(
            self.source_addr,
            self.default_ttl,
            decision,
        ))
    }

    fn map_route_decision_error(
        error: crate::node::PeerRuntimeRouteDecisionError,
    ) -> PipelinedEndpointPeerRuntimeRouteRequestError {
        match error {
            crate::node::PeerRuntimeRouteDecisionError::NoRoute { dest_addr } => {
                PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr }
            }
            crate::node::PeerRuntimeRouteDecisionError::FmpPreparation {
                next_hop_addr,
                error,
            } => PipelinedEndpointPeerRuntimeRouteRequestError::FmpPreparation {
                next_hop_addr,
                error,
            },
        }
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointSendPlan<'a> {
    fn new(
        source_addr: &NodeAddr,
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Result<Self, PipelinedEndpointSendPlanError> {
        Self::new_with_direct_fmp_opt_in(
            source_addr,
            send,
            next_hop_addr,
            path_mtu,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
            direct_endpoint_fmp_only_enabled(),
        )
    }

    fn new_with_direct_fmp_opt_in(
        source_addr: &NodeAddr,
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
        direct_fmp_opt_in: bool,
    ) -> Result<Self, PipelinedEndpointSendPlanError> {
        let dispatch_plan = PipelinedEndpointDispatchPlan::new_with_direct_fmp_opt_in(
            send,
            next_hop_addr,
            path_mtu,
            scheduling_weight,
            direct_path_blocks_direct_payload,
            direct_fmp_opt_in,
        )
        .ok_or(PipelinedEndpointSendPlanError::FspPayloadTooLarge)?;

        if let Some(direct_fmp_payload_len) = dispatch_plan.direct_fmp_payload_len() {
            return Ok(Self {
                wire_plan: None,
                dispatch_plan,
                direct_fmp_payload_len: Some(direct_fmp_payload_len),
            });
        }

        let wire_plan = PipelinedEndpointWirePlan::new(
            source_addr,
            send.dest_addr,
            send.inner_plaintext,
            send.my_coords,
            send.dest_coords,
            path_mtu,
            default_ttl,
        )
        .ok_or(PipelinedEndpointSendPlanError::FmpPayloadTooLarge)?;

        Ok(Self {
            wire_plan: Some(wire_plan),
            dispatch_plan,
            direct_fmp_payload_len: None,
        })
    }

    fn link_plaintext_len(&self) -> usize {
        match &self.wire_plan {
            Some(wire_plan) => wire_plan.link_plaintext_len(),
            None => 1 + self.dispatch_plan.payload.len(),
        }
    }

    fn fmp_payload_len(&self) -> u16 {
        self.direct_fmp_payload_len.unwrap_or_else(|| {
            self.wire_plan
                .as_ref()
                .expect("normal pipelined endpoint send keeps a wire plan")
                .fmp_payload_len()
        })
    }

    fn dest_addr(&self) -> NodeAddr {
        self.dispatch_plan.dest_addr
    }

    fn direct_fmp_endpoint(&self) -> bool {
        self.dispatch_plan.direct_fmp_endpoint
    }

    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        self.dispatch_plan.fsp_reservation_input()
    }

    fn into_prepared_worker_send(
        self,
        fmp_prepared: &crate::node::FmpSendPreparation,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
        send_target: PipelinedEndpointSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        debug_assert_eq!(fmp_prepared.payload_len, self.fmp_payload_len());
        let originated_bytes = self.link_plaintext_len() + crate::noise::TAG_SIZE;
        let wire_plan = self
            .wire_plan
            .expect("normal pipelined endpoint send keeps a wire plan");
        let dest_addr = wire_plan.dest_addr;
        let next_hop_addr = self.dispatch_plan.next_hop_addr;
        let wire = wire_plan.build(
            fmp_reservation.header,
            fsp_reservation.header,
            fmp_prepared.timestamp_ms,
        );
        let worker_wire = wire.into_worker_wire(fmp_reservation, fsp_reservation);
        debug_assert_eq!(
            worker_wire.link_plaintext_len,
            wire_plan.link_plaintext_len()
        );

        let fmp_counter = worker_wire.fmp_counter;
        let fsp_counter = worker_wire.fsp_counter;
        let fmp_wire_capacity = worker_wire.wire_capacity;
        let session_bookkeeping = PipelinedEndpointSessionBookkeeping::Fsp(
            self.dispatch_plan.fsp_bookkeeping_input(fsp_counter),
        );
        let worker_job = self.dispatch_plan.into_worker_job(
            worker_wire,
            send_target.into_selected_send_target(),
            queued_at,
        );

        PipelinedEndpointPreparedSend {
            dest_addr,
            next_hop_addr,
            fmp_counter,
            fmp_timestamp_ms: fmp_prepared.timestamp_ms,
            fmp_wire_capacity,
            originated_bytes,
            session_bookkeeping,
            worker_job,
        }
    }

    fn into_prepared_direct_fmp_worker_send(
        self,
        fmp_prepared: &crate::node::FmpSendPreparation,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        send_target: PipelinedEndpointSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        debug_assert!(self.direct_fmp_endpoint());
        debug_assert_eq!(fmp_prepared.payload_len, self.fmp_payload_len());
        debug_assert_eq!(fmp_reservation.predicted_bytes, ESTABLISHED_HEADER_SIZE + fmp_prepared.payload_len as usize + crate::noise::TAG_SIZE);

        let dest_addr = self.dispatch_plan.dest_addr;
        let next_hop_addr = self.dispatch_plan.next_hop_addr;
        let wire_capacity = fmp_reservation.predicted_bytes;
        let mut wire_buf = Vec::with_capacity(wire_capacity);
        wire_buf.extend_from_slice(&fmp_reservation.header);
        wire_buf.extend_from_slice(&fmp_prepared.timestamp_ms.to_le_bytes());
        wire_buf.push(LinkMessageType::DirectEndpointData.to_byte());
        wire_buf.extend_from_slice(self.dispatch_plan.payload.as_slice());
        debug_assert_eq!(
            wire_buf.len(),
            ESTABLISHED_HEADER_SIZE + fmp_prepared.payload_len as usize
        );

        let worker_job = crate::node::encrypt_worker::FmpSendJob {
            cipher: fmp_reservation.cipher,
            counter: fmp_reservation.counter,
            wire_buf,
            fsp_seal: None,
            send_target: send_target.into_selected_send_target(),
            endpoint_flow_dispatch_key: endpoint_flow_dispatch_key(
                self.dispatch_plan.payload.as_slice(),
            )
            .map(|key| key.get()),
            bulk_endpoint_data: self.dispatch_plan.bulk_endpoint_data,
            drop_on_backpressure: self.dispatch_plan.drop_on_backpressure,
            scheduling_weight: self.dispatch_plan.scheduling_weight,
            queued_at,
        };

        PipelinedEndpointPreparedSend {
            dest_addr,
            next_hop_addr,
            fmp_counter: fmp_reservation.counter,
            fmp_timestamp_ms: fmp_prepared.timestamp_ms,
            fmp_wire_capacity: wire_capacity,
            originated_bytes: self.link_plaintext_len() + crate::noise::TAG_SIZE,
            session_bookkeeping: self.dispatch_plan.direct_fmp_bookkeeping_input(),
            worker_job,
        }
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSendPlan<'a> {
    fn from_peer_route_snapshot(
        route_plan: PipelinedEndpointRoutePlan,
        send_plan: PipelinedEndpointSendPlan<'a>,
        peer_route_snapshot: crate::node::PeerRuntimeRouteSnapshot,
    ) -> Result<Self, PipelinedEndpointRuntimeSendPlanError> {
        let peer_snapshot_addr = peer_route_snapshot.node_addr();
        if route_plan.next_hop_addr != peer_snapshot_addr {
            return Err(PipelinedEndpointRuntimeSendPlanError::RoutePeerMismatch {
                route_next_hop: route_plan.next_hop_addr,
                peer_snapshot_addr,
            });
        }

        let peer_snapshot =
            peer_route_snapshot.prepare_send_snapshot(false, send_plan.fmp_payload_len());
        Self::from_parts(route_plan, send_plan, peer_snapshot)
    }

    fn from_parts(
        route_plan: PipelinedEndpointRoutePlan,
        send_plan: PipelinedEndpointSendPlan<'a>,
        peer_snapshot: crate::node::PeerRuntimeSendSnapshot,
    ) -> Result<Self, PipelinedEndpointRuntimeSendPlanError> {
        let plan_payload_len = send_plan.fmp_payload_len();
        let fmp_prepared = peer_snapshot.fmp_prepared();
        if fmp_prepared.payload_len != plan_payload_len {
            return Err(PipelinedEndpointRuntimeSendPlanError::FmpPayloadMismatch {
                prepared_payload_len: fmp_prepared.payload_len,
                plan_payload_len,
            });
        }

        Ok(Self {
            route_plan,
            send_plan,
            peer_snapshot,
        })
    }

    #[cfg(test)]
    fn source_addr(&self) -> NodeAddr {
        self.route_plan.source_addr
    }

    fn dest_addr(&self) -> NodeAddr {
        self.send_plan.dest_addr()
    }

    fn next_hop_addr(&self) -> NodeAddr {
        self.route_plan.next_hop_addr
    }

    #[cfg(test)]
    fn transport_id(&self) -> crate::transport::TransportId {
        self.peer_snapshot.fmp_prepared().transport_id
    }

    #[cfg(test)]
    fn fmp_payload_len(&self) -> u16 {
        self.send_plan.fmp_payload_len()
    }

    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        self.send_plan.fsp_reservation_input()
    }

    fn direct_fmp_endpoint(&self) -> bool {
        self.send_plan.direct_fmp_endpoint()
    }

    #[cfg(test)]
    fn drop_on_backpressure(&self) -> bool {
        self.send_plan.dispatch_plan.drop_on_backpressure
    }

    #[cfg(test)]
    fn scheduling_weight(&self) -> u8 {
        self.send_plan.dispatch_plan.scheduling_weight
    }

    #[cfg(test)]
    fn fmp_prepared(&self) -> &crate::node::FmpSendPreparation {
        self.peer_snapshot.fmp_prepared()
    }

    fn peer_snapshot(&self) -> &crate::node::PeerRuntimeSendSnapshot {
        &self.peer_snapshot
    }

    fn fmp_worker_send_available(&self) -> bool {
        self.peer_snapshot.fmp_worker_send_available()
    }

    #[cfg(test)]
    async fn resolve_send_target(
        &self,
        udp: &crate::transport::udp::UdpTransport,
    ) -> Option<PipelinedEndpointSendTarget> {
        PipelinedEndpointSendTarget::resolve(udp, self.fmp_prepared()).await
    }

    fn into_prepared_worker_send(
        self,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: Option<crate::node::session::FspSendReservation>,
        send_target: PipelinedEndpointSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        let Self {
            send_plan,
            peer_snapshot,
            ..
        } = self;
        let fmp_prepared = peer_snapshot.fmp_prepared();
        if send_plan.direct_fmp_endpoint() {
            return send_plan.into_prepared_direct_fmp_worker_send(
                fmp_prepared,
                fmp_reservation,
                send_target,
                queued_at,
            );
        }
        let fsp_reservation =
            fsp_reservation.expect("normal pipelined endpoint send reserves FSP state");
        send_plan.into_prepared_worker_send(
            fmp_prepared,
            fmp_reservation,
            fsp_reservation,
            send_target,
            queued_at,
        )
    }

    #[cfg(test)]
    fn into_parts_for_test(self) -> (PipelinedEndpointRoutePlan, PipelinedEndpointSendPlan<'a>) {
        (self.route_plan, self.send_plan)
    }
}
