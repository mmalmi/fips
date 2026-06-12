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
    fn new(
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Option<Self> {
        let fsp_payload_len = u16::try_from(send.inner_plaintext.len()).ok()?;
        let bulk_endpoint_data =
            send.fsp_flags & FSP_FLAG_CP == 0 && send.payload.bulk_endpoint_data();
        let drop_on_backpressure = next_hop_addr == *send.dest_addr
            && !direct_path_blocks_direct_payload
            && bulk_endpoint_data
            && send.payload.drop_on_backpressure();

        Some(Self {
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
            scheduling_weight,
        })
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

    fn runtime_send_plan<'a>(
        &self,
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
            self.peer_snapshot.clone(),
        )
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
        let dispatch_plan = PipelinedEndpointDispatchPlan::new(
            send,
            next_hop_addr,
            path_mtu,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        )
        .ok_or(PipelinedEndpointSendPlanError::FspPayloadTooLarge)?;

        Ok(Self {
            wire_plan,
            dispatch_plan,
        })
    }

    fn link_plaintext_len(&self) -> usize {
        self.wire_plan.link_plaintext_len()
    }

    fn fmp_payload_len(&self) -> u16 {
        self.wire_plan.fmp_payload_len()
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
        debug_assert_eq!(fmp_prepared.payload_len, self.wire_plan.fmp_payload_len());
        let dest_addr = self.wire_plan.dest_addr;
        let next_hop_addr = self.dispatch_plan.next_hop_addr;
        let wire = self.wire_plan.build(
            fmp_reservation.header,
            fsp_reservation.header,
            fmp_prepared.timestamp_ms,
        );
        let worker_wire = wire.into_worker_wire(fmp_reservation, fsp_reservation);
        debug_assert_eq!(
            worker_wire.link_plaintext_len,
            self.wire_plan.link_plaintext_len()
        );

        let fmp_counter = worker_wire.fmp_counter;
        let fsp_counter = worker_wire.fsp_counter;
        let fmp_wire_capacity = worker_wire.wire_capacity;
        let originated_bytes = self.link_plaintext_len() + crate::noise::TAG_SIZE;
        let fsp_bookkeeping = self.dispatch_plan.fsp_bookkeeping_input(fsp_counter);
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
            fsp_bookkeeping,
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
        self.send_plan.wire_plan.dest_addr
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

    #[cfg(test)]
    fn drop_on_backpressure(&self) -> bool {
        self.send_plan.dispatch_plan.drop_on_backpressure
    }

    #[cfg(test)]
    fn scheduling_weight(&self) -> u8 {
        self.send_plan.dispatch_plan.scheduling_weight
    }

    fn fmp_prepared(&self) -> &crate::node::FmpSendPreparation {
        self.peer_snapshot.fmp_prepared()
    }

    fn peer_snapshot(&self) -> &crate::node::PeerRuntimeSendSnapshot {
        &self.peer_snapshot
    }

    fn fmp_worker_send_available(&self) -> bool {
        self.peer_snapshot.fmp_worker_send_available()
    }

    async fn resolve_send_target(
        &self,
        udp: &crate::transport::udp::UdpTransport,
    ) -> Option<PipelinedEndpointSendTarget> {
        PipelinedEndpointSendTarget::resolve(udp, self.fmp_prepared()).await
    }

    fn into_prepared_worker_send(
        self,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
        send_target: PipelinedEndpointSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        let Self {
            send_plan,
            peer_snapshot,
            ..
        } = self;
        let fmp_prepared = peer_snapshot.fmp_prepared();
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
