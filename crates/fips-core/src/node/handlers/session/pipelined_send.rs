#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSendDispatch<'a> {
    fn new(
        runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
        send_target: PipelinedEndpointSendTarget,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
    ) -> Self {
        Self {
            runtime_plan,
            send_target,
            fmp_reservation,
            fsp_reservation,
        }
    }

    #[cfg(test)]
    fn dest_addr(&self) -> NodeAddr {
        self.runtime_plan.dest_addr()
    }

    #[cfg(test)]
    fn next_hop_addr(&self) -> NodeAddr {
        self.runtime_plan.next_hop_addr()
    }

    #[cfg(test)]
    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        self.runtime_plan.fsp_reservation_input()
    }

    fn into_prepared_send(
        self,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        let Self {
            runtime_plan,
            send_target,
            fmp_reservation,
            fsp_reservation,
        } = self;
        runtime_plan.into_prepared_worker_send(
            fmp_reservation,
            fsp_reservation,
            send_target,
            queued_at,
        )
    }

    fn commit(self, node: &mut Node, workers: &crate::node::encrypt_worker::EncryptWorkerPool) {
        self.into_prepared_send(crate::perf_profile::stamp())
            .commit(node, workers);
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSendAttempt<'a> {
    fn new(
        runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
        send_target: PipelinedEndpointSendTarget,
    ) -> Self {
        Self {
            runtime_plan,
            send_target,
        }
    }

    fn reserve(
        self,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointRuntimeSendAttemptError,
    > {
        let Self {
            runtime_plan,
            send_target,
        } = self;

        if !runtime_plan.fmp_worker_send_available() {
            return Ok(None);
        }

        let dest_addr = runtime_plan.dest_addr();
        let next_hop_addr = runtime_plan.next_hop_addr();
        let Some(fsp_reservation) = sessions
            .reserve_endpoint_data_fsp_worker_send(&dest_addr, runtime_plan.fsp_reservation_input())
            .map_err(
                |error| PipelinedEndpointRuntimeSendAttemptError::FspReservation {
                    dest_addr,
                    error,
                },
            )?
        else {
            return Ok(None);
        };

        let Some(fmp_reservation) = peers
            .reserve_peer_runtime_fmp_worker_send(runtime_plan.peer_snapshot())
            .map_err(
                |error| PipelinedEndpointRuntimeSendAttemptError::FmpReservation {
                    next_hop_addr,
                    error,
                },
            )?
        else {
            return Ok(None);
        };

        Ok(Some(PipelinedEndpointRuntimeSendDispatch::new(
            runtime_plan,
            send_target,
            fmp_reservation,
            fsp_reservation,
        )))
    }
}

#[cfg(all(test, unix))]
impl<'a> PipelinedEndpointRuntimeBatchSendAttempt<'a> {
    fn new(
        runtime_plans: Vec<PipelinedEndpointRuntimeSendPlan<'a>>,
        send_target: PipelinedEndpointSendTarget,
    ) -> Self {
        Self {
            runtime_plans,
            send_target,
        }
    }

    fn reserve(
        self,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<Option<Vec<PipelinedEndpointPreparedSend>>, PipelinedEndpointRuntimeSendAttemptError>
    {
        let Self {
            runtime_plans,
            send_target,
        } = self;

        let Some(first) = runtime_plans.first() else {
            return Ok(Some(Vec::new()));
        };
        if runtime_plans
            .iter()
            .any(|runtime_plan| !runtime_plan.fmp_worker_send_available())
        {
            return Ok(None);
        }

        let dest_addr = first.dest_addr();
        let next_hop_addr = first.next_hop_addr();
        debug_assert!(runtime_plans.iter().all(|runtime_plan| {
            runtime_plan.dest_addr() == dest_addr
                && runtime_plan.next_hop_addr() == next_hop_addr
        }));

        let fsp_inputs = runtime_plans
            .iter()
            .map(|runtime_plan| runtime_plan.fsp_reservation_input())
            .collect::<Vec<_>>();
        let Some(fsp_reservations) = sessions
            .reserve_endpoint_data_fsp_worker_send_batch(&dest_addr, &fsp_inputs)
            .map_err(
                |error| PipelinedEndpointRuntimeSendAttemptError::FspReservation {
                    dest_addr,
                    error,
                },
            )?
        else {
            return Ok(None);
        };

        let Some(fmp_reservations) = peers
            .reserve_peer_runtime_fmp_worker_send_batch(
                &next_hop_addr,
                runtime_plans
                    .iter()
                    .map(|runtime_plan| runtime_plan.peer_snapshot()),
            )
            .map_err(
                |error| PipelinedEndpointRuntimeSendAttemptError::FmpReservation {
                    next_hop_addr,
                    error,
                },
            )?
        else {
            return Ok(None);
        };

        debug_assert_eq!(runtime_plans.len(), fsp_reservations.len());
        debug_assert_eq!(runtime_plans.len(), fmp_reservations.len());

        let prepared_sends = runtime_plans
            .into_iter()
            .zip(fmp_reservations)
            .zip(fsp_reservations)
            .map(|((runtime_plan, fmp_reservation), fsp_reservation)| {
                runtime_plan.into_prepared_worker_send(
                    fmp_reservation,
                    fsp_reservation,
                    send_target.clone(),
                    None,
                )
            })
            .collect();

        Ok(Some(prepared_sends))
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct PipelinedEndpointBookkeeping {
    dest_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    fmp_counter: u64,
    fmp_timestamp_ms: u32,
    fmp_wire_capacity: usize,
    originated_bytes: usize,
    fsp_path_mtu: u16,
    fsp_bookkeeping: FspSendBookkeepingInput,
}

#[cfg(unix)]
fn record_pipelined_endpoint_session_bookkeeping(
    node: &mut Node,
    record: &PipelinedEndpointBookkeeping,
) {
    let _ = node
        .sessions
        .seed_endpoint_data_fsp_path_mtu_batch(&record.dest_addr, [record.fsp_path_mtu]);
    let _ = node
        .sessions
        .record_fsp_send_bookkeeping(&record.dest_addr, record.fsp_bookkeeping);
}

#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSend<'a> {
    fn new(runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>) -> Self {
        Self { runtime_plan }
    }

    async fn resolve_dispatch_with_transport(
        self,
        transport: &crate::transport::TransportHandle,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<Option<PipelinedEndpointRuntimeSendDispatch<'a>>, PipelinedEndpointRuntimeSendError>
    {
        let crate::transport::TransportHandle::Udp(udp) = transport else {
            return Ok(None);
        };
        let Some(send_target) = self.runtime_plan.resolve_send_target(udp).await else {
            return Ok(None);
        };

        PipelinedEndpointRuntimeSendAttempt::new(self.runtime_plan, send_target)
            .reserve(sessions, peers)
            .map_err(PipelinedEndpointRuntimeSendError::Attempt)
    }

    #[cfg(test)]
    async fn resolve_dispatch(
        self,
        transports: &std::collections::HashMap<
            crate::transport::TransportId,
            crate::transport::TransportHandle,
        >,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<Option<PipelinedEndpointRuntimeSendDispatch<'a>>, PipelinedEndpointRuntimeSendError>
    {
        let transport_id = self.runtime_plan.transport_id();
        let transport = transports.get(&transport_id).ok_or(
            PipelinedEndpointRuntimeSendError::TransportNotFound(transport_id),
        )?;
        self.resolve_dispatch_with_transport(transport, sessions, peers)
            .await
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointPeerRuntimeSend<'a> {
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(
        runtime_route: PipelinedEndpointPeerRuntimeRoute,
        send: PipelinedEndpointSend<'a>,
    ) -> Self {
        Self {
            runtime_route,
            send,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn resolve_dispatch_with_route(
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
        send: PipelinedEndpointSend<'a>,
        transports: &std::collections::HashMap<
            crate::transport::TransportId,
            crate::transport::TransportHandle,
        >,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendError,
    > {
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSendPlan);
        let dest_addr = *send.dest_addr;
        let next_hop_addr = runtime_route.next_hop_addr();
        let transport_id = runtime_route.transport_id();
        let transport = transports.get(&transport_id).ok_or(
            PipelinedEndpointPeerRuntimeSendError::RuntimeSend(
                PipelinedEndpointRuntimeSendError::TransportNotFound(transport_id),
            ),
        )?;
        let runtime_plan = runtime_route
            .runtime_send_plan(&send, transport)
            .map_err(|error| PipelinedEndpointPeerRuntimeSendError::RuntimePlan {
                dest_addr,
                next_hop_addr,
                error,
            })?;

        PipelinedEndpointRuntimeSend::new(runtime_plan)
            .resolve_dispatch_with_transport(transport, sessions, peers)
            .await
            .map_err(PipelinedEndpointPeerRuntimeSendError::RuntimeSend)
    }

    #[cfg(test)]
    fn resolve_dispatch_with_batch_target(
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
        send: PipelinedEndpointSend<'a>,
        batch_target: &PipelinedEndpointBatchTarget,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendError,
    > {
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSendPlan);
        let dest_addr = *send.dest_addr;
        let next_hop_addr = runtime_route.next_hop_addr();
        let runtime_plan = runtime_route
            .runtime_send_plan_with_path_mtu(&send, batch_target.path_mtu)
            .map_err(|error| PipelinedEndpointPeerRuntimeSendError::RuntimePlan {
                dest_addr,
                next_hop_addr,
                error,
            })?;

        PipelinedEndpointRuntimeSendAttempt::new(
            runtime_plan,
            batch_target.send_target.clone(),
        )
        .reserve(sessions, peers)
        .map_err(|error| {
            PipelinedEndpointPeerRuntimeSendError::RuntimeSend(
                PipelinedEndpointRuntimeSendError::Attempt(error),
            )
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn resolve_dispatch(
        self,
        transports: &std::collections::HashMap<
            crate::transport::TransportId,
            crate::transport::TransportHandle,
        >,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendError,
    > {
        Self::resolve_dispatch_with_route(
            &self.runtime_route,
            self.send,
            transports,
            sessions,
            peers,
        )
        .await
    }
}

#[cfg(all(test, unix))]
impl PipelinedEndpointPeerRuntimeBatchSend {
    fn resolve_prepared_sends_with_batch_target<'a, I>(
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
        sends: I,
        batch_target: &PipelinedEndpointBatchTarget,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<Option<Vec<PipelinedEndpointPreparedSend>>, PipelinedEndpointPeerRuntimeSendError>
    where
        I: IntoIterator<Item = PipelinedEndpointSend<'a>>,
    {
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSendPlan);
        let next_hop_addr = runtime_route.next_hop_addr();
        let mut runtime_plans = Vec::new();

        for send in sends {
            let dest_addr = *send.dest_addr;
            let runtime_plan = runtime_route
                .runtime_send_plan_with_path_mtu(&send, batch_target.path_mtu)
                .map_err(|error| PipelinedEndpointPeerRuntimeSendError::RuntimePlan {
                    dest_addr,
                    next_hop_addr,
                    error,
                })?;
            runtime_plans.push(runtime_plan);
        }

        PipelinedEndpointRuntimeBatchSendAttempt::new(
            runtime_plans,
            batch_target.send_target.clone(),
        )
        .reserve(sessions, peers)
        .map_err(|error| {
            PipelinedEndpointPeerRuntimeSendError::RuntimeSend(
                PipelinedEndpointRuntimeSendError::Attempt(error),
            )
        })
    }
}

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))]
impl<'a> PipelinedEndpointPeerRuntimeSendRequest<'a> {
    fn new(source_addr: NodeAddr, send: PipelinedEndpointSend<'a>, default_ttl: u8) -> Self {
        let route_request = PipelinedEndpointPeerRuntimeRouteRequest::new(
            source_addr,
            *send.dest_addr,
            send.now_ms,
            default_ttl,
        );
        Self {
            route_request,
            send,
        }
    }

    async fn resolve_dispatch(
        self,
        node: &mut Node,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendRequestError,
    > {
        let runtime_route = self
            .route_request
            .resolve(node)
            .map_err(PipelinedEndpointPeerRuntimeSendRequestError::Route)?;

        PipelinedEndpointPeerRuntimeSend::new(runtime_route, self.send)
            .resolve_dispatch(&node.transports, &mut node.sessions, &mut node.peers)
            .await
            .map_err(PipelinedEndpointPeerRuntimeSendRequestError::Send)
    }

    async fn execute(
        self,
        node: &mut Node,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) -> Result<bool, PipelinedEndpointPeerRuntimeSendRequestError> {
        let Some(dispatch) = self.resolve_dispatch(node).await? else {
            return Ok(false);
        };
        dispatch.commit(node, workers);
        Ok(true)
    }
}

#[cfg(unix)]
impl PipelinedEndpointPreparedSend {
    fn into_bookkeeping_and_job(
        self,
    ) -> (
        PipelinedEndpointBookkeeping,
        crate::node::encrypt_worker::FmpSendJob,
    ) {
        let PipelinedEndpointPreparedSend {
            dest_addr,
            next_hop_addr,
            fmp_counter,
            fmp_timestamp_ms,
            fmp_wire_capacity,
            originated_bytes,
            fsp_path_mtu,
            fsp_bookkeeping,
            worker_job,
        } = self;

        (
            PipelinedEndpointBookkeeping {
                dest_addr,
                next_hop_addr,
                fmp_counter,
                fmp_timestamp_ms,
                fmp_wire_capacity,
                originated_bytes,
                fsp_path_mtu,
                fsp_bookkeeping,
            },
            worker_job,
        )
    }

    fn record_bookkeeping(self, node: &mut Node) -> crate::node::encrypt_worker::FmpSendJob {
        let (bookkeeping, worker_job) = self.into_bookkeeping_and_job();

        let _ = node.peers.record_fmp_send_bookkeeping(
            &bookkeeping.next_hop_addr,
            bookkeeping.fmp_counter,
            bookkeeping.fmp_timestamp_ms,
            bookkeeping.fmp_wire_capacity,
        );
        node.stats_mut()
            .forwarding
            .record_originated(bookkeeping.originated_bytes);

        record_pipelined_endpoint_session_bookkeeping(node, &bookkeeping);

        worker_job
    }

    fn commit(self, node: &mut Node, workers: &crate::node::encrypt_worker::EncryptWorkerPool) {
        let _t = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::EndpointSendCommit,
        );
        let mut worker_job = self.record_bookkeeping(node);
        if worker_job.queued_at.is_none() {
            worker_job.queued_at = crate::perf_profile::stamp();
        }
        workers.dispatch(worker_job);
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointWireBody<'a> {
    fn inner_plaintext_len(&self) -> usize {
        match self {
            Self::InnerPlaintext(inner_plaintext) => inner_plaintext.len(),
            Self::EndpointPayload { payload, .. } => FSP_INNER_HEADER_SIZE + payload.len(),
        }
    }

    fn append_inner_plaintext(&self, wire_buf: &mut Vec<u8>) {
        match self {
            Self::InnerPlaintext(inner_plaintext) => {
                wire_buf.extend_from_slice(inner_plaintext);
            }
            Self::EndpointPayload {
                timestamp,
                msg_type,
                inner_flags,
                payload,
            } => {
                wire_buf.extend_from_slice(&timestamp.to_le_bytes());
                wire_buf.push(*msg_type);
                wire_buf.push(*inner_flags);
                wire_buf.extend_from_slice(payload);
            }
        }
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointWirePlan<'a> {
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(
        source_addr: &NodeAddr,
        dest_addr: &NodeAddr,
        inner_plaintext: &'a [u8],
        my_coords: Option<&'a crate::tree::TreeCoordinate>,
        dest_coords: Option<&'a crate::tree::TreeCoordinate>,
        path_mtu: u16,
        default_ttl: u8,
    ) -> Option<Self> {
        Self::new_with_body(
            source_addr,
            dest_addr,
            PipelinedEndpointWireBody::InnerPlaintext(inner_plaintext),
            my_coords,
            dest_coords,
            path_mtu,
            default_ttl,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn new_endpoint_payload(
        source_addr: &NodeAddr,
        dest_addr: &NodeAddr,
        timestamp: u32,
        msg_type: u8,
        inner_flags: u8,
        payload: &'a [u8],
        my_coords: Option<&'a crate::tree::TreeCoordinate>,
        dest_coords: Option<&'a crate::tree::TreeCoordinate>,
        path_mtu: u16,
        default_ttl: u8,
    ) -> Option<Self> {
        Self::new_with_body(
            source_addr,
            dest_addr,
            PipelinedEndpointWireBody::EndpointPayload {
                timestamp,
                msg_type,
                inner_flags,
                payload,
            },
            my_coords,
            dest_coords,
            path_mtu,
            default_ttl,
        )
    }

    fn new_with_body(
        source_addr: &NodeAddr,
        dest_addr: &NodeAddr,
        body: PipelinedEndpointWireBody<'a>,
        my_coords: Option<&'a crate::tree::TreeCoordinate>,
        dest_coords: Option<&'a crate::tree::TreeCoordinate>,
        path_mtu: u16,
        default_ttl: u8,
    ) -> Option<Self> {
        let inner_plaintext_len = body.inner_plaintext_len();
        let link_plaintext_len =
            pipelined_endpoint_link_plaintext_len(inner_plaintext_len, my_coords, dest_coords);
        let fmp_payload_len = pipelined_endpoint_fmp_payload_len(link_plaintext_len)?;
        Some(Self {
            source_addr: *source_addr,
            dest_addr: *dest_addr,
            body,
            my_coords,
            dest_coords,
            path_mtu,
            default_ttl,
            link_plaintext_len,
            fmp_payload_len,
        })
    }

    fn link_plaintext_len(&self) -> usize {
        self.link_plaintext_len
    }

    fn fmp_payload_len(&self) -> u16 {
        self.fmp_payload_len
    }

    fn build(
        &self,
        fmp_header: [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE],
        fsp_header: [u8; FSP_HEADER_SIZE],
        timestamp_ms: u32,
    ) -> PipelinedEndpointWire {
        let fmp_inner_len = self.fmp_payload_len as usize;

        let wire_capacity =
            crate::node::wire::ESTABLISHED_HEADER_SIZE + fmp_inner_len + crate::noise::TAG_SIZE;
        let mut wire_buf = Vec::with_capacity(wire_capacity);
        wire_buf.extend_from_slice(&fmp_header);
        wire_buf.extend_from_slice(&timestamp_ms.to_le_bytes());
        wire_buf.push(LinkMessageType::SessionDatagram.to_byte());
        wire_buf.push(self.default_ttl);
        wire_buf.extend_from_slice(&self.path_mtu.to_le_bytes());
        wire_buf.extend_from_slice(self.source_addr.as_bytes());
        wire_buf.extend_from_slice(self.dest_addr.as_bytes());
        let fsp_aad_offset = wire_buf.len();
        wire_buf.extend_from_slice(&fsp_header);
        if let (Some(src), Some(dst)) = (self.my_coords, self.dest_coords) {
            encode_coords(src, &mut wire_buf);
            encode_coords(dst, &mut wire_buf);
        }
        let fsp_plaintext_offset = wire_buf.len();
        self.body.append_inner_plaintext(&mut wire_buf);

        PipelinedEndpointWire {
            wire_buf,
            fsp_aad_offset,
            fsp_plaintext_offset,
            link_plaintext_len: self.link_plaintext_len,
            fmp_inner_len,
            wire_capacity,
        }
    }
}

#[cfg(unix)]
impl PipelinedEndpointWire {
    fn into_worker_wire(
        self,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
    ) -> PipelinedEndpointWorkerWire {
        debug_assert_eq!(self.wire_capacity, fmp_reservation.predicted_bytes);
        debug_assert_eq!(
            &self.wire_buf[..crate::node::wire::ESTABLISHED_HEADER_SIZE],
            &fmp_reservation.header
        );
        debug_assert_eq!(
            &self.wire_buf[self.fsp_aad_offset..self.fsp_aad_offset + FSP_HEADER_SIZE],
            &fsp_reservation.header
        );

        PipelinedEndpointWorkerWire {
            fmp_cipher: fmp_reservation.cipher,
            fmp_counter: fmp_reservation.counter,
            fsp_counter: fsp_reservation.counter,
            wire_buf: self.wire_buf,
            fsp_seal: crate::node::encrypt_worker::FspSealJob {
                cipher: fsp_reservation.cipher,
                counter: fsp_reservation.counter,
                aad_offset: self.fsp_aad_offset,
                plaintext_offset: self.fsp_plaintext_offset,
            },
            link_plaintext_len: self.link_plaintext_len,
            wire_capacity: self.wire_capacity,
        }
    }
}

#[cfg(unix)]
impl PipelinedEndpointWorkerWire {
    fn into_job(
        self,
        send_target: crate::node::encrypt_worker::SelectedSendTarget,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
        endpoint_flow_dispatch_key: Option<u64>,
        scheduling_weight: u8,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> crate::node::encrypt_worker::FmpSendJob {
        crate::node::encrypt_worker::FmpSendJob {
            cipher: self.fmp_cipher,
            counter: self.fmp_counter,
            wire_buf: self.wire_buf,
            fsp_seal: Some(self.fsp_seal),
            send_target,
            endpoint_flow_dispatch_key,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight,
            queued_at,
        }
    }
}
