#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSendDispatch<'a> {
    fn new(
        runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
        send_target: PipelinedEndpointSendTarget,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: Option<crate::node::session::FspSendReservation>,
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
        let _t =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointWorkerJobBuild);
        let Self {
            runtime_plan,
            send_target,
            fmp_reservation,
            fsp_reservation,
        } = self;
        runtime_plan.into_prepared_worker_send(fmp_reservation, fsp_reservation, send_target, queued_at)
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
        let fsp_reservation = if runtime_plan.direct_fmp_endpoint() {
            if !sessions.direct_endpoint_data_can_send(&dest_addr) {
                return Ok(None);
            }
            None
        } else {
            let Some(fsp_reservation) = sessions
                .reserve_endpoint_data_fsp_worker_send(
                    &dest_addr,
                    runtime_plan.fsp_reservation_input(),
                )
                .map_err(
                    |error| PipelinedEndpointRuntimeSendAttemptError::FspReservation {
                        dest_addr,
                        error,
                    },
                )?
            else {
                return Ok(None);
            };
            Some(fsp_reservation)
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

#[cfg(all(unix, test))]
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
        let TransportHandle::Udp(udp) = transport else {
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
    fn new(
        runtime_route: PipelinedEndpointPeerRuntimeRoute,
        send: PipelinedEndpointSend<'a>,
    ) -> Self {
        Self {
            runtime_route,
            send,
        }
    }

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
        let Some(resolved_route) = runtime_route
            .resolve_send_target(transports)
            .await
            .map_err(PipelinedEndpointPeerRuntimeSendError::RuntimeSend)?
        else {
            return Ok(None);
        };
        Self::resolve_dispatch_with_resolved_route(&resolved_route, send, sessions, peers)
    }

    fn resolve_dispatch_with_resolved_route(
        resolved_route: &PipelinedEndpointResolvedRoute,
        send: PipelinedEndpointSend<'a>,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendError,
    > {
        let dest_addr = *send.dest_addr;
        let next_hop_addr = resolved_route.next_hop_addr();
        let runtime_plan = resolved_route.runtime_send_plan(&send).map_err(|error| {
            PipelinedEndpointPeerRuntimeSendError::RuntimePlan {
                dest_addr,
                next_hop_addr,
                error,
            }
        })?;

        PipelinedEndpointRuntimeSendAttempt::new(runtime_plan, resolved_route.send_target())
            .reserve(sessions, peers)
            .map_err(PipelinedEndpointRuntimeSendError::Attempt)
            .map_err(PipelinedEndpointPeerRuntimeSendError::RuntimeSend)
    }

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

#[cfg(unix)]
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
impl PipelinedEndpointSessionBookkeeping {
    fn is_fsp(&self) -> bool {
        matches!(self, Self::Fsp(_))
    }

    fn is_direct_fmp(&self) -> bool {
        matches!(self, Self::DirectFmp { .. })
    }

    fn fsp(self) -> Option<FspSendBookkeepingInput> {
        match self {
            Self::Fsp(input) => Some(input),
            Self::DirectFmp { .. } => None,
        }
    }

    fn direct_fmp(self) -> Option<(usize, u64, NodeAddr)> {
        match self {
            Self::DirectFmp {
                payload_len,
                now_ms,
                next_hop,
            } => Some((payload_len, now_ms, next_hop)),
            Self::Fsp(_) => None,
        }
    }
}

#[cfg(unix)]
impl PipelinedEndpointPreparedBookkeeping {
    fn record_session_send(&self, node: &mut Node) {
        match self.session_bookkeeping {
            PipelinedEndpointSessionBookkeeping::Fsp(input) => {
                let _ = node
                    .sessions
                    .record_fsp_send_bookkeeping(&self.dest_addr, input);
            }
            PipelinedEndpointSessionBookkeeping::DirectFmp {
                payload_len,
                now_ms,
                next_hop,
            } => {
                let _ = node.sessions.record_direct_endpoint_data_send(
                    &self.dest_addr,
                    payload_len,
                    now_ms,
                    next_hop,
                );
            }
        }
    }
}

#[cfg(unix)]
impl PipelinedEndpointPreparedSend {
    fn into_bookkeeping_and_job(
        self,
    ) -> (
        PipelinedEndpointPreparedBookkeeping,
        crate::node::encrypt_worker::FmpSendJob,
    ) {
        let PipelinedEndpointPreparedSend {
            dest_addr,
            next_hop_addr,
            fmp_counter,
            fmp_timestamp_ms,
            fmp_wire_capacity,
            originated_bytes,
            session_bookkeeping,
            worker_job,
        } = self;

        (
            PipelinedEndpointPreparedBookkeeping {
                dest_addr,
                next_hop_addr,
                fmp_counter,
                fmp_timestamp_ms,
                fmp_wire_capacity,
                originated_bytes,
                session_bookkeeping,
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

        bookkeeping.record_session_send(node);

        worker_job
    }

    fn record_bookkeeping_many(
        records: &[PipelinedEndpointPreparedBookkeeping],
        node: &mut Node,
    ) {
        let Some(first) = records.first().copied() else {
            return;
        };

        if records
            .iter()
            .all(|record| {
                record.dest_addr == first.dest_addr && record.next_hop_addr == first.next_hop_addr
            })
        {
            let _ = node.peers.record_fmp_send_bookkeeping_batch(
                &first.next_hop_addr,
                records.iter().map(|record| {
                    (
                        record.fmp_counter,
                        record.fmp_timestamp_ms,
                        record.fmp_wire_capacity,
                    )
                }),
            );
            let originated_bytes = records
                .iter()
                .map(|record| record.originated_bytes)
                .sum::<usize>();
            node.stats_mut()
                .forwarding
                .record_originated_batch(records.len(), originated_bytes);
            if records.iter().all(|record| record.session_bookkeeping.is_fsp()) {
                let _ = node.sessions.record_fsp_send_bookkeeping_batch(
                    &first.dest_addr,
                    records
                        .iter()
                        .filter_map(|record| record.session_bookkeeping.fsp()),
                );
            } else if records
                .iter()
                .all(|record| record.session_bookkeeping.is_direct_fmp())
            {
                let _ = node.sessions.record_direct_endpoint_data_send_batch(
                    &first.dest_addr,
                    records
                        .iter()
                        .filter_map(|record| record.session_bookkeeping.direct_fmp()),
                );
            } else {
                for record in records {
                    record.record_session_send(node);
                }
            }
            return;
        }

        for record in records {
            let _ = node.peers.record_fmp_send_bookkeeping(
                &record.next_hop_addr,
                record.fmp_counter,
                record.fmp_timestamp_ms,
                record.fmp_wire_capacity,
            );
            node.stats_mut()
                .forwarding
                .record_originated(record.originated_bytes);
            record.record_session_send(node);
        }
    }

    fn commit(self, node: &mut Node, workers: &crate::node::encrypt_worker::EncryptWorkerPool) {
        let _t =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointWorkerCommit);
        let mut worker_job = self.record_bookkeeping(node);
        if worker_job.queued_at.is_none() {
            worker_job.queued_at = crate::perf_profile::stamp();
        }
        workers.dispatch(worker_job);
    }

    fn commit_many(
        sends: Vec<Self>,
        node: &mut Node,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) {
        if sends.is_empty() {
            return;
        }
        if sends.len() == 1 {
            sends
                .into_iter()
                .next()
                .expect("single send exists")
                .commit(node, workers);
            return;
        }

        let _t = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::EndpointWorkerCommit,
            sends.len(),
        );
        let queued_at = crate::perf_profile::stamp();
        let mut records = Vec::with_capacity(sends.len());
        let jobs = sends
            .into_iter()
            .map(|send| {
                let (bookkeeping, mut worker_job) = send.into_bookkeeping_and_job();
                records.push(bookkeeping);
                worker_job.queued_at = queued_at;
                worker_job
            })
            .collect();
        Self::record_bookkeeping_many(&records, node);
        workers.dispatch_bulk_batch(jobs);
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointWirePlan<'a> {
    fn new(
        source_addr: &NodeAddr,
        dest_addr: &NodeAddr,
        inner_plaintext: PipelinedEndpointInnerPlaintext<'a>,
        my_coords: Option<&'a crate::tree::TreeCoordinate>,
        dest_coords: Option<&'a crate::tree::TreeCoordinate>,
        path_mtu: u16,
        default_ttl: u8,
    ) -> Option<Self> {
        let link_plaintext_len =
            pipelined_endpoint_link_plaintext_len(inner_plaintext.len(), my_coords, dest_coords);
        let fmp_payload_len = pipelined_endpoint_fmp_payload_len(link_plaintext_len)?;
        Some(Self {
            source_addr: *source_addr,
            dest_addr: *dest_addr,
            inner_plaintext,
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
        fmp_header: [u8; ESTABLISHED_HEADER_SIZE],
        fsp_header: [u8; FSP_HEADER_SIZE],
        timestamp_ms: u32,
    ) -> PipelinedEndpointWire {
        let fmp_inner_len = self.fmp_payload_len as usize;

        let wire_capacity = ESTABLISHED_HEADER_SIZE + fmp_inner_len + crate::noise::TAG_SIZE;
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
        self.inner_plaintext.write_to(&mut wire_buf);

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
            &self.wire_buf[..ESTABLISHED_HEADER_SIZE],
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
