#[inline]
fn record_fsp_owner_match(owner_matches_current_worker: bool) {
    crate::perf_profile::record_event(if owner_matches_current_worker {
        crate::perf_profile::Event::DecryptFspOwnerSame
    } else {
        crate::perf_profile::Event::DecryptFspOwnerMismatch
    });
}

#[inline]
fn record_fsp_owner_match_count(owner_matches_current_worker: bool, count: usize) {
    crate::perf_profile::record_event_count(
        if owner_matches_current_worker {
            crate::perf_profile::Event::DecryptFspOwnerSame
        } else {
            crate::perf_profile::Event::DecryptFspOwnerMismatch
        },
        count as u64,
    );
}

#[inline]
fn record_fsp_path_local(lane: DecryptWorkerLane) {
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspPathLocal);
    crate::perf_profile::record_event(match lane {
        DecryptWorkerLane::Priority => crate::perf_profile::Event::DecryptFspPathLocalPriority,
        DecryptWorkerLane::Bulk => crate::perf_profile::Event::DecryptFspPathLocalBulk,
    });
}

#[inline]
fn record_fsp_path_handoff(lane: DecryptWorkerLane) {
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspPathHandoff);
    crate::perf_profile::record_event(match lane {
        DecryptWorkerLane::Priority => crate::perf_profile::Event::DecryptFspPathHandoffPriority,
        DecryptWorkerLane::Bulk => crate::perf_profile::Event::DecryptFspPathHandoffBulk,
    });
}

#[inline]
fn record_fsp_path_worker_open_bulk() {
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspPathWorkerOpen);
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspPathWorkerOpenBulk);
}

#[inline]
fn record_fsp_path_worker_open_bulk_count(count: usize) {
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspPathWorkerOpen,
        count as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspPathWorkerOpenBulk,
        count as u64,
    );
}

#[derive(Clone, Copy)]
enum FspOpenWorkerIneligibleReason {
    NotBulk,
    NotOwner,
    NoOwnerState,
    NoSiblingWorker,
    Malformed,
    KbitMismatch,
    WindowFull,
}

impl FspOpenWorkerIneligibleReason {
    fn local_fallback_event(self) -> crate::perf_profile::Event {
        match self {
            Self::NotBulk => {
                crate::perf_profile::Event::DecryptFspOpenWorkerLocalIneligibleNotBulk
            }
            Self::NotOwner => {
                crate::perf_profile::Event::DecryptFspOpenWorkerLocalIneligibleNotOwner
            }
            Self::NoOwnerState => {
                crate::perf_profile::Event::DecryptFspOpenWorkerLocalIneligibleNoShared
            }
            Self::NoSiblingWorker => {
                crate::perf_profile::Event::DecryptFspOpenWorkerLocalIneligibleNoSibling
            }
            Self::Malformed => {
                crate::perf_profile::Event::DecryptFspOpenWorkerLocalIneligibleMalformed
            }
            Self::KbitMismatch => {
                crate::perf_profile::Event::DecryptFspOpenWorkerLocalIneligibleKbitMismatch
            }
            Self::WindowFull => {
                crate::perf_profile::Event::DecryptFspOpenWorkerLocalIneligibleWindowFull
            }
        }
    }
}

fn record_fsp_open_worker_local_ineligible(reason: FspOpenWorkerIneligibleReason) {
    if !crate::perf_profile::enabled() {
        return;
    }
    crate::perf_profile::record_event(reason.local_fallback_event());
}

fn drop_fsp_owner_handoff_job(job: FspDecryptJob) {
    record_fsp_owner_handoff_drop(job.lane(), 1);
}

fn drop_fsp_owner_handoff_jobs(jobs: Vec<FspDecryptJob>) {
    let mut priority = 0usize;
    let mut bulk = 0usize;
    for job in jobs {
        match job.lane() {
            DecryptWorkerLane::Priority => priority += 1,
            DecryptWorkerLane::Bulk => bulk += 1,
        }
    }
    if priority > 0 {
        record_fsp_owner_handoff_drop(DecryptWorkerLane::Priority, priority);
    }
    if bulk > 0 {
        record_fsp_owner_handoff_drop(DecryptWorkerLane::Bulk, bulk);
    }
}

fn record_fsp_owner_handoff_drop(lane: DecryptWorkerLane, count: usize) {
    if count == 0 {
        return;
    }
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspOwnerHandoffDropped,
        count as u64,
    );
    let lane_event = match lane {
        DecryptWorkerLane::Priority => crate::perf_profile::Event::DecryptWorkerPriorityDropped,
        DecryptWorkerLane::Bulk => crate::perf_profile::Event::DecryptWorkerBulkDropped,
    };
    crate::perf_profile::record_event_count(lane_event, count as u64);
}

#[inline]
fn record_fsp_open_worker_returned_drop(count: usize) {
    if count == 0 {
        return;
    }
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspOpenWorkerReturnedDropped,
        count as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptWorkerBulkDropped,
        count as u64,
    );
}

#[inline]
fn record_fsp_aead_completion_drop(event: crate::perf_profile::Event, count: usize) {
    crate::perf_profile::record_event_count(event, count as u64);
}

#[inline]
fn record_fsp_aead_completion_order_error(error: &OrderedCompletionError) {
    let event = match error {
        OrderedCompletionError::Stale => crate::perf_profile::Event::FspAeadCompletionStaleTicket,
        OrderedCompletionError::Duplicate => {
            crate::perf_profile::Event::FspAeadCompletionDuplicateTicket
        }
        OrderedCompletionError::WindowExceeded => {
            crate::perf_profile::Event::FspAeadCompletionWindowExceeded
        }
    };
    crate::perf_profile::record_event(event);
}

fn record_fsp_aead_completion_wait(
    source: FspAeadCompletionSource,
    completed_at: Option<crate::perf_profile::TraceStamp>,
) {
    if source.is_worker_open() {
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::FspAeadWorkerOpenCompletionWait,
            completed_at,
            1,
        );
    }
}

fn record_fsp_ordered_drain(drain: &FspOrderedDrain) {
    debug_assert_eq!(drain.ready, drain.accounted_ready());
    crate::perf_profile::record_fsp_aead_completion_drain(
        drain.ready,
        drain.accepted,
        drain.aead_failures,
        drain.epoch_mismatches,
        drain.stale_epoch_worker_open_failures,
        drain.replay_drops,
    );
    drain.aead_failure_sources.record();
    drain.replay_drop_sources.record();
}

struct FspOpenWorkerPrepareError {
    job: FspDecryptJob,
    reason: FspOpenWorkerIneligibleReason,
}

impl FspOpenWorkerPrepareError {
    fn ineligible(job: FspDecryptJob, reason: FspOpenWorkerIneligibleReason) -> Self {
        Self { job, reason }
    }

    fn into_job(self) -> FspDecryptJob {
        self.job
    }
}

struct FspBulkOpenWorkerTarget<'a> {
    owner_idx: usize,
    open_idx: usize,
    state: &'a mut OwnedFspSessionState,
}

struct DecryptWorkerShard {
    pool: DecryptWorkerPool,
    // Lives entirely on this OS thread — never observed by any other thread.
    sessions: HashMap<DecryptSessionKey, OwnedSessionState>,
    fsp_sessions: HashMap<NodeAddr, OwnedFspSessionState>,
    fsp_open_scratch: FspAeadOpenScratch,
}

impl DecryptWorkerShard {
    fn new(pool: DecryptWorkerPool) -> Self {
        Self {
            pool,
            sessions: HashMap::new(),
            fsp_sessions: HashMap::new(),
            fsp_open_scratch: FspAeadOpenScratch::default(),
        }
    }

    fn handle_msg(&mut self, idx: usize, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Job(job) => {
                self.handle_job_msg(idx, job);
            }
            WorkerMsg::FspJob(job) => {
                self.handle_fsp_job_msg(idx, job);
            }
            WorkerMsg::RegisterSession { session_key, state } => {
                self.register_session(idx, session_key, state);
            }
            WorkerMsg::RegisterFspSession { source_addr, state } => {
                self.register_fsp_session(idx, source_addr, state);
            }
            WorkerMsg::UnregisterSession { session_key } => {
                self.unregister_session(idx, session_key);
            }
            WorkerMsg::UnregisterFspSession { source_addr } => {
                self.unregister_fsp_session(idx, source_addr);
            }
        }
    }

    fn handle_job_msg(&mut self, idx: usize, job: DecryptJob) {
        if let Some(action) = self.collect_job_action(job) {
            self.handle_job_action_immediate(idx, action);
        }
    }

    #[cfg(test)]
    fn handle_bulk_job_msg(
        &mut self,
        idx: usize,
        job: DecryptJob,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) {
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        if let Some(action) = self.collect_job_action(job) {
            self.push_job_action_output(
                idx,
                action,
                return_batch,
                None,
                &mut fsp_open_batcher,
            );
        }
        flush_fsp_open_batcher(idx, self, return_batch, &mut fsp_open_batcher);
    }

    fn handle_fsp_job_msg(&mut self, idx: usize, job: FspDecryptJob) {
        job.record_queue_wait();
        let _t_service =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptFspWorkerService);
        let mut return_batch =
            DecryptWorkerReturnBatch::new(self.pool.return_tx.clone());
        self.push_fsp_job_outputs(idx, job, &mut return_batch);
        return_batch.flush();
        trace!(worker = idx, "processed FSP decrypt worker job");
    }

    fn handle_bulk_fsp_job_batch_with_open_batcher(
        &mut self,
        idx: usize,
        jobs: Vec<FspDecryptJob>,
        item_started_at: Option<crate::perf_profile::TraceStamp>,
        trace_enabled: bool,
        return_batch: &mut DecryptWorkerReturnBatch,
        fsp_open_batcher: &mut FspAeadOpenDispatchBatcher,
    ) {
        let count = jobs.len();
        match self.try_prepare_fsp_bulk_open_worker_job_batch(idx, jobs) {
            Ok((open_idx, owner_idx, open_jobs)) => {
                if trace_enabled {
                    for _ in 0..count {
                        record_fsp_worker_bulk_input_tail_wait(item_started_at);
                    }
                }
                record_fsp_owner_match_count(true, count);
                record_fsp_path_worker_open_bulk_count(count);
                let returned = push_fsp_aead_open_dispatch_batch(
                    fsp_open_batcher,
                    &self.pool,
                    open_idx,
                    owner_idx,
                    open_jobs,
                );
                if !returned.is_empty() {
                    self.drop_returned_fsp_aead_open_jobs(idx, returned, return_batch);
                }
                trace!(
                    worker = idx,
                    packets = count,
                    "processed batched bulk FSP decrypt worker jobs"
                );
            }
            Err(jobs) => {
                for job in jobs {
                    if trace_enabled {
                        record_fsp_worker_bulk_input_tail_wait(item_started_at);
                    }
                    job.record_queue_wait();
                    let _t_service = crate::perf_profile::Timer::start(
                        crate::perf_profile::Stage::DecryptFspWorkerService,
                    );
                    self.push_job_action_output(
                        idx,
                        DecryptWorkerJobAction::FspJob(job),
                        return_batch,
                        None,
                        &mut *fsp_open_batcher,
                    );
                    trace!(worker = idx, "processed batched bulk FSP decrypt worker job");
                }
            }
        }
    }

    fn register_session(
        &mut self,
        idx: usize,
        session_key: DecryptSessionKey,
        state: OwnedSessionState,
    ) {
        trace!(
            worker = idx,
            ?session_key,
            "DecryptWorker: register session"
        );
        self.sessions.insert(session_key, state);
    }

    fn unregister_session(&mut self, idx: usize, session_key: DecryptSessionKey) {
        trace!(
            worker = idx,
            ?session_key,
            "DecryptWorker: unregister session"
        );
        self.sessions.remove(&session_key);
    }

    fn register_fsp_session(
        &mut self,
        idx: usize,
        source_addr: NodeAddr,
        mut state: OwnedFspSessionState,
    ) {
        trace!(
            worker = idx,
            %source_addr,
            "DecryptWorker: register FSP session"
        );
        if let Some(previous) = self.fsp_sessions.remove(&source_addr) {
            state.preserve_receive_order_from(previous);
        }
        self.fsp_sessions.insert(source_addr, state);
    }

    fn unregister_fsp_session(&mut self, idx: usize, source_addr: NodeAddr) {
        trace!(
            worker = idx,
            %source_addr,
            "DecryptWorker: unregister FSP session"
        );
        self.fsp_sessions.remove(&source_addr);
    }

    #[cfg(test)]
    fn handle_job(
        &mut self,
        job: DecryptJob,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(action) = self.collect_job_action(job) {
            self.handle_job_action_immediate(0, action);
        }
        Ok(())
    }

    fn handle_job_action_immediate(&mut self, idx: usize, action: DecryptWorkerJobAction) {
        let mut return_batch = DecryptWorkerReturnBatch::new(self.pool.return_tx.clone());
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        self.push_job_action_output(
            idx,
            action,
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );
        flush_fsp_open_batcher(idx, self, &mut return_batch, &mut fsp_open_batcher);
        return_batch.flush();
    }

    fn push_job_action_output(
        &mut self,
        idx: usize,
        action: DecryptWorkerJobAction,
        return_batch: &mut DecryptWorkerReturnBatch,
        mut fsp_batcher: Option<&mut FspDecryptJobBatcher>,
        fsp_open_batcher: &mut FspAeadOpenDispatchBatcher,
    ) {
        match action {
            DecryptWorkerJobAction::Output(output) => return_batch.push_output(output),
            DecryptWorkerJobAction::FspJob(job) => {
                let owner_idx = self.pool.worker_idx_for_fsp(&job.source_addr);
                record_fsp_owner_match(owner_idx == idx);
                let job = match self.try_prepare_fsp_bulk_open_worker_job(idx, owner_idx, job) {
                    Ok((open_idx, owner_idx, open_job)) => {
                        record_fsp_path_worker_open_bulk();
                        let returned = push_fsp_aead_open_dispatch(
                            fsp_open_batcher,
                            &self.pool,
                            open_idx,
                            owner_idx,
                            open_job,
                        );
                        if !returned.is_empty() {
                            self.drop_returned_fsp_aead_open_jobs(
                                idx,
                                returned,
                                return_batch,
                            );
                        }
                        return;
                    }
                    Err(error) => {
                        if owner_idx == idx {
                            record_fsp_open_worker_local_ineligible(error.reason);
                            if matches!(error.reason, FspOpenWorkerIneligibleReason::WindowFull) {
                                record_decrypt_worker_bulk_drop_count(idx, 1);
                                return;
                            }
                        }
                        error.into_job()
                    }
                };
                if owner_idx == idx {
                    record_fsp_path_local(job.lane());
                    self.push_fsp_job_outputs(idx, job, return_batch);
                    return;
                }
                record_fsp_path_handoff(job.lane());
                if let Some(fsp_batcher) = fsp_batcher.as_deref_mut() {
                    fsp_batcher.push_to(&self.pool, owner_idx, job);
                    return;
                }
                match self.pool.dispatch_fsp_job_or_return(job) {
                    Ok(()) => {}
                    Err(job) => {
                        crate::perf_profile::record_event(
                            crate::perf_profile::Event::DecryptFspPathFallback,
                        );
                        drop_fsp_owner_handoff_job(job);
                    }
                }
            }
        }
    }

    fn current_fsp_bulk_open_header(
        job: &FspDecryptJob,
        current_k_bit: bool,
    ) -> Result<FspEncryptedHeader, FspOpenWorkerIneligibleReason> {
        let (header, _, _) = Self::parse_fsp_encrypted_payload(
            &job.fallback.packet_data,
            job.fsp_payload_offset,
            job.fsp_payload_len,
        )
        .ok_or(FspOpenWorkerIneligibleReason::Malformed)?;
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        if received_k_bit != current_k_bit {
            return Err(FspOpenWorkerIneligibleReason::KbitMismatch);
        }
        Ok(header)
    }

    fn try_fsp_bulk_open_worker_target(
        &mut self,
        idx: usize,
        owner_idx: usize,
        source_addr: &NodeAddr,
    ) -> Result<FspBulkOpenWorkerTarget<'_>, FspOpenWorkerIneligibleReason> {
        if owner_idx != idx {
            return Err(FspOpenWorkerIneligibleReason::NotOwner);
        }
        if !self.pool.fsp_bulk_open_worker_enabled() {
            return Err(FspOpenWorkerIneligibleReason::NoSiblingWorker);
        }
        let Some(state) = self.fsp_sessions.get_mut(source_addr) else {
            return Err(FspOpenWorkerIneligibleReason::NoOwnerState);
        };
        if !state.has_single_current_epoch() {
            return Err(FspOpenWorkerIneligibleReason::NoOwnerState);
        }
        let Some(open_idx) = self.pool.worker_idx_for_fsp_open_avoiding(source_addr, idx) else {
            return Err(FspOpenWorkerIneligibleReason::NoSiblingWorker);
        };
        Ok(FspBulkOpenWorkerTarget {
            owner_idx,
            open_idx,
            state,
        })
    }

    fn parse_fsp_encrypted_payload(
        packet_data: &[u8],
        fsp_payload_offset: usize,
        fsp_payload_len: usize,
    ) -> Option<(FspEncryptedHeader, usize, usize)> {
        let payload_end = fsp_payload_offset.checked_add(fsp_payload_len)?;
        let payload = packet_data.get(fsp_payload_offset..payload_end)?;
        let header = FspEncryptedHeader::parse(payload)?;
        let ciphertext_len = payload.len().checked_sub(FSP_HEADER_SIZE)?;
        let expected_ciphertext_len =
            usize::from(header.payload_len).checked_add(crate::noise::TAG_SIZE)?;
        if ciphertext_len != expected_ciphertext_len {
            return None;
        }
        let ciphertext_offset = fsp_payload_offset.checked_add(FSP_HEADER_SIZE)?;
        Some((header, ciphertext_offset, payload_end))
    }

    #[allow(clippy::result_large_err)]
    fn direct_session_delivery_from_message(
        source_addr: NodeAddr,
        local_node_addr: NodeAddr,
        message: AuthenticatedSessionMessage,
    ) -> Result<DecryptDirectSessionDelivery, AuthenticatedSessionMessage> {
        match SessionMessageType::from_byte(message.msg_type()) {
            Some(SessionMessageType::EndpointData) => Ok(
                DecryptDirectSessionDelivery::EndpointData(message.into_endpoint_data_delivery()),
            ),
            Some(SessionMessageType::DataPacket) => {
                let body = message.body();
                if body.len() < FSP_PORT_HEADER_SIZE {
                    return Err(message);
                }
                let dst_port = u16::from_le_bytes([body[2], body[3]]);
                if dst_port != FSP_PORT_IPV6_SHIM {
                    return Err(message);
                }

                let src_ipv6 = FipsAddress::from_node_addr(&source_addr).to_ipv6().octets();
                let dst_ipv6 = FipsAddress::from_node_addr(&local_node_addr)
                    .to_ipv6()
                    .octets();
                let Some(packet) = crate::upper::ipv6_shim::decompress_ipv6(
                    &body[FSP_PORT_HEADER_SIZE..],
                    src_ipv6,
                    dst_ipv6,
                ) else {
                    return Err(message);
                };
                Ok(DecryptDirectSessionDelivery::Ipv6Packet(packet))
            }
            _ => Err(message),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn direct_session_event(
        sink: &DecryptDirectSessionDeliverySink,
        fmp: DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        ce_flag: bool,
        body_len: usize,
        delivery: DecryptDirectSessionDelivery,
        receive_sync: FspReceiveSync,
        lane: DecryptWorkerLane,
    ) -> (DecryptWorkerEvent, Option<PendingDirectSessionDelivery>) {
        let source_peer = match &delivery {
            DecryptDirectSessionDelivery::EndpointData(delivery) => delivery.source_peer,
            DecryptDirectSessionDelivery::Ipv6Packet(_) => fmp.source_peer,
        };
        let direct_hop = previous_hop_peer.node_addr() == &source_addr;
        let delivered_ipv6 = matches!(delivery, DecryptDirectSessionDelivery::Ipv6Packet(_));
        if direct_hop && sink.can_deliver(&delivery) {
            return (
                DecryptWorkerEvent::DirectSessionCommit(DecryptDirectSessionCommit {
                    fmp,
                    source_addr,
                    previous_hop_peer,
                    ce_flag,
                    receive_sync,
                    body_len,
                    delivered_ipv6,
                    lane,
                    trace_enqueued_at: None,
                }),
                Some(PendingDirectSessionDelivery {
                    sink: sink.clone(),
                    source_addr,
                    source_peer,
                    ce_flag,
                    delivery,
                }),
            );
        }

        (
            DecryptWorkerEvent::DirectSessionData(DecryptDirectSessionData {
                fmp,
                source_addr,
                previous_hop_peer,
                ce_flag,
                receive_sync,
                body_len,
                delivery,
                lane,
                trace_enqueued_at: None,
            }),
            None,
        )
    }

    #[allow(clippy::result_large_err)]
    fn try_prepare_fsp_bulk_open_worker_job(
        &mut self,
        idx: usize,
        owner_idx: usize,
        job: FspDecryptJob,
    ) -> Result<(usize, usize, FspAeadOpenDispatch), FspOpenWorkerPrepareError> {
        if !matches!(job.lane(), DecryptWorkerLane::Bulk) {
            return Err(FspOpenWorkerPrepareError::ineligible(
                job,
                FspOpenWorkerIneligibleReason::NotBulk,
            ));
        }

        let source_addr = job.source_addr;
        let target = match self.try_fsp_bulk_open_worker_target(idx, owner_idx, &source_addr) {
            Ok(target) => target,
            Err(reason) => return Err(FspOpenWorkerPrepareError::ineligible(job, reason)),
        };
        let current_k_bit = target.state.current_k_bit;
        let header = match Self::current_fsp_bulk_open_header(&job, current_k_bit) {
            Ok(header) => header,
            Err(reason) => return Err(FspOpenWorkerPrepareError::ineligible(job, reason)),
        };
        let Some(reservation) = target.state.reserve_worker_fsp_open() else {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::DecryptFspOpenWorkerWindowFallback,
                1,
            );
            return Err(FspOpenWorkerPrepareError::ineligible(
                job,
                FspOpenWorkerIneligibleReason::WindowFull,
            ));
        };
        let open_job = new_fsp_aead_open_dispatch(
            reservation.crypto_ticket(),
            Arc::clone(&target.state.current.cipher),
            job,
            header,
            FspAeadCompletionSource::WorkerOpen,
            None,
            None,
        );
        Ok((target.open_idx, target.owner_idx, open_job))
    }

    fn try_prepare_fsp_bulk_open_worker_job_batch(
        &mut self,
        idx: usize,
        jobs: Vec<FspDecryptJob>,
    ) -> Result<(usize, usize, Vec<FspAeadOpenDispatch>), Vec<FspDecryptJob>> {
        if jobs.len() < 2 {
            return Err(jobs);
        }
        let source_addr = jobs[0].source_addr;
        if !jobs
            .iter()
            .all(|job| job.source_addr == source_addr && matches!(job.lane(), DecryptWorkerLane::Bulk))
        {
            return Err(jobs);
        }

        let owner_idx = self.pool.worker_idx_for_fsp(&source_addr);
        let target = match self.try_fsp_bulk_open_worker_target(idx, owner_idx, &source_addr) {
            Ok(target) => target,
            Err(_) => return Err(jobs),
        };

        let current_k_bit = target.state.current_k_bit;
        let mut headers = Vec::with_capacity(jobs.len());
        for job in &jobs {
            match Self::current_fsp_bulk_open_header(job, current_k_bit) {
                Ok(header) => headers.push(header),
                Err(_) => return Err(jobs),
            }
        }

        let Some(reservation) = target.state.reserve_worker_fsp_open_batch(headers.len())
        else {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::DecryptFspOpenWorkerWindowFallback,
                headers.len() as u64,
            );
            return Err(jobs);
        };
        let cipher = Arc::clone(&target.state.current.cipher);
        let open_jobs = jobs
            .into_iter()
            .zip(headers)
            .enumerate()
            .map(|(offset, (job, header))| {
                new_fsp_aead_open_dispatch(
                    reservation.crypto_ticket_at(offset),
                    Arc::clone(&cipher),
                    job,
                    header,
                    FspAeadCompletionSource::WorkerOpen,
                    None,
                    None,
                )
            })
            .collect();

        Ok((target.open_idx, target.owner_idx, open_jobs))
    }

    fn drop_returned_fsp_aead_open_jobs<I>(
        &mut self,
        idx: usize,
        jobs: I,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) where
        I: IntoIterator<Item = FspAeadOpenDispatch>,
    {
        let mut returned_count = 0usize;
        let mut batcher = FspAeadCompletionBatchBuilder::new();
        for mut job in jobs {
            returned_count = returned_count.saturating_add(1);
            let completion_owner_idx = job.completion_owner_idx();
            let local_completion =
                completion_owner_idx == Some(idx) || completion_owner_idx.is_none();
            job.mark_returned_completion();
            if let Some(flush) = batcher.push(
                local_completion,
                completion_owner_idx,
                job.into_dropped_completion(),
            ) {
                self.flush_dropped_fsp_aead_open_completion_batch(
                    idx,
                    flush,
                    return_batch,
                );
            }
        }

        record_fsp_open_worker_returned_drop(returned_count);
        if let Some(flush) = batcher.flush() {
            self.flush_dropped_fsp_aead_open_completion_batch(idx, flush, return_batch);
        }
    }

    fn flush_dropped_fsp_aead_open_completion_batch(
        &mut self,
        idx: usize,
        flush: FspAeadCompletionBatchFlush,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) {
        if flush.local_completion {
            self.handle_fsp_aead_completion_batch_msg(idx, flush.batch, return_batch);
            return;
        }
        if let Some(owner_idx) = flush.owner_idx {
            send_fsp_aead_open_completion_batch(idx, &self.pool, owner_idx, flush.batch);
        }
    }

    fn complete_fsp_aead_completions_for_source<I>(
        &mut self,
        idx: usize,
        source_addr: NodeAddr,
        receive_order_id: u64,
        completions: I,
        completion_count: usize,
        invalid_order_message: &'static str,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) where
        I: IntoIterator<Item = FspAeadCompletion>,
    {
        if completion_count == 0 {
            return;
        }

        let mut completions = completions.into_iter();
        let Some(state) = self.fsp_sessions.get_mut(&source_addr) else {
            for completion in completions {
                record_fsp_aead_completion_wait(completion.source, completion.completed_at);
            }
            record_fsp_aead_completion_drop(
                crate::perf_profile::Event::FspAeadCompletionStaleSession,
                completion_count,
            );
            return;
        };
        if state.fsp_receive_order_id() != receive_order_id {
            for completion in completions {
                record_fsp_aead_completion_wait(completion.source, completion.completed_at);
            }
            record_fsp_aead_completion_drop(
                crate::perf_profile::Event::FspAeadCompletionStaleOrder,
                completion_count,
            );
            return;
        }

        let mut total_drain = FspOrderedDrain::default();
        let direct_delivery_sink = self.pool.direct_delivery_sink.clone();
        for completion in completions.by_ref() {
            record_fsp_aead_completion_wait(completion.source, completion.completed_at);
            let completion_source_addr = completion.source_addr();
            let completion_receive_order_id = completion.receive_order_id();
            if completion_source_addr != source_addr
                || completion_receive_order_id != receive_order_id
            {
                record_fsp_aead_completion_drop(
                    crate::perf_profile::Event::FspAeadCompletionStaleOrder,
                    1,
                );
                debug!(
                    worker = idx,
                    expected_source = %source_addr,
                    completion_source = %completion_source_addr,
                    expected_receive_order = receive_order_id,
                    completion_receive_order = completion_receive_order_id,
                    "dropping mismatched FSP AEAD completion from batch"
                );
                continue;
            }
            let drain = match state.complete_fsp_aead_completion(completion, |completion| {
                if let Some(output) =
                    Self::output_for_fsp_ready_completion(&direct_delivery_sink, completion)
                {
                    return_batch.push_output(output);
                }
            }) {
                Ok(drain) => drain,
                Err(error) => {
                    record_fsp_aead_completion_order_error(&error);
                    debug!(
                        worker = idx,
                        ?error,
                        %source_addr,
                        "{}",
                        invalid_order_message
                    );
                    continue;
                }
            };
            debug_assert_eq!(drain.ready, drain.accounted_ready());
            total_drain.add(drain);
        }
        record_fsp_ordered_drain(&total_drain);
    }

    fn handle_fsp_aead_completion_msg(
        &mut self,
        idx: usize,
        completion: FspAeadCompletion,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) {
        let _t_service = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::FspAeadCompletionService,
        );
        let source_addr = completion.source_addr();
        let receive_order_id = completion.receive_order_id();
        self.complete_fsp_aead_completions_for_source(
            idx,
            source_addr,
            receive_order_id,
            std::iter::once(completion),
            1,
            "dropping invalid ordered FSP AEAD completion",
            return_batch,
        );
    }

    fn handle_fsp_aead_completion_batch_msg(
        &mut self,
        idx: usize,
        completions: FspAeadCompletionBatch,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) {
        match completions {
            FspAeadCompletionBatch::One(completion) => {
                self.handle_fsp_aead_completion_msg(idx, completion, return_batch);
            }
            FspAeadCompletionBatch::Many(completions) => {
                let completion_count = completions.len();
                let Some(first) = completions.first() else {
                    return;
                };
                let source_addr = first.source_addr();
                let receive_order_id = first.receive_order_id();
                let _t_service = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::FspAeadCompletionService,
                );
                self.complete_fsp_aead_completions_for_source(
                    idx,
                    source_addr,
                    receive_order_id,
                    completions,
                    completion_count,
                    "dropping invalid ordered FSP AEAD completion",
                    return_batch,
                );
            }
        }
    }

    fn output_for_fsp_ready_completion(
        direct_delivery_sink: &DecryptDirectSessionDeliverySink,
        completion: FspReadyCompletion,
    ) -> Option<DecryptWorkerOutput> {
        match completion {
            FspReadyCompletion::Opened {
                opened,
                slot,
                source_peer,
            } => Self::output_for_opened_fsp_job(direct_delivery_sink, source_peer, opened, slot),
            FspReadyCompletion::AeadFailed {
                job,
                header,
                fallback_to_rx_loop,
            } => Some(Self::output_for_fsp_aead_failure(
                job,
                &header,
                fallback_to_rx_loop,
            )),
        }
    }

    fn output_for_fsp_aead_failure(
        job: FspDecryptJob,
        header: &FspEncryptedHeader,
        fallback_to_rx_loop: bool,
    ) -> DecryptWorkerOutput {
        let FspDecryptJob {
            fallback,
            lane,
            local_node_addr: _,
            source_addr,
            previous_hop_peer: _,
            path_mtu: _,
            ce_flag: _,
            inner_timestamp_ms,
            fsp_payload_offset: _,
            fsp_payload_len: _,
            trace_enqueued_at: _,
        } = job;
        crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspPathFallback);
        if !fallback_to_rx_loop {
            let fmp = DecryptFmpBookkeeping {
                source_peer: fallback.source_peer,
                transport_id: fallback.transport_id,
                remote_addr: fallback.remote_addr,
                packet_timestamp_ms: fallback.timestamp_ms,
                packet_len: fallback.packet_len,
                fmp_counter: fallback.fmp_counter,
                inner_timestamp_ms,
                fmp_flags: fallback.fmp_flags,
            };
            return DecryptWorkerOutput {
                event: DecryptWorkerEvent::FspDecryptFailure(DecryptFspFailureReport {
                    fmp,
                    source_addr,
                    counter: header.counter,
                    received_k_bit: header.flags & FSP_FLAG_K != 0,
                    lane,
                    trace_enqueued_at: None,
                }),
                direct_delivery: None,
            };
        }
        DecryptWorkerOutput {
            event: DecryptWorkerEvent::Plaintext(fallback),
            direct_delivery: None,
        }
    }

    fn output_for_malformed_fsp_drop(
        &self,
        fallback: DecryptFallback,
        lane: DecryptWorkerLane,
        inner_timestamp_ms: u32,
        previous_hop_peer: PeerIdentity,
    ) -> DecryptWorkerOutput {
        crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspMalformedDropped);
        DecryptWorkerOutput {
            event: DecryptWorkerEvent::AuthenticatedFmpReceive(DecryptAuthenticatedFmpReceive {
                fmp: DecryptFmpBookkeeping {
                    source_peer: fallback.source_peer,
                    transport_id: fallback.transport_id,
                    remote_addr: fallback.remote_addr,
                    packet_timestamp_ms: fallback.timestamp_ms,
                    packet_len: fallback.packet_len,
                    fmp_counter: fallback.fmp_counter,
                    inner_timestamp_ms,
                    fmp_flags: fallback.fmp_flags,
                },
                previous_hop_peer: Some(previous_hop_peer),
                lane,
                trace_enqueued_at: None,
            }),
            direct_delivery: None,
        }
    }

    fn output_for_opened_fsp_job(
        direct_delivery_sink: &DecryptDirectSessionDeliverySink,
        source_peer: PeerIdentity,
        opened: FspOpenedJob,
        slot: EpochSlot,
    ) -> Option<DecryptWorkerOutput> {
        let FspOpenedJob {
            job,
            header,
            plaintext_len,
        } = opened;
        let FspDecryptJob {
            fallback,
            lane,
            local_node_addr,
            source_addr,
            previous_hop_peer,
            path_mtu,
            ce_flag,
            inner_timestamp_ms,
            fsp_payload_offset,
            fsp_payload_len: _,
            trace_enqueued_at: _,
        } = job;
        let ciphertext_offset = fsp_payload_offset + FSP_HEADER_SIZE;
        let plaintext = fallback
            .packet_data
            .get(ciphertext_offset..ciphertext_offset + plaintext_len)?;
        let (timestamp, msg_type, inner_flags_byte, _body) = fsp_strip_inner_header(plaintext)?;
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        let spin_bit = inner_flags_byte & 0x01 != 0;
        let fmp = DecryptFmpBookkeeping {
            source_peer: fallback.source_peer,
            transport_id: fallback.transport_id,
            remote_addr: fallback.remote_addr,
            packet_timestamp_ms: fallback.timestamp_ms,
            packet_len: fallback.packet_len,
            fmp_counter: fallback.fmp_counter,
            inner_timestamp_ms,
            fmp_flags: fallback.fmp_flags,
        };
        let sync = FspReceiveSync {
            counter: header.counter,
            slot,
            received_k_bit,
            timestamp,
            plaintext_len,
            ce_flag,
            path_mtu,
            spin_bit,
        };
        let message = AuthenticatedSessionMessage::from_buffer(
            source_peer,
            fallback.packet_data,
            ciphertext_offset,
            plaintext_len,
            msg_type,
            inner_flags_byte,
            timestamp,
        );
        let body_len = message.body_len();

        match Self::direct_session_delivery_from_message(source_addr, local_node_addr, message) {
            Ok(delivery) => {
                let (event, direct_delivery) = Self::direct_session_event(
                    direct_delivery_sink,
                    fmp,
                    source_addr,
                    previous_hop_peer,
                    ce_flag,
                    body_len,
                    delivery,
                    sync,
                    lane,
                );
                Some(DecryptWorkerOutput {
                    event,
                    direct_delivery,
                })
            }
            Err(message) => Some(DecryptWorkerOutput {
                event: DecryptWorkerEvent::AuthenticatedSession(DecryptAuthenticatedSession {
                    fmp,
                    source_addr,
                    previous_hop_peer,
                    ce_flag,
                    message,
                    receive_sync: sync,
                    lane,
                    trace_enqueued_at: None,
                }),
                direct_delivery: None,
            }),
        }
    }

    fn push_fsp_job_outputs(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) {
        if self
            .fsp_sessions
            .get(&job.source_addr)
            .is_some_and(OwnedFspSessionState::has_single_current_epoch)
        {
            self.push_current_epoch_fsp_job_outputs(idx, job, return_batch);
            return;
        }
        self.push_epoch_churn_fsp_job_outputs(job, return_batch);
    }

    fn push_current_epoch_fsp_job_outputs(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) {
        let FspDecryptJob {
            mut fallback,
            lane,
            local_node_addr,
            source_addr,
            previous_hop_peer,
            path_mtu,
            ce_flag,
            inner_timestamp_ms,
            fsp_payload_offset,
            fsp_payload_len,
            trace_enqueued_at: _,
        } = job;
        let Some(state) = self.fsp_sessions.get(&source_addr) else {
            return_batch.push_output(DecryptWorkerOutput {
                event: DecryptWorkerEvent::Plaintext(fallback),
                direct_delivery: None,
            });
            return;
        };
        debug_assert!(state.has_single_current_epoch());

        let Some((header, ciphertext_offset, payload_end)) = Self::parse_fsp_encrypted_payload(
            &fallback.packet_data,
            fsp_payload_offset,
            fsp_payload_len,
        ) else {
            return_batch.push_output(self.output_for_malformed_fsp_drop(
                fallback,
                lane,
                inner_timestamp_ms,
                previous_hop_peer,
            ));
            return;
        };
        let ciphertext = &mut fallback.packet_data[ciphertext_offset..payload_end];
        self.fsp_open_scratch.preserve_ciphertext_from(ciphertext);
        let (reservation, open_result) = {
            let state = self
                .fsp_sessions
                .get_mut(&source_addr)
                .expect("FSP session was checked before current-epoch local open");
            let Some(reservation) = state.reserve_local_fsp_open(lane) else {
                match lane {
                    DecryptWorkerLane::Priority => {
                        record_decrypt_worker_priority_drop(idx, "fsp-receive-window");
                    }
                    DecryptWorkerLane::Bulk => {
                        record_decrypt_worker_bulk_drop_count(idx, 1);
                    }
                }
                return;
            };
            let open_result = state.current_epoch_matches(&header).then(|| {
                let _t_fsp =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
                state.open_current_established_frame_in_place_deferred_replay(&header, ciphertext)
            });
            (reservation, open_result)
        };
        if matches!(open_result, Some(Err(FspOpenError::Aead))) {
            let restore = &mut fallback.packet_data[ciphertext_offset..payload_end];
            restore.copy_from_slice(self.fsp_open_scratch.preserved_ciphertext());
        }
        let job = FspDecryptJob {
            fallback,
            lane,
            local_node_addr,
            source_addr,
            previous_hop_peer,
            path_mtu,
            ce_flag,
            inner_timestamp_ms,
            fsp_payload_offset,
            fsp_payload_len,
            trace_enqueued_at: None,
        };
        let completion = match open_result {
            Some(Ok(plaintext_len)) => FspOrderedCompletion::Opened {
                opened: FspOpenedJob {
                    job,
                    header,
                    plaintext_len,
                },
                source: FspAeadCompletionSource::Local,
            },
            Some(Err(FspOpenError::Aead)) => {
                FspOrderedCompletion::AeadFailed {
                    job,
                    header,
                    source: FspAeadCompletionSource::Local,
                    fallback_to_rx_loop: true,
                    count_failure: false,
                }
            }
            Some(Err(FspOpenError::Replay)) => {
                FspOrderedCompletion::AeadFailed {
                    job,
                    header,
                    source: FspAeadCompletionSource::Local,
                    fallback_to_rx_loop: false,
                    count_failure: true,
                }
            }
            None => FspOrderedCompletion::EpochMismatch {
                job,
                header,
                source: FspAeadCompletionSource::Local,
            },
        };

        self.complete_fsp_aead_completions_for_source(
            idx,
            source_addr,
            reservation.receive_order_id(),
            std::iter::once(FspAeadCompletion {
                crypto_ticket: reservation.crypto_ticket(),
                source: FspAeadCompletionSource::Local,
                result: completion,
                completed_at: None,
            }),
            1,
            "dropping invalid local ordered FSP completion",
            return_batch,
        );
    }

    fn push_epoch_churn_fsp_job_outputs(
        &mut self,
        job: FspDecryptJob,
        return_batch: &mut DecryptWorkerReturnBatch,
    ) {
        let FspDecryptJob {
            fallback,
            lane,
            local_node_addr,
            source_addr,
            previous_hop_peer,
            path_mtu,
            ce_flag,
            inner_timestamp_ms,
            fsp_payload_offset,
            fsp_payload_len,
            trace_enqueued_at: _,
        } = job;

        let Some(state) = self.fsp_sessions.get_mut(&source_addr) else {
            return_batch.push_output(DecryptWorkerOutput {
                event: DecryptWorkerEvent::Plaintext(fallback),
                direct_delivery: None,
            });
            return;
        };
        let Some((header, ciphertext_offset, payload_end)) = Self::parse_fsp_encrypted_payload(
            &fallback.packet_data,
            fsp_payload_offset,
            fsp_payload_len,
        ) else {
            return_batch.push_output(self.output_for_malformed_fsp_drop(
                fallback,
                lane,
                inner_timestamp_ms,
                previous_hop_peer,
            ));
            return;
        };
        let ciphertext = &fallback.packet_data[ciphertext_offset..payload_end];
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        let open_result = {
            let _t_fsp =
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
            state.open_established_frame(&header, ciphertext)
        };
        let FspOpenSuccess { plaintext, slot } = match open_result {
            Ok(success) => success,
            Err(FspOpenError::Replay) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFspWorkerReplayDropped,
                );
                return;
            }
            Err(FspOpenError::Aead) => {
                let job = FspDecryptJob {
                    fallback,
                    lane,
                    local_node_addr,
                    source_addr,
                    previous_hop_peer,
                    path_mtu,
                    ce_flag,
                    inner_timestamp_ms,
                    fsp_payload_offset,
                    fsp_payload_len,
                    trace_enqueued_at: None,
                };
                return_batch.push_output(Self::output_for_fsp_aead_failure(job, &header, true));
                return;
            }
        };
        let Some((timestamp, msg_type, inner_flags_byte, _body)) =
            fsp_strip_inner_header(&plaintext)
        else {
            return;
        };
        let fmp = DecryptFmpBookkeeping {
            source_peer: fallback.source_peer,
            transport_id: fallback.transport_id,
            remote_addr: fallback.remote_addr,
            packet_timestamp_ms: fallback.timestamp_ms,
            packet_len: fallback.packet_len,
            fmp_counter: fallback.fmp_counter,
            inner_timestamp_ms,
            fmp_flags: fallback.fmp_flags,
        };
        let spin_bit = inner_flags_byte & 0x01 != 0;
        let plaintext_len = plaintext.len();
        let sync = FspReceiveSync {
            counter: header.counter,
            slot,
            received_k_bit,
            timestamp,
            plaintext_len,
            ce_flag,
            path_mtu,
            spin_bit,
        };
        let message = AuthenticatedSessionMessage::new(
            state.source_peer,
            plaintext,
            msg_type,
            inner_flags_byte,
            timestamp,
        );
        let body_len = message.body_len();

        let event =
            match Self::direct_session_delivery_from_message(source_addr, local_node_addr, message)
            {
                Ok(delivery) => {
                    let (event, direct_delivery) = Self::direct_session_event(
                        &self.pool.direct_delivery_sink,
                        fmp,
                        source_addr,
                        previous_hop_peer,
                        ce_flag,
                        body_len,
                        delivery,
                        sync,
                        lane,
                    );
                    return_batch.push_output(DecryptWorkerOutput {
                        event,
                        direct_delivery,
                    });
                    return;
                }
                Err(message) => {
                    DecryptWorkerEvent::AuthenticatedSession(DecryptAuthenticatedSession {
                        fmp,
                        source_addr,
                        previous_hop_peer,
                        ce_flag,
                        message,
                        receive_sync: sync,
                        lane,
                        trace_enqueued_at: None,
                    })
                }
            };

        return_batch.push_output(DecryptWorkerOutput {
            event,
            direct_delivery: None,
        });
    }

    fn collect_job_action(&mut self, job: DecryptJob) -> Option<DecryptWorkerJobAction> {
        let session_key = job.session_key();
        let Some(state) = self.sessions.get_mut(&session_key) else {
            let _ = job;
            return None;
        };
        Self::collect_job_action_with_state(state, job)
    }

    fn push_bulk_job_outputs(
        &mut self,
        idx: usize,
        session_key: DecryptSessionKey,
        jobs: Vec<DecryptJob>,
        return_batch: &mut DecryptWorkerReturnBatch,
        fsp_batcher: &mut FspDecryptJobBatcher,
        fsp_open_batcher: &mut FspAeadOpenDispatchBatcher,
    ) {
        // Hold FMP session/replay state while FSP/output handling borrows the
        // rest of the shard; no control work is interleaved inside this item.
        let Some(mut state) = self.sessions.remove(&session_key) else {
            return;
        };
        for job in jobs {
            if let Some(action) = Self::collect_job_action_with_state(&mut state, job) {
                self.push_job_action_output(
                    idx,
                    action,
                    return_batch,
                    Some(&mut *fsp_batcher),
                    fsp_open_batcher,
                );
            }
        }
        let previous = self.sessions.insert(session_key, state);
        debug_assert!(previous.is_none());
    }

    fn collect_job_action_with_state(
        state: &mut OwnedSessionState,
        job: DecryptJob,
    ) -> Option<DecryptWorkerJobAction> {
        job.record_queue_wait();
        let DecryptJob {
            packet_data,
            lane,
            session_key: _,
            worker_idx: _,
            _transport_id: transport_id,
            _remote_addr: remote_addr,
            local_node_addr,
            timestamp_ms,
            fmp_counter,
            fmp_flags,
            fmp_header,
            fmp_ciphertext_offset,
            trace_enqueued_at: _,
        } = job;
        // Capture the wire packet length BEFORE decrypt mutates the
        // buffer — it'll be the same number either way (in-place AEAD
        // open doesn't change Vec::len), but documenting the intent.
        let packet_len = packet_data.len();

        let source_peer = state.source_peer;

        let reservation = match state.reserve_fmp_open(lane, fmp_counter) {
            Ok(reservation) => reservation,
            Err(FmpOpenError::Replay | FmpOpenError::WindowFull) => return None,
        };
        let work = state.fmp_open_work(
            reservation,
            packet_data,
            fmp_ciphertext_offset,
            fmp_counter,
            fmp_flags,
            fmp_header,
        );
        let mut opener = FmpAeadOpener;
        let crypto_completion = opener.execute(work);
        let completion = FmpAeadCompletion::new(reservation, crypto_completion);
        let mut action = None;
        if let Err(err) = state.complete_fmp_aead_completion(completion, |ready| {
            action = match ready {
                FmpReadyCompletion::Opened(opened) => Self::handle_opened_fmp_job(OpenedFmpJob {
                    packet_data: opened.packet_data,
                    source_peer,
                    transport_id,
                    remote_addr: remote_addr.clone(),
                    local_node_addr,
                    timestamp_ms,
                    packet_len,
                    fmp_counter,
                    fmp_flags,
                    fmp_plaintext_offset: fmp_ciphertext_offset,
                    fmp_plaintext_len: opened.plaintext_len,
                }),
                FmpReadyCompletion::DecryptFailure {
                    fmp_counter,
                    fmp_replay_highest,
                } => Some(DecryptWorkerJobAction::Output(DecryptWorkerOutput {
                    event: DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
                        source_peer,
                        fmp_counter,
                        fmp_replay_highest,
                        trace_enqueued_at: None,
                    }),
                    direct_delivery: None,
                })),
            };
        }) {
            debug!(?err, "dropping invalid ordered FMP completion");
            return None;
        }
        action
    }

    fn handle_opened_fmp_job(job: OpenedFmpJob) -> Option<DecryptWorkerJobAction> {
        let OpenedFmpJob {
            packet_data,
            source_peer,
            transport_id,
            remote_addr,
            local_node_addr,
            timestamp_ms,
            packet_len,
            fmp_counter,
            fmp_flags,
            fmp_plaintext_offset,
            fmp_plaintext_len,
        } = job;

        // The FMP plaintext lives in packet_data[fmp_ciphertext_offset..
        // fmp_ciphertext_offset + plaintext_len]. It carries a 4-byte
        // session-relative timestamp prefix, then the link-layer message.
        let fmp_plaintext_start = fmp_plaintext_offset;
        let fmp_plaintext_end = fmp_plaintext_offset + fmp_plaintext_len;
        const INNER_TIMESTAMP_LEN: usize = 4;
        if fmp_plaintext_len < INNER_TIMESTAMP_LEN {
            return None;
        }

        let inner_timestamp_ms = u32::from_le_bytes([
            packet_data[fmp_plaintext_start],
            packet_data[fmp_plaintext_start + 1],
            packet_data[fmp_plaintext_start + 2],
            packet_data[fmp_plaintext_start + 3],
        ]);
        if fmp_plaintext_len == INNER_TIMESTAMP_LEN {
            let fmp = DecryptFmpBookkeeping {
                source_peer,
                transport_id,
                remote_addr,
                packet_timestamp_ms: timestamp_ms,
                packet_len,
                fmp_counter,
                inner_timestamp_ms,
                fmp_flags,
            };
            return Some(DecryptWorkerJobAction::Output(DecryptWorkerOutput {
                event: DecryptWorkerEvent::AuthenticatedFmpReceive(
                    DecryptAuthenticatedFmpReceive {
                        fmp,
                        previous_hop_peer: None,
                        lane: DecryptWorkerLane::Priority,
                        trace_enqueued_at: None,
                    },
                ),
                direct_delivery: None,
            }));
        }

        let link_msg_start = fmp_plaintext_start + INNER_TIMESTAMP_LEN;
        let link_msg_end = fmp_plaintext_end;
        // Established no-coordinate FSP datagrams may be tiny TCP ACK-shaped
        // traffic, but they are still session data. Classify them as bulk after
        // FMP decrypt so they cannot flood the priority lane during LAN TCP
        // transfers. Handshakes, coordinate-carrying refreshes, heartbeats,
        // and other link control messages continue through the fallback path.
        let fsp_meta = local_established_fsp_datagram_meta(
            &packet_data,
            local_node_addr,
            link_msg_start,
            link_msg_end,
        );

        // Pass the buffer through by ownership + offset/length. No FMP-layer
        // allocation; rx_loop or the FSP worker slices into `packet_data`.
        let fallback = DecryptFallback::new(
            source_peer,
            transport_id,
            remote_addr,
            timestamp_ms,
            packet_len,
            fmp_counter,
            fmp_flags,
            packet_data,
            fmp_plaintext_start,
            fmp_plaintext_len,
        );

        if let Some(meta) = fsp_meta {
            let fsp_job = FspDecryptJob {
                fallback,
                lane: DecryptWorkerLane::Bulk,
                local_node_addr,
                source_addr: meta.source_addr,
                previous_hop_peer: source_peer,
                path_mtu: meta.path_mtu,
                ce_flag: fmp_flags & crate::node::wire::FLAG_CE != 0,
                inner_timestamp_ms,
                fsp_payload_offset: meta.fsp_payload_offset,
                fsp_payload_len: meta.fsp_payload_len,
                trace_enqueued_at: None,
            };
            return Some(DecryptWorkerJobAction::FspJob(fsp_job));
        }

        let event = DecryptWorkerEvent::Plaintext(fallback);
        Some(DecryptWorkerJobAction::Output(DecryptWorkerOutput {
            event,
            direct_delivery: None,
        }))
    }

    #[cfg(test)]
    fn contains_session(&self, session_key: DecryptSessionKey) -> bool {
        self.sessions.contains_key(&session_key)
    }

    #[cfg(test)]
    fn fmp_replay_highest(&self, session_key: DecryptSessionKey) -> Option<u64> {
        self.sessions
            .get(&session_key)
            .map(|state| state.fmp_replay.highest())
    }
}
