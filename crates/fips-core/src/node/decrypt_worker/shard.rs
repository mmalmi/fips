#[inline]
fn record_fsp_owner_match(owner_matches_current_worker: bool) {
    crate::perf_profile::record_event(if owner_matches_current_worker {
        crate::perf_profile::Event::DecryptFspOwnerSame
    } else {
        crate::perf_profile::Event::DecryptFspOwnerMismatch
    });
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
fn record_fsp_open_pool_bulk_drop(count: usize) {
    if count == 0 {
        return;
    }
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspOpenPoolQueueFullFallback,
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

enum FspOpenWorkerPrepareError {
    Ineligible(FspDecryptJob),
}

struct DecryptWorkerShard {
    pool: DecryptWorkerPool,
    // Lives entirely on this OS thread — never observed by any other thread.
    sessions: HashMap<DecryptSessionKey, OwnedSessionState>,
    fsp_sessions: HashMap<NodeAddr, OwnedFspSessionState>,
}

impl DecryptWorkerShard {
    fn new(pool: DecryptWorkerPool) -> Self {
        Self {
            pool,
            sessions: HashMap::new(),
            fsp_sessions: HashMap::new(),
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
        match self.handle_job_action(idx, job) {
            Ok(actions) => self.handle_job_actions_immediate(idx, actions),
            Err(err) => {
                debug!(worker = idx, error = %err, "decrypt worker job failed");
            }
        }
    }

    fn handle_bulk_job_msg(
        &mut self,
        idx: usize,
        job: DecryptJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        match self.handle_job_action(idx, job) {
            Ok(actions) => {
                self.push_job_actions_output(idx, actions, plaintext_batch, None, None);
            }
            Err(err) => {
                debug!(worker = idx, error = %err, "decrypt worker job failed");
            }
        }
    }

    fn handle_fsp_job_msg(&mut self, idx: usize, job: FspDecryptJob) {
        job.record_queue_wait();
        let _t_service =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptFspWorkerService);
        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        self.push_fsp_job_outputs(idx, job, &mut plaintext_batch);
        plaintext_batch.flush();
        trace!(worker = idx, "processed FSP decrypt worker job");
    }

    fn handle_bulk_fsp_job_msg(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        job.record_queue_wait();
        let _t_service =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptFspWorkerService);
        self.push_fsp_job_outputs(idx, job, plaintext_batch);
        trace!(worker = idx, "processed bulk FSP decrypt worker job");
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
        let shared = self
            .pool
            .fsp_bulk_open_worker_enabled()
            .then(|| state.shared_crypto_session(idx))
            .flatten()
            .map(Arc::new);
        if let Some(shared) = &shared {
            state.attach_shared_crypto_session(Arc::clone(shared));
        }
        self.pool.publish_fsp_aead_session(source_addr, shared);
        self.fsp_sessions.insert(source_addr, state);
    }

    fn unregister_fsp_session(&mut self, idx: usize, source_addr: NodeAddr) {
        trace!(
            worker = idx,
            %source_addr,
            "DecryptWorker: unregister FSP session"
        );
        self.fsp_sessions.remove(&source_addr);
        self.pool.publish_fsp_aead_session(source_addr, None);
    }

    #[cfg(test)]
    fn handle_job(
        &mut self,
        job: DecryptJob,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(output) = self.handle_job_output(0, job)? {
            let _ = output.send();
        }
        Ok(())
    }

    fn handle_job_actions_immediate(&mut self, idx: usize, actions: DecryptWorkerJobActions) {
        actions.for_each(|action| self.handle_job_action_immediate(idx, action));
    }

    fn handle_job_action_immediate(&mut self, idx: usize, action: DecryptWorkerJobAction) {
        match action {
            DecryptWorkerJobAction::Output(output) => {
                let _ = output.send();
            }
            DecryptWorkerJobAction::FspJob(job) => {
                for output in self.dispatch_or_handle_fsp_job(idx, job) {
                    let _ = output.send();
                }
            }
        }
    }

    fn push_job_actions_output(
        &mut self,
        idx: usize,
        actions: DecryptWorkerJobActions,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
        fsp_batcher: Option<&mut FspDecryptJobBatcher>,
        fsp_open_batcher: Option<&mut FspAeadOpenJobBatcher>,
    ) {
        let mut fsp_batcher = fsp_batcher;
        let mut fsp_open_batcher = fsp_open_batcher;
        actions.for_each(|action| {
            self.push_job_action_output(
                idx,
                action,
                plaintext_batch,
                fsp_batcher.as_deref_mut(),
                fsp_open_batcher.as_deref_mut(),
            );
        });
    }

    fn push_job_action_output(
        &mut self,
        idx: usize,
        action: DecryptWorkerJobAction,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
        fsp_batcher: Option<&mut FspDecryptJobBatcher>,
        fsp_open_batcher: Option<&mut FspAeadOpenJobBatcher>,
    ) {
        match action {
            DecryptWorkerJobAction::Output(output) => plaintext_batch.push_output(output),
            DecryptWorkerJobAction::FspJob(job) => {
                let owner_idx = self.pool.worker_idx_for_fsp(&job.source_addr);
                record_fsp_owner_match(owner_idx == idx);
                let job = if let Some(fsp_open_batcher) = fsp_open_batcher {
                    match self.try_prepare_fsp_bulk_open_worker_job(idx, job) {
                        Ok((open_idx, owner_idx, open_job)) => {
                            record_fsp_path_worker_open_bulk();
                            let returned =
                                fsp_open_batcher.push(&self.pool, open_idx, owner_idx, open_job);
                            if !returned.is_empty() {
                                self.drop_returned_fsp_aead_open_jobs(
                                    idx,
                                    returned,
                                    plaintext_batch,
                                );
                            }
                            return;
                        }
                        Err(FspOpenWorkerPrepareError::Ineligible(job)) => job,
                    }
                } else {
                    match self.try_start_fsp_bulk_open_worker(idx, job, plaintext_batch) {
                        Ok(()) => return,
                        Err(job) => job,
                    }
                };
                if owner_idx == idx {
                    record_fsp_path_local(job.lane());
                    self.push_fsp_job_outputs(idx, job, plaintext_batch);
                    return;
                }
                record_fsp_path_handoff(job.lane());
                if let Some(fsp_batcher) = fsp_batcher {
                    fsp_batcher.push(&self.pool, job);
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

    fn push_job_actions_output_with_fsp_batchers(
        &mut self,
        idx: usize,
        actions: DecryptWorkerJobActions,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let mut fsp_batcher = FspDecryptJobBatcher::new();
        let mut fsp_open_batcher = FspAeadOpenJobBatcher::new();
        self.push_job_actions_output(
            idx,
            actions,
            plaintext_batch,
            Some(&mut fsp_batcher),
            Some(&mut fsp_open_batcher),
        );
        fsp_batcher.flush(&self.pool);
        let returned = fsp_open_batcher.flush(&self.pool);
        if !returned.is_empty() {
            self.drop_returned_fsp_aead_open_jobs(idx, returned, plaintext_batch);
        }
    }

    fn local_established_fsp_meta(
        packet_data: &[u8],
        local_node_addr: NodeAddr,
        link_msg_start: usize,
        link_msg_end: usize,
    ) -> Option<FspDecryptJobMeta> {
        local_established_fsp_datagram_meta(
            packet_data,
            local_node_addr,
            link_msg_start,
            link_msg_end,
        )
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
        job: FspDecryptJob,
    ) -> Result<(usize, usize, FspAeadOpenJob), FspOpenWorkerPrepareError> {
        if !matches!(job.lane(), DecryptWorkerLane::Bulk) {
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        }

        let source_addr = job.source_addr;
        let Some(shared) = self.pool.fsp_aead_session(&source_addr) else {
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        };
        let owner_idx = shared.owner_idx;
        if owner_idx != idx || !self.pool.fsp_bulk_open_worker_enabled() {
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        }
        let Some(open_idx) = self.pool.worker_idx_for_fsp_open_avoiding(&source_addr, idx) else {
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        };
        let payload_end = job.fsp_payload_offset.saturating_add(job.fsp_payload_len);
        let Some(payload) = job.fallback.packet_data.get(job.fsp_payload_offset..payload_end)
        else {
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        };
        let Some(header) = FspEncryptedHeader::parse(payload) else {
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        };
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        if received_k_bit != shared.current_k_bit {
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        }
        let Some(ticket) = shared.try_issue_ticket() else {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::DecryptFspOpenWorkerWindowFallback,
                1,
            );
            return Err(FspOpenWorkerPrepareError::Ineligible(job));
        };

        let open_job = FspAeadOpenJob {
            source_addr,
            receive_order_id: shared.receive_order_id,
            ticket,
            cipher: Arc::clone(&shared.cipher),
            job,
            header,
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        };
        Ok((open_idx, owner_idx, open_job))
    }

    #[allow(clippy::result_large_err)]
    fn try_start_fsp_bulk_open_worker(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) -> Result<(), FspDecryptJob> {
        let (open_idx, owner_idx, open_job) = match self.try_prepare_fsp_bulk_open_worker_job(
            idx, job,
        ) {
            Ok(prepared) => prepared,
            Err(FspOpenWorkerPrepareError::Ineligible(job)) => return Err(job),
        };
        record_fsp_path_worker_open_bulk();
        match self
            .pool
            .dispatch_fsp_aead_open_worker_job(open_idx, owner_idx, open_job)
        {
            Ok(()) => Ok(()),
            Err(open_job) => {
                self.drop_returned_fsp_aead_open_job(idx, open_job, plaintext_batch);
                Ok(())
            }
        }
    }

    fn drop_returned_fsp_aead_open_job(
        &mut self,
        idx: usize,
        mut open_job: FspAeadOpenJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        record_fsp_open_pool_bulk_drop(1);
        let completion_owner_idx = open_job.completion_owner_idx.take();
        open_job.mark_returned_completion();
        let completion = open_job.into_dropped_completion();
        if completion_owner_idx == Some(idx) || completion_owner_idx.is_none() {
            self.handle_fsp_aead_completion_msg(idx, completion, plaintext_batch);
            return;
        }
        if let Some(owner_idx) = completion_owner_idx {
            let _ = self
                .pool
                .send_fsp_aead_completion_batch(owner_idx, FspAeadCompletionBatch::one(completion));
        }
    }

    fn drop_returned_fsp_aead_open_jobs(
        &mut self,
        idx: usize,
        jobs: Vec<FspAeadOpenJob>,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        record_fsp_open_pool_bulk_drop(jobs.len());
        let mut current_owner_idx = None;
        let mut current_local = false;
        let mut current_source_addr = None;
        let mut current_receive_order_id = None;
        let mut current_batch: Option<FspAeadCompletionBatch> = None;
        let completion_batch_max = DEFAULT_DECRYPT_WORKER_FSP_AEAD_COMPLETION_BATCH_MAX;

        for mut job in jobs {
            let completion_owner_idx = job.completion_owner_idx.take();
            let local_completion =
                completion_owner_idx == Some(idx) || completion_owner_idx.is_none();
            let source_addr = job.source_addr;
            let receive_order_id = job.receive_order_id;
            job.mark_returned_completion();
            let same_batch = current_batch
                .as_ref()
                .is_some_and(|batch| batch.len() < completion_batch_max)
                && current_local == local_completion
                && current_source_addr == Some(source_addr)
                && current_receive_order_id == Some(receive_order_id)
                && (local_completion || current_owner_idx == completion_owner_idx);

            if !same_batch {
                self.flush_dropped_fsp_aead_open_completion_batch(
                    idx,
                    current_local,
                    current_owner_idx.take(),
                    current_batch.take(),
                    plaintext_batch,
                );
                current_local = local_completion;
                current_owner_idx = completion_owner_idx.filter(|_| !local_completion);
                current_source_addr = Some(source_addr);
                current_receive_order_id = Some(receive_order_id);
                current_batch = Some(FspAeadCompletionBatch::one(job.into_dropped_completion()));
                continue;
            }

            let Some(batch) = current_batch.as_mut() else {
                unreachable!("same_batch requires an active completion batch")
            };
            batch.push(job.into_dropped_completion());
        }

        self.flush_dropped_fsp_aead_open_completion_batch(
            idx,
            current_local,
            current_owner_idx,
            current_batch,
            plaintext_batch,
        );
    }

    fn flush_dropped_fsp_aead_open_completion_batch(
        &mut self,
        idx: usize,
        local_completion: bool,
        completion_owner_idx: Option<usize>,
        batch: Option<FspAeadCompletionBatch>,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let Some(batch) = batch else { return };
        if local_completion {
            self.handle_fsp_aead_completion_batch_msg(idx, batch, plaintext_batch);
            return;
        }
        if let Some(owner_idx) = completion_owner_idx {
            let _ = self.pool.send_fsp_aead_completion_batch(owner_idx, batch);
        }
    }

    fn handle_fsp_aead_completion_msg(
        &mut self,
        idx: usize,
        completion: FspAeadCompletion,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let _t_service = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::FspAeadCompletionService,
        );
        record_fsp_aead_completion_wait(completion.source, completion.completed_at);
        let FspAeadCompletion {
            source_addr,
            receive_order_id,
            ticket,
            source: _,
            result,
            completed_at: _,
        } = completion;
        let Some(state) = self.fsp_sessions.get_mut(&source_addr) else {
            record_fsp_aead_completion_drop(
                crate::perf_profile::Event::FspAeadCompletionStaleSession,
                1,
            );
            return;
        };
        if state.fsp_receive_order_id() != receive_order_id {
            record_fsp_aead_completion_drop(
                crate::perf_profile::Event::FspAeadCompletionStaleOrder,
                1,
            );
            return;
        }
        let direct_delivery_sink = self.pool.direct_delivery_sink.clone();
        let mut outputs = Vec::with_capacity(1);
        let drain = match state.complete_ordered_fsp_open(ticket, result, |output| {
            if let Some(output) =
                Self::output_for_fsp_ready_completion(&direct_delivery_sink, output)
            {
                outputs.push(output);
            }
        }) {
            Ok(drain) => drain,
            Err(error) => {
                record_fsp_aead_completion_order_error(&error);
                debug!(
                    worker = idx,
                    ?error,
                    %source_addr,
                    "dropping invalid ordered FSP AEAD completion"
                );
                return;
            }
        };
        let next_ready = state.fsp_receive_order_next_ready();
        debug_assert_eq!(drain.ready, drain.accounted_ready());
        crate::perf_profile::record_fsp_aead_completion_drain(
            drain.ready,
            drain.accepted,
            drain.aead_failures,
            drain.epoch_mismatches,
            drain.replay_drops,
        );
        drain.aead_failure_sources.record();
        drain.replay_drop_sources.record();
        if let Some(shared) = self.pool.fsp_aead_session(&source_addr)
            && shared.receive_order_id == receive_order_id
        {
            shared.mark_next_ready(next_ready);
        }
        self.push_fsp_ready_outputs(outputs, plaintext_batch);
    }

    fn handle_fsp_aead_completion_batch_msg(
        &mut self,
        idx: usize,
        completions: FspAeadCompletionBatch,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let Some((source_addr, receive_order_id)) = completions.common_source_order() else {
            completions.for_each(|completion| {
                self.handle_fsp_aead_completion_msg(idx, completion, plaintext_batch);
            });
            return;
        };
        let completions = completions.into_vec();
        if completions.len() <= 1 {
            for completion in completions {
                self.handle_fsp_aead_completion_msg(idx, completion, plaintext_batch);
            }
            return;
        }
        self.handle_fsp_aead_completion_same_source_batch(
            idx,
            source_addr,
            receive_order_id,
            completions,
            plaintext_batch,
        );
    }

    fn handle_fsp_aead_completion_same_source_batch(
        &mut self,
        idx: usize,
        source_addr: NodeAddr,
        receive_order_id: u64,
        completions: Vec<FspAeadCompletion>,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let _t_service = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::FspAeadCompletionService,
        );
        for completion in &completions {
            record_fsp_aead_completion_wait(completion.source, completion.completed_at);
        }

        let mut ready = 0usize;
        let mut accepted = 0usize;
        let mut aead_failures = 0usize;
        let mut epoch_mismatches = 0usize;
        let mut replay_drops = 0usize;
        let mut dropped = 0usize;
        let mut rx_loop_fallbacks = 0usize;
        let mut aead_failure_sources = FspAeadFailureSources::default();
        let mut replay_drop_sources = FspReplayDropSources::default();
        let direct_delivery_sink = self.pool.direct_delivery_sink.clone();
        let mut outputs = Vec::with_capacity(completions.len());
        let next_ready;
        {
            let Some(state) = self.fsp_sessions.get_mut(&source_addr) else {
                record_fsp_aead_completion_drop(
                    crate::perf_profile::Event::FspAeadCompletionStaleSession,
                    completions.len(),
                );
                return;
            };
            if state.fsp_receive_order_id() != receive_order_id {
                record_fsp_aead_completion_drop(
                    crate::perf_profile::Event::FspAeadCompletionStaleOrder,
                    completions.len(),
                );
                return;
            }
            for completion in completions {
                let FspAeadCompletion {
                    source_addr: _,
                    receive_order_id: _,
                    ticket,
                    source: _,
                    result,
                    completed_at: _,
                } = completion;
                let drain = match state.complete_ordered_fsp_open(ticket, result, |output| {
                    if let Some(output) =
                        Self::output_for_fsp_ready_completion(&direct_delivery_sink, output)
                    {
                        outputs.push(output);
                    }
                }) {
                    Ok(drain) => drain,
                    Err(error) => {
                        record_fsp_aead_completion_order_error(&error);
                        debug!(
                            worker = idx,
                            ?error,
                            %source_addr,
                            "dropping invalid ordered FSP AEAD completion"
                        );
                        continue;
                    }
                };
                debug_assert_eq!(drain.ready, drain.accounted_ready());
                ready += drain.ready;
                accepted += drain.accepted;
                aead_failures += drain.aead_failures;
                epoch_mismatches += drain.epoch_mismatches;
                replay_drops += drain.replay_drops;
                dropped += drain.dropped;
                rx_loop_fallbacks += drain.rx_loop_fallbacks;
                aead_failure_sources.add_sources(drain.aead_failure_sources);
                replay_drop_sources.add_sources(drain.replay_drop_sources);
            }
            next_ready = state.fsp_receive_order_next_ready();
        }

        debug_assert_eq!(
            ready,
            accepted
                + aead_failures
                + epoch_mismatches
                + replay_drops
                + dropped
                + rx_loop_fallbacks
        );
        crate::perf_profile::record_fsp_aead_completion_drain(
            ready,
            accepted,
            aead_failures,
            epoch_mismatches,
            replay_drops,
        );
        aead_failure_sources.record();
        replay_drop_sources.record();
        if let Some(shared) = self.pool.fsp_aead_session(&source_addr)
            && shared.receive_order_id == receive_order_id
        {
            shared.mark_next_ready(next_ready);
        }
        self.push_fsp_ready_outputs(outputs, plaintext_batch);
    }

    fn push_fsp_ready_outputs(
        &self,
        outputs: Vec<DecryptWorkerOutput>,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        for output in outputs {
            plaintext_batch.push_output(output);
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

    fn dispatch_or_handle_fsp_job(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
    ) -> Vec<DecryptWorkerOutput> {
        let owner_idx = self.pool.worker_idx_for_fsp(&job.source_addr);
        record_fsp_owner_match(owner_idx == idx);
        if owner_idx == idx {
            record_fsp_path_local(job.lane());
            return self.handle_fsp_job_outputs(idx, job);
        }
        record_fsp_path_handoff(job.lane());
        match self.pool.dispatch_fsp_job_or_return(job) {
            Ok(()) => Vec::new(),
            Err(job) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFspPathFallback,
                );
                drop_fsp_owner_handoff_job(job);
                Vec::new()
            }
        }
    }

    fn output_for_fsp_aead_failure(
        job: FspDecryptJob,
        header: &FspEncryptedHeader,
        fallback_to_rx_loop: bool,
    ) -> DecryptWorkerOutput {
        let FspDecryptJob {
            fallback_tx,
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
                fallback_tx,
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
            fallback_tx,
            event: DecryptWorkerEvent::Plaintext(fallback),
            direct_delivery: None,
        }
    }

    fn output_for_malformed_fsp_drop(
        &self,
        fallback_tx: DecryptWorkerFallbackSender,
        fallback: DecryptFallback,
        lane: DecryptWorkerLane,
        inner_timestamp_ms: u32,
        previous_hop_peer: PeerIdentity,
    ) -> DecryptWorkerOutput {
        crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspMalformedDropped);
        DecryptWorkerOutput {
            fallback_tx,
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
            fallback_tx,
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
            remote_addr: fallback.remote_addr.clone(),
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
                    fallback_tx,
                    event,
                    direct_delivery,
                })
            }
            Err(message) => Some(DecryptWorkerOutput {
                fallback_tx,
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
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        for output in self.handle_fsp_job_outputs(idx, job) {
            plaintext_batch.push_output(output);
        }
    }

    fn handle_fsp_job_outputs(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
    ) -> Vec<DecryptWorkerOutput> {
        let FspDecryptJob {
            fallback_tx,
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

        let Some(state) = self.fsp_sessions.get_mut(&source_addr) else {
            return vec![DecryptWorkerOutput {
                fallback_tx,
                event: DecryptWorkerEvent::Plaintext(fallback),
                direct_delivery: None,
            }];
        };
        let payload_end = fsp_payload_offset.saturating_add(fsp_payload_len);
        let header = {
            let Some(payload) = fallback.packet_data.get(fsp_payload_offset..payload_end) else {
                return vec![self.output_for_malformed_fsp_drop(
                    fallback_tx,
                    fallback,
                    lane,
                    inner_timestamp_ms,
                    previous_hop_peer,
                )];
            };
            let Some(header) = FspEncryptedHeader::parse(payload) else {
                return vec![self.output_for_malformed_fsp_drop(
                    fallback_tx,
                    fallback,
                    lane,
                    inner_timestamp_ms,
                    previous_hop_peer,
                )];
            };
            header
        };
        let fmp = DecryptFmpBookkeeping {
            source_peer: fallback.source_peer,
            transport_id: fallback.transport_id,
            remote_addr: fallback.remote_addr.clone(),
            packet_timestamp_ms: fallback.timestamp_ms,
            packet_len: fallback.packet_len,
            fmp_counter: fallback.fmp_counter,
            inner_timestamp_ms,
            fmp_flags: fallback.fmp_flags,
        };

        if state.has_single_current_epoch() {
            let Some(ticket) = state.issue_fsp_receive_ticket() else {
                match lane {
                    DecryptWorkerLane::Priority => {
                        record_decrypt_worker_priority_drop(idx, "fsp-receive-window");
                    }
                    DecryptWorkerLane::Bulk => {
                        record_decrypt_worker_bulk_drop_count(idx, 1);
                    }
                }
                return Vec::new();
            };
            let ciphertext_offset = fsp_payload_offset + FSP_HEADER_SIZE;
            let Some(ciphertext) = fallback.packet_data.get_mut(ciphertext_offset..payload_end)
            else {
                return vec![self.output_for_malformed_fsp_drop(
                    fallback_tx,
                    fallback,
                    lane,
                    inner_timestamp_ms,
                    previous_hop_peer,
                )];
            };
            let local_open_preserves_ciphertext = matches!(lane, DecryptWorkerLane::Bulk);
            let restore_ciphertext = matches!(lane, DecryptWorkerLane::Priority)
                .then(|| ciphertext.to_vec());
            let mut scratch_ciphertext = Vec::new();
            let open_result = state.current_epoch_matches(&header).then(|| {
                let _t_fsp =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
                if local_open_preserves_ciphertext {
                    scratch_ciphertext.extend_from_slice(ciphertext);
                    state.open_current_established_frame_in_place_deferred_replay(
                        &header,
                        &mut scratch_ciphertext,
                    )
                } else {
                    state.open_current_established_frame_in_place_deferred_replay(
                        &header, ciphertext,
                    )
                }
            });
            let fallback_to_rx_loop =
                if matches!(open_result, Some(Err(FspOpenError::Aead))) {
                    if local_open_preserves_ciphertext {
                        true
                    } else if let Some(original) = restore_ciphertext.as_deref() {
                        ciphertext.copy_from_slice(original);
                        true
                    } else {
                        false
                    }
                } else {
                    false
            };
            let mut job = FspDecryptJob {
                fallback_tx,
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
                Some(Ok(plaintext_len)) => {
                    if local_open_preserves_ciphertext {
                        let plaintext = &scratch_ciphertext[..plaintext_len];
                        let restore = &mut job.fallback.packet_data
                            [ciphertext_offset..ciphertext_offset + plaintext_len];
                        restore.copy_from_slice(plaintext);
                    }
                    FspOrderedCompletion::Opened {
                        opened: FspOpenedJob {
                            job,
                            header,
                            plaintext_len,
                        },
                        source: FspAeadCompletionSource::Local,
                    }
                }
                Some(Err(FspOpenError::Aead)) => {
                    let count_failure = !fallback_to_rx_loop;
                    if count_failure {
                        crate::perf_profile::record_fsp_aead_completion_local_open_aead_failure();
                    }
                    FspOrderedCompletion::AeadFailed {
                        job,
                        header,
                        source: FspAeadCompletionSource::Local,
                        fallback_to_rx_loop,
                        count_failure,
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
            let direct_delivery_sink = self.pool.direct_delivery_sink.clone();
            let mut outputs = Vec::with_capacity(1);
            let drain = match state.complete_ordered_fsp_open(ticket, completion, |output| {
                if let Some(output) =
                    Self::output_for_fsp_ready_completion(&direct_delivery_sink, output)
                {
                    outputs.push(output);
                }
            }) {
                Ok(drain) => drain,
                Err(error) => {
                    record_fsp_aead_completion_order_error(&error);
                    debug!(
                        worker = idx,
                        ?error,
                        %source_addr,
                        "dropping invalid local ordered FSP completion"
                    );
                    return Vec::new();
                }
            };
            let next_ready = state.fsp_receive_order_next_ready();
            debug_assert_eq!(drain.ready, drain.accounted_ready());
            crate::perf_profile::record_fsp_aead_completion_drain(
                drain.ready,
                drain.accepted,
                drain.aead_failures,
                drain.epoch_mismatches,
                drain.replay_drops,
            );
            drain.aead_failure_sources.record();
            drain.replay_drop_sources.record();
            if let Some(shared) = self.pool.fsp_aead_session(&source_addr)
                && shared.receive_order_id == state.fsp_receive_order_id()
            {
                shared.mark_next_ready(next_ready);
            }
            return outputs;
        }

        let Some(payload) = fallback.packet_data.get(fsp_payload_offset..payload_end) else {
            return vec![self.output_for_malformed_fsp_drop(
                fallback_tx,
                fallback,
                lane,
                inner_timestamp_ms,
                previous_hop_peer,
            )];
        };
        let ciphertext = &payload[FSP_HEADER_SIZE..];
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
                return Vec::new();
            }
            Err(FspOpenError::Aead) => {
                let job = FspDecryptJob {
                    fallback_tx,
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
                return vec![Self::output_for_fsp_aead_failure(job, &header, true)];
            }
        };
        let Some((timestamp, msg_type, inner_flags_byte, _body)) =
            fsp_strip_inner_header(&plaintext)
        else {
            return Vec::new();
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
                    return vec![DecryptWorkerOutput {
                        fallback_tx,
                        event,
                        direct_delivery,
                    }];
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

        vec![DecryptWorkerOutput {
            fallback_tx,
            event,
            direct_delivery: None,
        }]
    }

    fn handle_job_action(
        &mut self,
        idx: usize,
        job: DecryptJob,
    ) -> Result<DecryptWorkerJobActions, Box<dyn std::error::Error + Send + Sync>> {
        job.record_queue_wait();
        let DecryptJob {
            mut packet_data,
            lane,
            session_key,
            worker_idx: _,
            _transport_id: transport_id,
            _remote_addr: remote_addr,
            local_node_addr,
            timestamp_ms,
            fmp_counter,
            fmp_flags,
            fmp_header,
            fmp_ciphertext_offset,
            fallback_tx,
            trace_enqueued_at: _,
        } = job;
        // Capture the wire packet length BEFORE decrypt mutates the
        // buffer — it'll be the same number either way (in-place AEAD
        // open doesn't change Vec::len), but documenting the intent.
        let packet_len = packet_data.len();

        if !self.pool.fmp_aead_helpers_enabled() {
            let (source_peer, fmp_plaintext_len) = {
                let state = match self.sessions.get_mut(&session_key) {
                    Some(s) => s,
                    None => {
                        let _ = fallback_tx; // explicitly ignore — drop path
                        let _ = packet_data;
                        return Ok(DecryptWorkerJobActions::None);
                    }
                };
                let source_peer = state.source_peer;
                let precheck = match state.precheck_fmp_replay(fmp_counter) {
                    Ok(precheck) => precheck,
                    Err(FmpOpenError::Replay) => return Ok(DecryptWorkerJobActions::None),
                    #[cfg(test)]
                    Err(FmpOpenError::Aead { .. }) => {
                        unreachable!("FMP replay precheck cannot run AEAD")
                    }
                };
                let outcome = match OwnedSessionState::open_fmp_aead_in_place(
                    &state.fmp_cipher,
                    &mut packet_data,
                    fmp_ciphertext_offset,
                    fmp_counter,
                    fmp_flags,
                    &fmp_header,
                ) {
                    Ok(outcome) => outcome,
                    Err(()) => {
                        return Ok(DecryptWorkerJobActions::one(DecryptWorkerJobAction::Output(
                            DecryptWorkerOutput {
                                fallback_tx,
                                event: DecryptWorkerEvent::DecryptFailure(
                                    DecryptFailureReport {
                                        source_peer,
                                        fmp_counter,
                                        fmp_replay_highest: precheck.replay_highest,
                                        trace_enqueued_at: None,
                                    },
                                ),
                                direct_delivery: None,
                            },
                        )));
                    }
                };
                if OwnedSessionState::accept_prechecked_fmp_replay_on(
                    &mut state.fmp_replay,
                    precheck,
                )
                .is_err()
                {
                    return Ok(DecryptWorkerJobActions::None);
                }
                (source_peer, outcome.plaintext_len)
            };

            let opened = OpenedFmpJob {
                packet_data,
                lane,
                source_peer,
                transport_id,
                remote_addr,
                local_node_addr,
                timestamp_ms,
                packet_len,
                fmp_counter,
                fmp_flags,
                fmp_plaintext_offset: fmp_ciphertext_offset,
                fmp_plaintext_len,
                fallback_tx,
            };
            return Ok(Self::handle_opened_fmp_job(opened)
                .map(DecryptWorkerJobActions::one)
                .unwrap_or(DecryptWorkerJobActions::None));
        }

        // Look up the shard-owned session state. If absent (session not
        // yet registered, or unregistered mid-flight), drop. The caller only
        // marks a session worker-owned after registration is accepted, so an
        // absent session here is stale in-flight work, not a fallback path.
        let (source_peer, receive_order_id, replay_precheck, ticket, cipher) = {
            let state = match self.sessions.get_mut(&session_key) {
                Some(s) => s,
                None => {
                    let _ = fallback_tx; // explicitly ignore — drop path
                    let _ = packet_data;
                    return Ok(DecryptWorkerJobActions::None);
                }
            };
            let source_peer = state.source_peer;

            // **Direct &mut access** to shard-owned replay state — no
            // Arc<Mutex> lock acquire and no split-brain replay owner. Replays
            // are dropped before AEAD work; successful AEAD is the only path
            // that accepts the counter into the replay window.
            let replay_precheck = match state.precheck_fmp_replay(fmp_counter) {
                Ok(precheck) => precheck,
                Err(FmpOpenError::Replay) => return Ok(DecryptWorkerJobActions::None),
                #[cfg(test)]
                Err(FmpOpenError::Aead { .. }) => {
                    unreachable!("FMP replay precheck cannot run AEAD")
                }
            };
            let Some(ticket) = state.issue_fmp_receive_ticket() else {
                crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerQueueFull);
                return Ok(DecryptWorkerJobActions::None);
            };
            (
                source_peer,
                state.fmp_receive_order_id(),
                replay_precheck,
                ticket,
                Arc::clone(&state.fmp_cipher),
            )
        };

        let helper_job = FmpAeadHelperJob {
            session_key,
            receive_order_id,
            ticket,
            replay: FmpReplayDecision::Prechecked(replay_precheck),
            cipher,
            fmp_header,
            opened: OpenedFmpJob {
                packet_data,
                lane,
                source_peer,
                transport_id,
                remote_addr,
                local_node_addr,
                timestamp_ms,
                packet_len,
                fmp_counter,
                fmp_flags,
                fmp_plaintext_offset: fmp_ciphertext_offset,
                fmp_plaintext_len: 0,
                fallback_tx,
            },
            completion_tx: None,
            helper_queued_at: None,
        };

        match self.pool.dispatch_fmp_aead_helper_job(idx, helper_job) {
            Ok(()) => Ok(DecryptWorkerJobActions::None),
            Err(helper_job) => {
                let completion = helper_job.into_completion();
                Ok(self.handle_fmp_aead_completion_action(completion))
            }
        }
    }

    fn handle_fmp_aead_completion_msg(
        &mut self,
        idx: usize,
        completion: FmpAeadCompletion,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let _t_service =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpAeadHelperCompletionService);
        let actions = self.handle_fmp_aead_completion_action(completion);
        self.push_job_actions_output_with_fsp_batchers(idx, actions, plaintext_batch);
    }

    fn handle_fmp_aead_completion_batch_msg(
        &mut self,
        idx: usize,
        completions: FmpAeadCompletionBatch,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let Some((session_key, receive_order_id)) = completions.common_session_order() else {
            completions.for_each(|completion| {
                self.handle_fmp_aead_completion_msg(idx, completion, plaintext_batch);
            });
            return;
        };
        let completions = completions.into_vec();
        if completions.len() <= 1 {
            for completion in completions {
                self.handle_fmp_aead_completion_msg(idx, completion, plaintext_batch);
            }
            return;
        }
        self.handle_fmp_aead_completion_same_session_batch(
            idx,
            session_key,
            receive_order_id,
            completions,
            plaintext_batch,
        );
    }

    fn handle_fmp_aead_completion_same_session_batch(
        &mut self,
        idx: usize,
        session_key: DecryptSessionKey,
        receive_order_id: u64,
        completions: Vec<FmpAeadCompletion>,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let _t_service = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::FmpAeadHelperCompletionService,
        );
        for completion in &completions {
            let (priority_count, bulk_count) = match completion.result.lane() {
                DecryptWorkerLane::Priority => (1, 0),
                DecryptWorkerLane::Bulk => (0, 1),
            };
            crate::perf_profile::record_since_split_count(
                crate::perf_profile::Stage::FmpAeadHelperCompletionWait,
                crate::perf_profile::Stage::FmpAeadHelperPriorityCompletionWait,
                crate::perf_profile::Stage::FmpAeadHelperBulkCompletionWait,
                completion.completed_at,
                1,
                priority_count,
                bulk_count,
            );
        }

        let mut ready = 0usize;
        let mut accepted = 0usize;
        let mut aead_failures = 0usize;
        let mut replay_drops = 0usize;
        let mut actions = DecryptWorkerJobActions::None;
        {
            let Some(state) = self.sessions.get_mut(&session_key) else {
                return;
            };
            if state.fmp_receive_order_id() != receive_order_id {
                return;
            }
            for completion in completions {
                let FmpAeadCompletion {
                    session_key: _,
                    receive_order_id: _,
                    ticket,
                    completed_at: _,
                    result,
                } = completion;
                let ordered = match result {
                    FmpAeadCompletionResult::Opened { replay, opened } => {
                        FmpOrderedCompletion::Opened {
                            replay,
                            value: opened,
                        }
                    }
                    FmpAeadCompletionResult::AeadFailed(failure) => {
                        FmpOrderedCompletion::AeadFailed(failure)
                    }
                };
                let drain_result =
                    state.complete_ordered_fmp_open_with_value(ticket, ordered, |ready| {
                        match ready {
                            FmpReadyCompletion::Opened(opened_job) => {
                                if let Some(action) = Self::handle_opened_fmp_job(opened_job) {
                                    actions.push(action);
                                }
                            }
                            FmpReadyCompletion::AeadFailed(failure) => {
                                actions.push(Self::fmp_aead_failure_action(failure));
                            }
                        }
                    });
                match drain_result {
                    Ok(drain) => {
                        ready += drain.ready;
                        accepted += drain.accepted;
                        aead_failures += drain.aead_failures;
                        replay_drops += drain.replay_drops;
                    }
                    Err(FmpOpenError::Replay) => {}
                    #[cfg(test)]
                    Err(FmpOpenError::Aead { .. }) => {
                        unreachable!("ordered FMP completion cannot run AEAD")
                    }
                }
            }
        }

        debug_assert_eq!(ready, accepted + aead_failures + replay_drops);
        crate::perf_profile::record_fmp_aead_completion_drain(
            ready,
            accepted,
            aead_failures,
            replay_drops,
        );
        self.push_job_actions_output_with_fsp_batchers(idx, actions, plaintext_batch);
    }

    fn handle_fmp_aead_completion_action(
        &mut self,
        completion: FmpAeadCompletion,
    ) -> DecryptWorkerJobActions {
        let (priority_count, bulk_count) = match completion.result.lane() {
            DecryptWorkerLane::Priority => (1, 0),
            DecryptWorkerLane::Bulk => (0, 1),
        };
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::FmpAeadHelperCompletionWait,
            crate::perf_profile::Stage::FmpAeadHelperPriorityCompletionWait,
            crate::perf_profile::Stage::FmpAeadHelperBulkCompletionWait,
            completion.completed_at,
            1,
            priority_count,
            bulk_count,
        );
        let FmpAeadCompletion {
            session_key,
            receive_order_id,
            ticket,
            completed_at: _,
            result,
        } = completion;

        let Some(state) = self.sessions.get_mut(&session_key) else {
            return DecryptWorkerJobActions::None;
        };
        if state.fmp_receive_order_id() != receive_order_id {
            return DecryptWorkerJobActions::None;
        }

        match result {
            FmpAeadCompletionResult::Opened { replay, opened } => {
                let mut actions = DecryptWorkerJobActions::None;
                let drain_result = state.complete_ordered_fmp_open_with_value(
                    ticket,
                    FmpOrderedCompletion::Opened {
                        replay,
                        value: opened,
                    },
                    |ready| match ready {
                        FmpReadyCompletion::Opened(opened_job) => {
                            if let Some(action) = Self::handle_opened_fmp_job(opened_job) {
                                actions.push(action);
                            }
                        }
                        FmpReadyCompletion::AeadFailed(failure) => {
                            actions.push(Self::fmp_aead_failure_action(failure));
                        }
                    },
                );
                match drain_result {
                    Ok(drain) => {
                        crate::perf_profile::record_fmp_aead_completion_drain(
                            drain.ready,
                            drain.accepted,
                            drain.aead_failures,
                            drain.replay_drops,
                        );
                    }
                    Err(FmpOpenError::Replay) => return actions,
                    #[cfg(test)]
                    Err(FmpOpenError::Aead { .. }) => {
                        unreachable!("ordered FMP completion cannot run AEAD")
                    }
                }
                actions
            }
            FmpAeadCompletionResult::AeadFailed(failure) => {
                let mut actions = DecryptWorkerJobActions::None;
                let drain_result = state.complete_ordered_fmp_open_with_value(
                    ticket,
                    FmpOrderedCompletion::AeadFailed(failure),
                    |ready| match ready {
                        FmpReadyCompletion::Opened(opened_job) => {
                            if let Some(action) = Self::handle_opened_fmp_job(opened_job) {
                                actions.push(action);
                            }
                        }
                        FmpReadyCompletion::AeadFailed(failure) => {
                            actions.push(Self::fmp_aead_failure_action(failure));
                        }
                    },
                );
                if let Ok(drain) = drain_result {
                    crate::perf_profile::record_fmp_aead_completion_drain(
                        drain.ready,
                        drain.accepted,
                        drain.aead_failures,
                        drain.replay_drops,
                    );
                }
                actions
            }
        }
    }

    fn fmp_aead_failure_action(failure: FmpAeadFailure) -> DecryptWorkerJobAction {
        DecryptWorkerJobAction::Output(DecryptWorkerOutput {
            fallback_tx: failure.fallback_tx,
            event: DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
                source_peer: failure.source_peer,
                fmp_counter: failure.fmp_counter,
                fmp_replay_highest: failure.fmp_replay_highest.unwrap_or(0),
                trace_enqueued_at: None,
            }),
            direct_delivery: None,
        })
    }

    fn handle_opened_fmp_job(job: OpenedFmpJob) -> Option<DecryptWorkerJobAction> {
        let OpenedFmpJob {
            packet_data,
            lane: _,
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
            fallback_tx,
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
                fallback_tx,
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
        let fsp_meta = Self::local_established_fsp_meta(
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
                fallback_tx: fallback_tx.clone(),
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
            fallback_tx,
            event,
            direct_delivery: None,
        }))
    }

    #[cfg(test)]
    fn handle_job_output(
        &mut self,
        idx: usize,
        job: DecryptJob,
    ) -> Result<Option<DecryptWorkerOutput>, Box<dyn std::error::Error + Send + Sync>> {
        let actions = self.handle_job_action(idx, job)?;
        Ok(self.handle_job_actions_output(idx, actions))
    }

    fn fmp_receive_order_window_available(&self, session_key: DecryptSessionKey) -> bool {
        self.sessions
            .get(&session_key)
            .is_none_or(OwnedSessionState::can_issue_fmp_receive_ticket)
    }

    #[cfg(test)]
    fn handle_job_actions_output(
        &mut self,
        idx: usize,
        actions: DecryptWorkerJobActions,
    ) -> Option<DecryptWorkerOutput> {
        let mut first_output = None;
        actions.for_each(|action| {
            let outputs = match action {
                DecryptWorkerJobAction::Output(output) => vec![output],
                DecryptWorkerJobAction::FspJob(job) => self.dispatch_or_handle_fsp_job(idx, job),
            };
            for output in outputs {
                if first_output.is_none() {
                    first_output = Some(output);
                } else {
                    let _ = output.send();
                }
            }
        });
        first_output
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
