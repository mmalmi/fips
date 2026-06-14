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
            Ok(Some(action)) => self.handle_job_action_immediate(idx, action),
            Ok(None) => {}
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
            Ok(Some(action)) => {
                self.push_job_action_output(idx, action, plaintext_batch, None);
            }
            Ok(None) => {}
            Err(err) => {
                debug!(worker = idx, error = %err, "decrypt worker job failed");
            }
        }
    }

    fn handle_fsp_job_msg(&mut self, idx: usize, job: FspDecryptJob) {
        job.record_queue_wait();
        let _t_service =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptFspWorkerService);
        if let Some(output) = self.handle_fsp_job_output(job) {
            let _ = output.send();
        }
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
        if let Some(output) = self.handle_fsp_job_output(job) {
            plaintext_batch.push_output(output);
        }
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
        state: OwnedFspSessionState,
    ) {
        trace!(
            worker = idx,
            %source_addr,
            "DecryptWorker: register FSP session"
        );
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
        if let Some(output) = self.handle_job_output(0, job)? {
            let _ = output.send();
        }
        Ok(())
    }

    fn handle_job_action_immediate(&mut self, idx: usize, action: DecryptWorkerJobAction) {
        match action {
            DecryptWorkerJobAction::Output(output) => {
                let _ = output.send();
            }
            DecryptWorkerJobAction::FspJob(job) => {
                if let Some(output) = self.dispatch_or_handle_fsp_job(idx, job) {
                    let _ = output.send();
                }
            }
        }
    }

    fn push_job_action_output(
        &mut self,
        idx: usize,
        action: DecryptWorkerJobAction,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
        fsp_batcher: Option<&mut FspDecryptJobBatcher>,
    ) {
        match action {
            DecryptWorkerJobAction::Output(output) => plaintext_batch.push_output(output),
            DecryptWorkerJobAction::FspJob(job) => {
                let job = match self.try_start_fsp_aead_helper(idx, job, plaintext_batch) {
                    Ok(()) => return,
                    Err(job) => job,
                };
                if self.pool.worker_idx_for_fsp(&job.source_addr) == idx {
                    if let Some(output) = self.handle_fsp_job_output(job) {
                        plaintext_batch.push_output(output);
                    }
                    return;
                }
                if let Some(fsp_batcher) = fsp_batcher {
                    fsp_batcher.push(&self.pool, job, plaintext_batch);
                    return;
                }
                match self.pool.dispatch_fsp_job_or_return(job) {
                    Ok(()) => {}
                    Err(job) => plaintext_batch.push_fsp_job_fallback(job),
                }
            }
        }
    }

    fn local_established_fsp_meta(
        packet_data: &[u8],
        local_node_addr: NodeAddr,
        link_msg_start: usize,
        link_msg_end: usize,
    ) -> Option<FspDecryptJobMeta> {
        let link_msg = packet_data.get(link_msg_start..link_msg_end)?;
        let (&msg_type, datagram_payload) = link_msg.split_first()?;
        if msg_type != LinkMessageType::SessionDatagram.to_byte() {
            return None;
        }
        let datagram = SessionDatagramRef::decode(datagram_payload).ok()?;
        if datagram.ttl == 0 || datagram.dest_addr != local_node_addr {
            return None;
        }
        let prefix = FspCommonPrefix::parse(datagram.payload)?;
        if prefix.phase != FSP_PHASE_ESTABLISHED || prefix.is_unencrypted() || prefix.has_coords() {
            return None;
        }
        let fsp_payload_offset = link_msg_start + 1 + SessionDatagramRef::HEADER_LEN;
        Some(FspDecryptJobMeta {
            source_addr: datagram.src_addr,
            path_mtu: datagram.path_mtu,
            fsp_payload_offset,
            fsp_payload_len: datagram.payload.len(),
        })
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
    fn try_start_fsp_aead_helper(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) -> Result<(), FspDecryptJob> {
        if !self.pool.fsp_aead_helpers_enabled()
            || !matches!(job.lane(), DecryptWorkerLane::Bulk)
        {
            return Err(job);
        }
        let Some(shared) = self.pool.fsp_aead_session(&job.source_addr) else {
            return Err(job);
        };
        let payload_end = job.fsp_payload_offset.saturating_add(job.fsp_payload_len);
        let header = {
            let Some(payload) = job.fallback.packet_data.get(job.fsp_payload_offset..payload_end)
            else {
                return Err(job);
            };
            let Some(header) = FspEncryptedHeader::parse(payload) else {
                return Err(job);
            };
            header
        };
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        if received_k_bit != shared.current_k_bit {
            return Err(job);
        }
        let owner_idx = shared.owner_idx;
        let helper_job = FspAeadHelperJob {
            source_addr: job.source_addr,
            receive_order_id: shared.receive_order_id,
            ticket: shared.issue_ticket(),
            cipher: Arc::clone(&shared.cipher),
            job,
            header,
            completion_tx: None,
            helper_queued_at: None,
        };

        match self.pool.dispatch_fsp_aead_helper_job(owner_idx, helper_job) {
            Ok(()) => Ok(()),
            Err(helper_job) => {
                let completion = helper_job.into_completion();
                if owner_idx == idx {
                    self.handle_fsp_aead_completion_msg(idx, completion, plaintext_batch);
                } else {
                    let _ = self
                        .pool
                        .send_fsp_aead_completion_blocking(owner_idx, completion);
                }
                Ok(())
            }
        }
    }

    fn handle_fsp_aead_completion_msg(
        &mut self,
        idx: usize,
        completion: FspAeadCompletion,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::FspAeadHelperCompletionWait,
            completion.completed_at,
            1,
        );
        let FspAeadCompletion {
            source_addr,
            receive_order_id,
            ticket,
            result,
            completed_at: _,
        } = completion;
        let Some(state) = self.fsp_sessions.get_mut(&source_addr) else {
            return;
        };
        if state.fsp_receive_order_id() != receive_order_id {
            return;
        }
        let drain = match state.complete_ordered_fsp_open(ticket, result) {
            Ok(drain) => drain,
            Err(error) => {
                debug!(
                    worker = idx,
                    ?error,
                    %source_addr,
                    "dropping invalid ordered FSP AEAD completion"
                );
                return;
            }
        };
        debug_assert_eq!(drain.ready, drain.accepted + drain.aead_failures + drain.replay_drops);
        for completion in drain.outputs {
            match completion {
                FspReadyCompletion::Opened {
                    opened,
                    slot,
                    source_peer,
                } => {
                    if let Some(output) =
                        self.output_for_opened_fsp_job(source_peer, opened, slot)
                    {
                        plaintext_batch.push_output(output);
                    }
                }
                FspReadyCompletion::AeadFailed { job, header } => {
                    plaintext_batch.push_output(self.output_for_fsp_aead_failure(job, &header));
                }
            }
        }
    }

    fn dispatch_or_handle_fsp_job(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
    ) -> Option<DecryptWorkerOutput> {
        if self.pool.worker_idx_for_fsp(&job.source_addr) == idx {
            return self.handle_fsp_job_output(job);
        }
        match self.pool.dispatch_fsp_job_or_return(job) {
            Ok(()) => None,
            Err(job) => Some(DecryptWorkerOutput {
                fallback_tx: job.fallback_tx,
                event: DecryptWorkerEvent::Plaintext(job.fallback),
                direct_delivery: None,
            }),
        }
    }

    fn output_for_fsp_aead_failure(
        &self,
        job: FspDecryptJob,
        header: &FspEncryptedHeader,
    ) -> DecryptWorkerOutput {
        let FspDecryptJob {
            fallback_tx,
            fallback,
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
        let lane = fallback.lane();
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
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
        DecryptWorkerOutput {
            fallback_tx,
            event: DecryptWorkerEvent::FspDecryptFailure(DecryptFspFailureReport {
                fmp,
                source_addr,
                counter: header.counter,
                received_k_bit,
                lane,
                trace_enqueued_at: None,
            }),
            direct_delivery: None,
        }
    }

    fn output_for_opened_fsp_job(
        &self,
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
        let lane = fallback.lane();
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

    fn handle_fsp_job_output(&mut self, job: FspDecryptJob) -> Option<DecryptWorkerOutput> {
        let FspDecryptJob {
            fallback_tx,
            mut fallback,
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
            return Some(DecryptWorkerOutput {
                fallback_tx,
                event: DecryptWorkerEvent::Plaintext(fallback),
                direct_delivery: None,
            });
        };
        let payload_end = fsp_payload_offset.saturating_add(fsp_payload_len);
        let header = {
            let Some(payload) = fallback.packet_data.get(fsp_payload_offset..payload_end) else {
                return Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::Plaintext(fallback),
                    direct_delivery: None,
                });
            };
            let Some(header) = FspEncryptedHeader::parse(payload) else {
                return Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::Plaintext(fallback),
                    direct_delivery: None,
                });
            };
            header
        };
        let lane = fallback.lane();
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
            let ciphertext_offset = fsp_payload_offset + FSP_HEADER_SIZE;
            let Some(ciphertext) = fallback.packet_data.get_mut(ciphertext_offset..payload_end)
            else {
                return Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::Plaintext(fallback),
                    direct_delivery: None,
                });
            };
            let received_k_bit = header.flags & FSP_FLAG_K != 0;
            let open_result = {
                let _t_fsp =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
                state.open_current_established_frame_in_place(&header, ciphertext)
            };
            let FspOpenInPlaceSuccess {
                plaintext_len,
                slot,
            } = match open_result {
                Ok(success) => success,
                Err(FspOpenError::Replay) => {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::DecryptFspWorkerReplayDropped,
                    );
                    return None;
                }
                Err(FspOpenError::Aead) => {
                    return Some(DecryptWorkerOutput {
                        fallback_tx,
                        event: DecryptWorkerEvent::FspDecryptFailure(DecryptFspFailureReport {
                            fmp,
                            source_addr,
                            counter: header.counter,
                            received_k_bit,
                            lane,
                            trace_enqueued_at: None,
                        }),
                        direct_delivery: None,
                    });
                }
            };
            let source_peer = state.source_peer;
            return self.output_for_opened_fsp_job(
                source_peer,
                FspOpenedJob {
                    job: FspDecryptJob {
                        fallback_tx,
                        fallback,
                        local_node_addr,
                        source_addr,
                        previous_hop_peer,
                        path_mtu,
                        ce_flag,
                        inner_timestamp_ms,
                        fsp_payload_offset,
                        fsp_payload_len,
                        trace_enqueued_at: None,
                    },
                    header,
                    plaintext_len,
                },
                slot,
            );
        }

        let Some(payload) = fallback.packet_data.get(fsp_payload_offset..payload_end) else {
            return Some(DecryptWorkerOutput {
                fallback_tx,
                event: DecryptWorkerEvent::Plaintext(fallback),
                direct_delivery: None,
            });
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
                return None;
            }
            Err(FspOpenError::Aead) => {
                return Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::Plaintext(fallback),
                    direct_delivery: None,
                });
            }
        };
        let (timestamp, msg_type, inner_flags_byte, _body) = fsp_strip_inner_header(&plaintext)?;
        let spin_bit = inner_flags_byte & 0x01 != 0;
        let plaintext_len = plaintext.len();
        let lane = fallback.lane();
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
                    return Some(DecryptWorkerOutput {
                        fallback_tx,
                        event,
                        direct_delivery,
                    });
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

        Some(DecryptWorkerOutput {
            fallback_tx,
            event,
            direct_delivery: None,
        })
    }

    fn handle_job_action(
        &mut self,
        _idx: usize,
        job: DecryptJob,
    ) -> Result<Option<DecryptWorkerJobAction>, Box<dyn std::error::Error + Send + Sync>> {
        job.record_queue_wait();
        let DecryptJob {
            mut packet_data,
            lane: _,
            session_key,
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

        // Look up the shard-owned session state. If absent (session not
        // yet registered, or unregistered mid-flight), drop. The caller only
        // marks a session worker-owned after registration is accepted, so an
        // absent session here is stale in-flight work, not a fallback path.
        let state = match self.sessions.get_mut(&session_key) {
            Some(s) => s,
            None => {
                let _ = fallback_tx; // explicitly ignore — drop path
                let _ = packet_data;
                return Ok(None);
            }
        };
        let source_peer = state.source_peer;

        // === Phase 1: FMP decrypt ===
        let _t_fmp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);

        // **Direct &mut access** to shard-owned cipher + replay state — no
        // Arc<Mutex> lock acquire and no split-brain replay owner. Replays are
        // dropped before AEAD work; successful AEAD is the only path that
        // accepts the counter into the replay window.
        let plaintext_len = match state.open_fmp_in_place(
            &mut packet_data,
            fmp_ciphertext_offset,
            fmp_counter,
            &fmp_header,
        ) {
            Ok(outcome) => outcome.plaintext_len,
            Err(FmpOpenError::Replay) => return Ok(None),
            Err(FmpOpenError::Aead { fmp_replay_highest }) => {
                return Ok(Some(DecryptWorkerJobAction::Output(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
                        source_peer,
                        fmp_counter,
                        fmp_replay_highest,
                        trace_enqueued_at: None,
                    }),
                    direct_delivery: None,
                })));
            }
        };
        drop(_t_fmp);

        // The FMP plaintext lives in packet_data[fmp_ciphertext_offset..
        // fmp_ciphertext_offset + plaintext_len]. It carries a 4-byte
        // session-relative timestamp prefix, then the link-layer message.
        let fmp_plaintext_start = fmp_ciphertext_offset;
        let fmp_plaintext_end = fmp_ciphertext_offset + plaintext_len;
        const INNER_TIMESTAMP_LEN: usize = 4;
        if plaintext_len < INNER_TIMESTAMP_LEN {
            return Ok(None);
        }

        let inner_timestamp_ms = u32::from_le_bytes([
            packet_data[fmp_plaintext_start],
            packet_data[fmp_plaintext_start + 1],
            packet_data[fmp_plaintext_start + 2],
            packet_data[fmp_plaintext_start + 3],
        ]);
        if plaintext_len == INNER_TIMESTAMP_LEN {
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
            return Ok(Some(DecryptWorkerJobAction::Output(DecryptWorkerOutput {
                fallback_tx,
                event: DecryptWorkerEvent::AuthenticatedFmpReceive(
                    DecryptAuthenticatedFmpReceive {
                        fmp,
                        lane: DecryptWorkerLane::Priority,
                        trace_enqueued_at: None,
                    },
                ),
                direct_delivery: None,
            })));
        }

        let link_msg_start = fmp_plaintext_start + INNER_TIMESTAMP_LEN;
        let link_msg_end = fmp_plaintext_end;
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
            plaintext_len,
        );

        if let Some(meta) = fsp_meta {
            let fsp_job = FspDecryptJob {
                fallback_tx: fallback_tx.clone(),
                fallback,
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
            return Ok(Some(DecryptWorkerJobAction::FspJob(fsp_job)));
        }

        let event = DecryptWorkerEvent::Plaintext(fallback);
        Ok(Some(DecryptWorkerJobAction::Output(DecryptWorkerOutput {
            fallback_tx,
            event,
            direct_delivery: None,
        })))
    }

    #[cfg(test)]
    fn handle_job_output(
        &mut self,
        idx: usize,
        job: DecryptJob,
    ) -> Result<Option<DecryptWorkerOutput>, Box<dyn std::error::Error + Send + Sync>> {
        match self.handle_job_action(idx, job)? {
            Some(DecryptWorkerJobAction::Output(output)) => Ok(Some(output)),
            Some(DecryptWorkerJobAction::FspJob(job)) => {
                Ok(self.dispatch_or_handle_fsp_job(idx, job))
            }
            None => Ok(None),
        }
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
