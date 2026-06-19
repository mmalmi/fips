/// Start an in-place FSP recovery rekey after this many consecutive AEAD
/// decryption failures from a peer. Recovers from stale session state on
/// either side (e.g. peer restarted with new keys but our entry still holds
/// the old keys, or vice versa) without dropping the old session while the
/// new XK handshake completes.
const DECRYPT_FAILURE_RECOVERY_THRESHOLD: u32 = 32;
const DECRYPT_FAILURE_RECOVERY_QUIET_MS: u64 = 15_000;
fn pending_rekey_wins_tiebreak(
    our_addr: &NodeAddr,
    peer_addr: &NodeAddr,
    existing: &SessionEntry,
) -> bool {
    existing.pending_new_session().is_some()
        && existing.is_rekey_initiator()
        && our_addr < peer_addr
}

fn duplicate_rekey_responder_ack(existing: &SessionEntry) -> Option<Vec<u8>> {
    if existing.is_established()
        && existing.has_rekey_in_progress()
        && !existing.is_rekey_initiator()
    {
        return existing.handshake_payload().map(<[u8]>::to_vec);
    }
    None
}

fn should_start_decrypt_failure_rekey(
    entry: &SessionEntry,
    consecutive: u32,
    now_ms: u64,
) -> bool {
    consecutive >= DECRYPT_FAILURE_RECOVERY_THRESHOLD
        && entry.is_established()
        && !entry.has_rekey_in_progress()
        && entry.pending_new_session().is_none()
        && entry
            .last_authenticated_inbound_age_ms(now_ms)
            .is_some_and(|age_ms| age_ms >= DECRYPT_FAILURE_RECOVERY_QUIET_MS)
}

fn should_ignore_stale_epoch_drain_failure(entry: &SessionEntry, received_k_bit: bool) -> bool {
    entry.is_draining()
        && entry.pending_new_session().is_none()
        && received_k_bit != entry.current_k_bit()
}

/// Receive-side owner for one established FSP frame.
///
/// This is still called from the rx loop today, but it is the movable boundary
/// for the future peer/session runtime: FSP open/replay, K-bit cutover,
/// decrypt-failure accounting, MMP receive bookkeeping, and dispatch metadata
/// now live behind one owner instead of an inline `Node` block.
struct SessionRuntimeReceive<'a> {
    entry: &'a mut SessionEntry,
    ciphertext: &'a [u8],
    counter: u64,
    aad: &'a [u8],
    received_k_bit: bool,
    path_mtu: u16,
    ce_flag: bool,
    now_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct EstablishedFspReceive<'a> {
    header: &'a FspEncryptedHeader,
    ciphertext: &'a [u8],
    path_mtu: u16,
    ce_flag: bool,
    now_ms: u64,
}

impl<'a> EstablishedFspReceive<'a> {
    fn new(
        header: &'a FspEncryptedHeader,
        ciphertext: &'a [u8],
        path_mtu: u16,
        ce_flag: bool,
        now_ms: u64,
    ) -> Self {
        Self {
            header,
            ciphertext,
            path_mtu,
            ce_flag,
            now_ms,
        }
    }
}

#[derive(Debug)]
enum EstablishedFspWireError {
    BadHeader,
    BadCoords(crate::protocol::ProtocolError),
}

#[derive(Debug, Default)]
struct EstablishedFspCoordWarmup {
    source: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
    local: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
}

impl EstablishedFspCoordWarmup {
    fn from_parsed(
        source_addr: NodeAddr,
        local_addr: NodeAddr,
        source_coords: Option<crate::tree::TreeCoordinate>,
        local_coords: Option<crate::tree::TreeCoordinate>,
    ) -> Self {
        Self {
            source: source_coords.map(|coords| (source_addr, coords)),
            local: local_coords.map(|coords| (local_addr, coords)),
        }
    }

    fn is_empty(&self) -> bool {
        self.source.is_none() && self.local.is_none()
    }

    fn apply(self, coord_cache: &mut crate::cache::CoordCache, now_ms: u64) {
        if let Some((addr, coords)) = self.source {
            coord_cache.insert(addr, coords, now_ms);
        }
        if let Some((addr, coords)) = self.local {
            coord_cache.insert(addr, coords, now_ms);
        }
    }
}

#[derive(Debug)]
struct EstablishedFspWire<'a> {
    header: FspEncryptedHeader,
    ciphertext: &'a [u8],
    coord_warmup: EstablishedFspCoordWarmup,
}

impl<'a> EstablishedFspWire<'a> {
    fn parse(
        payload: &'a [u8],
        source_addr: NodeAddr,
        local_addr: NodeAddr,
    ) -> Result<Self, EstablishedFspWireError> {
        let header =
            FspEncryptedHeader::parse(payload).ok_or(EstablishedFspWireError::BadHeader)?;
        let mut ciphertext_offset = FSP_HEADER_SIZE;
        let mut coord_warmup = EstablishedFspCoordWarmup::default();

        if header.has_coords() {
            let (source_coords, local_coords, bytes_consumed) =
                parse_encrypted_coords(&payload[FSP_HEADER_SIZE..])
                    .map_err(EstablishedFspWireError::BadCoords)?;
            coord_warmup = EstablishedFspCoordWarmup::from_parsed(
                source_addr,
                local_addr,
                source_coords,
                local_coords,
            );
            ciphertext_offset += bytes_consumed;
        }

        Ok(Self {
            header,
            ciphertext: &payload[ciphertext_offset..],
            coord_warmup,
        })
    }

    fn has_coord_warmup(&self) -> bool {
        !self.coord_warmup.is_empty()
    }

    fn apply_coord_warmup(&mut self, coord_cache: &mut crate::cache::CoordCache, now_ms: u64) {
        std::mem::take(&mut self.coord_warmup).apply(coord_cache, now_ms);
    }

    fn receive(&self, path_mtu: u16, ce_flag: bool, now_ms: u64) -> EstablishedFspReceive<'_> {
        EstablishedFspReceive::new(&self.header, self.ciphertext, path_mtu, ce_flag, now_ms)
    }
}

#[derive(Debug)]
enum EarlyEncryptedHandshakeResend {
    NoPayload,
    BudgetExhausted,
    Resend { payload: Vec<u8> },
}

impl<'a> SessionRuntimeReceive<'a> {
    fn new(
        entry: &'a mut SessionEntry,
        header: &'a FspEncryptedHeader,
        ciphertext: &'a [u8],
        path_mtu: u16,
        ce_flag: bool,
        now_ms: u64,
    ) -> Self {
        Self {
            entry,
            ciphertext,
            counter: header.counter,
            aad: &header.header_bytes,
            received_k_bit: header.flags & FSP_FLAG_K != 0,
            path_mtu,
            ce_flag,
            now_ms,
        }
    }

    fn open_established(self) -> FspFrameOutcome {
        if !self.entry.is_established() {
            return FspFrameOutcome::NotEstablished;
        }

        let (plaintext, slot) = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
            match self.entry.open_fsp_established_frame(
                self.ciphertext,
                self.counter,
                self.aad,
                self.received_k_bit,
                self.now_ms,
            ) {
                Ok(result) => result,
                Err(FspOpenError::NoLiveEpochAccepted) => {
                    if should_ignore_stale_epoch_drain_failure(self.entry, self.received_k_bit) {
                        return FspFrameOutcome::StaleEpochDrainFailure {
                            counter: self.counter,
                        };
                    }
                    let consecutive = self.entry.record_decrypt_failure();
                    let recover_session =
                        should_start_decrypt_failure_rekey(self.entry, consecutive, self.now_ms);
                    return FspFrameOutcome::DecryptFailed {
                        error: crate::noise::NoiseError::DecryptionFailed,
                        counter: self.counter,
                        consecutive,
                        recover_session,
                    };
                }
            }
        };

        match slot {
            EpochSlot::Pending => {
                // A frame that authenticates against pending proves the peer
                // reached the new epoch; promote pending to current.
                if self.entry.rekey_msg3_payload().is_some() {
                    self.entry.confirm_peer_new_epoch();
                }
                self.entry.handle_peer_kbit_flip(self.now_ms);
            }
            EpochSlot::Current => {
                // If the initiator already cut over on its timer, a
                // current-epoch frame confirms the responder received msg3.
                if self.entry.rekey_msg3_payload().is_some()
                    && self.entry.pending_new_session().is_none()
                {
                    self.entry.confirm_peer_new_epoch();
                }
            }
            EpochSlot::Previous => {}
        }

        // Successful decrypt resets failure accounting so one bad packet does
        // not carry forward toward recovery rekey.
        self.entry.reset_decrypt_failures();
        if self.entry.handshake_payload().is_some()
            && self.entry.pending_new_session().is_none()
            && !self.entry.has_rekey_in_progress()
            && slot == EpochSlot::Current
            && self.received_k_bit == self.entry.current_k_bit()
        {
            self.entry.clear_handshake_payload();
        }

        let (timestamp, msg_type, inner_flags_byte) = match fsp_strip_inner_header(&plaintext) {
            Some((ts, mt, inf, _rest)) => (ts, mt, inf),
            None => return FspFrameOutcome::BadInnerHeader,
        };

        if let Some(mmp) = self.entry.mmp_mut() {
            let now = std::time::Instant::now();
            mmp.receiver
                .record_recv(self.counter, timestamp, plaintext.len(), self.ce_flag, now);
            let inner_flags = FspInnerFlags::from_byte(inner_flags_byte);
            let _spin_rtt = mmp
                .spin_bit
                .rx_observe(inner_flags.spin_bit, self.counter, now);
            mmp.path_mtu.observe_incoming_mtu(self.path_mtu);
        }
        self.entry.touch_inbound_frame(self.now_ms);

        let Some(source_peer) = self.entry.remote_identity() else {
            return FspFrameOutcome::MissingRemoteIdentity;
        };

        FspFrameOutcome::Authentic(AuthenticatedSessionMessage::new(
            source_peer,
            plaintext,
            msg_type,
            inner_flags_byte,
            timestamp,
        ))
    }
}

impl crate::node::SessionRegistry {
    fn prepare_handshake_resend_after_early_encrypted_data(
        &mut self,
        source_addr: &NodeAddr,
        max_resends: u32,
    ) -> EarlyEncryptedHandshakeResend {
        let Some(entry) = self.get_mut(source_addr) else {
            return EarlyEncryptedHandshakeResend::NoPayload;
        };
        if entry.handshake_payload().is_none() {
            return EarlyEncryptedHandshakeResend::NoPayload;
        }
        if entry.resend_count() >= max_resends {
            entry.clear_handshake_payload();
            return EarlyEncryptedHandshakeResend::BudgetExhausted;
        }

        EarlyEncryptedHandshakeResend::Resend {
            payload: entry
                .handshake_payload()
                .expect("checked handshake payload above")
                .to_vec(),
        }
    }

    fn record_handshake_resend(&mut self, source_addr: &NodeAddr, next_resend_at_ms: u64) -> bool {
        let Some(entry) = self.get_mut(source_addr) else {
            return false;
        };
        entry.record_resend(next_resend_at_ms);
        true
    }

    fn abandon_rekey(&mut self, source_addr: &NodeAddr) -> bool {
        let Some(entry) = self.get_mut(source_addr) else {
            return false;
        };
        entry.abandon_rekey();
        true
    }

    fn install_initiating_session(
        &mut self,
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        handshake: HandshakeState,
        setup_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> Option<SessionEntry> {
        let mut entry = SessionEntry::new(
            remote_addr,
            remote_pubkey,
            EndToEndState::Initiating(handshake),
            now_ms,
            true,
        );
        entry.set_handshake_payload(setup_payload, now_ms + resend_interval_ms);
        self.insert(remote_addr, entry)
    }

    fn install_awaiting_msg3_session(
        &mut self,
        remote_addr: NodeAddr,
        placeholder_pubkey: PublicKey,
        handshake: HandshakeState,
        ack_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> Option<SessionEntry> {
        let mut entry = SessionEntry::new(
            remote_addr,
            placeholder_pubkey,
            EndToEndState::AwaitingMsg3(handshake),
            now_ms,
            false,
        );
        entry.set_handshake_payload(ack_payload, now_ms + resend_interval_ms);
        self.insert(remote_addr, entry)
    }

    #[allow(clippy::too_many_arguments)]
    fn install_established_initiator_session(
        &mut self,
        remote_addr: NodeAddr,
        mut entry: SessionEntry,
        session: NoiseSession,
        msg3_resend_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
        coords_warmup_packets: u8,
        mmp_config: &crate::config::SessionMmpConfig,
    ) -> Option<SessionEntry> {
        entry.set_state(EndToEndState::Established(session));
        entry.set_coords_warmup_remaining(coords_warmup_packets);
        entry.mark_established(now_ms);
        entry.init_mmp(mmp_config);
        entry.set_handshake_payload(msg3_resend_payload, now_ms + resend_interval_ms);
        entry.touch(now_ms);
        self.insert(remote_addr, entry)
    }

    fn install_established_responder_session(
        &mut self,
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        session: NoiseSession,
        now_ms: u64,
        coords_warmup_packets: u8,
        mmp_config: &crate::config::SessionMmpConfig,
    ) -> Option<SessionEntry> {
        let mut entry = SessionEntry::new(
            remote_addr,
            remote_pubkey,
            EndToEndState::Established(session),
            now_ms,
            false,
        );
        entry.set_coords_warmup_remaining(coords_warmup_packets);
        entry.mark_established(now_ms);
        entry.init_mmp(mmp_config);
        entry.touch(now_ms);
        self.insert(remote_addr, entry)
    }

    fn install_rekey_responder_awaiting_msg3(
        &mut self,
        remote_addr: &NodeAddr,
        handshake: HandshakeState,
        ack_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(remote_addr) else {
            return false;
        };
        entry.set_rekey_state(handshake, false);
        entry.set_handshake_payload(ack_payload, now_ms + resend_interval_ms);
        entry.record_peer_rekey(now_ms);
        true
    }

    fn install_rekey_initiator_pending_session(
        &mut self,
        remote_addr: NodeAddr,
        mut entry: SessionEntry,
        session: NoiseSession,
        msg3_resend_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> Option<SessionEntry> {
        entry.set_pending_session(session);
        entry.set_rekey_completed_ms(now_ms);
        entry.clear_handshake_payload();
        entry.set_rekey_msg3_payload(msg3_resend_payload, now_ms + resend_interval_ms);
        self.insert(remote_addr, entry)
    }

    fn install_rekey_responder_pending_session(
        &mut self,
        remote_addr: NodeAddr,
        mut entry: SessionEntry,
        session: NoiseSession,
    ) -> Option<SessionEntry> {
        entry.set_pending_session(session);
        entry.clear_handshake_payload();
        self.insert(remote_addr, entry)
    }

    fn open_established_fsp_frame(
        &mut self,
        source_addr: &NodeAddr,
        receive: EstablishedFspReceive<'_>,
    ) -> FspFrameOutcome {
        let Some(entry) = self.get_mut(source_addr) else {
            return FspFrameOutcome::UnknownSession;
        };

        SessionRuntimeReceive::new(
            entry,
            receive.header,
            receive.ciphertext,
            receive.path_mtu,
            receive.ce_flag,
            receive.now_ms,
        )
        .open_established()
    }

    fn record_receive_completion(
        &mut self,
        completion: SessionReceiveCompletion,
        now_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(&completion.source_addr) else {
            return false;
        };
        entry.record_recv(completion.body_len);
        entry.touch(now_ms);
        true
    }

    fn process_session_receiver_report(
        &mut self,
        src_addr: &NodeAddr,
        rr: &ReceiverReport,
        now_ms: u64,
        now: std::time::Instant,
    ) -> Result<ProcessedSessionReceiverReport, SessionReceiverReportSkip> {
        let Some(entry) = self.get_mut(src_addr) else {
            return Err(SessionReceiverReportSkip::UnknownSession);
        };

        let our_timestamp_ms = entry.session_timestamp(now_ms);
        let last_outbound_next_hop = entry.last_outbound_next_hop();

        let Some(mmp) = entry.mmp_mut() else {
            return Err(SessionReceiverReportSkip::MmpDisabled);
        };

        mmp.metrics
            .process_receiver_report(rr, our_timestamp_ms, now);

        let srtt_ms = mmp.metrics.srtt_ms();
        if let Some(srtt_ms) = srtt_ms {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.receiver.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.path_mtu.update_interval_from_srtt(srtt_ms);
        }

        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

        Ok(ProcessedSessionReceiverReport {
            sample: mmp.metrics.last_forward_loss_sample(),
            used_direct_next_hop: last_outbound_next_hop == Some(*src_addr),
            srtt_ms,
            route_quality_sample: session_receiver_report_can_drive_route_quality(
                mmp.mode(),
                srtt_ms,
            ),
        })
    }

    fn apply_session_path_mtu_signal(
        &mut self,
        dest_addr: &NodeAddr,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<SessionPathMtuApplyResult, SessionPathMtuApplySkip> {
        let Some(entry) = self.get_mut(dest_addr) else {
            return Err(SessionPathMtuApplySkip::UnknownSession);
        };
        let Some(mmp) = entry.mmp_mut() else {
            return Err(SessionPathMtuApplySkip::MmpDisabled);
        };

        let old_mtu = mmp.path_mtu.current_mtu();
        if !mmp.path_mtu.apply_notification(path_mtu, now) {
            return Ok(SessionPathMtuApplyResult::Unchanged);
        }

        Ok(SessionPathMtuApplyResult::Changed(SessionPathMtuChange {
            old_mtu,
            new_mtu: mmp.path_mtu.current_mtu(),
        }))
    }

    fn route_error_can_send_coords_warmup(&self, dest_addr: &NodeAddr) -> bool {
        self.get(dest_addr)
            .is_some_and(|entry| entry.is_established())
    }

    fn reset_route_error_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
        warmup_packets: u8,
    ) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        entry.set_coords_warmup_remaining(warmup_packets);
        true
    }

    fn session_fsp_send_context(
        &self,
        dest_addr: &NodeAddr,
        now_ms: u64,
    ) -> Result<SessionFspSendContext, SessionFspSendContextError> {
        let Some(entry) = self.get(dest_addr) else {
            return Err(SessionFspSendContextError::NoSession);
        };
        if !entry.is_established() {
            return Err(SessionFspSendContextError::NotEstablished);
        }

        Ok(SessionFspSendContext {
            timestamp: entry.session_timestamp(now_ms),
            spin_bit: entry.mmp().is_some_and(|m| m.spin_bit.tx_bit()),
            current_k_bit: entry.current_k_bit(),
            coords_warmup_remaining: entry.coords_warmup_remaining(),
        })
    }

    fn consume_coords_warmup_packet(&mut self, dest_addr: &NodeAddr) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        let remaining = entry.coords_warmup_remaining();
        if remaining == 0 {
            return false;
        }
        entry.set_coords_warmup_remaining(remaining - 1);
        true
    }

    fn seal_session_fsp_send(
        &mut self,
        plan: SessionFspSendPlan<'_>,
    ) -> Result<SealedSessionFspSend, NodeError> {
        let dest_addr = plan.dest_addr();
        let Some(entry) = self.get_mut(&dest_addr) else {
            return Err(SessionFspSendContextError::NoSession.into_node_error(dest_addr));
        };
        let session = match entry.state_mut() {
            EndToEndState::Established(session) => session,
            _ => {
                return Err(SessionFspSendContextError::NotEstablished.into_node_error(dest_addr));
            }
        };
        plan.seal(session)
    }

    fn seed_session_datagram_path_mtu(&mut self, dest_addr: &NodeAddr, path_mtu: u16) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        let Some(mmp) = entry.mmp_mut() else {
            return false;
        };
        mmp.path_mtu.seed_source_mtu(path_mtu);
        true
    }

    fn record_session_datagram_next_hop(
        &mut self,
        dest_addr: &NodeAddr,
        next_hop_addr: NodeAddr,
    ) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        entry.record_outbound_next_hop(next_hop_addr);
        true
    }

    fn should_skip_session_initiation(&self, dest_addr: &NodeAddr) -> bool {
        self.get(dest_addr)
            .is_some_and(|entry| entry.is_established() || entry.is_initiating())
    }

    fn outbound_session_state(&self, dest_addr: &NodeAddr) -> OutboundSessionState {
        let Some(entry) = self.get(dest_addr) else {
            return OutboundSessionState::Missing;
        };
        if entry.is_established() {
            OutboundSessionState::Established
        } else {
            OutboundSessionState::Pending
        }
    }

    fn tun_outbound_session_decision(
        &self,
        dest_addr: &NodeAddr,
        effective_mtu: usize,
        packet_len: usize,
    ) -> TunOutboundSessionDecision {
        let Some(entry) = self.get(dest_addr) else {
            return TunOutboundSessionDecision::Missing;
        };
        if !entry.is_established() {
            return TunOutboundSessionDecision::Pending;
        }

        if let Some(mmp) = entry.mmp() {
            let path_mtu = mmp.path_mtu.current_mtu();
            let path_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as usize;
            if path_ipv6_mtu < effective_mtu && packet_len > path_ipv6_mtu {
                return TunOutboundSessionDecision::EstablishedPathMtuExceeded {
                    path_ipv6_mtu: path_ipv6_mtu as u32,
                };
            }
        }

        TunOutboundSessionDecision::Established
    }

    fn prepare_retry_session_after_discovery(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> DiscoveryRetrySessionDecision {
        let Some(existing) = self.get(dest_addr) else {
            return DiscoveryRetrySessionDecision::Missing;
        };
        if existing.is_established() {
            return DiscoveryRetrySessionDecision::Established;
        }

        self.remove(dest_addr);
        DiscoveryRetrySessionDecision::RestartedPending
    }
}
