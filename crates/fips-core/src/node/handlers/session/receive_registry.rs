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

impl crate::node::SessionRegistry {
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
        mmp_config: &crate::config::SessionMmpConfig,
    ) -> Option<SessionEntry> {
        entry.set_state(EndToEndState::Established(session));
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
        mmp_config: &crate::config::SessionMmpConfig,
    ) -> Option<SessionEntry> {
        let mut entry = SessionEntry::new(
            remote_addr,
            remote_pubkey,
            EndToEndState::Established(session),
            now_ms,
            false,
        );
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

    fn record_receive_completion(
        &mut self,
        completion: SessionReceiveCompletion,
        now_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(&completion.source_addr) else {
            return false;
        };
        entry.touch(now_ms);
        true
    }

    fn process_session_receiver_report(
        &mut self,
        src_addr: &NodeAddr,
        rr: &ReceiverReport,
        last_outbound_next_hop: Option<NodeAddr>,
        now_ms: u64,
        now: std::time::Instant,
    ) -> Result<ProcessedSessionReceiverReport, SessionReceiverReportSkip> {
        let Some(entry) = self.get_mut(src_addr) else {
            return Err(SessionReceiverReportSkip::UnknownSession);
        };

        let our_timestamp_ms = entry.session_timestamp(now_ms);

        let Some(mmp) = entry.mmp_mut() else {
            return Err(SessionReceiverReportSkip::MmpDisabled);
        };

        mmp.metrics
            .process_receiver_report(rr, our_timestamp_ms, now);
        let loss_sample = mmp
            .metrics
            .take_forward_loss_evidence(SESSION_DIRECT_DEGRADED_MIN_SAMPLE);

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
            sample: loss_sample,
            // Missing route metadata must not make direct-path loss invisible;
            // older/fast endpoint sends may only have the peer session sample.
            used_direct_next_hop: last_outbound_next_hop
                .map_or(true, |next_hop| next_hop == *src_addr),
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
