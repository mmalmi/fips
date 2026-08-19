/// Start an in-place FSP recovery rekey after this many consecutive AEAD
/// decryption failures from a peer. Recovers from stale session state on
/// either side (e.g. peer restarted with new keys but our entry still holds
/// the old keys, or vice versa) without dropping the old session while the
/// new XK handshake completes.
///
/// Eight failures plus five seconds without authenticated inbound traffic is
/// long enough to reject transient reordering, but short enough to recover
/// before a roaming peer's previous-epoch drain window closes.
const DECRYPT_FAILURE_RECOVERY_THRESHOLD: u32 = 8;
const DECRYPT_FAILURE_RECOVERY_QUIET_MS: u64 = 5_000;
/// Stop spending receive-loop capacity on a session that has stayed unable to
/// authenticate traffic through several complete recovery-rekey attempts.
/// Removing only the end-to-end session lets the next valid setup establish a
/// clean epoch without discarding an otherwise healthy carrier peer.
const DECRYPT_FAILURE_EVICTION_THRESHOLD: u32 = 64;
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
    entry_can_recover: bool,
    consecutive: u32,
    authenticated_inbound_age_ms: Option<u64>,
) -> bool {
    consecutive >= DECRYPT_FAILURE_RECOVERY_THRESHOLD
        && entry_can_recover
        && authenticated_inbound_age_ms
            .is_some_and(|age_ms| age_ms >= DECRYPT_FAILURE_RECOVERY_QUIET_MS)
}

fn should_evict_decrypt_failure_session(
    consecutive: u32,
    authenticated_inbound_age_ms: Option<u64>,
) -> bool {
    consecutive >= DECRYPT_FAILURE_EVICTION_THRESHOLD
        && authenticated_inbound_age_ms
            .is_some_and(|age_ms| age_ms >= DECRYPT_FAILURE_RECOVERY_QUIET_MS)
}

fn session_can_recover_from_decrypt_failures(entry: &SessionEntry, now_ms: u64) -> bool {
    let pending_epoch_is_stalled = entry.pending_new_session().is_none()
        || now_ms.saturating_sub(entry.rekey_completed_ms()) >= DECRYPT_FAILURE_RECOVERY_QUIET_MS;
    entry.is_established() && !entry.has_rekey_in_progress() && pending_epoch_is_stalled
}

impl crate::node::SessionRegistry {
    fn should_defer_incoming_session_rekey(&self, source_addr: &NodeAddr) -> bool {
        self.get(source_addr)
            .is_some_and(|entry| entry.is_established() && entry.is_draining())
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
        now_ms: u64,
    ) -> Option<SessionEntry> {
        entry.set_pending_session(session);
        entry.set_rekey_completed_ms(now_ms);
        entry.clear_handshake_payload();
        self.insert(remote_addr, entry)
    }

    fn should_skip_session_initiation(&self, dest_addr: &NodeAddr) -> bool {
        self.get(dest_addr).is_some()
    }
}
