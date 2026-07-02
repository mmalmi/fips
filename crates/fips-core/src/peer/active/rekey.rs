use super::*;

impl ActivePeer {
    // === Rekey (Key Rotation) ===

    /// When the current Noise session was established.
    pub fn session_established_at(&self) -> Instant {
        self.session_established_at
    }

    #[cfg(test)]
    pub(crate) fn set_session_established_at_for_test(&mut self, instant: Instant) {
        self.session_established_at = instant;
    }

    /// Per-session symmetric rekey-timer jitter offset (seconds).
    pub fn rekey_jitter_secs(&self) -> i64 {
        self.rekey_jitter_secs
    }

    /// Current K-bit epoch value.
    pub fn current_k_bit(&self) -> bool {
        self.current_k_bit
    }

    /// Whether a rekey is currently in progress.
    pub fn rekey_in_progress(&self) -> bool {
        self.rekey_in_progress
    }

    /// Mark that a rekey has been initiated.
    pub fn set_rekey_in_progress(&mut self) {
        self.rekey_in_progress = true;
    }

    /// Check if rekey initiation is dampened (peer recently sent us msg1).
    pub fn is_rekey_dampened(&self, dampening_secs: u64) -> bool {
        match self.last_peer_rekey {
            Some(t) => t.elapsed().as_secs() < dampening_secs,
            None => false,
        }
    }

    /// Record that the peer initiated a rekey (for dampening).
    pub fn record_peer_rekey(&mut self) {
        self.last_peer_rekey = Some(Instant::now());
    }

    /// Get the pending new session's our_index.
    pub fn pending_our_index(&self) -> Option<SessionIndex> {
        self.pending_our_index
    }

    /// Get the pending new session's their_index.
    pub fn pending_their_index(&self) -> Option<SessionIndex> {
        self.pending_their_index
    }

    /// Get the previous session's our_index (during drain).
    pub fn previous_our_index(&self) -> Option<SessionIndex> {
        self.previous_our_index
    }

    /// Get the previous session for decryption fallback.
    pub fn previous_session(&self) -> Option<&NoiseSession> {
        self.previous_session.as_ref()
    }

    /// Get mutable access to the previous session for decryption.
    pub fn previous_session_mut(&mut self) -> Option<&mut NoiseSession> {
        self.previous_session.as_mut()
    }

    /// Get the pending new session (completed rekey, not yet cut over).
    pub fn pending_new_session(&self) -> Option<&NoiseSession> {
        self.pending_new_session.as_ref()
    }

    /// Whether this node should drive the K-bit cutover for the pending FMP rekey.
    pub fn pending_rekey_initiator(&self) -> bool {
        self.pending_rekey_initiator
    }

    /// Whether the locally initiated pending FMP rekey has waited long enough
    /// to cut over. Responders cut over only after observing the peer's K-bit.
    pub fn pending_rekey_cutover_due(&self, delay: Duration) -> bool {
        self.pending_rekey_initiator
            && self
                .pending_rekey_completed_at
                .is_some_and(|completed| completed.elapsed() >= delay)
    }

    /// Store a completed rekey session and its indices.
    ///
    /// Called when the rekey handshake completes. Initiators cut over after a
    /// short grace period; responders hold the session pending until they
    /// authenticate the peer's K-bit flip.
    pub fn set_pending_session(
        &mut self,
        session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
        initiated_by_local: bool,
    ) {
        self.pending_new_session = Some(session);
        self.pending_our_index = Some(our_index);
        self.pending_their_index = Some(their_index);
        self.pending_rekey_initiator = initiated_by_local;
        self.pending_rekey_completed_at = Some(Instant::now());
        self.rekey_in_progress = false;
        // Clear initiator handshake state (index now lives in pending_our_index)
        self.rekey_our_index = None;
        self.rekey_handshake = None;
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;
        self.rekey_msg1_resend_count = 0;
    }

    /// Cut over to the pending new session (initiator side).
    ///
    /// Moves current session to previous (for drain), promotes pending to current,
    /// flips the K-bit. Returns the old our_index that should remain in dispatch
    /// during the drain window.
    pub fn cutover_to_new_session(&mut self) -> Option<SessionIndex> {
        let new_session = self.pending_new_session.take()?;
        let new_our_index = self.pending_our_index.take();
        let new_their_index = self.pending_their_index.take();

        // Demote current to previous
        self.previous_session = self.noise_session.take();
        self.previous_our_index = self.our_index;
        self.drain_started = Some(Instant::now());

        // Promote pending to current
        self.noise_session = Some(new_session);
        self.our_index = new_our_index;
        self.their_index = new_their_index;
        self.pending_rekey_initiator = false;
        self.pending_rekey_completed_at = None;

        // Flip K-bit and reset timing
        self.current_k_bit = !self.current_k_bit;
        self.session_established_at = Instant::now();
        self.session_start = Instant::now();
        self.session_generation = self.session_generation.wrapping_add(1).max(1);
        self.rekey_in_progress = false;
        self.rekey_msg1_resend_count = 0;
        self.rekey_jitter_secs = draw_rekey_jitter();
        self.last_heartbeat_sent = None;
        self.reset_replay_suppressed();

        self.previous_our_index
    }

    /// Handle receiving a K-bit flip from the peer (responder side).
    ///
    /// Promotes pending_new_session to current, demotes current to previous.
    /// Returns the old our_index for drain tracking.
    pub fn handle_peer_kbit_flip(&mut self) -> Option<SessionIndex> {
        let new_session = self.pending_new_session.take()?;
        let new_our_index = self.pending_our_index.take();
        let new_their_index = self.pending_their_index.take();

        // Demote current to previous
        self.previous_session = self.noise_session.take();
        self.previous_our_index = self.our_index;
        self.drain_started = Some(Instant::now());

        // Promote pending to current
        self.noise_session = Some(new_session);
        self.our_index = new_our_index;
        self.their_index = new_their_index;
        self.pending_rekey_initiator = false;
        self.pending_rekey_completed_at = None;

        // Match peer's K-bit
        self.current_k_bit = !self.current_k_bit;
        self.session_established_at = Instant::now();
        self.session_start = Instant::now();
        self.session_generation = self.session_generation.wrapping_add(1).max(1);
        self.rekey_in_progress = false;
        self.rekey_msg1_resend_count = 0;
        self.rekey_jitter_secs = draw_rekey_jitter();
        self.last_heartbeat_sent = None;
        self.reset_replay_suppressed();

        self.previous_our_index
    }

    /// Check if the drain window has expired.
    pub fn drain_expired(&self, drain_secs: u64) -> bool {
        match self.drain_started {
            Some(t) => t.elapsed().as_secs() >= drain_secs,
            None => false,
        }
    }

    /// Whether a drain is in progress.
    pub fn is_draining(&self) -> bool {
        self.drain_started.is_some()
    }

    /// Complete the drain: drop previous session and free its index.
    ///
    /// Returns the previous our_index so the caller can remove it from
    /// the registry and free it from the IndexAllocator.
    pub fn complete_drain(&mut self) -> Option<SessionIndex> {
        self.previous_session = None;
        self.drain_started = None;
        self.previous_our_index.take()
    }

    /// Abandon an in-progress rekey.
    ///
    /// Returns the rekey our_index so the caller can free it.
    /// Also clears any pending session state if the handshake was completed
    /// but not yet cut over.
    pub fn abandon_rekey(&mut self) -> Option<SessionIndex> {
        self.rekey_handshake = None;
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;
        self.rekey_msg1_resend_count = 0;
        self.rekey_in_progress = false;
        // Return whichever index needs freeing
        self.rekey_our_index.take().or_else(|| {
            self.pending_new_session = None;
            self.pending_their_index = None;
            self.pending_rekey_initiator = false;
            self.pending_rekey_completed_at = None;
            self.pending_our_index.take()
        })
    }

    // === Rekey Handshake State (Initiator) ===

    /// Store rekey handshake state after sending msg1.
    pub fn set_rekey_state(
        &mut self,
        handshake: NoiseHandshakeState,
        our_index: SessionIndex,
        wire_msg1: Vec<u8>,
        next_resend_ms: u64,
    ) {
        self.rekey_handshake = Some(handshake);
        self.rekey_our_index = Some(our_index);
        self.rekey_msg1 = Some(wire_msg1);
        self.rekey_msg1_next_resend = next_resend_ms;
        self.rekey_msg1_resend_count = 0;
        self.rekey_in_progress = true;
    }

    /// Get the rekey our_index (for msg2 dispatch lookup).
    pub fn rekey_our_index(&self) -> Option<SessionIndex> {
        self.rekey_our_index
    }

    /// Complete the rekey by processing msg2 (initiator side).
    ///
    /// Takes the stored handshake state, reads msg2, and returns the
    /// completed NoiseSession. Clears the handshake-related fields but
    /// leaves rekey_our_index for set_pending_session to use.
    pub fn complete_rekey_msg2(
        &mut self,
        msg2_bytes: &[u8],
    ) -> Result<(NoiseSession, Option<[u8; 8]>), NoiseError> {
        let mut hs = self
            .rekey_handshake
            .take()
            .ok_or_else(|| NoiseError::WrongState {
                expected: "rekey handshake in progress".to_string(),
                got: "no handshake state".to_string(),
            })?;

        hs.read_message_2(msg2_bytes)?;
        let remote_epoch = hs.remote_epoch();
        let session = hs.into_session()?;

        // Clear msg1 resend state
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;
        self.rekey_msg1_resend_count = 0;

        Ok((session, remote_epoch))
    }

    /// Check if msg1 needs resending.
    pub fn needs_msg1_resend(&self, now_ms: u64) -> bool {
        self.rekey_in_progress && self.rekey_msg1.is_some() && now_ms >= self.rekey_msg1_next_resend
    }

    /// Get msg1 bytes for resend (without consuming).
    pub fn rekey_msg1(&self) -> Option<&[u8]> {
        self.rekey_msg1.as_deref()
    }

    /// Update next resend timestamp.
    pub fn set_msg1_next_resend(&mut self, next_ms: u64) {
        self.rekey_msg1_next_resend = next_ms;
    }

    /// Number of rekey msg1 retransmissions performed so far.
    pub fn rekey_msg1_resend_count(&self) -> u32 {
        self.rekey_msg1_resend_count
    }

    /// Record a rekey msg1 retransmission and schedule the next one.
    pub fn record_rekey_msg1_resend(&mut self, next_ms: u64) {
        self.rekey_msg1_resend_count = self.rekey_msg1_resend_count.saturating_add(1);
        self.rekey_msg1_next_resend = next_ms;
    }
}
