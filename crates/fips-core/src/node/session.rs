//! End-to-end session state.
//!
//! Tracks Noise XK sessions between this node and remote endpoints.
//! Sessions are established via a three-message XK handshake
//! (SessionSetup/SessionAck/SessionMsg3) carried inside SessionDatagram
//! envelopes through the mesh.

use crate::node::REKEY_JITTER_SECS;
use crate::noise::{HandshakeState, NoiseSession};
use crate::{NodeAddr, PeerIdentity};
use rand::RngExt;
use ring::aead::LessSafeKey;
use secp256k1::PublicKey;

fn draw_rekey_jitter() -> i64 {
    rand::rng().random_range(-REKEY_JITTER_SECS..=REKEY_JITTER_SECS)
}

/// State machine for an end-to-end session.
///
/// `Established` is intentionally larger than the handshake variants:
/// `NoiseSession` carries ring's `LessSafeKey` (×2, send + recv), each of
/// which embeds the precomputed Poly1305 key + per-implementation AEAD
/// state. That precomputation is exactly the win — it lets the per-packet
/// AEAD skip key derivation and dispatch straight to NEON / AVX. Boxing
/// the variant would add an allocation per session and double-indirection
/// on every encrypt/decrypt, working against that win.
#[allow(clippy::large_enum_variant)]
pub(crate) enum EndToEndState {
    /// We initiated: sent SessionSetup with Noise XK msg1, awaiting SessionAck.
    Initiating(HandshakeState),
    /// XK responder: processed msg1, sent msg2, awaiting msg3.
    /// Transitions to Established when msg3 arrives.
    AwaitingMsg3(HandshakeState),
    /// Handshake complete, NoiseSession available for encrypt/decrypt.
    Established(NoiseSession),
}

impl EndToEndState {
    /// Check if the session is established and ready for data.
    pub(crate) fn is_established(&self) -> bool {
        matches!(self, EndToEndState::Established(_))
    }

    /// Check if we are the initiator (waiting for ack).
    pub(crate) fn is_initiating(&self) -> bool {
        matches!(self, EndToEndState::Initiating(_))
    }

    /// Check if we are an XK responder awaiting msg3.
    pub(crate) fn is_awaiting_msg3(&self) -> bool {
        matches!(self, EndToEndState::AwaitingMsg3(_))
    }
}

/// A single end-to-end session with a remote node.
///
/// The state is wrapped in `Option` to allow taking ownership of the
/// handshake state during transitions without placeholder values.
/// The state is `None` only transiently during handler processing.
pub(crate) struct SessionEntry {
    /// Remote node's address (session table key).
    #[allow(dead_code)]
    remote_addr: NodeAddr,
    /// Remote node's authenticated identity, once the handshake has revealed it.
    remote_identity: Option<PeerIdentity>,
    /// Remote node's static public key.
    remote_pubkey: PublicKey,
    /// Current session state. `None` only during state transitions.
    state: Option<EndToEndState>,
    /// When the session was created (Unix milliseconds).
    created_at: u64,
    /// When the session transitioned to Established (Unix milliseconds).
    /// Used to compute session-relative timestamps for the FSP inner header.
    /// Set to 0 until the session is established.
    session_start_ms: u64,
    /// Whether this node initiated the Noise handshake.
    is_initiator: bool,
    // === Handshake Resend ===
    /// Encoded session-layer payload for resend (SessionSetup or SessionAck).
    /// Cleared on Established transition.
    handshake_payload: Option<Vec<u8>>,
    /// Number of resends performed.
    resend_count: u32,
    /// When the next resend should fire (Unix ms). 0 = no resend scheduled.
    next_resend_at_ms: u64,

    // === Rekey (Key Rotation) ===
    /// Current K-bit epoch value (alternates each rekey).
    current_k_bit: bool,
    /// When drain window started (Unix ms). 0 = no drain.
    drain_started_ms: u64,
    /// In-progress rekey state (runs alongside Established session).
    rekey_state: Option<HandshakeState>,
    /// Pending completed session awaiting K-bit cutover.
    pending_new_session: Option<NoiseSession>,
    /// Whether we initiated the current rekey.
    rekey_initiator: bool,
    /// Dampening: last time peer sent us a rekey msg1 (Unix ms).
    last_peer_rekey_ms: u64,
    /// When the FSP rekey handshake completed (initiator sent msg3, Unix ms).
    /// Used to defer cutover until msg3 has time to reach the responder.
    rekey_completed_ms: u64,
    /// Encoded SessionMsg3 payload retained for rekey retransmission.
    rekey_msg3_payload: Option<Vec<u8>>,
    /// Next rekey msg3 retransmission deadline (Unix ms). 0 = unscheduled.
    rekey_msg3_next_resend_ms: u64,
    /// Number of rekey msg3 retransmissions performed.
    rekey_msg3_resend_count: u32,
    /// Per-session symmetric jitter applied to the rekey timer trigger.
    rekey_jitter_secs: i64,
}

impl SessionEntry {
    /// Create a new session entry.
    pub(crate) fn new(
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        state: EndToEndState,
        now_ms: u64,
        is_initiator: bool,
    ) -> Self {
        let remote_identity = PeerIdentity::from_pubkey_full(remote_pubkey);
        let remote_identity =
            (*remote_identity.node_addr() == remote_addr).then_some(remote_identity);
        Self {
            remote_addr,
            remote_identity,
            remote_pubkey,
            state: Some(state),
            created_at: now_ms,
            session_start_ms: 0,
            is_initiator,
            handshake_payload: None,
            resend_count: 0,
            next_resend_at_ms: 0,
            current_k_bit: false,
            drain_started_ms: 0,
            rekey_state: None,
            pending_new_session: None,
            rekey_initiator: false,
            last_peer_rekey_ms: 0,
            rekey_completed_ms: 0,
            rekey_msg3_payload: None,
            rekey_msg3_next_resend_ms: 0,
            rekey_msg3_resend_count: 0,
            rekey_jitter_secs: draw_rekey_jitter(),
        }
    }

    pub(crate) fn new_established(
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        session: NoiseSession,
        now_ms: u64,
        is_initiator: bool,
    ) -> Self {
        let mut entry = Self::new(
            remote_addr,
            remote_pubkey,
            EndToEndState::Established(session),
            now_ms,
            is_initiator,
        );
        entry.mark_established(now_ms);
        entry
    }

    /// Get the remote node's public key.
    pub(crate) fn remote_pubkey(&self) -> &PublicKey {
        &self.remote_pubkey
    }

    /// Get the remote node's authenticated identity.
    pub(crate) fn remote_identity(&self) -> Option<PeerIdentity> {
        self.remote_identity
    }

    /// Replace the session state.
    pub(crate) fn set_state(&mut self, state: EndToEndState) {
        self.state = Some(state);
    }

    /// Take the state out, leaving `None`.
    ///
    /// The caller must call `set_state()` to restore a valid state,
    /// or discard the entry entirely.
    pub(crate) fn take_state(&mut self) -> Option<EndToEndState> {
        self.state.take()
    }

    /// Check if the session is established.
    pub(crate) fn is_established(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_established())
    }

    /// Check if we are the initiator (waiting for ack).
    pub(crate) fn is_initiating(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_initiating())
    }

    /// Check if we are an XK responder awaiting msg3.
    pub(crate) fn is_awaiting_msg3(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_awaiting_msg3())
    }

    /// Get creation time.
    pub(crate) fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Mark the session as started (transition to Established).
    ///
    /// Records the current time as the session start for computing
    /// session-relative timestamps in the FSP inner header.
    pub(crate) fn mark_established(&mut self, now_ms: u64) {
        self.session_start_ms = now_ms;
    }

    pub(crate) fn establish(&mut self, session: NoiseSession, now_ms: u64) {
        self.set_state(EndToEndState::Established(session));
        self.mark_established(now_ms);
    }

    /// Whether this node initiated the Noise handshake.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    // === Handshake Resend ===

    /// Store the encoded session-layer payload for potential resend.
    ///
    /// For initiators, this is the SessionSetup payload bytes while waiting
    /// for msg2, and the final SessionMsg3 payload briefly after entering
    /// Established. For responders, this is the SessionAck payload bytes.
    /// The payload is re-wrapped in a fresh SessionDatagram on each resend
    /// so routing can adapt to topology changes.
    pub(crate) fn set_handshake_payload(&mut self, payload: Vec<u8>, next_resend_at_ms: u64) {
        self.handshake_payload = Some(payload);
        self.resend_count = 0;
        self.next_resend_at_ms = next_resend_at_ms;
    }

    /// Get the stored handshake payload for resend.
    pub(crate) fn handshake_payload(&self) -> Option<&[u8]> {
        self.handshake_payload.as_deref()
    }

    /// Clear the stored handshake payload.
    pub(crate) fn clear_handshake_payload(&mut self) {
        self.handshake_payload = None;
        self.next_resend_at_ms = 0;
    }

    /// Number of resends performed so far.
    pub(crate) fn resend_count(&self) -> u32 {
        self.resend_count
    }

    /// When the next resend should fire (Unix ms). 0 = no resend scheduled.
    pub(crate) fn next_resend_at_ms(&self) -> u64 {
        self.next_resend_at_ms
    }

    /// Record a resend and schedule the next one.
    pub(crate) fn record_resend(&mut self, next_resend_at_ms: u64) {
        self.resend_count += 1;
        self.next_resend_at_ms = next_resend_at_ms;
    }

    // === Rekey (Key Rotation) ===

    /// Current K-bit epoch value.
    pub(crate) fn current_k_bit(&self) -> bool {
        self.current_k_bit
    }

    /// Whether a rekey is currently in progress.
    pub(crate) fn has_rekey_in_progress(&self) -> bool {
        self.rekey_state.is_some()
    }

    /// Get the pending new session (completed rekey, not yet cut over).
    pub(crate) fn pending_new_session(&self) -> Option<&NoiseSession> {
        self.pending_new_session.as_ref()
    }

    fn current_noise_session(&self) -> Option<&NoiseSession> {
        match self.state.as_ref() {
            Some(EndToEndState::Established(session)) => Some(session),
            _ => None,
        }
    }

    /// Snapshot the current established-FSP open/seal keys for dataplane owner state.
    pub(crate) fn fsp_crypto_keys(&self) -> Option<(LessSafeKey, LessSafeKey)> {
        let session = self.current_noise_session()?;
        Some((session.recv_cipher_clone()?, session.send_cipher_clone()?))
    }

    /// Whether we initiated the current rekey.
    pub(crate) fn is_rekey_initiator(&self) -> bool {
        self.rekey_initiator
    }

    /// Check if rekey initiation is dampened.
    pub(crate) fn is_rekey_dampened(&self, now_ms: u64, dampening_ms: u64) -> bool {
        if self.last_peer_rekey_ms == 0 {
            return false;
        }
        now_ms.saturating_sub(self.last_peer_rekey_ms) < dampening_ms
    }

    /// Record that the peer initiated a rekey (for dampening).
    pub(crate) fn record_peer_rekey(&mut self, now_ms: u64) {
        self.last_peer_rekey_ms = now_ms;
    }

    /// When the session transitioned to Established (for rekey timer).
    pub(crate) fn session_start_ms(&self) -> u64 {
        self.session_start_ms
    }

    /// Clone the established FSP send-counter authority for off-task dataplane workers.
    pub(crate) fn send_counter_authority(&self) -> Option<crate::noise::SendCounterAuthority> {
        Some(self.current_noise_session()?.send_counter_authority())
    }

    /// When the FSP rekey handshake completed (initiator sent msg3).
    pub(crate) fn rekey_completed_ms(&self) -> u64 {
        self.rekey_completed_ms
    }

    /// Per-session symmetric rekey-timer jitter offset (seconds).
    pub(crate) fn rekey_jitter_secs(&self) -> i64 {
        self.rekey_jitter_secs
    }

    /// Record when the FSP rekey handshake completed (initiator side).
    pub(crate) fn set_rekey_completed_ms(&mut self, ms: u64) {
        self.rekey_completed_ms = ms;
    }

    /// Retain the encoded rekey SessionMsg3 payload for retransmission.
    pub(crate) fn set_rekey_msg3_payload(&mut self, payload: Vec<u8>, next_resend_at_ms: u64) {
        self.rekey_msg3_payload = Some(payload);
        self.rekey_msg3_next_resend_ms = next_resend_at_ms;
        self.rekey_msg3_resend_count = 0;
    }

    /// Get the retained rekey SessionMsg3 payload.
    pub(crate) fn rekey_msg3_payload(&self) -> Option<&[u8]> {
        self.rekey_msg3_payload.as_deref()
    }

    /// When the next rekey SessionMsg3 retransmission should fire.
    pub(crate) fn rekey_msg3_next_resend_ms(&self) -> u64 {
        self.rekey_msg3_next_resend_ms
    }

    /// Number of rekey SessionMsg3 retransmissions performed.
    pub(crate) fn rekey_msg3_resend_count(&self) -> u32 {
        self.rekey_msg3_resend_count
    }

    /// Record a rekey SessionMsg3 retransmission and schedule the next one.
    pub(crate) fn record_rekey_msg3_resend(&mut self, next_resend_at_ms: u64) {
        self.rekey_msg3_resend_count += 1;
        self.rekey_msg3_next_resend_ms = next_resend_at_ms;
    }

    /// Clear the retained rekey SessionMsg3 payload.
    pub(crate) fn clear_rekey_msg3_payload(&mut self) {
        self.rekey_msg3_payload = None;
        self.rekey_msg3_next_resend_ms = 0;
        self.rekey_msg3_resend_count = 0;
    }

    /// Stop retransmitting the final rekey msg3 without discarding the
    /// completed pending epoch. The peer may already have received msg3, and
    /// destroying `pending_new_session` here can split the two FSP epochs.
    pub(crate) fn stop_rekey_msg3_retransmit(&mut self) {
        self.clear_rekey_msg3_payload();
        if self.pending_new_session.is_none() {
            self.rekey_completed_ms = 0;
        }
    }

    /// Clear control-plane retransmit payloads after dataplane has authenticated the
    /// established FSP owner epoch. dataplane owns the packet-path confirmation; the
    /// registry only drops stale handshake/rekey scaffolding.
    pub(crate) fn clear_dataplane_confirmed_fsp_retransmits(&mut self) -> bool {
        if !self.is_established() || self.current_noise_session().is_none() {
            return false;
        }

        if self.rekey_msg3_payload().is_some() && self.pending_new_session().is_none() {
            self.clear_rekey_msg3_payload();
        }
        if self.handshake_payload().is_some()
            && self.pending_new_session().is_none()
            && !self.has_rekey_in_progress()
        {
            self.clear_handshake_payload();
        }
        true
    }

    /// Store a completed rekey session.
    pub(crate) fn set_pending_session(&mut self, session: NoiseSession) {
        self.pending_new_session = Some(session);
        self.rekey_state = None;
    }

    /// Set the rekey handshake state (in-progress XK handshake).
    pub(crate) fn set_rekey_state(&mut self, state: HandshakeState, is_initiator: bool) {
        self.rekey_state = Some(state);
        self.rekey_initiator = is_initiator;
    }

    /// Take the rekey state for processing.
    pub(crate) fn take_rekey_state(&mut self) -> Option<HandshakeState> {
        self.rekey_state.take()
    }

    fn promote_pending(&mut self, now_ms: u64) -> bool {
        let new_session = match self.pending_new_session.take() {
            Some(s) => s,
            None => return false,
        };

        self.drain_started_ms = now_ms;

        // Promote pending to current
        self.state = Some(EndToEndState::Established(new_session));
        self.current_k_bit = !self.current_k_bit;
        self.session_start_ms = now_ms;
        self.rekey_state = None;
        self.rekey_initiator = false;
        self.rekey_completed_ms = 0;
        self.rekey_jitter_secs = draw_rekey_jitter();

        true
    }

    /// Cut over to the pending new session (initiator side).
    pub(crate) fn cutover_to_new_session(&mut self, now_ms: u64) -> bool {
        self.promote_pending(now_ms)
    }

    pub(crate) fn cutover_to_authenticated_pending_epoch(
        &mut self,
        now_ms: u64,
        received_k_bit: bool,
    ) -> bool {
        if self.pending_new_session.is_none()
            || self.has_rekey_in_progress()
            || received_k_bit == self.current_k_bit
        {
            return false;
        }
        let promoted = self.promote_pending(now_ms);
        if promoted {
            self.clear_rekey_msg3_payload();
        }
        promoted
    }

    /// Check if the drain window has expired.
    pub(crate) fn drain_expired(&self, now_ms: u64, drain_ms: u64) -> bool {
        if self.drain_started_ms == 0 {
            return false;
        }
        now_ms.saturating_sub(self.drain_started_ms) >= drain_ms
    }

    /// Whether a drain is in progress.
    pub(crate) fn is_draining(&self) -> bool {
        self.drain_started_ms > 0
    }

    /// Complete the stale-epoch drain window.
    pub(crate) fn complete_drain(&mut self) {
        self.drain_started_ms = 0;
    }

    /// Abandon an in-progress rekey.
    pub(crate) fn abandon_rekey(&mut self) {
        self.clear_handshake_payload();
        self.rekey_state = None;
        self.pending_new_session = None;
        self.rekey_initiator = false;
        self.rekey_completed_ms = 0;
        self.clear_rekey_msg3_payload();
    }
}
