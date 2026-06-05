//! End-to-end session state.
//!
//! Tracks Noise XK sessions between this node and remote endpoints.
//! Sessions are established via a three-message XK handshake
//! (SessionSetup/SessionAck/SessionMsg3) carried inside SessionDatagram
//! envelopes through the mesh.

use std::time::Instant;

use crate::NodeAddr;
use crate::config::SessionMmpConfig;
use crate::mmp::MmpSessionState;
use crate::node::REKEY_JITTER_SECS;
use crate::noise::{HandshakeState, NoiseSession};
use rand::RngExt;
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

/// Which key epoch an encrypted FSP frame authenticated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EpochSlot {
    /// The current active session.
    Current,
    /// A completed rekey session that has not yet been promoted.
    Pending,
    /// The old session retained during the drain window after cutover.
    Previous,
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
    /// Remote node's static public key.
    remote_pubkey: PublicKey,
    /// Current session state. `None` only during state transitions.
    state: Option<EndToEndState>,
    /// When the session was created (Unix milliseconds).
    #[cfg_attr(not(test), allow(dead_code))]
    created_at: u64,
    /// Last application data activity timestamp (Unix milliseconds).
    /// Only updated for DataPacket send/receive and session establishment.
    /// MMP reports do not update this field. Used for idle session timeout.
    last_activity: u64,
    /// Last authenticated FSP frame received from this peer (Unix milliseconds).
    ///
    /// Outbound-only application traffic can keep `last_activity` fresh even
    /// when the peer stopped returning valid FSP frames. This timestamp is
    /// used to retire such stale sessions so the next send re-handshakes.
    last_inbound_frame_ms: u64,
    /// When the session transitioned to Established (Unix milliseconds).
    /// Used to compute session-relative timestamps for the FSP inner header.
    /// Set to 0 until the session is established.
    session_start_ms: u64,
    /// Remaining data packets that should include COORDS_PRESENT.
    /// Initialized from config when session becomes Established;
    /// reset on CoordsRequired receipt.
    coords_warmup_remaining: u8,
    /// Whether this node initiated the Noise handshake.
    /// Used for spin bit role assignment in session-layer MMP.
    is_initiator: bool,
    /// Session-layer MMP state. Initialized on Established transition.
    mmp: Option<MmpSessionState>,

    // === Traffic Counters ===
    /// Total data packets sent on this session.
    packets_sent: u64,
    /// Total data packets received on this session.
    packets_recv: u64,
    /// Total data bytes sent on this session (FSP payload).
    bytes_sent: u64,
    /// Total data bytes received on this session (FSP payload).
    bytes_recv: u64,

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
    /// Previous NoiseSession during drain window after cutover.
    previous_noise_session: Option<NoiseSession>,
    /// When drain window started (Unix ms). 0 = no drain.
    drain_started_ms: u64,
    /// Last inbound frame time that authenticated against `previous`.
    previous_last_used_ms: u64,
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
    /// True once the peer has authenticated on the new rekey epoch.
    peer_new_epoch_confirmed: bool,
    /// Per-session symmetric jitter applied to the rekey timer trigger.
    rekey_jitter_secs: i64,

    /// Consecutive AEAD decryption failures from this peer.
    /// Reset on every successful decrypt. Drives auto re-handshake when
    /// the session keys diverge (e.g. peer restart with stale state on
    /// our side, or vice versa) — see `DECRYPT_FAILURE_REINIT_THRESHOLD`.
    consecutive_decrypt_failures: u32,
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
        Self {
            remote_addr,
            remote_pubkey,
            state: Some(state),
            created_at: now_ms,
            last_activity: now_ms,
            last_inbound_frame_ms: now_ms,
            session_start_ms: 0,
            coords_warmup_remaining: 0,
            is_initiator,
            mmp: None,
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            handshake_payload: None,
            resend_count: 0,
            next_resend_at_ms: 0,
            current_k_bit: false,
            previous_noise_session: None,
            drain_started_ms: 0,
            previous_last_used_ms: 0,
            rekey_state: None,
            pending_new_session: None,
            rekey_initiator: false,
            last_peer_rekey_ms: 0,
            rekey_completed_ms: 0,
            rekey_msg3_payload: None,
            rekey_msg3_next_resend_ms: 0,
            rekey_msg3_resend_count: 0,
            peer_new_epoch_confirmed: false,
            rekey_jitter_secs: draw_rekey_jitter(),
            consecutive_decrypt_failures: 0,
        }
    }

    /// Get the remote node's public key.
    pub(crate) fn remote_pubkey(&self) -> &PublicKey {
        &self.remote_pubkey
    }

    /// Get the current session state.
    #[allow(dead_code)] // kept for future shard-side FSP access; the legacy lazy-register
    // path that used it is gone, but the API is the right shape for the
    // upcoming FSP fast path in the decrypt worker.
    pub(crate) fn state(&self) -> &EndToEndState {
        self.state
            .as_ref()
            .expect("session state taken but not restored")
    }

    /// Get mutable access to the session state.
    pub(crate) fn state_mut(&mut self) -> &mut EndToEndState {
        self.state
            .as_mut()
            .expect("session state taken but not restored")
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

    /// Update the last application data activity timestamp.
    ///
    /// Only call for DataPacket send/receive and session establishment,
    /// not for MMP reports. Used by the idle session timeout.
    pub(crate) fn touch(&mut self, now_ms: u64) {
        self.last_activity = now_ms;
    }

    /// Mark receipt of any authenticated FSP frame from the peer.
    pub(crate) fn touch_inbound_frame(&mut self, now_ms: u64) {
        self.last_inbound_frame_ms = now_ms;
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
    #[cfg(test)]
    pub(crate) fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get last activity time.
    pub(crate) fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Get last authenticated inbound FSP frame time.
    #[cfg(test)]
    pub(crate) fn last_inbound_frame_ms(&self) -> u64 {
        self.last_inbound_frame_ms
    }

    /// True when app sends are active but the peer has stopped proving
    /// session-layer liveness by returning authenticated FSP frames.
    pub(crate) fn has_stale_outbound_only_activity(&self, now_ms: u64, timeout_ms: u64) -> bool {
        self.packets_sent > 0 && now_ms.saturating_sub(self.last_inbound_frame_ms) > timeout_ms
    }

    /// Remaining DataPackets that should include COORDS_PRESENT.
    pub(crate) fn coords_warmup_remaining(&self) -> u8 {
        self.coords_warmup_remaining
    }

    /// Set the coords warmup counter (used on Established transition
    /// and CoordsRequired reset).
    pub(crate) fn set_coords_warmup_remaining(&mut self, value: u8) {
        self.coords_warmup_remaining = value;
    }

    /// Mark the session as started (transition to Established).
    ///
    /// Records the current time as the session start for computing
    /// session-relative timestamps in the FSP inner header.
    pub(crate) fn mark_established(&mut self, now_ms: u64) {
        self.session_start_ms = now_ms;
    }

    /// Compute a session-relative timestamp for the FSP inner header.
    ///
    /// Returns `(now_ms - session_start_ms)` truncated to u32.
    /// Wraps naturally at ~49.7 days, which is fine for relative timing.
    pub(crate) fn session_timestamp(&self, now_ms: u64) -> u32 {
        now_ms.wrapping_sub(self.session_start_ms) as u32
    }

    /// Whether this node initiated the Noise handshake.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Get a reference to the session-layer MMP state, if initialized.
    pub(crate) fn mmp(&self) -> Option<&MmpSessionState> {
        self.mmp.as_ref()
    }

    /// Get a mutable reference to the session-layer MMP state, if initialized.
    pub(crate) fn mmp_mut(&mut self) -> Option<&mut MmpSessionState> {
        self.mmp.as_mut()
    }

    /// Initialize session-layer MMP state (called on Established transition).
    pub(crate) fn init_mmp(&mut self, config: &SessionMmpConfig) {
        self.mmp = Some(MmpSessionState::new(config, self.is_initiator));
    }

    // === Traffic Counters ===

    /// Record a sent data packet.
    pub(crate) fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received data packet.
    pub(crate) fn record_recv(&mut self, bytes: usize) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
    }

    /// Get traffic counters: (packets_sent, packets_recv, bytes_sent, bytes_recv).
    pub(crate) fn traffic_counters(&self) -> (u64, u64, u64, u64) {
        (
            self.packets_sent,
            self.packets_recv,
            self.bytes_sent,
            self.bytes_recv,
        )
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

    /// Get the previous session for decryption fallback during drain.
    #[cfg(test)]
    pub(crate) fn previous_noise_session_mut(&mut self) -> Option<&mut NoiseSession> {
        self.previous_noise_session.as_mut()
    }

    /// Mutable access to the current established session.
    pub(crate) fn current_noise_session_mut(&mut self) -> Option<&mut NoiseSession> {
        match self.state.as_mut() {
            Some(EndToEndState::Established(session)) => Some(session),
            _ => None,
        }
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

    /// Get the current send counter from the established NoiseSession.
    pub(crate) fn send_counter(&self) -> u64 {
        match self.state.as_ref() {
            Some(EndToEndState::Established(s)) => s.current_send_counter(),
            _ => 0,
        }
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
        self.peer_new_epoch_confirmed = false;
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

    #[cfg(test)]
    pub(crate) fn peer_new_epoch_confirmed(&self) -> bool {
        self.peer_new_epoch_confirmed
    }

    /// Mark the peer as confirmed on the new epoch and stop msg3 retransmission.
    pub(crate) fn confirm_peer_new_epoch(&mut self) {
        self.peer_new_epoch_confirmed = true;
        self.clear_rekey_msg3_payload();
    }

    /// Trial-decrypt an FSP frame against every live key epoch.
    pub(crate) fn fsp_trial_decrypt(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
        received_k_bit: bool,
        now_ms: u64,
    ) -> Option<(Vec<u8>, EpochSlot)> {
        let pending_first =
            received_k_bit != self.current_k_bit && self.pending_new_session.is_some();
        let order = if pending_first {
            [EpochSlot::Pending, EpochSlot::Current, EpochSlot::Previous]
        } else {
            [EpochSlot::Current, EpochSlot::Pending, EpochSlot::Previous]
        };

        for slot in order {
            let session = match slot {
                EpochSlot::Current => self.current_noise_session_mut(),
                EpochSlot::Pending => self.pending_new_session.as_mut(),
                EpochSlot::Previous => self.previous_noise_session.as_mut(),
            };
            if let Some(session) = session
                && let Ok(plaintext) =
                    session.decrypt_with_replay_check_and_aad(ciphertext, counter, aad)
            {
                if slot == EpochSlot::Previous {
                    self.refresh_previous_use(now_ms);
                }
                return Some((plaintext, slot));
            }
        }
        None
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

        // Demote current to previous for drain
        if let Some(EndToEndState::Established(old)) = self.state.take() {
            self.previous_noise_session = Some(old);
        }
        self.drain_started_ms = now_ms;
        self.previous_last_used_ms = 0;

        // Promote pending to current
        self.state = Some(EndToEndState::Established(new_session));
        self.current_k_bit = !self.current_k_bit;
        self.session_start_ms = now_ms;
        self.rekey_state = None;
        self.rekey_initiator = false;
        self.rekey_completed_ms = 0;
        self.rekey_jitter_secs = draw_rekey_jitter();

        // Reset MMP counters to avoid metric discontinuity
        let now = Instant::now();
        if let Some(mmp) = &mut self.mmp {
            mmp.reset_for_rekey(now);
        }
        true
    }

    /// Cut over to the pending new session (initiator side).
    pub(crate) fn cutover_to_new_session(&mut self, now_ms: u64) -> bool {
        self.promote_pending(now_ms)
    }

    /// Handle receiving a K-bit flip from the peer (responder side).
    pub(crate) fn handle_peer_kbit_flip(&mut self, now_ms: u64) -> bool {
        self.promote_pending(now_ms)
    }

    /// Check if the drain window has expired.
    pub(crate) fn drain_expired(&self, now_ms: u64, drain_ms: u64) -> bool {
        if self.drain_started_ms == 0 {
            return false;
        }
        let deadline_anchor = self.drain_started_ms.max(self.previous_last_used_ms);
        now_ms.saturating_sub(deadline_anchor) >= drain_ms
    }

    /// Whether a drain is in progress.
    pub(crate) fn is_draining(&self) -> bool {
        self.drain_started_ms > 0
    }

    /// Refresh the drain deadline after a frame authenticates against `previous`.
    pub(crate) fn refresh_previous_use(&mut self, now_ms: u64) {
        if self.drain_started_ms > 0 {
            self.previous_last_used_ms = now_ms;
        }
    }

    /// Complete the drain: drop previous session.
    pub(crate) fn complete_drain(&mut self) {
        self.previous_noise_session = None;
        self.drain_started_ms = 0;
        self.previous_last_used_ms = 0;
    }

    /// Abandon an in-progress rekey.
    pub(crate) fn abandon_rekey(&mut self) {
        self.clear_handshake_payload();
        self.rekey_state = None;
        self.pending_new_session = None;
        self.rekey_initiator = false;
        self.rekey_completed_ms = 0;
        self.clear_rekey_msg3_payload();
        self.peer_new_epoch_confirmed = false;
    }

    // === Decrypt Failure Tracking ===

    /// Record one AEAD decryption failure and return the new consecutive
    /// count. Both current-session and drain-window decrypt must have
    /// failed before calling.
    pub(crate) fn record_decrypt_failure(&mut self) -> u32 {
        self.consecutive_decrypt_failures = self.consecutive_decrypt_failures.saturating_add(1);
        self.consecutive_decrypt_failures
    }

    /// Reset the consecutive AEAD failure counter on any successful decrypt.
    pub(crate) fn reset_decrypt_failures(&mut self) {
        self.consecutive_decrypt_failures = 0;
    }

    #[cfg(test)]
    pub(crate) fn consecutive_decrypt_failures(&self) -> u32 {
        self.consecutive_decrypt_failures
    }

    #[cfg(test)]
    pub(crate) fn set_previous_session_for_test(&mut self, session: NoiseSession, now_ms: u64) {
        self.previous_noise_session = Some(session);
        self.drain_started_ms = now_ms;
    }

    #[cfg(test)]
    pub(crate) fn previous_highest_counter(&self) -> Option<u64> {
        self.previous_noise_session
            .as_ref()
            .map(|session| session.highest_received_counter())
    }

    #[cfg(test)]
    pub(crate) fn pending_highest_counter(&self) -> Option<u64> {
        self.pending_new_session
            .as_ref()
            .map(|session| session.highest_received_counter())
    }

    #[cfg(test)]
    pub(crate) fn current_highest_counter(&self) -> Option<u64> {
        match self.state.as_ref() {
            Some(EndToEndState::Established(session)) => Some(session.highest_received_counter()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod overlapping_epoch_tests {
    use super::*;
    use crate::node::session_wire::{FSP_FLAG_K, build_fsp_header};
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    fn keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let mut bytes = [1u8; 32];
        bytes[0] = seed;
        let sk = SecretKey::from_slice(&bytes).expect("valid secret key");
        Keypair::from_secret_key(&secp, &sk)
    }

    fn xk_pair(init_seed: u8, resp_seed: u8) -> (NoiseSession, NoiseSession) {
        let init_kp = keypair(init_seed);
        let resp_kp = keypair(resp_seed);
        let mut initiator = HandshakeState::new_xk_initiator(init_kp, resp_kp.public_key());
        initiator.set_local_epoch([0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44]);
        let mut responder = HandshakeState::new_xk_responder(resp_kp);
        responder.set_local_epoch([0xD4, 0xC3, 0xB2, 0xA1, 0x44, 0x33, 0x22, 0x11]);

        let msg1 = initiator.write_xk_message_1().unwrap();
        responder.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder.write_xk_message_2().unwrap();
        initiator.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator.write_xk_message_3().unwrap();
        responder.read_xk_message_3(&msg3).unwrap();

        (
            initiator.into_session().unwrap(),
            responder.into_session().unwrap(),
        )
    }

    fn seal(sender: &mut NoiseSession, plaintext: &[u8], k_bit: bool) -> (Vec<u8>, u64, [u8; 12]) {
        let counter = sender.current_send_counter();
        let flags = if k_bit { FSP_FLAG_K } else { 0 };
        let header = build_fsp_header(counter, flags, plaintext.len() as u16);
        let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
        (ciphertext, counter, header)
    }

    fn entry_with_current(session: NoiseSession) -> SessionEntry {
        let addr = NodeAddr::from_bytes([7u8; 16]);
        let pubkey = keypair(99).public_key();
        let mut entry = SessionEntry::new(
            addr,
            pubkey,
            EndToEndState::Established(session),
            1_000,
            true,
        );
        entry.mark_established(1_000);
        entry
    }

    #[test]
    fn trial_decrypt_picks_current() {
        let (mut cur_send, cur_recv) = xk_pair(1, 2);
        let (_p_send, p_recv) = xk_pair(3, 4);
        let (_o_send, o_recv) = xk_pair(5, 6);

        let mut entry = entry_with_current(cur_recv);
        entry.set_pending_session(p_recv);
        entry.set_previous_session_for_test(o_recv, 1_000);

        let (ct, counter, hdr) = seal(&mut cur_send, b"steady-state", false);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, false, 2_000)
            .expect("current frame must decrypt");

        assert_eq!(pt, b"steady-state");
        assert_eq!(slot, EpochSlot::Current);
        assert_eq!(entry.pending_highest_counter(), Some(0));
        assert_eq!(entry.previous_highest_counter(), Some(0));
    }

    #[test]
    fn trial_decrypt_picks_pending_and_promotes() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);

        let (ct, counter, hdr) = seal(&mut p_send, b"new-epoch", !k_before);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, !k_before, 2_000)
            .expect("pending frame must decrypt");
        assert_eq!(pt, b"new-epoch");
        assert_eq!(slot, EpochSlot::Pending);

        entry.handle_peer_kbit_flip(2_000);
        assert!(entry.pending_new_session().is_none());
        assert!(entry.previous_highest_counter().is_some());
        assert_ne!(entry.current_k_bit(), k_before);
    }

    #[test]
    fn trial_decrypt_picks_previous_during_drain() {
        let (mut old_send, old_recv) = xk_pair(1, 2);
        let (_new_send, new_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(new_recv);
        entry.set_previous_session_for_test(old_recv, 1_500);
        let k_after = entry.current_k_bit();

        let (ct, counter, hdr) = seal(&mut old_send, b"old-straggler", !k_after);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, !k_after, 3_000)
            .expect("previous frame must decrypt");

        assert_eq!(pt, b"old-straggler");
        assert_eq!(slot, EpochSlot::Previous);
        assert_eq!(entry.current_k_bit(), k_after);
        assert!(entry.is_draining());
    }

    #[test]
    fn trial_decrypt_reordered_old_after_cutover() {
        let (mut cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);

        let (ct_new, c_new, hdr_new) = seal(&mut p_send, b"after-cutover", !k_before);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct_new, c_new, &hdr_new, !k_before, 2_000)
            .unwrap();
        assert_eq!(slot, EpochSlot::Pending);
        entry.handle_peer_kbit_flip(2_000);

        let (ct_old, c_old, hdr_old) = seal(&mut cur_send, b"reordered-old", k_before);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct_old, c_old, &hdr_old, k_before, 2_500)
            .expect("reordered old-epoch frame must still decrypt");
        assert_eq!(pt, b"reordered-old");
        assert_eq!(slot, EpochSlot::Previous);
    }

    #[test]
    fn trial_decrypt_replay_is_per_slot() {
        let (mut cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);

        let (ct, counter, hdr) = seal(&mut cur_send, b"first", k_before);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, k_before, 2_000)
            .unwrap();
        assert_eq!(slot, EpochSlot::Current);

        assert!(
            entry
                .fsp_trial_decrypt(&ct, counter, &hdr, k_before, 2_100)
                .is_none(),
            "a genuine replay must be rejected by every slot"
        );
        assert_eq!(entry.pending_highest_counter(), Some(0));

        let (ct_p, c_p, hdr_p) = seal(&mut p_send, b"pending-c0", !k_before);
        assert_eq!(c_p, 0);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct_p, c_p, &hdr_p, !k_before, 2_200)
            .expect("pending frame must decrypt despite current replay overlap");
        assert_eq!(pt, b"pending-c0");
        assert_eq!(slot, EpochSlot::Pending);
    }

    #[test]
    fn trial_decrypt_failed_slot_leaves_replay_window_intact() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);
        let (_o_send, o_recv) = xk_pair(5, 6);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);
        entry.set_previous_session_for_test(o_recv, 1_000);

        for _ in 0..4 {
            let _ = seal(&mut p_send, b"warmup", !k_before);
        }
        let (ct, counter, hdr) = seal(&mut p_send, b"pending-hit", !k_before);
        assert_eq!(counter, 4);

        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, false, 2_000)
            .expect("pending frame must decrypt");
        assert_eq!(slot, EpochSlot::Pending);

        assert_eq!(entry.current_highest_counter(), Some(0));
        assert_eq!(entry.previous_highest_counter(), Some(0));
        assert_eq!(entry.pending_highest_counter(), Some(4));
    }

    #[test]
    fn msg3_retransmit_stops_on_peer_new_epoch_confirmed() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        entry.set_pending_session(p_recv);
        entry.set_rekey_completed_ms(1_000);
        entry.set_rekey_msg3_payload(vec![0xAB; 73], 1_500);

        assert!(entry.cutover_to_new_session(2_000));
        assert!(entry.rekey_msg3_payload().is_some());
        assert!(!entry.peer_new_epoch_confirmed());

        let k_now = entry.current_k_bit();
        let (ct, counter, hdr) = seal(&mut p_send, b"peer-on-new-epoch", k_now);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, k_now, 2_500)
            .unwrap();
        assert_eq!(slot, EpochSlot::Current);
        assert!(entry.rekey_msg3_payload().is_some() && entry.pending_new_session().is_none());
        entry.confirm_peer_new_epoch();
        assert!(entry.peer_new_epoch_confirmed());
        assert!(entry.rekey_msg3_payload().is_none());
    }

    #[test]
    fn msg3_retransmit_budget_exhaustion_abandons_cleanly() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (_p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        entry.set_pending_session(p_recv);
        entry.set_rekey_completed_ms(1_000);
        entry.set_rekey_msg3_payload(vec![0xCD; 73], 1_500);

        let max_resends = 8;
        for i in 0..max_resends {
            entry.record_rekey_msg3_resend(2_000 + i as u64 * 100);
        }
        assert_eq!(entry.rekey_msg3_resend_count(), max_resends);

        entry.abandon_rekey();
        assert!(entry.rekey_msg3_payload().is_none());
        assert!(entry.pending_new_session().is_none());
        assert!(!entry.has_rekey_in_progress());
        assert!(entry.is_established());
        assert!(!entry.peer_new_epoch_confirmed());
    }

    #[test]
    fn initiator_cutover_keeps_responder_old_epoch_decryptable() {
        let (old_a, old_b) = xk_pair(1, 2);
        let (new_a, mut new_b) = xk_pair(3, 4);

        let mut a = entry_with_current(old_a);
        a.set_rekey_completed_ms(1_000);
        a.set_rekey_msg3_payload(vec![0xEE; 73], 1_500);
        a.set_pending_session(new_a);
        assert!(a.cutover_to_new_session(2_000));
        assert!(a.rekey_msg3_payload().is_some());

        let mut b = entry_with_current(old_b);

        let (ct_new, c_new, hdr_new) = seal(&mut new_b, b"new-from-a", true);
        assert!(
            b.fsp_trial_decrypt(&ct_new, c_new, &hdr_new, true, 2_100)
                .is_none(),
            "responder without msg3 drops the new-epoch frame cleanly"
        );

        let (ct_old, c_old, hdr_old) = {
            let b_old = b.current_noise_session_mut().unwrap();
            seal(b_old, b"old-from-b", false)
        };
        let (pt, slot) = a
            .fsp_trial_decrypt(&ct_old, c_old, &hdr_old, false, 2_200)
            .expect("initiator must still decrypt the responder's old-epoch frame");
        assert_eq!(pt, b"old-from-b");
        assert_eq!(slot, EpochSlot::Previous);

        let (new_a2, mut new_b2) = xk_pair(3, 4);
        b.set_pending_session(new_a2);
        let (ct_new2, c_new2, hdr_new2) = seal(&mut new_b2, b"new-from-a-2", true);
        let (pt, slot) = b
            .fsp_trial_decrypt(&ct_new2, c_new2, &hdr_new2, true, 2_300)
            .expect("responder must decrypt new-epoch frame once pending is installed");
        assert_eq!(pt, b"new-from-a-2");
        assert_eq!(slot, EpochSlot::Pending);
    }

    #[test]
    fn drain_expiry_is_peer_progress_aware() {
        const DRAIN_MS: u64 = 10_000;
        let cutover_ms = 1_000;

        let (mut old_send, old_recv) = xk_pair(1, 2);
        let (_new_send, new_recv) = xk_pair(3, 4);
        let mut entry = entry_with_current(old_recv);
        entry.set_pending_session(new_recv);
        assert!(entry.cutover_to_new_session(cutover_ms));
        assert!(entry.is_draining());

        let k_old = !entry.current_k_bit();
        for &t in &[5_000u64, 15_000, 25_000] {
            let (ct, counter, hdr) = seal(&mut old_send, b"still-old-epoch", k_old);
            let (_pt, slot) = entry
                .fsp_trial_decrypt(&ct, counter, &hdr, k_old, t)
                .expect("old-epoch frame must still decrypt while peer uses it");
            assert_eq!(slot, EpochSlot::Previous);
            assert!(
                !entry.drain_expired(t, DRAIN_MS),
                "previous slot must not be retired while peer keeps using it"
            );
            assert!(entry.previous_highest_counter().is_some());
        }

        assert!(!entry.drain_expired(34_999, DRAIN_MS));
        assert!(entry.drain_expired(35_000, DRAIN_MS));

        entry.complete_drain();
        assert!(entry.previous_highest_counter().is_none());
        assert!(!entry.is_draining());
    }

    #[test]
    fn drain_expiry_unaffected_when_peer_off_old_epoch() {
        const DRAIN_MS: u64 = 10_000;
        let cutover_ms = 1_000;

        let (_old_send, old_recv) = xk_pair(1, 2);
        let (_new_send, new_recv) = xk_pair(3, 4);
        let mut entry = entry_with_current(old_recv);
        entry.set_pending_session(new_recv);
        assert!(entry.cutover_to_new_session(cutover_ms));

        assert!(!entry.drain_expired(cutover_ms + DRAIN_MS - 1, DRAIN_MS));
        assert!(entry.drain_expired(cutover_ms + DRAIN_MS, DRAIN_MS));
    }
}
