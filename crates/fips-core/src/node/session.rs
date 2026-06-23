//! End-to-end session state.
//!
//! Tracks Noise XK sessions between this node and remote endpoints.
//! Sessions are established via a three-message XK handshake
//! (SessionSetup/SessionAck/SessionMsg3) carried inside SessionDatagram
//! envelopes through the mesh.

use std::time::Instant;

use crate::config::SessionMmpConfig;
use crate::mmp::MmpSessionState;
use crate::node::REKEY_JITTER_SECS;
#[cfg(unix)]
use crate::node::session_wire::{FSP_HEADER_SIZE, build_fsp_header};
use crate::noise::ReplayWindow;
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

/// Why an established FSP frame could not be opened by any live epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FspOpenError {
    /// Current, pending, and previous epochs all rejected the frame.
    NoLiveEpochAccepted,
}

/// Reserved FSP send state for off-task worker encryption.
#[cfg(unix)]
pub(crate) struct FspSendReservation {
    pub(crate) counter: u64,
    pub(crate) header: [u8; FSP_HEADER_SIZE],
    pub(crate) cipher: LessSafeKey,
}

/// Recv-side epoch state exported to the decrypt worker.
pub(crate) struct FspRecvEpochSnapshot {
    pub(crate) cipher: LessSafeKey,
    pub(crate) replay: ReplayWindow,
}

/// Recv-side established-FSP state exported to the decrypt worker.
///
/// The worker owns replay admission for packet auth, while the rx-loop mirrors
/// successful counters via [`FspReceiveSync`] and keeps a final canonical replay
/// guard so slow paths, rekey cutover, and observability stay coherent.
pub(crate) struct FspRecvSessionSnapshot {
    pub(crate) source_peer: PeerIdentity,
    pub(crate) current_k_bit: bool,
    pub(crate) current: FspRecvEpochSnapshot,
    pub(crate) pending: Option<FspRecvEpochSnapshot>,
    pub(crate) previous: Option<FspRecvEpochSnapshot>,
}

/// Authenticated FSP receive metadata produced by the decrypt worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FspReceiveSync {
    pub(crate) counter: u64,
    pub(crate) slot: EpochSlot,
    pub(crate) received_k_bit: bool,
    pub(crate) timestamp: u32,
    pub(crate) plaintext_len: usize,
    pub(crate) ce_flag: bool,
    pub(crate) path_mtu: u16,
    pub(crate) spin_bit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FspReceiveSyncApply {
    applied: bool,
    refresh_worker_session: bool,
}

impl FspReceiveSyncApply {
    fn applied(refresh_worker_session: bool) -> Self {
        Self {
            applied: true,
            refresh_worker_session,
        }
    }

    fn stale() -> Self {
        Self {
            applied: false,
            refresh_worker_session: false,
        }
    }

    pub(crate) fn is_applied(self) -> bool {
        self.applied
    }

    pub(crate) fn refresh_worker_session(self) -> bool {
        self.refresh_worker_session
    }
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
    /// Last received application data frame on this session (Unix milliseconds).
    ///
    /// Control/MMP frames can prove the peer and keys are alive without proving
    /// endpoint payloads are returning. Route trust for direct endpoint traffic
    /// uses this data-specific timestamp.
    last_inbound_data_frame_ms: u64,
    /// Last application data frame sent on this session (Unix milliseconds).
    ///
    /// This keeps route trust decisions tied to currently active traffic. A
    /// months-old send counter must not make an otherwise healthy quiet direct
    /// link look blackholed.
    last_outbound_frame_ms: u64,
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
    /// First-hop peer used by the most recent outbound SessionDatagram.
    last_outbound_next_hop: Option<NodeAddr>,

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
        let remote_identity = PeerIdentity::from_pubkey_full(remote_pubkey);
        let remote_identity =
            (*remote_identity.node_addr() == remote_addr).then_some(remote_identity);
        Self {
            remote_addr,
            remote_identity,
            remote_pubkey,
            state: Some(state),
            created_at: now_ms,
            last_activity: now_ms,
            last_inbound_frame_ms: now_ms,
            last_inbound_data_frame_ms: now_ms,
            last_outbound_frame_ms: 0,
            session_start_ms: 0,
            coords_warmup_remaining: 0,
            is_initiator,
            mmp: None,
            last_outbound_next_hop: None,
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

    /// Get the remote node's authenticated identity.
    pub(crate) fn remote_identity(&self) -> Option<PeerIdentity> {
        self.remote_identity
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

    /// Mark receipt of authenticated application data that arrived from the
    /// source peer's direct path.
    ///
    /// Fallback/transit data still counts toward traffic and idle activity,
    /// but it must not refresh direct-path trust for future payload routing.
    pub(crate) fn touch_inbound_data_frame(&mut self, now_ms: u64) {
        self.last_inbound_data_frame_ms = now_ms;
    }

    /// Mark transmission of application data on this session.
    pub(crate) fn touch_outbound_frame(&mut self, now_ms: u64) {
        self.last_outbound_frame_ms = now_ms;
    }

    pub(crate) fn last_authenticated_inbound_age_ms(&self, now_ms: u64) -> Option<u64> {
        (now_ms >= self.last_inbound_frame_ms).then(|| now_ms - self.last_inbound_frame_ms)
    }

    pub(crate) fn last_authenticated_inbound_data_age_ms(&self, now_ms: u64) -> Option<u64> {
        if self.packets_recv == 0 {
            return None;
        }
        (now_ms >= self.last_inbound_data_frame_ms)
            .then(|| now_ms - self.last_inbound_data_frame_ms)
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

    #[cfg(test)]
    pub(crate) fn last_inbound_data_frame_ms(&self) -> u64 {
        self.last_inbound_data_frame_ms
    }

    /// Get last outbound application data frame time.
    #[cfg(test)]
    pub(crate) fn last_outbound_frame_ms(&self) -> u64 {
        self.last_outbound_frame_ms
    }

    /// True when the session has sent data and the peer has stopped proving
    /// session-layer liveness by returning authenticated FSP frames.
    pub(crate) fn has_stale_outbound_only_activity(&self, now_ms: u64, timeout_ms: u64) -> bool {
        self.packets_sent > 0 && now_ms.saturating_sub(self.last_inbound_frame_ms) > timeout_ms
    }

    /// True when current outbound traffic is not getting authenticated return
    /// traffic within the route trust window.
    pub(crate) fn has_recent_outbound_without_inbound(&self, now_ms: u64, timeout_ms: u64) -> bool {
        let inbound_data_stale = self
            .last_authenticated_inbound_data_age_ms(now_ms)
            .is_none_or(|age_ms| age_ms > timeout_ms);
        self.packets_sent > 0
            && self.last_outbound_frame_ms != 0
            && now_ms.saturating_sub(self.last_outbound_frame_ms) <= timeout_ms
            && inbound_data_stale
    }

    pub(crate) fn has_recent_outbound_activity(&self, now_ms: u64, timeout_ms: u64) -> bool {
        self.last_outbound_frame_ms != 0
            && now_ms.saturating_sub(self.last_outbound_frame_ms) <= timeout_ms
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

    /// Remember which adjacent peer carried recent outbound session traffic.
    pub(crate) fn record_outbound_next_hop(&mut self, next_hop: NodeAddr) {
        self.last_outbound_next_hop = Some(next_hop);
    }

    /// First-hop peer used by recent outbound session traffic, if known.
    pub(crate) fn last_outbound_next_hop(&self) -> Option<NodeAddr> {
        self.last_outbound_next_hop
    }

    // === Traffic Counters ===

    /// Record a sent data packet.
    pub(crate) fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record multiple sent data packets.
    pub(crate) fn record_sent_batch(&mut self, packets: usize, bytes: usize) {
        self.packets_sent += packets as u64;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received data packet.
    pub(crate) fn record_recv(&mut self, bytes: usize) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
    }

    /// Record multiple received data packets.
    pub(crate) fn record_recv_batch(&mut self, packets: usize, bytes: usize) {
        self.packets_recv += packets as u64;
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

    fn current_noise_session(&self) -> Option<&NoiseSession> {
        match self.state.as_ref() {
            Some(EndToEndState::Established(session)) => Some(session),
            _ => None,
        }
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

    fn fsp_recv_epoch_snapshot(session: &NoiseSession) -> Option<FspRecvEpochSnapshot> {
        Some(FspRecvEpochSnapshot {
            cipher: session.recv_cipher_clone()?,
            replay: session.recv_replay_snapshot_owned(),
        })
    }

    /// Export established-FSP recv state for an owning decrypt-worker shard.
    pub(crate) fn fsp_recv_snapshot(&self) -> Option<FspRecvSessionSnapshot> {
        Some(FspRecvSessionSnapshot {
            source_peer: self.remote_identity?,
            current_k_bit: self.current_k_bit,
            current: Self::fsp_recv_epoch_snapshot(self.current_noise_session()?)?,
            pending: self
                .pending_new_session
                .as_ref()
                .and_then(Self::fsp_recv_epoch_snapshot),
            previous: self
                .previous_noise_session
                .as_ref()
                .and_then(Self::fsp_recv_epoch_snapshot),
        })
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

    /// Snapshot send-side FSP material for a short-lived endpoint bulk lease.
    ///
    /// The lease receives cloned AEAD state plus the shared counter authority;
    /// it does not receive mutable session state. Node-owned bookkeeping still
    /// returns through the endpoint feedback lane.
    #[cfg(unix)]
    pub(crate) fn endpoint_bulk_fsp_lease(&self) -> Option<crate::node::EndpointBulkSendFspLease> {
        if !self.is_established() {
            return None;
        }
        let session = self.current_noise_session()?;
        Some(crate::node::EndpointBulkSendFspLease {
            cipher: session.send_cipher_clone()?,
            counter_authority: session.send_counter_authority(),
            session_start_ms: self.session_start_ms,
            current_k_bit: self.current_k_bit,
            spin_bit: self.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()),
        })
    }

    /// Reserve FSP send state for worker-side encryption.
    ///
    /// The session entry owns the send counter sequence. Worker paths receive a
    /// clone of the AEAD key plus the already-reserved counter/header pair, so
    /// worker encryption cannot advance or rebuild session-owned sequencing.
    #[cfg(unix)]
    pub(crate) fn reserve_fsp_worker_send(
        &mut self,
        flags: u8,
        payload_len: u16,
    ) -> Result<Option<FspSendReservation>, crate::noise::NoiseError> {
        let Some(session) = self.current_noise_session_mut() else {
            return Ok(None);
        };
        let Some(cipher) = session.send_cipher_clone() else {
            return Ok(None);
        };
        let counter = session.take_send_counter()?;
        let header = build_fsp_header(counter, flags, payload_len);
        Ok(Some(FspSendReservation {
            counter,
            header,
            cipher,
        }))
    }

    /// Reserve a contiguous batch of FSP send counters for worker-side
    /// encryption under one mutable borrow of the session-owned send state.
    #[cfg(unix)]
    pub(crate) fn reserve_fsp_worker_send_batch<I>(
        &mut self,
        inputs: I,
    ) -> Result<Option<Vec<FspSendReservation>>, crate::noise::NoiseError>
    where
        I: IntoIterator<Item = (u8, u16)>,
    {
        let Some(session) = self.current_noise_session_mut() else {
            return Ok(None);
        };
        let Some(cipher) = session.send_cipher_clone() else {
            return Ok(None);
        };
        let counter_authority = session.send_counter_authority();

        let inputs = inputs.into_iter().collect::<Vec<_>>();
        let counters = counter_authority.reserve_range(inputs.len())?;
        let mut reservations = Vec::with_capacity(inputs.len());
        for ((flags, payload_len), counter) in inputs.into_iter().zip(counters) {
            let header = build_fsp_header(counter, flags, payload_len);
            reservations.push(FspSendReservation {
                counter,
                header,
                cipher: cipher.clone(),
            });
        }

        Ok(Some(reservations))
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

    /// Open an established FSP frame against every live key epoch.
    ///
    /// This is the receive-side ownership boundary for FSP replay acceptance:
    /// each epoch checks, decrypts, and accepts its own replay state. Failed
    /// candidates leave their replay windows untouched; only the epoch that
    /// authenticates the frame is returned to the session handler.
    pub(crate) fn open_fsp_established_frame(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
        received_k_bit: bool,
        now_ms: u64,
    ) -> Result<(Vec<u8>, EpochSlot), FspOpenError> {
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
                return Ok((plaintext, slot));
            }
        }
        Err(FspOpenError::NoLiveEpochAccepted)
    }

    /// Mirror a frame authenticated by the decrypt worker into rx-loop-owned
    /// session metadata.
    ///
    /// The worker already performed AEAD verification and replay admission
    /// against its owned snapshot. This method keeps the canonical
    /// `SessionEntry` coherent and performs the final rx-loop replay guard:
    /// replay windows are advanced for slow paths, pending epochs are
    /// promoted, MMP receive state is updated, and idle counters observe
    /// application data.
    pub(crate) fn apply_fsp_receive_sync_result(
        &mut self,
        sync: FspReceiveSync,
        now_ms: u64,
        now: Instant,
    ) -> FspReceiveSyncApply {
        if !self.is_established() {
            return FspReceiveSyncApply::stale();
        }

        let mut refresh_worker_session = false;
        match sync.slot {
            EpochSlot::Current => {
                let Some(session) = self.current_noise_session_mut() else {
                    return FspReceiveSyncApply::stale();
                };
                if session.check_replay(sync.counter).is_err() {
                    return FspReceiveSyncApply::stale();
                }
                session.accept_replay(sync.counter);
                if self.rekey_msg3_payload().is_some() && self.pending_new_session().is_none() {
                    self.confirm_peer_new_epoch();
                }
            }
            EpochSlot::Pending => {
                if let Some(session) = self.pending_new_session.as_mut() {
                    if session.check_replay(sync.counter).is_err() {
                        return FspReceiveSyncApply::stale();
                    }
                    session.accept_replay(sync.counter);
                    if self.rekey_msg3_payload().is_some() {
                        self.confirm_peer_new_epoch();
                    }
                    self.handle_peer_kbit_flip(now_ms);
                    refresh_worker_session = true;
                } else if sync.received_k_bit == self.current_k_bit {
                    // A second pending-epoch event can reach rx_loop after an
                    // earlier event already promoted the pending session. The
                    // worker authenticated it before promotion; mirror it into
                    // the now-current slot instead of dropping good data.
                    let Some(session) = self.current_noise_session_mut() else {
                        return FspReceiveSyncApply::stale();
                    };
                    if session.check_replay(sync.counter).is_err() {
                        return FspReceiveSyncApply::stale();
                    }
                    session.accept_replay(sync.counter);
                } else {
                    return FspReceiveSyncApply::stale();
                }
            }
            EpochSlot::Previous => {
                let Some(session) = self.previous_noise_session.as_mut() else {
                    return FspReceiveSyncApply::stale();
                };
                if session.check_replay(sync.counter).is_err() {
                    return FspReceiveSyncApply::stale();
                }
                session.accept_replay(sync.counter);
                self.refresh_previous_use(now_ms);
            }
        }

        self.reset_decrypt_failures();
        if self.handshake_payload().is_some()
            && self.pending_new_session().is_none()
            && !self.has_rekey_in_progress()
            && sync.slot == EpochSlot::Current
            && sync.received_k_bit == self.current_k_bit()
        {
            self.clear_handshake_payload();
        }

        if let Some(mmp) = self.mmp_mut() {
            mmp.receiver.record_recv(
                sync.counter,
                sync.timestamp,
                sync.plaintext_len,
                sync.ce_flag,
                now,
            );
            let _spin_rtt = mmp.spin_bit.rx_observe(sync.spin_bit, sync.counter, now);
            mmp.path_mtu.observe_incoming_mtu(sync.path_mtu);
        }
        self.touch_inbound_frame(now_ms);
        FspReceiveSyncApply::applied(refresh_worker_session)
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
mod overlapping_epoch_tests;
