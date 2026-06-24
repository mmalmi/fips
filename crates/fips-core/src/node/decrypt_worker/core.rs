use crate::FipsAddress;
use crate::NodeAddr;
use crate::PeerIdentity;
use crate::node::handlers::session::AuthenticatedSessionMessage;
use crate::node::handlers::session::mark_ipv6_ecn_ce;
use crate::node::session::{EpochSlot, FspReceiveSync, FspRecvSessionSnapshot};
use crate::node::session_wire::{
    FSP_FLAG_K, FSP_HEADER_SIZE, FSP_PHASE_ESTABLISHED, FSP_PORT_HEADER_SIZE, FSP_PORT_IPV6_SHIM,
    FspCommonPrefix, FspEncryptedHeader, fsp_strip_inner_header,
};
use crate::node::{
    EndpointDataDelivery, EndpointEventSender, NodeDeliveredPacket, NodeEndpointEvent,
};
use crate::packet_mover::{
    CryptoCompletion, CryptoDispatch, CryptoReject, CryptoResult, CryptoTicket, CryptoWork,
    DispatchBatcher, LaneCreditGate, OrderSequence, OrderToken, OwnerCompletionBatch,
    OwnerGeneration, OwnerKey, OwnerOrderedCompletion, OwnerReservation, OutputTarget, PacketLane,
    PacketOutputTarget, StatelessCryptoWorker,
};
use crate::protocol::{LinkMessageType, SessionDatagramRef, SessionMessageType};
use crate::transport::{PacketBuffer, TransportAddr, TransportId};
use crate::upper::tun::TunTx;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::{
    Receiver as TokioReceiver, Sender as TokioSender, error::TrySendError as TokioTrySendError,
};
use tracing::{debug, trace, warn};

// `endpoint_event_tx` used to ride on every `DecryptJob`, bloating the hot
// packet shape with an extra Arc clone and accidentally gating TUN-only worker
// use. Keep it pool-owned instead: workers may deliver direct-hop endpoint data
// after the direct-session commit is accepted by the rx-loop bookkeeping lane.

use crate::noise::ReplayWindow;

const DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_WORKER_CONTROL_CHANNEL_CAP: usize = 1024;
const DEFAULT_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP: usize = 1024;
const DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP: usize = 1024;
/// Emit the backlog-high event before already-decrypted bulk completions can
/// crowd out priority/control work. The receive loop no longer expands its
/// drain budget under pressure, so this is an observability threshold, not a
/// trigger for a second packet path.
pub(crate) const DECRYPT_FALLBACK_BACKLOG_HIGH_WATER: usize = 256;
const DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN: usize = 512;
const DECRYPT_WORKER_BULK_BURST_BUDGET: usize = 128;
const DECRYPT_WORKER_BULK_BATCH_MAX: usize = 16;
const DECRYPT_WORKER_AEAD_COMPLETION_DRAIN_BUDGET: usize = DECRYPT_WORKER_BULK_BATCH_MAX * 2;
const DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET: usize = DECRYPT_WORKER_BULK_BATCH_MAX * 2;
const DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE: usize = 64;
const DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX: usize = DECRYPT_WORKER_BULK_BATCH_MAX;
const DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX: usize = DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX;
/// Match the WireGuard-style packet mover for the common same-owner case:
/// the peer/session owner keeps replay and delivery order, while bulk FSP
/// AEAD can run on another worker and return through the owner's ordered
/// completion lane. Same-owner bulk stays on this opener path; pressure is
/// surfaced as bounded opener/completion backpressure instead of a local open
/// fallback that would make a second semantic path for the same packet stream.
/// This is no longer an env-gated experiment: when a sibling decrypt worker
/// exists, same-owner bulk uses the opener path and pressure is bounded by the
/// opener bulk queue plus the ordered receive-ticket window.
/// Keep FMP receive sessions on the same peer-derived owner as FSP receive
/// sessions. This removes the direct-peer hash lottery between local and
/// handoff FSP lanes while preserving the wire protocol.
const DEFAULT_DECRYPT_WORKER_FSP_AEAD_COMPLETION_BATCH_MAX: usize =
    DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET;
static NEXT_FSP_RECEIVE_ORDER_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_FSP_CRYPTO_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_FSP_EPOCH_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_FMP_RECEIVE_ORDER_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_FMP_CRYPTO_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecryptWorkerLane {
    Priority,
    Bulk,
}

impl From<DecryptWorkerLane> for PacketLane {
    fn from(lane: DecryptWorkerLane) -> Self {
        match lane {
            DecryptWorkerLane::Priority => Self::Priority,
            DecryptWorkerLane::Bulk => Self::Bulk,
        }
    }
}

/// Stable owner key for decrypt-worker shard state.
///
/// The rx loop still looks up peers by the raw `(transport_id,
/// receiver_idx)` tuple, but once a packet crosses into the worker pool this
/// named key is the contract: registration, packet jobs, and unregister all
/// hash the same value so one FMP recv session has one shard owner.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DecryptSessionKey {
    transport_id: TransportId,
    receiver_idx: u32,
}

impl DecryptSessionKey {
    pub(crate) fn new(transport_id: TransportId, receiver_idx: u32) -> Self {
        Self {
            transport_id,
            receiver_idx,
        }
    }
}

impl From<(TransportId, u32)> for DecryptSessionKey {
    fn from((transport_id, receiver_idx): (TransportId, u32)) -> Self {
        Self::new(transport_id, receiver_idx)
    }
}

#[cfg(test)]
#[inline]
fn decrypt_session_fast_hash(session_key: DecryptSessionKey) -> u64 {
    let packed =
        (u64::from(session_key.transport_id.as_u32()) << 32) | u64::from(session_key.receiver_idx);
    mix_decrypt_session_hash(packed ^ 0x9e37_79b9_7f4a_7c15)
}

#[inline]
fn decrypt_fsp_session_fast_hash(source_addr: &NodeAddr) -> u64 {
    let bytes = source_addr.as_bytes();
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&bytes[..8]);
    hi.copy_from_slice(&bytes[8..]);
    mix_decrypt_session_hash(
        u64::from_le_bytes(lo) ^ u64::from_le_bytes(hi).rotate_left(17) ^ 0xa24b_aed4_963e_e407,
    )
}

#[inline]
fn decrypt_fsp_open_worker_fast_hash(source_addr: &NodeAddr) -> u64 {
    mix_decrypt_session_hash(decrypt_fsp_session_fast_hash(source_addr) ^ 0xd1b5_4a32_d192_ed03)
}

#[inline]
fn mix_decrypt_session_hash(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn parse_channel_cap(primary: Option<&str>, fallback: Option<&str>, default: usize) -> usize {
    primary
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .or_else(|| fallback.and_then(|raw| raw.trim().parse::<usize>().ok()))
        .unwrap_or(default)
        .clamp(1, default)
}

fn bulk_channel_cap() -> usize {
    let decrypt_cap = std::env::var("FIPS_DECRYPT_WORKER_CHANNEL_CAP").ok();
    let shared_cap = std::env::var("FIPS_WORKER_CHANNEL_CAP").ok();
    parse_channel_cap(
        decrypt_cap.as_deref(),
        shared_cap.as_deref(),
        DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP,
    )
}

fn control_channel_cap() -> usize {
    let control_cap = std::env::var("FIPS_DECRYPT_WORKER_CONTROL_CHANNEL_CAP").ok();
    parse_channel_cap(
        control_cap.as_deref(),
        None,
        DEFAULT_DECRYPT_WORKER_CONTROL_CHANNEL_CAP,
    )
}

fn fsp_receive_window_from_bulk_cap(bulk_cap: usize) -> usize {
    bulk_cap
        .max(1)
        .saturating_add(DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE)
}

fn fsp_receive_window() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| fsp_receive_window_from_bulk_cap(bulk_channel_cap()))
}

fn fsp_aead_completion_channel_cap_from_bulk_cap(bulk_cap: usize) -> usize {
    // The channel stores completion batches, but pressure safety has to hold
    // when completions arrive singly. Match the ordered ticket window so a
    // helper/open worker cannot block merely because it used the advertised
    // FSP receive headroom.
    fsp_receive_window_from_bulk_cap(bulk_cap)
}

fn priority_channel_cap() -> usize {
    let priority_cap = std::env::var("FIPS_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP").ok();
    parse_channel_cap(
        priority_cap.as_deref(),
        None,
        DEFAULT_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP,
    )
}

fn fallback_bulk_channel_cap() -> usize {
    let bulk_cap = std::env::var("FIPS_DECRYPT_FALLBACK_CHANNEL_CAP").ok();
    fallback_bulk_channel_cap_from_raw(bulk_cap.as_deref())
}

fn fallback_bulk_channel_cap_from_raw(bulk_cap: Option<&str>) -> usize {
    // Keep the worker input pressure knob from shrinking the worker->rx-loop
    // return lane. Tests can still force this lane small with the explicit
    // fallback cap.
    parse_channel_cap(bulk_cap, None, DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP)
}

fn fallback_priority_channel_cap() -> usize {
    let priority_cap = std::env::var("FIPS_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP").ok();
    parse_channel_cap(
        priority_cap.as_deref(),
        None,
        DEFAULT_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP,
    )
}

fn decrypt_worker_packet_lane(len: usize) -> DecryptWorkerLane {
    if len <= DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN {
        DecryptWorkerLane::Priority
    } else {
        DecryptWorkerLane::Bulk
    }
}

fn decrypt_job_lane(job: &DecryptJob) -> DecryptWorkerLane {
    job.lane()
}

/// Owning recv-side state for one established FMP session. Lives
/// **inside the worker thread that owns this session** — never
/// shared, never behind a mutex.
///
/// **FMP first** — the worker owns FMP decrypt + replay accept. It returns
/// compact receive bookkeeping for timestamp-only frames, decodes direct local
/// established-session data once FSP state is registered, and only falls back
/// to authenticated FMP plaintext when rx_loop still owns the link dispatch.
/// This split is what makes register-at-FMP-establishment correct: the worker
/// can become authoritative for FMP replay before the FSP handshake completes.
///
/// Built at FMP-session establishment time (`promote_connection`)
/// and shipped to the assigned worker via `WorkerMsg::RegisterSession`.
pub(crate) struct OwnedSessionState {
    fmp_cipher: Arc<LessSafeKey>,
    fmp_replay: ReplayWindow,
    fmp_crypto_generation: u64,
    fmp_receive_order_id: u64,
    fmp_receive_order: FmpReceiveOrder,
    source_peer: PeerIdentity,
}

type FspEpochId = u64;

struct OwnedFspEpochState {
    epoch_id: FspEpochId,
    cipher: Arc<LessSafeKey>,
    replay: ReplayWindow,
}

pub(crate) struct OwnedFspSessionState {
    source_peer: PeerIdentity,
    current_k_bit: bool,
    current: OwnedFspEpochState,
    pending: Option<OwnedFspEpochState>,
    previous: Option<OwnedFspEpochState>,
    fsp_crypto_generation: u64,
    fsp_receive_order_id: u64,
    fsp_receive_order: FspReceiveOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FspOpenReservation {
    crypto_ticket: CryptoTicket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FspOpenReservationBatch {
    reservation: OwnerReservation,
}

impl FspOpenReservation {
    fn new(reservation: OwnerReservation) -> Self {
        Self {
            crypto_ticket: CryptoTicket { reservation },
        }
    }

    fn receive_order_id(self) -> u64 {
        self.crypto_ticket.reservation.order.receive_order_id
    }

    #[cfg(test)]
    fn crypto_generation(self) -> u64 {
        self.crypto_ticket.reservation.generation.0
    }

    #[cfg(test)]
    fn ticket(self) -> FspReceiveTicket {
        FspReceiveTicket {
            sequence: self.crypto_ticket.reservation.order.sequence.0,
        }
    }

    fn crypto_ticket(self) -> CryptoTicket {
        self.crypto_ticket
    }

    #[cfg(test)]
    fn owner_reservation(self) -> OwnerReservation {
        self.crypto_ticket.reservation
    }
}

impl FspOpenReservationBatch {
    fn new(reservation: OwnerReservation) -> Self {
        Self { reservation }
    }

    #[cfg(test)]
    fn receive_order_id(self) -> u64 {
        self.reservation.order.receive_order_id
    }

    #[cfg(test)]
    fn crypto_generation(self) -> u64 {
        self.reservation.generation.0
    }

    fn first_sequence(self) -> u64 {
        self.reservation.order.sequence.0
    }

    #[cfg(test)]
    fn ticket_at(self, offset: usize) -> FspReceiveTicket {
        FspReceiveTicket {
            sequence: self.first_sequence().saturating_add(offset as u64),
        }
    }

    fn crypto_ticket_at(self, offset: usize) -> CryptoTicket {
        let mut reservation = self.reservation;
        reservation.order.sequence =
            OrderSequence(self.first_sequence().saturating_add(offset as u64));
        reservation.packet_count = 1;
        CryptoTicket { reservation }
    }

    #[cfg(test)]
    fn owner_reservation(self) -> OwnerReservation {
        self.reservation
    }
}

struct FspOpenSuccess {
    plaintext: Vec<u8>,
    slot: EpochSlot,
    epoch_id: FspEpochId,
}

#[derive(Debug)]
enum FspOpenError {
    Replay,
    Aead,
}

impl From<FspRecvSessionSnapshot> for OwnedFspSessionState {
    fn from(snapshot: FspRecvSessionSnapshot) -> Self {
        Self {
            source_peer: snapshot.source_peer,
            current_k_bit: snapshot.current_k_bit,
            current: OwnedFspEpochState::from(snapshot.current),
            pending: snapshot.pending.map(OwnedFspEpochState::from),
            previous: snapshot.previous.map(OwnedFspEpochState::from),
            fsp_crypto_generation: NEXT_FSP_CRYPTO_GENERATION.fetch_add(1, Ordering::Relaxed),
            fsp_receive_order_id: NEXT_FSP_RECEIVE_ORDER_ID.fetch_add(1, Ordering::Relaxed),
            fsp_receive_order: new_fsp_receive_order(),
        }
    }
}

impl From<crate::node::session::FspRecvEpochSnapshot> for OwnedFspEpochState {
    fn from(snapshot: crate::node::session::FspRecvEpochSnapshot) -> Self {
        Self {
            epoch_id: NEXT_FSP_EPOCH_ID.fetch_add(1, Ordering::Relaxed),
            cipher: Arc::new(snapshot.cipher),
            replay: snapshot.replay,
        }
    }
}

impl OwnedFspEpochState {
    fn open_deferred_replay(
        &self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, FspOpenError> {
        let mut plaintext = ciphertext.to_vec();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let plaintext_len = self
            .cipher
            .open_in_place(nonce, Aad::from(aad), &mut plaintext)
            .map_err(|_| FspOpenError::Aead)?
            .len();
        plaintext.truncate(plaintext_len);
        Ok(plaintext)
    }

    fn open_in_place_deferred_replay(
        &self,
        ciphertext: &mut [u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<usize, FspOpenError> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        self.cipher
            .open_in_place(nonce, Aad::from(aad), ciphertext)
            .map(|plaintext| plaintext.len())
            .map_err(|_| FspOpenError::Aead)
    }

    fn accept_replay(&mut self, counter: u64) -> Result<(), FspOpenError> {
        if let Some(rejection) = self.replay.rejection_reason(counter) {
            let counter_lag = self.replay.highest().saturating_sub(counter);
            crate::perf_profile::record_fsp_aead_completion_replay_drop_reason(
                rejection,
                counter_lag,
            );
            return Err(FspOpenError::Replay);
        }
        self.replay.accept(counter);
        Ok(())
    }
}

impl OwnedFspSessionState {
    fn has_single_current_epoch(&self) -> bool {
        self.pending.is_none() && self.previous.is_none()
    }

    fn preserve_receive_order_from(&mut self, previous: OwnedFspSessionState) {
        let next_ticket = previous.fsp_receive_order.next_ticket();
        self.fsp_receive_order_id = previous.fsp_receive_order_id;
        self.fsp_receive_order = previous.fsp_receive_order;
        self.fsp_receive_order.advance_next_ticket_to(next_ticket);
    }

    fn fsp_receive_order_id(&self) -> u64 {
        self.fsp_receive_order_id
    }

    fn fsp_crypto_generation(&self) -> u64 {
        self.fsp_crypto_generation
    }

    #[cfg(test)]
    fn fsp_receive_order_next_ready(&self) -> u64 {
        self.fsp_receive_order.next_ready()
    }

    fn current_epoch_matches(&self, header: &FspEncryptedHeader) -> bool {
        (header.flags & FSP_FLAG_K != 0) == self.current_k_bit
    }

    fn fsp_owner_key(&self) -> OwnerKey {
        OwnerKey::Fsp {
            source_addr: *self.source_peer.node_addr(),
        }
    }

    fn owner_reservation_for_sequence(
        &self,
        sequence: u64,
        lane: PacketLane,
        packet_count: usize,
    ) -> OwnerReservation {
        OwnerReservation {
            owner: self.fsp_owner_key(),
            generation: OwnerGeneration(self.fsp_crypto_generation()),
            order: OrderToken {
                receive_order_id: self.fsp_receive_order_id(),
                sequence: OrderSequence(sequence),
            },
            lane,
            packet_count,
        }
    }

    fn reservation_for_ticket(
        &self,
        ticket: FspReceiveTicket,
        lane: PacketLane,
    ) -> FspOpenReservation {
        FspOpenReservation::new(self.owner_reservation_for_sequence(ticket.sequence, lane, 1))
    }

    fn reservation_for_ticket_batch(
        &self,
        first_sequence: u64,
        lane: PacketLane,
        packet_count: usize,
    ) -> FspOpenReservationBatch {
        FspOpenReservationBatch::new(self.owner_reservation_for_sequence(
            first_sequence,
            lane,
            packet_count,
        ))
    }

    fn reserve_local_fsp_open(&mut self, lane: DecryptWorkerLane) -> Option<FspOpenReservation> {
        let ticket = self.fsp_receive_order.issue()?;
        Some(self.reservation_for_ticket(ticket, lane.into()))
    }

    fn reserve_worker_fsp_open(&mut self) -> Option<FspOpenReservation> {
        let ticket = self
            .fsp_receive_order
            .issue_with_reserve(DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE)?;
        Some(self.reservation_for_ticket(ticket, PacketLane::Bulk))
    }

    fn reserve_worker_fsp_open_batch(&mut self, count: usize) -> Option<FspOpenReservationBatch> {
        let first_sequence = self
            .fsp_receive_order
            .issue_batch_with_reserve(count, DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE)?;
        Some(self.reservation_for_ticket_batch(
            first_sequence,
            PacketLane::Bulk,
            count,
        ))
    }

    #[cfg(test)]
    fn issue_fsp_receive_ticket(&mut self) -> Option<FspReceiveTicket> {
        self.fsp_receive_order.issue()
    }

    fn open_established_frame_deferred_replay(
        &self,
        header: &FspEncryptedHeader,
        ciphertext: &[u8],
    ) -> Result<FspOpenSuccess, FspOpenError> {
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        let pending_first = received_k_bit != self.current_k_bit && self.pending.is_some();
        let order = if pending_first {
            [EpochSlot::Pending, EpochSlot::Current, EpochSlot::Previous]
        } else {
            [EpochSlot::Current, EpochSlot::Pending, EpochSlot::Previous]
        };

        for slot in order {
            let epoch = match slot {
                EpochSlot::Current => Some(&self.current),
                EpochSlot::Pending => self.pending.as_ref(),
                EpochSlot::Previous => self.previous.as_ref(),
            };
            let Some(epoch) = epoch else {
                continue;
            };
            match epoch.open_deferred_replay(ciphertext, header.counter, &header.header_bytes) {
                Ok(plaintext) => {
                    return Ok(FspOpenSuccess {
                        plaintext,
                        slot,
                        epoch_id: epoch.epoch_id,
                    });
                }
                Err(FspOpenError::Aead) => {}
                Err(FspOpenError::Replay) => unreachable!(
                    "deferred FSP open does not consult replay before owner retire"
                ),
            }
        }

        Err(FspOpenError::Aead)
    }

    fn accept_opened_established_frame_for_epoch(
        current: &mut OwnedFspEpochState,
        pending: &mut Option<OwnedFspEpochState>,
        previous: &mut Option<OwnedFspEpochState>,
        current_k_bit: &mut bool,
        header: &FspEncryptedHeader,
        epoch_id: FspEpochId,
    ) -> Result<EpochSlot, FspOpenError> {
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        if current.epoch_id == epoch_id {
            if received_k_bit != *current_k_bit {
                return Err(FspOpenError::Aead);
            }
            current.accept_replay(header.counter)?;
            return Ok(EpochSlot::Current);
        }

        if pending.as_ref().is_some_and(|epoch| epoch.epoch_id == epoch_id) {
            let pending_epoch = pending
                .as_mut()
                .expect("pending epoch exists after identity check");
            pending_epoch.accept_replay(header.counter)?;
            let old = std::mem::replace(
                current,
                pending
                    .take()
                    .expect("pending epoch exists after replay accept"),
            );
            *previous = Some(old);
            *current_k_bit = received_k_bit;
            return Ok(EpochSlot::Pending);
        }

        if let Some(previous_epoch) = previous.as_mut()
            && previous_epoch.epoch_id == epoch_id
        {
            previous_epoch.accept_replay(header.counter)?;
            return Ok(EpochSlot::Previous);
        }

        Err(FspOpenError::Aead)
    }

    fn open_current_established_frame_in_place_deferred_replay(
        &mut self,
        header: &FspEncryptedHeader,
        ciphertext: &mut [u8],
    ) -> Result<usize, FspOpenError> {
        debug_assert!(self.has_single_current_epoch());
        self.current
            .open_in_place_deferred_replay(ciphertext, header.counter, &header.header_bytes)
    }

    fn accept_opened_current_established_frame_for(
        current: &mut OwnedFspEpochState,
        current_k_bit: bool,
        header: &FspEncryptedHeader,
    ) -> Result<EpochSlot, FspOpenError> {
        if header.flags & FSP_FLAG_K != u8::from(current_k_bit) * FSP_FLAG_K {
            return Err(FspOpenError::Aead);
        }
        if let Some(rejection) = current.replay.rejection_reason(header.counter) {
            let counter_lag = current.replay.highest().saturating_sub(header.counter);
            crate::perf_profile::record_fsp_aead_completion_replay_drop_reason(
                rejection,
                counter_lag,
            );
            return Err(FspOpenError::Replay);
        }
        current.replay.accept(header.counter);
        Ok(EpochSlot::Current)
    }

    fn complete_ordered_fsp_open(
        &mut self,
        ticket: FspReceiveTicket,
        completion: FspOrderedCompletion,
        mut on_output: impl FnMut(FspReadyCompletion),
    ) -> Result<FspOrderedDrain, OrderedCompletionError> {
        let owner = self.fsp_owner_key();
        let generation = OwnerGeneration(self.fsp_crypto_generation());
        let receive_order_id = self.fsp_receive_order_id();
        let current = &mut self.current;
        let pending = &mut self.pending;
        let previous = &mut self.previous;
        let current_k_bit = &mut self.current_k_bit;
        let source_peer = self.source_peer;
        let mut drain = FspOrderedDrain::default();
        let ready_count = self
            .fsp_receive_order
            .complete(ticket, completion, |ready_ticket, completion| match completion {
                FspOrderedCompletion::Opened { opened, source } => {
                    let reservation = OwnerReservation {
                        owner,
                        generation,
                        order: OrderToken {
                            receive_order_id,
                            sequence: OrderSequence(ready_ticket.sequence),
                        },
                        lane: opened.job.lane.into(),
                        packet_count: 1,
                    };
                    match Self::accept_opened_current_established_frame_for(
                        current,
                        *current_k_bit,
                        &opened.header,
                    ) {
                        Ok(slot) => {
                            drain.accepted += 1;
                            on_output(FspReadyCompletion::Opened {
                                reservation,
                                opened,
                                slot,
                                source_peer,
                            });
                        }
                        Err(FspOpenError::Replay) => {
                            drain.replay_drops += 1;
                            drain.replay_drop_sources.add(source);
                            crate::perf_profile::record_event(
                                crate::perf_profile::Event::DecryptFspWorkerReplayDropped,
                            );
                        }
                        Err(FspOpenError::Aead) => {
                            drain.aead_failures += 1;
                            drain.aead_failure_sources.add(source);
                            crate::perf_profile::record_fsp_aead_completion_accept_kbit_mismatch();
                        }
                    }
                }
                FspOrderedCompletion::OpenedOwned {
                    opened,
                    slot,
                    epoch_id,
                    source,
                } => {
                    let reservation = OwnerReservation {
                        owner,
                        generation,
                        order: OrderToken {
                            receive_order_id,
                            sequence: OrderSequence(ready_ticket.sequence),
                        },
                        lane: opened.job.lane.into(),
                        packet_count: 1,
                    };
                    match Self::accept_opened_established_frame_for_epoch(
                        current,
                        pending,
                        previous,
                        current_k_bit,
                        &opened.header,
                        epoch_id,
                    ) {
                        Ok(retired_slot) => {
                            drain.accepted += 1;
                            let _ = slot;
                            on_output(FspReadyCompletion::OpenedOwned {
                                reservation,
                                opened,
                                slot: retired_slot,
                                source_peer,
                            });
                        }
                        Err(FspOpenError::Replay) => {
                            drain.replay_drops += 1;
                            drain.replay_drop_sources.add(source);
                            crate::perf_profile::record_event(
                                crate::perf_profile::Event::DecryptFspWorkerReplayDropped,
                            );
                        }
                        Err(FspOpenError::Aead) => {
                            drain.aead_failures += 1;
                            drain.aead_failure_sources.add(source);
                            crate::perf_profile::record_fsp_aead_completion_accept_kbit_mismatch();
                        }
                    }
                }
                FspOrderedCompletion::AeadFailed {
                    job,
                    header,
                    source,
                    fallback_to_rx_loop,
                    count_failure,
                } => {
                    let reservation = OwnerReservation {
                        owner,
                        generation,
                        order: OrderToken {
                            receive_order_id,
                            sequence: OrderSequence(ready_ticket.sequence),
                        },
                        lane: job.lane.into(),
                        packet_count: 1,
                    };
                    let mut emit_failure = true;
                    if count_failure {
                        let stale_worker_open_epoch = source.is_worker_open()
                            && header.flags & FSP_FLAG_K
                                != u8::from(*current_k_bit) * FSP_FLAG_K;
                        if stale_worker_open_epoch {
                            drain.stale_epoch_worker_open_failures += 1;
                            emit_failure = false;
                        } else {
                            drain.aead_failures += 1;
                            drain.aead_failure_sources.add(source);
                        }
                    } else if fallback_to_rx_loop {
                        drain.rx_loop_fallbacks += 1;
                    }
                    if emit_failure {
                        on_output(FspReadyCompletion::AeadFailed {
                            reservation,
                            job,
                            header,
                            fallback_to_rx_loop,
                        });
                    }
                }
                FspOrderedCompletion::EpochMismatch {
                    job,
                    header,
                    source,
                } => {
                    let reservation = OwnerReservation {
                        owner,
                        generation,
                        order: OrderToken {
                            receive_order_id,
                            sequence: OrderSequence(ready_ticket.sequence),
                        },
                        lane: job.lane.into(),
                        packet_count: 1,
                    };
                    let _ = source;
                    drain.epoch_mismatches += 1;
                    on_output(FspReadyCompletion::AeadFailed {
                        reservation,
                        job,
                        header,
                        fallback_to_rx_loop: true,
                    });
                }
                FspOrderedCompletion::Dropped { source } => {
                    let _ = source;
                    drain.dropped += 1;
                }
                FspOrderedCompletion::StaleWorkerOpen { source } => {
                    debug_assert!(source.is_worker_open());
                    drain.stale_epoch_worker_open_failures += 1;
                }
            })?;
        drain.ready = ready_count;
        Ok(drain)
    }

    fn complete_fsp_aead_completion(
        &mut self,
        completion: FspAeadCompletion,
        on_output: impl FnMut(FspReadyCompletion),
    ) -> Result<FspOrderedDrain, OrderedCompletionError> {
        let reservation = completion.owner_reservation();
        debug_assert_eq!(reservation.owner, self.fsp_owner_key());
        debug_assert_eq!(
            reservation.order.receive_order_id,
            self.fsp_receive_order_id()
        );
        let ticket = fsp_receive_ticket_from_reservation(reservation);
        let source = completion.source;
        let result = if source.is_worker_open()
            && reservation.generation.0 != self.fsp_crypto_generation()
        {
            FspOrderedCompletion::StaleWorkerOpen { source }
        } else {
            completion.result
        };
        self.complete_ordered_fsp_open(ticket, result, on_output)
    }
}

type OrderedReceiveTicket = crate::packet_mover::OwnerReceiveTicket;
type FmpReceiveTicket = OrderedReceiveTicket;
type FspReceiveTicket = OrderedReceiveTicket;
type OrderedCompletionError = crate::packet_mover::OwnerCompletionError;
type OrderedReceiveWindow<T> = crate::packet_mover::OwnerReceiveWindow<T>;

type FmpReceiveOrder = OrderedReceiveWindow<FmpOrderedCompletion>;
type FspReceiveOrder = OrderedReceiveWindow<FspOrderedCompletion>;

fn new_fmp_receive_order() -> FmpReceiveOrder {
    OrderedReceiveWindow::new(fsp_receive_window())
}

fn new_fsp_receive_order() -> FspReceiveOrder {
    OrderedReceiveWindow::new(fsp_receive_window())
}

struct FspOpenedJob {
    job: FspDecryptJob,
    header: FspEncryptedHeader,
    plaintext_len: usize,
}

struct FspOpenedOwnedJob {
    job: FspDecryptJob,
    header: FspEncryptedHeader,
    plaintext: Vec<u8>,
}

enum FspOrderedCompletion {
    Opened {
        opened: FspOpenedJob,
        source: FspAeadCompletionSource,
    },
    OpenedOwned {
        opened: FspOpenedOwnedJob,
        slot: EpochSlot,
        epoch_id: FspEpochId,
        source: FspAeadCompletionSource,
    },
    AeadFailed {
        job: FspDecryptJob,
        header: FspEncryptedHeader,
        source: FspAeadCompletionSource,
        fallback_to_rx_loop: bool,
        count_failure: bool,
    },
    EpochMismatch {
        job: FspDecryptJob,
        header: FspEncryptedHeader,
        source: FspAeadCompletionSource,
    },
    Dropped {
        source: FspAeadCompletionSource,
    },
    StaleWorkerOpen {
        source: FspAeadCompletionSource,
    },
}

enum FspReadyCompletion {
    Opened {
        reservation: OwnerReservation,
        opened: FspOpenedJob,
        slot: EpochSlot,
        source_peer: PeerIdentity,
    },
    OpenedOwned {
        reservation: OwnerReservation,
        opened: FspOpenedOwnedJob,
        slot: EpochSlot,
        source_peer: PeerIdentity,
    },
    AeadFailed {
        reservation: OwnerReservation,
        job: FspDecryptJob,
        header: FspEncryptedHeader,
        fallback_to_rx_loop: bool,
    },
}

#[derive(Default)]
struct FspOrderedDrain {
    ready: usize,
    accepted: usize,
    aead_failures: usize,
    epoch_mismatches: usize,
    stale_epoch_worker_open_failures: usize,
    replay_drops: usize,
    dropped: usize,
    rx_loop_fallbacks: usize,
    aead_failure_sources: FspAeadFailureSources,
    replay_drop_sources: FspReplayDropSources,
}

impl FspOrderedDrain {
    fn add(&mut self, other: Self) {
        self.ready += other.ready;
        self.accepted += other.accepted;
        self.aead_failures += other.aead_failures;
        self.epoch_mismatches += other.epoch_mismatches;
        self.stale_epoch_worker_open_failures += other.stale_epoch_worker_open_failures;
        self.replay_drops += other.replay_drops;
        self.dropped += other.dropped;
        self.rx_loop_fallbacks += other.rx_loop_fallbacks;
        self.aead_failure_sources
            .add_sources(other.aead_failure_sources);
        self.replay_drop_sources
            .add_sources(other.replay_drop_sources);
    }

    fn accounted_ready(&self) -> usize {
        self.accepted
            + self.aead_failures
            + self.epoch_mismatches
            + self.stale_epoch_worker_open_failures
            + self.replay_drops
            + self.dropped
            + self.rx_loop_fallbacks
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FspAeadFailureSources {
    local: usize,
    worker_open: usize,
    worker_open_returned: usize,
}

impl FspAeadFailureSources {
    fn add(&mut self, source: FspAeadCompletionSource) {
        match source {
            FspAeadCompletionSource::Local => self.local += 1,
            FspAeadCompletionSource::WorkerOpen => self.worker_open += 1,
            FspAeadCompletionSource::WorkerOpenReturned => self.worker_open_returned += 1,
        }
    }

    fn add_sources(&mut self, other: Self) {
        self.local += other.local;
        self.worker_open += other.worker_open;
        self.worker_open_returned += other.worker_open_returned;
    }

    fn record(self) {
        crate::perf_profile::record_fsp_aead_completion_source_aead_failures(
            self.local,
            self.worker_open,
            self.worker_open_returned,
        );
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FspReplayDropSources {
    worker_open: usize,
    worker_open_returned: usize,
}

impl FspReplayDropSources {
    fn add(&mut self, source: FspAeadCompletionSource) {
        match source {
            FspAeadCompletionSource::Local => {}
            FspAeadCompletionSource::WorkerOpen => self.worker_open += 1,
            FspAeadCompletionSource::WorkerOpenReturned => self.worker_open_returned += 1,
        }
    }

    fn add_sources(&mut self, other: Self) {
        self.worker_open += other.worker_open;
        self.worker_open_returned += other.worker_open_returned;
    }

    fn record(self) {
        crate::perf_profile::record_fsp_aead_completion_source_replay_drops(
            self.worker_open,
            self.worker_open_returned,
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FmpReplayPrecheck {
    counter: u64,
    replay_highest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FmpOpenReservation {
    crypto_ticket: CryptoTicket,
    replay_precheck: FmpReplayPrecheck,
}

impl FmpOpenReservation {
    fn new(reservation: OwnerReservation, replay_precheck: FmpReplayPrecheck) -> Self {
        Self {
            crypto_ticket: CryptoTicket { reservation },
            replay_precheck,
        }
    }

    fn crypto_ticket(self) -> CryptoTicket {
        self.crypto_ticket
    }

    fn replay_precheck(self) -> FmpReplayPrecheck {
        self.replay_precheck
    }
}

struct FmpAeadOpenWork {
    cipher: Arc<LessSafeKey>,
    packet_data: PacketBuffer,
    fmp_ciphertext_offset: usize,
    fmp_counter: u64,
    fmp_flags: u8,
    fmp_header: [u8; 16],
}

impl FmpAeadOpenWork {
    fn open(self) -> Result<FmpAeadOpened, ()> {
        let Self {
            cipher,
            mut packet_data,
            fmp_ciphertext_offset,
            fmp_counter,
            fmp_flags,
            fmp_header,
        } = self;
        let outcome = OwnedSessionState::open_fmp_aead_in_place(
            cipher.as_ref(),
            &mut packet_data,
            fmp_ciphertext_offset,
            fmp_counter,
            fmp_flags,
            &fmp_header,
        )?;
        Ok(FmpAeadOpened {
            packet_data,
            plaintext_len: outcome.plaintext_len,
        })
    }
}

struct FmpAeadOpened {
    packet_data: PacketBuffer,
    plaintext_len: usize,
}

#[derive(Default)]
struct FmpAeadOpener;

impl StatelessCryptoWorker<FmpAeadOpenWork> for FmpAeadOpener {
    type Output = FmpAeadOpened;
    type RejectOutput = ();

    fn execute(
        &mut self,
        work: CryptoWork<FmpAeadOpenWork>,
    ) -> CryptoCompletion<Self::Output, Self::RejectOutput> {
        let ticket = work.ticket;
        let result = match work.work.open() {
            Ok(opened) => CryptoResult::Opened(opened),
            Err(()) => CryptoResult::Rejected(CryptoReject::Aead),
        };
        CryptoCompletion { ticket, result }
    }
}

struct FmpAeadCompletion {
    crypto: CryptoCompletion<FmpAeadOpened>,
    replay_precheck: FmpReplayPrecheck,
}

impl FmpAeadCompletion {
    fn new(reservation: FmpOpenReservation, crypto: CryptoCompletion<FmpAeadOpened>) -> Self {
        debug_assert_eq!(crypto.ticket, reservation.crypto_ticket());
        Self {
            crypto,
            replay_precheck: reservation.replay_precheck(),
        }
    }

    fn owner_reservation(&self) -> OwnerReservation {
        self.crypto.ticket.reservation
    }
}

impl OwnerOrderedCompletion for FmpAeadCompletion {
    fn owner_reservation(&self) -> OwnerReservation {
        self.crypto.ticket.reservation
    }
}

enum FmpOrderedCompletion {
    Opened {
        opened: FmpAeadOpened,
        replay_precheck: FmpReplayPrecheck,
    },
    AeadFailed {
        fmp_counter: u64,
        fmp_replay_highest: u64,
    },
    Dropped,
}

enum FmpReadyCompletion {
    Opened(FmpAeadOpened),
    DecryptFailure {
        fmp_counter: u64,
        fmp_replay_highest: u64,
    },
}

struct OpenedFmpJob {
    packet_data: PacketBuffer,
    source_peer: PeerIdentity,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    local_node_addr: NodeAddr,
    timestamp_ms: u64,
    packet_len: usize,
    fmp_counter: u64,
    fmp_flags: u8,
    fmp_plaintext_offset: usize,
    fmp_plaintext_len: usize,
}

fn local_established_fsp_datagram_meta(
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

type FspAeadOpenDispatch = CryptoDispatch<FspAeadOpenWork, FspAeadOpenRoute>;

struct FspAeadOpenRoute {
    completion_source: FspAeadCompletionSource,
    completion_owner_idx: Option<usize>,
    open_queued_at: Option<crate::perf_profile::TraceStamp>,
}

struct FspAeadOpenWork {
    cipher: Arc<LessSafeKey>,
    job: FspDecryptJob,
    header: FspEncryptedHeader,
}

struct FspAeadOpenReject {
    job: FspDecryptJob,
    header: FspEncryptedHeader,
    fallback_to_rx_loop: bool,
    count_failure: bool,
}

struct FspAeadOpener;

impl StatelessCryptoWorker<FspAeadOpenWork> for FspAeadOpener {
    type Output = FspOpenedJob;
    type RejectOutput = FspAeadOpenReject;

    fn execute(
        &mut self,
        work: CryptoWork<FspAeadOpenWork>,
    ) -> CryptoCompletion<Self::Output, Self::RejectOutput> {
        let ticket = work.ticket;
        let FspAeadOpenWork {
            cipher,
            mut job,
            header,
        } = work.work;
        let payload_end = job.fsp_payload_offset.saturating_add(job.fsp_payload_len);
        let ciphertext_offset = job.fsp_payload_offset + FSP_HEADER_SIZE;
        let Some(ciphertext) = job
            .fallback
            .packet_data
            .get_mut(ciphertext_offset..payload_end)
        else {
            return CryptoCompletion {
                ticket,
                result: CryptoResult::RejectedWith {
                    reject: CryptoReject::Malformed,
                    value: FspAeadOpenReject {
                        job,
                        header,
                        fallback_to_rx_loop: false,
                        count_failure: true,
                    },
                },
            };
        };

        let _t_fsp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&header.counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let open_result = cipher
            .open_in_place(nonce, Aad::from(&header.header_bytes), ciphertext)
            .map(|plaintext| plaintext.len());

        match open_result {
            Ok(plaintext_len) => CryptoCompletion {
                ticket,
                result: CryptoResult::Opened(FspOpenedJob {
                    job,
                    header,
                    plaintext_len,
                }),
            },
            Err(_) => CryptoCompletion {
                ticket,
                result: CryptoResult::RejectedWith {
                    reject: CryptoReject::Aead,
                    value: FspAeadOpenReject {
                        job,
                        header,
                        fallback_to_rx_loop: false,
                        count_failure: true,
                    },
                },
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FspAeadCompletionSource {
    Local,
    WorkerOpen,
    WorkerOpenReturned,
}

impl FspAeadCompletionSource {
    fn returned(self) -> Self {
        match self {
            Self::Local => Self::Local,
            Self::WorkerOpen => Self::WorkerOpenReturned,
            already_returned => already_returned,
        }
    }

    fn is_worker_open(self) -> bool {
        matches!(self, Self::WorkerOpen | Self::WorkerOpenReturned)
    }
}

struct FspAeadCompletion {
    crypto_ticket: CryptoTicket,
    source: FspAeadCompletionSource,
    result: FspOrderedCompletion,
    completed_at: Option<crate::perf_profile::TraceStamp>,
}

fn fsp_reservation_source_addr(reservation: OwnerReservation) -> NodeAddr {
    match reservation.owner {
        OwnerKey::Fsp { source_addr } => source_addr,
        owner => unreachable!("FSP AEAD owner reservation must be FSP, got {owner:?}"),
    }
}

fn fsp_receive_ticket_from_reservation(reservation: OwnerReservation) -> FspReceiveTicket {
    FspReceiveTicket {
        sequence: reservation.order.sequence.0,
    }
}

fn fmp_receive_ticket_from_reservation(reservation: OwnerReservation) -> FmpReceiveTicket {
    FmpReceiveTicket {
        sequence: reservation.order.sequence.0,
    }
}

impl FspAeadCompletion {
    fn from_crypto_completion(
        source: FspAeadCompletionSource,
        crypto: CryptoCompletion<FspOpenedJob, FspAeadOpenReject>,
        completed_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        let crypto_ticket = crypto.ticket;
        let result = match crypto.result {
            CryptoResult::Opened(opened) => FspOrderedCompletion::Opened { opened, source },
            CryptoResult::RejectedWith { value, .. } => FspOrderedCompletion::AeadFailed {
                job: value.job,
                header: value.header,
                source,
                fallback_to_rx_loop: value.fallback_to_rx_loop,
                count_failure: value.count_failure,
            },
            CryptoResult::Rejected(_) | CryptoResult::Dropped => FspOrderedCompletion::Dropped {
                source,
            },
        };
        Self {
            crypto_ticket,
            source,
            result,
            completed_at,
        }
    }

    fn owner_reservation(&self) -> OwnerReservation {
        self.crypto_ticket.reservation
    }

    fn source_addr(&self) -> NodeAddr {
        fsp_reservation_source_addr(self.owner_reservation())
    }

    fn receive_order_id(&self) -> u64 {
        self.owner_reservation().order.receive_order_id
    }

    #[cfg(test)]
    fn receive_ticket(&self) -> FspReceiveTicket {
        fsp_receive_ticket_from_reservation(self.owner_reservation())
    }
}

impl OwnerOrderedCompletion for FspAeadCompletion {
    fn owner_reservation(&self) -> OwnerReservation {
        self.crypto_ticket.reservation
    }
}

type FspAeadCompletionBatch = OwnerCompletionBatch<FspAeadCompletion>;

struct FspAeadCompletionBatchFlush {
    local_completion: bool,
    owner_idx: Option<usize>,
    batch: FspAeadCompletionBatch,
}

struct FspAeadCompletionBatchBuilder {
    current_local: bool,
    current_owner_idx: Option<usize>,
    current_batch: Option<FspAeadCompletionBatch>,
    max_len: usize,
}

impl FspAeadCompletionBatchBuilder {
    fn new() -> Self {
        Self {
            current_local: false,
            current_owner_idx: None,
            current_batch: None,
            max_len: DEFAULT_DECRYPT_WORKER_FSP_AEAD_COMPLETION_BATCH_MAX,
        }
    }

    fn push(
        &mut self,
        local_completion: bool,
        owner_idx: Option<usize>,
        completion: FspAeadCompletion,
    ) -> Option<FspAeadCompletionBatchFlush> {
        let owner_idx = owner_idx.filter(|_| !local_completion);
        let reservation = completion.owner_reservation();
        let same_batch = self
            .current_batch
            .as_ref()
            .is_some_and(|batch| {
                batch.can_push(
                    reservation.owner,
                    reservation.order.receive_order_id,
                    self.max_len,
                )
            })
            && self.current_local == local_completion
            && self.current_owner_idx == owner_idx;

        if same_batch {
            let Some(batch) = self.current_batch.as_mut() else {
                unreachable!("same_batch requires an active completion batch")
            };
            batch.push_with_capacity(completion, self.max_len);
            return None;
        }

        let flush = self.flush();
        self.current_local = local_completion;
        self.current_owner_idx = owner_idx;
        self.current_batch = Some(FspAeadCompletionBatch::one(completion));
        flush
    }

    fn flush(&mut self) -> Option<FspAeadCompletionBatchFlush> {
        Some(FspAeadCompletionBatchFlush {
            local_completion: self.current_local,
            owner_idx: self.current_owner_idx.take(),
            batch: self.current_batch.take()?,
        })
    }
}

fn new_fsp_aead_open_dispatch(
    crypto_ticket: CryptoTicket,
    cipher: Arc<LessSafeKey>,
    job: FspDecryptJob,
    header: FspEncryptedHeader,
    completion_source: FspAeadCompletionSource,
    completion_owner_idx: Option<usize>,
    open_queued_at: Option<crate::perf_profile::TraceStamp>,
) -> FspAeadOpenDispatch {
    CryptoDispatch::new(
        CryptoWork {
            ticket: crypto_ticket,
            work: FspAeadOpenWork {
                cipher,
                job,
                header,
            },
        },
        FspAeadOpenRoute {
            completion_source,
            completion_owner_idx,
            open_queued_at,
        },
    )
}

trait FspAeadOpenDispatchExt {
    #[cfg(test)]
    fn crypto_ticket(&self) -> CryptoTicket;

    fn completion_owner_idx(&self) -> Option<usize>;

    fn queue_for_completion_owner(
        &mut self,
        owner_idx: usize,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    );

    #[cfg(test)]
    fn completion_source(&self) -> FspAeadCompletionSource;

    fn set_completion_source(&mut self, source: FspAeadCompletionSource);

    #[cfg(test)]
    fn owner_reservation(&self) -> OwnerReservation;

    #[cfg(test)]
    fn source_addr(&self) -> NodeAddr;

    #[cfg(test)]
    fn receive_order_id(&self) -> u64;

    #[cfg(test)]
    fn crypto_generation(&self) -> u64;

    #[cfg(test)]
    fn receive_ticket(&self) -> FspReceiveTicket;

    fn mark_returned_completion(&mut self);

    fn into_completion(self) -> FspAeadCompletion;

    fn into_dropped_completion(self) -> FspAeadCompletion;
}

impl FspAeadOpenDispatchExt for FspAeadOpenDispatch {
    #[cfg(test)]
    fn crypto_ticket(&self) -> CryptoTicket {
        self.work.ticket
    }

    fn completion_owner_idx(&self) -> Option<usize> {
        self.route.completion_owner_idx
    }

    fn queue_for_completion_owner(
        &mut self,
        owner_idx: usize,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) {
        self.route.completion_owner_idx = Some(owner_idx);
        self.route.open_queued_at = queued_at;
    }

    #[cfg(test)]
    fn completion_source(&self) -> FspAeadCompletionSource {
        self.route.completion_source
    }

    fn set_completion_source(&mut self, source: FspAeadCompletionSource) {
        self.route.completion_source = source;
    }

    #[cfg(test)]
    fn owner_reservation(&self) -> OwnerReservation {
        self.crypto_ticket().reservation
    }

    #[cfg(test)]
    fn source_addr(&self) -> NodeAddr {
        fsp_reservation_source_addr(self.owner_reservation())
    }

    #[cfg(test)]
    fn receive_order_id(&self) -> u64 {
        self.owner_reservation().order.receive_order_id
    }

    #[cfg(test)]
    fn crypto_generation(&self) -> u64 {
        self.owner_reservation().generation.0
    }

    #[cfg(test)]
    fn receive_ticket(&self) -> FspReceiveTicket {
        fsp_receive_ticket_from_reservation(self.owner_reservation())
    }

    fn mark_returned_completion(&mut self) {
        match self.route.completion_source {
            FspAeadCompletionSource::WorkerOpen => crate::perf_profile::record_event(
                crate::perf_profile::Event::FspAeadCompletionReturnedWorkerOpen,
            ),
            FspAeadCompletionSource::Local | FspAeadCompletionSource::WorkerOpenReturned => {}
        }
        self.set_completion_source(self.route.completion_source.returned());
    }

    fn into_completion(self) -> FspAeadCompletion {
        let CryptoDispatch { work, route } = self;
        let source = route.completion_source;
        if source.is_worker_open() {
            crate::perf_profile::record_since_count(
                crate::perf_profile::Stage::FspAeadWorkerOpenQueueWait,
                route.open_queued_at,
                1,
            );
        }
        let completed_at = route.open_queued_at.and_then(|_| crate::perf_profile::stamp());
        let mut opener = FspAeadOpener;
        FspAeadCompletion::from_crypto_completion(source, opener.execute(work), completed_at)
    }

    fn into_dropped_completion(self) -> FspAeadCompletion {
        let CryptoDispatch { work, route } = self;
        let source = route.completion_source;
        if source.is_worker_open() {
            crate::perf_profile::record_since_count(
                crate::perf_profile::Stage::FspAeadWorkerOpenQueueWait,
                route.open_queued_at,
                1,
            );
        }
        let completed_at = route.open_queued_at.and_then(|_| crate::perf_profile::stamp());
        FspAeadCompletion {
            crypto_ticket: work.ticket,
            source,
            result: FspOrderedCompletion::Dropped { source },
            completed_at,
        }
    }
}

#[derive(Debug)]
struct FmpOpenOutcome {
    plaintext_len: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum FmpOpenError {
    Replay,
    WindowFull,
}

impl OwnedSessionState {
    pub(crate) fn new(
        fmp_cipher: LessSafeKey,
        fmp_replay: ReplayWindow,
        source_peer: PeerIdentity,
    ) -> Self {
        Self {
            fmp_cipher: Arc::new(fmp_cipher),
            fmp_replay,
            fmp_crypto_generation: NEXT_FMP_CRYPTO_GENERATION.fetch_add(1, Ordering::Relaxed),
            fmp_receive_order_id: NEXT_FMP_RECEIVE_ORDER_ID.fetch_add(1, Ordering::Relaxed),
            fmp_receive_order: new_fmp_receive_order(),
            source_peer,
        }
    }

    fn fmp_owner_key(&self) -> OwnerKey {
        OwnerKey::Fmp {
            source_addr: *self.source_peer.node_addr(),
        }
    }

    fn fmp_crypto_generation(&self) -> u64 {
        self.fmp_crypto_generation
    }

    fn fmp_receive_order_id(&self) -> u64 {
        self.fmp_receive_order_id
    }

    fn precheck_fmp_replay(&self, fmp_counter: u64) -> Result<FmpReplayPrecheck, FmpOpenError> {
        let replay_highest = self.fmp_replay.highest();
        if !self.fmp_replay.check(fmp_counter) {
            return Err(FmpOpenError::Replay);
        }
        Ok(FmpReplayPrecheck {
            counter: fmp_counter,
            replay_highest,
        })
    }

    fn reserve_fmp_open(
        &mut self,
        lane: DecryptWorkerLane,
        fmp_counter: u64,
    ) -> Result<FmpOpenReservation, FmpOpenError> {
        let replay_precheck = self.precheck_fmp_replay(fmp_counter)?;
        let Some(ticket) = self.fmp_receive_order.issue() else {
            return Err(FmpOpenError::WindowFull);
        };
        Ok(FmpOpenReservation::new(
            OwnerReservation {
                owner: self.fmp_owner_key(),
                generation: OwnerGeneration(self.fmp_crypto_generation()),
                order: OrderToken {
                    receive_order_id: self.fmp_receive_order_id(),
                    sequence: OrderSequence(ticket.sequence),
                },
                lane: lane.into(),
                packet_count: 1,
            },
            replay_precheck,
        ))
    }

    fn fmp_open_work(
        &self,
        reservation: FmpOpenReservation,
        packet_data: PacketBuffer,
        fmp_ciphertext_offset: usize,
        fmp_counter: u64,
        fmp_flags: u8,
        fmp_header: [u8; 16],
    ) -> CryptoWork<FmpAeadOpenWork> {
        CryptoWork {
            ticket: reservation.crypto_ticket(),
            work: FmpAeadOpenWork {
                cipher: Arc::clone(&self.fmp_cipher),
                packet_data,
                fmp_ciphertext_offset,
                fmp_counter,
                fmp_flags,
                fmp_header,
            },
        }
    }

    fn open_fmp_aead_in_place(
        cipher: &LessSafeKey,
        packet_data: &mut [u8],
        fmp_ciphertext_offset: usize,
        fmp_counter: u64,
        _fmp_flags: u8,
        fmp_header: &[u8; 16],
    ) -> Result<FmpOpenOutcome, ()> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&fmp_counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let buf = &mut packet_data[fmp_ciphertext_offset..];
        let _t_fmp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);
        let plaintext_len = cipher
            .open_in_place(nonce, Aad::from(fmp_header), buf)
            .map_err(|_| ())?
            .len();

        Ok(FmpOpenOutcome { plaintext_len })
    }

    fn complete_fmp_aead_completion(
        &mut self,
        completion: FmpAeadCompletion,
        mut on_ready: impl FnMut(FmpReadyCompletion),
    ) -> Result<usize, OrderedCompletionError> {
        let reservation = completion.owner_reservation();
        debug_assert_eq!(reservation.owner, self.fmp_owner_key());
        debug_assert_eq!(
            reservation.order.receive_order_id,
            self.fmp_receive_order_id()
        );
        debug_assert_eq!(
            reservation.generation,
            OwnerGeneration(self.fmp_crypto_generation())
        );
        let ticket = fmp_receive_ticket_from_reservation(reservation);
        let replay_precheck = completion.replay_precheck;
        let ordered = match completion.crypto.result {
            CryptoResult::Opened(opened) => FmpOrderedCompletion::Opened {
                opened,
                replay_precheck,
            },
            CryptoResult::Rejected(CryptoReject::Replay)
            | CryptoResult::RejectedWith {
                reject: CryptoReject::Replay,
                ..
            }
            | CryptoResult::Dropped => FmpOrderedCompletion::Dropped,
            CryptoResult::Rejected(
                CryptoReject::Aead | CryptoReject::Malformed | CryptoReject::StaleGeneration,
            )
            | CryptoResult::RejectedWith {
                reject:
                    CryptoReject::Aead
                    | CryptoReject::Malformed
                    | CryptoReject::StaleGeneration,
                ..
            } => FmpOrderedCompletion::AeadFailed {
                fmp_counter: replay_precheck.counter,
                fmp_replay_highest: replay_precheck.replay_highest,
            },
        };
        let fmp_replay = &mut self.fmp_replay;
        self.fmp_receive_order
            .complete(ticket, ordered, |_ticket, completion| match completion {
                FmpOrderedCompletion::Opened {
                    opened,
                    replay_precheck,
                } => {
                    if Self::accept_prechecked_fmp_replay_in(fmp_replay, replay_precheck) {
                        on_ready(FmpReadyCompletion::Opened(opened));
                    }
                }
                FmpOrderedCompletion::AeadFailed {
                    fmp_counter,
                    fmp_replay_highest,
                } => on_ready(FmpReadyCompletion::DecryptFailure {
                    fmp_counter,
                    fmp_replay_highest,
                }),
                FmpOrderedCompletion::Dropped => {}
            })
    }

    fn accept_prechecked_fmp_replay_in(
        fmp_replay: &mut ReplayWindow,
        precheck: FmpReplayPrecheck,
    ) -> bool {
        if let Some(reason) = fmp_replay.rejection_reason(precheck.counter) {
            let counter_lag = fmp_replay.highest().saturating_sub(precheck.counter);
            crate::perf_profile::record_fmp_aead_completion_prechecked_replay_drop_reason(
                reason,
                counter_lag,
            );
            return false;
        }
        fmp_replay.accept(precheck.counter);
        true
    }

    #[cfg(test)]
    fn accept_prechecked_fmp_replay(&mut self, precheck: FmpReplayPrecheck) -> bool {
        Self::accept_prechecked_fmp_replay_in(&mut self.fmp_replay, precheck)
    }
}

/// Pre-cooked decrypt + dispatch job. Built on rx_loop after parsing
/// the FMP header; the worker pulls its session state from its own
/// local HashMap (keyed by `session_key`) instead of receiving a
/// `WorkerSessionState` clone per packet.
pub(crate) struct DecryptJob {
    /// The raw packet bytes (incl. the 16-byte FMP outer header).
    /// Mutated in place during AEAD open — must reach the worker
    /// with the full ciphertext + tag intact.
    pub packet_data: PacketBuffer,
    /// Lane selected when rx_loop builds the worker message. Dispatch consumes
    /// this queued value instead of recalculating lane policy later.
    lane: DecryptWorkerLane,
    /// Lookup key into the worker's owned session HashMap. Mirrors the
    /// active peer registry session-index key on the Node side:
    /// `(transport_id, receiver_idx)`.
    pub session_key: DecryptSessionKey,
    /// Worker shard that accepted this FMP session registration. This is the
    /// same owner selected at registration time; carrying it on the job keeps
    /// hot packet dispatch out of the pool owner map.
    worker_idx: usize,
    /// Source kernel transport. Forwarded into the bounced
    /// `DecryptFallback` so rx_loop can update per-peer last-seen +
    /// link stats (otherwise the MMP link-dead timer fires at 30s
    /// because the worker handles packets without ever calling
    /// `peer.touch()` / `record_recv()`).
    pub _transport_id: TransportId,
    pub _remote_addr: TransportAddr,
    pub local_node_addr: NodeAddr,
    pub timestamp_ms: u64,
    /// Counter from the FMP outer header. Used both as nonce input
    /// and to update the replay window.
    pub fmp_counter: u64,
    /// Flag byte from the FMP outer header. Carried through the
    /// fallback so the rx_loop bounce arm can extract `CE` and `SP`
    /// for ECN propagation, MMP stats, and spin-bit RTT
    /// observation — these used to be dropped on the worker path
    /// because the bounce hardcoded `fmp_flags: 0`.
    pub fmp_flags: u8,
    /// 16-byte FMP outer header used as AAD during AEAD open.
    pub fmp_header: [u8; 16],
    /// Offset within `packet_data` where the FMP ciphertext+tag begins.
    pub fmp_ciphertext_offset: usize,
    /// Monotonic timestamp captured immediately before rx_loop queues this job
    /// to the decrypt worker. Used only when pipeline tracing is on.
    trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptJob {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        packet_data: impl Into<PacketBuffer>,
        session_key: DecryptSessionKey,
        worker_idx: usize,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        local_node_addr: NodeAddr,
        timestamp_ms: u64,
        fmp_counter: u64,
        fmp_flags: u8,
        fmp_header: [u8; 16],
        fmp_ciphertext_offset: usize,
    ) -> Self {
        let packet_data = packet_data.into();
        let lane = decrypt_worker_packet_lane(packet_data.len());
        Self {
            packet_data,
            lane,
            session_key,
            worker_idx,
            _transport_id: transport_id,
            _remote_addr: remote_addr,
            local_node_addr,
            timestamp_ms,
            fmp_counter,
            fmp_flags,
            fmp_header,
            fmp_ciphertext_offset,
            trace_enqueued_at: None,
        }
    }

    fn lane(&self) -> DecryptWorkerLane {
        self.lane
    }

    fn worker_idx(&self) -> usize {
        self.worker_idx
    }

    fn session_key(&self) -> DecryptSessionKey {
        self.session_key
    }

    fn is_bulk_lane(&self) -> bool {
        matches!(self.lane(), DecryptWorkerLane::Bulk)
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        self.trace_enqueued_at = queued_at;
    }

    fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at;
        if queued_at.is_none() {
            return;
        }
        let priority_count = u64::from(matches!(self.lane(), DecryptWorkerLane::Priority));
        let bulk_count = u64::from(matches!(self.lane(), DecryptWorkerLane::Bulk));
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::DecryptWorkerQueueWait,
            crate::perf_profile::Stage::DecryptWorkerPriorityQueueWait,
            crate::perf_profile::Stage::DecryptWorkerBulkQueueWait,
            queued_at,
            1,
            priority_count,
            bulk_count,
        );
    }
}

/// Result of a successful FMP decrypt + replay accept that still needs legacy
/// link-message dispatch on rx_loop. Local established FSP data takes the
/// narrower authenticated/direct-data event when the worker can safely decode
/// it first.
#[allow(dead_code)] // fmp_counter / fmp_flags retained for future debug paths
pub(crate) struct DecryptFallback {
    pub source_peer: PeerIdentity,
    /// Transport this packet arrived on — used by rx_loop's bounce
    /// arm to call `peer.set_current_addr()` so address rotation +
    /// MMP link-dead tracking continue to see updates for packets
    /// handled by the worker.
    pub transport_id: TransportId,
    /// Remote transport address — companion to `transport_id`.
    pub remote_addr: TransportAddr,
    pub timestamp_ms: u64,
    /// Length of the wire packet that produced this bounce. Used
    /// by rx_loop to call `peer.link_stats_mut().record_recv()` so
    /// per-peer stats + MMP last-seen + link-dead detection see
    /// progress for worker-handled packets. Without this update,
    /// MMP's 30-second link-dead timer fires even though packets
    /// are arriving fine.
    pub packet_len: usize,
    /// Return queue lane selected when the worker creates this completion
    /// event. The return sender consumes this queued value instead of
    /// deriving queue policy later from mutable metadata.
    lane: DecryptWorkerLane,
    pub fmp_counter: u64,
    pub fmp_flags: u8,
    /// Original received wire buffer, mutated in place by the FMP
    /// AEAD open. Bytes `[fmp_plaintext_offset ..
    /// fmp_plaintext_offset+fmp_plaintext_len]` are the decrypted
    /// FMP plaintext: a 4-byte session timestamp followed by the
    /// link-layer message (FSP frame when
    /// `phase == FSP_PHASE_ESTABLISHED`). rx_loop slices into this
    /// Vec for FSP decrypt + dispatch and only allocates on the
    /// actual delivery hop.
    ///
    /// **Why packet_data + offset, not `Vec<u8>` of the plaintext:**
    /// the pre-fix bounce did `packet_data[a..b].to_vec()` per
    /// packet, which is one fresh ~1500-byte allocation on every
    /// inbound bulk frame. At 150k pps that's ~225 MB/sec of
    /// memory bandwidth on the worker + rx_loop hot path, and a
    /// per-packet allocator round-trip. Passing the original Vec
    /// through unmodified lets the consumer borrow a slice; zero
    /// alloc, zero memcpy.
    pub packet_data: PacketBuffer,
    pub fmp_plaintext_offset: usize,
    pub fmp_plaintext_len: usize,
    /// Monotonic timestamp captured immediately before the worker queues this
    /// completion back to the rx loop. Used only when pipeline tracing is on.
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptFallback {
    #[allow(clippy::too_many_arguments)]
    fn new(
        source_peer: PeerIdentity,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        fmp_flags: u8,
        packet_data: impl Into<PacketBuffer>,
        fmp_plaintext_offset: usize,
        fmp_plaintext_len: usize,
    ) -> Self {
        let packet_data = packet_data.into();
        let lane = decrypt_worker_packet_lane(packet_len);
        Self {
            source_peer,
            transport_id,
            remote_addr,
            timestamp_ms,
            packet_len,
            lane,
            fmp_counter,
            fmp_flags,
            packet_data,
            fmp_plaintext_offset,
            fmp_plaintext_len,
            trace_enqueued_at: None,
        }
    }

    fn lane(&self) -> DecryptWorkerLane {
        self.lane
    }
}

/// Report from the decrypt worker when a registered FMP session fails
/// AEAD authentication. Routed back to rx_loop so peer/session recovery
/// decisions stay in one place instead of being silently dropped inside
/// the worker thread.
pub(crate) struct DecryptFailureReport {
    pub source_peer: PeerIdentity,
    pub fmp_counter: u64,
    pub fmp_replay_highest: u64,
    /// Monotonic timestamp captured immediately before the worker queues this
    /// failure report back to the rx loop.
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

pub(crate) struct DecryptFmpBookkeeping {
    pub source_peer: PeerIdentity,
    pub transport_id: TransportId,
    pub remote_addr: TransportAddr,
    pub packet_timestamp_ms: u64,
    pub packet_len: usize,
    pub fmp_counter: u64,
    pub inner_timestamp_ms: u32,
    pub fmp_flags: u8,
}

pub(crate) struct DecryptAuthenticatedFmpReceive {
    pub fmp: DecryptFmpBookkeeping,
    pub previous_hop_peer: Option<PeerIdentity>,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

pub(crate) struct DecryptAuthenticatedSession {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub previous_hop_peer: PeerIdentity,
    pub ce_flag: bool,
    pub message: AuthenticatedSessionMessage,
    pub receive_sync: FspReceiveSync,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

pub(crate) enum DecryptDirectSessionDelivery {
    Ipv6Packet(Vec<u8>),
    EndpointData(EndpointDataDelivery),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DecryptDirectSessionDeliverySink {
    tun_tx: Option<TunTx>,
    external_packet_tx: Option<TokioSender<NodeDeliveredPacket>>,
    endpoint_event_tx: Option<EndpointEventSender>,
}

impl DecryptDirectSessionDeliverySink {
    pub(crate) fn new(
        tun_tx: Option<TunTx>,
        external_packet_tx: Option<TokioSender<NodeDeliveredPacket>>,
        endpoint_event_tx: Option<EndpointEventSender>,
    ) -> Self {
        Self {
            tun_tx,
            external_packet_tx,
            endpoint_event_tx,
        }
    }

    fn output_target_for(&self, delivery: &DecryptDirectSessionDelivery) -> Option<OutputTarget> {
        match delivery {
            DecryptDirectSessionDelivery::EndpointData(_) => self
                .endpoint_event_tx
                .is_some()
                .then_some(OutputTarget::Endpoint),
            DecryptDirectSessionDelivery::Ipv6Packet(_) => {
                (self.external_packet_tx.is_some() || self.tun_tx.is_some())
                    .then_some(OutputTarget::Tun)
            }
        }
    }

    fn same_endpoint_event_channel(&self, other: &Self) -> bool {
        match (&self.endpoint_event_tx, &other.endpoint_event_tx) {
            (Some(lhs), Some(rhs)) => lhs.same_channels(rhs),
            (None, None) => true,
            _ => false,
        }
    }

    fn endpoint_event_sender(&self) -> Option<&EndpointEventSender> {
        self.endpoint_event_tx.as_ref()
    }

    fn deliver(
        &self,
        source_addr: NodeAddr,
        source_peer: PeerIdentity,
        ce_flag: bool,
        delivery: DecryptDirectSessionDelivery,
    ) {
        match delivery {
            DecryptDirectSessionDelivery::EndpointData(delivery) => {
                let Some(endpoint_event_tx) = &self.endpoint_event_tx else {
                    return;
                };
                let _t_deliver =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
                let event = NodeEndpointEvent::Data {
                    source_peer: delivery.source_peer,
                    payload: delivery.payload,
                    queued_at: crate::perf_profile::stamp(),
                };
                if let Err(error) = endpoint_event_tx.send(event) {
                    debug!(error = %error, "Failed to deliver worker-decoded endpoint data");
                }
            }
            DecryptDirectSessionDelivery::Ipv6Packet(mut packet) => {
                if ce_flag {
                    mark_ipv6_ecn_ce(&mut packet);
                }
                if let Some(external_packet_tx) = &self.external_packet_tx {
                    if packet.len() < 40 {
                        return;
                    }
                    let Ok(destination) = FipsAddress::from_slice(&packet[24..40]) else {
                        return;
                    };
                    let delivered = NodeDeliveredPacket {
                        source_node_addr: source_addr,
                        source_npub: Some(source_peer.npub()),
                        destination,
                        packet,
                    };
                    if let Err(error) = external_packet_tx.try_send(delivered) {
                        debug!(error = %error, "Failed to deliver worker-decoded packet to external app sink");
                    }
                    return;
                }
                if let Some(tun_tx) = &self.tun_tx {
                    let _t =
                        crate::perf_profile::Timer::start(crate::perf_profile::Stage::TunWrite);
                    if let Err(error) = tun_tx.send(packet) {
                        debug!(error = %error, "Failed to deliver worker-decoded IPv6 packet to TUN");
                    }
                }
            }
        }
    }
}

struct PendingDirectSessionDelivery {
    sink: DecryptDirectSessionDeliverySink,
    source_addr: NodeAddr,
    source_peer: PeerIdentity,
    ce_flag: bool,
    delivery: DecryptDirectSessionDelivery,
}

impl PendingDirectSessionDelivery {
    fn deliver(self) {
        self.sink.deliver(
            self.source_addr,
            self.source_peer,
            self.ce_flag,
            self.delivery,
        );
    }

    #[allow(clippy::result_large_err)]
    fn into_endpoint_data(
        self,
    ) -> Result<(DecryptDirectSessionDeliverySink, EndpointDataDelivery), Self> {
        match self.delivery {
            DecryptDirectSessionDelivery::EndpointData(delivery) => Ok((self.sink, delivery)),
            delivery => Err(Self {
                sink: self.sink,
                source_addr: self.source_addr,
                source_peer: self.source_peer,
                ce_flag: self.ce_flag,
                delivery,
            }),
        }
    }
}

impl PacketOutputTarget for PendingDirectSessionDelivery {
    fn output_target(&self) -> Option<OutputTarget> {
        self.sink.output_target_for(&self.delivery)
    }
}

pub(crate) struct DecryptDirectSessionData {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub previous_hop_peer: PeerIdentity,
    pub ce_flag: bool,
    pub receive_sync: FspReceiveSync,
    pub body_len: usize,
    pub delivery: DecryptDirectSessionDelivery,
    pub(crate) owner_reservation: Option<OwnerReservation>,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptDirectSessionData {
    #[cfg(test)]
    pub(in crate::node) fn for_test(
        fmp: DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        ce_flag: bool,
        receive_sync: FspReceiveSync,
        body_len: usize,
        delivery: DecryptDirectSessionDelivery,
    ) -> Self {
        Self {
            fmp,
            source_addr,
            previous_hop_peer,
            ce_flag,
            receive_sync,
            body_len,
            delivery,
            owner_reservation: None,
            lane: DecryptWorkerLane::Bulk,
            trace_enqueued_at: None,
        }
    }
}

pub(crate) struct DecryptDirectSessionCommit {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub previous_hop_peer: PeerIdentity,
    pub ce_flag: bool,
    pub receive_sync: FspReceiveSync,
    pub body_len: usize,
    pub delivered_ipv6: bool,
    pub(crate) owner_reservation: Option<OwnerReservation>,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptDirectSessionCommit {
    #[cfg(test)]
    pub(in crate::node) fn for_test(
        fmp: DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        ce_flag: bool,
        receive_sync: FspReceiveSync,
        body_len: usize,
        delivered_ipv6: bool,
    ) -> Self {
        Self {
            fmp,
            source_addr,
            previous_hop_peer,
            ce_flag,
            receive_sync,
            body_len,
            delivered_ipv6,
            owner_reservation: None,
            lane: DecryptWorkerLane::Bulk,
            trace_enqueued_at: None,
        }
    }
}

pub(crate) struct DecryptFspFailureReport {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub counter: u64,
    pub received_k_bit: bool,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

/// Event emitted by the decrypt worker to the rx_loop.
pub(crate) enum DecryptWorkerEvent {
    Plaintext(DecryptFallback),
    PlaintextBatch(Vec<DecryptFallback>),
    AuthenticatedFmpReceive(DecryptAuthenticatedFmpReceive),
    AuthenticatedSession(DecryptAuthenticatedSession),
    AuthenticatedSessionBatch(Vec<DecryptAuthenticatedSession>),
    DirectSessionCommit(DecryptDirectSessionCommit),
    DirectSessionCommitBatch(Vec<DecryptDirectSessionCommit>),
    DirectSessionData(DecryptDirectSessionData),
    DirectSessionDataBatch(Vec<DecryptDirectSessionData>),
    #[allow(dead_code)]
    FspDecryptFailure(DecryptFspFailureReport),
    DecryptFailure(DecryptFailureReport),
}

impl DecryptWorkerEvent {
    fn lane(&self) -> DecryptWorkerLane {
        decrypt_worker_event_lane(self)
    }

    pub(crate) fn packet_count(&self) -> usize {
        match self {
            Self::Plaintext(_) | Self::DecryptFailure(_) => 1,
            Self::AuthenticatedFmpReceive(_) => 1,
            Self::AuthenticatedSession(_) => 1,
            Self::AuthenticatedSessionBatch(sessions) => sessions.len(),
            Self::DirectSessionCommit(_) => 1,
            Self::DirectSessionCommitBatch(commits) => commits.len(),
            Self::DirectSessionData(_) => 1,
            Self::DirectSessionDataBatch(directs) => directs.len(),
            Self::FspDecryptFailure(_) => 1,
            Self::PlaintextBatch(fallbacks) => fallbacks.len(),
        }
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at = queued_at,
            Self::PlaintextBatch(fallbacks) => {
                for fallback in fallbacks {
                    fallback.trace_enqueued_at = queued_at;
                }
            }
            Self::AuthenticatedFmpReceive(receive) => receive.trace_enqueued_at = queued_at,
            Self::AuthenticatedSession(session) => session.trace_enqueued_at = queued_at,
            Self::AuthenticatedSessionBatch(sessions) => {
                for session in sessions {
                    session.trace_enqueued_at = queued_at;
                }
            }
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at = queued_at,
            Self::DirectSessionCommitBatch(commits) => {
                for commit in commits {
                    commit.trace_enqueued_at = queued_at;
                }
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at = queued_at,
            Self::DirectSessionDataBatch(directs) => {
                for direct in directs {
                    direct.trace_enqueued_at = queued_at;
                }
            }
            Self::FspDecryptFailure(report) => report.trace_enqueued_at = queued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at = queued_at,
        }
    }

    fn trace_enqueued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at,
            Self::PlaintextBatch(fallbacks) => fallbacks
                .first()
                .and_then(|fallback| fallback.trace_enqueued_at),
            Self::AuthenticatedFmpReceive(receive) => receive.trace_enqueued_at,
            Self::AuthenticatedSession(session) => session.trace_enqueued_at,
            Self::AuthenticatedSessionBatch(sessions) => sessions
                .first()
                .and_then(|session| session.trace_enqueued_at),
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at,
            Self::DirectSessionCommitBatch(commits) => {
                commits.first().and_then(|commit| commit.trace_enqueued_at)
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at,
            Self::DirectSessionDataBatch(directs) => {
                directs.first().and_then(|direct| direct.trace_enqueued_at)
            }
            Self::FspDecryptFailure(report) => report.trace_enqueued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at,
        }
    }

    fn queue_wait_stages(
        &self,
    ) -> (
        crate::perf_profile::Stage,
        crate::perf_profile::Stage,
        crate::perf_profile::Stage,
    ) {
        match self {
            Self::AuthenticatedFmpReceive(_) => (
                crate::perf_profile::Stage::DecryptAuthenticatedFmpReceiveWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionPriorityWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionBulkWait,
            ),
            Self::AuthenticatedSession(_)
            | Self::AuthenticatedSessionBatch(_)
            | Self::DirectSessionCommit(_)
            | Self::DirectSessionCommitBatch(_)
            | Self::DirectSessionData(_)
            | Self::DirectSessionDataBatch(_) => (
                crate::perf_profile::Stage::DecryptAuthenticatedSessionWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionPriorityWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionBulkWait,
            ),
            Self::Plaintext(_)
            | Self::PlaintextBatch(_)
            | Self::FspDecryptFailure(_)
            | Self::DecryptFailure(_) => (
                crate::perf_profile::Stage::DecryptFallbackWait,
                crate::perf_profile::Stage::DecryptFallbackPriorityWait,
                crate::perf_profile::Stage::DecryptFallbackBulkWait,
            ),
        }
    }

    fn direct_queue_wait_stage(&self) -> Option<crate::perf_profile::Stage> {
        match self {
            Self::DirectSessionCommit(_) | Self::DirectSessionCommitBatch(_) => {
                Some(crate::perf_profile::Stage::DecryptDirectSessionCommitWait)
            }
            Self::DirectSessionData(_) | Self::DirectSessionDataBatch(_) => {
                Some(crate::perf_profile::Stage::DecryptDirectSessionDataWait)
            }
            _ => None,
        }
    }

    pub(crate) fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at();
        if queued_at.is_none() {
            return;
        }
        let count = self.packet_count() as u64;
        let (priority_count, bulk_count) = match self.lane() {
            DecryptWorkerLane::Priority => (count, 0),
            DecryptWorkerLane::Bulk => (0, count),
        };
        let (total_stage, priority_stage, bulk_stage) = self.queue_wait_stages();
        crate::perf_profile::record_since_split_count(
            total_stage,
            priority_stage,
            bulk_stage,
            queued_at,
            count,
            priority_count,
            bulk_count,
        );
        if let Some(direct_stage) = self.direct_queue_wait_stage() {
            crate::perf_profile::record_since_count(direct_stage, queued_at, count);
        }
    }
}
