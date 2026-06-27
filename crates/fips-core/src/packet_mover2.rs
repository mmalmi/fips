//! Scratch packet mover for the intended straight dataplane.
//!
//! This module is intentionally separate from `packet_mover`: it models the
//! final ownership shape first, then old runtime edges can adapt into it. The
//! path is:
//!
//! ```text
//! UDP/socket drain
//!   -> bounded priority/bulk admission
//!   -> peer/session owner sequencer
//!   -> stateless crypto workers
//!   -> ordered owner retire
//!   -> TUN/endpoint/transport output
//! ```
//!
//! The core invariant is simple: owners reserve replay, order, generation, and
//! in-flight state before crypto work leaves the owner; workers only copy/open
//! bytes and return completions; owners retire those completions in order.

use crate::transport::{PacketBuffer, ReceivedPacket, TransportAddr, TransportId};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

const FMP_VERSION: u8 = crate::node::wire::FMP_VERSION;
const FMP_PHASE_ESTABLISHED: u8 = crate::node::wire::PHASE_ESTABLISHED;
const FMP_ESTABLISHED_HEADER_SIZE: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
const FSP_VERSION: u8 = crate::node::session_wire::FSP_VERSION;
const FSP_PHASE_ESTABLISHED: u8 = crate::node::session_wire::FSP_PHASE_ESTABLISHED;
const FSP_HEADER_SIZE: usize = crate::node::session_wire::FSP_HEADER_SIZE;
const FSP_FLAG_U: u8 = crate::node::session_wire::FSP_FLAG_U;
const AEAD_TAG_SIZE: usize = crate::noise::TAG_SIZE;

pub(crate) type AeadKey = Arc<LessSafeKey>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PacketProtocol {
    Fmp,
    Fsp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OwnerId {
    peer: u64,
    protocol: PacketProtocol,
}

impl OwnerId {
    pub(crate) fn fmp(peer: u64) -> Self {
        Self {
            peer,
            protocol: PacketProtocol::Fmp,
        }
    }

    pub(crate) fn fsp(peer: u64) -> Self {
        Self {
            peer,
            protocol: PacketProtocol::Fsp,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketClass {
    Control,
    Rekey,
    Mmp,
    Liveness,
    Bulk,
}

impl PacketClass {
    fn lane(self) -> Lane {
        match self {
            Self::Control | Self::Rekey | Self::Mmp | Self::Liveness => Lane::Priority,
            Self::Bulk => Lane::Bulk,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lane {
    Priority,
    Bulk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputTarget {
    Tun,
    Endpoint,
    Transport,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TransportPath(u64);

impl TransportPath {
    pub(crate) fn new(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ActivityTick(u64);

impl ActivityTick {
    pub(crate) fn new(tick: u64) -> Self {
        Self(tick)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocketPacket {
    owner: OwnerId,
    generation: u64,
    counter: u64,
    class: PacketClass,
    output: OutputTarget,
    source_path: Option<TransportPath>,
    activity_tick: Option<ActivityTick>,
    payload: PacketBuffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundWire {
    Fmp { receiver_idx: u32, flags: u8 },
    Fsp { flags: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundPacket {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    wire: OutboundWire,
    activity_tick: Option<ActivityTick>,
    payload: PacketBuffer,
}

impl OutboundPacket {
    pub(crate) fn fmp(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        receiver_idx: u32,
        flags: u8,
        payload: impl Into<PacketBuffer>,
    ) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fmp {
                receiver_idx,
                flags,
            },
            activity_tick: None,
            payload: payload.into(),
        }
    }

    pub(crate) fn fsp(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        flags: u8,
        payload: impl Into<PacketBuffer>,
    ) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fsp { flags },
            activity_tick: None,
            payload: payload.into(),
        }
    }

    pub(crate) fn with_activity_tick(mut self, tick: ActivityTick) -> Self {
        self.activity_tick = Some(tick);
        self
    }

    fn lane(&self) -> Lane {
        self.class.lane()
    }
}

impl SocketPacket {
    pub(crate) fn new(
        owner: OwnerId,
        generation: u64,
        counter: u64,
        class: PacketClass,
        output: OutputTarget,
        payload: impl Into<PacketBuffer>,
    ) -> Self {
        Self {
            owner,
            generation,
            counter,
            class,
            output,
            source_path: None,
            activity_tick: None,
            payload: payload.into(),
        }
    }

    pub(crate) fn with_source_path(mut self, path: TransportPath) -> Self {
        self.source_path = Some(path);
        self
    }

    pub(crate) fn with_activity_tick(mut self, tick: ActivityTick) -> Self {
        self.activity_tick = Some(tick);
        self
    }

    fn lane(&self) -> Lane {
        self.class.lane()
    }

    pub(crate) fn from_fmp_established_wire(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        data: impl Into<PacketBuffer>,
    ) -> Result<Self, WirePreflightError> {
        let payload: PacketBuffer = data.into();
        let header = FmpWireHeader::parse(&payload)?;
        Ok(Self::new(
            owner,
            generation,
            header.counter,
            PacketClass::Bulk,
            output,
            payload,
        ))
    }

    pub(crate) fn from_fsp_established_wire(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        data: impl Into<PacketBuffer>,
    ) -> Result<Self, WirePreflightError> {
        let payload: PacketBuffer = data.into();
        let header = FspWireHeader::parse(&payload)?;
        Ok(Self::new(
            owner,
            generation,
            header.counter,
            PacketClass::Bulk,
            output,
            payload,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WirePreflightError {
    TooShort,
    WrongVersion,
    WrongPhase,
    PlaintextFsp,
    CounterMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireBuildError {
    PayloadTooLarge,
    ProtocolMismatch,
    PlaintextFsp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FmpWireHeader {
    receiver_idx: u32,
    counter: u64,
    flags: u8,
    header_bytes: [u8; FMP_ESTABLISHED_HEADER_SIZE],
    ciphertext_offset: usize,
}

impl FmpWireHeader {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, WirePreflightError> {
        if data.len() < FMP_ESTABLISHED_HEADER_SIZE {
            return Err(WirePreflightError::TooShort);
        }
        let version = data[0] >> 4;
        if version != FMP_VERSION {
            return Err(WirePreflightError::WrongVersion);
        }
        let phase = data[0] & 0x0f;
        if phase != FMP_PHASE_ESTABLISHED {
            return Err(WirePreflightError::WrongPhase);
        }

        let mut header_bytes = [0u8; FMP_ESTABLISHED_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..FMP_ESTABLISHED_HEADER_SIZE]);

        Ok(Self {
            receiver_idx: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            counter: u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
            flags: data[1],
            header_bytes,
            ciphertext_offset: FMP_ESTABLISHED_HEADER_SIZE,
        })
    }

    pub(crate) fn receiver_idx(self) -> u32 {
        self.receiver_idx
    }

    pub(crate) fn counter(self) -> u64 {
        self.counter
    }

    pub(crate) fn flags(self) -> u8 {
        self.flags
    }

    pub(crate) fn header_bytes(self) -> [u8; FMP_ESTABLISHED_HEADER_SIZE] {
        self.header_bytes
    }

    pub(crate) fn ciphertext_offset(self) -> usize {
        self.ciphertext_offset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FspWireHeader {
    counter: u64,
    flags: u8,
    header_bytes: [u8; FSP_HEADER_SIZE],
    ciphertext_offset: usize,
}

impl FspWireHeader {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, WirePreflightError> {
        if data.len() < FSP_HEADER_SIZE {
            return Err(WirePreflightError::TooShort);
        }
        let version = data[0] >> 4;
        if version != FSP_VERSION {
            return Err(WirePreflightError::WrongVersion);
        }
        let phase = data[0] & 0x0f;
        if phase != FSP_PHASE_ESTABLISHED {
            return Err(WirePreflightError::WrongPhase);
        }
        let flags = data[1];
        if flags & FSP_FLAG_U != 0 {
            return Err(WirePreflightError::PlaintextFsp);
        }

        let mut header_bytes = [0u8; FSP_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..FSP_HEADER_SIZE]);

        Ok(Self {
            counter: u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]),
            flags,
            header_bytes,
            ciphertext_offset: FSP_HEADER_SIZE,
        })
    }

    pub(crate) fn counter(self) -> u64 {
        self.counter
    }

    pub(crate) fn flags(self) -> u8 {
        self.flags
    }

    pub(crate) fn header_bytes(self) -> [u8; FSP_HEADER_SIZE] {
        self.header_bytes
    }

    pub(crate) fn ciphertext_offset(self) -> usize {
        self.ciphertext_offset
    }
}

fn build_fmp_established_header(
    receiver_idx: u32,
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> [u8; FMP_ESTABLISHED_HEADER_SIZE] {
    let mut header = [0u8; FMP_ESTABLISHED_HEADER_SIZE];
    header[0] = (FMP_VERSION << 4) | FMP_PHASE_ESTABLISHED;
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
    header[8..16].copy_from_slice(&counter.to_le_bytes());
    header
}

fn build_fsp_established_header(
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> Result<[u8; FSP_HEADER_SIZE], WireBuildError> {
    if flags & FSP_FLAG_U != 0 {
        return Err(WireBuildError::PlaintextFsp);
    }

    let mut header = [0u8; FSP_HEADER_SIZE];
    header[0] = (FSP_VERSION << 4) | FSP_PHASE_ESTABLISHED;
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..12].copy_from_slice(&counter.to_le_bytes());
    Ok(header)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionConfig {
    priority_capacity: usize,
    bulk_capacity: usize,
}

impl AdmissionConfig {
    pub(crate) fn new(priority_capacity: usize, bulk_capacity: usize) -> Self {
        Self {
            priority_capacity,
            bulk_capacity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDropReason {
    PriorityFull,
    BulkFull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionDrop {
    owner: OwnerId,
    counter: u64,
    class: PacketClass,
    lane: Lane,
    payload_len: usize,
    reason: AdmissionDropReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedPacket {
    ingress_seq: u64,
    packet: SocketPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedOutboundPacket {
    ingress_seq: u64,
    packet: OutboundPacket,
}

#[derive(Debug)]
pub(crate) struct AdmissionQueue {
    config: AdmissionConfig,
    next_ingress_seq: u64,
    priority: VecDeque<QueuedPacket>,
    bulk: VecDeque<QueuedPacket>,
}

impl AdmissionQueue {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            next_ingress_seq: 0,
            priority: VecDeque::with_capacity(config.priority_capacity),
            bulk: VecDeque::with_capacity(config.bulk_capacity),
        }
    }

    pub(crate) fn admit(&mut self, packet: SocketPacket) -> Result<u64, AdmissionDrop> {
        let lane = packet.lane();
        let target = match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
        };
        let capacity = match lane {
            Lane::Priority => self.config.priority_capacity,
            Lane::Bulk => self.config.bulk_capacity,
        };

        if target.len() >= capacity {
            return Err(AdmissionDrop {
                owner: packet.owner,
                counter: packet.counter,
                class: packet.class,
                lane,
                payload_len: packet.payload.len(),
                reason: match lane {
                    Lane::Priority => AdmissionDropReason::PriorityFull,
                    Lane::Bulk => AdmissionDropReason::BulkFull,
                },
            });
        }

        let ingress_seq = self.next_ingress_seq;
        self.next_ingress_seq = self.next_ingress_seq.wrapping_add(1);
        target.push_back(QueuedPacket {
            ingress_seq,
            packet,
        });
        Ok(ingress_seq)
    }

    fn pop_next(&mut self) -> Option<QueuedPacket> {
        self.priority.pop_front().or_else(|| self.bulk.pop_front())
    }

    #[cfg(test)]
    fn lens(&self) -> (usize, usize) {
        (self.priority.len(), self.bulk.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundAdmissionDrop {
    owner: OwnerId,
    class: PacketClass,
    lane: Lane,
    payload_len: usize,
    reason: AdmissionDropReason,
}

#[derive(Debug)]
pub(crate) struct OutboundAdmissionQueue {
    config: AdmissionConfig,
    next_ingress_seq: u64,
    priority: VecDeque<QueuedOutboundPacket>,
    bulk: VecDeque<QueuedOutboundPacket>,
}

impl OutboundAdmissionQueue {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            next_ingress_seq: 0,
            priority: VecDeque::with_capacity(config.priority_capacity),
            bulk: VecDeque::with_capacity(config.bulk_capacity),
        }
    }

    pub(crate) fn admit(&mut self, packet: OutboundPacket) -> Result<u64, OutboundAdmissionDrop> {
        let lane = packet.lane();
        let target = match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
        };
        let capacity = match lane {
            Lane::Priority => self.config.priority_capacity,
            Lane::Bulk => self.config.bulk_capacity,
        };

        if target.len() >= capacity {
            return Err(OutboundAdmissionDrop {
                owner: packet.owner,
                class: packet.class,
                lane,
                payload_len: packet.payload.len(),
                reason: match lane {
                    Lane::Priority => AdmissionDropReason::PriorityFull,
                    Lane::Bulk => AdmissionDropReason::BulkFull,
                },
            });
        }

        let ingress_seq = self.next_ingress_seq;
        self.next_ingress_seq = self.next_ingress_seq.wrapping_add(1);
        target.push_back(QueuedOutboundPacket {
            ingress_seq,
            packet,
        });
        Ok(ingress_seq)
    }

    fn pop_next(&mut self) -> Option<QueuedOutboundPacket> {
        self.priority.pop_front().or_else(|| self.bulk.pop_front())
    }

    #[cfg(test)]
    fn lens(&self) -> (usize, usize) {
        (self.priority.len(), self.bulk.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerConfig {
    generation: u64,
    in_flight_limit: usize,
    next_send_counter: u64,
}

impl OwnerConfig {
    pub(crate) fn new(generation: u64, in_flight_limit: usize) -> Self {
        Self {
            generation,
            in_flight_limit,
            next_send_counter: 0,
        }
    }

    pub(crate) fn with_next_send_counter(mut self, next_send_counter: u64) -> Self {
        self.next_send_counter = next_send_counter;
        self
    }
}

#[derive(Clone)]
pub(crate) struct OwnerCryptoKeys {
    open: AeadKey,
    seal: AeadKey,
}

impl OwnerCryptoKeys {
    pub(crate) fn new(open: AeadKey, seal: AeadKey) -> Self {
        Self { open, seal }
    }
}

impl std::fmt::Debug for OwnerCryptoKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerCryptoKeys").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct OrderToken(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerReservation {
    owner: OwnerId,
    generation: u64,
    order: OrderToken,
    ingress_seq: u64,
    counter: u64,
    lane: Lane,
    output_path: Option<TransportPath>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerReserveError {
    Replay,
    InFlightFull,
    StaleGeneration,
}

#[derive(Debug)]
pub(crate) struct OwnerState {
    owner: OwnerId,
    generation: u64,
    in_flight_limit: usize,
    in_flight: usize,
    next_order: u64,
    next_retire: u64,
    next_send_counter: u64,
    crypto_keys: Option<OwnerCryptoKeys>,
    active_path: Option<TransportPath>,
    last_rx_activity: Option<ActivityTick>,
    last_tx_activity: Option<ActivityTick>,
    last_hard_event: Option<ActivityTick>,
    hard_events: u64,
    accepted_counters: HashSet<u64>,
    pending: BTreeMap<OrderToken, CryptoCompletion>,
}

impl OwnerState {
    pub(crate) fn new(owner: OwnerId, config: OwnerConfig) -> Self {
        Self {
            owner,
            generation: config.generation,
            in_flight_limit: config.in_flight_limit,
            in_flight: 0,
            next_order: 0,
            next_retire: 0,
            next_send_counter: config.next_send_counter,
            crypto_keys: None,
            active_path: None,
            last_rx_activity: None,
            last_tx_activity: None,
            last_hard_event: None,
            hard_events: 0,
            accepted_counters: HashSet::new(),
            pending: BTreeMap::new(),
        }
    }

    pub(crate) fn rekey(&mut self, generation: u64) {
        self.generation = generation;
        self.accepted_counters.clear();
        self.next_send_counter = 0;
        self.crypto_keys = None;
    }

    pub(crate) fn set_crypto_keys(&mut self, keys: OwnerCryptoKeys) {
        self.crypto_keys = Some(keys);
    }

    fn crypto_keys(&self) -> Option<OwnerCryptoKeys> {
        self.crypto_keys.clone()
    }

    pub(crate) fn set_active_path(&mut self, path: TransportPath) {
        self.active_path = Some(path);
    }

    pub(crate) fn active_path(&self) -> Option<TransportPath> {
        self.active_path
    }

    pub(crate) fn last_rx_activity(&self) -> Option<ActivityTick> {
        self.last_rx_activity
    }

    pub(crate) fn last_tx_activity(&self) -> Option<ActivityTick> {
        self.last_tx_activity
    }

    pub(crate) fn last_hard_event(&self) -> Option<ActivityTick> {
        self.last_hard_event
    }

    pub(crate) fn hard_events(&self) -> u64 {
        self.hard_events
    }

    pub(crate) fn record_hard_event(&mut self, tick: ActivityTick) {
        self.hard_events = self.hard_events.saturating_add(1);
        note_activity(&mut self.last_hard_event, tick);
    }

    pub(crate) fn reserve(
        &mut self,
        packet: &SocketPacket,
        ingress_seq: u64,
    ) -> Result<OwnerReservation, OwnerReserveError> {
        if packet.generation != self.generation {
            return Err(OwnerReserveError::StaleGeneration);
        }
        if self.accepted_counters.contains(&packet.counter) {
            return Err(OwnerReserveError::Replay);
        }
        if self.in_flight >= self.in_flight_limit {
            return Err(OwnerReserveError::InFlightFull);
        }

        self.accepted_counters.insert(packet.counter);
        if let Some(path) = packet.source_path {
            self.active_path = Some(path);
        }
        if let Some(tick) = packet.activity_tick {
            note_activity(&mut self.last_rx_activity, tick);
        }
        self.in_flight += 1;
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        Ok(OwnerReservation {
            owner: self.owner,
            generation: self.generation,
            order,
            ingress_seq,
            counter: packet.counter,
            lane: packet.lane(),
            output_path: None,
        })
    }

    pub(crate) fn reserve_outbound(
        &mut self,
        packet: &OutboundPacket,
        ingress_seq: u64,
    ) -> Result<OwnerReservation, OwnerReserveError> {
        if packet.generation != self.generation {
            return Err(OwnerReserveError::StaleGeneration);
        }
        if self.in_flight >= self.in_flight_limit {
            return Err(OwnerReserveError::InFlightFull);
        }

        let counter = self.next_send_counter;
        let output_path = self.active_path;
        if let Some(tick) = packet.activity_tick {
            note_activity(&mut self.last_tx_activity, tick);
        }
        self.next_send_counter = self.next_send_counter.wrapping_add(1);
        self.in_flight += 1;
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        Ok(OwnerReservation {
            owner: self.owner,
            generation: self.generation,
            order,
            ingress_seq,
            counter,
            lane: packet.lane(),
            output_path,
        })
    }

    pub(crate) fn retire(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        self.pending
            .insert(completion.reservation.order, completion);
        let mut retired = Vec::new();

        while let Some(completion) = self.pending.remove(&OrderToken(self.next_retire)) {
            self.next_retire = self.next_retire.wrapping_add(1);
            self.in_flight = self.in_flight.saturating_sub(1);

            if completion.reservation.generation != self.generation {
                retired.push(RetiredPacket::Drop(PacketDrop::from_completion(
                    &completion,
                    PacketDropReason::StaleCompletionGeneration,
                )));
                continue;
            }

            match completion.result {
                CryptoResult::Opened(output) => retired.push(RetiredPacket::Output(output)),
                CryptoResult::Sealed(output) => retired.push(RetiredPacket::Output(output)),
                CryptoResult::Failed => {
                    retired.push(RetiredPacket::Drop(PacketDrop::from_completion(
                        &completion,
                        PacketDropReason::CryptoFailed,
                    )));
                }
            }
        }

        retired
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.in_flight
    }

    #[cfg(test)]
    fn next_send_counter(&self) -> u64 {
        self.next_send_counter
    }
}

fn note_activity(slot: &mut Option<ActivityTick>, tick: ActivityTick) {
    match slot {
        Some(current) if *current >= tick => {}
        _ => *slot = Some(tick),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoWork {
    reservation: OwnerReservation,
    packet: SocketPacket,
}

impl CryptoWork {
    #[cfg(test)]
    fn order(&self) -> u64 {
        self.reservation.order.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundCryptoWork {
    reservation: OwnerReservation,
    packet: OutboundPacket,
}

impl OutboundCryptoWork {
    #[cfg(test)]
    fn order(&self) -> u64 {
        self.reservation.order.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoCompletion {
    reservation: OwnerReservation,
    result: CryptoResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CryptoResult {
    Opened(PacketOutput),
    Sealed(PacketOutput),
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketOutput {
    owner: OwnerId,
    counter: u64,
    ingress_seq: u64,
    target: OutputTarget,
    path: Option<TransportPath>,
    payload: PacketBuffer,
}

impl PacketOutput {
    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn ingress_seq(&self) -> u64 {
        self.ingress_seq
    }

    pub(crate) fn target(&self) -> OutputTarget {
        self.target
    }

    pub(crate) fn path(&self) -> Option<TransportPath> {
        self.path
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub(crate) fn into_payload(self) -> PacketBuffer {
        self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetiredPacket {
    Output(PacketOutput),
    Drop(PacketDrop),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketDropReason {
    Admission(AdmissionDropReason),
    UnknownOwner,
    Replay,
    OwnerInFlightFull,
    StaleGeneration,
    StaleCompletionGeneration,
    CryptoFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketDrop {
    owner: OwnerId,
    counter: Option<u64>,
    ingress_seq: Option<u64>,
    lane: Lane,
    reason: PacketDropReason,
}

impl PacketDrop {
    fn from_queued(queued: &QueuedPacket, reason: PacketDropReason) -> Self {
        Self {
            owner: queued.packet.owner,
            counter: Some(queued.packet.counter),
            ingress_seq: Some(queued.ingress_seq),
            lane: queued.packet.lane(),
            reason,
        }
    }

    fn from_queued_outbound(queued: &QueuedOutboundPacket, reason: PacketDropReason) -> Self {
        Self {
            owner: queued.packet.owner,
            counter: None,
            ingress_seq: Some(queued.ingress_seq),
            lane: queued.packet.lane(),
            reason,
        }
    }

    fn from_completion(completion: &CryptoCompletion, reason: PacketDropReason) -> Self {
        Self {
            owner: completion.reservation.owner,
            counter: Some(completion.reservation.counter),
            ingress_seq: Some(completion.reservation.ingress_seq),
            lane: completion.reservation.lane,
            reason,
        }
    }
}

impl From<AdmissionDrop> for PacketDrop {
    fn from(drop: AdmissionDrop) -> Self {
        Self {
            owner: drop.owner,
            counter: Some(drop.counter),
            ingress_seq: None,
            lane: drop.lane,
            reason: PacketDropReason::Admission(drop.reason),
        }
    }
}

impl From<OutboundAdmissionDrop> for PacketDrop {
    fn from(drop: OutboundAdmissionDrop) -> Self {
        Self {
            owner: drop.owner,
            counter: None,
            ingress_seq: None,
            lane: drop.lane,
            reason: PacketDropReason::Admission(drop.reason),
        }
    }
}

impl From<OwnerReserveError> for PacketDropReason {
    fn from(error: OwnerReserveError) -> Self {
        match error {
            OwnerReserveError::Replay => Self::Replay,
            OwnerReserveError::InFlightFull => Self::OwnerInFlightFull,
            OwnerReserveError::StaleGeneration => Self::StaleGeneration,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AdmissionBatchSummary {
    admitted: usize,
    dropped: usize,
}

impl AdmissionBatchSummary {
    pub(crate) fn admitted(self) -> usize {
        self.admitted
    }

    pub(crate) fn dropped(self) -> usize {
        self.dropped
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketMoverTurn {
    dispatched: usize,
    retired: Vec<RetiredPacket>,
    drops: Vec<PacketDrop>,
}

impl PacketMoverTurn {
    pub(crate) fn dispatched(&self) -> usize {
        self.dispatched
    }

    pub(crate) fn retired(&self) -> &[RetiredPacket] {
        &self.retired
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        &self.drops
    }

    #[cfg(test)]
    fn outputs(&self) -> Vec<&PacketOutput> {
        self.retired
            .iter()
            .filter_map(|item| match item {
                RetiredPacket::Output(output) => Some(output),
                RetiredPacket::Drop(_) => None,
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2RawIngress {
    protocol: PacketProtocol,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    path: TransportPath,
    activity_tick: Option<ActivityTick>,
    payload: PacketBuffer,
}

impl PacketMover2RawIngress {
    pub(crate) fn from_received(
        protocol: PacketProtocol,
        path: TransportPath,
        packet: ReceivedPacket,
    ) -> Self {
        Self {
            protocol,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr,
            path,
            activity_tick: Some(ActivityTick::new(packet.timestamp_ms)),
            payload: packet.data,
        }
    }

    pub(crate) fn protocol(&self) -> PacketProtocol {
        self.protocol
    }

    pub(crate) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    pub(crate) fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    pub(crate) fn path(&self) -> TransportPath {
        self.path
    }

    pub(crate) fn activity_tick(&self) -> Option<ActivityTick> {
        self.activity_tick
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2IngressHeader {
    Fmp(FmpWireHeader),
    Fsp(FspWireHeader),
}

impl PacketMover2IngressHeader {
    pub(crate) fn counter(self) -> u64 {
        match self {
            Self::Fmp(header) => header.counter(),
            Self::Fsp(header) => header.counter(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2IngressRoute {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    output: OutputTarget,
}

impl PacketMover2IngressRoute {
    pub(crate) fn new(owner: OwnerId, generation: u64, output: OutputTarget) -> Self {
        Self {
            owner,
            generation,
            class: PacketClass::Bulk,
            output,
        }
    }

    pub(crate) fn with_class(mut self, class: PacketClass) -> Self {
        self.class = class;
        self
    }
}

pub(crate) trait PacketMover2IngressRouter {
    fn route(
        &mut self,
        packet: &PacketMover2RawIngress,
        header: PacketMover2IngressHeader,
    ) -> Option<PacketMover2IngressRoute>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2RawIngressDropReason {
    Wire(WirePreflightError),
    Unrouted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2RawIngressDrop {
    protocol: PacketProtocol,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    path: TransportPath,
    payload_len: usize,
    reason: PacketMover2RawIngressDropReason,
}

impl PacketMover2RawIngressDrop {
    fn from_packet(
        packet: PacketMover2RawIngress,
        reason: PacketMover2RawIngressDropReason,
    ) -> Self {
        Self {
            protocol: packet.protocol,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr,
            path: packet.path,
            payload_len: packet.payload.len(),
            reason,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2OutputError {
    Unavailable,
    Backpressure,
    NoRoute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2OutputDrop {
    owner: OwnerId,
    counter: u64,
    ingress_seq: u64,
    target: OutputTarget,
    path: Option<TransportPath>,
    payload_len: usize,
    reason: PacketMover2OutputError,
}

impl PacketMover2OutputDrop {
    pub(crate) fn from_output(output: &PacketOutput, reason: PacketMover2OutputError) -> Self {
        Self {
            owner: output.owner,
            counter: output.counter,
            ingress_seq: output.ingress_seq,
            target: output.target,
            path: output.path,
            payload_len: output.payload.len(),
            reason,
        }
    }
}

pub(crate) trait PacketMover2OutputSink {
    fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError>;

    fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<PacketMover2OutputDrop>) -> usize
    where
        I: IntoIterator<Item = PacketOutput>,
    {
        let mut sent = 0;
        for output in outputs {
            let mut drop =
                PacketMover2OutputDrop::from_output(&output, PacketMover2OutputError::Unavailable);
            match self.send(output) {
                Ok(()) => sent += 1,
                Err(reason) => {
                    drop.reason = reason;
                    drops.push(drop);
                }
            }
        }
        sent
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketMover2RuntimeSummary {
    raw_ingress_dropped: usize,
    inbound_admitted: usize,
    inbound_dropped: usize,
    outbound_admitted: usize,
    outbound_dropped: usize,
    dispatched: usize,
    outputs: usize,
    outputs_sent: usize,
    outputs_dropped: usize,
    drops: usize,
}

impl PacketMover2RuntimeSummary {
    pub(crate) fn raw_ingress_dropped(self) -> usize {
        self.raw_ingress_dropped
    }

    pub(crate) fn inbound_admitted(self) -> usize {
        self.inbound_admitted
    }

    pub(crate) fn inbound_dropped(self) -> usize {
        self.inbound_dropped
    }

    pub(crate) fn outbound_admitted(self) -> usize {
        self.outbound_admitted
    }

    pub(crate) fn outbound_dropped(self) -> usize {
        self.outbound_dropped
    }

    pub(crate) fn dispatched(self) -> usize {
        self.dispatched
    }

    pub(crate) fn outputs(self) -> usize {
        self.outputs
    }

    pub(crate) fn outputs_sent(self) -> usize {
        self.outputs_sent
    }

    pub(crate) fn outputs_dropped(self) -> usize {
        self.outputs_dropped
    }

    pub(crate) fn drops(self) -> usize {
        self.drops
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2RuntimeTurn<'a> {
    summary: PacketMover2RuntimeSummary,
    raw_ingress_drops: &'a [PacketMover2RawIngressDrop],
    output_drops: &'a [PacketMover2OutputDrop],
    outputs: &'a [PacketOutput],
    drops: &'a [PacketDrop],
}

impl PacketMover2RuntimeTurn<'_> {
    pub(crate) fn summary(&self) -> PacketMover2RuntimeSummary {
        self.summary
    }

    pub(crate) fn raw_ingress_drops(&self) -> &[PacketMover2RawIngressDrop] {
        self.raw_ingress_drops
    }

    pub(crate) fn output_drops(&self) -> &[PacketMover2OutputDrop] {
        self.output_drops
    }

    pub(crate) fn outputs(&self) -> &[PacketOutput] {
        self.outputs
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        self.drops
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2TurnDriver<W = CopyCryptoWorker> {
    mover: PacketMover2<W>,
    open_work: Vec<CryptoWork>,
    seal_work: Vec<OutboundCryptoWork>,
    raw_ingress_drops: Vec<PacketMover2RawIngressDrop>,
    output_drops: Vec<PacketMover2OutputDrop>,
    outputs: Vec<PacketOutput>,
    drops: Vec<PacketDrop>,
}

impl<W: StatelessCryptoWorker> PacketMover2TurnDriver<W> {
    pub(crate) fn new(config: AdmissionConfig, worker: W) -> Self {
        Self {
            mover: PacketMover2::new(config, worker),
            open_work: Vec::new(),
            seal_work: Vec::new(),
            raw_ingress_drops: Vec::new(),
            output_drops: Vec::new(),
            outputs: Vec::new(),
            drops: Vec::new(),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.mover.register_owner(owner, config);
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.mover.owner_mut(owner)
    }

    pub(crate) fn mover_mut(&mut self) -> &mut PacketMover2<W> {
        &mut self.mover
    }

    pub(crate) fn run_aead_classified_turn<I, O>(
        &mut self,
        inbound: I,
        outbound: O,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = SocketPacket>,
        O: IntoIterator<Item = OutboundPacket>,
    {
        self.outputs.clear();
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();

        let mut summary = PacketMover2RuntimeSummary::default();
        for packet in inbound {
            match self.mover.submit_socket_packet(packet) {
                Ok(_) => summary.inbound_admitted += 1,
                Err(_) => summary.inbound_dropped += 1,
            }
        }
        for packet in outbound {
            match self.mover.submit_outbound_packet(packet) {
                Ok(_) => summary.outbound_admitted += 1,
                Err(_) => summary.outbound_dropped += 1,
            }
        }

        self.finish_aead_turn(summary, limit)
    }

    pub(crate) fn run_aead_classified_output_turn<I, O, S>(
        &mut self,
        inbound: I,
        outbound: O,
        sink: &mut S,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = SocketPacket>,
        O: IntoIterator<Item = OutboundPacket>,
        S: PacketMover2OutputSink,
    {
        self.outputs.clear();
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();

        let mut summary = PacketMover2RuntimeSummary::default();
        for packet in inbound {
            match self.mover.submit_socket_packet(packet) {
                Ok(_) => summary.inbound_admitted += 1,
                Err(_) => summary.inbound_dropped += 1,
            }
        }
        for packet in outbound {
            match self.mover.submit_outbound_packet(packet) {
                Ok(_) => summary.outbound_admitted += 1,
                Err(_) => summary.outbound_dropped += 1,
            }
        }

        self.finish_aead_output_turn(summary, sink, limit)
    }

    pub(crate) fn run_aead_raw_ingress_turn<I, O, R>(
        &mut self,
        inbound: I,
        router: &mut R,
        outbound: O,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = PacketMover2RawIngress>,
        O: IntoIterator<Item = OutboundPacket>,
        R: PacketMover2IngressRouter,
    {
        self.outputs.clear();
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();

        let summary = self.admit_raw_ingress_turn(inbound, router, outbound);
        self.finish_aead_turn(summary, limit)
    }

    pub(crate) fn run_aead_raw_ingress_output_turn<I, O, R, S>(
        &mut self,
        inbound: I,
        router: &mut R,
        outbound: O,
        sink: &mut S,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = PacketMover2RawIngress>,
        O: IntoIterator<Item = OutboundPacket>,
        R: PacketMover2IngressRouter,
        S: PacketMover2OutputSink,
    {
        self.outputs.clear();
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();

        let summary = self.admit_raw_ingress_turn(inbound, router, outbound);
        self.finish_aead_output_turn(summary, sink, limit)
    }

    fn admit_raw_ingress_turn<I, O, R>(
        &mut self,
        inbound: I,
        router: &mut R,
        outbound: O,
    ) -> PacketMover2RuntimeSummary
    where
        I: IntoIterator<Item = PacketMover2RawIngress>,
        O: IntoIterator<Item = OutboundPacket>,
        R: PacketMover2IngressRouter,
    {
        let mut summary = PacketMover2RuntimeSummary::default();
        for packet in inbound {
            let header = match packet.protocol {
                PacketProtocol::Fmp => match FmpWireHeader::parse(&packet.payload) {
                    Ok(header) => PacketMover2IngressHeader::Fmp(header),
                    Err(error) => {
                        summary.raw_ingress_dropped += 1;
                        self.raw_ingress_drops
                            .push(PacketMover2RawIngressDrop::from_packet(
                                packet,
                                PacketMover2RawIngressDropReason::Wire(error),
                            ));
                        continue;
                    }
                },
                PacketProtocol::Fsp => match FspWireHeader::parse(&packet.payload) {
                    Ok(header) => PacketMover2IngressHeader::Fsp(header),
                    Err(error) => {
                        summary.raw_ingress_dropped += 1;
                        self.raw_ingress_drops
                            .push(PacketMover2RawIngressDrop::from_packet(
                                packet,
                                PacketMover2RawIngressDropReason::Wire(error),
                            ));
                        continue;
                    }
                },
            };

            let Some(route) = router.route(&packet, header) else {
                summary.raw_ingress_dropped += 1;
                self.raw_ingress_drops
                    .push(PacketMover2RawIngressDrop::from_packet(
                        packet,
                        PacketMover2RawIngressDropReason::Unrouted,
                    ));
                continue;
            };

            let mut socket_packet = SocketPacket::new(
                route.owner,
                route.generation,
                header.counter(),
                route.class,
                route.output,
                packet.payload,
            )
            .with_source_path(packet.path);
            if let Some(tick) = packet.activity_tick {
                socket_packet = socket_packet.with_activity_tick(tick);
            }
            match self.mover.submit_socket_packet(socket_packet) {
                Ok(_) => summary.inbound_admitted += 1,
                Err(_) => summary.inbound_dropped += 1,
            }
        }
        for packet in outbound {
            match self.mover.submit_outbound_packet(packet) {
                Ok(_) => summary.outbound_admitted += 1,
                Err(_) => summary.outbound_dropped += 1,
            }
        }
        summary
    }

    fn finish_aead_turn(
        &mut self,
        summary: PacketMover2RuntimeSummary,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_> {
        let summary = self.collect_aead_outputs(summary, limit);

        PacketMover2RuntimeTurn {
            summary,
            raw_ingress_drops: &self.raw_ingress_drops,
            output_drops: &self.output_drops,
            outputs: &self.outputs,
            drops: &self.drops,
        }
    }

    fn finish_aead_output_turn<S>(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        sink: &mut S,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        S: PacketMover2OutputSink,
    {
        summary = self.collect_aead_outputs(summary, limit);
        let dropped_before = self.output_drops.len();
        let sent = sink.send_batch(self.outputs.drain(..), &mut self.output_drops);
        summary.outputs_sent += sent;
        summary.outputs_dropped += self.output_drops.len().saturating_sub(dropped_before);

        PacketMover2RuntimeTurn {
            summary,
            raw_ingress_drops: &self.raw_ingress_drops,
            output_drops: &self.output_drops,
            outputs: &self.outputs,
            drops: &self.drops,
        }
    }

    fn collect_aead_outputs(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        limit: usize,
    ) -> PacketMover2RuntimeSummary {
        let PacketMoverTurn {
            dispatched,
            retired,
            drops,
        } = self.mover.run_aead_available_with_scratch(
            limit,
            &mut self.open_work,
            &mut self.seal_work,
        );
        summary.dispatched = dispatched;
        self.drops.extend(drops);

        for packet in retired {
            if let RetiredPacket::Output(output) = packet {
                self.outputs.push(output);
            }
        }

        summary.outputs = self.outputs.len();
        summary.drops = self.drops.len();
        summary
    }
}

pub(crate) trait StatelessCryptoWorker {
    fn execute(&self, work: CryptoWork) -> CryptoCompletion;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CopyCryptoWorker;

impl StatelessCryptoWorker for CopyCryptoWorker {
    fn execute(&self, work: CryptoWork) -> CryptoCompletion {
        let output = PacketOutput {
            owner: work.packet.owner,
            counter: work.packet.counter,
            ingress_seq: work.reservation.ingress_seq,
            target: work.packet.output,
            path: work.reservation.output_path,
            payload: work.packet.payload,
        };
        CryptoCompletion {
            reservation: work.reservation,
            result: CryptoResult::Opened(output),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AeadHeader {
    Fmp([u8; FMP_ESTABLISHED_HEADER_SIZE]),
    Fsp([u8; FSP_HEADER_SIZE]),
}

impl AeadHeader {
    fn as_aad(&self) -> &[u8] {
        match self {
            Self::Fmp(header) => header,
            Self::Fsp(header) => header,
        }
    }
}

pub(crate) struct AeadOpenWork {
    work: CryptoWork,
    cipher: AeadKey,
    header: AeadHeader,
    ciphertext_offset: usize,
}

impl AeadOpenWork {
    pub(crate) fn from_crypto_work(
        work: CryptoWork,
        cipher: AeadKey,
    ) -> Result<Self, WirePreflightError> {
        let (header, ciphertext_offset, counter) = match work.packet.owner.protocol {
            PacketProtocol::Fmp => {
                let header = FmpWireHeader::parse(&work.packet.payload)?;
                (
                    AeadHeader::Fmp(header.header_bytes()),
                    header.ciphertext_offset(),
                    header.counter(),
                )
            }
            PacketProtocol::Fsp => {
                let header = FspWireHeader::parse(&work.packet.payload)?;
                (
                    AeadHeader::Fsp(header.header_bytes()),
                    header.ciphertext_offset(),
                    header.counter(),
                )
            }
        };
        if counter != work.packet.counter {
            return Err(WirePreflightError::CounterMismatch);
        }

        Ok(Self {
            work,
            cipher,
            header,
            ciphertext_offset,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StatelessAeadOpenWorker;

impl StatelessAeadOpenWorker {
    pub(crate) fn execute(&self, mut work: AeadOpenWork) -> CryptoCompletion {
        let reservation = work.work.reservation;
        let target = work.work.packet.output;
        let header = work.header;
        let opened_len = match work.work.packet.payload.get_mut(work.ciphertext_offset..) {
            Some(ciphertext) => {
                let nonce = aead_nonce(reservation.counter);
                work.cipher
                    .open_in_place(nonce, Aad::from(header.as_aad()), ciphertext)
                    .map(|plaintext| plaintext.len())
                    .ok()
            }
            None => None,
        };

        let result = match opened_len {
            Some(plaintext_len) => {
                work.work
                    .packet
                    .payload
                    .truncate(work.ciphertext_offset + plaintext_len);
                CryptoResult::Opened(PacketOutput {
                    owner: reservation.owner,
                    counter: reservation.counter,
                    ingress_seq: reservation.ingress_seq,
                    target,
                    path: reservation.output_path,
                    payload: work.work.packet.payload,
                })
            }
            None => CryptoResult::Failed,
        };

        CryptoCompletion {
            reservation,
            result,
        }
    }
}

pub(crate) struct AeadSealWork {
    work: OutboundCryptoWork,
    cipher: AeadKey,
    ciphertext_offset: usize,
}

impl AeadSealWork {
    pub(crate) fn from_outbound_work(
        mut work: OutboundCryptoWork,
        cipher: AeadKey,
    ) -> Result<Self, WireBuildError> {
        let payload_len = u16::try_from(work.packet.payload.len())
            .map_err(|_| WireBuildError::PayloadTooLarge)?;
        let counter = work.reservation.counter;
        let (header, ciphertext_offset) = match (work.packet.owner.protocol, work.packet.wire) {
            (
                PacketProtocol::Fmp,
                OutboundWire::Fmp {
                    receiver_idx,
                    flags,
                },
            ) => (
                build_fmp_established_header(receiver_idx, counter, flags, payload_len).to_vec(),
                FMP_ESTABLISHED_HEADER_SIZE,
            ),
            (PacketProtocol::Fsp, OutboundWire::Fsp { flags }) => (
                build_fsp_established_header(counter, flags, payload_len)?.to_vec(),
                FSP_HEADER_SIZE,
            ),
            _ => return Err(WireBuildError::ProtocolMismatch),
        };

        let mut wire = Vec::with_capacity(header.len() + work.packet.payload.len() + AEAD_TAG_SIZE);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&work.packet.payload);
        work.packet.payload = wire.into();

        Ok(Self {
            work,
            cipher,
            ciphertext_offset,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StatelessAeadSealWorker;

impl StatelessAeadSealWorker {
    pub(crate) fn execute(&self, mut work: AeadSealWork) -> CryptoCompletion {
        let reservation = work.work.reservation;
        let tag = if work.ciphertext_offset <= work.work.packet.payload.len() {
            let nonce = aead_nonce(reservation.counter);
            let (aad, plaintext) = work
                .work
                .packet
                .payload
                .split_at_mut(work.ciphertext_offset);
            work.cipher
                .seal_in_place_separate_tag(nonce, Aad::from(&*aad), plaintext)
                .ok()
        } else {
            None
        };

        let result = match tag {
            Some(tag) => {
                work.work.packet.payload.extend_from_slice(tag.as_ref());
                CryptoResult::Sealed(PacketOutput {
                    owner: reservation.owner,
                    counter: reservation.counter,
                    ingress_seq: reservation.ingress_seq,
                    target: OutputTarget::Transport,
                    path: reservation.output_path,
                    payload: work.work.packet.payload,
                })
            }
            None => CryptoResult::Failed,
        };

        CryptoCompletion {
            reservation,
            result,
        }
    }
}

fn aead_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}

#[derive(Debug)]
pub(crate) struct PacketMover2<W = CopyCryptoWorker> {
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
    worker: W,
    drops: Vec<PacketDrop>,
}

impl<W: StatelessCryptoWorker> PacketMover2<W> {
    pub(crate) fn new(config: AdmissionConfig, worker: W) -> Self {
        Self {
            admission: AdmissionQueue::new(config),
            outbound_admission: OutboundAdmissionQueue::new(config),
            owners: HashMap::new(),
            worker,
            drops: Vec::new(),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.owners.insert(owner, OwnerState::new(owner, config));
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owners.get_mut(&owner)
    }

    fn owner_crypto_keys(&self, owner: OwnerId) -> Option<OwnerCryptoKeys> {
        self.owners.get(&owner).and_then(OwnerState::crypto_keys)
    }

    pub(crate) fn submit_socket_packet(
        &mut self,
        packet: SocketPacket,
    ) -> Result<u64, AdmissionDrop> {
        match self.admission.admit(packet) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    pub(crate) fn submit_socket_batch<I>(&mut self, packets: I) -> AdmissionBatchSummary
    where
        I: IntoIterator<Item = SocketPacket>,
    {
        let mut summary = AdmissionBatchSummary::default();
        for packet in packets {
            match self.submit_socket_packet(packet) {
                Ok(_) => summary.admitted += 1,
                Err(_) => summary.dropped += 1,
            }
        }
        summary
    }

    pub(crate) fn submit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
    ) -> Result<u64, OutboundAdmissionDrop> {
        match self.outbound_admission.admit(packet) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    pub(crate) fn dispatch_available(&mut self, limit: usize) -> Vec<CryptoWork> {
        let mut work = Vec::new();
        self.dispatch_available_into(limit, &mut work);
        work
    }

    pub(crate) fn dispatch_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> usize {
        work.clear();

        while work.len() < limit {
            let Some(queued) = self.admission.pop_next() else {
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };

            match owner.reserve(&queued.packet, queued.ingress_seq) {
                Ok(reservation) => work.push(CryptoWork {
                    reservation,
                    packet: queued.packet,
                }),
                Err(error) => self
                    .drops
                    .push(PacketDrop::from_queued(&queued, error.into())),
            }
        }

        work.len()
    }

    pub(crate) fn dispatch_outbound_available(&mut self, limit: usize) -> Vec<OutboundCryptoWork> {
        let mut work = Vec::new();
        self.dispatch_outbound_available_into(limit, &mut work);
        work
    }

    pub(crate) fn dispatch_outbound_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> usize {
        work.clear();

        while work.len() < limit {
            let Some(queued) = self.outbound_admission.pop_next() else {
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued_outbound(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };

            match owner.reserve_outbound(&queued.packet, queued.ingress_seq) {
                Ok(reservation) => work.push(OutboundCryptoWork {
                    reservation,
                    packet: queued.packet,
                }),
                Err(error) => self
                    .drops
                    .push(PacketDrop::from_queued_outbound(&queued, error.into())),
            }
        }

        work.len()
    }

    pub(crate) fn execute_work(&self, work: CryptoWork) -> CryptoCompletion {
        self.worker.execute(work)
    }

    pub(crate) fn retire_completion(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        let Some(owner) = self.owners.get_mut(&completion.reservation.owner) else {
            return vec![RetiredPacket::Drop(PacketDrop::from_completion(
                &completion,
                PacketDropReason::UnknownOwner,
            ))];
        };
        let retired = owner.retire(completion);
        self.drops
            .extend(retired.iter().filter_map(|item| match item {
                RetiredPacket::Drop(drop) => Some(drop.clone()),
                RetiredPacket::Output(_) => None,
            }));
        retired
    }

    pub(crate) fn run_available(&mut self, limit: usize) -> PacketMoverTurn {
        let mut work = Vec::new();
        self.run_available_with_scratch(limit, &mut work)
    }

    pub(crate) fn run_available_with_scratch(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> PacketMoverTurn {
        let dispatched = self.dispatch_available_into(limit, work);
        let mut retired = Vec::new();
        for work in work.drain(..) {
            let completion = self.worker.execute(work);
            retired.extend(self.retire_completion(completion));
        }
        PacketMoverTurn {
            dispatched,
            retired,
            drops: self.drain_drops(),
        }
    }

    pub(crate) fn run_aead_available(&mut self, limit: usize) -> PacketMoverTurn {
        let mut open_work = Vec::new();
        let mut seal_work = Vec::new();
        self.run_aead_available_with_scratch(limit, &mut open_work, &mut seal_work)
    }

    pub(crate) fn run_aead_available_with_scratch(
        &mut self,
        limit: usize,
        open_work: &mut Vec<CryptoWork>,
        seal_work: &mut Vec<OutboundCryptoWork>,
    ) -> PacketMoverTurn {
        let opened = StatelessAeadOpenWorker;
        let sealed = StatelessAeadSealWorker;
        let inbound_dispatched = self.dispatch_available_into(limit, open_work);
        let outbound_dispatched = self
            .dispatch_outbound_available_into(limit.saturating_sub(inbound_dispatched), seal_work);
        let mut retired = Vec::new();

        for work in open_work.drain(..) {
            let reservation = work.reservation;
            let completion = match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => match AeadOpenWork::from_crypto_work(work, keys.open) {
                    Ok(work) => opened.execute(work),
                    Err(_) => CryptoCompletion {
                        reservation,
                        result: CryptoResult::Failed,
                    },
                },
                None => CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed,
                },
            };
            retired.extend(self.retire_completion(completion));
        }

        for work in seal_work.drain(..) {
            let reservation = work.reservation;
            let completion = match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => match AeadSealWork::from_outbound_work(work, keys.seal) {
                    Ok(work) => sealed.execute(work),
                    Err(_) => CryptoCompletion {
                        reservation,
                        result: CryptoResult::Failed,
                    },
                },
                None => CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed,
                },
            };
            retired.extend(self.retire_completion(completion));
        }

        PacketMoverTurn {
            dispatched: inbound_dispatched + outbound_dispatched,
            retired,
            drops: self.drain_drops(),
        }
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    #[cfg(test)]
    fn queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }

    #[cfg(test)]
    fn outbound_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission.lens()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ReceivedPacket, TransportAddr, TransportId};
    use ring::aead::UnboundKey;

    fn mover() -> PacketMover2 {
        PacketMover2::new(AdmissionConfig::new(4, 8), CopyCryptoWorker)
    }

    fn packet(
        owner: OwnerId,
        generation: u64,
        counter: u64,
        class: PacketClass,
        output: OutputTarget,
    ) -> SocketPacket {
        SocketPacket::new(
            owner,
            generation,
            counter,
            class,
            output,
            vec![counter as u8],
        )
    }

    fn fmp_wire(receiver_idx: u32, counter: u64, flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; FMP_ESTABLISHED_HEADER_SIZE + 16];
        data[0] = (FMP_VERSION << 4) | FMP_PHASE_ESTABLISHED;
        data[1] = flags;
        data[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
        data[8..16].copy_from_slice(&counter.to_le_bytes());
        data
    }

    fn fsp_wire(counter: u64, flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; FSP_HEADER_SIZE + 16];
        data[0] = (FSP_VERSION << 4) | FSP_PHASE_ESTABLISHED;
        data[1] = flags;
        data[4..12].copy_from_slice(&counter.to_le_bytes());
        data
    }

    fn test_cipher(byte: u8) -> LessSafeKey {
        let key = [byte; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap();
        LessSafeKey::new(unbound)
    }

    fn test_key(byte: u8) -> AeadKey {
        Arc::new(test_cipher(byte))
    }

    fn fmp_encrypted_wire(
        receiver_idx: u32,
        counter: u64,
        flags: u8,
        plaintext: &[u8],
        key: u8,
    ) -> Vec<u8> {
        let mut data = fmp_wire(receiver_idx, counter, flags);
        data.truncate(FMP_ESTABLISHED_HEADER_SIZE);
        let mut ciphertext = plaintext.to_vec();
        test_cipher(key)
            .seal_in_place_append_tag(
                aead_nonce(counter),
                Aad::from(&data[..FMP_ESTABLISHED_HEADER_SIZE]),
                &mut ciphertext,
            )
            .unwrap();
        data.extend_from_slice(&ciphertext);
        data
    }

    fn fsp_encrypted_wire(counter: u64, flags: u8, plaintext: &[u8], key: u8) -> Vec<u8> {
        let mut data = fsp_wire(counter, flags);
        data.truncate(FSP_HEADER_SIZE);
        let mut ciphertext = plaintext.to_vec();
        test_cipher(key)
            .seal_in_place_append_tag(
                aead_nonce(counter),
                Aad::from(&data[..FSP_HEADER_SIZE]),
                &mut ciphertext,
            )
            .unwrap();
        data.extend_from_slice(&ciphertext);
        data
    }

    fn open_sealed_output(output: &PacketOutput, key: u8) -> Vec<u8> {
        match output.owner.protocol {
            PacketProtocol::Fmp => {
                let header = FmpWireHeader::parse(&output.payload).unwrap();
                let aad = header.header_bytes();
                let mut ciphertext = output.payload[header.ciphertext_offset()..].to_vec();
                let plaintext_len = test_cipher(key)
                    .open_in_place(
                        aead_nonce(header.counter()),
                        Aad::from(&aad),
                        &mut ciphertext,
                    )
                    .unwrap()
                    .len();
                ciphertext.truncate(plaintext_len);
                ciphertext
            }
            PacketProtocol::Fsp => {
                let header = FspWireHeader::parse(&output.payload).unwrap();
                let aad = header.header_bytes();
                let mut ciphertext = output.payload[header.ciphertext_offset()..].to_vec();
                let plaintext_len = test_cipher(key)
                    .open_in_place(
                        aead_nonce(header.counter()),
                        Aad::from(&aad),
                        &mut ciphertext,
                    )
                    .unwrap()
                    .len();
                ciphertext.truncate(plaintext_len);
                ciphertext
            }
        }
    }

    fn outbound_packet(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        payload: &[u8],
    ) -> OutboundPacket {
        match owner.protocol {
            PacketProtocol::Fmp => OutboundPacket::fmp(
                owner,
                generation,
                class,
                owner.peer as u32,
                0,
                payload.to_vec(),
            ),
            PacketProtocol::Fsp => {
                OutboundPacket::fsp(owner, generation, class, 0, payload.to_vec())
            }
        }
    }

    fn outputs(items: Vec<RetiredPacket>) -> Vec<PacketOutput> {
        items
            .into_iter()
            .map(|item| match item {
                RetiredPacket::Output(output) => output,
                RetiredPacket::Drop(drop) => panic!("unexpected drop: {drop:?}"),
            })
            .collect()
    }

    fn drops(items: Vec<RetiredPacket>) -> Vec<PacketDrop> {
        items
            .into_iter()
            .map(|item| match item {
                RetiredPacket::Drop(drop) => drop,
                RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
            })
            .collect()
    }

    #[test]
    fn happy_path_dispatches_fmp_and_fsp_packets() {
        let fmp = OwnerId::fmp(7);
        let fsp = OwnerId::fsp(7);
        let mut mover = mover();
        mover.register_owner(fmp, OwnerConfig::new(1, 8));
        mover.register_owner(fsp, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(packet(fsp, 1, 10, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(
                fmp,
                1,
                20,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();

        let work = mover.dispatch_available(8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.owner, fmp);
        assert_eq!(work[1].packet.owner, fsp);

        let mut retired = Vec::new();
        for item in work {
            let completion = mover.execute_work(item);
            retired.extend(mover.retire_completion(completion));
        }
        let outputs = outputs(retired);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        assert_eq!(outputs[1].target, OutputTarget::Tun);
        assert_eq!(outputs[0].payload, vec![20]);
        assert_eq!(outputs[1].payload, vec![10]);
    }

    #[test]
    fn wire_preflight_parses_fmp_and_fsp_established_headers() {
        let fmp = FmpWireHeader::parse(&fmp_wire(77, 900, 0x03)).unwrap();
        assert_eq!(fmp.receiver_idx(), 77);
        assert_eq!(fmp.counter(), 900);
        assert_eq!(fmp.flags(), 0x03);
        assert_eq!(fmp.ciphertext_offset(), FMP_ESTABLISHED_HEADER_SIZE);

        let fsp = FspWireHeader::parse(&fsp_wire(901, 0x02)).unwrap();
        assert_eq!(fsp.counter(), 901);
        assert_eq!(fsp.flags(), 0x02);
        assert_eq!(fsp.ciphertext_offset(), FSP_HEADER_SIZE);

        let owner = OwnerId::fmp(77);
        let packet = SocketPacket::from_fmp_established_wire(
            owner,
            5,
            OutputTarget::Transport,
            fmp_wire(77, 902, 0),
        )
        .unwrap();
        assert_eq!(packet.owner, owner);
        assert_eq!(packet.generation, 5);
        assert_eq!(packet.counter, 902);
        assert_eq!(packet.class, PacketClass::Bulk);

        let mut wrong_phase = fmp_wire(77, 903, 0);
        wrong_phase[0] = (FMP_VERSION << 4) | crate::node::wire::PHASE_MSG1;
        assert_eq!(
            FmpWireHeader::parse(&wrong_phase).unwrap_err(),
            WirePreflightError::WrongPhase
        );

        let plaintext_fsp = fsp_wire(904, FSP_FLAG_U);
        assert_eq!(
            FspWireHeader::parse(&plaintext_fsp).unwrap_err(),
            WirePreflightError::PlaintextFsp
        );
    }

    #[test]
    fn priority_admission_keeps_reserved_progress_when_bulk_is_full() {
        let owner = OwnerId::fsp(1);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 1), CopyCryptoWorker);
        mover.register_owner(owner, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        let bulk_drop = mover
            .submit_socket_packet(packet(owner, 1, 2, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap_err();
        mover
            .submit_socket_packet(packet(
                owner,
                1,
                3,
                PacketClass::Liveness,
                OutputTarget::Endpoint,
            ))
            .unwrap();

        assert_eq!(bulk_drop.reason, AdmissionDropReason::BulkFull);
        assert_eq!(mover.queue_lens(), (1, 1));
        let work = mover.dispatch_available(1);
        assert_eq!(work[0].packet.counter, 3);

        let drops = mover.drain_drops();
        assert_eq!(
            drops[0].reason,
            PacketDropReason::Admission(AdmissionDropReason::BulkFull)
        );
        assert_eq!(drops[0].counter, Some(2));
    }

    #[test]
    fn turn_runner_batches_admission_and_reuses_work_scratch() {
        let owner = OwnerId::fsp(11);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 4), CopyCryptoWorker);
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        let summary = mover.submit_socket_batch([
            packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun),
            packet(owner, 1, 2, PacketClass::Liveness, OutputTarget::Endpoint),
            packet(owner, 1, 3, PacketClass::Bulk, OutputTarget::Transport),
        ]);
        assert_eq!(summary.admitted(), 3);
        assert_eq!(summary.dropped(), 0);

        let mut work = Vec::with_capacity(8);
        let turn = mover.run_available_with_scratch(2, &mut work);
        assert!(work.is_empty());
        assert_eq!(turn.dispatched(), 2);
        assert!(turn.drops().is_empty());
        assert_eq!(
            turn.outputs()
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert_eq!(
            turn.retired()
                .iter()
                .filter(|item| matches!(item, RetiredPacket::Output(_)))
                .count(),
            2
        );

        let turn = mover.run_available_with_scratch(2, &mut work);
        assert_eq!(turn.dispatched(), 1);
        assert_eq!(turn.outputs()[0].counter, 3);
        assert_eq!(work.capacity(), 8);
    }

    #[test]
    fn owner_retires_worker_completions_in_owner_order() {
        let owner = OwnerId::fsp(9);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        for counter in 1..=3 {
            mover
                .submit_socket_packet(packet(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                ))
                .unwrap();
        }

        let work = mover.dispatch_available(8);
        assert_eq!(
            work.iter().map(CryptoWork::order).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let completion_2 = mover.execute_work(work[2].clone());
        assert!(mover.retire_completion(completion_2).is_empty());

        let completion_0 = mover.execute_work(work[0].clone());
        let retired = outputs(mover.retire_completion(completion_0));
        assert_eq!(
            retired
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![1]
        );

        let completion_1 = mover.execute_work(work[1].clone());
        let retired = outputs(mover.retire_completion(completion_1));
        assert_eq!(
            retired
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn owner_rejects_replay_and_in_flight_overflow_at_reservation() {
        let owner = OwnerId::fsp(3);
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4), CopyCryptoWorker);
        mover.register_owner(owner, OwnerConfig::new(1, 1));

        mover
            .submit_socket_packet(packet(owner, 1, 8, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(owner, 1, 9, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(owner, 1, 8, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();

        let work = mover.dispatch_available(8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.counter, 8);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight(), 1);

        let drops = mover.drain_drops();
        assert_eq!(drops[0].reason, PacketDropReason::OwnerInFlightFull);
        assert_eq!(drops[0].counter, Some(9));
        assert_eq!(drops[1].reason, PacketDropReason::Replay);
        assert_eq!(drops[1].counter, Some(8));

        let completion = mover.execute_work(work[0].clone());
        assert_eq!(outputs(mover.retire_completion(completion)).len(), 1);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight(), 0);
    }

    #[test]
    fn stale_generation_is_dropped_before_dispatch_and_at_retire() {
        let owner = OwnerId::fmp(4);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_socket_packet(packet(
                owner,
                1,
                1,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();

        let mut work = mover.dispatch_available(8);
        assert_eq!(work.len(), 1);
        mover.owner_mut(owner).unwrap().rekey(2);
        let stale_retire = mover.retire_completion(mover.execute_work(work.pop().unwrap()));
        let stale_retire_drops = drops(stale_retire);
        assert_eq!(
            stale_retire_drops[0].reason,
            PacketDropReason::StaleCompletionGeneration
        );

        mover
            .submit_socket_packet(packet(
                owner,
                1,
                2,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();
        mover
            .submit_socket_packet(packet(
                owner,
                2,
                3,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();
        let work = mover.dispatch_available(8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.counter, 3);

        let drops = mover.drain_drops();
        assert!(drops.iter().any(
            |drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter == Some(2)
        ));
    }

    #[test]
    fn tun_endpoint_and_transport_outputs_keep_owner_order() {
        let owner = OwnerId::fsp(42);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        let targets = [
            OutputTarget::Tun,
            OutputTarget::Endpoint,
            OutputTarget::Transport,
        ];
        for (idx, target) in targets.into_iter().enumerate() {
            mover
                .submit_socket_packet(packet(owner, 1, idx as u64 + 1, PacketClass::Bulk, target))
                .unwrap();
        }

        let work = mover.dispatch_available(8);
        let mut retired = Vec::new();
        for work in work.into_iter().rev() {
            retired.extend(mover.retire_completion(mover.execute_work(work)));
        }
        let outputs = outputs(retired);
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.target)
                .collect::<Vec<_>>(),
            vec![
                OutputTarget::Tun,
                OutputTarget::Endpoint,
                OutputTarget::Transport,
            ]
        );
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn stateless_aead_worker_opens_fmp_and_fsp_packets() {
        let fmp = OwnerId::fmp(77);
        let fsp = OwnerId::fsp(88);
        let key = 9;
        let mut mover = mover();
        mover.register_owner(fmp, OwnerConfig::new(1, 8));
        mover.register_owner(fsp, OwnerConfig::new(1, 8));

        let fmp_plaintext = b"fmp inner packet";
        let fsp_plaintext = b"fsp inner packet";
        let fmp_wire = fmp_encrypted_wire(77, 100, 0x02, fmp_plaintext, key);
        let fsp_wire = fsp_encrypted_wire(101, 0, fsp_plaintext, key);

        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(fmp, 1, OutputTarget::Transport, fmp_wire)
                    .unwrap(),
            )
            .unwrap();
        mover
            .submit_socket_packet(
                SocketPacket::from_fsp_established_wire(fsp, 1, OutputTarget::Tun, fsp_wire)
                    .unwrap(),
            )
            .unwrap();

        let worker = StatelessAeadOpenWorker;
        let mut retired = Vec::new();
        for work in mover.dispatch_available(8) {
            let work = AeadOpenWork::from_crypto_work(work, test_key(key)).unwrap();
            retired.extend(mover.retire_completion(worker.execute(work)));
        }

        let outputs = outputs(retired);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            fmp_plaintext
        );
        assert_eq!(
            outputs[0].payload.len(),
            FMP_ESTABLISHED_HEADER_SIZE + fmp_plaintext.len()
        );
        assert_eq!(outputs[1].counter, 101);
        assert_eq!(outputs[1].target, OutputTarget::Tun);
        assert_eq!(&outputs[1].payload[FSP_HEADER_SIZE..], fsp_plaintext);
        assert_eq!(
            outputs[1].payload.len(),
            FSP_HEADER_SIZE + fsp_plaintext.len()
        );
    }

    #[test]
    fn stateless_aead_worker_crypto_failure_retires_in_owner_order() {
        let owner = OwnerId::fmp(91);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(91, 1, 0, b"first", 1),
                )
                .unwrap(),
            )
            .unwrap();
        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(91, 2, 0, b"second", 1),
                )
                .unwrap(),
            )
            .unwrap();

        let worker = StatelessAeadOpenWorker;
        let work = mover.dispatch_available(8);
        assert_eq!(work.len(), 2);

        let second = AeadOpenWork::from_crypto_work(work[1].clone(), test_key(1)).unwrap();
        assert!(mover.retire_completion(worker.execute(second)).is_empty());

        let first = AeadOpenWork::from_crypto_work(work[0].clone(), test_key(2)).unwrap();
        let retired = mover.retire_completion(worker.execute(first));
        assert_eq!(retired.len(), 2);
        match &retired[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.counter, Some(1));
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
        }
        match &retired[1] {
            RetiredPacket::Output(output) => {
                assert_eq!(output.counter, 2);
                assert_eq!(&output.payload[FMP_ESTABLISHED_HEADER_SIZE..], b"second");
            }
            RetiredPacket::Drop(drop) => panic!("unexpected drop: {drop:?}"),
        }
    }

    #[test]
    fn outbound_seal_worker_builds_fmp_and_fsp_wire_from_owner_reserved_counters() {
        let fmp = OwnerId::fmp(77);
        let fsp = OwnerId::fsp(88);
        let key = 6;
        let mut mover = mover();
        mover.register_owner(fmp, OwnerConfig::new(1, 8).with_next_send_counter(10));
        mover.register_owner(fsp, OwnerConfig::new(1, 8).with_next_send_counter(20));

        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                fmp,
                1,
                PacketClass::Bulk,
                777,
                0x02,
                b"fmp outbound".to_vec(),
            ))
            .unwrap();
        mover
            .submit_outbound_packet(OutboundPacket::fsp(
                fsp,
                1,
                PacketClass::Bulk,
                0,
                b"fsp outbound".to_vec(),
            ))
            .unwrap();

        let worker = StatelessAeadSealWorker;
        let mut retired = Vec::new();
        for work in mover.dispatch_outbound_available(8) {
            let work = AeadSealWork::from_outbound_work(work, test_key(key)).unwrap();
            retired.extend(mover.retire_completion(worker.execute(work)));
        }

        let outputs = outputs(retired);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].owner, fmp);
        assert_eq!(outputs[0].counter, 10);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        let fmp_header = FmpWireHeader::parse(&outputs[0].payload).unwrap();
        assert_eq!(fmp_header.receiver_idx(), 777);
        assert_eq!(fmp_header.counter(), 10);
        assert_eq!(fmp_header.flags(), 0x02);
        assert_eq!(
            u16::from_le_bytes([outputs[0].payload[2], outputs[0].payload[3]]) as usize,
            b"fmp outbound".len()
        );
        assert_eq!(open_sealed_output(&outputs[0], key), b"fmp outbound");
        assert_eq!(
            outputs[0].payload.len(),
            FMP_ESTABLISHED_HEADER_SIZE + b"fmp outbound".len() + AEAD_TAG_SIZE
        );

        assert_eq!(outputs[1].owner, fsp);
        assert_eq!(outputs[1].counter, 20);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        let fsp_header = FspWireHeader::parse(&outputs[1].payload).unwrap();
        assert_eq!(fsp_header.counter(), 20);
        assert_eq!(fsp_header.flags(), 0);
        assert_eq!(
            u16::from_le_bytes([outputs[1].payload[2], outputs[1].payload[3]]) as usize,
            b"fsp outbound".len()
        );
        assert_eq!(open_sealed_output(&outputs[1], key), b"fsp outbound");
        assert_eq!(
            outputs[1].payload.len(),
            FSP_HEADER_SIZE + b"fsp outbound".len() + AEAD_TAG_SIZE
        );
    }

    #[test]
    fn outbound_owner_reserves_counters_after_priority_overtakes_bulk() {
        let owner = OwnerId::fsp(33);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 1), CopyCryptoWorker);
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(40));

        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-a"))
            .unwrap();
        let bulk_drop = mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-b"))
            .unwrap_err();
        mover
            .submit_outbound_packet(outbound_packet(
                owner,
                1,
                PacketClass::Liveness,
                b"priority",
            ))
            .unwrap();

        assert_eq!(bulk_drop.reason, AdmissionDropReason::BulkFull);
        assert_eq!(mover.outbound_queue_lens(), (1, 1));

        let work = mover.dispatch_outbound_available(8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.class, PacketClass::Liveness);
        assert_eq!(work[0].reservation.counter, 40);
        assert_eq!(work[1].packet.class, PacketClass::Bulk);
        assert_eq!(work[1].reservation.counter, 41);
        assert_eq!(mover.owner_mut(owner).unwrap().next_send_counter(), 42);

        let drops = mover.drain_drops();
        assert_eq!(
            drops[0].reason,
            PacketDropReason::Admission(AdmissionDropReason::BulkFull)
        );
        assert_eq!(drops[0].counter, None);
        assert_eq!(drops[0].lane, Lane::Bulk);
    }

    #[test]
    fn outbound_completions_retire_in_owner_order() {
        let owner = OwnerId::fmp(44);
        let key = 7;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(5));
        for payload in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            mover
                .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, payload))
                .unwrap();
        }

        let work = mover.dispatch_outbound_available(8);
        assert_eq!(
            work.iter()
                .map(OutboundCryptoWork::order)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let worker = StatelessAeadSealWorker;
        let third = AeadSealWork::from_outbound_work(work[2].clone(), test_key(key)).unwrap();
        assert!(mover.retire_completion(worker.execute(third)).is_empty());

        let first = AeadSealWork::from_outbound_work(work[0].clone(), test_key(key)).unwrap();
        let retired = outputs(mover.retire_completion(worker.execute(first)));
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].counter, 5);
        assert_eq!(open_sealed_output(&retired[0], key), b"first");

        let second = AeadSealWork::from_outbound_work(work[1].clone(), test_key(key)).unwrap();
        let retired = outputs(mover.retire_completion(worker.execute(second)));
        assert_eq!(
            retired
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![6, 7]
        );
        assert_eq!(open_sealed_output(&retired[0], key), b"second");
        assert_eq!(open_sealed_output(&retired[1], key), b"third");
    }

    #[test]
    fn outbound_wire_build_rejects_mismatched_protocol_and_plaintext_fsp() {
        let fmp_owner = OwnerId::fmp(12);
        let fsp_owner = OwnerId::fsp(12);
        let mut fmp_state =
            OwnerState::new(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(1));
        let mismatch = OutboundPacket::fsp(fmp_owner, 1, PacketClass::Bulk, 0, b"body".to_vec());
        let mismatch_work = OutboundCryptoWork {
            reservation: fmp_state.reserve_outbound(&mismatch, 0).unwrap(),
            packet: mismatch,
        };
        assert_eq!(
            AeadSealWork::from_outbound_work(mismatch_work, test_key(1)).err(),
            Some(WireBuildError::ProtocolMismatch)
        );

        let mut fsp_state =
            OwnerState::new(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(1));
        let plaintext_fsp = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Bulk,
            FSP_FLAG_U,
            b"body".to_vec(),
        );
        let plaintext_work = OutboundCryptoWork {
            reservation: fsp_state.reserve_outbound(&plaintext_fsp, 0).unwrap(),
            packet: plaintext_fsp,
        };
        assert_eq!(
            AeadSealWork::from_outbound_work(plaintext_work, test_key(1)).err(),
            Some(WireBuildError::PlaintextFsp)
        );
    }

    #[test]
    fn aead_turn_runner_uses_owner_keys_for_inbound_and_outbound_work() {
        let owner = OwnerId::fmp(70);
        let open_key = 11;
        let seal_key = 12;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(200));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(70, 100, 0, b"inbound", open_key),
                )
                .unwrap(),
            )
            .unwrap();
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                700,
                0,
                b"outbound".to_vec(),
            ))
            .unwrap();

        let mut open_scratch = Vec::with_capacity(4);
        let mut seal_scratch = Vec::with_capacity(4);
        let turn = mover.run_aead_available_with_scratch(8, &mut open_scratch, &mut seal_scratch);
        assert_eq!(turn.dispatched(), 2);
        assert!(turn.drops().is_empty());
        assert!(open_scratch.is_empty());
        assert!(seal_scratch.is_empty());

        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"inbound"
        );
        assert_eq!(outputs[1].counter, 200);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        let sealed_header = FmpWireHeader::parse(&outputs[1].payload).unwrap();
        assert_eq!(sealed_header.receiver_idx(), 700);
        assert_eq!(sealed_header.counter(), 200);
        assert_eq!(open_sealed_output(outputs[1], seal_key), b"outbound");
        assert_eq!(open_scratch.capacity(), 4);
        assert_eq!(seal_scratch.capacity(), 4);
    }

    #[test]
    fn aead_turn_runner_missing_keys_retires_failed_work_and_releases_in_flight() {
        let owner = OwnerId::fsp(71);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_outbound_packet(OutboundPacket::fsp(
                owner,
                1,
                PacketClass::Bulk,
                0,
                b"needs key".to_vec(),
            ))
            .unwrap();

        let turn = mover.run_aead_available(8);
        assert_eq!(turn.dispatched(), 1);
        assert_eq!(turn.retired().len(), 1);
        match &turn.retired()[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
                assert_eq!(drop.counter, Some(0));
                assert_eq!(drop.lane, Lane::Bulk);
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
        }
        assert_eq!(turn.drops().len(), 1);
        assert_eq!(turn.drops()[0].reason, PacketDropReason::CryptoFailed);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight(), 0);
    }

    #[test]
    fn rekey_clears_owner_crypto_keys_and_restarts_send_counter() {
        let owner = OwnerId::fmp(72);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(99));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(1), test_key(1)));
        mover.owner_mut(owner).unwrap().rekey(2);
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                2,
                PacketClass::Bulk,
                720,
                0,
                b"after rekey".to_vec(),
            ))
            .unwrap();

        let turn = mover.run_aead_available(8);
        assert_eq!(turn.dispatched(), 1);
        match &turn.retired()[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
                assert_eq!(drop.counter, Some(0));
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
        }
        let owner = mover.owner_mut(owner).unwrap();
        assert_eq!(owner.next_send_counter(), 1);
        assert_eq!(owner.in_flight(), 0);
    }

    #[test]
    fn owner_tracks_inbound_path_drift_and_uses_latest_path_for_outbound_transport() {
        let owner = OwnerId::fmp(73);
        let open_key = 21;
        let seal_key = 22;
        let path_a = TransportPath::new(100);
        let path_b = TransportPath::new(200);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(500));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        let inbound_a = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(73, 1000, 0, b"in-a", open_key),
        )
        .unwrap()
        .with_source_path(path_a);
        mover.submit_socket_packet(inbound_a).unwrap();
        let turn = mover.run_aead_available(8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path, None);
        assert_eq!(mover.owner_mut(owner).unwrap().active_path(), Some(path_a));

        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                730,
                0,
                b"out-a".to_vec(),
            ))
            .unwrap();
        let turn = mover.run_aead_available(8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 500);
        assert_eq!(output.target, OutputTarget::Transport);
        assert_eq!(output.path, Some(path_a));
        assert_eq!(open_sealed_output(output, seal_key), b"out-a");

        let inbound_b = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(73, 1001, 0, b"in-b", open_key),
        )
        .unwrap()
        .with_source_path(path_b);
        mover.submit_socket_packet(inbound_b).unwrap();
        let turn = mover.run_aead_available(8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path, None);
        assert_eq!(mover.owner_mut(owner).unwrap().active_path(), Some(path_b));

        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                730,
                0,
                b"out-b".to_vec(),
            ))
            .unwrap();
        let turn = mover.run_aead_available(8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 501);
        assert_eq!(output.path, Some(path_b));
        assert_eq!(open_sealed_output(output, seal_key), b"out-b");
    }

    #[test]
    fn stale_generation_does_not_move_owner_path() {
        let owner = OwnerId::fsp(74);
        let old_path = TransportPath::new(10);
        let stale_path = TransportPath::new(11);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(2, 8));
        mover.owner_mut(owner).unwrap().set_active_path(old_path);
        mover
            .submit_socket_packet(
                SocketPacket::new(
                    owner,
                    1,
                    5,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    b"stale".to_vec(),
                )
                .with_source_path(stale_path),
            )
            .unwrap();

        let work = mover.dispatch_available(8);
        assert!(work.is_empty());
        let drops = mover.drain_drops();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].reason, PacketDropReason::StaleGeneration);
        assert_eq!(
            mover.owner_mut(owner).unwrap().active_path(),
            Some(old_path)
        );
    }

    #[test]
    fn owner_tracks_inbound_activity_only_for_reserved_packets() {
        let owner = OwnerId::fsp(75);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun)
                    .with_activity_tick(ActivityTick::new(10)),
            )
            .unwrap();
        assert_eq!(mover.dispatch_available(8).len(), 1);
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        mover
            .submit_socket_packet(
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun)
                    .with_activity_tick(ActivityTick::new(20)),
            )
            .unwrap();
        assert!(mover.dispatch_available(8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        mover
            .submit_socket_packet(
                packet(owner, 0, 2, PacketClass::Bulk, OutputTarget::Tun)
                    .with_activity_tick(ActivityTick::new(30)),
            )
            .unwrap();
        assert!(mover.dispatch_available(8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        let drops = mover.drain_drops();
        assert!(
            drops
                .iter()
                .any(|drop| drop.reason == PacketDropReason::Replay && drop.counter == Some(1))
        );
        assert!(drops.iter().any(
            |drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter == Some(2)
        ));
    }

    #[test]
    fn owner_tracks_outbound_activity_only_for_reserved_packets() {
        let owner = OwnerId::fmp(76);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(7));

        mover
            .submit_outbound_packet(
                outbound_packet(owner, 1, PacketClass::Bulk, b"newer")
                    .with_activity_tick(ActivityTick::new(50)),
            )
            .unwrap();
        let work = mover.dispatch_outbound_available(8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].reservation.counter, 7);
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_tx_activity(),
            Some(ActivityTick::new(50))
        );

        mover
            .submit_outbound_packet(
                outbound_packet(owner, 1, PacketClass::Liveness, b"older")
                    .with_activity_tick(ActivityTick::new(40)),
            )
            .unwrap();
        assert_eq!(mover.dispatch_outbound_available(8).len(), 1);
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_tx_activity(),
            Some(ActivityTick::new(50))
        );

        mover
            .submit_outbound_packet(
                outbound_packet(owner, 0, PacketClass::Liveness, b"stale")
                    .with_activity_tick(ActivityTick::new(60)),
            )
            .unwrap();
        assert!(mover.dispatch_outbound_available(8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_tx_activity(),
            Some(ActivityTick::new(50))
        );

        let drops = mover.drain_drops();
        assert!(
            drops
                .iter()
                .any(|drop| drop.reason == PacketDropReason::StaleGeneration
                    && drop.counter.is_none())
        );
    }

    #[test]
    fn hard_event_liveness_state_stays_owner_owned_across_rekey() {
        let owner = OwnerId::fmp(77);
        let mut state = OwnerState::new(owner, OwnerConfig::new(1, 8));

        state.record_hard_event(ActivityTick::new(100));
        state.record_hard_event(ActivityTick::new(90));
        assert_eq!(state.hard_events(), 2);
        assert_eq!(state.last_hard_event(), Some(ActivityTick::new(100)));

        state.rekey(2);
        assert_eq!(state.hard_events(), 2);
        assert_eq!(state.last_hard_event(), Some(ActivityTick::new(100)));
        assert_eq!(state.last_rx_activity(), None);
        assert_eq!(state.last_tx_activity(), None);
    }

    #[test]
    fn runtime_turn_driver_runs_classified_inbound_and_outbound_once() {
        let owner = OwnerId::fmp(78);
        let open_key = 31;
        let seal_key = 32;
        let path = TransportPath::new(7800);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        let inbound = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(78, 100, 0, b"inbound", open_key),
        )
        .unwrap()
        .with_source_path(path)
        .with_activity_tick(ActivityTick::new(10));
        let outbound = OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Liveness,
            780,
            0,
            b"outbound".to_vec(),
        )
        .with_activity_tick(ActivityTick::new(11));

        let turn = driver.run_aead_classified_turn([inbound], [outbound], 8);
        assert_eq!(
            turn.summary(),
            PacketMover2RuntimeSummary {
                raw_ingress_dropped: 0,
                inbound_admitted: 1,
                inbound_dropped: 0,
                outbound_admitted: 1,
                outbound_dropped: 0,
                dispatched: 2,
                outputs: 2,
                outputs_sent: 0,
                outputs_dropped: 0,
                drops: 0,
            }
        );
        assert!(turn.drops().is_empty());

        let outputs = turn.outputs();
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"inbound"
        );
        assert_eq!(outputs[0].path, None);

        assert_eq!(outputs[1].target, OutputTarget::Transport);
        assert_eq!(outputs[1].counter, 300);
        assert_eq!(outputs[1].path, Some(path));
        assert_eq!(open_sealed_output(&outputs[1], seal_key), b"outbound");

        let owner_state = driver.owner_mut(owner).unwrap();
        assert_eq!(owner_state.active_path(), Some(path));
        assert_eq!(owner_state.last_rx_activity(), Some(ActivityTick::new(10)));
        assert_eq!(owner_state.last_tx_activity(), Some(ActivityTick::new(11)));
    }

    #[test]
    fn runtime_turn_driver_reports_admission_and_crypto_drops() {
        let owner = OwnerId::fsp(79);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(1, 1), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let first = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fsp_encrypted_wire(10, 0, b"first", 40),
        )
        .unwrap();
        let second = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fsp_encrypted_wire(11, 0, b"second", 40),
        )
        .unwrap();

        let turn = driver.run_aead_classified_turn([first, second], std::iter::empty(), 8);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().inbound_dropped(), 1);
        assert_eq!(turn.summary().outbound_admitted(), 0);
        assert_eq!(turn.summary().outbound_dropped(), 0);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 0);
        assert_eq!(turn.summary().drops(), 2);
        assert!(turn.outputs().is_empty());

        assert!(turn.drops().iter().any(|drop| {
            drop.reason == PacketDropReason::Admission(AdmissionDropReason::BulkFull)
                && drop.counter == Some(11)
        }));
        assert!(turn.drops().iter().any(|drop| {
            drop.reason == PacketDropReason::CryptoFailed && drop.counter == Some(10)
        }));
    }

    #[test]
    fn runtime_turn_driver_reuses_scratch_and_output_buffers() {
        let owner = OwnerId::fsp(80);
        let key = 41;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(20));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        let inbound = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Endpoint,
            fsp_encrypted_wire(50, 0, b"in", key),
        )
        .unwrap();
        let outbound = OutboundPacket::fsp(owner, 1, PacketClass::Bulk, 0, b"out".to_vec());
        {
            let turn = driver.run_aead_classified_turn([inbound], [outbound], 8);
            assert_eq!(turn.outputs().len(), 2);
            assert!(turn.drops().is_empty());
        }

        let capacities = (
            driver.open_work.capacity(),
            driver.seal_work.capacity(),
            driver.raw_ingress_drops.capacity(),
            driver.output_drops.capacity(),
            driver.outputs.capacity(),
            driver.drops.capacity(),
        );
        let turn = driver.run_aead_classified_turn(std::iter::empty(), std::iter::empty(), 8);
        assert_eq!(turn.summary(), PacketMover2RuntimeSummary::default());
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(
            capacities,
            (
                driver.open_work.capacity(),
                driver.seal_work.capacity(),
                driver.raw_ingress_drops.capacity(),
                driver.output_drops.capacity(),
                driver.outputs.capacity(),
                driver.drops.capacity(),
            )
        );
    }

    struct FixedIngressRouter {
        route: Option<PacketMover2IngressRoute>,
    }

    impl PacketMover2IngressRouter for FixedIngressRouter {
        fn route(
            &mut self,
            packet: &PacketMover2RawIngress,
            header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            assert_eq!(packet.transport_id(), TransportId::new(5));
            assert_eq!(
                packet.remote_addr(),
                &TransportAddr::from_string("198.51.100.9:9000")
            );
            assert_eq!(packet.path(), TransportPath::new(9005));
            assert_eq!(packet.activity_tick(), Some(ActivityTick::new(123_456)));
            assert_eq!(
                packet.payload_len(),
                FMP_ESTABLISHED_HEADER_SIZE + b"raw-in".len() + AEAD_TAG_SIZE
            );
            assert_eq!(packet.protocol(), PacketProtocol::Fmp);
            assert!(matches!(header, PacketMover2IngressHeader::Fmp(_)));
            assert_eq!(header.counter(), 1200);
            self.route
        }
    }

    struct NullIngressRouter;

    impl PacketMover2IngressRouter for NullIngressRouter {
        fn route(
            &mut self,
            _packet: &PacketMover2RawIngress,
            _header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            None
        }
    }

    #[derive(Default)]
    struct RecordingOutputSink {
        outputs: Vec<PacketOutput>,
        fail_counter: Option<u64>,
    }

    impl PacketMover2OutputSink for RecordingOutputSink {
        fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError> {
            if Some(output.counter) == self.fail_counter {
                return Err(PacketMover2OutputError::Backpressure);
            }
            self.outputs.push(output);
            Ok(())
        }
    }

    #[derive(Default)]
    struct BatchRecordingOutputSink {
        batch_calls: usize,
        outputs: Vec<PacketOutput>,
    }

    impl PacketMover2OutputSink for BatchRecordingOutputSink {
        fn send(&mut self, _output: PacketOutput) -> Result<(), PacketMover2OutputError> {
            panic!("batch sink must not use per-output send")
        }

        fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<PacketMover2OutputDrop>) -> usize
        where
            I: IntoIterator<Item = PacketOutput>,
        {
            self.batch_calls += 1;
            let drops_before = drops.len();
            let mut sent = 0;
            for output in outputs {
                assert_eq!(output.payload_len(), output.payload().len());
                self.outputs.push(output);
                sent += 1;
            }
            assert_eq!(drops.len(), drops_before);
            sent
        }
    }

    #[test]
    fn runtime_raw_ingress_turn_parses_received_packet_before_owner_admission() {
        let owner = OwnerId::fmp(81);
        let open_key = 51;
        let path = TransportPath::new(9005);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(7, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
        let received = ReceivedPacket::with_timestamp(
            TransportId::new(5),
            TransportAddr::from_string("198.51.100.9:9000"),
            fmp_encrypted_wire(81, 1200, 0, b"raw-in", open_key),
            123_456,
        );
        let raw = PacketMover2RawIngress::from_received(PacketProtocol::Fmp, path, received);
        let mut router = FixedIngressRouter {
            route: Some(
                PacketMover2IngressRoute::new(owner, 7, OutputTarget::Tun)
                    .with_class(PacketClass::Liveness),
            ),
        };

        let turn = driver.run_aead_raw_ingress_turn([raw], &mut router, std::iter::empty(), 8);
        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 1);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].target, OutputTarget::Tun);
        assert_eq!(turn.outputs()[0].counter, 1200);
        assert_eq!(
            &turn.outputs()[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"raw-in"
        );

        let owner_state = driver.owner_mut(owner).unwrap();
        assert_eq!(owner_state.active_path(), Some(path));
        assert_eq!(
            owner_state.last_rx_activity(),
            Some(ActivityTick::new(123_456))
        );
    }

    #[test]
    fn runtime_raw_ingress_turn_drops_wire_and_unrouted_packets_before_admission() {
        let owner = OwnerId::fsp(82);
        let path = TransportPath::new(9105);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        let bad_wire = PacketMover2RawIngress::from_received(
            PacketProtocol::Fmp,
            path,
            ReceivedPacket::with_timestamp(
                TransportId::new(5),
                TransportAddr::from_string("198.51.100.9:9000"),
                vec![0],
                1,
            ),
        );
        let unrouted = PacketMover2RawIngress::from_received(
            PacketProtocol::Fsp,
            path,
            ReceivedPacket::with_timestamp(
                TransportId::new(5),
                TransportAddr::from_string("198.51.100.9:9000"),
                fsp_encrypted_wire(44, 0, b"unrouted", 61),
                2,
            ),
        );
        let mut router = NullIngressRouter;

        let turn = driver.run_aead_raw_ingress_turn(
            [bad_wire, unrouted],
            &mut router,
            std::iter::empty(),
            8,
        );
        assert_eq!(turn.summary().raw_ingress_dropped(), 2);
        assert_eq!(turn.summary().inbound_admitted(), 0);
        assert_eq!(turn.summary().dispatched(), 0);
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(turn.raw_ingress_drops().len(), 2);
        assert_eq!(
            turn.raw_ingress_drops()[0].reason,
            PacketMover2RawIngressDropReason::Wire(WirePreflightError::TooShort)
        );
        assert_eq!(
            turn.raw_ingress_drops()[1].reason,
            PacketMover2RawIngressDropReason::Unrouted
        );
        assert_eq!(
            turn.raw_ingress_drops()[1].transport_id,
            TransportId::new(5)
        );
        assert_eq!(turn.raw_ingress_drops()[1].path, path);
    }

    #[test]
    fn runtime_raw_ingress_output_turn_batches_ordered_outputs_once() {
        let owner = OwnerId::fmp(85);
        let open_key = 73;
        let seal_key = 74;
        let path = TransportPath::new(9005);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(7, 8).with_next_send_counter(500));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));
        let received = ReceivedPacket::with_timestamp(
            TransportId::new(5),
            TransportAddr::from_string("198.51.100.9:9000"),
            fmp_encrypted_wire(85, 1200, 0, b"raw-in", open_key),
            123_456,
        );
        let raw = PacketMover2RawIngress::from_received(PacketProtocol::Fmp, path, received);
        let mut router = FixedIngressRouter {
            route: Some(
                PacketMover2IngressRoute::new(owner, 7, OutputTarget::Tun)
                    .with_class(PacketClass::Liveness),
            ),
        };
        let outbound =
            OutboundPacket::fmp(owner, 7, PacketClass::Bulk, 850, 0, b"raw-out".to_vec());
        let mut sink = BatchRecordingOutputSink::default();

        let turn =
            driver.run_aead_raw_ingress_output_turn([raw], &mut router, [outbound], &mut sink, 8);
        assert_eq!(
            turn.summary(),
            PacketMover2RuntimeSummary {
                raw_ingress_dropped: 0,
                inbound_admitted: 1,
                inbound_dropped: 0,
                outbound_admitted: 1,
                outbound_dropped: 0,
                dispatched: 2,
                outputs: 2,
                outputs_sent: 2,
                outputs_dropped: 0,
                drops: 0,
            }
        );
        assert!(turn.outputs().is_empty());
        assert!(turn.output_drops().is_empty());
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty());

        assert_eq!(sink.batch_calls, 1);
        assert_eq!(sink.outputs.len(), 2);
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::owner)
                .collect::<Vec<_>>(),
            vec![owner, owner]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![1200, 500]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::target)
                .collect::<Vec<_>>(),
            vec![OutputTarget::Tun, OutputTarget::Transport]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::path)
                .collect::<Vec<_>>(),
            vec![None, Some(path)]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::ingress_seq)
                .collect::<Vec<_>>(),
            vec![0, 0]
        );
        assert_eq!(
            &sink.outputs[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"raw-in"
        );
        assert_eq!(open_sealed_output(&sink.outputs[1], seal_key), b"raw-out");
    }

    #[test]
    fn runtime_output_sink_sends_ordered_outputs_once() {
        let owner = OwnerId::fmp(83);
        let key = 71;
        let path = TransportPath::new(8300);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(400));
        driver.owner_mut(owner).unwrap().set_active_path(path);
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        let inbound_tun = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(83, 10, 0, b"tun", key),
        )
        .unwrap();
        let inbound_endpoint = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Endpoint,
            fmp_encrypted_wire(83, 11, 0, b"endpoint", key),
        )
        .unwrap();
        let outbound =
            OutboundPacket::fmp(owner, 1, PacketClass::Bulk, 830, 0, b"transport".to_vec());
        let mut sink = RecordingOutputSink::default();

        let turn = driver.run_aead_classified_output_turn(
            [inbound_tun, inbound_endpoint],
            [outbound],
            &mut sink,
            8,
        );
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 3);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert!(turn.outputs().is_empty());
        assert!(turn.output_drops().is_empty());
        assert_eq!(
            sink.outputs
                .iter()
                .map(|output| output.target)
                .collect::<Vec<_>>(),
            vec![
                OutputTarget::Tun,
                OutputTarget::Endpoint,
                OutputTarget::Transport,
            ]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![10, 11, 400]
        );
        assert_eq!(sink.outputs[2].path, Some(path));
        assert_eq!(open_sealed_output(&sink.outputs[2], key), b"transport");
    }

    #[test]
    fn runtime_output_sink_reports_failures_without_retrying() {
        let owner = OwnerId::fsp(84);
        let key = 72;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        let packets = [
            SocketPacket::from_fsp_established_wire(
                owner,
                1,
                OutputTarget::Tun,
                fsp_encrypted_wire(20, 0, b"first", key),
            )
            .unwrap(),
            SocketPacket::from_fsp_established_wire(
                owner,
                1,
                OutputTarget::Endpoint,
                fsp_encrypted_wire(21, 0, b"second", key),
            )
            .unwrap(),
            SocketPacket::from_fsp_established_wire(
                owner,
                1,
                OutputTarget::Transport,
                fsp_encrypted_wire(22, 0, b"third", key),
            )
            .unwrap(),
        ];
        let mut sink = RecordingOutputSink {
            outputs: Vec::new(),
            fail_counter: Some(21),
        };

        let turn =
            driver.run_aead_classified_output_turn(packets, std::iter::empty(), &mut sink, 8);
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 2);
        assert_eq!(turn.summary().outputs_dropped(), 1);
        assert!(turn.outputs().is_empty());
        assert_eq!(
            sink.outputs
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![20, 22]
        );
        assert_eq!(turn.output_drops().len(), 1);
        let drop = &turn.output_drops()[0];
        assert_eq!(drop.owner, owner);
        assert_eq!(drop.counter, 21);
        assert_eq!(drop.ingress_seq, 1);
        assert_eq!(drop.target, OutputTarget::Endpoint);
        assert_eq!(drop.reason, PacketMover2OutputError::Backpressure);
        assert_eq!(drop.payload_len, FSP_HEADER_SIZE + b"second".len());
    }
}
