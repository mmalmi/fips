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

use crate::transport::PacketBuffer;
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

const FMP_VERSION: u8 = crate::node::wire::FMP_VERSION;
const FMP_PHASE_ESTABLISHED: u8 = crate::node::wire::PHASE_ESTABLISHED;
const FMP_ESTABLISHED_HEADER_SIZE: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
const FSP_VERSION: u8 = crate::node::session_wire::FSP_VERSION;
const FSP_PHASE_ESTABLISHED: u8 = crate::node::session_wire::FSP_PHASE_ESTABLISHED;
const FSP_HEADER_SIZE: usize = crate::node::session_wire::FSP_HEADER_SIZE;
const FSP_FLAG_U: u8 = crate::node::session_wire::FSP_FLAG_U;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocketPacket {
    owner: OwnerId,
    generation: u64,
    counter: u64,
    class: PacketClass,
    output: OutputTarget,
    payload: PacketBuffer,
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
            payload: payload.into(),
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerConfig {
    generation: u64,
    in_flight_limit: usize,
}

impl OwnerConfig {
    pub(crate) fn new(generation: u64, in_flight_limit: usize) -> Self {
        Self {
            generation,
            in_flight_limit,
        }
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
            accepted_counters: HashSet::new(),
            pending: BTreeMap::new(),
        }
    }

    pub(crate) fn rekey(&mut self, generation: u64) {
        self.generation = generation;
        self.accepted_counters.clear();
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
pub(crate) struct CryptoCompletion {
    reservation: OwnerReservation,
    result: CryptoResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CryptoResult {
    Opened(PacketOutput),
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketOutput {
    owner: OwnerId,
    counter: u64,
    ingress_seq: u64,
    target: OutputTarget,
    payload: PacketBuffer,
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
    counter: u64,
    ingress_seq: Option<u64>,
    lane: Lane,
    reason: PacketDropReason,
}

impl PacketDrop {
    fn from_queued(queued: &QueuedPacket, reason: PacketDropReason) -> Self {
        Self {
            owner: queued.packet.owner,
            counter: queued.packet.counter,
            ingress_seq: Some(queued.ingress_seq),
            lane: queued.packet.lane(),
            reason,
        }
    }

    fn from_completion(completion: &CryptoCompletion, reason: PacketDropReason) -> Self {
        Self {
            owner: completion.reservation.owner,
            counter: completion.reservation.counter,
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
            counter: drop.counter,
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
    cipher: LessSafeKey,
    header: AeadHeader,
    ciphertext_offset: usize,
}

impl AeadOpenWork {
    pub(crate) fn from_crypto_work(
        work: CryptoWork,
        cipher: LessSafeKey,
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
    owners: HashMap<OwnerId, OwnerState>,
    worker: W,
    drops: Vec<PacketDrop>,
}

impl<W: StatelessCryptoWorker> PacketMover2<W> {
    pub(crate) fn new(config: AdmissionConfig, worker: W) -> Self {
        Self {
            admission: AdmissionQueue::new(config),
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

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    #[cfg(test)]
    fn queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(drops[0].counter, 2);
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
        assert_eq!(drops[0].counter, 9);
        assert_eq!(drops[1].reason, PacketDropReason::Replay);
        assert_eq!(drops[1].counter, 8);

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
        assert!(
            drops
                .iter()
                .any(|drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter == 2)
        );
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
            let work = AeadOpenWork::from_crypto_work(work, test_cipher(key)).unwrap();
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

        let second = AeadOpenWork::from_crypto_work(work[1].clone(), test_cipher(1)).unwrap();
        assert!(mover.retire_completion(worker.execute(second)).is_empty());

        let first = AeadOpenWork::from_crypto_work(work[0].clone(), test_cipher(2)).unwrap();
        let retired = mover.retire_completion(worker.execute(first));
        assert_eq!(retired.len(), 2);
        match &retired[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.counter, 1);
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
}
