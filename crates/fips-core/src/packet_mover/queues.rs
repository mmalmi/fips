use super::{AdmissionDrop, AdmissionDropReason, PacketLane};
use crate::transport::{PacketRx, ReceivedPacket};
use crossbeam_channel::{
    Receiver as CrossbeamReceiver, Sender as CrossbeamSender, TrySendError as CrossbeamTrySendError,
};
use std::collections::{HashMap, VecDeque, hash_map::RandomState};
use std::hash::{BuildHasher, Hash};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering::Relaxed},
};
use tokio::sync::mpsc::{
    Receiver, Sender as TokioSender, error::TrySendError as TokioTrySendError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QueueCaps {
    pub(crate) priority_packets: usize,
    pub(crate) bulk_packets: usize,
}

impl QueueCaps {
    pub(crate) fn new(priority_packets: usize, bulk_packets: usize) -> Self {
        Self {
            priority_packets: priority_packets.max(1),
            bulk_packets: bulk_packets.max(1),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LaneCreditGate {
    lane: PacketLane,
    queued_packets: Arc<AtomicUsize>,
    capacity: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaneCreditReservation {
    lane: PacketLane,
    packet_count: usize,
}

impl LaneCreditReservation {
    pub(crate) fn lane(self) -> PacketLane {
        self.lane
    }

    pub(crate) fn packet_count(self) -> usize {
        self.packet_count
    }
}

impl LaneCreditGate {
    pub(crate) fn new(lane: PacketLane, capacity: usize) -> Self {
        Self {
            lane,
            queued_packets: Arc::new(AtomicUsize::new(0)),
            capacity: capacity.max(1),
        }
    }

    pub(crate) fn reserve(
        &self,
        packet_count: usize,
        byte_count: usize,
    ) -> Result<LaneCreditReservation, AdmissionDrop> {
        let packet_count = packet_count.max(1);
        self.reserve_with_previous(packet_count, byte_count)
            .map(|(reservation, _previous)| reservation)
    }

    pub(crate) fn reserve_with_previous(
        &self,
        packet_count: usize,
        byte_count: usize,
    ) -> Result<(LaneCreditReservation, usize), AdmissionDrop> {
        if packet_count == 0 {
            return Ok((
                LaneCreditReservation {
                    lane: self.lane,
                    packet_count: 0,
                },
                self.queued_packets(),
            ));
        }
        match self
            .queued_packets
            .fetch_update(Relaxed, Relaxed, |current| {
                current
                    .checked_add(packet_count)
                    .filter(|next| *next <= self.capacity)
            }) {
            Ok(previous) => Ok((
                LaneCreditReservation {
                    lane: self.lane,
                    packet_count,
                },
                previous,
            )),
            Err(_) => Err(self.pressure_drop(packet_count, byte_count)),
        }
    }

    pub(crate) fn reserve_prefix(&self, requested: usize) -> Option<LaneCreditReservation> {
        if requested == 0 {
            return None;
        }

        let mut current = self.queued_packets.load(Relaxed);
        loop {
            let available = self.capacity.saturating_sub(current);
            let granted = requested.min(available);
            if granted == 0 {
                return None;
            }
            match self.queued_packets.compare_exchange_weak(
                current,
                current + granted,
                Relaxed,
                Relaxed,
            ) {
                Ok(_) => {
                    return Some(LaneCreditReservation {
                        lane: self.lane,
                        packet_count: granted,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub(crate) fn release(&self, reservation: LaneCreditReservation) {
        debug_assert_eq!(reservation.lane, self.lane);
        self.release_count(reservation.packet_count);
    }

    pub(crate) fn release_count(&self, count: usize) {
        if count == 0 {
            return;
        }

        let previous = self.queued_packets.fetch_sub(count, Relaxed);
        debug_assert!(
            previous >= count,
            "packet mover lane credit accounting underflow"
        );
    }

    pub(crate) fn pressure_drop(&self, packet_count: usize, byte_count: usize) -> AdmissionDrop {
        AdmissionDrop::pressure(self.lane, packet_count, byte_count)
    }

    pub(crate) fn queued_packets(&self) -> usize {
        self.queued_packets.load(Relaxed)
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }
}

pub(crate) struct FlowCreditGate<K, S = RandomState> {
    state: Mutex<FlowCreditState<K, S>>,
    not_full: Condvar,
    reserved_len: AtomicUsize,
    total_cap: usize,
    per_flow_cap: usize,
    min_weight: usize,
    max_weight: usize,
}

struct FlowCreditState<K, S> {
    flows: HashMap<K, FlowCreditQueue, S>,
    total_len: usize,
    full_waiters: usize,
    closed: bool,
}

struct FlowCreditQueue {
    queued: usize,
    weight: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowCreditReservation<K> {
    key: K,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlowCreditReserve<K> {
    Reserved(FlowCreditReservation<K>),
    Full,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowCreditClosed;

impl<K> FlowCreditReservation<K>
where
    K: Copy,
{
    pub(crate) fn key(&self) -> K {
        self.key
    }
}

impl FlowCreditQueue {
    fn new(weight: usize) -> Self {
        Self { queued: 0, weight }
    }
}

impl<K, S> FlowCreditState<K, S>
where
    S: BuildHasher + Default,
{
    fn new() -> Self {
        Self {
            flows: HashMap::with_hasher(S::default()),
            total_len: 0,
            full_waiters: 0,
            closed: false,
        }
    }
}

impl<K> FlowCreditGate<K, RandomState>
where
    K: Copy + Eq + Hash,
{
    pub(crate) fn new(
        total_cap: usize,
        per_flow_cap: usize,
        min_weight: usize,
        max_weight: usize,
    ) -> Self {
        Self::new_with_hasher(total_cap, per_flow_cap, min_weight, max_weight)
    }
}

impl<K, S> FlowCreditGate<K, S>
where
    K: Copy + Eq + Hash,
    S: BuildHasher + Default,
{
    pub(crate) fn new_with_hasher(
        total_cap: usize,
        per_flow_cap: usize,
        min_weight: usize,
        max_weight: usize,
    ) -> Self {
        let total_cap = total_cap.max(1);
        let per_flow_cap = per_flow_cap.max(1);
        let min_weight = min_weight.max(1);
        let max_weight = max_weight.max(min_weight);
        Self {
            state: Mutex::new(FlowCreditState::new()),
            not_full: Condvar::new(),
            reserved_len: AtomicUsize::new(0),
            total_cap,
            per_flow_cap,
            min_weight,
            max_weight,
        }
    }

    pub(crate) fn try_reserve(&self, key: K, weight: usize) -> FlowCreditReserve<K> {
        let mut state = self
            .state
            .lock()
            .expect("packet mover flow credit gate poisoned");
        if state.closed {
            return FlowCreditReserve::Closed;
        }
        if self.reserve_locked(&mut state, key, weight) {
            self.reserved_len.store(state.total_len, Relaxed);
            return FlowCreditReserve::Reserved(FlowCreditReservation { key });
        }
        FlowCreditReserve::Full
    }

    pub(crate) fn reserve_blocking(
        &self,
        key: K,
        weight: usize,
    ) -> Result<FlowCreditReservation<K>, FlowCreditClosed> {
        let mut state = self
            .state
            .lock()
            .expect("packet mover flow credit gate poisoned");
        loop {
            if state.closed {
                return Err(FlowCreditClosed);
            }
            if self.reserve_locked(&mut state, key, weight) {
                self.reserved_len.store(state.total_len, Relaxed);
                return Ok(FlowCreditReservation { key });
            }
            state.full_waiters = state.full_waiters.saturating_add(1);
            state = self
                .not_full
                .wait(state)
                .expect("packet mover flow credit gate poisoned");
            state.full_waiters = state.full_waiters.saturating_sub(1);
        }
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.reserved_len.load(Relaxed) == 0
    }

    pub(crate) fn release(&self, reservation: FlowCreditReservation<K>) {
        self.release_many(std::slice::from_ref(&reservation));
    }

    pub(crate) fn release_many(&self, reservations: &[FlowCreditReservation<K>]) {
        if reservations.is_empty() {
            return;
        }
        let mut state = self
            .state
            .lock()
            .expect("packet mover flow credit gate poisoned");
        for reservation in reservations {
            let key = reservation.key();
            if let Some(flow) = state.flows.get_mut(&key) {
                flow.queued = flow.queued.saturating_sub(1);
                if flow.queued == 0 {
                    state.flows.remove(&key);
                }
            }
            state.total_len = state.total_len.saturating_sub(1);
        }
        self.reserved_len.store(state.total_len, Relaxed);
        let should_notify = state.full_waiters > 0;
        drop(state);
        if should_notify {
            self.not_full.notify_all();
        }
    }

    pub(crate) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .expect("packet mover flow credit gate poisoned");
        state.closed = true;
        drop(state);
        self.not_full.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn queued_packets(&self) -> usize {
        self.reserved_len.load(Relaxed)
    }

    fn reserve_locked(&self, state: &mut FlowCreditState<K, S>, key: K, weight: usize) -> bool {
        if state.total_len.saturating_add(1) > self.total_cap {
            return false;
        }
        let weight = weight.clamp(self.min_weight, self.max_weight);
        match state.flows.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let flow = entry.get_mut();
                flow.weight = flow.weight.max(weight);
                let cap = self
                    .per_flow_cap
                    .saturating_mul(flow.weight)
                    .min(self.total_cap)
                    .max(1);
                if flow.queued.saturating_add(1) > cap {
                    return false;
                }
                flow.queued = flow.queued.saturating_add(1);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mut flow = FlowCreditQueue::new(weight);
                flow.queued = 1;
                entry.insert(flow);
            }
        }
        state.total_len = state.total_len.saturating_add(1);
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QueuedPacket<T> {
    pub(crate) item: T,
    pub(crate) lane: PacketLane,
    pub(crate) packet_count: usize,
    pub(crate) byte_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QueueAdmission<T> {
    Enqueued,
    Dropped { item: T, drop: AdmissionDrop },
}

#[derive(Debug)]
pub(crate) struct BoundedLaneQueues<T> {
    caps: QueueCaps,
    priority_packets: usize,
    bulk_packets: usize,
    priority: VecDeque<QueuedPacket<T>>,
    bulk: VecDeque<QueuedPacket<T>>,
}

pub(crate) struct PriorityBulkLaneSender<T> {
    priority: TokioSender<T>,
    bulk: TokioSender<T>,
    bulk_credits: LaneCreditGate,
}

impl<T> Clone for PriorityBulkLaneSender<T> {
    fn clone(&self) -> Self {
        Self {
            priority: self.priority.clone(),
            bulk: self.bulk.clone(),
            bulk_credits: self.bulk_credits.clone(),
        }
    }
}

pub(crate) struct PriorityBulkLaneReceivers<T> {
    priority: Receiver<T>,
    bulk: Receiver<T>,
    bulk_credits: LaneCreditGate,
}

pub(crate) trait SplitBulkLaneItem: Sized {
    fn packet_count(&self) -> usize;

    fn split_at_packet_count(self, packet_count: usize) -> (Option<Self>, Option<Self>);
}

pub(crate) struct BulkLanePrefixSender<T> {
    tx: CrossbeamSender<T>,
    credits: LaneCreditGate,
}

impl<T> Clone for BulkLanePrefixSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            credits: self.credits.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BulkLanePrefixRejectReason {
    CreditPressure,
    ChannelFull,
    ReceiverClosed,
}

#[derive(Debug)]
pub(crate) struct BulkLanePrefixReject<T> {
    pub(crate) item: T,
    pub(crate) overflow: Option<T>,
    pub(crate) reason: BulkLanePrefixRejectReason,
}

#[derive(Debug)]
pub(crate) enum BulkLanePrefixSendResult<T> {
    Sent {
        reserved_packets: usize,
        overflow: Option<T>,
    },
    Rejected(BulkLanePrefixReject<T>),
}

#[derive(Debug)]
pub(crate) struct BulkLanePrefixReturned<R> {
    pub(crate) reserved_packets: usize,
    pub(crate) returned: Vec<R>,
    pub(crate) rejected: Option<BulkLanePrefixRejectReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PriorityBulkLaneDropReason {
    CreditPressure,
    ChannelFull,
    ReceiverClosed,
}

#[derive(Debug)]
pub(crate) struct PriorityBulkLaneDrop<T> {
    pub(crate) item: T,
    pub(crate) drop: AdmissionDrop,
    pub(crate) reason: PriorityBulkLaneDropReason,
}

#[derive(Debug)]
pub(crate) enum PriorityBulkLaneSendResult<T> {
    Sent { previous_bulk_queued: Option<usize> },
    Dropped(PriorityBulkLaneDrop<T>),
}

pub(crate) fn priority_bulk_lane_channels<T>(
    priority_cap: usize,
    bulk_cap: usize,
) -> (PriorityBulkLaneSender<T>, PriorityBulkLaneReceivers<T>) {
    let (priority_tx, priority_rx) = tokio::sync::mpsc::channel(priority_cap.max(1));
    let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(bulk_cap.max(1));
    let bulk_credits = LaneCreditGate::new(PacketLane::Bulk, bulk_cap);
    (
        PriorityBulkLaneSender {
            priority: priority_tx,
            bulk: bulk_tx,
            bulk_credits: bulk_credits.clone(),
        },
        PriorityBulkLaneReceivers {
            priority: priority_rx,
            bulk: bulk_rx,
            bulk_credits,
        },
    )
}

impl<T> PriorityBulkLaneSender<T> {
    pub(crate) fn try_send(
        &self,
        item: T,
        lane: PacketLane,
        packet_count: usize,
        byte_count: usize,
    ) -> PriorityBulkLaneSendResult<T> {
        let mut bulk_reservation = None;
        let mut previous_bulk_queued = None;

        if matches!(lane, PacketLane::Bulk) {
            match self
                .bulk_credits
                .reserve_with_previous(packet_count, byte_count)
            {
                Ok((reservation, previous)) => {
                    bulk_reservation = Some(reservation);
                    previous_bulk_queued = Some(previous);
                }
                Err(drop) => {
                    return PriorityBulkLaneSendResult::Dropped(PriorityBulkLaneDrop {
                        item,
                        drop,
                        reason: PriorityBulkLaneDropReason::CreditPressure,
                    });
                }
            }
        }

        let result = match lane {
            PacketLane::Priority => self.priority.try_send(item),
            PacketLane::Bulk => self.bulk.try_send(item),
        };

        match result {
            Ok(()) => PriorityBulkLaneSendResult::Sent {
                previous_bulk_queued,
            },
            Err(TokioTrySendError::Full(item)) => {
                if let Some(reservation) = bulk_reservation {
                    self.bulk_credits.release(reservation);
                }
                PriorityBulkLaneSendResult::Dropped(PriorityBulkLaneDrop {
                    item,
                    drop: AdmissionDrop::pressure(lane, packet_count, byte_count),
                    reason: PriorityBulkLaneDropReason::ChannelFull,
                })
            }
            Err(TokioTrySendError::Closed(item)) => {
                if let Some(reservation) = bulk_reservation {
                    self.bulk_credits.release(reservation);
                }
                PriorityBulkLaneSendResult::Dropped(PriorityBulkLaneDrop {
                    item,
                    drop: AdmissionDrop {
                        reason: AdmissionDropReason::ReceiverClosed,
                        lane,
                        packet_count,
                        byte_count,
                    },
                    reason: PriorityBulkLaneDropReason::ReceiverClosed,
                })
            }
        }
    }

    pub(crate) fn bulk_capacity(&self) -> usize {
        self.bulk_credits.capacity()
    }
}

impl<T> BulkLanePrefixSender<T> {
    pub(crate) fn new(tx: CrossbeamSender<T>, credits: LaneCreditGate) -> Self {
        Self { tx, credits }
    }

    pub(crate) fn queued_packets(&self) -> usize {
        self.credits.queued_packets()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.credits.capacity()
    }

    #[cfg(test)]
    pub(crate) fn reserve_for_test(
        &self,
        packet_count: usize,
    ) -> Result<LaneCreditReservation, AdmissionDrop> {
        self.credits.reserve(packet_count, 0)
    }
}

impl<T: SplitBulkLaneItem> BulkLanePrefixSender<T> {
    pub(crate) fn try_send_prefix(&self, item: T) -> BulkLanePrefixSendResult<T> {
        let packet_count = item.packet_count();
        let Some(reservation) = self.credits.reserve_prefix(packet_count) else {
            return BulkLanePrefixSendResult::Rejected(BulkLanePrefixReject {
                item,
                overflow: None,
                reason: BulkLanePrefixRejectReason::CreditPressure,
            });
        };
        let reserved_packets = reservation.packet_count();

        let (reserved_item, overflow) = item.split_at_packet_count(reserved_packets);
        let reserved_item = reserved_item.expect("positive reservation must produce a bulk item");

        match self.tx.try_send(reserved_item) {
            Ok(()) => BulkLanePrefixSendResult::Sent {
                reserved_packets,
                overflow,
            },
            Err(CrossbeamTrySendError::Full(item)) => {
                self.credits.release(reservation);
                BulkLanePrefixSendResult::Rejected(BulkLanePrefixReject {
                    item,
                    overflow,
                    reason: BulkLanePrefixRejectReason::ChannelFull,
                })
            }
            Err(CrossbeamTrySendError::Disconnected(item)) => {
                self.credits.release(reservation);
                BulkLanePrefixSendResult::Rejected(BulkLanePrefixReject {
                    item,
                    overflow,
                    reason: BulkLanePrefixRejectReason::ReceiverClosed,
                })
            }
        }
    }

    pub(crate) fn try_send_prefix_returning<R>(
        &self,
        item: T,
        mut returned_from_item: impl FnMut(T) -> Vec<R>,
    ) -> BulkLanePrefixReturned<R> {
        match self.try_send_prefix(item) {
            BulkLanePrefixSendResult::Sent {
                reserved_packets,
                overflow,
            } => BulkLanePrefixReturned {
                reserved_packets,
                returned: overflow.map(returned_from_item).unwrap_or_default(),
                rejected: None,
            },
            BulkLanePrefixSendResult::Rejected(reject) => {
                let mut returned = returned_from_item(reject.item);
                if let Some(overflow) = reject.overflow {
                    returned.extend(returned_from_item(overflow));
                }
                BulkLanePrefixReturned {
                    reserved_packets: 0,
                    returned,
                    rejected: Some(reject.reason),
                }
            }
        }
    }
}

impl<T> PriorityBulkLaneReceivers<T> {
    pub(crate) fn into_parts(self) -> (Receiver<T>, Receiver<T>, LaneCreditGate) {
        (self.priority, self.bulk, self.bulk_credits)
    }
}

impl<T> BoundedLaneQueues<T> {
    pub(crate) fn new(caps: QueueCaps) -> Self {
        Self {
            caps,
            priority_packets: 0,
            bulk_packets: 0,
            priority: VecDeque::new(),
            bulk: VecDeque::new(),
        }
    }

    pub(crate) fn push(
        &mut self,
        item: T,
        lane: PacketLane,
        packet_count: usize,
        byte_count: usize,
    ) -> QueueAdmission<T> {
        let packet_count = packet_count.max(1);
        let (queued, cap, reason) = match lane {
            PacketLane::Priority => (
                &mut self.priority_packets,
                self.caps.priority_packets,
                AdmissionDropReason::PriorityPressure,
            ),
            PacketLane::Bulk => (
                &mut self.bulk_packets,
                self.caps.bulk_packets,
                AdmissionDropReason::BulkPressure,
            ),
        };
        if queued.saturating_add(packet_count) > cap {
            return QueueAdmission::Dropped {
                item,
                drop: AdmissionDrop {
                    reason,
                    lane,
                    packet_count,
                    byte_count,
                },
            };
        }

        *queued += packet_count;
        let queued_packet = QueuedPacket {
            item,
            lane,
            packet_count,
            byte_count,
        };
        match lane {
            PacketLane::Priority => self.priority.push_back(queued_packet),
            PacketLane::Bulk => self.bulk.push_back(queued_packet),
        }
        QueueAdmission::Enqueued
    }

    pub(crate) fn pop(&mut self) -> Option<QueuedPacket<T>> {
        let packet = self
            .priority
            .pop_front()
            .or_else(|| self.bulk.pop_front())?;
        match packet.lane {
            PacketLane::Priority => {
                self.priority_packets = self.priority_packets.saturating_sub(packet.packet_count);
            }
            PacketLane::Bulk => {
                self.bulk_packets = self.bulk_packets.saturating_sub(packet.packet_count);
            }
        }
        Some(packet)
    }

    pub(crate) fn queued_packets(&self, lane: PacketLane) -> usize {
        match lane {
            PacketLane::Priority => self.priority_packets,
            PacketLane::Bulk => self.bulk_packets,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DispatchBatcher<K, T> {
    key: Option<K>,
    items: Vec<T>,
    buffer_capacity: usize,
}

impl<K: Copy + Eq, T> DispatchBatcher<K, T> {
    pub(crate) fn new(buffer_capacity: usize) -> Self {
        Self {
            key: None,
            items: Vec::with_capacity(buffer_capacity),
            buffer_capacity,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.key.is_none() && self.items.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn pending_buffer_ptr(&self) -> *const T {
        self.items.as_ptr()
    }

    pub(crate) fn push(
        &mut self,
        key: K,
        batch_max: usize,
        item: T,
        mut dispatch: impl FnMut(K, Vec<T>) -> Vec<T>,
    ) -> Vec<T> {
        let mut returned = Vec::new();
        let batch_max = batch_max.max(1);
        if self.key != Some(key) || self.items.len() >= batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }

        self.key = Some(key);
        self.items.push(item);

        if self.items.len() >= batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }
        returned
    }

    pub(crate) fn push_with_single(
        &mut self,
        key: K,
        batch_max: usize,
        item: T,
        mut dispatch_single: impl FnMut(K, T) -> Vec<T>,
        mut dispatch_batch: impl FnMut(K, Vec<T>) -> Vec<T>,
    ) -> Vec<T> {
        let mut returned = Vec::new();
        let batch_max = batch_max.max(1);
        if self.key != Some(key) || self.items.len() >= batch_max {
            returned.extend(self.flush_with_single(&mut dispatch_single, &mut dispatch_batch));
        }

        self.key = Some(key);
        self.items.push(item);

        if self.items.len() >= batch_max {
            returned.extend(self.flush_with_single(&mut dispatch_single, &mut dispatch_batch));
        }
        returned
    }

    pub(crate) fn push_batch(
        &mut self,
        key: K,
        batch_max: usize,
        items: Vec<T>,
        mut dispatch: impl FnMut(K, Vec<T>) -> Vec<T>,
    ) -> Vec<T> {
        if items.is_empty() {
            return Vec::new();
        }

        let mut returned = Vec::new();
        let batch_max = batch_max.max(1);
        if self.key != Some(key) || self.items.len().saturating_add(items.len()) > batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }

        self.key = Some(key);
        if self.items.is_empty() {
            self.items = items;
            if self.items.len() >= batch_max {
                returned.extend(self.flush_with(&mut dispatch));
            }
            return returned;
        }

        self.items.extend(items);
        if self.items.len() >= batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }
        returned
    }

    pub(crate) fn flush(&mut self, mut dispatch: impl FnMut(K, Vec<T>) -> Vec<T>) -> Vec<T> {
        self.flush_with(&mut dispatch)
    }

    pub(crate) fn flush_with_single(
        &mut self,
        mut dispatch_single: impl FnMut(K, T) -> Vec<T>,
        mut dispatch_batch: impl FnMut(K, Vec<T>) -> Vec<T>,
    ) -> Vec<T> {
        self.flush_with_single_fns(&mut dispatch_single, &mut dispatch_batch)
    }

    fn flush_with(&mut self, dispatch: &mut impl FnMut(K, Vec<T>) -> Vec<T>) -> Vec<T> {
        let Some(key) = self.key.take() else {
            return Vec::new();
        };
        if self.items.is_empty() {
            return Vec::new();
        }

        let items = std::mem::replace(&mut self.items, Vec::with_capacity(self.buffer_capacity));
        dispatch(key, items)
    }

    fn flush_with_single_fns(
        &mut self,
        dispatch_single: &mut impl FnMut(K, T) -> Vec<T>,
        dispatch_batch: &mut impl FnMut(K, Vec<T>) -> Vec<T>,
    ) -> Vec<T> {
        let Some(key) = self.key.take() else {
            return Vec::new();
        };
        if self.items.is_empty() {
            return Vec::new();
        }
        if self.items.len() == 1 {
            let item = self.items.pop().expect("checked single pending item");
            return dispatch_single(key, item);
        }

        let items = std::mem::replace(&mut self.items, Vec::with_capacity(self.buffer_capacity));
        dispatch_batch(key, items)
    }
}

pub(crate) struct PriorityBulkDrainCursor<T> {
    first_priority: Option<T>,
    first_bulk: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> PriorityBulkDrainCursor<T> {
    pub(crate) fn new(first_priority: Option<T>, first_bulk: Option<T>, budget: usize) -> Self {
        Self {
            first_priority,
            first_bulk,
            remaining: budget,
            drained: 0,
        }
    }

    pub(crate) fn next(
        &mut self,
        priority_rx: &mut Receiver<T>,
        bulk_rx: &mut Receiver<T>,
    ) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let item = if let Some(item) = self.first_priority.take() {
            Some(item)
        } else {
            priority_rx
                .try_recv()
                .ok()
                .or_else(|| self.first_bulk.take())
                .or_else(|| bulk_rx.try_recv().ok())
        }?;

        self.remaining -= 1;
        self.drained += 1;
        Some(item)
    }

    pub(crate) fn next_bulk_if_no_priority(
        &mut self,
        priority_rx: &mut Receiver<T>,
        bulk_rx: &mut Receiver<T>,
    ) -> Option<T> {
        if self.remaining == 0 || self.first_priority.is_some() || !priority_rx.is_empty() {
            return None;
        }

        let item = self.first_bulk.take().or_else(|| bulk_rx.try_recv().ok())?;
        self.remaining -= 1;
        self.drained += 1;
        Some(item)
    }

    pub(crate) fn defer_bulk(&mut self, item: T) {
        debug_assert!(
            self.first_bulk.is_none(),
            "priority/bulk drain already has a deferred bulk item"
        );
        self.first_bulk = Some(item);
        self.remaining = self.remaining.saturating_add(1);
        self.drained = self.drained.saturating_sub(1);
    }

    pub(crate) fn drained(&self) -> usize {
        self.drained
    }

    pub(crate) fn charge_extra(&mut self, extra: usize) {
        self.remaining = self.remaining.saturating_sub(extra);
        self.drained = self.drained.saturating_add(extra);
    }
}

pub(crate) struct SingleLaneDrainCursor<T> {
    first_item: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> SingleLaneDrainCursor<T> {
    pub(crate) fn new(first_item: Option<T>, budget: usize) -> Self {
        Self {
            first_item,
            remaining: budget,
            drained: 0,
        }
    }

    pub(crate) fn next(&mut self, rx: &mut Receiver<T>) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let packet = self.first_item.take().or_else(|| rx.try_recv().ok())?;
        self.remaining -= 1;
        self.drained += 1;
        Some(packet)
    }

    pub(crate) fn drained(&self) -> usize {
        self.drained
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PacketDrainAction<T> {
    Packet(T),
    InterleaveDecryptReturn,
    InterleaveSideQueues,
}

pub(crate) struct PacketDrainCursor<T> {
    first_packet: Option<T>,
    remaining: usize,
    drained: usize,
    decrypt_return_interleave_every: usize,
    side_queue_interleave_every: usize,
    packets_until_decrypt_return_interleave: usize,
    packets_until_side_queue_interleave: usize,
}

impl<T> PacketDrainCursor<T> {
    pub(crate) fn new(
        first_packet: Option<T>,
        budget: usize,
        decrypt_return_interleave_every: usize,
        side_queue_interleave_every: usize,
    ) -> Self {
        Self {
            first_packet,
            remaining: budget,
            drained: 0,
            decrypt_return_interleave_every,
            side_queue_interleave_every,
            packets_until_decrypt_return_interleave: decrypt_return_interleave_every,
            packets_until_side_queue_interleave: side_queue_interleave_every,
        }
    }

    pub(crate) fn next<R>(&mut self, packet_rx: &mut R) -> Option<PacketDrainAction<T>>
    where
        R: PacketDrainReceiver<T>,
    {
        if self.remaining == 0 {
            return None;
        }

        if self.decrypt_return_interleave_due() {
            self.packets_until_decrypt_return_interleave = self.decrypt_return_interleave_every;
            self.charge_interleave_turn();
            return Some(PacketDrainAction::InterleaveDecryptReturn);
        }

        if self.side_queue_interleave_due() {
            self.packets_until_side_queue_interleave = self.side_queue_interleave_every;
            self.charge_interleave_turn();
            return Some(PacketDrainAction::InterleaveSideQueues);
        }

        let packet = self
            .first_packet
            .take()
            .or_else(|| packet_rx.try_recv_packet())?;
        self.charge_packet();
        Some(PacketDrainAction::Packet(packet))
    }

    pub(crate) fn drained(&self) -> usize {
        self.drained
    }

    fn decrypt_return_interleave_due(&self) -> bool {
        self.drained > 0
            && self.decrypt_return_interleave_every > 0
            && self.packets_until_decrypt_return_interleave == 0
    }

    fn side_queue_interleave_due(&self) -> bool {
        self.drained > 0
            && self.side_queue_interleave_every > 0
            && self.packets_until_side_queue_interleave == 0
    }

    fn charge_packet(&mut self) {
        self.remaining -= 1;
        self.drained += 1;
        if self.packets_until_decrypt_return_interleave > 0 {
            self.packets_until_decrypt_return_interleave -= 1;
        }
        if self.packets_until_side_queue_interleave > 0 {
            self.packets_until_side_queue_interleave -= 1;
        }
    }

    fn charge_interleave_turn(&mut self) {
        self.remaining -= 1;
    }

    pub(crate) fn refund_empty_interleave_turn(&mut self) {
        self.remaining += 1;
    }
}

pub(crate) trait PacketDrainReceiver<T> {
    fn try_recv_packet(&mut self) -> Option<T>;
}

impl<T> PacketDrainReceiver<T> for tokio::sync::mpsc::UnboundedReceiver<T> {
    fn try_recv_packet(&mut self) -> Option<T> {
        self.try_recv().ok()
    }
}

impl PacketDrainReceiver<ReceivedPacket> for PacketRx {
    fn try_recv_packet(&mut self) -> Option<ReceivedPacket> {
        self.try_recv().ok()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum WorkerReservedQueueItem<C, P> {
    Control(C),
    Priority(P),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum WorkerQueueItem<C, P, R, B> {
    Control(C),
    Priority(P),
    Completion(R),
    Bulk(B),
    Closed,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum WorkerDrainAction<C, P, R, B> {
    Control {
        item: C,
        flush_completion_outputs: bool,
    },
    Priority {
        item: P,
        flush_completion_outputs: bool,
    },
    Completion(R),
    FlushCompletionOutputs,
    Bulk(B),
}

#[derive(Debug)]
pub(crate) struct WorkerDrainCursor {
    remaining_bulk_items: usize,
    remaining_completion_packets: usize,
    completion_outputs_need_flush: bool,
}

pub(crate) fn try_recv_reserved_worker_queue_item<C, P>(
    control_rx: &CrossbeamReceiver<C>,
    priority_rx: &CrossbeamReceiver<P>,
) -> Option<WorkerReservedQueueItem<C, P>> {
    if let Ok(item) = control_rx.try_recv() {
        return Some(WorkerReservedQueueItem::Control(item));
    }
    if let Ok(item) = priority_rx.try_recv() {
        return Some(WorkerReservedQueueItem::Priority(item));
    }
    None
}

pub(crate) fn recv_biased_worker_queue_item<C, P, R, B>(
    control_rx: &CrossbeamReceiver<C>,
    priority_rx: &CrossbeamReceiver<P>,
    completion_rx: &CrossbeamReceiver<R>,
    bulk_rx: &CrossbeamReceiver<B>,
) -> WorkerQueueItem<C, P, R, B> {
    if let Some(item) = try_recv_reserved_worker_queue_item(control_rx, priority_rx) {
        return match item {
            WorkerReservedQueueItem::Control(item) => WorkerQueueItem::Control(item),
            WorkerReservedQueueItem::Priority(item) => WorkerQueueItem::Priority(item),
        };
    }
    if let Ok(item) = completion_rx.try_recv() {
        return WorkerQueueItem::Completion(item);
    }

    crossbeam_channel::select_biased! {
        recv(control_rx) -> item => match item {
            Ok(item) => WorkerQueueItem::Control(item),
            Err(_) => WorkerQueueItem::Closed,
        },
        recv(priority_rx) -> item => match item {
            Ok(item) => WorkerQueueItem::Priority(item),
            Err(_) => WorkerQueueItem::Closed,
        },
        recv(completion_rx) -> item => match item {
            Ok(item) => WorkerQueueItem::Completion(item),
            Err(_) => WorkerQueueItem::Closed,
        },
        recv(bulk_rx) -> item => match item {
            Ok(item) => WorkerQueueItem::Bulk(item),
            Err(_) => WorkerQueueItem::Closed,
        },
    }
}

impl WorkerDrainCursor {
    pub(crate) fn new(bulk_item_budget: usize, completion_packet_budget: usize) -> Self {
        Self {
            remaining_bulk_items: bulk_item_budget,
            remaining_completion_packets: completion_packet_budget,
            completion_outputs_need_flush: false,
        }
    }

    pub(crate) fn next<C, P, R, B>(
        &mut self,
        control_rx: &CrossbeamReceiver<C>,
        priority_rx: &CrossbeamReceiver<P>,
        completion_rx: &CrossbeamReceiver<R>,
        bulk_rx: &CrossbeamReceiver<B>,
        mut completion_packet_count: impl FnMut(&R) -> usize,
    ) -> Option<WorkerDrainAction<C, P, R, B>> {
        if self.remaining_bulk_items == 0 {
            return None;
        }

        if let Some(item) = try_recv_reserved_worker_queue_item(control_rx, priority_rx) {
            let flush_completion_outputs = std::mem::take(&mut self.completion_outputs_need_flush);
            return Some(match item {
                WorkerReservedQueueItem::Control(item) => WorkerDrainAction::Control {
                    item,
                    flush_completion_outputs,
                },
                WorkerReservedQueueItem::Priority(item) => WorkerDrainAction::Priority {
                    item,
                    flush_completion_outputs,
                },
            });
        }

        if self.remaining_completion_packets > 0
            && let Ok(item) = completion_rx.try_recv()
        {
            self.remaining_completion_packets = self
                .remaining_completion_packets
                .saturating_sub(completion_packet_count(&item).max(1));
            self.completion_outputs_need_flush = true;
            return Some(WorkerDrainAction::Completion(item));
        }

        if self.completion_outputs_need_flush {
            self.completion_outputs_need_flush = false;
            return Some(WorkerDrainAction::FlushCompletionOutputs);
        }

        bulk_rx.try_recv().ok().map(WorkerDrainAction::Bulk)
    }

    pub(crate) fn charge_bulk_work(&mut self, count: usize) {
        self.remaining_bulk_items = self.remaining_bulk_items.saturating_sub(count.max(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct TestBulk(Vec<usize>);

    impl SplitBulkLaneItem for TestBulk {
        fn packet_count(&self) -> usize {
            self.0.len()
        }

        fn split_at_packet_count(
            self,
            packet_count: usize,
        ) -> (Option<TestBulk>, Option<TestBulk>) {
            if packet_count == 0 {
                return (None, Some(self));
            }
            let mut packets = self.0;
            if packet_count >= packets.len() {
                return (Some(TestBulk(packets)), None);
            }
            let overflow = packets.split_off(packet_count);
            (Some(TestBulk(packets)), Some(TestBulk(overflow)))
        }
    }

    #[test]
    fn priority_queue_drains_before_bulk() {
        let mut queues = BoundedLaneQueues::new(QueueCaps::new(2, 2));
        assert_eq!(
            queues.push("bulk", PacketLane::Bulk, 1, 100),
            QueueAdmission::Enqueued
        );
        assert_eq!(
            queues.push("priority", PacketLane::Priority, 1, 20),
            QueueAdmission::Enqueued
        );

        assert_eq!(queues.pop().expect("priority").item, "priority");
        assert_eq!(queues.pop().expect("bulk").item, "bulk");
        assert!(queues.pop().is_none());
    }

    #[test]
    fn bulk_pressure_is_explicit_and_attributable() {
        let mut queues = BoundedLaneQueues::new(QueueCaps::new(1, 1));
        assert_eq!(
            queues.push("bulk-1", PacketLane::Bulk, 1, 100),
            QueueAdmission::Enqueued
        );

        let QueueAdmission::Dropped { item, drop } =
            queues.push("bulk-2", PacketLane::Bulk, 1, 200)
        else {
            panic!("second bulk packet must drop under bulk pressure");
        };

        assert_eq!(item, "bulk-2");
        assert_eq!(drop.reason, AdmissionDropReason::BulkPressure);
        assert_eq!(drop.lane, PacketLane::Bulk);
        assert_eq!(drop.packet_count, 1);
        assert_eq!(drop.byte_count, 200);
        assert_eq!(queues.queued_packets(PacketLane::Bulk), 1);
    }

    #[test]
    fn lane_credit_gate_reports_pressure_without_expanding_queue() {
        let gate = LaneCreditGate::new(PacketLane::Bulk, 1);

        let reservation = gate.reserve(1, 100).expect("first packet");
        let drop = gate.reserve(1, 200).expect_err("bulk lane should be full");

        assert_eq!(drop.reason, AdmissionDropReason::BulkPressure);
        assert_eq!(drop.lane, PacketLane::Bulk);
        assert_eq!(drop.packet_count, 1);
        assert_eq!(drop.byte_count, 200);
        assert_eq!(gate.queued_packets(), 1);

        gate.release(reservation);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn lane_credit_gate_can_reserve_prefix_and_release_exact_count() {
        let gate = LaneCreditGate::new(PacketLane::Priority, 3);
        let existing = gate.reserve(1, 10).expect("existing packet");

        let prefix = gate.reserve_prefix(4).expect("partial prefix");

        assert_eq!(prefix.lane(), PacketLane::Priority);
        assert_eq!(prefix.packet_count(), 2);
        assert_eq!(gate.queued_packets(), 3);
        assert!(gate.reserve_prefix(1).is_none());

        gate.release(prefix);
        assert_eq!(gate.queued_packets(), 1);
        gate.release(existing);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn lane_credit_gate_reports_previous_depth_for_backlog_edges() {
        let gate = LaneCreditGate::new(PacketLane::Bulk, 4);

        let (first, previous) = gate.reserve_with_previous(2, 200).expect("first");
        assert_eq!(previous, 0);
        assert_eq!(gate.queued_packets(), 2);

        let (second, previous) = gate.reserve_with_previous(2, 200).expect("second");
        assert_eq!(previous, 2);
        assert_eq!(gate.queued_packets(), 4);
        assert!(gate.reserve_with_previous(1, 100).is_err());

        gate.release(first);
        gate.release(second);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn lane_credit_gate_zero_count_reservation_does_not_consume_capacity() {
        let gate = LaneCreditGate::new(PacketLane::Bulk, 1);

        let (reservation, previous) = gate.reserve_with_previous(0, 0).expect("zero");

        assert_eq!(previous, 0);
        assert_eq!(reservation.packet_count(), 0);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn flow_credit_gate_bounds_total_and_per_flow_progress() {
        let gate = FlowCreditGate::new(2, 1, 1, 4);
        assert!(gate.is_idle());

        let first = match gate.try_reserve(7u8, 1) {
            FlowCreditReserve::Reserved(reservation) => reservation,
            FlowCreditReserve::Full => panic!("first flow packet should reserve"),
            FlowCreditReserve::Closed => panic!("gate should be open"),
        };
        assert_eq!(first.key(), 7);
        assert_eq!(gate.queued_packets(), 1);
        assert!(!gate.is_idle());
        assert!(matches!(gate.try_reserve(7u8, 1), FlowCreditReserve::Full));

        let second = match gate.try_reserve(8u8, 1) {
            FlowCreditReserve::Reserved(reservation) => reservation,
            FlowCreditReserve::Full => panic!("different flow should reserve"),
            FlowCreditReserve::Closed => panic!("gate should be open"),
        };
        assert!(matches!(gate.try_reserve(9u8, 1), FlowCreditReserve::Full));

        gate.release(first);
        assert_eq!(gate.queued_packets(), 1);
        gate.release(second);
        assert!(gate.is_idle());
    }

    #[test]
    fn flow_credit_gate_weight_expands_one_flow_without_exceeding_total_cap() {
        let gate = FlowCreditGate::new(3, 1, 1, 2);

        let first = match gate.try_reserve(7u8, 2) {
            FlowCreditReserve::Reserved(reservation) => reservation,
            FlowCreditReserve::Full => panic!("first weighted packet should reserve"),
            FlowCreditReserve::Closed => panic!("gate should be open"),
        };
        let second = match gate.try_reserve(7u8, 2) {
            FlowCreditReserve::Reserved(reservation) => reservation,
            FlowCreditReserve::Full => panic!("weight should allow a second same-flow packet"),
            FlowCreditReserve::Closed => panic!("gate should be open"),
        };
        assert!(matches!(gate.try_reserve(7u8, 2), FlowCreditReserve::Full));

        let third = match gate.try_reserve(8u8, 1) {
            FlowCreditReserve::Reserved(reservation) => reservation,
            FlowCreditReserve::Full => panic!("total cap should still leave one slot"),
            FlowCreditReserve::Closed => panic!("gate should be open"),
        };
        assert!(matches!(gate.try_reserve(9u8, 1), FlowCreditReserve::Full));

        gate.release_many(&[first, second, third]);
        assert!(gate.is_idle());
    }

    #[test]
    fn flow_credit_gate_close_rejects_new_reservations() {
        let gate = FlowCreditGate::new(1, 1, 1, 1);
        gate.close();

        assert!(matches!(
            gate.try_reserve(7u8, 1),
            FlowCreditReserve::Closed
        ));
        assert_eq!(gate.reserve_blocking(7u8, 1), Err(FlowCreditClosed));
    }

    #[test]
    fn priority_bulk_lane_sender_keeps_priority_independent_of_bulk_pressure() {
        let (sender, receivers) = priority_bulk_lane_channels(1, 1);
        let (mut priority_rx, mut bulk_rx, credits) = receivers.into_parts();

        assert!(matches!(
            sender.try_send("bulk", PacketLane::Bulk, 1, 100),
            PriorityBulkLaneSendResult::Sent {
                previous_bulk_queued: Some(0)
            }
        ));
        assert_eq!(credits.queued_packets(), 1);

        assert!(matches!(
            sender.try_send("priority", PacketLane::Priority, 1, 10),
            PriorityBulkLaneSendResult::Sent {
                previous_bulk_queued: None
            }
        ));

        assert_eq!(priority_rx.try_recv().expect("priority"), "priority");
        assert_eq!(bulk_rx.try_recv().expect("bulk"), "bulk");
        credits.release_count(1);
        assert_eq!(credits.queued_packets(), 0);
    }

    #[test]
    fn priority_bulk_lane_sender_reports_bulk_credit_pressure() {
        let (sender, receivers) = priority_bulk_lane_channels(1, 1);
        let (_priority_rx, mut bulk_rx, credits) = receivers.into_parts();

        assert!(matches!(
            sender.try_send("bulk-1", PacketLane::Bulk, 1, 100),
            PriorityBulkLaneSendResult::Sent { .. }
        ));

        let PriorityBulkLaneSendResult::Dropped(drop) =
            sender.try_send("bulk-2", PacketLane::Bulk, 1, 200)
        else {
            panic!("second bulk packet should hit credit pressure");
        };

        assert_eq!(drop.item, "bulk-2");
        assert_eq!(drop.reason, PriorityBulkLaneDropReason::CreditPressure);
        assert_eq!(drop.drop.reason, AdmissionDropReason::BulkPressure);
        assert_eq!(drop.drop.lane, PacketLane::Bulk);
        assert_eq!(drop.drop.packet_count, 1);
        assert_eq!(drop.drop.byte_count, 200);
        assert_eq!(credits.queued_packets(), 1);
        assert_eq!(bulk_rx.try_recv().expect("first bulk"), "bulk-1");
        credits.release_count(1);
        assert_eq!(credits.queued_packets(), 0);
    }

    #[test]
    fn priority_bulk_lane_sender_allows_zero_packet_bulk_event_without_credit() {
        let (sender, receivers) = priority_bulk_lane_channels(1, 1);
        let (_priority_rx, mut bulk_rx, credits) = receivers.into_parts();

        assert!(matches!(
            sender.try_send("empty-bulk", PacketLane::Bulk, 0, 0),
            PriorityBulkLaneSendResult::Sent {
                previous_bulk_queued: Some(0)
            }
        ));

        assert_eq!(credits.queued_packets(), 0);
        assert_eq!(bulk_rx.try_recv().expect("empty bulk event"), "empty-bulk");
    }

    #[test]
    fn priority_bulk_lane_sender_reports_priority_channel_full() {
        let (sender, receivers) = priority_bulk_lane_channels(1, 1);
        let (mut priority_rx, _bulk_rx, credits) = receivers.into_parts();

        assert!(matches!(
            sender.try_send("priority-1", PacketLane::Priority, 1, 10),
            PriorityBulkLaneSendResult::Sent {
                previous_bulk_queued: None
            }
        ));

        let PriorityBulkLaneSendResult::Dropped(drop) =
            sender.try_send("priority-2", PacketLane::Priority, 1, 20)
        else {
            panic!("second priority item should hit channel capacity");
        };

        assert_eq!(drop.item, "priority-2");
        assert_eq!(drop.reason, PriorityBulkLaneDropReason::ChannelFull);
        assert_eq!(drop.drop.reason, AdmissionDropReason::PriorityPressure);
        assert_eq!(drop.drop.lane, PacketLane::Priority);
        assert_eq!(drop.drop.packet_count, 1);
        assert_eq!(drop.drop.byte_count, 20);
        assert_eq!(credits.queued_packets(), 0);
        assert_eq!(
            priority_rx.try_recv().expect("first priority"),
            "priority-1"
        );
    }

    #[test]
    fn priority_bulk_lane_sender_releases_bulk_credit_when_receiver_closed() {
        let (sender, receivers) = priority_bulk_lane_channels(1, 2);
        let (_priority_rx, bulk_rx, credits) = receivers.into_parts();
        drop(bulk_rx);

        let PriorityBulkLaneSendResult::Dropped(drop) =
            sender.try_send("bulk", PacketLane::Bulk, 1, 100)
        else {
            panic!("closed bulk receiver should reject the packet");
        };

        assert_eq!(drop.item, "bulk");
        assert_eq!(drop.reason, PriorityBulkLaneDropReason::ReceiverClosed);
        assert_eq!(drop.drop.reason, AdmissionDropReason::ReceiverClosed);
        assert_eq!(
            credits.queued_packets(),
            0,
            "bulk credit reservation for the failed send should be released"
        );
    }

    #[test]
    fn bulk_lane_prefix_sender_admits_prefix_and_returns_overflow() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let credits = LaneCreditGate::new(PacketLane::Bulk, 3);
        let sender = BulkLanePrefixSender::new(tx, credits.clone());

        let BulkLanePrefixSendResult::Sent {
            reserved_packets,
            overflow,
        } = sender.try_send_prefix(TestBulk(vec![1, 2, 3, 4]))
        else {
            panic!("partial capacity should admit a prefix");
        };

        assert_eq!(reserved_packets, 3);
        assert_eq!(overflow, Some(TestBulk(vec![4])));
        assert_eq!(sender.queued_packets(), 3);
        assert_eq!(
            rx.try_recv().expect("admitted prefix"),
            TestBulk(vec![1, 2, 3])
        );

        credits.release_count(reserved_packets);
        assert_eq!(sender.queued_packets(), 0);
    }

    #[test]
    fn bulk_lane_prefix_sender_returns_overflow_as_caller_work() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let credits = LaneCreditGate::new(PacketLane::Bulk, 2);
        let sender = BulkLanePrefixSender::new(tx, credits.clone());

        let outcome = sender.try_send_prefix_returning(TestBulk(vec![1, 2, 3, 4]), |item| item.0);

        assert_eq!(outcome.reserved_packets, 2);
        assert_eq!(outcome.returned, vec![3, 4]);
        assert_eq!(outcome.rejected, None);
        assert_eq!(sender.queued_packets(), 2);
        assert_eq!(
            rx.try_recv().expect("admitted prefix"),
            TestBulk(vec![1, 2])
        );

        credits.release_count(outcome.reserved_packets);
        assert_eq!(sender.queued_packets(), 0);
    }

    #[test]
    fn bulk_lane_prefix_sender_returns_rejected_prefix_and_overflow_as_caller_work() {
        let (tx, rx) = crossbeam_channel::bounded(0);
        let credits = LaneCreditGate::new(PacketLane::Bulk, 2);
        let sender = BulkLanePrefixSender::new(tx, credits);

        let outcome = sender.try_send_prefix_returning(TestBulk(vec![1, 2, 3]), |item| item.0);

        assert_eq!(outcome.reserved_packets, 0);
        assert_eq!(outcome.returned, vec![1, 2, 3]);
        assert_eq!(
            outcome.rejected,
            Some(BulkLanePrefixRejectReason::ChannelFull)
        );
        assert_eq!(
            sender.queued_packets(),
            0,
            "failed channel handoff must release its prefix reservation"
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn bulk_lane_prefix_sender_reports_credit_pressure_without_sending() {
        let (tx, rx) = crossbeam_channel::bounded(2);
        let credits = LaneCreditGate::new(PacketLane::Bulk, 1);
        let sender = BulkLanePrefixSender::new(tx, credits.clone());

        assert!(matches!(
            sender.try_send_prefix(TestBulk(vec![1])),
            BulkLanePrefixSendResult::Sent { .. }
        ));

        let BulkLanePrefixSendResult::Rejected(reject) = sender.try_send_prefix(TestBulk(vec![2]))
        else {
            panic!("full credits should reject without touching the channel");
        };

        assert_eq!(reject.reason, BulkLanePrefixRejectReason::CreditPressure);
        assert_eq!(reject.item, TestBulk(vec![2]));
        assert_eq!(reject.overflow, None);
        assert_eq!(sender.queued_packets(), 1);
        assert_eq!(rx.len(), 1);

        drop(rx);
        credits.release_count(1);
    }

    #[test]
    fn bulk_lane_prefix_sender_releases_credit_when_channel_full() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let credits = LaneCreditGate::new(PacketLane::Bulk, 2);
        let sender = BulkLanePrefixSender::new(tx, credits.clone());

        assert!(matches!(
            sender.try_send_prefix(TestBulk(vec![1])),
            BulkLanePrefixSendResult::Sent { .. }
        ));
        assert_eq!(sender.queued_packets(), 1);

        let BulkLanePrefixSendResult::Rejected(reject) = sender.try_send_prefix(TestBulk(vec![2]))
        else {
            panic!("full channel should reject after releasing its reservation");
        };

        assert_eq!(reject.reason, BulkLanePrefixRejectReason::ChannelFull);
        assert_eq!(reject.item, TestBulk(vec![2]));
        assert_eq!(reject.overflow, None);
        assert_eq!(sender.queued_packets(), 1);

        assert_eq!(rx.try_recv().expect("existing item"), TestBulk(vec![1]));
        credits.release_count(1);
        assert_eq!(sender.queued_packets(), 0);
    }

    #[test]
    fn bulk_lane_prefix_sender_releases_credit_when_receiver_closed() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let credits = LaneCreditGate::new(PacketLane::Bulk, 2);
        let sender = BulkLanePrefixSender::new(tx, credits);
        drop(rx);

        let BulkLanePrefixSendResult::Rejected(reject) =
            sender.try_send_prefix(TestBulk(vec![1, 2]))
        else {
            panic!("closed receiver should reject");
        };

        assert_eq!(reject.reason, BulkLanePrefixRejectReason::ReceiverClosed);
        assert_eq!(reject.item, TestBulk(vec![1, 2]));
        assert_eq!(reject.overflow, None);
        assert_eq!(sender.queued_packets(), 0);
    }

    #[test]
    fn worker_reserved_queue_item_prefers_control_before_priority() {
        let (control_tx, control_rx) = crossbeam_channel::bounded(1);
        let (priority_tx, priority_rx) = crossbeam_channel::bounded(1);
        control_tx.send("control").unwrap();
        priority_tx.send("priority").unwrap();

        assert_eq!(
            try_recv_reserved_worker_queue_item(&control_rx, &priority_rx),
            Some(WorkerReservedQueueItem::Control("control"))
        );
        assert_eq!(
            try_recv_reserved_worker_queue_item(&control_rx, &priority_rx),
            Some(WorkerReservedQueueItem::Priority("priority"))
        );
        assert_eq!(
            try_recv_reserved_worker_queue_item(&control_rx, &priority_rx),
            None
        );
    }

    #[test]
    fn worker_queue_blocking_receive_prefers_reserved_then_completion_then_bulk() {
        let (control_tx, control_rx) = crossbeam_channel::bounded(1);
        let (priority_tx, priority_rx) = crossbeam_channel::bounded(1);
        let (completion_tx, completion_rx) = crossbeam_channel::bounded(1);
        let (bulk_tx, bulk_rx) = crossbeam_channel::bounded(1);
        control_tx.send("control").unwrap();
        priority_tx.send("priority").unwrap();
        completion_tx.send("completion").unwrap();
        bulk_tx.send("bulk").unwrap();

        assert_eq!(
            recv_biased_worker_queue_item(&control_rx, &priority_rx, &completion_rx, &bulk_rx),
            WorkerQueueItem::Control("control")
        );
        assert_eq!(
            recv_biased_worker_queue_item(&control_rx, &priority_rx, &completion_rx, &bulk_rx),
            WorkerQueueItem::Priority("priority")
        );
        assert_eq!(
            recv_biased_worker_queue_item(&control_rx, &priority_rx, &completion_rx, &bulk_rx),
            WorkerQueueItem::Completion("completion")
        );
        assert_eq!(
            recv_biased_worker_queue_item(&control_rx, &priority_rx, &completion_rx, &bulk_rx),
            WorkerQueueItem::Bulk("bulk")
        );
    }

    #[test]
    fn worker_drain_cursor_bounds_completion_slice_before_bulk() {
        let (_control_tx, control_rx) = crossbeam_channel::bounded::<&str>(1);
        let (_priority_tx, priority_rx) = crossbeam_channel::bounded::<&str>(1);
        let (completion_tx, completion_rx) = crossbeam_channel::bounded(3);
        let (bulk_tx, bulk_rx) = crossbeam_channel::bounded(1);
        completion_tx.send(vec![1]).unwrap();
        completion_tx.send(vec![2]).unwrap();
        completion_tx.send(vec![3]).unwrap();
        bulk_tx.send("bulk").unwrap();
        let mut cursor = WorkerDrainCursor::new(1, 2);

        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::Completion(vec![1]))
        );
        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::Completion(vec![2]))
        );
        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::FlushCompletionOutputs)
        );
        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::Bulk("bulk"))
        );
        assert_eq!(completion_rx.len(), 1);
    }

    #[test]
    fn worker_drain_cursor_flushes_completion_outputs_before_reserved_work() {
        let (control_tx, control_rx) = crossbeam_channel::bounded(1);
        let (_priority_tx, priority_rx) = crossbeam_channel::bounded::<&str>(1);
        let (completion_tx, completion_rx) = crossbeam_channel::bounded(1);
        let (_bulk_tx, bulk_rx) = crossbeam_channel::bounded::<&str>(1);
        completion_tx.send(vec![1]).unwrap();
        let mut cursor = WorkerDrainCursor::new(1, 1);

        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::Completion(vec![1]))
        );
        control_tx.send("control").unwrap();
        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::Control {
                item: "control",
                flush_completion_outputs: true,
            })
        );
    }

    #[test]
    fn worker_drain_cursor_charges_bulk_by_handled_work() {
        let (_control_tx, control_rx) = crossbeam_channel::bounded::<&str>(1);
        let (_priority_tx, priority_rx) = crossbeam_channel::bounded::<&str>(1);
        let (_completion_tx, completion_rx) = crossbeam_channel::bounded::<Vec<usize>>(1);
        let (bulk_tx, bulk_rx) = crossbeam_channel::bounded(3);
        bulk_tx.send("bulk-1").unwrap();
        bulk_tx.send("bulk-2").unwrap();
        bulk_tx.send("bulk-3").unwrap();
        let mut cursor = WorkerDrainCursor::new(3, 0);

        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::Bulk("bulk-1"))
        );
        cursor.charge_bulk_work(2);
        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            Some(WorkerDrainAction::Bulk("bulk-2"))
        );
        cursor.charge_bulk_work(1);
        assert_eq!(
            cursor.next(
                &control_rx,
                &priority_rx,
                &completion_rx,
                &bulk_rx,
                Vec::len,
            ),
            None
        );
        assert_eq!(bulk_rx.len(), 1);
    }

    #[test]
    fn dispatch_batcher_groups_same_key_until_capacity() {
        let mut batcher = DispatchBatcher::new(4);
        let mut dispatched = Vec::new();

        assert!(
            batcher
                .push(1, 3, "a", |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );
        assert!(
            batcher
                .push(1, 3, "b", |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );
        assert!(dispatched.is_empty());

        assert!(
            batcher
                .push(1, 3, "c", |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );

        assert_eq!(dispatched, vec![(1, vec!["a", "b", "c"])]);
        assert!(batcher.is_empty());
    }

    #[test]
    fn dispatch_batcher_flushes_on_key_change_and_preserves_returned_items() {
        let mut batcher = DispatchBatcher::new(4);
        assert!(
            batcher
                .push(1, 8, "a", |_key, _items| Vec::new())
                .is_empty()
        );

        let returned = batcher.push(2, 8, "b", |key, items| {
            assert_eq!(key, 1);
            assert_eq!(items, vec!["a"]);
            vec!["returned"]
        });

        assert_eq!(returned, vec!["returned"]);
        let mut dispatched = Vec::new();
        assert!(
            batcher
                .flush(|key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );
        assert_eq!(dispatched, vec![(2, vec!["b"])]);
    }

    #[test]
    fn dispatch_batcher_single_flush_preserves_pending_buffer() {
        let mut batcher = DispatchBatcher::new(4);
        let pending_buffer = batcher.pending_buffer_ptr();
        let mut singles = Vec::new();
        let mut batches = Vec::new();

        assert!(
            batcher
                .push_with_single(
                    1,
                    8,
                    "a",
                    |key, item| {
                        singles.push((key, item));
                        Vec::new()
                    },
                    |key, items| {
                        batches.push((key, items));
                        Vec::new()
                    }
                )
                .is_empty()
        );
        assert!(singles.is_empty());
        assert!(batches.is_empty());

        assert!(
            batcher
                .flush_with_single(
                    |key, item| {
                        singles.push((key, item));
                        Vec::new()
                    },
                    |key, items| {
                        batches.push((key, items));
                        Vec::new()
                    }
                )
                .is_empty()
        );

        assert_eq!(singles, vec![(1, "a")]);
        assert!(batches.is_empty());
        assert_eq!(batcher.pending_buffer_ptr(), pending_buffer);
    }

    #[test]
    fn dispatch_batcher_directly_flushes_full_batch_when_empty() {
        let mut batcher = DispatchBatcher::new(4);
        let mut dispatched = Vec::new();

        assert!(
            batcher
                .push_batch(7, 2, vec!["a", "b"], |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );

        assert_eq!(dispatched, vec![(7, vec!["a", "b"])]);
        assert!(batcher.is_empty());
    }

    #[test]
    fn dispatch_batcher_adopts_first_partial_batch_vec_without_copy() {
        let mut batcher = DispatchBatcher::new(4);
        let mut items = Vec::with_capacity(3);
        items.push("a");
        items.push("b");
        let items_ptr = items.as_ptr();
        let items_capacity = items.capacity();

        assert!(
            batcher
                .push_batch(7, 4, items, |_key, _items| Vec::new())
                .is_empty()
        );

        assert_eq!(batcher.key, Some(7));
        assert_eq!(batcher.items, vec!["a", "b"]);
        assert_eq!(batcher.items.capacity(), items_capacity);
        assert_eq!(batcher.items.as_ptr(), items_ptr);

        let mut dispatched = Vec::new();
        assert!(
            batcher
                .flush(|key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );
        assert_eq!(dispatched, vec![(7, vec!["a", "b"])]);
    }

    #[tokio::test]
    async fn priority_bulk_drain_prefers_ready_priority_over_selected_bulk() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("priority").await.unwrap();
        bulk_tx.send("bulk-queued").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("bulk-selected"), 4);

        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), Some("priority"));
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("bulk-selected")
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("bulk-queued")
        );
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn priority_bulk_drain_charges_batch_extra_against_budget() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("queued-priority").await.unwrap();
        bulk_tx.send("queued-bulk").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk"), 4);

        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("queued-priority")
        );
        drain.charge_extra(3);
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
        assert_eq!(drain.drained(), 4);
    }

    #[tokio::test]
    async fn priority_bulk_drain_bulk_only_stops_for_priority() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("priority").await.unwrap();
        bulk_tx.send("bulk").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk"), 4);

        assert_eq!(
            drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
            None,
            "bulk coalescing must stop when priority work is ready"
        );
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), Some("priority"));
        assert_eq!(
            drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
            Some("selected-bulk")
        );
        assert_eq!(
            drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
            Some("bulk")
        );
    }

    #[tokio::test]
    async fn priority_bulk_drain_deferred_bulk_yields_to_later_priority() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (_bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);
        let mut drain = PriorityBulkDrainCursor::new(None, None, 4);

        drain.defer_bulk("deferred-bulk");
        priority_tx.send("priority").await.unwrap();

        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("priority"),
            "a non-coalesced bulk command should be put back behind new priority work"
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("deferred-bulk")
        );
    }

    #[tokio::test]
    async fn packet_drain_cursor_owns_first_packet_budget_and_interleave() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        let mut drain = PacketDrainCursor::new(Some("selected"), 3, 2, 0);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("selected"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveDecryptReturn)
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(packet_rx.try_recv().ok(), Some("queued-2"));
        assert_eq!(drain.drained(), 2);
    }

    #[tokio::test]
    async fn packet_drain_cursor_charges_interleaves_against_budget() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        let mut drain = PacketDrainCursor::new(Some("selected"), 4, 2, 0);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("selected"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveDecryptReturn)
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn packet_drain_cursor_refunds_empty_interleave_turns() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        packet_tx.send("queued-3").unwrap();
        let mut drain = PacketDrainCursor::new(None, 3, 1, 0);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveDecryptReturn)
        );
        drain.refund_empty_interleave_turn();
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveDecryptReturn)
        );
        drain.refund_empty_interleave_turn();
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-3"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn packet_drain_cursor_interleaves_side_queues_after_decrypt_return() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        packet_tx.send("queued-3").unwrap();
        let mut drain = PacketDrainCursor::new(None, 5, 2, 2);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveDecryptReturn)
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveSideQueues)
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-3"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn packet_drain_cursor_can_disable_side_queue_interleaves() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        packet_tx.send("queued-3").unwrap();
        let mut drain = PacketDrainCursor::new(None, 3, 0, 0);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-3"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn single_lane_drain_owns_first_item_and_budget() {
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(4);

        tun_tx.send("queued-1").await.unwrap();
        tun_tx.send("queued-2").await.unwrap();
        tun_tx.send("queued-3").await.unwrap();
        let mut drain = SingleLaneDrainCursor::new(Some("selected"), 3);

        assert_eq!(drain.next(&mut tun_rx), Some("selected"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-1"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-2"));
        assert_eq!(drain.next(&mut tun_rx), None);
        assert_eq!(tun_rx.try_recv().ok(), Some("queued-3"));
        assert_eq!(drain.drained(), 3);
    }
}
