use crossbeam_channel::{Sender as CrossbeamSender, TrySendError as CrossbeamTrySendError};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMoverSendLane {
    Priority,
    Bulk,
}

impl PacketMoverSendLane {
    pub(crate) fn for_endpoint_data(bulk_endpoint_data: bool) -> Self {
        if bulk_endpoint_data {
            Self::Bulk
        } else {
            Self::Priority
        }
    }
}

pub(crate) trait PacketMoverSendTarget: Clone {
    type Key: Copy + Eq + std::fmt::Debug;

    fn packet_mover_send_key(&self) -> Self::Key;
}

pub(crate) trait PacketMoverBulkSendItem {
    type Key: Copy + Eq + Hash + std::fmt::Debug;

    fn bulk_send_target_key(&self) -> Self::Key;

    fn is_bulk_send_item(&self) -> bool;
}

#[derive(Default)]
pub(crate) struct PacketMoverOrderedSendBatch<T> {
    state: Mutex<PacketMoverOrderedSendBatchState<T>>,
    ready_cv: Condvar,
}

#[derive(Default)]
struct PacketMoverOrderedSendBatchState<T> {
    completed: Option<T>,
}

impl<T> PacketMoverOrderedSendBatch<T> {
    pub(crate) fn complete(&self, completed: T) {
        let mut state = self
            .state
            .lock()
            .expect("packet mover ordered send batch state poisoned");
        debug_assert!(
            state.completed.is_none(),
            "packet mover ordered send batch completed twice"
        );
        state.completed = Some(completed);
        drop(state);
        self.ready_cv.notify_one();
    }

    pub(crate) fn wait(&self) -> T {
        let mut state = self
            .state
            .lock()
            .expect("packet mover ordered send batch state poisoned");
        loop {
            if let Some(completed) = state.completed.take() {
                return completed;
            }
            state = self
                .ready_cv
                .wait(state)
                .expect("packet mover ordered send batch state poisoned");
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PacketMoverOrderedSendInflight {
    queued: Arc<AtomicUsize>,
}

impl PacketMoverOrderedSendInflight {
    pub(crate) fn queued(&self) -> usize {
        self.queued.load(Relaxed)
    }

    fn reserve_one(&self) {
        self.queued.fetch_add(1, Relaxed);
    }

    pub(crate) fn complete_one(&self) {
        self.release_one("completion");
    }

    fn rollback_one(&self) {
        self.release_one("rollback");
    }

    fn release_one(&self, action: &str) {
        let previous = self.queued.fetch_sub(1, Relaxed);
        debug_assert!(
            previous > 0,
            "packet mover ordered send inflight accounting underflow during {action}"
        );
    }
}

pub(crate) struct PacketMoverOrderedSendFlow<T> {
    sender: CrossbeamSender<T>,
    inflight: PacketMoverOrderedSendInflight,
    last_used_ms: AtomicU64,
}

pub(crate) trait PacketMoverOrderedSendFlowLifecycle {
    fn mark_used(&self, now_ms: u64);

    fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool;

    fn close_for_prune(&self) {}
}

impl<T> PacketMoverOrderedSendFlow<T> {
    pub(crate) fn new(sender: CrossbeamSender<T>, now_ms: u64) -> Self {
        Self {
            sender,
            inflight: PacketMoverOrderedSendInflight::default(),
            last_used_ms: AtomicU64::new(now_ms),
        }
    }

    pub(crate) fn inflight(&self) -> PacketMoverOrderedSendInflight {
        self.inflight.clone()
    }

    pub(crate) fn try_enqueue(&self, item: T) -> Result<(), CrossbeamTrySendError<T>> {
        self.inflight.reserve_one();
        match self.sender.try_send(item) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.inflight.rollback_one();
                Err(err)
            }
        }
    }

    pub(crate) fn enqueue_blocking(&self, item: T) -> bool {
        self.inflight.reserve_one();
        match self.sender.send(item) {
            Ok(()) => true,
            Err(_) => {
                self.inflight.rollback_one();
                false
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn complete_one(&self) {
        self.inflight.complete_one();
    }

    pub(crate) fn mark_used(&self, now_ms: u64) {
        self.last_used_ms.store(now_ms, Relaxed);
    }

    pub(crate) fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        let last_used = self.last_used_ms.load(Relaxed);
        now_ms.saturating_sub(last_used) >= idle_ms && self.inflight.queued() == 0
    }
}

impl<T> PacketMoverOrderedSendFlowLifecycle for PacketMoverOrderedSendFlow<T> {
    fn mark_used(&self, now_ms: u64) {
        PacketMoverOrderedSendFlow::mark_used(self, now_ms);
    }

    fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        PacketMoverOrderedSendFlow::is_idle(self, now_ms, idle_ms)
    }
}

pub(crate) struct PacketMoverOrderedSendFlows<K, F> {
    flows: Mutex<HashMap<K, Arc<F>>>,
    last_prune_ms: AtomicU64,
    prune_interval_ms: u64,
    idle_ms: u64,
}

impl<K, F> PacketMoverOrderedSendFlows<K, F>
where
    K: Copy + Eq + Hash,
    F: PacketMoverOrderedSendFlowLifecycle,
{
    pub(crate) fn new(prune_interval_ms: u64, idle_ms: u64) -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            last_prune_ms: AtomicU64::new(0),
            prune_interval_ms,
            idle_ms,
        }
    }

    pub(crate) fn flow_for_with<Create>(&self, key: K, now_ms: u64, create: Create) -> Arc<F>
    where
        Create: FnOnce(K, u64) -> Arc<F>,
    {
        let mut flows = self
            .flows
            .lock()
            .expect("packet mover ordered send flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = create(key, now_ms);
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    fn prune_idle_locked(&self, flows: &mut HashMap<K, Arc<F>>, now_ms: u64) {
        let last = self.last_prune_ms.load(Relaxed);
        if now_ms.saturating_sub(last) < self.prune_interval_ms {
            return;
        }
        if self
            .last_prune_ms
            .compare_exchange(last, now_ms, Relaxed, Relaxed)
            .is_err()
        {
            return;
        }

        let idle_ms = self.idle_ms;
        flows.retain(|_, flow| {
            if flow.is_idle(now_ms, idle_ms) {
                flow.close_for_prune();
                false
            } else {
                true
            }
        });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.flows
            .lock()
            .expect("packet mover ordered send flow map poisoned")
            .len()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PacketMoverBulkSendTargets<K>
where
    K: Copy + Eq + Hash + std::fmt::Debug,
{
    Single(K),
    Multiple(HashMap<K, usize>),
}

impl<K> PacketMoverBulkSendTargets<K>
where
    K: Copy + Eq + Hash + std::fmt::Debug,
{
    pub(crate) fn contains(&self, target: K) -> bool {
        match self {
            Self::Single(selected) => *selected == target,
            Self::Multiple(selected) => selected.contains_key(&target),
        }
    }

    #[cfg(test)]
    pub(crate) fn get(&self, target: &K) -> Option<&usize> {
        match self {
            Self::Single(_) => None,
            Self::Multiple(selected) => selected.get(target),
        }
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, target: &K) -> bool {
        self.contains(*target)
    }
}

pub(crate) fn select_packet_mover_bulk_send_targets<T>(
    items: &[T],
    min_packets: usize,
) -> Option<PacketMoverBulkSendTargets<T::Key>>
where
    T: PacketMoverBulkSendItem,
{
    if items.len() < min_packets {
        return None;
    }

    let first = items.first()?;
    if !first.is_bulk_send_item() {
        return None;
    }
    let first_target = first.bulk_send_target_key();
    let mut all_same_target = true;
    for item in &items[1..] {
        if !item.is_bulk_send_item() {
            return None;
        }
        if item.bulk_send_target_key() != first_target {
            all_same_target = false;
        }
    }
    if all_same_target {
        return Some(PacketMoverBulkSendTargets::Single(first_target));
    }

    let mut targets = HashMap::new();
    for item in items {
        let count = targets.entry(item.bulk_send_target_key()).or_insert(0usize);
        *count = count.saturating_add(1);
    }

    targets.retain(|_, count| *count >= min_packets);
    (!targets.is_empty()).then_some(PacketMoverBulkSendTargets::Multiple(targets))
}

pub(crate) trait PacketMoverSendPacket {
    fn packet_len(&self) -> usize;
}

impl PacketMoverSendPacket for Vec<u8> {
    fn packet_len(&self) -> usize {
        self.len()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PacketMoverSendGroupSplitReason {
    Target,
    Lane,
    Backpressure,
}

fn record_packet_mover_send_group_split(reason: PacketMoverSendGroupSplitReason) {
    match reason {
        PacketMoverSendGroupSplitReason::Target => {
            crate::perf_profile::record_fmp_send_group_split_target()
        }
        PacketMoverSendGroupSplitReason::Lane => {
            crate::perf_profile::record_fmp_send_group_split_lane()
        }
        PacketMoverSendGroupSplitReason::Backpressure => {
            crate::perf_profile::record_fmp_send_group_split_backpressure()
        }
    }
}

pub(crate) struct PacketMoverSendBatch<Target, Packet>
where
    Target: PacketMoverSendTarget,
    Packet: PacketMoverSendPacket,
{
    pub(crate) send_target: Target,
    pub(crate) target_key: Target::Key,
    pub(crate) lane: PacketMoverSendLane,
    pub(crate) wire_packets: Vec<Packet>,
    pub(crate) drop_on_backpressure: bool,
    #[cfg(target_os = "linux")]
    gso_segment_len: usize,
    #[cfg(target_os = "linux")]
    gso_last_len: usize,
    #[cfg(target_os = "linux")]
    gso_prefix_uniform: bool,
    #[cfg(target_os = "linux")]
    gso_eligible_sizes: bool,
}

impl<Target, Packet> PacketMoverSendBatch<Target, Packet>
where
    Target: PacketMoverSendTarget,
    Packet: PacketMoverSendPacket,
{
    #[cfg(test)]
    pub(crate) fn new(
        send_target: Target,
        target_key: Target::Key,
        wire_packet: Packet,
        drop_on_backpressure: bool,
    ) -> Self {
        Self::new_with_capacity(
            send_target,
            target_key,
            PacketMoverSendLane::Bulk,
            wire_packet,
            drop_on_backpressure,
            1,
        )
    }

    pub(crate) fn new_with_capacity(
        send_target: Target,
        target_key: Target::Key,
        lane: PacketMoverSendLane,
        wire_packet: Packet,
        drop_on_backpressure: bool,
        packet_capacity: usize,
    ) -> Self {
        debug_assert_eq!(
            send_target.packet_mover_send_key(),
            target_key,
            "packet mover send batch must keep the queued target key"
        );
        #[cfg(target_os = "linux")]
        let gso_segment_len = wire_packet.packet_len();
        let mut wire_packets = Vec::with_capacity(packet_capacity.max(1));
        wire_packets.push(wire_packet);
        Self {
            send_target,
            target_key,
            lane,
            wire_packets,
            drop_on_backpressure,
            #[cfg(target_os = "linux")]
            gso_segment_len,
            #[cfg(target_os = "linux")]
            gso_last_len: gso_segment_len,
            #[cfg(target_os = "linux")]
            gso_prefix_uniform: gso_segment_len > 0,
            #[cfg(target_os = "linux")]
            gso_eligible_sizes: false,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn target_key(&self) -> Target::Key {
        self.target_key
    }

    #[cfg(test)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn lane(&self) -> PacketMoverSendLane {
        self.lane
    }

    fn split_reason_for(
        &self,
        target_key: Target::Key,
        lane: PacketMoverSendLane,
        drop_on_backpressure: bool,
    ) -> Option<PacketMoverSendGroupSplitReason> {
        if self.target_key != target_key {
            return Some(PacketMoverSendGroupSplitReason::Target);
        }
        if self.lane != lane {
            return Some(PacketMoverSendGroupSplitReason::Lane);
        }
        if self.drop_on_backpressure != drop_on_backpressure {
            return Some(PacketMoverSendGroupSplitReason::Backpressure);
        }
        None
    }

    pub(crate) fn push(&mut self, wire_packet: Packet, drop_on_backpressure: bool) {
        debug_assert_eq!(
            self.drop_on_backpressure, drop_on_backpressure,
            "send batches keep one backpressure policy so bulk remains droppable"
        );
        #[cfg(target_os = "linux")]
        {
            let packet_len = wire_packet.packet_len();
            self.gso_prefix_uniform &= self.gso_last_len == self.gso_segment_len;
            self.gso_last_len = packet_len;
            self.gso_eligible_sizes = self.gso_prefix_uniform && packet_len <= self.gso_segment_len;
        }
        self.wire_packets.push(wire_packet);
    }

    fn packet_count(&self) -> usize {
        self.wire_packets.len()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn gso_eligible_sizes(&self) -> bool {
        self.gso_eligible_sizes
    }

    #[cfg(test)]
    pub(crate) fn wire_packet_capacity(&self) -> usize {
        self.wire_packets.capacity()
    }

    pub(crate) fn into_parts(self) -> (Target, Vec<Packet>, bool) {
        (
            self.send_target,
            self.wire_packets,
            self.drop_on_backpressure,
        )
    }
}

pub(crate) fn push_packet_mover_send_batch_with_lane_and_capacity<Target, Packet>(
    groups: &mut Vec<PacketMoverSendBatch<Target, Packet>>,
    send_target: Target,
    target_key: Target::Key,
    lane: PacketMoverSendLane,
    wire_packet: Packet,
    drop_on_backpressure: bool,
    packet_capacity: usize,
) where
    Target: PacketMoverSendTarget,
    Packet: PacketMoverSendPacket,
{
    if let Some(group) = groups.last_mut() {
        if let Some(reason) = group.split_reason_for(target_key, lane, drop_on_backpressure) {
            record_packet_mover_send_group_split(reason);
        } else {
            group.push(wire_packet, drop_on_backpressure);
            return;
        }
    }

    groups.push(PacketMoverSendBatch::new_with_capacity(
        send_target,
        target_key,
        lane,
        wire_packet,
        drop_on_backpressure,
        packet_capacity,
    ));
}

pub(crate) fn packet_mover_send_group_stats<Target, Packet>(
    groups: &[PacketMoverSendBatch<Target, Packet>],
) -> (usize, usize, usize)
where
    Target: PacketMoverSendTarget,
    Packet: PacketMoverSendPacket,
{
    let mut packets = 0usize;
    let mut single_groups = 0usize;
    for group in groups {
        let count = group.packet_count();
        packets = packets.saturating_add(count);
        if count == 1 {
            single_groups = single_groups.saturating_add(1);
        }
    }
    (groups.len(), packets, single_groups)
}

pub(crate) fn record_packet_mover_send_groups<Target, Packet>(
    groups: &[PacketMoverSendBatch<Target, Packet>],
) where
    Target: PacketMoverSendTarget,
    Packet: PacketMoverSendPacket,
{
    if !crate::perf_profile::enabled() || groups.is_empty() {
        return;
    }
    let (group_count, packets, single_groups) = packet_mover_send_group_stats(groups);
    crate::perf_profile::record_fmp_send_groups(group_count, packets, single_groups);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::bounded;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct TestOrderedSendFlow {
        last_used_ms: AtomicU64,
        closed: AtomicUsize,
        idle_after_ms: u64,
    }

    impl TestOrderedSendFlow {
        fn new(now_ms: u64, idle_after_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                last_used_ms: AtomicU64::new(now_ms),
                closed: AtomicUsize::new(0),
                idle_after_ms,
            })
        }

        fn last_used_ms(&self) -> u64 {
            self.last_used_ms.load(Relaxed)
        }

        fn closed(&self) -> usize {
            self.closed.load(Relaxed)
        }
    }

    impl PacketMoverOrderedSendFlowLifecycle for TestOrderedSendFlow {
        fn mark_used(&self, now_ms: u64) {
            self.last_used_ms.store(now_ms, Relaxed);
        }

        fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
            now_ms.saturating_sub(self.last_used_ms()) >= idle_ms && now_ms >= self.idle_after_ms
        }

        fn close_for_prune(&self) {
            self.closed.fetch_add(1, Relaxed);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestTarget {
        key: u8,
    }

    impl PacketMoverSendTarget for TestTarget {
        type Key = u8;

        fn packet_mover_send_key(&self) -> Self::Key {
            self.key
        }
    }

    #[derive(Clone, Copy)]
    struct TestBulkItem {
        key: u8,
        bulk: bool,
    }

    impl PacketMoverBulkSendItem for TestBulkItem {
        type Key = u8;

        fn bulk_send_target_key(&self) -> Self::Key {
            self.key
        }

        fn is_bulk_send_item(&self) -> bool {
            self.bulk
        }
    }

    fn push_test_group(
        groups: &mut Vec<PacketMoverSendBatch<TestTarget, Vec<u8>>>,
        key: u8,
        lane: PacketMoverSendLane,
        byte: u8,
        drop_on_backpressure: bool,
    ) {
        push_packet_mover_send_batch_with_lane_and_capacity(
            groups,
            TestTarget { key },
            key,
            lane,
            vec![byte],
            drop_on_backpressure,
            8,
        );
    }

    #[test]
    fn send_groups_merge_only_adjacent_matching_target_lane_and_backpressure() {
        let mut groups = Vec::new();
        push_test_group(&mut groups, 1, PacketMoverSendLane::Bulk, 1, true);
        push_test_group(&mut groups, 1, PacketMoverSendLane::Bulk, 2, true);
        push_test_group(&mut groups, 1, PacketMoverSendLane::Priority, 3, false);
        push_test_group(&mut groups, 1, PacketMoverSendLane::Bulk, 4, true);
        push_test_group(&mut groups, 2, PacketMoverSendLane::Bulk, 5, true);

        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0].wire_packets, vec![vec![1], vec![2]]);
        assert_eq!(groups[1].wire_packets, vec![vec![3]]);
        assert_eq!(groups[2].wire_packets, vec![vec![4]]);
        assert_eq!(groups[3].target_key(), 2);
        assert_eq!(packet_mover_send_group_stats(&groups), (4, 5, 3));
    }

    #[test]
    fn bulk_send_target_selection_accepts_single_bulk_target_without_map() {
        let items = vec![
            TestBulkItem { key: 7, bulk: true },
            TestBulkItem { key: 7, bulk: true },
            TestBulkItem { key: 7, bulk: true },
        ];

        let selected = select_packet_mover_bulk_send_targets(&items, 3)
            .expect("single bulk target should be selected");
        assert!(matches!(selected, PacketMoverBulkSendTargets::Single(7)));
        assert!(selected.contains_key(&7));
    }

    #[test]
    fn bulk_send_target_selection_keeps_only_targets_with_enough_packets() {
        let items = vec![
            TestBulkItem { key: 1, bulk: true },
            TestBulkItem { key: 2, bulk: true },
            TestBulkItem { key: 1, bulk: true },
            TestBulkItem { key: 3, bulk: true },
            TestBulkItem { key: 1, bulk: true },
            TestBulkItem { key: 2, bulk: true },
        ];

        let selected = select_packet_mover_bulk_send_targets(&items, 3)
            .expect("target 1 has enough packets across the batch");
        assert_eq!(selected.get(&1), Some(&3));
        assert!(!selected.contains_key(&2));
        assert!(!selected.contains_key(&3));
    }

    #[test]
    fn bulk_send_target_selection_rejects_priority_or_underfilled_batches() {
        let underfilled = vec![
            TestBulkItem { key: 1, bulk: true },
            TestBulkItem { key: 1, bulk: true },
        ];
        assert!(select_packet_mover_bulk_send_targets(&underfilled, 3).is_none());

        let mixed_lane = vec![
            TestBulkItem { key: 1, bulk: true },
            TestBulkItem {
                key: 1,
                bulk: false,
            },
            TestBulkItem { key: 1, bulk: true },
        ];
        assert!(select_packet_mover_bulk_send_targets(&mixed_lane, 3).is_none());
    }

    #[test]
    fn ordered_send_batch_returns_completed_items() {
        let batch = PacketMoverOrderedSendBatch::default();
        batch.complete(vec![1u8, 2, 3]);

        assert_eq!(batch.wait(), vec![1u8, 2, 3]);
    }

    #[test]
    fn ordered_send_batch_waits_for_worker_completion() {
        let batch = Arc::new(PacketMoverOrderedSendBatch::default());
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiter_batch = Arc::clone(&batch);
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).expect("signal waiter started");
            waiter_batch.wait()
        });

        started_rx.recv().expect("waiter started");
        batch.complete(Vec::<u8>::new());

        assert_eq!(
            waiter.join().expect("waiter thread should complete"),
            Vec::<u8>::new(),
            "empty completions still advance the ordered sender"
        );
    }

    #[test]
    fn ordered_send_flow_tracks_successful_enqueues_and_completion() {
        let (tx, rx) = bounded(1);
        let flow = PacketMoverOrderedSendFlow::new(tx, 10);
        assert!(flow.is_idle(25, 10));

        flow.try_enqueue(1u8).expect("first enqueue should fit");
        assert_eq!(flow.inflight().queued(), 1);
        assert!(
            !flow.is_idle(25, 10),
            "queued batches keep the flow alive while a sender is waiting"
        );

        assert!(flow.try_enqueue(2u8).is_err());
        assert_eq!(
            flow.inflight().queued(),
            1,
            "failed enqueue must roll back reserved in-flight progress"
        );

        assert_eq!(rx.recv().expect("queued item"), 1u8);
        flow.complete_one();
        assert!(flow.is_idle(25, 10));
    }

    #[test]
    fn ordered_send_flow_blocking_enqueue_reports_closed_receiver() {
        let (tx, rx) = bounded(1);
        let flow = PacketMoverOrderedSendFlow::new(tx, 10);
        drop(rx);

        assert!(!flow.enqueue_blocking(1u8));
        assert_eq!(flow.inflight().queued(), 0);
    }

    #[test]
    fn ordered_send_flow_reserves_before_blocking_enqueue_handoff() {
        let (tx, rx) = bounded(0);
        let flow = Arc::new(PacketMoverOrderedSendFlow::new(tx, 10));
        let started = Arc::new(Barrier::new(2));
        let sender_flow = Arc::clone(&flow);
        let sender_started = Arc::clone(&started);
        let handle = std::thread::spawn(move || {
            sender_started.wait();
            assert!(sender_flow.enqueue_blocking(1u8));
        });

        started.wait();
        let deadline = Instant::now() + Duration::from_secs(1);
        while flow.inflight().queued() == 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(
            flow.inflight().queued(),
            1,
            "blocking dispatch must reserve in-flight progress before handoff"
        );

        assert_eq!(rx.recv().expect("handoff item"), 1u8);
        handle.join().expect("blocking sender thread should finish");
        flow.complete_one();
        assert_eq!(flow.inflight().queued(), 0);
    }

    #[test]
    fn ordered_send_flow_mark_used_delays_idle_prune() {
        let (tx, _rx) = bounded::<u8>(1);
        let flow = PacketMoverOrderedSendFlow::new(tx, 10);
        assert!(flow.is_idle(25, 10));

        flow.mark_used(24);
        assert!(!flow.is_idle(25, 10));
    }

    #[test]
    fn ordered_send_flow_registry_reuses_existing_flow_and_marks_used() {
        let flows = PacketMoverOrderedSendFlows::new(10, 100);
        let spawned = AtomicUsize::new(0);

        let first = flows.flow_for_with(7u8, 10, |_, now_ms| {
            spawned.fetch_add(1, Relaxed);
            TestOrderedSendFlow::new(now_ms, u64::MAX)
        });
        let second = flows.flow_for_with(7u8, 15, |_, now_ms| {
            spawned.fetch_add(1, Relaxed);
            TestOrderedSendFlow::new(now_ms, u64::MAX)
        });

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(spawned.load(Relaxed), 1);
        assert_eq!(first.last_used_ms(), 15);
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn ordered_send_flow_registry_prunes_idle_flows_and_closes_them() {
        let flows = PacketMoverOrderedSendFlows::new(10, 5);
        let stale = flows.flow_for_with(1u8, 0, |_, now_ms| TestOrderedSendFlow::new(now_ms, 0));
        assert_eq!(flows.len(), 1);

        let active = flows.flow_for_with(2u8, 11, |_, now_ms| {
            TestOrderedSendFlow::new(now_ms, u64::MAX)
        });

        assert_eq!(stale.closed(), 1);
        assert_eq!(active.closed(), 0);
        assert_eq!(flows.len(), 1);

        let replacement = flows.flow_for_with(1u8, 12, |_, now_ms| {
            TestOrderedSendFlow::new(now_ms, u64::MAX)
        });
        assert!(!Arc::ptr_eq(&stale, &replacement));
        assert_eq!(flows.len(), 2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn send_groups_track_gso_size_eligibility() {
        let target = TestTarget { key: 7 };
        let mut batch = PacketMoverSendBatch::new(target, 7, vec![0u8; 1500], true);
        assert!(!batch.gso_eligible_sizes());

        batch.push(vec![0u8; 1500], true);
        assert!(batch.gso_eligible_sizes());

        batch.push(vec![0u8; 900], true);
        assert!(batch.gso_eligible_sizes());

        batch.push(vec![0u8; 1500], true);
        assert!(!batch.gso_eligible_sizes());
    }
}
