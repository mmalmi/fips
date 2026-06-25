use std::collections::HashMap;
use std::sync::{Condvar, Mutex};

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
    type Key: Copy + Eq + std::hash::Hash + std::fmt::Debug;

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

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PacketMoverBulkSendTargets<K>
where
    K: Copy + Eq + std::hash::Hash + std::fmt::Debug,
{
    Single(K),
    Multiple(HashMap<K, usize>),
}

impl<K> PacketMoverBulkSendTargets<K>
where
    K: Copy + Eq + std::hash::Hash + std::fmt::Debug,
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
    use std::sync::Arc;

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
