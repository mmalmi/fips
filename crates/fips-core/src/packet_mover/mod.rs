//! Canonical dataplane packet mover.
//!
//! Target pipeline:
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
//! This module is the new internal implementation boundary for the packet
//! mover rewrite. Keep public FIPS APIs stable for nvpn; port behavior into
//! this crate-private module in coherent chunks, then delete the old receive,
//! helper, and return-path machinery that it replaces.
//!
//! Old code to absorb behind this boundary:
//! - `transport::udp::{mod, peer_drain}` as socket-drain sources only.
//! - `transport::packet_channel` as bounded priority/bulk admission.
//! - `node::handlers::rx_loop` as owner-selection and output orchestration.
//! - `node::decrypt_worker::{queue, pool, runtime}` as stateless worker
//!   scheduling.
//! - `node::decrypt_worker::shard` as owner state, order reservation, replay,
//!   generation, ordered retire, and output decisions.
//! - `node::{send_impl, encrypt_worker, endpoint_event}` as output and send
//!   batching.
//!
//! Old paths to delete or keep deleted:
//! - Connected-UDP direct-decrypt bypass and env-selected packet movers.
//! - Any helper path that decrypts or retires packets outside the owner.
//! - Queue-full side-path retries; pressure must reserve, explicitly drop, or
//!   return an ordered dropped completion to the owner.
//! - Temporary migration scaffolding once behavior is routed through this
//!   module.

// Temporary while the new packet mover is being wired into the existing
// receive path. Remove this as each interface becomes production-owned.
#![allow(dead_code, unused_imports)]

mod admission;
mod crypto;
mod output;
mod owner;
mod pipeline;
mod queues;
mod retire;
mod send;

pub(crate) use admission::{
    AdmissionClass, AdmissionCredit, AdmissionDecision, AdmissionDrop, AdmissionDropReason,
    AdmissionPrefix, AdmissionPrefixDecision, AdmittedPacket, PacketFacts, PacketLane,
    UdpAdmission, UdpBatchAdmission, UdpBatchAdmissionPlan, UdpIngress, UdpSocketDrain,
    classify_udp_admission, plan_udp_batch_admission,
};
pub(crate) use crypto::{
    CryptoCompletion, CryptoDispatch, CryptoReject, CryptoResult, CryptoTicket, CryptoWork,
    NoopCryptoWorker, OwnerCompletionBatch, OwnerCompletionBatchFlush,
    OwnerCompletionBatchIntoIter, OwnerCompletionBatcher, OwnerCompletionRetireReport,
    OwnerOrderedCompletion, StatelessCryptoWorker, retire_owner_ordered_completion_batch,
};
pub(crate) use output::{
    CommitBeforeOutputBatch, CommitBeforeOutputItems, OutputDrop, OutputDropReason, OutputTarget,
    OwnerRetireBatchSink, OwnerRetireBatchTypes, OwnerRetireOutput, OwnerRetireOutputBatch,
    PacketOutput, PacketOutputTarget, RetireOutput, RetiredPacket, VecOutputSink,
};
pub(crate) use owner::{
    OrderSequence, OrderToken, OwnerCompletionError, OwnerGeneration, OwnerKey,
    OwnerReceiveReservationSource, OwnerReceiveSequencer, OwnerReceiveTicket, OwnerReceiveWindow,
    OwnerReservation, OwnerReservationBatch, OwnerReserveError, OwnerSequencer, OwnerWindow,
};
pub(crate) use pipeline::{
    CanonicalOwnerConfig, CanonicalOwnerPacketMover, CanonicalOwnerPacketMoverConfig,
    CanonicalPacketMover, CanonicalPacketMoverConfig, OwnedUdpIngress, PacketMoverDispatch,
    PacketMoverRetireError,
};
pub(crate) use queues::{
    BoundedLaneQueues, BulkLanePrefixReject, BulkLanePrefixRejectReason, BulkLanePrefixSendResult,
    BulkLanePrefixSender, DispatchBatcher, LaneCreditGate, LaneCreditReservation,
    PacketDrainAction, PacketDrainCursor, PacketDrainReceiver, PriorityBulkDrainCursor,
    PriorityBulkLaneDropReason, PriorityBulkLaneSendResult, PriorityBulkLaneSender, QueueAdmission,
    QueueCaps, QueuedPacket, SingleLaneDrainCursor, SplitBulkLaneItem, WorkerDrainAction,
    WorkerDrainCursor, WorkerQueueItem, WorkerReservedQueueItem, priority_bulk_lane_channels,
    recv_biased_worker_queue_item, try_recv_reserved_worker_queue_item,
};
pub(crate) use retire::{OrderedRetireBuffer, OrderedRetireError};
pub(crate) use send::{
    PacketMoverBulkSendItem, PacketMoverBulkSendTargets, PacketMoverOrderedSendBatch,
    PacketMoverOrderedSendFlow, PacketMoverOrderedSendInflight, PacketMoverSendBatch,
    PacketMoverSendLane, PacketMoverSendPacket, PacketMoverSendTarget,
    packet_mover_send_group_stats, push_packet_mover_send_batch_with_lane_and_capacity,
    record_packet_mover_send_groups, select_packet_mover_bulk_send_targets,
};

pub(crate) const CANONICAL_PACKET_MOVER_STAGES: &[PacketMoverStage] = &[
    PacketMoverStage::SocketDrain,
    PacketMoverStage::Admission,
    PacketMoverStage::OwnerSequence,
    PacketMoverStage::CryptoWorker,
    PacketMoverStage::OrderedRetire,
    PacketMoverStage::Output,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMoverStage {
    SocketDrain,
    Admission,
    OwnerSequence,
    CryptoWorker,
    OrderedRetire,
    Output,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMoverMap {
    pub(crate) stages: &'static [PacketMoverStage],
    pub(crate) absorbs: &'static [&'static str],
    pub(crate) deletes: &'static [&'static str],
}

pub(crate) fn canonical_packet_mover_map() -> PacketMoverMap {
    PacketMoverMap {
        stages: CANONICAL_PACKET_MOVER_STAGES,
        absorbs: &[
            "transport::udp::{mod,peer_drain}",
            "transport::packet_channel",
            "node::handlers::rx_loop",
            "node::decrypt_worker::{queue,pool,runtime}",
            "node::decrypt_worker::shard",
            "node::{send_impl,encrypt_worker,endpoint_event}",
        ],
        deletes: &[
            "connected UDP direct-decrypt bypass",
            "env-selected packet mover/opener mode",
            "owner-bypassing decrypt helper paths",
            "queue-full side-path retries",
            "temporary migration scaffolding",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::bounded;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    #[test]
    fn canonical_packet_mover_map_is_one_straight_pipeline() {
        assert_eq!(
            canonical_packet_mover_map().stages,
            &[
                PacketMoverStage::SocketDrain,
                PacketMoverStage::Admission,
                PacketMoverStage::OwnerSequence,
                PacketMoverStage::CryptoWorker,
                PacketMoverStage::OrderedRetire,
                PacketMoverStage::Output,
            ]
        );
    }

    #[test]
    fn boundary_names_old_paths_to_absorb_or_delete() {
        let map = canonical_packet_mover_map();
        assert!(
            map.absorbs
                .iter()
                .any(|path| path.contains("packet_channel"))
        );
        assert!(
            map.absorbs
                .iter()
                .any(|path| path.contains("decrypt_worker"))
        );
        assert!(
            map.deletes
                .iter()
                .any(|path| path.contains("connected UDP direct-decrypt"))
        );
        assert!(
            map.deletes
                .iter()
                .any(|path| path.contains("queue-full side-path"))
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
}
