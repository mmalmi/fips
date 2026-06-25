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

pub(crate) use admission::{
    AdmissionClass, AdmissionCredit, AdmissionDecision, AdmissionDrop, AdmissionDropReason,
    AdmissionPrefix, AdmissionPrefixDecision, AdmittedPacket, PacketFacts, PacketLane,
    UdpAdmission, UdpBatchAdmission, UdpBatchAdmissionPlan, UdpIngress, UdpSocketDrain,
    classify_udp_admission, plan_udp_batch_admission,
};
pub(crate) use crypto::{
    CryptoCompletion, CryptoDispatch, CryptoReject, CryptoResult, CryptoTicket, CryptoWork,
    NoopCryptoWorker, OwnerCompletionBatch, OwnerOrderedCompletion, StatelessCryptoWorker,
};
pub(crate) use output::{
    CommitBeforeOutputBatch, CommitBeforeOutputItems, OutputDrop, OutputDropReason, OutputTarget,
    OwnerRetireBatchSink, OwnerRetireBatchTypes, OwnerRetireOutputBatch, PacketOutput,
    PacketOutputTarget, RetireOutput, RetiredPacket, VecOutputSink,
};
pub(crate) use owner::{
    OrderSequence, OrderToken, OwnerCompletionError, OwnerGeneration, OwnerKey, OwnerReceiveTicket,
    OwnerReceiveWindow, OwnerReservation, OwnerReserveError, OwnerSequencer, OwnerWindow,
};
pub(crate) use pipeline::{
    CanonicalOwnerConfig, CanonicalOwnerPacketMover, CanonicalOwnerPacketMoverConfig,
    CanonicalPacketMover, CanonicalPacketMoverConfig, OwnedUdpIngress, PacketMoverDispatch,
    PacketMoverRetireError,
};
pub(crate) use queues::{
    BoundedLaneQueues, DispatchBatcher, LaneCreditGate, LaneCreditReservation, PacketDrainAction,
    PacketDrainCursor, PacketDrainReceiver, PriorityBulkDrainCursor, QueueAdmission, QueueCaps,
    QueuedPacket, SingleLaneDrainCursor,
};
pub(crate) use retire::{OrderedRetireBuffer, OrderedRetireError};

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
}
