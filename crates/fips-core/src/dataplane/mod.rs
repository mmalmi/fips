//! Straight dataplane packet processing.
//!
//! This module owns the canonical FIPS dataplane. The path is:
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
//! bytes into fixed result slots; owners retire ready slots in order.
//!
//! Worker/shard direction: owner loops, not crypto workers, own replay,
//! counters, session generation, liveness, path state, and ordered output.
//! Stateless workers may only execute prepared crypto/send batches and wake the
//! owner path for ordered retirement. Priority/control/rekey/liveness work must
//! keep reserved progress outside bulk pressure.

#[cfg(test)]
use crate::node::endpoint_data_batch_channel;
use crate::node::{
    EndpointDataBatchRx, EndpointDataPayload, EndpointDirectSink, EndpointEventSender,
    FipsEndpointDirectPacketBatch, FipsEndpointDirectPacketRun, FipsEndpointDirectPacketRunMeta,
    NodeEndpointDataBatch,
};
use crate::transport::{
    PacketBuffer, PacketFastIngressSink, PacketRx, PacketTx, ReceivedPacket, TransportAddr,
    TransportError, TransportHandle, TransportId,
};
use crate::upper::tun::TunOutboundRx;
use crate::{NodeAddr, PeerIdentity};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

const FMP_VERSION: u8 = crate::node::wire::FMP_VERSION;
const FMP_PHASE_ESTABLISHED: u8 = crate::node::wire::PHASE_ESTABLISHED;
const FMP_PHASE_MSG1: u8 = crate::node::wire::PHASE_MSG1;
const FMP_PHASE_MSG2: u8 = crate::node::wire::PHASE_MSG2;
const FMP_COMMON_PREFIX_SIZE: usize = crate::node::wire::COMMON_PREFIX_SIZE;
const FMP_ESTABLISHED_HEADER_SIZE: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
const FSP_VERSION: u8 = crate::node::session_wire::FSP_VERSION;
const FSP_PHASE_ESTABLISHED: u8 = crate::node::session_wire::FSP_PHASE_ESTABLISHED;
const FSP_HEADER_SIZE: usize = crate::node::session_wire::FSP_HEADER_SIZE;
const FSP_INNER_HEADER_SIZE: usize = crate::node::session_wire::FSP_INNER_HEADER_SIZE;
const FSP_FLAG_U: u8 = crate::node::session_wire::FSP_FLAG_U;
const AEAD_TAG_SIZE: usize = crate::noise::TAG_SIZE;

include!("types.rs");
include!("session_wrap.rs");
include!("wire.rs");
include!("admission.rs");
include!("owner.rs");
include!("owner_state.rs");
include!("owner_io.rs");
include!("owner_retire.rs");
include!("owner_replay.rs");
include!("owner_shard.rs");
include!("work.rs");
include!("direct_transport.rs");
include!("live_ingress.rs");
include!("live_routes.rs");
include!("tun_outbound.rs");
include!("endpoint_data.rs");
include!("session_handoff.rs");
include!("live_output.rs");
include!("live_transport.rs");
include!("turn.rs");
include!("turn_extract.rs");
include!("runtime.rs");
include!("runtime_io.rs");
include!("live_node.rs");
include!("crypto.rs");
include!("engine.rs");
include!("engine_support.rs");

#[cfg(test)]
mod tests;
