//! End-to-end session message handlers.
//!
//! Handles locally-delivered session payloads from SessionDatagram envelopes.
//! Dispatches based on FSP common prefix phase to specific handlers for
//! SessionSetup (Noise XK msg1), SessionAck (msg2), SessionMsg3 (msg3),
//! encrypted data, and error signals (CoordsRequired, PathBroken).

use crate::discovery::nostr::{TraversalAnswer, TraversalOffer};
use crate::mmp::report::ReceiverReport;
use crate::mmp::{MAX_SESSION_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS, MmpMode};
use crate::node::decrypt_worker::{
    DecryptAuthenticatedSession, DecryptDirectSessionCommit, DecryptDirectSessionData,
    DecryptDirectSessionDelivery, DecryptFspFailureReport,
};
use crate::node::session::{EndToEndState, EpochSlot, FspOpenError, SessionEntry};
use crate::node::session_wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_FLAG_CP, FSP_FLAG_K, FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE,
    FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3, FSP_PORT_HEADER_SIZE,
    FSP_PORT_IPV6_SHIM, FspCommonPrefix, FspEncryptedHeader, build_fsp_header,
    fsp_prepend_inner_header, fsp_strip_inner_header, parse_encrypted_coords,
};
#[cfg(unix)]
use crate::node::wire::ESTABLISHED_HEADER_SIZE;
use crate::node::wire::{FLAG_CE, FLAG_SP};
use crate::node::{
    EncryptedSessionPayload, EndpointCommandLane, EndpointDataDelivery, EndpointDataPayload,
    EndpointDataSend, EndpointSendBatchCommand, EndpointSendCommand, FspSendBookkeepingInput,
    LocalSessionPayload, Node, NodeEndpointCommand, NodeEndpointPeer, NodeEndpointRelayStatus,
    NodeError, SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD, SESSION_DIRECT_DEGRADED_MIN_SAMPLE,
    SESSION_DIRECT_RECOVERY_LOSS_THRESHOLD,
};
use crate::noise::{
    HandshakeState, NoiseSession, XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE,
    XK_HANDSHAKE_MSG3_SIZE,
};
use crate::protocol::{
    CoordsRequired, FspInnerFlags, MtuExceeded, PathBroken, PathMtuNotification, SessionAck,
    SessionDatagram, SessionMessageType, SessionMsg3, SessionReceiverReport, SessionSenderReport,
    SessionSetup,
};
#[cfg(unix)]
use crate::protocol::{LinkMessageType, SESSION_DATAGRAM_HEADER_SIZE};
use crate::protocol::{coords_wire_size, encode_coords};
#[cfg(unix)]
use crate::transport::TransportHandle;
use crate::upper::icmp::FIPS_OVERHEAD;
use crate::{NodeAddr, PeerIdentity};
use secp256k1::PublicKey;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Output of the single-borrow steady-state block in
/// [`Node::handle_encrypted_session_msg`]. Carries the small amount of
/// state the post-borrow path needs (the decrypted plaintext +
/// inner-header fields), or which slow path (UnknownSession,
/// NotEstablished, BadInnerHeader, DecryptFailed) to take after the
/// `&mut entry` borrow on `self.sessions` drops. Lets the steady-state
/// AEAD + MMP + path-MTU work all run under one `get_mut(src_addr)`
/// instead of seven `self.sessions` operations per packet.
#[derive(Debug)]
enum FspFrameOutcome {
    /// FSP frame decrypted successfully; ready to dispatch by msg_type.
    /// `plaintext` is the full inner-decoded payload — the per-msg_type
    /// payload starts at offset `FSP_INNER_HEADER_SIZE`.
    Authentic(AuthenticatedSessionMessage),
    /// `self.sessions` had no entry for the source address.
    UnknownSession,
    /// Session entry exists but the XK handshake hasn't completed yet.
    NotEstablished,
    /// Decrypted payload was shorter than `FSP_INNER_HEADER_SIZE`.
    BadInnerHeader,
    /// Established session does not yet have an authenticated remote identity.
    MissingRemoteIdentity,
    /// All live epoch AEAD attempts failed.
    /// `consecutive` tracks the post-failure counter; if it crossed the
    /// threshold, `recover_session` is true so the post-borrow path can
    /// start an in-place recovery rekey against the same peer. The old
    /// session stays usable while the new XK handshake completes.
    DecryptFailed {
        error: crate::noise::NoiseError,
        counter: u64,
        consecutive: u32,
        recover_session: bool,
    },
    /// A packet from the previous key epoch arrived during the drain window,
    /// but it could not be authenticated by the retained previous session
    /// either. This is normally replayed or very stale post-cutover traffic,
    /// not evidence that the current session diverged.
    StaleEpochDrainFailure { counter: u64 },
}

fn record_endpoint_command_wait(
    queued_at: Option<crate::perf_profile::TraceStamp>,
    lane: EndpointCommandLane,
    count: u64,
) {
    let (priority_count, bulk_count) = match lane {
        EndpointCommandLane::Priority => (count, 0),
        EndpointCommandLane::Bulk => (0, count),
    };
    crate::perf_profile::record_since_split_count(
        crate::perf_profile::Stage::EndpointCommandWait,
        crate::perf_profile::Stage::EndpointPriorityCommandWait,
        crate::perf_profile::Stage::EndpointBulkCommandWait,
        queued_at,
        count,
        priority_count,
        bulk_count,
    );
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct ProcessedSessionReceiverReport {
    sample: Option<(u64, f64)>,
    used_direct_next_hop: bool,
    srtt_ms: Option<f64>,
    route_quality_sample: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionReceiverReportSkip {
    UnknownSession,
    MmpDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionPathMtuChange {
    old_mtu: u16,
    new_mtu: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionPathMtuApplyResult {
    Changed(SessionPathMtuChange),
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionPathMtuApplySkip {
    UnknownSession,
    MmpDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFspSendContextError {
    NoSession,
    NotEstablished,
}

impl SessionFspSendContextError {
    fn into_node_error(self, node_addr: NodeAddr) -> NodeError {
        let reason = match self {
            Self::NoSession => "no session",
            Self::NotEstablished => "session not established",
        };
        NodeError::SendFailed {
            node_addr,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionFspSendContext {
    timestamp: u32,
    spin_bit: bool,
    current_k_bit: bool,
    coords_warmup_remaining: u8,
}

impl SessionFspSendContext {
    fn wants_coords(&self) -> bool {
        self.coords_warmup_remaining > 0
    }

    fn inner_flags_byte(&self) -> u8 {
        FspInnerFlags {
            spin_bit: self.spin_bit,
        }
        .to_byte()
    }

    fn fsp_flags(&self, include_coords: bool) -> u8 {
        let mut flags = if include_coords { FSP_FLAG_CP } else { 0 };
        if self.current_k_bit {
            flags |= FSP_FLAG_K;
        }
        flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundSessionState {
    Established,
    Pending,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunOutboundSessionDecision {
    Established,
    EstablishedPathMtuExceeded { path_ipv6_mtu: u32 },
    Pending,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryRetrySessionDecision {
    Established,
    RestartedPending,
    Missing,
}

/// Authenticated established-FSP message ready for local dispatch.
///
/// This is the post-open unit the rx loop dispatches today, and the future
/// peer/session runtime should be able to own directly: source identity,
/// inner-header metadata, and payload move together instead of returning to
/// loose msg_type/plaintext/source arguments.
#[derive(Debug)]
pub(in crate::node) struct AuthenticatedSessionMessage {
    source_peer: PeerIdentity,
    buffer: Vec<u8>,
    plaintext_offset: usize,
    plaintext_len: usize,
    msg_type: u8,
    #[allow(dead_code)]
    inner_flags_byte: u8,
    #[allow(dead_code)]
    timestamp: u32,
}

impl AuthenticatedSessionMessage {
    pub(in crate::node) fn new(
        source_peer: PeerIdentity,
        plaintext: Vec<u8>,
        msg_type: u8,
        inner_flags_byte: u8,
        timestamp: u32,
    ) -> Self {
        debug_assert!(plaintext.len() >= FSP_INNER_HEADER_SIZE);
        let plaintext_len = plaintext.len();
        Self {
            source_peer,
            buffer: plaintext,
            plaintext_offset: 0,
            plaintext_len,
            msg_type,
            inner_flags_byte,
            timestamp,
        }
    }

    pub(in crate::node) fn from_buffer(
        source_peer: PeerIdentity,
        buffer: Vec<u8>,
        plaintext_offset: usize,
        plaintext_len: usize,
        msg_type: u8,
        inner_flags_byte: u8,
        timestamp: u32,
    ) -> Self {
        debug_assert!(plaintext_len >= FSP_INNER_HEADER_SIZE);
        debug_assert!(
            plaintext_offset
                .checked_add(plaintext_len)
                .is_some_and(|end| end <= buffer.len())
        );
        Self {
            source_peer,
            buffer,
            plaintext_offset,
            plaintext_len,
            msg_type,
            inner_flags_byte,
            timestamp,
        }
    }

    #[cfg(test)]
    fn source_peer(&self) -> PeerIdentity {
        self.source_peer
    }

    #[cfg(test)]
    fn plaintext(&self) -> &[u8] {
        debug_assert!(self.plaintext_len >= FSP_INNER_HEADER_SIZE);
        &self.buffer[self.plaintext_offset..self.plaintext_offset + self.plaintext_len]
    }

    pub(in crate::node) fn msg_type(&self) -> u8 {
        self.msg_type
    }

    #[cfg(test)]
    fn inner_flags_byte(&self) -> u8 {
        self.inner_flags_byte
    }

    #[cfg(test)]
    fn timestamp(&self) -> u32 {
        self.timestamp
    }

    pub(in crate::node) fn body(&self) -> &[u8] {
        let body_offset = self.plaintext_offset + FSP_INNER_HEADER_SIZE;
        let body_len = self.body_len();
        &self.buffer[body_offset..body_offset + body_len]
    }

    pub(in crate::node) fn body_len(&self) -> usize {
        debug_assert!(self.plaintext_len >= FSP_INNER_HEADER_SIZE);
        self.plaintext_len - FSP_INNER_HEADER_SIZE
    }

    pub(in crate::node) fn is_application_data(&self) -> bool {
        self.msg_type == SessionMessageType::DataPacket.to_byte()
            || self.msg_type == SessionMessageType::EndpointData.to_byte()
    }

    pub(in crate::node) fn into_endpoint_data_delivery(mut self) -> EndpointDataDelivery {
        debug_assert_eq!(self.msg_type, SessionMessageType::EndpointData.to_byte());
        // Keep the receive hot path allocation-free after AEAD open. Slow
        // paths store plaintext at offset 0; worker fast paths may store it
        // inside the original FMP packet buffer. In both cases, move the
        // endpoint body to the front of the existing Vec and truncate the
        // trailing wire bytes instead of allocating a fresh payload Vec.
        let body_offset = self.plaintext_offset + FSP_INNER_HEADER_SIZE;
        let body_len = self.body_len();
        if body_offset > 0 {
            self.buffer.drain(..body_offset);
        }
        self.buffer.truncate(body_len);
        EndpointDataDelivery::new(self.source_peer, self.buffer)
    }
}

/// Local dispatch context for an authenticated established-FSP message.
///
/// The rx loop still executes the handlers today. This object is the next
/// ownership boundary for the future peer/session runtime: source route facts,
/// CE state, the authenticated session message, and receive-completion
/// bookkeeping move together.
#[derive(Debug)]
struct AuthenticatedSessionDispatch {
    source_addr: NodeAddr,
    previous_hop_addr: NodeAddr,
    ce_flag: bool,
    message: AuthenticatedSessionMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionReceiveCompletion {
    source_addr: NodeAddr,
    body_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionDispatchCommit {
    source_addr: NodeAddr,
    receive_completion: Option<SessionReceiveCompletion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionDispatchFinish {
    pending_flush_dest: Option<NodeAddr>,
}

impl SessionDispatchFinish {
    fn pending_flush_dest(&self) -> Option<NodeAddr> {
        self.pending_flush_dest
    }
}

impl AuthenticatedSessionDispatch {
    fn new(
        source_addr: NodeAddr,
        previous_hop_addr: NodeAddr,
        ce_flag: bool,
        message: AuthenticatedSessionMessage,
    ) -> Self {
        Self {
            source_addr,
            previous_hop_addr,
            ce_flag,
            message,
        }
    }

    fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    fn previous_hop_addr(&self) -> &NodeAddr {
        &self.previous_hop_addr
    }

    fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    fn msg_type(&self) -> u8 {
        self.message.msg_type()
    }

    fn is_endpoint_data(&self) -> bool {
        self.msg_type() == SessionMessageType::EndpointData.to_byte()
    }

    fn body(&self) -> &[u8] {
        self.message.body()
    }

    fn receive_completion(&self) -> Option<SessionReceiveCompletion> {
        self.message
            .is_application_data()
            .then_some(SessionReceiveCompletion {
                source_addr: self.source_addr,
                body_len: self.message.body_len(),
            })
    }

    fn commit(&self) -> SessionDispatchCommit {
        SessionDispatchCommit {
            source_addr: self.source_addr,
            receive_completion: self.receive_completion(),
        }
    }

    fn into_endpoint_data_delivery(self) -> EndpointDataDelivery {
        self.message.into_endpoint_data_delivery()
    }

    async fn dispatch(self, node: &mut Node) {
        // Reverse-route learning runs after the session-entry borrow drops.
        node.learn_reverse_route(*self.source_addr(), *self.previous_hop_addr());

        // Capture the dispatch facts now, before the EndpointData branch takes
        // ownership of the message and drains the inner header in place.
        let source_addr = *self.source_addr();
        let msg_type = self.msg_type();
        let commit = self.commit();

        match SessionMessageType::from_byte(msg_type) {
            Some(SessionMessageType::DataPacket) => {
                let rest = self.body();
                // msg_type 0x10: port-multiplexed service dispatch
                if rest.len() < FSP_PORT_HEADER_SIZE {
                    debug!(len = rest.len(), "DataPacket too short for port header");
                    return;
                }
                let dst_port = u16::from_le_bytes([rest[2], rest[3]]);
                let service_payload = &rest[FSP_PORT_HEADER_SIZE..];

                match dst_port {
                    FSP_PORT_IPV6_SHIM => {
                        use crate::FipsAddress;
                        let src_ipv6 = FipsAddress::from_node_addr(&source_addr).to_ipv6().octets();
                        let dst_ipv6 = FipsAddress::from_node_addr(node.node_addr())
                            .to_ipv6()
                            .octets();

                        match crate::upper::ipv6_shim::decompress_ipv6(
                            service_payload,
                            src_ipv6,
                            dst_ipv6,
                        ) {
                            Some(mut packet) => {
                                if self.ce_flag() {
                                    mark_ipv6_ecn_ce(&mut packet);
                                    node.stats_mut().congestion.record_ce_received();
                                }
                                if node.external_packet_tx.is_some() {
                                    node.deliver_external_ipv6_packet(&source_addr, packet);
                                } else if let Some(tun_tx) = &node.tun_tx {
                                    let _t = crate::perf_profile::Timer::start(
                                        crate::perf_profile::Stage::TunWrite,
                                    );
                                    if let Err(e) = tun_tx.send(packet) {
                                        debug!(error = %e, "Failed to deliver decompressed IPv6 packet to TUN");
                                    }
                                } else {
                                    trace!(
                                        src = %node.peer_display_name(&source_addr),
                                        "IPv6 shim packet decompressed (no TUN interface)"
                                    );
                                }
                            }
                            None => {
                                debug!(
                                    src = %node.peer_display_name(&source_addr),
                                    len = service_payload.len(),
                                    "IPv6 shim decompression failed"
                                );
                            }
                        }
                    }
                    _ => {
                        debug!(
                            src = %node.peer_display_name(&source_addr),
                            dst_port,
                            "Unknown FSP service port, dropping DataPacket"
                        );
                    }
                }
            }
            Some(SessionMessageType::EndpointData) => {
                node.deliver_endpoint_data(self.into_endpoint_data_delivery());
            }
            Some(SessionMessageType::TraversalOffer) => {
                let rest = self.body();
                node.handle_mesh_traversal_offer(&source_addr, rest).await;
            }
            Some(SessionMessageType::TraversalAnswer) => {
                let rest = self.body();
                node.handle_mesh_traversal_answer(&source_addr, rest).await;
            }
            Some(SessionMessageType::SenderReport) => {
                let rest = self.body();
                node.handle_session_sender_report(&source_addr, rest);
            }
            Some(SessionMessageType::ReceiverReport) => {
                let rest = self.body();
                node.handle_session_receiver_report(&source_addr, rest)
                    .await;
            }
            Some(SessionMessageType::PathMtuNotification) => {
                let rest = self.body();
                node.handle_session_path_mtu_notification(&source_addr, rest);
            }
            Some(SessionMessageType::CoordsWarmup) => {
                // Standalone coordinate warming — coords already extracted
                // from CP flag by transit nodes. No action needed at endpoint.
                trace!(src = %node.peer_display_name(&source_addr), "CoordsWarmup received");
            }
            _ => {
                debug!(
                    src = %node.peer_display_name(&source_addr),
                    msg_type,
                    "Unknown session message type, dropping"
                );
            }
        }

        commit.finalize(node).await;
    }

    fn dispatch_endpoint_data_fast(self, node: &mut Node) -> SessionDispatchFinish {
        debug_assert!(self.is_endpoint_data());

        // Reverse-route learning still belongs to the authenticated dispatch
        // edge; the endpoint-data fast branch only avoids the async dispatcher.
        node.learn_reverse_route(*self.source_addr(), *self.previous_hop_addr());

        let commit = self.commit();
        node.deliver_endpoint_data(self.into_endpoint_data_delivery());
        commit.finish_receive(node)
    }
}

impl SessionDispatchCommit {
    #[cfg(test)]
    fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    #[cfg(test)]
    fn receive_completion(&self) -> Option<SessionReceiveCompletion> {
        self.receive_completion
    }

    fn record_receive(&self, sessions: &mut crate::node::SessionRegistry, now_ms: u64) -> bool {
        let Some(completion) = self.receive_completion else {
            return false;
        };
        sessions.record_receive_completion(completion, now_ms)
    }

    fn finish_receive(&self, node: &mut Node) -> SessionDispatchFinish {
        // Only application data resets the idle timer and traffic counters —
        // MMP reports (SenderReport, ReceiverReport, PathMtuNotification) do not.
        self.record_receive(&mut node.sessions, Node::now_ms());

        SessionDispatchFinish {
            pending_flush_dest: node
                .pending_session_traffic
                .has_traffic_for(&self.source_addr)
                .then_some(self.source_addr),
        }
    }

    async fn finalize(self, node: &mut Node) {
        // Flush any pending outbound packets (e.g., simultaneous initiation
        // where responder also had queued outbound packets).
        let finish = self.finish_receive(node);
        if let Some(dest_addr) = finish.pending_flush_dest() {
            node.flush_pending_packets(&dest_addr).await;
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
struct PipelinedEndpointSend<'a> {
    dest_addr: &'a NodeAddr,
    payload: &'a EndpointDataPayload,
    now_ms: u64,
    timestamp: u32,
    fsp_flags: u8,
    inner_plaintext: &'a [u8],
    my_coords: Option<&'a crate::tree::TreeCoordinate>,
    dest_coords: Option<&'a crate::tree::TreeCoordinate>,
}

struct PreparedEndpointSessionData<'a> {
    dest_addr: &'a NodeAddr,
    payload: &'a EndpointDataPayload,
    now_ms: u64,
    timestamp: u32,
    fsp_flags: u8,
    inner_plaintext: Vec<u8>,
    my_coords: Option<crate::tree::TreeCoordinate>,
    dest_coords: Option<crate::tree::TreeCoordinate>,
}

#[cfg(unix)]
struct PipelinedEndpointWire {
    wire_buf: Vec<u8>,
    fsp_aad_offset: usize,
    fsp_plaintext_offset: usize,
    link_plaintext_len: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    fmp_inner_len: usize,
    wire_capacity: usize,
}

#[cfg(unix)]
struct PipelinedEndpointWirePlan<'a> {
    source_addr: NodeAddr,
    dest_addr: NodeAddr,
    inner_plaintext: &'a [u8],
    my_coords: Option<&'a crate::tree::TreeCoordinate>,
    dest_coords: Option<&'a crate::tree::TreeCoordinate>,
    path_mtu: u16,
    default_ttl: u8,
    link_plaintext_len: usize,
    fmp_payload_len: u16,
}

#[cfg(unix)]
struct PipelinedEndpointWorkerWire {
    fmp_cipher: ring::aead::LessSafeKey,
    fmp_counter: u64,
    fsp_counter: u64,
    wire_buf: Vec<u8>,
    fsp_seal: crate::node::encrypt_worker::FspSealJob,
    link_plaintext_len: usize,
    wire_capacity: usize,
}

#[cfg(unix)]
struct PipelinedEndpointSendTarget {
    socket: crate::transport::udp::socket::AsyncUdpSocket,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_socket:
        Option<std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
    socket_addr: std::net::SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFspSendBookkeeping {
    Data { payload_len: usize, now_ms: u64 },
    Control,
}

struct SessionFspSendPlan<'a> {
    dest_addr: NodeAddr,
    timestamp: u32,
    fsp_flags: u8,
    inner_plaintext: &'a [u8],
    coords: Option<(
        &'a crate::tree::TreeCoordinate,
        &'a crate::tree::TreeCoordinate,
    )>,
    bookkeeping: SessionFspSendBookkeeping,
}

struct SealedSessionFspSend {
    dest_addr: NodeAddr,
    timestamp: u32,
    counter: u64,
    ciphertext_len: usize,
    fsp_payload: Vec<u8>,
    bookkeeping: SessionFspSendBookkeeping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionDatagramRuntimeRoute {
    dest_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    path_mtu: u16,
    source_mmp_seeded: bool,
}

#[cfg(unix)]
struct PipelinedEndpointDispatchPlan<'a> {
    next_hop_addr: NodeAddr,
    payload: &'a EndpointDataPayload,
    timestamp: u32,
    now_ms: u64,
    fsp_flags: u8,
    path_mtu: u16,
    inner_plaintext_len: usize,
    fsp_payload_len: u16,
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
    scheduling_weight: u8,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PipelinedEndpointRoutePlan {
    source_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    path_mtu: u16,
    default_ttl: u8,
    scheduling_weight: u8,
    direct_path_blocks_direct_payload: bool,
}

#[cfg(unix)]
struct PipelinedEndpointPeerRuntimeRoute {
    source_addr: NodeAddr,
    peer_snapshot: crate::node::PeerRuntimeRouteSnapshot,
    default_ttl: u8,
    scheduling_weight: u8,
    direct_path_blocks_direct_payload: bool,
}

#[cfg(unix)]
struct PipelinedEndpointPeerRuntimeRouteRequest {
    source_addr: NodeAddr,
    dest_addr: NodeAddr,
    now_ms: u64,
    default_ttl: u8,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointSendPlanError {
    FmpPayloadTooLarge,
    FspPayloadTooLarge,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointPeerRuntimeRouteRequestError {
    NoRoute {
        dest_addr: NodeAddr,
    },
    FmpPreparation {
        next_hop_addr: NodeAddr,
        error: crate::node::FmpSendPreparationError,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointRuntimeSendPlanError {
    SendPlan(PipelinedEndpointSendPlanError),
    RoutePeerMismatch {
        route_next_hop: NodeAddr,
        peer_snapshot_addr: NodeAddr,
    },
    FmpPayloadMismatch {
        prepared_payload_len: u16,
        plan_payload_len: u16,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointRuntimeSendAttemptError {
    FspReservation {
        dest_addr: NodeAddr,
        error: crate::node::FspWorkerSendReservationError,
    },
    FmpReservation {
        next_hop_addr: NodeAddr,
        error: crate::node::FmpSendPreparationError,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointRuntimeSendError {
    TransportNotFound(crate::transport::TransportId),
    Attempt(PipelinedEndpointRuntimeSendAttemptError),
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointPeerRuntimeSendError {
    RuntimePlan {
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        error: PipelinedEndpointRuntimeSendPlanError,
    },
    RuntimeSend(PipelinedEndpointRuntimeSendError),
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointPeerRuntimeSendRequestError {
    Route(PipelinedEndpointPeerRuntimeRouteRequestError),
    Send(PipelinedEndpointPeerRuntimeSendError),
}

#[cfg(unix)]
struct PipelinedEndpointSendPlan<'a> {
    wire_plan: PipelinedEndpointWirePlan<'a>,
    dispatch_plan: PipelinedEndpointDispatchPlan<'a>,
}

#[cfg(unix)]
struct PipelinedEndpointRuntimeSendPlan<'a> {
    route_plan: PipelinedEndpointRoutePlan,
    send_plan: PipelinedEndpointSendPlan<'a>,
    peer_snapshot: crate::node::PeerRuntimeSendSnapshot,
}

#[cfg(unix)]
struct PipelinedEndpointRuntimeSendDispatch<'a> {
    runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
    send_target: PipelinedEndpointSendTarget,
    fmp_reservation: crate::node::PreparedFmpWorkerReservation,
    fsp_reservation: crate::node::session::FspSendReservation,
}

#[cfg(unix)]
struct PipelinedEndpointRuntimeSendAttempt<'a> {
    runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
    send_target: PipelinedEndpointSendTarget,
}

#[cfg(unix)]
struct PipelinedEndpointRuntimeSend<'a> {
    runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
}

#[cfg(unix)]
struct PipelinedEndpointPeerRuntimeSend<'a> {
    runtime_route: PipelinedEndpointPeerRuntimeRoute,
    send: PipelinedEndpointSend<'a>,
}

#[cfg(unix)]
struct PipelinedEndpointPeerRuntimeSendRequest<'a> {
    route_request: PipelinedEndpointPeerRuntimeRouteRequest,
    send: PipelinedEndpointSend<'a>,
}

#[cfg(unix)]
struct PipelinedEndpointPreparedSend {
    dest_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    fmp_counter: u64,
    fmp_timestamp_ms: u32,
    fmp_wire_capacity: usize,
    originated_bytes: usize,
    fsp_bookkeeping: FspSendBookkeepingInput,
    worker_job: crate::node::encrypt_worker::FmpSendJob,
}

#[cfg(unix)]
fn pipelined_endpoint_link_plaintext_len(
    inner_plaintext_len: usize,
    my_coords: Option<&crate::tree::TreeCoordinate>,
    dest_coords: Option<&crate::tree::TreeCoordinate>,
) -> usize {
    let coords_size = match (my_coords, dest_coords) {
        (Some(src), Some(dst)) => coords_wire_size(src) + coords_wire_size(dst),
        _ => 0,
    };
    SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + coords_size + inner_plaintext_len
}

#[cfg(unix)]
fn pipelined_endpoint_fmp_payload_len(link_plaintext_len: usize) -> Option<u16> {
    let payload_len = 4usize
        .checked_add(link_plaintext_len)?
        .checked_add(crate::noise::TAG_SIZE)?;
    u16::try_from(payload_len).ok()
}

impl<'a> PreparedEndpointSessionData<'a> {
    fn pipelined(&self) -> PipelinedEndpointSend<'_> {
        PipelinedEndpointSend {
            dest_addr: self.dest_addr,
            payload: self.payload,
            now_ms: self.now_ms,
            timestamp: self.timestamp,
            fsp_flags: self.fsp_flags,
            inner_plaintext: &self.inner_plaintext,
            my_coords: self.my_coords.as_ref(),
            dest_coords: self.dest_coords.as_ref(),
        }
    }

    fn fallback_plan(&self) -> SessionFspSendPlan<'_> {
        SessionFspSendPlan::new(
            *self.dest_addr,
            self.timestamp,
            self.fsp_flags,
            &self.inner_plaintext,
            self.my_coords.as_ref().zip(self.dest_coords.as_ref()),
            SessionFspSendBookkeeping::Data {
                payload_len: self.payload.len(),
                now_ms: self.now_ms,
            },
        )
    }
}

impl<'a> SessionFspSendPlan<'a> {
    fn new(
        dest_addr: NodeAddr,
        timestamp: u32,
        fsp_flags: u8,
        inner_plaintext: &'a [u8],
        coords: Option<(
            &'a crate::tree::TreeCoordinate,
            &'a crate::tree::TreeCoordinate,
        )>,
        bookkeeping: SessionFspSendBookkeeping,
    ) -> Self {
        let fsp_flags = if coords.is_some() {
            fsp_flags | FSP_FLAG_CP
        } else {
            fsp_flags & !FSP_FLAG_CP
        };
        Self {
            dest_addr,
            timestamp,
            fsp_flags,
            inner_plaintext,
            coords,
            bookkeeping,
        }
    }

    fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    fn seal(self, session: &mut NoiseSession) -> Result<SealedSessionFspSend, NodeError> {
        let payload_len =
            u16::try_from(self.inner_plaintext.len()).map_err(|_| NodeError::SendFailed {
                node_addr: self.dest_addr,
                reason: "session FSP payload too large".into(),
            })?;
        let counter = session.current_send_counter();
        let header = build_fsp_header(counter, self.fsp_flags, payload_len);
        let ciphertext = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspEncrypt);
            session
                .encrypt_with_aad(self.inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: self.dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?
        };

        let coords_size = self
            .coords
            .as_ref()
            .map(|(src, dst)| coords_wire_size(src) + coords_wire_size(dst))
            .unwrap_or(0);
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + coords_size + ciphertext.len());
        fsp_payload.extend_from_slice(&header);
        if let Some((src, dst)) = self.coords {
            encode_coords(src, &mut fsp_payload);
            encode_coords(dst, &mut fsp_payload);
        }
        fsp_payload.extend_from_slice(&ciphertext);

        Ok(SealedSessionFspSend {
            dest_addr: self.dest_addr,
            timestamp: self.timestamp,
            counter,
            ciphertext_len: ciphertext.len(),
            fsp_payload,
            bookkeeping: self.bookkeeping,
        })
    }
}

impl SealedSessionFspSend {
    #[cfg(test)]
    fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    #[cfg(test)]
    fn counter(&self) -> u64 {
        self.counter
    }

    fn fsp_bookkeeping_input(&self) -> FspSendBookkeepingInput {
        match self.bookkeeping {
            SessionFspSendBookkeeping::Data {
                payload_len,
                now_ms,
            } => FspSendBookkeepingInput::data(
                payload_len,
                self.counter,
                self.timestamp,
                self.ciphertext_len,
                now_ms,
            ),
            SessionFspSendBookkeeping::Control => {
                FspSendBookkeepingInput::control(self.counter, self.timestamp, self.ciphertext_len)
            }
        }
    }

    fn into_datagram(
        self,
        source_addr: NodeAddr,
        ttl: u8,
    ) -> (SessionDatagram, FspSendBookkeepingInput) {
        let bookkeeping = self.fsp_bookkeeping_input();
        let datagram =
            SessionDatagram::new(source_addr, self.dest_addr, self.fsp_payload).with_ttl(ttl);
        (datagram, bookkeeping)
    }
}

impl SessionDatagramRuntimeRoute {
    fn new(
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        source_mmp_seeded: bool,
    ) -> Self {
        Self {
            dest_addr,
            next_hop_addr,
            path_mtu,
            source_mmp_seeded,
        }
    }

    #[cfg(test)]
    fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    fn next_hop_addr(&self) -> NodeAddr {
        self.next_hop_addr
    }

    #[cfg(test)]
    fn path_mtu(&self) -> u16 {
        self.path_mtu
    }

    #[cfg(test)]
    fn source_mmp_seeded(&self) -> bool {
        self.source_mmp_seeded
    }

    fn record_success(self, node: &mut Node, encoded_len: usize) {
        node.sessions
            .record_session_datagram_next_hop(&self.dest_addr, self.next_hop_addr);
        node.stats_mut().forwarding.record_originated(encoded_len);
    }

    fn record_failure(self, node: &mut Node) {
        node.record_route_failure(self.dest_addr, self.next_hop_addr);
    }
}

#[cfg(unix)]
impl PipelinedEndpointSendTarget {
    async fn resolve(
        udp: &crate::transport::udp::UdpTransport,
        prepared: &crate::node::FmpSendPreparation,
    ) -> Option<Self> {
        let socket_addr = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                match prepared.connected_socket.as_ref() {
                    Some(socket) => Some(socket.peer_addr()),
                    None => udp.resolve_for_off_task(&prepared.remote_addr).await.ok(),
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                udp.resolve_for_off_task(&prepared.remote_addr).await.ok()
            }
        }?;
        let socket = udp.async_socket()?;
        Some(Self {
            socket,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: prepared.connected_socket.clone(),
            socket_addr,
        })
    }

    fn into_selected_send_target(self) -> crate::node::encrypt_worker::SelectedSendTarget {
        crate::node::encrypt_worker::SelectedSendTarget::new(
            self.socket,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            self.connected_socket,
            self.socket_addr,
        )
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointDispatchPlan<'a> {
    fn new(
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Option<Self> {
        let fsp_payload_len = u16::try_from(send.inner_plaintext.len()).ok()?;
        let bulk_endpoint_data =
            send.fsp_flags & FSP_FLAG_CP == 0 && send.payload.bulk_endpoint_data();
        let drop_on_backpressure = next_hop_addr == *send.dest_addr
            && !direct_path_blocks_direct_payload
            && bulk_endpoint_data
            && send.payload.drop_on_backpressure();

        Some(Self {
            next_hop_addr,
            payload: send.payload,
            timestamp: send.timestamp,
            now_ms: send.now_ms,
            fsp_flags: send.fsp_flags,
            path_mtu,
            inner_plaintext_len: send.inner_plaintext.len(),
            fsp_payload_len,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight,
        })
    }

    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        crate::node::FspWorkerSendReservationInput {
            flags: self.fsp_flags,
            payload_len: self.fsp_payload_len,
            path_mtu: self.path_mtu,
        }
    }

    fn fsp_bookkeeping_input(&self, fsp_counter: u64) -> FspSendBookkeepingInput {
        FspSendBookkeepingInput::data(
            self.payload.len(),
            fsp_counter,
            self.timestamp,
            self.inner_plaintext_len + crate::noise::TAG_SIZE,
            self.now_ms,
        )
        .with_next_hop(self.next_hop_addr)
    }

    fn into_worker_job(
        self,
        worker_wire: PipelinedEndpointWorkerWire,
        send_target: crate::node::encrypt_worker::SelectedSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> crate::node::encrypt_worker::FmpSendJob {
        worker_wire.into_job(
            send_target,
            self.bulk_endpoint_data,
            self.drop_on_backpressure,
            self.scheduling_weight,
            queued_at,
        )
    }
}

#[cfg(unix)]
impl PipelinedEndpointRoutePlan {
    fn new(
        source_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Self {
        Self {
            source_addr,
            next_hop_addr,
            path_mtu,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        }
    }

    fn build_send_plan<'a>(
        &self,
        send: &PipelinedEndpointSend<'a>,
    ) -> Result<PipelinedEndpointSendPlan<'a>, PipelinedEndpointSendPlanError> {
        PipelinedEndpointSendPlan::new(
            &self.source_addr,
            send,
            self.next_hop_addr,
            self.path_mtu,
            self.default_ttl,
            self.scheduling_weight,
            self.direct_path_blocks_direct_payload,
        )
    }
}

#[cfg(unix)]
impl PipelinedEndpointPeerRuntimeRoute {
    fn new(
        source_addr: NodeAddr,
        peer_snapshot: crate::node::PeerRuntimeRouteSnapshot,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Self {
        Self {
            source_addr,
            peer_snapshot,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        }
    }

    fn from_decision(
        source_addr: NodeAddr,
        default_ttl: u8,
        decision: crate::node::PeerRuntimeRouteDecision,
    ) -> Self {
        let (peer_snapshot, scheduling_weight, direct_path_blocks_direct_payload) =
            decision.into_parts();
        Self::new(
            source_addr,
            peer_snapshot,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        )
    }

    fn next_hop_addr(&self) -> NodeAddr {
        self.peer_snapshot.node_addr()
    }

    fn transport_id(&self) -> crate::transport::TransportId {
        self.peer_snapshot.transport_id()
    }

    #[cfg(test)]
    fn default_ttl(&self) -> u8 {
        self.default_ttl
    }

    #[cfg(test)]
    fn scheduling_weight(&self) -> u8 {
        self.scheduling_weight
    }

    #[cfg(test)]
    fn direct_path_blocks_direct_payload(&self) -> bool {
        self.direct_path_blocks_direct_payload
    }

    fn route_plan(
        &self,
        transport: &crate::transport::TransportHandle,
    ) -> PipelinedEndpointRoutePlan {
        PipelinedEndpointRoutePlan::new(
            self.source_addr,
            self.peer_snapshot.node_addr(),
            self.peer_snapshot.path_mtu(transport),
            self.default_ttl,
            self.scheduling_weight,
            self.direct_path_blocks_direct_payload,
        )
    }

    fn runtime_send_plan<'a>(
        &self,
        send: &PipelinedEndpointSend<'a>,
        transport: &crate::transport::TransportHandle,
    ) -> Result<PipelinedEndpointRuntimeSendPlan<'a>, PipelinedEndpointRuntimeSendPlanError> {
        let route_plan = self.route_plan(transport);
        let send_plan = route_plan
            .build_send_plan(send)
            .map_err(PipelinedEndpointRuntimeSendPlanError::SendPlan)?;
        PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
            route_plan,
            send_plan,
            self.peer_snapshot.clone(),
        )
    }

    #[cfg(test)]
    fn into_runtime_send_plan<'a>(
        self,
        send: &PipelinedEndpointSend<'a>,
        transport: &crate::transport::TransportHandle,
    ) -> Result<PipelinedEndpointRuntimeSendPlan<'a>, PipelinedEndpointRuntimeSendPlanError> {
        let route_plan = self.route_plan(transport);
        let send_plan = route_plan
            .build_send_plan(send)
            .map_err(PipelinedEndpointRuntimeSendPlanError::SendPlan)?;
        PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
            route_plan,
            send_plan,
            self.peer_snapshot,
        )
    }
}

#[cfg(unix)]
impl PipelinedEndpointPeerRuntimeRouteRequest {
    fn new(source_addr: NodeAddr, dest_addr: NodeAddr, now_ms: u64, default_ttl: u8) -> Self {
        Self {
            source_addr,
            dest_addr,
            now_ms,
            default_ttl,
        }
    }

    fn resolve(
        self,
        node: &mut Node,
    ) -> Result<PipelinedEndpointPeerRuntimeRoute, PipelinedEndpointPeerRuntimeRouteRequestError>
    {
        let decision = node
            .resolve_peer_runtime_route_decision(&self.dest_addr, self.now_ms)
            .map_err(Self::map_route_decision_error)?;

        Ok(PipelinedEndpointPeerRuntimeRoute::from_decision(
            self.source_addr,
            self.default_ttl,
            decision,
        ))
    }

    fn map_route_decision_error(
        error: crate::node::PeerRuntimeRouteDecisionError,
    ) -> PipelinedEndpointPeerRuntimeRouteRequestError {
        match error {
            crate::node::PeerRuntimeRouteDecisionError::NoRoute { dest_addr } => {
                PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr }
            }
            crate::node::PeerRuntimeRouteDecisionError::FmpPreparation {
                next_hop_addr,
                error,
            } => PipelinedEndpointPeerRuntimeRouteRequestError::FmpPreparation {
                next_hop_addr,
                error,
            },
        }
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointSendPlan<'a> {
    fn new(
        source_addr: &NodeAddr,
        send: &PipelinedEndpointSend<'a>,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Result<Self, PipelinedEndpointSendPlanError> {
        let wire_plan = PipelinedEndpointWirePlan::new(
            source_addr,
            send.dest_addr,
            send.inner_plaintext,
            send.my_coords,
            send.dest_coords,
            path_mtu,
            default_ttl,
        )
        .ok_or(PipelinedEndpointSendPlanError::FmpPayloadTooLarge)?;
        let dispatch_plan = PipelinedEndpointDispatchPlan::new(
            send,
            next_hop_addr,
            path_mtu,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        )
        .ok_or(PipelinedEndpointSendPlanError::FspPayloadTooLarge)?;

        Ok(Self {
            wire_plan,
            dispatch_plan,
        })
    }

    fn link_plaintext_len(&self) -> usize {
        self.wire_plan.link_plaintext_len()
    }

    fn fmp_payload_len(&self) -> u16 {
        self.wire_plan.fmp_payload_len()
    }

    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        self.dispatch_plan.fsp_reservation_input()
    }

    fn into_prepared_worker_send(
        self,
        fmp_prepared: &crate::node::FmpSendPreparation,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
        send_target: PipelinedEndpointSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        debug_assert_eq!(fmp_prepared.payload_len, self.wire_plan.fmp_payload_len());
        let dest_addr = self.wire_plan.dest_addr;
        let next_hop_addr = self.dispatch_plan.next_hop_addr;
        let wire = self.wire_plan.build(
            fmp_reservation.header,
            fsp_reservation.header,
            fmp_prepared.timestamp_ms,
        );
        let worker_wire = wire.into_worker_wire(fmp_reservation, fsp_reservation);
        debug_assert_eq!(
            worker_wire.link_plaintext_len,
            self.wire_plan.link_plaintext_len()
        );

        let fmp_counter = worker_wire.fmp_counter;
        let fsp_counter = worker_wire.fsp_counter;
        let fmp_wire_capacity = worker_wire.wire_capacity;
        let originated_bytes = self.link_plaintext_len() + crate::noise::TAG_SIZE;
        let fsp_bookkeeping = self.dispatch_plan.fsp_bookkeeping_input(fsp_counter);
        let worker_job = self.dispatch_plan.into_worker_job(
            worker_wire,
            send_target.into_selected_send_target(),
            queued_at,
        );

        PipelinedEndpointPreparedSend {
            dest_addr,
            next_hop_addr,
            fmp_counter,
            fmp_timestamp_ms: fmp_prepared.timestamp_ms,
            fmp_wire_capacity,
            originated_bytes,
            fsp_bookkeeping,
            worker_job,
        }
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSendPlan<'a> {
    fn from_peer_route_snapshot(
        route_plan: PipelinedEndpointRoutePlan,
        send_plan: PipelinedEndpointSendPlan<'a>,
        peer_route_snapshot: crate::node::PeerRuntimeRouteSnapshot,
    ) -> Result<Self, PipelinedEndpointRuntimeSendPlanError> {
        let peer_snapshot_addr = peer_route_snapshot.node_addr();
        if route_plan.next_hop_addr != peer_snapshot_addr {
            return Err(PipelinedEndpointRuntimeSendPlanError::RoutePeerMismatch {
                route_next_hop: route_plan.next_hop_addr,
                peer_snapshot_addr,
            });
        }

        let peer_snapshot =
            peer_route_snapshot.prepare_send_snapshot(false, send_plan.fmp_payload_len());
        Self::from_parts(route_plan, send_plan, peer_snapshot)
    }

    fn from_parts(
        route_plan: PipelinedEndpointRoutePlan,
        send_plan: PipelinedEndpointSendPlan<'a>,
        peer_snapshot: crate::node::PeerRuntimeSendSnapshot,
    ) -> Result<Self, PipelinedEndpointRuntimeSendPlanError> {
        let plan_payload_len = send_plan.fmp_payload_len();
        let fmp_prepared = peer_snapshot.fmp_prepared();
        if fmp_prepared.payload_len != plan_payload_len {
            return Err(PipelinedEndpointRuntimeSendPlanError::FmpPayloadMismatch {
                prepared_payload_len: fmp_prepared.payload_len,
                plan_payload_len,
            });
        }

        Ok(Self {
            route_plan,
            send_plan,
            peer_snapshot,
        })
    }

    #[cfg(test)]
    fn source_addr(&self) -> NodeAddr {
        self.route_plan.source_addr
    }

    fn dest_addr(&self) -> NodeAddr {
        self.send_plan.wire_plan.dest_addr
    }

    fn next_hop_addr(&self) -> NodeAddr {
        self.route_plan.next_hop_addr
    }

    #[cfg(test)]
    fn transport_id(&self) -> crate::transport::TransportId {
        self.peer_snapshot.fmp_prepared().transport_id
    }

    #[cfg(test)]
    fn fmp_payload_len(&self) -> u16 {
        self.send_plan.fmp_payload_len()
    }

    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        self.send_plan.fsp_reservation_input()
    }

    #[cfg(test)]
    fn drop_on_backpressure(&self) -> bool {
        self.send_plan.dispatch_plan.drop_on_backpressure
    }

    #[cfg(test)]
    fn scheduling_weight(&self) -> u8 {
        self.send_plan.dispatch_plan.scheduling_weight
    }

    fn fmp_prepared(&self) -> &crate::node::FmpSendPreparation {
        self.peer_snapshot.fmp_prepared()
    }

    fn peer_snapshot(&self) -> &crate::node::PeerRuntimeSendSnapshot {
        &self.peer_snapshot
    }

    fn fmp_worker_send_available(&self) -> bool {
        self.peer_snapshot.fmp_worker_send_available()
    }

    async fn resolve_send_target(
        &self,
        udp: &crate::transport::udp::UdpTransport,
    ) -> Option<PipelinedEndpointSendTarget> {
        PipelinedEndpointSendTarget::resolve(udp, self.fmp_prepared()).await
    }

    fn into_prepared_worker_send(
        self,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
        send_target: PipelinedEndpointSendTarget,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        let Self {
            send_plan,
            peer_snapshot,
            ..
        } = self;
        let fmp_prepared = peer_snapshot.fmp_prepared();
        send_plan.into_prepared_worker_send(
            fmp_prepared,
            fmp_reservation,
            fsp_reservation,
            send_target,
            queued_at,
        )
    }

    #[cfg(test)]
    fn into_parts_for_test(self) -> (PipelinedEndpointRoutePlan, PipelinedEndpointSendPlan<'a>) {
        (self.route_plan, self.send_plan)
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSendDispatch<'a> {
    fn new(
        runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
        send_target: PipelinedEndpointSendTarget,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
    ) -> Self {
        Self {
            runtime_plan,
            send_target,
            fmp_reservation,
            fsp_reservation,
        }
    }

    #[cfg(test)]
    fn dest_addr(&self) -> NodeAddr {
        self.runtime_plan.dest_addr()
    }

    #[cfg(test)]
    fn next_hop_addr(&self) -> NodeAddr {
        self.runtime_plan.next_hop_addr()
    }

    #[cfg(test)]
    fn fsp_reservation_input(&self) -> crate::node::FspWorkerSendReservationInput {
        self.runtime_plan.fsp_reservation_input()
    }

    fn into_prepared_send(
        self,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> PipelinedEndpointPreparedSend {
        let Self {
            runtime_plan,
            send_target,
            fmp_reservation,
            fsp_reservation,
        } = self;
        runtime_plan.into_prepared_worker_send(
            fmp_reservation,
            fsp_reservation,
            send_target,
            queued_at,
        )
    }

    fn commit(self, node: &mut Node, workers: &crate::node::encrypt_worker::EncryptWorkerPool) {
        self.into_prepared_send(crate::perf_profile::stamp())
            .commit(node, workers);
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSendAttempt<'a> {
    fn new(
        runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
        send_target: PipelinedEndpointSendTarget,
    ) -> Self {
        Self {
            runtime_plan,
            send_target,
        }
    }

    fn reserve(
        self,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointRuntimeSendAttemptError,
    > {
        let Self {
            runtime_plan,
            send_target,
        } = self;

        if !runtime_plan.fmp_worker_send_available() {
            return Ok(None);
        }

        let dest_addr = runtime_plan.dest_addr();
        let next_hop_addr = runtime_plan.next_hop_addr();
        let Some(fsp_reservation) = sessions
            .reserve_endpoint_data_fsp_worker_send(&dest_addr, runtime_plan.fsp_reservation_input())
            .map_err(
                |error| PipelinedEndpointRuntimeSendAttemptError::FspReservation {
                    dest_addr,
                    error,
                },
            )?
        else {
            return Ok(None);
        };

        let Some(fmp_reservation) = peers
            .reserve_peer_runtime_fmp_worker_send(runtime_plan.peer_snapshot())
            .map_err(
                |error| PipelinedEndpointRuntimeSendAttemptError::FmpReservation {
                    next_hop_addr,
                    error,
                },
            )?
        else {
            return Ok(None);
        };

        Ok(Some(PipelinedEndpointRuntimeSendDispatch::new(
            runtime_plan,
            send_target,
            fmp_reservation,
            fsp_reservation,
        )))
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointRuntimeSend<'a> {
    fn new(runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>) -> Self {
        Self { runtime_plan }
    }

    async fn resolve_dispatch_with_transport(
        self,
        transport: &crate::transport::TransportHandle,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<Option<PipelinedEndpointRuntimeSendDispatch<'a>>, PipelinedEndpointRuntimeSendError>
    {
        let TransportHandle::Udp(udp) = transport else {
            return Ok(None);
        };
        let Some(send_target) = self.runtime_plan.resolve_send_target(udp).await else {
            return Ok(None);
        };

        PipelinedEndpointRuntimeSendAttempt::new(self.runtime_plan, send_target)
            .reserve(sessions, peers)
            .map_err(PipelinedEndpointRuntimeSendError::Attempt)
    }

    #[cfg(test)]
    async fn resolve_dispatch(
        self,
        transports: &std::collections::HashMap<
            crate::transport::TransportId,
            crate::transport::TransportHandle,
        >,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<Option<PipelinedEndpointRuntimeSendDispatch<'a>>, PipelinedEndpointRuntimeSendError>
    {
        let transport_id = self.runtime_plan.transport_id();
        let transport = transports.get(&transport_id).ok_or(
            PipelinedEndpointRuntimeSendError::TransportNotFound(transport_id),
        )?;
        self.resolve_dispatch_with_transport(transport, sessions, peers)
            .await
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointPeerRuntimeSend<'a> {
    fn new(
        runtime_route: PipelinedEndpointPeerRuntimeRoute,
        send: PipelinedEndpointSend<'a>,
    ) -> Self {
        Self {
            runtime_route,
            send,
        }
    }

    async fn resolve_dispatch_with_route(
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
        send: PipelinedEndpointSend<'a>,
        transports: &std::collections::HashMap<
            crate::transport::TransportId,
            crate::transport::TransportHandle,
        >,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendError,
    > {
        let dest_addr = *send.dest_addr;
        let next_hop_addr = runtime_route.next_hop_addr();
        let transport_id = runtime_route.transport_id();
        let transport = transports.get(&transport_id).ok_or(
            PipelinedEndpointPeerRuntimeSendError::RuntimeSend(
                PipelinedEndpointRuntimeSendError::TransportNotFound(transport_id),
            ),
        )?;
        let runtime_plan = runtime_route
            .runtime_send_plan(&send, transport)
            .map_err(|error| PipelinedEndpointPeerRuntimeSendError::RuntimePlan {
                dest_addr,
                next_hop_addr,
                error,
            })?;

        PipelinedEndpointRuntimeSend::new(runtime_plan)
            .resolve_dispatch_with_transport(transport, sessions, peers)
            .await
            .map_err(PipelinedEndpointPeerRuntimeSendError::RuntimeSend)
    }

    async fn resolve_dispatch(
        self,
        transports: &std::collections::HashMap<
            crate::transport::TransportId,
            crate::transport::TransportHandle,
        >,
        sessions: &mut crate::node::SessionRegistry,
        peers: &mut crate::node::PeerLifecycleRegistry,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendError,
    > {
        Self::resolve_dispatch_with_route(
            &self.runtime_route,
            self.send,
            transports,
            sessions,
            peers,
        )
        .await
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointPeerRuntimeSendRequest<'a> {
    fn new(source_addr: NodeAddr, send: PipelinedEndpointSend<'a>, default_ttl: u8) -> Self {
        let route_request = PipelinedEndpointPeerRuntimeRouteRequest::new(
            source_addr,
            *send.dest_addr,
            send.now_ms,
            default_ttl,
        );
        Self {
            route_request,
            send,
        }
    }

    async fn resolve_dispatch(
        self,
        node: &mut Node,
    ) -> Result<
        Option<PipelinedEndpointRuntimeSendDispatch<'a>>,
        PipelinedEndpointPeerRuntimeSendRequestError,
    > {
        let runtime_route = self
            .route_request
            .resolve(node)
            .map_err(PipelinedEndpointPeerRuntimeSendRequestError::Route)?;

        PipelinedEndpointPeerRuntimeSend::new(runtime_route, self.send)
            .resolve_dispatch(&node.transports, &mut node.sessions, &mut node.peers)
            .await
            .map_err(PipelinedEndpointPeerRuntimeSendRequestError::Send)
    }

    async fn execute(
        self,
        node: &mut Node,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) -> Result<bool, PipelinedEndpointPeerRuntimeSendRequestError> {
        let Some(dispatch) = self.resolve_dispatch(node).await? else {
            return Ok(false);
        };
        dispatch.commit(node, workers);
        Ok(true)
    }
}

#[cfg(unix)]
impl PipelinedEndpointPreparedSend {
    fn commit(self, node: &mut Node, workers: &crate::node::encrypt_worker::EncryptWorkerPool) {
        let PipelinedEndpointPreparedSend {
            dest_addr,
            next_hop_addr,
            fmp_counter,
            fmp_timestamp_ms,
            fmp_wire_capacity,
            originated_bytes,
            fsp_bookkeeping,
            worker_job,
        } = self;

        let _ = node.peers.record_fmp_send_bookkeeping(
            &next_hop_addr,
            fmp_counter,
            fmp_timestamp_ms,
            fmp_wire_capacity,
        );
        node.stats_mut()
            .forwarding
            .record_originated(originated_bytes);

        let _ = node
            .sessions
            .record_fsp_send_bookkeeping(&dest_addr, fsp_bookkeeping);

        workers.dispatch(worker_job);
    }
}

#[cfg(unix)]
impl<'a> PipelinedEndpointWirePlan<'a> {
    fn new(
        source_addr: &NodeAddr,
        dest_addr: &NodeAddr,
        inner_plaintext: &'a [u8],
        my_coords: Option<&'a crate::tree::TreeCoordinate>,
        dest_coords: Option<&'a crate::tree::TreeCoordinate>,
        path_mtu: u16,
        default_ttl: u8,
    ) -> Option<Self> {
        let link_plaintext_len =
            pipelined_endpoint_link_plaintext_len(inner_plaintext.len(), my_coords, dest_coords);
        let fmp_payload_len = pipelined_endpoint_fmp_payload_len(link_plaintext_len)?;
        Some(Self {
            source_addr: *source_addr,
            dest_addr: *dest_addr,
            inner_plaintext,
            my_coords,
            dest_coords,
            path_mtu,
            default_ttl,
            link_plaintext_len,
            fmp_payload_len,
        })
    }

    fn link_plaintext_len(&self) -> usize {
        self.link_plaintext_len
    }

    fn fmp_payload_len(&self) -> u16 {
        self.fmp_payload_len
    }

    fn build(
        &self,
        fmp_header: [u8; ESTABLISHED_HEADER_SIZE],
        fsp_header: [u8; FSP_HEADER_SIZE],
        timestamp_ms: u32,
    ) -> PipelinedEndpointWire {
        let fmp_inner_len = self.fmp_payload_len as usize;

        let wire_capacity = ESTABLISHED_HEADER_SIZE + fmp_inner_len + crate::noise::TAG_SIZE;
        let mut wire_buf = Vec::with_capacity(wire_capacity);
        wire_buf.extend_from_slice(&fmp_header);
        wire_buf.extend_from_slice(&timestamp_ms.to_le_bytes());
        wire_buf.push(LinkMessageType::SessionDatagram.to_byte());
        wire_buf.push(self.default_ttl);
        wire_buf.extend_from_slice(&self.path_mtu.to_le_bytes());
        wire_buf.extend_from_slice(self.source_addr.as_bytes());
        wire_buf.extend_from_slice(self.dest_addr.as_bytes());
        let fsp_aad_offset = wire_buf.len();
        wire_buf.extend_from_slice(&fsp_header);
        if let (Some(src), Some(dst)) = (self.my_coords, self.dest_coords) {
            encode_coords(src, &mut wire_buf);
            encode_coords(dst, &mut wire_buf);
        }
        let fsp_plaintext_offset = wire_buf.len();
        wire_buf.extend_from_slice(self.inner_plaintext);

        PipelinedEndpointWire {
            wire_buf,
            fsp_aad_offset,
            fsp_plaintext_offset,
            link_plaintext_len: self.link_plaintext_len,
            fmp_inner_len,
            wire_capacity,
        }
    }
}

#[cfg(unix)]
impl PipelinedEndpointWire {
    fn into_worker_wire(
        self,
        fmp_reservation: crate::node::PreparedFmpWorkerReservation,
        fsp_reservation: crate::node::session::FspSendReservation,
    ) -> PipelinedEndpointWorkerWire {
        debug_assert_eq!(self.wire_capacity, fmp_reservation.predicted_bytes);
        debug_assert_eq!(
            &self.wire_buf[..ESTABLISHED_HEADER_SIZE],
            &fmp_reservation.header
        );
        debug_assert_eq!(
            &self.wire_buf[self.fsp_aad_offset..self.fsp_aad_offset + FSP_HEADER_SIZE],
            &fsp_reservation.header
        );

        PipelinedEndpointWorkerWire {
            fmp_cipher: fmp_reservation.cipher,
            fmp_counter: fmp_reservation.counter,
            fsp_counter: fsp_reservation.counter,
            wire_buf: self.wire_buf,
            fsp_seal: crate::node::encrypt_worker::FspSealJob {
                cipher: fsp_reservation.cipher,
                counter: fsp_reservation.counter,
                aad_offset: self.fsp_aad_offset,
                plaintext_offset: self.fsp_plaintext_offset,
            },
            link_plaintext_len: self.link_plaintext_len,
            wire_capacity: self.wire_capacity,
        }
    }
}

#[cfg(unix)]
impl PipelinedEndpointWorkerWire {
    fn into_job(
        self,
        send_target: crate::node::encrypt_worker::SelectedSendTarget,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
        scheduling_weight: u8,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> crate::node::encrypt_worker::FmpSendJob {
        crate::node::encrypt_worker::FmpSendJob {
            cipher: self.fmp_cipher,
            counter: self.fmp_counter,
            wire_buf: self.wire_buf,
            fsp_seal: Some(self.fsp_seal),
            send_target,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight,
            queued_at,
        }
    }
}

/// Start an in-place FSP recovery rekey after this many consecutive AEAD
/// decryption failures from a peer. Recovers from stale session state on
/// either side (e.g. peer restarted with new keys but our entry still holds
/// the old keys, or vice versa) without dropping the old session while the
/// new XK handshake completes.
const DECRYPT_FAILURE_RECOVERY_THRESHOLD: u32 = 32;
fn pending_rekey_wins_tiebreak(
    our_addr: &NodeAddr,
    peer_addr: &NodeAddr,
    existing: &SessionEntry,
) -> bool {
    existing.pending_new_session().is_some()
        && existing.is_rekey_initiator()
        && our_addr < peer_addr
}

fn duplicate_rekey_responder_ack(existing: &SessionEntry) -> Option<Vec<u8>> {
    if existing.is_established()
        && existing.has_rekey_in_progress()
        && !existing.is_rekey_initiator()
    {
        return existing.handshake_payload().map(<[u8]>::to_vec);
    }
    None
}

fn should_start_decrypt_failure_rekey(entry: &SessionEntry, consecutive: u32) -> bool {
    consecutive >= DECRYPT_FAILURE_RECOVERY_THRESHOLD
        && entry.is_established()
        && !entry.has_rekey_in_progress()
        && entry.pending_new_session().is_none()
}

fn should_ignore_stale_epoch_drain_failure(entry: &SessionEntry, received_k_bit: bool) -> bool {
    entry.is_draining()
        && entry.pending_new_session().is_none()
        && received_k_bit != entry.current_k_bit()
}

/// Receive-side owner for one established FSP frame.
///
/// This is still called from the rx loop today, but it is the movable boundary
/// for the future peer/session runtime: FSP open/replay, K-bit cutover,
/// decrypt-failure accounting, MMP receive bookkeeping, and dispatch metadata
/// now live behind one owner instead of an inline `Node` block.
struct SessionRuntimeReceive<'a> {
    entry: &'a mut SessionEntry,
    ciphertext: &'a [u8],
    counter: u64,
    aad: &'a [u8],
    received_k_bit: bool,
    path_mtu: u16,
    ce_flag: bool,
    now_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct EstablishedFspReceive<'a> {
    header: &'a FspEncryptedHeader,
    ciphertext: &'a [u8],
    path_mtu: u16,
    ce_flag: bool,
    now_ms: u64,
}

impl<'a> EstablishedFspReceive<'a> {
    fn new(
        header: &'a FspEncryptedHeader,
        ciphertext: &'a [u8],
        path_mtu: u16,
        ce_flag: bool,
        now_ms: u64,
    ) -> Self {
        Self {
            header,
            ciphertext,
            path_mtu,
            ce_flag,
            now_ms,
        }
    }
}

#[derive(Debug)]
enum EstablishedFspWireError {
    BadHeader,
    BadCoords(crate::protocol::ProtocolError),
}

#[derive(Debug, Default)]
struct EstablishedFspCoordWarmup {
    source: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
    local: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
}

impl EstablishedFspCoordWarmup {
    fn from_parsed(
        source_addr: NodeAddr,
        local_addr: NodeAddr,
        source_coords: Option<crate::tree::TreeCoordinate>,
        local_coords: Option<crate::tree::TreeCoordinate>,
    ) -> Self {
        Self {
            source: source_coords.map(|coords| (source_addr, coords)),
            local: local_coords.map(|coords| (local_addr, coords)),
        }
    }

    fn is_empty(&self) -> bool {
        self.source.is_none() && self.local.is_none()
    }

    fn apply(self, coord_cache: &mut crate::cache::CoordCache, now_ms: u64) {
        if let Some((addr, coords)) = self.source {
            coord_cache.insert(addr, coords, now_ms);
        }
        if let Some((addr, coords)) = self.local {
            coord_cache.insert(addr, coords, now_ms);
        }
    }
}

#[derive(Debug)]
struct EstablishedFspWire<'a> {
    header: FspEncryptedHeader,
    ciphertext: &'a [u8],
    coord_warmup: EstablishedFspCoordWarmup,
}

impl<'a> EstablishedFspWire<'a> {
    fn parse(
        payload: &'a [u8],
        source_addr: NodeAddr,
        local_addr: NodeAddr,
    ) -> Result<Self, EstablishedFspWireError> {
        let header =
            FspEncryptedHeader::parse(payload).ok_or(EstablishedFspWireError::BadHeader)?;
        let mut ciphertext_offset = FSP_HEADER_SIZE;
        let mut coord_warmup = EstablishedFspCoordWarmup::default();

        if header.has_coords() {
            let (source_coords, local_coords, bytes_consumed) =
                parse_encrypted_coords(&payload[FSP_HEADER_SIZE..])
                    .map_err(EstablishedFspWireError::BadCoords)?;
            coord_warmup = EstablishedFspCoordWarmup::from_parsed(
                source_addr,
                local_addr,
                source_coords,
                local_coords,
            );
            ciphertext_offset += bytes_consumed;
        }

        Ok(Self {
            header,
            ciphertext: &payload[ciphertext_offset..],
            coord_warmup,
        })
    }

    fn has_coord_warmup(&self) -> bool {
        !self.coord_warmup.is_empty()
    }

    fn apply_coord_warmup(&mut self, coord_cache: &mut crate::cache::CoordCache, now_ms: u64) {
        std::mem::take(&mut self.coord_warmup).apply(coord_cache, now_ms);
    }

    fn receive(&self, path_mtu: u16, ce_flag: bool, now_ms: u64) -> EstablishedFspReceive<'_> {
        EstablishedFspReceive::new(&self.header, self.ciphertext, path_mtu, ce_flag, now_ms)
    }
}

#[derive(Debug)]
enum EarlyEncryptedHandshakeResend {
    NoPayload,
    BudgetExhausted,
    Resend { payload: Vec<u8> },
}

impl<'a> SessionRuntimeReceive<'a> {
    fn new(
        entry: &'a mut SessionEntry,
        header: &'a FspEncryptedHeader,
        ciphertext: &'a [u8],
        path_mtu: u16,
        ce_flag: bool,
        now_ms: u64,
    ) -> Self {
        Self {
            entry,
            ciphertext,
            counter: header.counter,
            aad: &header.header_bytes,
            received_k_bit: header.flags & FSP_FLAG_K != 0,
            path_mtu,
            ce_flag,
            now_ms,
        }
    }

    fn open_established(self) -> FspFrameOutcome {
        if !self.entry.is_established() {
            return FspFrameOutcome::NotEstablished;
        }

        let (plaintext, slot) = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
            match self.entry.open_fsp_established_frame(
                self.ciphertext,
                self.counter,
                self.aad,
                self.received_k_bit,
                self.now_ms,
            ) {
                Ok(result) => result,
                Err(FspOpenError::NoLiveEpochAccepted) => {
                    if should_ignore_stale_epoch_drain_failure(self.entry, self.received_k_bit) {
                        return FspFrameOutcome::StaleEpochDrainFailure {
                            counter: self.counter,
                        };
                    }
                    let consecutive = self.entry.record_decrypt_failure();
                    let recover_session =
                        should_start_decrypt_failure_rekey(self.entry, consecutive);
                    return FspFrameOutcome::DecryptFailed {
                        error: crate::noise::NoiseError::DecryptionFailed,
                        counter: self.counter,
                        consecutive,
                        recover_session,
                    };
                }
            }
        };

        match slot {
            EpochSlot::Pending => {
                // A frame that authenticates against pending proves the peer
                // reached the new epoch; promote pending to current.
                if self.entry.rekey_msg3_payload().is_some() {
                    self.entry.confirm_peer_new_epoch();
                }
                self.entry.handle_peer_kbit_flip(self.now_ms);
            }
            EpochSlot::Current => {
                // If the initiator already cut over on its timer, a
                // current-epoch frame confirms the responder received msg3.
                if self.entry.rekey_msg3_payload().is_some()
                    && self.entry.pending_new_session().is_none()
                {
                    self.entry.confirm_peer_new_epoch();
                }
            }
            EpochSlot::Previous => {}
        }

        // Successful decrypt resets failure accounting so one bad packet does
        // not carry forward toward recovery rekey.
        self.entry.reset_decrypt_failures();
        if self.entry.handshake_payload().is_some()
            && self.entry.pending_new_session().is_none()
            && !self.entry.has_rekey_in_progress()
            && slot == EpochSlot::Current
            && self.received_k_bit == self.entry.current_k_bit()
        {
            self.entry.clear_handshake_payload();
        }

        let (timestamp, msg_type, inner_flags_byte) = match fsp_strip_inner_header(&plaintext) {
            Some((ts, mt, inf, _rest)) => (ts, mt, inf),
            None => return FspFrameOutcome::BadInnerHeader,
        };

        if let Some(mmp) = self.entry.mmp_mut() {
            let now = std::time::Instant::now();
            mmp.receiver
                .record_recv(self.counter, timestamp, plaintext.len(), self.ce_flag, now);
            let inner_flags = FspInnerFlags::from_byte(inner_flags_byte);
            let _spin_rtt = mmp
                .spin_bit
                .rx_observe(inner_flags.spin_bit, self.counter, now);
            mmp.path_mtu.observe_incoming_mtu(self.path_mtu);
        }
        self.entry.touch_inbound_frame(self.now_ms);

        let Some(source_peer) = self.entry.remote_identity() else {
            return FspFrameOutcome::MissingRemoteIdentity;
        };

        FspFrameOutcome::Authentic(AuthenticatedSessionMessage::new(
            source_peer,
            plaintext,
            msg_type,
            inner_flags_byte,
            timestamp,
        ))
    }
}

impl crate::node::SessionRegistry {
    fn prepare_handshake_resend_after_early_encrypted_data(
        &mut self,
        source_addr: &NodeAddr,
        max_resends: u32,
    ) -> EarlyEncryptedHandshakeResend {
        let Some(entry) = self.get_mut(source_addr) else {
            return EarlyEncryptedHandshakeResend::NoPayload;
        };
        if entry.handshake_payload().is_none() {
            return EarlyEncryptedHandshakeResend::NoPayload;
        }
        if entry.resend_count() >= max_resends {
            entry.clear_handshake_payload();
            return EarlyEncryptedHandshakeResend::BudgetExhausted;
        }

        EarlyEncryptedHandshakeResend::Resend {
            payload: entry
                .handshake_payload()
                .expect("checked handshake payload above")
                .to_vec(),
        }
    }

    fn record_handshake_resend(&mut self, source_addr: &NodeAddr, next_resend_at_ms: u64) -> bool {
        let Some(entry) = self.get_mut(source_addr) else {
            return false;
        };
        entry.record_resend(next_resend_at_ms);
        true
    }

    fn abandon_rekey(&mut self, source_addr: &NodeAddr) -> bool {
        let Some(entry) = self.get_mut(source_addr) else {
            return false;
        };
        entry.abandon_rekey();
        true
    }

    fn install_initiating_session(
        &mut self,
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        handshake: HandshakeState,
        setup_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> Option<SessionEntry> {
        let mut entry = SessionEntry::new(
            remote_addr,
            remote_pubkey,
            EndToEndState::Initiating(handshake),
            now_ms,
            true,
        );
        entry.set_handshake_payload(setup_payload, now_ms + resend_interval_ms);
        self.insert(remote_addr, entry)
    }

    fn install_awaiting_msg3_session(
        &mut self,
        remote_addr: NodeAddr,
        placeholder_pubkey: PublicKey,
        handshake: HandshakeState,
        ack_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> Option<SessionEntry> {
        let mut entry = SessionEntry::new(
            remote_addr,
            placeholder_pubkey,
            EndToEndState::AwaitingMsg3(handshake),
            now_ms,
            false,
        );
        entry.set_handshake_payload(ack_payload, now_ms + resend_interval_ms);
        self.insert(remote_addr, entry)
    }

    fn install_established_initiator_session(
        &mut self,
        remote_addr: NodeAddr,
        mut entry: SessionEntry,
        session: NoiseSession,
        msg3_resend_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
        coords_warmup_packets: u8,
        mmp_config: &crate::config::SessionMmpConfig,
    ) -> Option<SessionEntry> {
        entry.set_state(EndToEndState::Established(session));
        entry.set_coords_warmup_remaining(coords_warmup_packets);
        entry.mark_established(now_ms);
        entry.init_mmp(mmp_config);
        entry.set_handshake_payload(msg3_resend_payload, now_ms + resend_interval_ms);
        entry.touch(now_ms);
        self.insert(remote_addr, entry)
    }

    fn install_established_responder_session(
        &mut self,
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        session: NoiseSession,
        now_ms: u64,
        coords_warmup_packets: u8,
        mmp_config: &crate::config::SessionMmpConfig,
    ) -> Option<SessionEntry> {
        let mut entry = SessionEntry::new(
            remote_addr,
            remote_pubkey,
            EndToEndState::Established(session),
            now_ms,
            false,
        );
        entry.set_coords_warmup_remaining(coords_warmup_packets);
        entry.mark_established(now_ms);
        entry.init_mmp(mmp_config);
        entry.touch(now_ms);
        self.insert(remote_addr, entry)
    }

    fn install_rekey_responder_awaiting_msg3(
        &mut self,
        remote_addr: &NodeAddr,
        handshake: HandshakeState,
        ack_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(remote_addr) else {
            return false;
        };
        entry.set_rekey_state(handshake, false);
        entry.set_handshake_payload(ack_payload, now_ms + resend_interval_ms);
        entry.record_peer_rekey(now_ms);
        true
    }

    fn install_rekey_initiator_pending_session(
        &mut self,
        remote_addr: NodeAddr,
        mut entry: SessionEntry,
        session: NoiseSession,
        msg3_resend_payload: Vec<u8>,
        now_ms: u64,
        resend_interval_ms: u64,
    ) -> Option<SessionEntry> {
        entry.set_pending_session(session);
        entry.set_rekey_completed_ms(now_ms);
        entry.clear_handshake_payload();
        entry.set_rekey_msg3_payload(msg3_resend_payload, now_ms + resend_interval_ms);
        self.insert(remote_addr, entry)
    }

    fn install_rekey_responder_pending_session(
        &mut self,
        remote_addr: NodeAddr,
        mut entry: SessionEntry,
        session: NoiseSession,
    ) -> Option<SessionEntry> {
        entry.set_pending_session(session);
        entry.clear_handshake_payload();
        self.insert(remote_addr, entry)
    }

    fn open_established_fsp_frame(
        &mut self,
        source_addr: &NodeAddr,
        receive: EstablishedFspReceive<'_>,
    ) -> FspFrameOutcome {
        let Some(entry) = self.get_mut(source_addr) else {
            return FspFrameOutcome::UnknownSession;
        };

        SessionRuntimeReceive::new(
            entry,
            receive.header,
            receive.ciphertext,
            receive.path_mtu,
            receive.ce_flag,
            receive.now_ms,
        )
        .open_established()
    }

    fn record_receive_completion(
        &mut self,
        completion: SessionReceiveCompletion,
        now_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(&completion.source_addr) else {
            return false;
        };
        entry.record_recv(completion.body_len);
        entry.touch(now_ms);
        true
    }

    fn process_session_receiver_report(
        &mut self,
        src_addr: &NodeAddr,
        rr: &ReceiverReport,
        now_ms: u64,
        now: std::time::Instant,
    ) -> Result<ProcessedSessionReceiverReport, SessionReceiverReportSkip> {
        let Some(entry) = self.get_mut(src_addr) else {
            return Err(SessionReceiverReportSkip::UnknownSession);
        };

        let our_timestamp_ms = entry.session_timestamp(now_ms);
        let last_outbound_next_hop = entry.last_outbound_next_hop();

        let Some(mmp) = entry.mmp_mut() else {
            return Err(SessionReceiverReportSkip::MmpDisabled);
        };

        mmp.metrics
            .process_receiver_report(rr, our_timestamp_ms, now);

        let srtt_ms = mmp.metrics.srtt_ms();
        if let Some(srtt_ms) = srtt_ms {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.receiver.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.path_mtu.update_interval_from_srtt(srtt_ms);
        }

        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

        Ok(ProcessedSessionReceiverReport {
            sample: mmp.metrics.last_forward_loss_sample(),
            used_direct_next_hop: last_outbound_next_hop == Some(*src_addr),
            srtt_ms,
            route_quality_sample: session_receiver_report_can_drive_route_quality(
                mmp.mode(),
                srtt_ms,
            ),
        })
    }

    fn apply_session_path_mtu_signal(
        &mut self,
        dest_addr: &NodeAddr,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<SessionPathMtuApplyResult, SessionPathMtuApplySkip> {
        let Some(entry) = self.get_mut(dest_addr) else {
            return Err(SessionPathMtuApplySkip::UnknownSession);
        };
        let Some(mmp) = entry.mmp_mut() else {
            return Err(SessionPathMtuApplySkip::MmpDisabled);
        };

        let old_mtu = mmp.path_mtu.current_mtu();
        if !mmp.path_mtu.apply_notification(path_mtu, now) {
            return Ok(SessionPathMtuApplyResult::Unchanged);
        }

        Ok(SessionPathMtuApplyResult::Changed(SessionPathMtuChange {
            old_mtu,
            new_mtu: mmp.path_mtu.current_mtu(),
        }))
    }

    fn route_error_can_send_coords_warmup(&self, dest_addr: &NodeAddr) -> bool {
        self.get(dest_addr)
            .is_some_and(|entry| entry.is_established())
    }

    fn reset_route_error_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
        warmup_packets: u8,
    ) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        entry.set_coords_warmup_remaining(warmup_packets);
        true
    }

    fn session_fsp_send_context(
        &self,
        dest_addr: &NodeAddr,
        now_ms: u64,
    ) -> Result<SessionFspSendContext, SessionFspSendContextError> {
        let Some(entry) = self.get(dest_addr) else {
            return Err(SessionFspSendContextError::NoSession);
        };
        if !entry.is_established() {
            return Err(SessionFspSendContextError::NotEstablished);
        }

        Ok(SessionFspSendContext {
            timestamp: entry.session_timestamp(now_ms),
            spin_bit: entry.mmp().is_some_and(|m| m.spin_bit.tx_bit()),
            current_k_bit: entry.current_k_bit(),
            coords_warmup_remaining: entry.coords_warmup_remaining(),
        })
    }

    fn consume_coords_warmup_packet(&mut self, dest_addr: &NodeAddr) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        let remaining = entry.coords_warmup_remaining();
        if remaining == 0 {
            return false;
        }
        entry.set_coords_warmup_remaining(remaining - 1);
        true
    }

    fn seal_session_fsp_send(
        &mut self,
        plan: SessionFspSendPlan<'_>,
    ) -> Result<SealedSessionFspSend, NodeError> {
        let dest_addr = plan.dest_addr();
        let Some(entry) = self.get_mut(&dest_addr) else {
            return Err(SessionFspSendContextError::NoSession.into_node_error(dest_addr));
        };
        let session = match entry.state_mut() {
            EndToEndState::Established(session) => session,
            _ => {
                return Err(SessionFspSendContextError::NotEstablished.into_node_error(dest_addr));
            }
        };
        plan.seal(session)
    }

    fn seed_session_datagram_path_mtu(&mut self, dest_addr: &NodeAddr, path_mtu: u16) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        let Some(mmp) = entry.mmp_mut() else {
            return false;
        };
        mmp.path_mtu.seed_source_mtu(path_mtu);
        true
    }

    fn record_session_datagram_next_hop(
        &mut self,
        dest_addr: &NodeAddr,
        next_hop_addr: NodeAddr,
    ) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        entry.record_outbound_next_hop(next_hop_addr);
        true
    }

    fn should_skip_session_initiation(&self, dest_addr: &NodeAddr) -> bool {
        self.get(dest_addr)
            .is_some_and(|entry| entry.is_established() || entry.is_initiating())
    }

    fn outbound_session_state(&self, dest_addr: &NodeAddr) -> OutboundSessionState {
        let Some(entry) = self.get(dest_addr) else {
            return OutboundSessionState::Missing;
        };
        if entry.is_established() {
            OutboundSessionState::Established
        } else {
            OutboundSessionState::Pending
        }
    }

    fn tun_outbound_session_decision(
        &self,
        dest_addr: &NodeAddr,
        effective_mtu: usize,
        packet_len: usize,
    ) -> TunOutboundSessionDecision {
        let Some(entry) = self.get(dest_addr) else {
            return TunOutboundSessionDecision::Missing;
        };
        if !entry.is_established() {
            return TunOutboundSessionDecision::Pending;
        }

        if let Some(mmp) = entry.mmp() {
            let path_mtu = mmp.path_mtu.current_mtu();
            let path_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as usize;
            if path_ipv6_mtu < effective_mtu && packet_len > path_ipv6_mtu {
                return TunOutboundSessionDecision::EstablishedPathMtuExceeded {
                    path_ipv6_mtu: path_ipv6_mtu as u32,
                };
            }
        }

        TunOutboundSessionDecision::Established
    }

    fn prepare_retry_session_after_discovery(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> DiscoveryRetrySessionDecision {
        let Some(existing) = self.get(dest_addr) else {
            return DiscoveryRetrySessionDecision::Missing;
        };
        if existing.is_established() {
            return DiscoveryRetrySessionDecision::Established;
        }

        self.remove(dest_addr);
        DiscoveryRetrySessionDecision::RestartedPending
    }
}

impl Node {
    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches based on the 4-byte FSP common prefix:
    ///
    /// - Phase 0x1 → SessionSetup (handshake msg1)
    /// - Phase 0x2 → SessionAck (handshake msg2)
    /// - Phase 0x3 → SessionMsg3 (XK handshake msg3)
    /// - Phase 0x0 + U flag → plaintext error signal (CoordsRequired/PathBroken)
    /// - Phase 0x0 + !U → encrypted session message (data, reports, etc.)
    pub(in crate::node) async fn handle_session_payload(
        &mut self,
        delivery: LocalSessionPayload<'_>,
    ) {
        let src_addr = *delivery.source_addr();
        let payload = delivery.payload();
        let prefix = match FspCommonPrefix::parse(payload) {
            Some(p) => p,
            None => {
                debug!(
                    len = payload.len(),
                    "Session payload too short for FSP prefix"
                );
                return;
            }
        };

        let inner = &payload[FSP_COMMON_PREFIX_SIZE..];

        match prefix.phase {
            FSP_PHASE_MSG1 => {
                self.handle_session_setup(&src_addr, inner).await;
            }
            FSP_PHASE_MSG2 => {
                self.handle_session_ack(&src_addr, inner).await;
            }
            FSP_PHASE_MSG3 => {
                self.handle_session_msg3(&src_addr, inner).await;
            }
            FSP_PHASE_ESTABLISHED if prefix.is_unencrypted() => {
                // Plaintext error signals: read msg_type from first byte after prefix
                if inner.is_empty() {
                    debug!("Empty plaintext error signal");
                    return;
                }
                let error_type = inner[0];
                let error_body = &inner[1..];
                match SessionMessageType::from_byte(error_type) {
                    Some(SessionMessageType::CoordsRequired) => {
                        self.handle_coords_required(error_body).await;
                    }
                    Some(SessionMessageType::PathBroken) => {
                        self.handle_path_broken(error_body).await;
                    }
                    Some(SessionMessageType::MtuExceeded) => {
                        self.handle_mtu_exceeded(error_body).await;
                    }
                    _ => {
                        debug!(error_type, "Unknown plaintext error signal type");
                    }
                }
            }
            FSP_PHASE_ESTABLISHED => {
                self.handle_encrypted_session_msg(delivery.into_encrypted())
                    .await;
            }
            _ => {
                debug!(phase = prefix.phase, "Unknown FSP phase");
            }
        }
    }

    /// Handle an encrypted session message (phase 0x0, U flag clear).
    ///
    /// Full FSP receive pipeline:
    /// 1. Parse FspEncryptedHeader (12 bytes) → counter, flags, header_bytes
    /// 2. If CP flag: parse cleartext coords, cache them
    /// 3. Session lookup (must be Established)
    /// 4. AEAD decrypt with AAD = header_bytes
    /// 5. Strip FSP inner header → timestamp, msg_type, inner_flags
    /// 6. Dispatch by msg_type
    async fn handle_encrypted_session_msg(&mut self, delivery: EncryptedSessionPayload<'_>) {
        let _t_fsp_handle =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspHandle);
        let src_addr = delivery.source_addr();
        let payload = delivery.payload();
        let mut wire = match EstablishedFspWire::parse(payload, *src_addr, *self.node_addr()) {
            Ok(wire) => wire,
            Err(EstablishedFspWireError::BadHeader) => {
                debug!(
                    len = payload.len(),
                    "Encrypted session message too short for FSP header"
                );
                return;
            }
            Err(EstablishedFspWireError::BadCoords(e)) => {
                debug!(error = %e, "Failed to parse coords from encrypted session message");
                return;
            }
        };

        if wire.has_coord_warmup() {
            wire.apply_coord_warmup(&mut self.coord_cache, Self::now_ms());
        }

        // The session registry owns the mutable lookup plus FSP open/replay,
        // K-bit handling, failure accounting, MMP receive bookkeeping, and
        // dispatch metadata. The rx loop supplies the parsed wire facts but no
        // longer peeks into the session map directly on this hot edge.
        let outcome = self.sessions.open_established_fsp_frame(
            src_addr,
            wire.receive(delivery.path_mtu(), delivery.ce_flag(), Self::now_ms()),
        );

        // The &mut entry borrow on self.sessions has dropped. Handle
        // slow-path outcomes and dispatch by msg_type (which calls
        // other &mut self handlers).
        let session_message = match outcome {
            FspFrameOutcome::Authentic(session_message) => session_message,
            FspFrameOutcome::UnknownSession => {
                debug!(src = %self.peer_display_name(src_addr), "Encrypted session message for unknown session");
                return;
            }
            FspFrameOutcome::NotEstablished => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Encrypted message but session not established (awaiting handshake completion)"
                );
                self.resend_handshake_after_early_encrypted_data(src_addr)
                    .await;
                return;
            }
            FspFrameOutcome::BadInnerHeader => {
                debug!(src = %self.peer_display_name(src_addr), "Decrypted payload too short for FSP inner header");
                return;
            }
            FspFrameOutcome::MissingRemoteIdentity => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Established session missing authenticated remote identity"
                );
                return;
            }
            FspFrameOutcome::DecryptFailed {
                error,
                counter,
                consecutive,
                recover_session,
            } => {
                debug!(
                    error = %error, src = %self.peer_display_name(src_addr),
                    counter, consecutive_failures = consecutive,
                    "Session AEAD decryption failed"
                );
                if recover_session {
                    warn!(
                        peer = %self.peer_display_name(src_addr),
                        consecutive_failures = consecutive,
                        "Session AEAD failures exceeded threshold; starting recovery rekey"
                    );
                    if !self.initiate_session_rekey(src_addr).await {
                        debug!(
                            peer = %self.peer_display_name(src_addr),
                            "Failed to start recovery rekey after decrypt-failure threshold"
                        );
                    }
                }
                return;
            }
            FspFrameOutcome::StaleEpochDrainFailure { counter } => {
                trace!(
                    src = %self.peer_display_name(src_addr),
                    counter,
                    "Ignoring stale FSP packet from previous key epoch during drain"
                );
                return;
            }
        };
        self.register_decrypt_worker_fsp_session(src_addr);
        let dispatch = AuthenticatedSessionDispatch::new(
            *src_addr,
            *delivery.previous_hop_addr(),
            delivery.ce_flag(),
            session_message,
        );
        if dispatch.is_endpoint_data() {
            let finish = dispatch.dispatch_endpoint_data_fast(self);
            if let Some(dest_addr) = finish.pending_flush_dest() {
                self.flush_pending_packets(&dest_addr).await;
            }
            return;
        }
        dispatch.dispatch(self).await;
    }

    fn record_worker_authenticated_fmp_receive(
        &mut self,
        fmp: &crate::node::decrypt_worker::DecryptFmpBookkeeping,
    ) {
        let now = Instant::now();
        let path_bookkeeping_allowed = self.authenticated_packet_path_allows_bookkeeping(
            fmp.source_peer.node_addr(),
            fmp.transport_id,
            &fmp.remote_addr,
            fmp.packet_timestamp_ms,
        );
        let bookkeeping = self.peers.record_authenticated_fmp_receive(
            fmp.source_peer.node_addr(),
            fmp.transport_id,
            &fmp.remote_addr,
            fmp.packet_timestamp_ms,
            fmp.packet_len,
            fmp.fmp_counter,
            fmp.inner_timestamp_ms,
            fmp.fmp_flags & FLAG_CE != 0,
            fmp.fmp_flags & FLAG_SP != 0,
            now,
            path_bookkeeping_allowed,
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if bookkeeping.is_some_and(|update| update.address_changed) {
            self.clear_connected_udp_for_peer(fmp.source_peer.node_addr());
        }
    }

    pub(in crate::node) async fn process_authenticated_session_from_worker(
        &mut self,
        authenticated: DecryptAuthenticatedSession,
    ) {
        let now = Instant::now();
        self.record_worker_authenticated_fmp_receive(&authenticated.fmp);

        let source_addr = authenticated.source_addr;
        let receive_applied = self.sessions.get_mut(&source_addr).is_some_and(|entry| {
            entry.apply_fsp_receive_sync(authenticated.receive_sync, Self::now_ms(), now)
        });
        if !receive_applied {
            debug!(
                src = %self.peer_display_name(&source_addr),
                "Dropping worker-authenticated session message for missing or stale session"
            );
            return;
        }

        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            *authenticated.previous_hop_peer.node_addr(),
            authenticated.ce_flag,
            authenticated.message,
        );
        if dispatch.is_endpoint_data() {
            let finish = dispatch.dispatch_endpoint_data_fast(self);
            if let Some(dest_addr) = finish.pending_flush_dest() {
                self.flush_pending_packets(&dest_addr).await;
            }
            return;
        }
        dispatch.dispatch(self).await;
    }

    pub(in crate::node) async fn process_direct_session_data_from_worker(
        &mut self,
        direct: DecryptDirectSessionData,
    ) {
        let Some(finish) = self.commit_direct_session_data_from_worker(
            &direct.fmp,
            direct.source_addr,
            direct.previous_hop_peer,
            direct.receive_sync,
            direct.body_len,
        ) else {
            return;
        };

        let source_addr = direct.source_addr;
        match direct.delivery {
            DecryptDirectSessionDelivery::Ipv6Packet(mut packet) => {
                if direct.ce_flag {
                    mark_ipv6_ecn_ce(&mut packet);
                    self.stats_mut().congestion.record_ce_received();
                }
                if self.external_packet_tx.is_some() {
                    self.deliver_external_ipv6_packet(&source_addr, packet);
                } else if let Some(tun_tx) = &self.tun_tx {
                    let _t =
                        crate::perf_profile::Timer::start(crate::perf_profile::Stage::TunWrite);
                    if let Err(error) = tun_tx.send(packet) {
                        debug!(error = %error, "Failed to deliver worker-decoded IPv6 packet to TUN");
                    }
                } else {
                    trace!(
                        src = %self.peer_display_name(&source_addr),
                        "Worker-decoded IPv6 packet ready (no TUN interface)"
                    );
                }
            }
            DecryptDirectSessionDelivery::EndpointData(delivery) => {
                self.deliver_endpoint_data(delivery);
            }
        }

        if let Some(dest_addr) = finish.pending_flush_dest() {
            self.flush_pending_packets(&dest_addr).await;
        }
    }

    pub(in crate::node) async fn process_direct_session_commit_from_worker(
        &mut self,
        commit: DecryptDirectSessionCommit,
    ) {
        let Some(finish) = self.commit_direct_session_data_from_worker(
            &commit.fmp,
            commit.source_addr,
            commit.previous_hop_peer,
            commit.receive_sync,
            commit.body_len,
        ) else {
            return;
        };

        if commit.ce_flag && commit.delivered_ipv6 {
            self.stats_mut().congestion.record_ce_received();
        }

        if let Some(dest_addr) = finish.pending_flush_dest() {
            self.flush_pending_packets(&dest_addr).await;
        }
    }

    fn commit_direct_session_data_from_worker(
        &mut self,
        fmp: &crate::node::decrypt_worker::DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        receive_sync: crate::node::session::FspReceiveSync,
        body_len: usize,
    ) -> Option<SessionDispatchFinish> {
        let now = Instant::now();
        self.record_worker_authenticated_fmp_receive(fmp);

        let receive_applied = self
            .sessions
            .get_mut(&source_addr)
            .is_some_and(|entry| entry.apply_fsp_receive_sync(receive_sync, Self::now_ms(), now));
        if !receive_applied {
            debug!(
                src = %self.peer_display_name(&source_addr),
                "Dropping worker-decoded direct session data for missing or stale session"
            );
            return None;
        }

        self.learn_reverse_route(source_addr, *previous_hop_peer.node_addr());
        let finish = SessionDispatchCommit {
            source_addr,
            receive_completion: Some(SessionReceiveCompletion {
                source_addr,
                body_len,
            }),
        }
        .finish_receive(self);

        Some(finish)
    }

    pub(in crate::node) async fn process_fsp_decrypt_failure_from_worker(
        &mut self,
        report: DecryptFspFailureReport,
    ) {
        self.record_worker_authenticated_fmp_receive(&report.fmp);
        let src_addr = report.source_addr;
        let Some(entry) = self.sessions.get_mut(&src_addr) else {
            debug!(
                src = %self.peer_display_name(&src_addr),
                counter = report.counter,
                "Worker FSP AEAD failure for unknown session"
            );
            return;
        };
        if should_ignore_stale_epoch_drain_failure(entry, report.received_k_bit) {
            trace!(
                src = %self.peer_display_name(&src_addr),
                counter = report.counter,
                "Ignoring worker FSP AEAD failure from stale previous key epoch during drain"
            );
            return;
        }
        let consecutive = entry.record_decrypt_failure();
        let recover_session = should_start_decrypt_failure_rekey(entry, consecutive);
        debug!(
            src = %self.peer_display_name(&src_addr),
            counter = report.counter,
            consecutive_failures = consecutive,
            "Worker FSP AEAD decryption failed"
        );
        if recover_session {
            warn!(
                peer = %self.peer_display_name(&src_addr),
                consecutive_failures = consecutive,
                "Session AEAD failures exceeded threshold; starting recovery rekey"
            );
            if !self.initiate_session_rekey(&src_addr).await {
                debug!(
                    peer = %self.peer_display_name(&src_addr),
                    "Failed to start recovery rekey after worker FSP decrypt-failure threshold"
                );
            }
        }
    }

    async fn handle_mesh_traversal_offer(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let Some(bootstrap) = self.nostr_discovery.clone() else {
            trace!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal offer without Nostr discovery runtime"
            );
            return;
        };
        if self.configured_peer(src_addr).is_none() {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal offer from unconfigured peer"
            );
            return;
        }
        let Some(sender_npub) = self.npub_for_node_addr(src_addr) else {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal offer without known sender npub"
            );
            return;
        };
        let offer = match serde_json::from_slice::<TraversalOffer>(body) {
            Ok(offer) => offer,
            Err(error) => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    error = %error,
                    "Malformed mesh traversal offer"
                );
                return;
            }
        };
        if offer.sender_npub != sender_npub {
            debug!(
                src = %self.peer_display_name(src_addr),
                claimed = %offer.sender_npub,
                actual = %sender_npub,
                "Ignoring mesh traversal offer with sender mismatch"
            );
            return;
        }
        bootstrap
            .receive_mesh_traversal_offer(offer, sender_npub)
            .await;
    }

    async fn handle_mesh_traversal_answer(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let Some(bootstrap) = self.nostr_discovery.clone() else {
            trace!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal answer without Nostr discovery runtime"
            );
            return;
        };
        if self.configured_peer(src_addr).is_none() {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal answer from unconfigured peer"
            );
            return;
        }
        let Some(sender_npub) = self.npub_for_node_addr(src_addr) else {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal answer without known sender npub"
            );
            return;
        };
        let answer = match serde_json::from_slice::<TraversalAnswer>(body) {
            Ok(answer) => answer,
            Err(error) => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    error = %error,
                    "Malformed mesh traversal answer"
                );
                return;
            }
        };
        if answer.sender_npub != sender_npub {
            debug!(
                src = %self.peer_display_name(src_addr),
                claimed = %answer.sender_npub,
                actual = %sender_npub,
                "Ignoring mesh traversal answer with sender mismatch"
            );
            return;
        }
        bootstrap
            .receive_mesh_traversal_answer(answer, sender_npub)
            .await;
    }

    /// Handle an incoming SessionSetup (Noise XK msg1).
    ///
    /// The remote node wants to establish an end-to-end session with us.
    /// We create an XK responder handshake, process msg1, send SessionAck with msg2,
    /// and transition to AwaitingMsg3.
    async fn handle_session_setup(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let setup = match SessionSetup::decode(inner) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Malformed SessionSetup");
                return;
            }
        };

        if setup.handshake_payload.len() != XK_HANDSHAKE_MSG1_SIZE {
            debug!(
                len = setup.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG1_SIZE,
                "Invalid handshake payload size in SessionSetup"
            );
            return;
        }

        // Check for existing session with this remote
        if let Some(existing) = self.sessions.get(src_addr) {
            if existing.is_initiating() {
                // Simultaneous initiation: smaller NodeAddr wins as initiator
                if self.identity.node_addr() < src_addr {
                    // We win — drop their setup, they'll process ours
                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "Simultaneous session initiation: we win (smaller addr), dropping their setup"
                    );
                    return;
                }
                // We lose — discard our pending handshake, become responder below
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Simultaneous session initiation: we lose, becoming responder"
                );
            } else if existing.is_awaiting_msg3() {
                // Duplicate setup while we already sent msg2 — resend stored ack
                if let Some(payload) = existing.handshake_payload() {
                    debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, resending SessionAck");
                    let my_addr = *self.node_addr();
                    let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload.to_vec())
                        .with_ttl(self.config.node.session.default_ttl);
                    if let Err(e) = self.send_session_datagram(&mut datagram).await {
                        debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to resend SessionAck");
                    }
                } else {
                    debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, no stored ack to resend");
                }
                return;
            } else if existing.is_established() {
                // Rekey: if rekey enabled, treat as rekey for key rotation.
                // The existing established session remains active for traffic.
                if self.config.node.rekey.enabled {
                    let rekey_in_progress = existing.has_rekey_in_progress();
                    let has_pending = existing.pending_new_session().is_some();

                    // Dual-initiation detection: both sides sent SessionSetup
                    // simultaneously. Apply tie-breaker — smaller NodeAddr
                    // wins as initiator (same as initial session setup).
                    if rekey_in_progress {
                        if let Some(payload) = duplicate_rekey_responder_ack(existing) {
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "Duplicate FSP rekey msg1, resending SessionAck"
                            );
                            let my_addr = *self.node_addr();
                            let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload)
                                .with_ttl(self.config.node.session.default_ttl);
                            let sent = match self.send_session_datagram(&mut datagram).await {
                                Ok(()) => true,
                                Err(e) => {
                                    debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to resend rekey SessionAck");
                                    false
                                }
                            };
                            if sent {
                                let now_ms = Self::now_ms();
                                let interval =
                                    self.config.node.rate_limit.handshake_resend_interval_ms;
                                self.sessions
                                    .record_handshake_resend(src_addr, now_ms + interval);
                            }
                            return;
                        }
                        if self.identity.node_addr() < src_addr {
                            // We win as initiator — drop their msg1.
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "Dual FSP rekey initiation: we win (smaller addr), dropping their msg1"
                            );
                            return;
                        }
                        // We lose — abandon our rekey, become responder below.
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            "Dual FSP rekey initiation: we lose (larger addr), abandoning ours"
                        );
                        self.sessions.abandon_rekey(src_addr);
                    } else if has_pending {
                        if pending_rekey_wins_tiebreak(
                            self.identity.node_addr(),
                            src_addr,
                            existing,
                        ) {
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "FSP rekey msg1 received while local pending rekey wins tiebreak, dropping"
                            );
                            return;
                        }

                        debug!(
                            src = %self.peer_display_name(src_addr),
                            local_pending_initiator = existing.is_rekey_initiator(),
                            "FSP rekey msg1 received with stale pending rekey, abandoning pending and responding"
                        );
                        self.sessions.abandon_rekey(src_addr);
                    }
                    let our_keypair = self.identity.keypair();
                    let mut handshake = HandshakeState::new_xk_responder(our_keypair);
                    handshake.set_local_epoch(self.startup_epoch);

                    if let Err(e) = handshake.read_xk_message_1(&setup.handshake_payload) {
                        debug!(error = %e, "Failed to process rekey XK msg1");
                        return;
                    }

                    // Generate msg2
                    let msg2 = match handshake.write_xk_message_2() {
                        Ok(m) => m,
                        Err(e) => {
                            debug!(error = %e, "Failed to generate rekey XK msg2");
                            return;
                        }
                    };

                    // Build and send SessionAck
                    let our_coords = self.tree_state.my_coords().clone();
                    let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
                    let ack_payload = ack.encode();
                    let my_addr = *self.node_addr();
                    let mut datagram =
                        SessionDatagram::new(my_addr, *src_addr, ack_payload.clone())
                            .with_ttl(self.config.node.session.default_ttl);

                    if let Err(e) = self.send_session_datagram(&mut datagram).await {
                        debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionAck");
                        return;
                    }

                    // Store rekey state on the existing entry
                    let now_ms = Self::now_ms();
                    let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
                    self.sessions.install_rekey_responder_awaiting_msg3(
                        src_addr,
                        handshake,
                        ack_payload,
                        now_ms,
                        resend_interval,
                    );

                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "FSP rekey: processed peer's msg1, sent msg2, awaiting msg3"
                    );
                    return;
                }

                // Re-establishment: replace existing session below
                debug!(src = %self.peer_display_name(src_addr), "Session re-establishment from peer");
            }
        }

        // Create XK responder handshake and process msg1
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_responder(our_keypair);
        handshake.set_local_epoch(self.startup_epoch);

        if let Err(e) = handshake.read_xk_message_1(&setup.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg1 in SessionSetup");
            return;
        }

        // XK: responder does NOT learn initiator's identity until msg3
        // Use a placeholder pubkey from src_addr for the session entry.
        // The real pubkey will be registered when msg3 arrives.

        // Generate msg2
        let msg2 = match handshake.write_xk_message_2() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XK msg2 for SessionAck");
                return;
            }
        };

        // Build and send SessionAck (include initiator's coords for return-path warming)
        let our_coords = self.tree_state.my_coords().clone();
        let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
        let ack_payload = ack.encode();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, ack_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route the ack back to the initiator
        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionAck");
            return;
        }

        // Store session entry in AwaitingMsg3 state with ack payload for potential resend.
        // Use a dummy pubkey since we don't know the initiator's identity yet.
        // We use our own pubkey as placeholder; it will be replaced in handle_session_msg3.
        let placeholder_pubkey = self.identity.keypair().public_key();
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        self.sessions.install_awaiting_msg3_session(
            *src_addr,
            placeholder_pubkey,
            handshake,
            ack_payload,
            now_ms,
            resend_interval,
        );

        debug!(src = %self.peer_display_name(src_addr), "SessionSetup processed (XK), SessionAck sent, awaiting msg3");
    }

    /// Handle an incoming SessionAck (Noise XK msg2).
    ///
    /// Processes msg2, generates and sends msg3, then transitions to Established.
    async fn handle_session_ack(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let ack = match SessionAck::decode(inner) {
            Ok(a) => a,
            Err(e) => {
                debug!(error = %e, "Malformed SessionAck");
                return;
            }
        };

        if ack.handshake_payload.len() != XK_HANDSHAKE_MSG2_SIZE {
            debug!(
                len = ack.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG2_SIZE,
                "Invalid handshake payload size in SessionAck"
            );
            return;
        }

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck for unknown session");
                return;
            }
        };

        // Rekey path: entry is Established with rekey_state
        if entry.is_established() && entry.has_rekey_in_progress() && entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XK msg2
            if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg2");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Generate XK msg3
            let msg3 = match handshake.write_xk_message_3() {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = %e, "Failed to generate rekey XK msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Send SessionMsg3
            let msg3_wire = SessionMsg3::new(msg3);
            let msg3_payload = msg3_wire.encode();
            let msg3_resend_payload = msg3_payload.clone();
            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
                .with_ttl(self.config.node.session.default_ttl);

            if let Err(e) = self.send_session_datagram(&mut datagram).await {
                debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionMsg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            let now_ms = Self::now_ms();
            let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
            self.sessions.install_rekey_initiator_pending_session(
                *src_addr,
                entry,
                session,
                msg3_resend_payload,
                now_ms,
                resend_interval,
            );
            self.register_decrypt_worker_fsp_session(src_addr);

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as initiator, pending cutover"
            );
            return;
        }

        if entry.is_established() {
            if let Some(payload) = entry.handshake_payload().map(<[u8]>::to_vec) {
                if entry.resend_count() < self.config.node.rate_limit.handshake_max_resends {
                    let my_addr = *self.node_addr();
                    let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload)
                        .with_ttl(self.config.node.session.default_ttl);
                    let sent = match self.send_session_datagram(&mut datagram).await {
                        Ok(()) => true,
                        Err(e) => {
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                error = %e,
                                "Failed to resend final SessionMsg3 after duplicate SessionAck"
                            );
                            false
                        }
                    };
                    if sent {
                        let now_ms = Self::now_ms();
                        let interval = self.config.node.rate_limit.handshake_resend_interval_ms;
                        entry.record_resend(now_ms + interval);
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            "Duplicate SessionAck after establishment, resent final SessionMsg3"
                        );
                    }
                } else {
                    entry.clear_handshake_payload();
                }
            } else {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck for already-established session");
            }
            self.sessions.insert(*src_addr, entry);
            return;
        }

        // Must be in Initiating state — check before take to avoid poisoning
        if !entry.is_initiating() {
            debug!(src = %self.peer_display_name(src_addr), "SessionAck but session not in Initiating state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::Initiating(hs)) => hs,
            _ => unreachable!("checked is_initiating above"),
        };

        // Process XK msg2: read_xk_message_2 (extracts responder's epoch)
        if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg2 in SessionAck");
            return; // Entry was already removed, don't put back a broken session
        }

        // Generate XK msg3: write_xk_message_3 (sends encrypted static + epoch)
        let msg3 = match handshake.write_xk_message_3() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XK msg3");
                return;
            }
        };

        // Send SessionMsg3 (phase 0x3)
        let msg3_wire = SessionMsg3::new(msg3);
        let msg3_payload = msg3_wire.encode();
        let msg3_resend_payload = msg3_payload.clone();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
            .with_ttl(self.config.node.session.default_ttl);

        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionMsg3");
            return;
        }

        // Complete the handshake: into_session()
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session after XK msg3");
                return;
            }
        };

        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        self.sessions.install_established_initiator_session(
            *src_addr,
            entry,
            session,
            msg3_resend_payload,
            now_ms,
            resend_interval,
            self.config.node.session.coords_warmup_packets,
            &self.config.node.session_mmp,
        );
        self.register_decrypt_worker_fsp_session(src_addr);
        self.coord_cache.insert(*src_addr, ack.src_coords, now_ms);

        // Flush any queued outbound packets for this destination
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (initiator, XK)");
    }

    async fn resend_handshake_after_early_encrypted_data(&mut self, src_addr: &NodeAddr) {
        let max_resends = self.config.node.rate_limit.handshake_max_resends;
        let payload = match self
            .sessions
            .prepare_handshake_resend_after_early_encrypted_data(src_addr, max_resends)
        {
            EarlyEncryptedHandshakeResend::Resend { payload } => payload,
            EarlyEncryptedHandshakeResend::BudgetExhausted => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Early encrypted data arrived after handshake resend budget was exhausted"
                );
                return;
            }
            EarlyEncryptedHandshakeResend::NoPayload => return,
        };

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload)
            .with_ttl(self.config.node.session.default_ttl);
        let sent = match self.send_session_datagram(&mut datagram).await {
            Ok(()) => true,
            Err(e) => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    error = %e,
                    "Failed to resend session handshake after early encrypted data"
                );
                false
            }
        };
        if sent {
            let now_ms = Self::now_ms();
            let interval = self.config.node.rate_limit.handshake_resend_interval_ms;
            self.sessions
                .record_handshake_resend(src_addr, now_ms + interval);
            debug!(
                src = %self.peer_display_name(src_addr),
                "Resent session handshake after early encrypted data"
            );
        }
    }

    /// Handle an incoming SessionMsg3 (Noise XK msg3).
    ///
    /// The initiator reveals their encrypted static key. The responder
    /// processes msg3, learns the initiator's identity, and transitions
    /// to Established.
    async fn handle_session_msg3(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let msg3 = match SessionMsg3::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed SessionMsg3");
                return;
            }
        };

        if msg3.handshake_payload.len() != XK_HANDSHAKE_MSG3_SIZE {
            debug!(
                len = msg3.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG3_SIZE,
                "Invalid handshake payload size in SessionMsg3"
            );
            return;
        }

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 for unknown session");
                return;
            }
        };

        // Rekey path: entry is Established with rekey_state (responder side)
        if entry.is_established() && entry.has_rekey_in_progress() && !entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XK msg3
            if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete the handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            self.sessions
                .install_rekey_responder_pending_session(*src_addr, entry, session);
            self.register_decrypt_worker_fsp_session(src_addr);

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as responder, pending cutover"
            );
            return;
        }

        // Must be in AwaitingMsg3 state
        if !entry.is_awaiting_msg3() {
            debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 but session not in AwaitingMsg3 state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::AwaitingMsg3(hs)) => hs,
            _ => unreachable!("checked is_awaiting_msg3 above"),
        };

        // Process XK msg3: read_xk_message_3 (extracts initiator's static key and epoch)
        if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg3");
            return; // Entry was already removed
        }

        // Extract the initiator's static public key (now available after msg3)
        let remote_pubkey = match handshake.remote_static() {
            Some(pk) => *pk,
            None => {
                debug!("No remote static key after processing XK msg3");
                return;
            }
        };

        // Register the initiator's identity for future TUN → session routing
        self.register_identity(*src_addr, remote_pubkey);

        // Complete the handshake
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session from XK handshake");
                return;
            }
        };

        let now_ms = Self::now_ms();
        // Replace the placeholder pubkey with the real one
        self.sessions.install_established_responder_session(
            *src_addr,
            remote_pubkey,
            session,
            now_ms,
            self.config.node.session.coords_warmup_packets,
            &self.config.node.session_mmp,
        );
        self.register_decrypt_worker_fsp_session(src_addr);

        // Flush any pending packets
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (responder, XK)");
    }

    // === Session-layer MMP report handlers ===

    /// Handle an incoming session-layer SenderReport (msg_type 0x11).
    ///
    /// Informational only — the peer is telling us about what they sent.
    /// Logged but not used for metrics (same pattern as link-layer).
    fn handle_session_sender_report(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let sr = match SessionSenderReport::decode(body) {
            Ok(sr) => sr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionSenderReport");
                return;
            }
        };

        trace!(
            src = %self.peer_display_name(src_addr),
            cum_pkts = sr.cumulative_packets_sent,
            interval_bytes = sr.interval_bytes_sent,
            "Received SessionSenderReport"
        );
    }

    /// Handle an incoming session-layer ReceiverReport (msg_type 0x12).
    ///
    /// The peer is telling us about what they received from us. We feed
    /// this to our metrics to compute RTT, loss rate, and trend indicators.
    pub(in crate::node) async fn handle_session_receiver_report(
        &mut self,
        src_addr: &NodeAddr,
        body: &[u8],
    ) {
        let session_rr = match SessionReceiverReport::decode(body) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionReceiverReport");
                return;
            }
        };

        // Convert to link-layer ReceiverReport for MmpMetrics processing
        let rr: ReceiverReport = ReceiverReport::from(&session_rr);

        let now_ms = Self::now_ms();
        let peer_name = self.peer_display_name(src_addr);
        let processed = match self.sessions.process_session_receiver_report(
            src_addr,
            &rr,
            now_ms,
            std::time::Instant::now(),
        ) {
            Ok(processed) => processed,
            Err(SessionReceiverReportSkip::UnknownSession) => {
                debug!(src = %peer_name, "SessionReceiverReport for unknown session");
                return;
            }
            Err(SessionReceiverReportSkip::MmpDisabled) => return,
        };

        if let Some((span, loss)) = processed.sample
            && processed.used_direct_next_hop
            && processed.route_quality_sample
            && span >= SESSION_DIRECT_DEGRADED_MIN_SAMPLE
        {
            if loss >= SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD
                && self.peers.get(src_addr).is_some_and(|peer| peer.can_send())
            {
                let newly_degraded = self.mark_session_direct_path_degraded(*src_addr, now_ms);
                if newly_degraded || !self.retry_pending.contains_key(src_addr) {
                    self.schedule_link_dead_reprobe(*src_addr, now_ms);
                }
                debug!(
                    src = %peer_name,
                    loss = format_args!("{:.1}%", loss * 100.0),
                    sample_packets = span,
                    newly_degraded,
                    "Session loss marked direct path degraded; fallback routing may carry traffic while direct probes continue"
                );
                self.maybe_initiate_link_dead_fallback_lookup(src_addr)
                    .await;
            } else if loss <= SESSION_DIRECT_RECOVERY_LOSS_THRESHOLD
                && self.clear_session_direct_path_degraded(src_addr)
            {
                debug!(
                    src = %peer_name,
                    loss = format_args!("{:.1}%", loss * 100.0),
                    sample_packets = span,
                    "Session loss recovered; direct path eligible for normal routing"
                );
            }
        }

        trace!(
            src = %peer_name,
            rtt_ms = ?processed.srtt_ms,
            route_quality_sample = processed.route_quality_sample,
            loss = processed.sample
                .map(|(_, loss)| format!("{:.1}%", loss * 100.0))
                .unwrap_or_else(|| "n/a".to_string()),
            "Processed SessionReceiverReport"
        );
    }

    /// Handle an incoming PathMtuNotification (msg_type 0x13).
    ///
    /// The destination is telling us the path MTU has changed.
    /// Apply source-side rules (decrease immediate, increase validated).
    pub(in crate::node) fn handle_session_path_mtu_notification(
        &mut self,
        src_addr: &NodeAddr,
        body: &[u8],
    ) {
        let notif = match PathMtuNotification::decode(body) {
            Ok(n) => n,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed PathMtuNotification");
                return;
            }
        };

        let peer_name = self.peer_display_name(src_addr);
        let change = match self.sessions.apply_session_path_mtu_signal(
            src_addr,
            notif.path_mtu,
            std::time::Instant::now(),
        ) {
            Ok(SessionPathMtuApplyResult::Changed(change)) => change,
            Ok(SessionPathMtuApplyResult::Unchanged) => return,
            Err(SessionPathMtuApplySkip::UnknownSession) => {
                debug!(src = %peer_name, "PathMtuNotification for unknown session");
                return;
            }
            Err(SessionPathMtuApplySkip::MmpDisabled) => return,
        };

        debug!(
            src = %peer_name,
            old_mtu = change.old_mtu,
            new_mtu = change.new_mtu,
            "Path MTU changed via notification"
        );

        // Mirror the new effective MTU into the FipsAddress-keyed lookup used
        // by the TUN reader/writer at TCP MSS clamp time. Without this, new
        // TCP flows opened on a path the proactive end-to-end echo has
        // already tightened keep getting clamped by the staler discovery-
        // time value until a reactive MtuExceeded happens to fire. Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(src_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= change.new_mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu = change.new_mtu,
                        existing,
                        "PathMtuNotification: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, change.new_mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu = change.new_mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "PathMtuNotification: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    new_mtu = change.new_mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; PathMtuNotification not reflected"
                );
            }
        }
    }

    /// Handle a CoordsRequired error signal from a transit router.
    ///
    /// The router couldn't route our packet because it lacks cached
    /// coordinates for the destination. Send a standalone CoordsWarmup
    /// immediately (rate-limited), trigger discovery, and reset the
    /// warmup counter for subsequent data packets.
    async fn handle_coords_required(&mut self, inner: &[u8]) {
        self.stats_mut().errors.coords_required += 1;

        let msg = match CoordsRequired::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed CoordsRequired");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "CoordsRequired: transit router needs coordinates"
        );

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
            if self
                .sessions
                .route_error_can_send_coords_warmup(&msg.dest_addr)
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to CoordsRequired");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "CoordsRequired response rate-limited, skipping standalone CoordsWarmup");
        }

        // Only trigger discovery if we have the target's identity cached —
        // otherwise we can't verify the LookupResponse proof.
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after CoordsRequired: no cached identity for target");
        }

        // Reset coords warmup counter so the next N packets also include
        // COORDS_PRESENT, re-warming transit caches along the path.
        let n = self.config.node.session.coords_warmup_packets;
        if self
            .sessions
            .reset_route_error_coords_warmup(&msg.dest_addr, n)
        {
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after CoordsRequired"
            );
        }
    }

    /// Handle a PathBroken error signal from a transit router.
    ///
    /// The router has coordinates but still can't route to the destination.
    /// Send a standalone CoordsWarmup immediately (rate-limited), invalidate
    /// cached coordinates, trigger re-discovery, and reset the warmup counter.
    async fn handle_path_broken(&mut self, inner: &[u8]) {
        self.stats_mut().errors.path_broken += 1;

        let msg = match PathBroken::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed PathBroken");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "PathBroken: transit router reports routing failure"
        );

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
            if self
                .sessions
                .route_error_can_send_coords_warmup(&msg.dest_addr)
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to PathBroken");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "PathBroken response rate-limited, skipping standalone CoordsWarmup");
        }

        // Invalidate stale cached coordinates
        self.coord_cache.remove(&msg.dest_addr);

        // Trigger re-discovery to get fresh coordinates, but only if we have
        // the target's identity cached — otherwise we can't verify the
        // LookupResponse proof. This avoids a race when the XK responder
        // receives PathBroken before msg3 completes (identity unknown).
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after PathBroken: no cached identity for target");
        }

        // Reset coords warmup counter so the next N packets include
        // COORDS_PRESENT, re-warming transit caches along the new path.
        let n = self.config.node.session.coords_warmup_packets;
        if self
            .sessions
            .reset_route_error_coords_warmup(&msg.dest_addr, n)
        {
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after PathBroken"
            );
        }
    }

    /// Handle an MtuExceeded error signal from a transit router.
    ///
    /// A transit router couldn't forward our packet because it exceeded the
    /// next-hop transport MTU. Apply the reported bottleneck MTU to our
    /// PathMtuState for the affected session, causing an immediate decrease.
    pub(in crate::node) async fn handle_mtu_exceeded(&mut self, inner: &[u8]) {
        self.stats_mut().errors.mtu_exceeded += 1;

        let msg = match MtuExceeded::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed MtuExceeded");
                return;
            }
        };

        let peer_name = self.peer_display_name(&msg.dest_addr);
        debug!(
            dest = %peer_name,
            reporter = %msg.reporter,
            bottleneck_mtu = msg.mtu,
            "MtuExceeded: transit router reports oversized packet"
        );

        // Apply to PathMtuState: immediate decrease via apply_notification()
        match self.sessions.apply_session_path_mtu_signal(
            &msg.dest_addr,
            msg.mtu,
            std::time::Instant::now(),
        ) {
            Ok(SessionPathMtuApplyResult::Changed(change)) => {
                info!(
                    dest = %peer_name,
                    old_mtu = change.old_mtu,
                    new_mtu = change.new_mtu,
                    reporter = %msg.reporter,
                    "Path MTU decreased via reactive MtuExceeded signal"
                );
            }
            Ok(SessionPathMtuApplyResult::Unchanged)
            | Err(SessionPathMtuApplySkip::UnknownSession)
            | Err(SessionPathMtuApplySkip::MmpDisabled) => {}
        }

        // Mirror the bottleneck into the FipsAddress-keyed lookup used by
        // the TUN reader/writer at TCP MSS clamp time. Discovery's reverse-
        // path response can carry a value too generous for the actual
        // forward path; the reactive signal from a forwarder that actually
        // dropped a packet is authoritative for "what fits". Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(&msg.dest_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= msg.mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        existing,
                        "Reactive MtuExceeded: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, msg.mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "Reactive MtuExceeded: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    bottleneck_mtu = msg.mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; reactive MtuExceeded not reflected"
                );
            }
        }
    }

    // === Session Initiation (Send Path) ===

    /// Initiate an end-to-end session with a remote node.
    ///
    /// Creates a Noise XK handshake as initiator, wraps msg1 in a
    /// SessionSetup, encapsulates in a SessionDatagram, and routes
    /// toward the destination.
    pub(in crate::node) async fn initiate_session(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
    ) -> Result<(), NodeError> {
        if self.sessions.should_skip_session_initiation(&dest_addr) {
            return Ok(());
        }

        // Create Noise XK initiator handshake
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_initiator(our_keypair, dest_pubkey);
        handshake.set_local_epoch(self.startup_epoch);
        let msg1 = handshake
            .write_xk_message_1()
            .map_err(|e| NodeError::SendFailed {
                node_addr: dest_addr,
                reason: format!("Noise XK msg1 generation failed: {}", e),
            })?;

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(&dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
        let setup_payload = setup.encode();

        // Wrap in SessionDatagram
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, dest_addr, setup_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route toward destination
        self.send_session_datagram(&mut datagram).await?;

        // Register destination identity for TUN → session routing
        self.register_identity(dest_addr, dest_pubkey);

        // Store session entry with handshake payload for potential resend
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        self.sessions.install_initiating_session(
            dest_addr,
            dest_pubkey,
            handshake,
            setup_payload,
            now_ms,
            resend_interval,
        );

        debug!(dest = %self.peer_display_name(&dest_addr), "Session initiation started");
        Ok(())
    }

    /// Send application data over an established session.
    ///
    /// Uses the FSP pipeline: builds a 12-byte cleartext header (used as AAD),
    /// prepends the 6-byte inner header to the plaintext, encrypts with AAD,
    /// optionally inserts cleartext coords, and wraps in a SessionDatagram.
    ///
    /// The `src_port` and `dst_port` identify the service. A 4-byte port header
    /// `[src_port:2 LE][dst_port:2 LE]` is prepended to `payload` inside the
    /// AEAD envelope. The receiver dispatches by `dst_port`.
    pub(in crate::node) async fn send_session_data(
        &mut self,
        dest_addr: &NodeAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let wants_coords = send_context.wants_coords();
        let timestamp = send_context.timestamp;

        // Build port-prefixed plaintext: [src_port:2 LE][dst_port:2 LE][payload...]
        let mut port_payload = Vec::with_capacity(FSP_PORT_HEADER_SIZE + payload.len());
        port_payload.extend_from_slice(&src_port.to_le_bytes());
        port_payload.extend_from_slice(&dst_port.to_le_bytes());
        port_payload.extend_from_slice(payload);

        // Build inner plaintext (doesn't depend on counter)
        let msg_type = SessionMessageType::DataPacket.to_byte(); // 0x10
        let inner_flags = send_context.inner_flags_byte();
        let inner_plaintext =
            fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &port_payload);

        // Determine whether coords fit within transport MTU.
        // If not, send standalone CoordsWarmup before the data packet.
        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire =
                FIPS_OVERHEAD as usize + FSP_PORT_HEADER_SIZE + coords_size + payload.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                // Coords don't fit piggybacked — send standalone CoordsWarmup first
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before data packet");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        // Consume one warmup opportunity for either piggybacked coords or the
        // standalone warmup attempt, preserving the previous retry behavior.
        if wants_coords {
            self.sessions.consume_coords_warmup_packet(dest_addr);
        }

        // Build FSP flags (CP flag if coords, K-bit for key epoch)
        let flags = send_context.fsp_flags(include_coords);

        let coords = my_coords.as_ref().zip(dest_coords.as_ref());
        self.send_session_fsp_plan(SessionFspSendPlan::new(
            *dest_addr,
            timestamp,
            flags,
            &inner_plaintext,
            coords,
            SessionFspSendBookkeeping::Data {
                payload_len: payload.len(),
                now_ms,
            },
        ))
        .await
    }

    async fn send_session_fsp_plan(
        &mut self,
        plan: SessionFspSendPlan<'_>,
    ) -> Result<(), NodeError> {
        let dest_addr = plan.dest_addr();
        let sealed = self.sessions.seal_session_fsp_send(plan)?;
        let (mut datagram, bookkeeping) =
            sealed.into_datagram(*self.node_addr(), self.config.node.session.default_ttl);
        self.send_session_datagram(&mut datagram).await?;

        let _ = self
            .sessions
            .record_fsp_send_bookkeeping(&dest_addr, bookkeeping);
        Ok(())
    }

    /// Send an IPv6 packet through the IPv6 shim (port 256) with header compression.
    ///
    /// Compresses the IPv6 header (format 0x00), then sends via `send_session_data`
    /// with `src_port=256, dst_port=256`.
    pub(in crate::node) async fn send_ipv6_packet(
        &mut self,
        dest_addr: &NodeAddr,
        ipv6_packet: &[u8],
    ) -> Result<(), NodeError> {
        let compressed = crate::upper::ipv6_shim::compress_ipv6(ipv6_packet).ok_or_else(|| {
            NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "IPv6 header compression failed".into(),
            }
        })?;
        self.send_session_data(
            dest_addr,
            FSP_PORT_IPV6_SHIM,
            FSP_PORT_IPV6_SHIM,
            &compressed,
        )
        .await
    }

    /// Handle an embedded endpoint data command.
    pub(in crate::node) async fn handle_endpoint_data_command(
        &mut self,
        command: NodeEndpointCommand,
    ) {
        match command {
            NodeEndpointCommand::Send {
                command,
                response_tx,
            } => {
                let result = self.handle_endpoint_send_command(command).await;
                let _ = response_tx.send(result);
            }
            NodeEndpointCommand::SendOneway { command } => {
                // Result deliberately discarded — caller wanted
                // fire-and-forget. Errors still get logged inside
                // `send_endpoint_data` so they're not silent.
                let _ = self.handle_endpoint_send_command(command).await;
            }
            NodeEndpointCommand::SendBatchOneway { command, .. } => {
                self.handle_endpoint_send_batch_command(command).await;
            }
            NodeEndpointCommand::UpdatePeers { peers, response_tx } => {
                let result = self.update_peers(peers).await;
                let _ = response_tx.send(result);
            }
            NodeEndpointCommand::PeerSnapshot { response_tx } => {
                let nostr_failure_state: std::collections::HashMap<String, _> = self
                    .nostr_discovery_handle()
                    .map(|discovery| {
                        discovery
                            .failure_state_snapshot()
                            .into_iter()
                            .map(|state| (state.npub.clone(), state))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut peers = self
                    .peers()
                    .map(|peer| {
                        let link_id = peer.link_id();
                        let retry_state = self.retry_pending.get(peer.node_addr());
                        let npub = peer.npub();
                        let nostr_state = nostr_failure_state.get(&npub);
                        let nostr_traversal_cooldown_until_ms =
                            nostr_state.and_then(|state| state.cooldown_until_ms);
                        let transport_type = self.get_link(&link_id).and_then(|link| {
                            self.get_transport(&link.transport_id())
                                .map(|handle| handle.transport_type().name.to_string())
                        });
                        let stats = peer.link_stats();
                        let direct_probe_pending = retry_state.is_some();
                        NodeEndpointPeer {
                            npub,
                            node_addr: *peer.node_addr(),
                            connected: true,
                            transport_addr: peer.current_addr().map(|addr| addr.to_string()),
                            transport_type,
                            link_id: link_id.as_u64(),
                            srtt_ms: peer
                                .mmp()
                                .and_then(|mmp| mmp.metrics.srtt_ms())
                                .map(|srtt| srtt.round() as u64),
                            packets_sent: stats.packets_sent,
                            packets_recv: stats.packets_recv,
                            bytes_sent: stats.bytes_sent,
                            bytes_recv: stats.bytes_recv,
                            rekey_in_progress: peer.rekey_in_progress(),
                            rekey_draining: peer.is_draining(),
                            current_k_bit: Some(peer.current_k_bit()),
                            direct_probe_pending,
                            direct_probe_after_ms: retry_state.map(|state| state.retry_after_ms),
                            direct_probe_retry_count: retry_state
                                .map_or(0, |state| state.retry_count),
                            direct_probe_auto_reconnect: retry_state
                                .is_some_and(|state| state.reconnect),
                            direct_probe_expires_at_ms: retry_state
                                .and_then(|state| state.expires_at_ms),
                            nostr_traversal_consecutive_failures: nostr_state
                                .map_or(0, |state| state.consecutive_failures),
                            nostr_traversal_in_cooldown: nostr_traversal_cooldown_until_ms
                                .is_some(),
                            nostr_traversal_cooldown_until_ms,
                            nostr_traversal_last_observed_skew_ms: nostr_state
                                .and_then(|state| state.last_observed_skew_ms),
                        }
                    })
                    .collect::<Vec<_>>();

                for (node_addr, retry_state) in self.retry_pending.iter() {
                    if self.peers.contains_key(node_addr)
                        || !self
                            .config
                            .peers
                            .iter()
                            .any(|peer| peer.npub == retry_state.peer_config.npub)
                    {
                        continue;
                    }

                    let npub = retry_state.peer_config.npub.clone();
                    let nostr_state = nostr_failure_state.get(&npub);
                    let nostr_traversal_cooldown_until_ms =
                        nostr_state.and_then(|state| state.cooldown_until_ms);
                    peers.push(NodeEndpointPeer {
                        npub,
                        node_addr: *node_addr,
                        connected: false,
                        transport_addr: None,
                        transport_type: None,
                        link_id: 0,
                        srtt_ms: None,
                        packets_sent: 0,
                        packets_recv: 0,
                        bytes_sent: 0,
                        bytes_recv: 0,
                        rekey_in_progress: false,
                        rekey_draining: false,
                        current_k_bit: None,
                        direct_probe_pending: true,
                        direct_probe_after_ms: Some(retry_state.retry_after_ms),
                        direct_probe_retry_count: retry_state.retry_count,
                        direct_probe_auto_reconnect: retry_state.reconnect,
                        direct_probe_expires_at_ms: retry_state.expires_at_ms,
                        nostr_traversal_consecutive_failures: nostr_state
                            .map_or(0, |state| state.consecutive_failures),
                        nostr_traversal_in_cooldown: nostr_traversal_cooldown_until_ms.is_some(),
                        nostr_traversal_cooldown_until_ms,
                        nostr_traversal_last_observed_skew_ms: nostr_state
                            .and_then(|state| state.last_observed_skew_ms),
                    });
                }

                let _ = response_tx.send(peers);
            }
            NodeEndpointCommand::RelaySnapshot { response_tx } => {
                let relays = if let Some(discovery) = self.nostr_discovery_handle() {
                    discovery
                        .relay_statuses()
                        .await
                        .into_iter()
                        .map(|relay| NodeEndpointRelayStatus {
                            url: relay.url,
                            status: relay.status,
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let _ = response_tx.send(relays);
            }
            NodeEndpointCommand::UpdateRelays {
                advert_relays,
                dm_relays,
                response_tx,
            } => {
                let result = if let Some(discovery) = self.nostr_discovery_handle() {
                    discovery
                        .update_relays(advert_relays, dm_relays)
                        .await
                        .map_err(|error| NodeError::Discovery(error.to_string()))
                } else {
                    Err(NodeError::Discovery(
                        "Nostr discovery is not running".to_string(),
                    ))
                };
                let _ = response_tx.send(result);
            }
        }
    }

    async fn handle_endpoint_send_command(
        &mut self,
        command: EndpointSendCommand,
    ) -> Result<(), NodeError> {
        let lane = command.lane();
        let (send, queued_at) = command.into_parts();
        record_endpoint_command_wait(queued_at, lane, 1);
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
        self.send_endpoint_data_send(send).await
    }

    async fn handle_endpoint_send_batch_command(&mut self, command: EndpointSendBatchCommand) {
        let lane = command.lane();
        let count = command.len() as u64;
        let (remote, payloads, queued_at) = command.into_parts();
        // The command queue wait ends when rx_loop starts handling the batch.
        // Count one sample per payload without charging earlier payload send
        // work to later payloads' queue residence.
        record_endpoint_command_wait(queued_at, lane, count);
        let dest_addr = *remote.node_addr();
        let dest_pubkey = remote.pubkey_full();
        self.register_identity(dest_addr, dest_pubkey);

        #[cfg(unix)]
        if self.encrypt_workers.is_some()
            && self
                .sessions
                .get(&dest_addr)
                .is_some_and(|entry| entry.is_established())
        {
            self.handle_established_endpoint_send_batch(dest_addr, dest_pubkey, payloads)
                .await;
            return;
        }

        self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
            .await;
    }

    async fn handle_endpoint_send_batch_slow_path(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
    ) {
        for payload in payloads {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
            let _ = self
                .send_or_queue_endpoint_payload(dest_addr, dest_pubkey, payload)
                .await;
        }
    }

    #[cfg(unix)]
    async fn handle_established_endpoint_send_batch(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payloads: Vec<EndpointDataPayload>,
    ) {
        let route = match self.resolve_peer_runtime_endpoint_route(dest_addr, Self::now_ms()) {
            Ok(route) => route,
            Err(_) => {
                self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
                    .await;
                return;
            }
        };

        let mut use_reused_route = true;

        for payload in payloads {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);

            if !use_reused_route {
                let _ = self
                    .send_or_queue_endpoint_payload(dest_addr, dest_pubkey, payload)
                    .await;
                continue;
            }

            match self
                .send_session_endpoint_data_with_route(&dest_addr, &payload, &route)
                .await
            {
                Ok(()) => {}
                Err(error) if Self::session_send_needs_path_recovery(&error, &dest_addr) => {
                    debug!(
                        dest = %self.peer_display_name(&dest_addr),
                        error = %error,
                        "Established endpoint-data session lost route during batch send; queueing payload and probing fallback"
                    );
                    self.queue_pending_endpoint_data(dest_addr, payload);
                    self.maybe_initiate_lookup(&dest_addr).await;
                    use_reused_route = false;
                }
                Err(_) => {
                    use_reused_route = false;
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn send_endpoint_data(
        &mut self,
        remote: crate::PeerIdentity,
        payload: Vec<u8>,
    ) -> Result<(), NodeError> {
        self.send_endpoint_data_send(EndpointDataSend::new(
            remote,
            EndpointDataPayload::new(payload),
        ))
        .await
    }

    async fn send_endpoint_data_send(&mut self, send: EndpointDataSend) -> Result<(), NodeError> {
        let dest_addr = send.dest_addr();
        let dest_pubkey = send.dest_pubkey();
        self.register_identity(dest_addr, dest_pubkey);
        self.send_or_queue_endpoint_payload(dest_addr, dest_pubkey, send.into_payload())
            .await
    }

    async fn send_or_queue_endpoint_payload(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        payload: EndpointDataPayload,
    ) -> Result<(), NodeError> {
        match self.sessions.outbound_session_state(&dest_addr) {
            OutboundSessionState::Established => {
                match self.send_session_endpoint_data(&dest_addr, &payload).await {
                    Ok(()) => return Ok(()),
                    Err(error) if Self::session_send_needs_path_recovery(&error, &dest_addr) => {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            error = %error,
                            "Established endpoint-data session lost route; queueing payload and probing fallback"
                        );
                        self.queue_pending_endpoint_data(dest_addr, payload);
                        self.maybe_initiate_lookup(&dest_addr).await;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            OutboundSessionState::Pending => {
                self.queue_pending_endpoint_data(dest_addr, payload);
                let should_discover = self.config.node.routing.mode
                    == crate::config::RoutingMode::ReplyLearned
                    || self.find_next_hop(&dest_addr).is_none();
                if should_discover {
                    self.maybe_initiate_lookup(&dest_addr).await;
                }
                return Ok(());
            }
            OutboundSessionState::Missing => {}
        }

        if self.find_next_hop(&dest_addr).is_none() {
            self.queue_pending_endpoint_data(dest_addr, payload);
            self.maybe_initiate_lookup(&dest_addr).await;
            return Ok(());
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {}
            Err(NodeError::SendFailed { node_addr, reason })
                if node_addr == dest_addr && reason == "no route to destination" =>
            {
                self.queue_pending_endpoint_data(dest_addr, payload);
                self.maybe_initiate_lookup(&dest_addr).await;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        self.queue_pending_endpoint_data(dest_addr, payload);
        Ok(())
    }

    fn session_send_needs_path_recovery(error: &NodeError, dest_addr: &NodeAddr) -> bool {
        matches!(
            error,
            NodeError::SendFailed { node_addr, reason }
                if node_addr == dest_addr && reason == "no route to destination"
        ) || error.is_local_route_unavailable()
    }

    /// Send app-owned endpoint bytes over an established session without DataPacket ports.
    async fn send_session_endpoint_data(
        &mut self,
        dest_addr: &NodeAddr,
        payload: &EndpointDataPayload,
    ) -> Result<(), NodeError> {
        let prepared = self
            .prepare_session_endpoint_data(dest_addr, payload)
            .await?;
        self.send_prepared_session_endpoint_data(prepared).await
    }

    async fn prepare_session_endpoint_data<'a>(
        &mut self,
        dest_addr: &'a NodeAddr,
        payload: &'a EndpointDataPayload,
    ) -> Result<PreparedEndpointSessionData<'a>, NodeError> {
        if payload.len() > u16::MAX as usize - FSP_INNER_HEADER_SIZE {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "endpoint data payload too long".into(),
            });
        }

        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let wants_coords = send_context.wants_coords();
        let timestamp = send_context.timestamp;

        let msg_type = SessionMessageType::EndpointData.to_byte();
        let inner_flags = send_context.inner_flags_byte();
        let inner_plaintext =
            fsp_prepend_inner_header(timestamp, msg_type, inner_flags, payload.as_slice());

        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire = FIPS_OVERHEAD as usize + coords_size + payload.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before endpoint data");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        // Consume one warmup opportunity for either piggybacked coords or the
        // standalone warmup attempt, preserving the previous retry behavior.
        if wants_coords {
            self.sessions.consume_coords_warmup_packet(dest_addr);
        }

        let flags = send_context.fsp_flags(include_coords);

        Ok(PreparedEndpointSessionData {
            dest_addr,
            payload,
            now_ms,
            timestamp,
            fsp_flags: flags,
            inner_plaintext,
            my_coords,
            dest_coords,
        })
    }

    async fn send_prepared_session_endpoint_data(
        &mut self,
        prepared: PreparedEndpointSessionData<'_>,
    ) -> Result<(), NodeError> {
        if self
            .try_send_session_endpoint_data_pipelined(prepared.pipelined())
            .await?
        {
            return Ok(());
        }

        self.send_session_fsp_plan(prepared.fallback_plan()).await
    }

    #[cfg(unix)]
    async fn send_prepared_session_endpoint_data_with_route(
        &mut self,
        prepared: PreparedEndpointSessionData<'_>,
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
    ) -> Result<(), NodeError> {
        if self
            .try_send_session_endpoint_data_pipelined_with_route(
                prepared.pipelined(),
                runtime_route,
            )
            .await?
        {
            return Ok(());
        }

        self.send_session_fsp_plan(prepared.fallback_plan()).await
    }

    #[cfg(unix)]
    async fn send_session_endpoint_data_with_route(
        &mut self,
        dest_addr: &NodeAddr,
        payload: &EndpointDataPayload,
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
    ) -> Result<(), NodeError> {
        let prepared = self
            .prepare_session_endpoint_data(dest_addr, payload)
            .await?;
        self.send_prepared_session_endpoint_data_with_route(prepared, runtime_route)
            .await
    }

    #[cfg(unix)]
    fn map_pipelined_endpoint_runtime_send_plan_error(
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        error: PipelinedEndpointRuntimeSendPlanError,
    ) -> NodeError {
        match error {
            PipelinedEndpointRuntimeSendPlanError::SendPlan(
                PipelinedEndpointSendPlanError::FmpPayloadTooLarge,
            ) => NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: "pipelined FMP payload too large".into(),
            },
            PipelinedEndpointRuntimeSendPlanError::SendPlan(
                PipelinedEndpointSendPlanError::FspPayloadTooLarge,
            ) => NodeError::SendFailed {
                node_addr: dest_addr,
                reason: "endpoint FSP payload too large".into(),
            },
            PipelinedEndpointRuntimeSendPlanError::RoutePeerMismatch {
                route_next_hop,
                peer_snapshot_addr,
            } => NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: format!(
                    "pipelined route peer mismatch: route {} peer snapshot {}",
                    route_next_hop, peer_snapshot_addr
                ),
            },
            PipelinedEndpointRuntimeSendPlanError::FmpPayloadMismatch {
                prepared_payload_len,
                plan_payload_len,
            } => NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: format!(
                    "pipelined FMP preparation payload mismatch: prepared {} plan {}",
                    prepared_payload_len, plan_payload_len
                ),
            },
        }
    }

    #[cfg(unix)]
    fn map_pipelined_endpoint_peer_runtime_route_request_error(
        error: PipelinedEndpointPeerRuntimeRouteRequestError,
    ) -> NodeError {
        match error {
            PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr } => {
                NodeError::SendFailed {
                    node_addr: dest_addr,
                    reason: "no route to destination".into(),
                }
            }
            PipelinedEndpointPeerRuntimeRouteRequestError::FmpPreparation {
                next_hop_addr,
                error,
            } => Self::map_fmp_send_preparation_error(next_hop_addr, error),
        }
    }

    #[cfg(unix)]
    fn map_pipelined_endpoint_runtime_send_attempt_error(
        error: PipelinedEndpointRuntimeSendAttemptError,
    ) -> NodeError {
        match error {
            PipelinedEndpointRuntimeSendAttemptError::FspReservation { dest_addr, error } => {
                Self::map_fsp_worker_send_reservation_error(dest_addr, error)
            }
            PipelinedEndpointRuntimeSendAttemptError::FmpReservation {
                next_hop_addr,
                error,
            } => Self::map_fmp_send_preparation_error(next_hop_addr, error),
        }
    }

    #[cfg(unix)]
    fn map_pipelined_endpoint_runtime_send_error(
        error: PipelinedEndpointRuntimeSendError,
    ) -> NodeError {
        match error {
            PipelinedEndpointRuntimeSendError::TransportNotFound(transport_id) => {
                NodeError::TransportNotFound(transport_id)
            }
            PipelinedEndpointRuntimeSendError::Attempt(error) => {
                Self::map_pipelined_endpoint_runtime_send_attempt_error(error)
            }
        }
    }

    #[cfg(unix)]
    fn map_pipelined_endpoint_peer_runtime_send_error(
        error: PipelinedEndpointPeerRuntimeSendError,
    ) -> NodeError {
        match error {
            PipelinedEndpointPeerRuntimeSendError::RuntimePlan {
                dest_addr,
                next_hop_addr,
                error,
            } => Self::map_pipelined_endpoint_runtime_send_plan_error(
                dest_addr,
                next_hop_addr,
                error,
            ),
            PipelinedEndpointPeerRuntimeSendError::RuntimeSend(error) => {
                Self::map_pipelined_endpoint_runtime_send_error(error)
            }
        }
    }

    #[cfg(unix)]
    fn map_pipelined_endpoint_peer_runtime_send_request_error(
        error: PipelinedEndpointPeerRuntimeSendRequestError,
    ) -> NodeError {
        match error {
            PipelinedEndpointPeerRuntimeSendRequestError::Route(error) => {
                Self::map_pipelined_endpoint_peer_runtime_route_request_error(error)
            }
            PipelinedEndpointPeerRuntimeSendRequestError::Send(error) => {
                Self::map_pipelined_endpoint_peer_runtime_send_error(error)
            }
        }
    }

    #[cfg(unix)]
    async fn execute_peer_runtime_endpoint_send(
        &mut self,
        send: PipelinedEndpointSend<'_>,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) -> Result<bool, PipelinedEndpointPeerRuntimeSendRequestError> {
        let source_addr = *self.node_addr();
        let default_ttl = self.config.node.session.default_ttl;
        PipelinedEndpointPeerRuntimeSendRequest::new(source_addr, send, default_ttl)
            .execute(self, workers)
            .await
    }

    #[cfg(unix)]
    fn resolve_peer_runtime_endpoint_route(
        &mut self,
        dest_addr: NodeAddr,
        now_ms: u64,
    ) -> Result<PipelinedEndpointPeerRuntimeRoute, PipelinedEndpointPeerRuntimeRouteRequestError>
    {
        let source_addr = *self.node_addr();
        let default_ttl = self.config.node.session.default_ttl;
        PipelinedEndpointPeerRuntimeRouteRequest::new(source_addr, dest_addr, now_ms, default_ttl)
            .resolve(self)
    }

    #[cfg(unix)]
    async fn execute_peer_runtime_endpoint_send_with_route(
        &mut self,
        send: PipelinedEndpointSend<'_>,
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
        workers: &crate::node::encrypt_worker::EncryptWorkerPool,
    ) -> Result<bool, PipelinedEndpointPeerRuntimeSendError> {
        let Some(dispatch) = PipelinedEndpointPeerRuntimeSend::resolve_dispatch_with_route(
            runtime_route,
            send,
            &self.transports,
            &mut self.sessions,
            &mut self.peers,
        )
        .await?
        else {
            return Ok(false);
        };
        dispatch.commit(self, workers);
        Ok(true)
    }

    #[cfg(unix)]
    async fn try_send_session_endpoint_data_pipelined(
        &mut self,
        send: PipelinedEndpointSend<'_>,
    ) -> Result<bool, NodeError> {
        let Some(workers) = self.encrypt_workers.as_ref().cloned() else {
            return Ok(false);
        };

        let sent = self
            .execute_peer_runtime_endpoint_send(send, &workers)
            .await
            .map_err(Self::map_pipelined_endpoint_peer_runtime_send_request_error)?;

        Ok(sent)
    }

    #[cfg(unix)]
    async fn try_send_session_endpoint_data_pipelined_with_route(
        &mut self,
        send: PipelinedEndpointSend<'_>,
        runtime_route: &PipelinedEndpointPeerRuntimeRoute,
    ) -> Result<bool, NodeError> {
        let Some(workers) = self.encrypt_workers.as_ref().cloned() else {
            return Ok(false);
        };

        let sent = self
            .execute_peer_runtime_endpoint_send_with_route(send, runtime_route, &workers)
            .await
            .map_err(Self::map_pipelined_endpoint_peer_runtime_send_error)?;

        Ok(sent)
    }

    #[cfg(not(unix))]
    async fn try_send_session_endpoint_data_pipelined(
        &mut self,
        _send: PipelinedEndpointSend<'_>,
    ) -> Result<bool, NodeError> {
        Ok(false)
    }

    fn deliver_endpoint_data(&mut self, delivery: EndpointDataDelivery) {
        let src_addr = *delivery.source_peer.node_addr();
        if !self.endpoint_events.is_attached() {
            trace!(
                src = %self.peer_display_name(&src_addr),
                "Endpoint data received without an attached endpoint"
            );
            return;
        }

        if let Err(error) = self.deliver_endpoint_event_message(delivery) {
            debug!(
                src = %self.peer_display_name(&src_addr),
                error = %error,
                "Failed to deliver endpoint data event"
            );
        }
    }

    /// Send a non-data session message (reports, notifications) over an established session.
    ///
    /// Similar to `send_session_data()` but:
    /// - Takes an explicit `msg_type` byte (0x11, 0x12, 0x13, etc.)
    /// - Never includes COORDS_PRESENT (reports are lightweight)
    /// - Reads spin bit from MMP state for the inner header
    /// - Records the send in MMP sender state
    pub(in crate::node) async fn send_session_msg(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let timestamp = send_context.timestamp;

        // Build inner flags with spin bit
        let inner_flags = send_context.inner_flags_byte();
        let k_flags = send_context.fsp_flags(false);

        // FSP inner header + plaintext
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, payload);

        self.send_session_fsp_plan(SessionFspSendPlan::new(
            *dest_addr,
            timestamp,
            k_flags,
            &inner_plaintext,
            None,
            SessionFspSendBookkeeping::Control,
        ))
        .await
    }

    /// Send a standalone CoordsWarmup message to warm transit node caches.
    ///
    /// Constructs an encrypted FSP message with CP flag set and
    /// msg_type=CoordsWarmup. Transit nodes extract the cleartext
    /// coordinates via `try_warm_coord_cache()` (same as CP-flagged data
    /// packets). The encrypted inner payload is the 6-byte inner header
    /// with no application data.
    pub(in crate::node) async fn send_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        let my_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let timestamp = send_context.timestamp;

        // FSP inner header only, no body payload
        let msg_type = SessionMessageType::CoordsWarmup.to_byte();
        let inner_flags = send_context.inner_flags_byte();
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &[]);

        self.send_session_fsp_plan(SessionFspSendPlan::new(
            *dest_addr,
            timestamp,
            0,
            &inner_plaintext,
            Some((&my_coords, &dest_coords)),
            SessionFspSendBookkeeping::Control,
        ))
        .await?;

        debug!(dest = %self.peer_display_name(dest_addr), "Sent standalone CoordsWarmup");
        Ok(())
    }

    /// Route and send a SessionDatagram through the mesh.
    ///
    /// Finds the next hop for the destination, seeds path_mtu from the
    /// first-hop transport MTU, and sends as an encrypted link message.
    pub(in crate::node) async fn send_session_datagram(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<(), NodeError> {
        let runtime_route = self.resolve_session_datagram_runtime_route(datagram)?;

        let encoded = datagram.encode();
        if let Err(err) = self
            .send_encrypted_link_message(&runtime_route.next_hop_addr(), &encoded)
            .await
        {
            runtime_route.record_failure(self);
            return Err(err);
        }
        runtime_route.record_success(self, encoded.len());
        Ok(())
    }

    fn resolve_session_datagram_runtime_route(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<SessionDatagramRuntimeRoute, NodeError> {
        let dest_addr = datagram.dest_addr;
        let next_hop_addr = match self.find_next_hop(&dest_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                return Err(NodeError::SendFailed {
                    node_addr: dest_addr,
                    reason: "no route to destination".into(),
                });
            }
        };

        let mut path_mtu = datagram.path_mtu;
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            path_mtu = if let Some(addr) = peer.current_addr() {
                path_mtu.min(transport.link_mtu(addr))
            } else {
                path_mtu.min(transport.mtu())
            };
        }
        datagram.path_mtu = path_mtu;

        let source_mmp_seeded = self
            .sessions
            .seed_session_datagram_path_mtu(&dest_addr, path_mtu);

        Ok(SessionDatagramRuntimeRoute::new(
            dest_addr,
            next_hop_addr,
            path_mtu,
            source_mmp_seeded,
        ))
    }

    /// Look up destination coordinates from available caches.
    ///
    /// Returns our own coordinates as a fallback (the SessionSetup will
    /// carry src_coords for return path routing; empty dest_coords
    /// would fail wire encoding since TreeCoordinate requires ≥1 entry).
    pub(in crate::node) fn get_dest_coords(&self, dest: &NodeAddr) -> crate::tree::TreeCoordinate {
        let now_ms = Self::now_ms();
        if let Some(coords) = self.coord_cache.get(dest, now_ms) {
            return coords.clone();
        }
        // Fallback: use our own coordinates. The SessionSetup dest_coords
        // field cannot be empty (wire format requires ≥1 entry). Using our
        // own coords is safe — transit routers will still cache them, and
        // the destination will return its actual coords in the SessionAck.
        self.tree_state.my_coords().clone()
    }

    /// Current Unix time in milliseconds.
    pub(in crate::node) fn now_ms() -> u64 {
        crate::time::now_ms()
    }

    // === TUN Outbound (Data Plane) ===

    /// Handle an outbound IPv6 packet from the TUN reader.
    ///
    /// Extracts the destination FipsAddress, looks up the NodeAddr and PublicKey
    /// from the identity cache, and either sends through an established session
    /// or initiates a new one (queuing the packet until established).
    ///
    /// Also performs MTU checking: if the packet (plus FIPS overhead) exceeds
    /// the transport MTU, an ICMP Packet Too Big message is sent back to the
    /// source and the packet is dropped.
    pub(in crate::node) async fn handle_tun_outbound(&mut self, ipv6_packet: Vec<u8>) {
        // Validate IPv6 header
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            return;
        }

        // Check if packet will fit after FIPS encapsulation
        let effective_mtu = self.effective_ipv6_mtu() as usize;
        if ipv6_packet.len() > effective_mtu {
            self.send_icmpv6_packet_too_big(&ipv6_packet, effective_mtu as u32);
            return;
        }

        // Extract destination FipsAddress prefix (IPv6 dest bytes 1-15)
        // IPv6 header: bytes 24-39 are dest addr, so prefix = bytes 25-39
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&ipv6_packet[25..40]);

        // Look up in identity cache
        let (dest_addr, dest_pubkey) = match self.lookup_by_fips_prefix(&prefix) {
            Some((addr, pk)) => (addr, pk),
            None => {
                self.send_icmpv6_dest_unreachable(&ipv6_packet);
                return;
            }
        };

        match self.sessions.tun_outbound_session_decision(
            &dest_addr,
            effective_mtu,
            ipv6_packet.len(),
        ) {
            TunOutboundSessionDecision::Established => {
                if let Err(e) = self.send_ipv6_packet(&dest_addr, &ipv6_packet).await {
                    if Self::session_send_needs_path_recovery(&e, &dest_addr) {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            error = %e,
                            "Established TUN session lost route; queueing packet and probing fallback"
                        );
                        self.queue_pending_packet(dest_addr, ipv6_packet);
                        self.maybe_initiate_lookup(&dest_addr).await;
                    } else {
                        debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to send TUN packet via session");
                    }
                }
                return;
            }
            TunOutboundSessionDecision::EstablishedPathMtuExceeded { path_ipv6_mtu } => {
                self.send_icmpv6_packet_too_big(&ipv6_packet, path_ipv6_mtu);
                return;
            }
            TunOutboundSessionDecision::Pending => {
                self.queue_pending_packet(dest_addr, ipv6_packet);
                let should_discover = self.config.node.routing.mode
                    == crate::config::RoutingMode::ReplyLearned
                    || self.find_next_hop(&dest_addr).is_none();
                if should_discover {
                    self.maybe_initiate_lookup(&dest_addr).await;
                }
                return;
            }
            TunOutboundSessionDecision::Missing => {}
        }

        // No session: initiate one and queue the packet.
        // If session initiation fails (no route), trigger discovery and
        // queue the packet for retry when discovery completes.
        if let Err(e) = self.initiate_session(dest_addr, dest_pubkey).await {
            debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to initiate session, trying discovery");
            self.maybe_initiate_lookup(&dest_addr).await;
            self.queue_pending_packet(dest_addr, ipv6_packet);
            return;
        }
        self.queue_pending_packet(dest_addr, ipv6_packet);
    }

    /// Send ICMPv6 Destination Unreachable back through TUN.
    pub(in crate::node) fn send_icmpv6_dest_unreachable(&self, original_packet: &[u8]) {
        use crate::FipsAddress;
        use crate::upper::icmp::{
            DestUnreachableCode, build_dest_unreachable, should_send_icmp_error,
        };

        if !should_send_icmp_error(original_packet) {
            return;
        }

        let our_ipv6 = FipsAddress::from_node_addr(self.node_addr()).to_ipv6();
        if let Some(response) =
            build_dest_unreachable(original_packet, DestUnreachableCode::NoRoute, our_ipv6)
            && let Some(tun_tx) = &self.tun_tx
        {
            let _ = tun_tx.send(response);
        }
    }

    /// Send ICMPv6 Packet Too Big back through TUN.
    ///
    /// Rate-limited per source address to prevent ICMP floods from
    /// misconfigured applications sending repeated oversized packets.
    pub(in crate::node) fn send_icmpv6_packet_too_big(&mut self, original_packet: &[u8], mtu: u32) {
        use crate::upper::icmp::build_packet_too_big;
        use std::net::Ipv6Addr;

        // Extract source address for rate limiting
        if original_packet.len() < 40 {
            return;
        }
        let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[8..24]).unwrap());

        // Rate limit ICMP PTB messages per source
        if !self.icmp_rate_limiter.should_send(src_addr) {
            debug!(
                src = %src_addr,
                "Rate limiting ICMP Packet Too Big"
            );
            return;
        }

        // Use the original packet's *destination* as the ICMP source so the
        // kernel sees the PTB coming from a remote router, not from itself.
        // Linux ignores PTBs whose source matches a local address, which
        // causes a PMTUD blackhole when both src and ICMP-src are local.
        let dest_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[24..40]).unwrap());
        if let Some(response) = build_packet_too_big(original_packet, mtu, dest_addr)
            && let Some(tun_tx) = &self.tun_tx
        {
            debug!(
                original_src = %src_addr,
                original_dst = %dest_addr,
                packet_size = original_packet.len(),
                reported_mtu = mtu,
                "Sending ICMP Packet Too Big"
            );
            let _ = tun_tx.send(response);
        }
    }

    /// Queue a packet while waiting for session establishment.
    fn queue_pending_packet(&mut self, dest_addr: NodeAddr, packet: Vec<u8>) {
        let admission = self.pending_session_traffic.push_tun_packet(
            dest_addr,
            packet,
            self.config.node.session.pending_max_destinations,
            self.config.node.session.pending_packets_per_dest,
        );
        if admission.destination_dropped() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PendingTunDestinationDropped,
            );
            return;
        }
        if admission.dropped_oldest() {
            crate::perf_profile::record_event(crate::perf_profile::Event::PendingTunPacketDropped);
        }
    }

    /// Queue endpoint data while waiting for session establishment.
    fn queue_pending_endpoint_data(
        &mut self,
        dest_addr: NodeAddr,
        payload: impl Into<EndpointDataPayload>,
    ) {
        let admission = self.pending_session_traffic.push_endpoint_data(
            dest_addr,
            payload,
            self.config.node.session.pending_max_destinations,
            self.config.node.session.pending_packets_per_dest,
        );
        if admission.destination_dropped() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PendingEndpointDestinationDropped,
            );
            return;
        }
        if admission.dropped_oldest() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PendingEndpointPacketDropped,
            );
        }
    }

    /// Flush pending packets for a destination whose session just reached Established.
    pub(in crate::node) async fn flush_pending_packets(&mut self, dest_addr: &NodeAddr) {
        if !self.pending_session_traffic.has_traffic_for(dest_addr) {
            return;
        }

        if let Some(packets) = self.pending_session_traffic.take_tun_packets(dest_addr) {
            for packet in packets.into_packets() {
                if let Err(e) = self.send_ipv6_packet(dest_addr, &packet).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued TUN packet");
                    break;
                }
            }
        }

        if let Some(payloads) = self.pending_session_traffic.take_endpoint_data(dest_addr) {
            for payload in payloads.into_payloads() {
                if let Err(e) = self.send_session_endpoint_data(dest_addr, &payload).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued endpoint data");
                    break;
                }
            }
        }
    }

    /// Retry session initiation after discovery provided coordinates.
    ///
    /// Called when a LookupResponse arrives and we have pending TUN packets or
    /// endpoint data for the discovered target. The coord_cache now has coords, so
    /// `find_next_hop()` should succeed and the SessionSetup can be sent.
    pub(in crate::node) async fn retry_session_after_discovery(&mut self, dest_addr: NodeAddr) {
        // Look up the destination's public key from the identity cache
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&dest_addr.as_bytes()[0..15]);
        let dest_pubkey = match self.lookup_by_fips_prefix(&prefix) {
            Some((_, pk)) => pk,
            None => {
                debug!(dest = %self.peer_display_name(&dest_addr), "Discovery complete but no identity for session retry");
                return;
            }
        };

        match self
            .sessions
            .prepare_retry_session_after_discovery(&dest_addr)
        {
            DiscoveryRetrySessionDecision::Established => {
                return;
            }
            DiscoveryRetrySessionDecision::RestartedPending => {
                debug!(
                    dest = %self.peer_display_name(&dest_addr),
                    "Restarting pending session after discovery refreshed route"
                );
            }
            DiscoveryRetrySessionDecision::Missing => {}
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {
                debug!(dest = %self.peer_display_name(&dest_addr), "Session initiated after discovery");
            }
            Err(e) => {
                debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Session retry after discovery failed");
            }
        }
    }
}

fn session_receiver_report_can_drive_route_quality(mode: MmpMode, srtt_ms: Option<f64>) -> bool {
    match mode {
        MmpMode::Full => srtt_ms.is_some(),
        MmpMode::Lightweight => true,
        MmpMode::Minimal => false,
    }
}

#[cfg(test)]
mod pending_queue_tests {
    use crate::config::Config;
    use crate::node::{Node, NodeAddr};

    fn make_node() -> Node {
        Node::new(Config::new()).unwrap()
    }

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    #[test]
    fn pending_session_queues_drop_oldest_per_destination() {
        let mut node = make_node();
        node.config.node.session.pending_packets_per_dest = 2;

        let tun_dest = make_node_addr(0x41);
        node.queue_pending_packet(tun_dest, vec![1]);
        node.queue_pending_packet(tun_dest, vec![2]);
        node.queue_pending_packet(tun_dest, vec![3]);
        let tun_packets: Vec<Vec<u8>> = node
            .pending_session_traffic
            .tun_packets_for(&tun_dest)
            .expect("tun queue")
            .iter()
            .cloned()
            .collect();
        assert_eq!(tun_packets, vec![vec![2], vec![3]]);

        let endpoint_dest = make_node_addr(0x42);
        node.queue_pending_endpoint_data(endpoint_dest, vec![4]);
        node.queue_pending_endpoint_data(endpoint_dest, vec![5]);
        node.queue_pending_endpoint_data(endpoint_dest, vec![6]);
        let endpoint_payloads: Vec<Vec<u8>> = node
            .pending_session_traffic
            .endpoint_data_for(&endpoint_dest)
            .expect("endpoint queue")
            .iter()
            .map(|payload| payload.as_slice().to_vec())
            .collect();
        assert_eq!(endpoint_payloads, vec![vec![5], vec![6]]);
    }

    #[test]
    fn pending_endpoint_data_queue_owns_drop_oldest_policy() {
        let mut queue = crate::node::PendingEndpointDataQueue::default();
        assert!(!queue.push_bounded(vec![1].into(), 2).dropped_oldest());
        assert!(!queue.push_bounded(vec![2].into(), 2).dropped_oldest());
        assert!(queue.push_bounded(vec![3].into(), 2).dropped_oldest());

        let payloads: Vec<Vec<u8>> = queue
            .iter()
            .map(|payload| payload.as_slice().to_vec())
            .collect();
        assert_eq!(payloads, vec![vec![2], vec![3]]);
    }

    #[test]
    fn pending_tun_packet_queue_owns_drop_oldest_policy() {
        let mut queue = crate::node::PendingTunPacketQueue::default();
        assert!(!queue.push_bounded(vec![1], 2).dropped_oldest());
        assert!(!queue.push_bounded(vec![2], 2).dropped_oldest());
        assert!(queue.push_bounded(vec![3], 2).dropped_oldest());

        let packets: Vec<Vec<u8>> = queue.iter().cloned().collect();
        assert_eq!(packets, vec![vec![2], vec![3]]);
    }

    #[test]
    fn pending_session_traffic_queues_own_destination_admission() {
        let mut queues = crate::node::PendingSessionTrafficQueues::default();
        let tun_dest = NodeAddr::from_bytes([1u8; 16]);
        let rejected_tun_dest = NodeAddr::from_bytes([2u8; 16]);
        let endpoint_dest = NodeAddr::from_bytes([3u8; 16]);
        let rejected_endpoint_dest = NodeAddr::from_bytes([4u8; 16]);

        assert!(
            !queues
                .push_tun_packet(tun_dest, vec![1], 1, 2)
                .destination_dropped()
        );
        assert!(queues.has_traffic_for(&tun_dest));
        assert!(
            queues
                .push_tun_packet(rejected_tun_dest, vec![2], 1, 2)
                .destination_dropped()
        );
        assert!(!queues.has_traffic_for(&rejected_tun_dest));

        assert!(
            !queues
                .push_endpoint_data(endpoint_dest, vec![3], 1, 2)
                .destination_dropped()
        );
        assert!(queues.has_traffic_for(&endpoint_dest));
        assert!(
            queues
                .push_endpoint_data(rejected_endpoint_dest, vec![4], 1, 2)
                .destination_dropped()
        );
        assert!(!queues.has_traffic_for(&rejected_endpoint_dest));

        assert!(
            !queues
                .push_tun_packet(tun_dest, vec![5], 1, 2)
                .dropped_oldest()
        );
        assert!(
            queues
                .push_tun_packet(tun_dest, vec![6], 1, 2)
                .dropped_oldest()
        );

        let packets: Vec<Vec<u8>> = queues
            .tun_packets_for(&tun_dest)
            .expect("accepted TUN queue")
            .iter()
            .cloned()
            .collect();
        assert_eq!(packets, vec![vec![5], vec![6]]);

        let removed = queues.remove_destination(&tun_dest);
        assert_eq!(removed.tun_packets().map(|queue| queue.len()), Some(2));
        assert!(queues.tun_packets_for(&tun_dest).is_none());
        assert!(!queues.has_traffic_for(&tun_dest));
        assert!(queues.endpoint_data_for(&endpoint_dest).is_some());
        assert!(queues.has_traffic_for(&endpoint_dest));
    }

    #[test]
    fn pending_session_traffic_destination_guard_tracks_partial_takes() {
        let mut queues = crate::node::PendingSessionTrafficQueues::default();
        let dest = NodeAddr::from_bytes([9u8; 16]);

        assert!(
            !queues
                .push_tun_packet(dest, vec![1], 8, 2)
                .destination_dropped()
        );
        assert!(
            !queues
                .push_endpoint_data(dest, vec![2], 8, 2)
                .destination_dropped()
        );
        assert!(queues.has_traffic_for(&dest));

        assert!(queues.take_tun_packets(&dest).is_some());
        assert!(
            queues.has_traffic_for(&dest),
            "endpoint payloads should keep the destination guard set"
        );
        assert!(queues.take_endpoint_data(&dest).is_some());
        assert!(
            !queues.has_traffic_for(&dest),
            "guard should clear after the final pending queue is removed"
        );
    }

    #[test]
    fn pending_session_queues_reject_new_destinations_at_cap() {
        let mut node = make_node();
        node.config.node.session.pending_max_destinations = 1;

        let accepted_tun_dest = make_node_addr(0x51);
        let rejected_tun_dest = make_node_addr(0x52);
        node.queue_pending_packet(accepted_tun_dest, vec![1]);
        node.queue_pending_packet(rejected_tun_dest, vec![2]);
        assert!(
            node.pending_session_traffic
                .tun_packets_for(&accepted_tun_dest)
                .is_some()
        );
        assert!(
            node.pending_session_traffic
                .tun_packets_for(&rejected_tun_dest)
                .is_none()
        );

        let accepted_endpoint_dest = make_node_addr(0x61);
        let rejected_endpoint_dest = make_node_addr(0x62);
        node.queue_pending_endpoint_data(accepted_endpoint_dest, vec![3]);
        node.queue_pending_endpoint_data(rejected_endpoint_dest, vec![4]);
        assert!(
            node.pending_session_traffic
                .endpoint_data_for(&accepted_endpoint_dest)
                .is_some()
        );
        assert!(
            node.pending_session_traffic
                .endpoint_data_for(&rejected_endpoint_dest)
                .is_none()
        );
    }
}

/// Mark ECN-CE in an IPv6 packet's Traffic Class field.
///
/// IPv6 Traffic Class occupies bits across bytes 0 and 1:
///   byte[0] bits[3:0] = TC[7:4]
///   byte[1] bits[7:4] = TC[3:0]
/// ECN is TC[1:0]. Only marks CE (0b11) if the packet is ECN-capable
/// (ECT(0) or ECT(1)). Packets with ECN=0b00 (Not-ECT) are never marked
/// per RFC 3168.
///
/// No checksum update needed: IPv6 has no header checksum, and the Traffic
/// Class field is not part of the TCP/UDP pseudo-header.
pub(in crate::node) fn mark_ipv6_ecn_ce(packet: &mut [u8]) {
    if packet.len() < 2 {
        return;
    }
    // Extract 8-bit Traffic Class from IPv6 header bytes 0-1
    let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let ecn = tc & 0x03;
    // Only mark CE on ECN-capable packets (ECT(0)=0b10 or ECT(1)=0b01)
    if ecn == 0 {
        return;
    }
    // Set both ECN bits to 1 (CE = 0b11)
    let new_tc = tc | 0x03;
    packet[0] = (packet[0] & 0xF0) | (new_tc >> 4);
    packet[1] = (new_tc << 4) | (packet[1] & 0x0F);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use crate::noise::{NoiseError, NoiseSession};

    fn node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_xk_session_pair(
        initiator: &Identity,
        responder: &Identity,
    ) -> (NoiseSession, NoiseSession) {
        let mut initiator_hs =
            HandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
        let mut responder_hs = HandshakeState::new_xk_responder(responder.keypair());
        initiator_hs.set_local_epoch([1u8; 8]);
        responder_hs.set_local_epoch([2u8; 8]);

        let msg1 = initiator_hs.write_xk_message_1().unwrap();
        responder_hs.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder_hs.write_xk_message_2().unwrap();
        initiator_hs.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator_hs.write_xk_message_3().unwrap();
        responder_hs.read_xk_message_3(&msg3).unwrap();

        (
            initiator_hs.into_session().unwrap(),
            responder_hs.into_session().unwrap(),
        )
    }

    fn make_xk_session(initiator: &Identity, responder: &Identity) -> NoiseSession {
        make_xk_session_pair(initiator, responder).0
    }

    fn encrypt_frame(session: &mut NoiseSession, plaintext: &[u8], aad: &[u8]) -> (u64, Vec<u8>) {
        let counter = session.current_send_counter();
        let ciphertext = session.encrypt_with_aad(plaintext, aad).unwrap();
        (counter, ciphertext)
    }

    fn decrypt_current(
        entry: &mut SessionEntry,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        match entry.state_mut() {
            EndToEndState::Established(session) => {
                session.decrypt_with_replay_check_and_aad(ciphertext, counter, aad)
            }
            _ => unreachable!("test entry is established"),
        }
    }

    fn established_entry(local: &Identity, peer: &Identity) -> SessionEntry {
        let session = make_xk_session(local, peer);
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(session),
            1000,
            true,
        )
    }

    fn initiating_entry(local: &Identity, peer: &Identity) -> SessionEntry {
        let mut handshake = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        handshake.set_local_epoch([1u8; 8]);
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
        )
    }

    fn receiver_report(
        highest_counter: u64,
        cumulative_packets_recv: u64,
        cumulative_bytes_recv: u64,
        timestamp_echo: u32,
    ) -> ReceiverReport {
        ReceiverReport {
            highest_counter,
            cumulative_packets_recv,
            cumulative_bytes_recv,
            timestamp_echo,
            dwell_time: 0,
            max_burst_loss: 0,
            mean_burst_loss: 0,
            jitter: 0,
            ecn_ce_count: 0,
            owd_trend: 0,
            burst_loss_count: 0,
            cumulative_reorder_count: 0,
            interval_packets_recv: 0,
            interval_bytes_recv: 0,
        }
    }

    #[test]
    fn session_registry_owns_session_receiver_report_processing() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());
        entry.record_outbound_next_hop(peer_addr);
        entry.mmp_mut().expect("session mmp").receiver.record_recv(
            40,
            10,
            1200,
            false,
            std::time::Instant::now(),
        );

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let now = std::time::Instant::now();
        let baseline = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(100, 100, 10_000, 50),
                1_100,
                now,
            )
            .expect("baseline report should process");

        assert_eq!(baseline.sample, None);
        assert!(baseline.used_direct_next_hop);
        assert_eq!(baseline.srtt_ms, Some(50.0));
        assert!(baseline.route_quality_sample);

        let lossy = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(300, 290, 29_000, 100),
                1_200,
                now + std::time::Duration::from_secs(1),
            )
            .expect("lossy report should process");
        let (span, loss) = lossy.sample.expect("second report should sample loss");
        assert_eq!(span, 200);
        assert!(
            (loss - 0.05).abs() < 0.01,
            "loss={loss}, expected roughly 5%"
        );

        let mmp = sessions
            .get(&peer_addr)
            .and_then(|entry| entry.mmp())
            .expect("session mmp");
        assert!(mmp.metrics.srtt_ms().is_some());
        assert_eq!(
            mmp.sender.report_interval(),
            std::time::Duration::from_millis(MIN_SESSION_REPORT_INTERVAL_MS)
        );
        assert_eq!(
            mmp.receiver.report_interval(),
            std::time::Duration::from_millis(MIN_SESSION_REPORT_INTERVAL_MS)
        );
    }

    #[test]
    fn session_registry_session_receiver_report_processing_reports_skip_reasons() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();
        let rr = receiver_report(100, 100, 10_000, 50);

        assert_eq!(
            sessions.process_session_receiver_report(
                &peer_addr,
                &rr,
                1_100,
                std::time::Instant::now()
            ),
            Err(SessionReceiverReportSkip::UnknownSession)
        );

        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        assert!(sessions.insert(peer_addr, entry).is_none());

        assert_eq!(
            sessions.process_session_receiver_report(
                &peer_addr,
                &rr,
                1_100,
                std::time::Instant::now()
            ),
            Err(SessionReceiverReportSkip::MmpDisabled)
        );
    }

    #[test]
    fn session_registry_owns_session_path_mtu_signal_application() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut entry = established_entry(&local, &peer);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let now = std::time::Instant::now();
        assert_eq!(
            sessions.apply_session_path_mtu_signal(&peer_addr, 1280, now),
            Ok(SessionPathMtuApplyResult::Changed(SessionPathMtuChange {
                old_mtu: u16::MAX,
                new_mtu: 1280
            }))
        );
        assert_eq!(
            sessions
                .get(&peer_addr)
                .and_then(|entry| entry.mmp())
                .expect("session mmp")
                .path_mtu
                .current_mtu(),
            1280
        );

        assert_eq!(
            sessions.apply_session_path_mtu_signal(
                &peer_addr,
                1400,
                now + std::time::Duration::from_secs(1)
            ),
            Ok(SessionPathMtuApplyResult::Unchanged),
            "a single larger PMTU signal must not loosen the source-side MTU"
        );
    }

    #[test]
    fn session_registry_session_path_mtu_signal_reports_skip_reasons() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();
        let now = std::time::Instant::now();

        assert_eq!(
            sessions.apply_session_path_mtu_signal(&peer_addr, 1280, now),
            Err(SessionPathMtuApplySkip::UnknownSession)
        );

        assert!(
            sessions
                .insert(peer_addr, established_entry(&local, &peer))
                .is_none()
        );
        assert_eq!(
            sessions.apply_session_path_mtu_signal(&peer_addr, 1280, now),
            Err(SessionPathMtuApplySkip::MmpDisabled)
        );
    }

    #[test]
    fn session_registry_owns_route_error_coords_warmup_policy() {
        let local = Identity::generate();
        let established_peer = Identity::generate();
        let initiating_peer = Identity::generate();
        let established_addr = *established_peer.node_addr();
        let initiating_addr = *initiating_peer.node_addr();
        let missing_addr = node_addr(0x99);
        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(
                    established_addr,
                    established_entry(&local, &established_peer)
                )
                .is_none()
        );
        assert!(
            sessions
                .insert(initiating_addr, initiating_entry(&local, &initiating_peer))
                .is_none()
        );

        assert!(sessions.route_error_can_send_coords_warmup(&established_addr));
        assert!(!sessions.route_error_can_send_coords_warmup(&initiating_addr));
        assert!(!sessions.route_error_can_send_coords_warmup(&missing_addr));

        assert!(sessions.reset_route_error_coords_warmup(&established_addr, 3));
        assert!(sessions.reset_route_error_coords_warmup(&initiating_addr, 2));
        assert!(!sessions.reset_route_error_coords_warmup(&missing_addr, 1));
        assert_eq!(
            sessions
                .get(&established_addr)
                .expect("established session")
                .coords_warmup_remaining(),
            3
        );
        assert_eq!(
            sessions
                .get(&initiating_addr)
                .expect("initiating session")
                .coords_warmup_remaining(),
            2
        );
    }

    #[test]
    fn session_registry_owns_fsp_send_context_and_coords_warmup_consumption() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let now_ms = 0x0102_0304_0506_0708;
        let mut entry = established_entry(&local, &peer);
        let expected_timestamp = entry.session_timestamp(now_ms);
        entry.set_coords_warmup_remaining(2);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let context = sessions
            .session_fsp_send_context(&peer_addr, now_ms)
            .expect("established context");
        assert_eq!(context.timestamp, expected_timestamp);
        assert!(context.wants_coords());
        assert_eq!(
            context.inner_flags_byte(),
            FspInnerFlags { spin_bit: false }.to_byte()
        );
        assert_eq!(context.fsp_flags(false), 0);
        assert_eq!(context.fsp_flags(true), FSP_FLAG_CP);

        assert!(sessions.consume_coords_warmup_packet(&peer_addr));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .expect("session")
                .coords_warmup_remaining(),
            1
        );
        assert!(sessions.consume_coords_warmup_packet(&peer_addr));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .expect("session")
                .coords_warmup_remaining(),
            0
        );
        assert!(!sessions.consume_coords_warmup_packet(&peer_addr));
    }

    #[test]
    fn session_registry_fsp_send_context_reports_skip_reasons() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();

        assert_eq!(
            sessions.session_fsp_send_context(&peer_addr, 123),
            Err(SessionFspSendContextError::NoSession)
        );

        assert!(
            sessions
                .insert(peer_addr, initiating_entry(&local, &peer))
                .is_none()
        );
        assert_eq!(
            sessions.session_fsp_send_context(&peer_addr, 123),
            Err(SessionFspSendContextError::NotEstablished)
        );

        let inner_plaintext =
            fsp_prepend_inner_header(123, SessionMessageType::EndpointData.to_byte(), 0, b"hello");
        let plan = SessionFspSendPlan::new(
            peer_addr,
            123,
            0,
            &inner_plaintext,
            None,
            SessionFspSendBookkeeping::Control,
        );
        let error = match sessions.seal_session_fsp_send(plan) {
            Ok(_) => panic!("initiating session must not seal established FSP data"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                NodeError::SendFailed { node_addr, ref reason }
                    if node_addr == peer_addr && reason == "session not established"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn session_registry_owns_fsp_sealing_and_datagram_bookkeeping() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let next_hop = node_addr(0x55);
        let mut entry = established_entry(&local, &peer);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());
        let counter_before = entry.send_counter();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let inner_plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            b"hello",
        );
        let plan = SessionFspSendPlan::new(
            peer_addr,
            0x0102_0304,
            FSP_FLAG_K,
            &inner_plaintext,
            None,
            SessionFspSendBookkeeping::Data {
                payload_len: 5,
                now_ms: 0x5566_7788,
            },
        );

        let sealed = sessions
            .seal_session_fsp_send(plan)
            .expect("established session should seal");
        assert_eq!(sealed.dest_addr(), peer_addr);
        assert_eq!(sealed.counter(), counter_before);
        assert_eq!(
            sessions.get(&peer_addr).expect("session").send_counter(),
            counter_before + 1
        );

        let (_datagram, bookkeeping) = sealed.into_datagram(node_addr(0xaa), 7);
        assert_eq!(
            bookkeeping,
            FspSendBookkeepingInput::data(
                5,
                counter_before,
                0x0102_0304,
                inner_plaintext.len() + crate::noise::TAG_SIZE,
                0x5566_7788,
            )
        );

        assert!(sessions.seed_session_datagram_path_mtu(&peer_addr, 1280));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .and_then(|entry| entry.mmp())
                .expect("session mmp")
                .path_mtu
                .current_mtu(),
            1280
        );
        assert!(sessions.record_session_datagram_next_hop(&peer_addr, next_hop));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .expect("session")
                .last_outbound_next_hop(),
            Some(next_hop)
        );
        assert!(!sessions.seed_session_datagram_path_mtu(&node_addr(0x77), 1280));
        assert!(!sessions.record_session_datagram_next_hop(&node_addr(0x77), next_hop));
    }

    #[test]
    fn session_registry_owns_outbound_session_state_and_tun_pmtu_guard() {
        let local = Identity::generate();
        let established_peer = Identity::generate();
        let initiating_peer = Identity::generate();
        let established_addr = *established_peer.node_addr();
        let initiating_addr = *initiating_peer.node_addr();
        let missing_addr = node_addr(0x99);
        let mut established = established_entry(&local, &established_peer);
        established.init_mmp(&crate::config::SessionMmpConfig::default());
        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(established_addr, established).is_none());
        assert!(
            sessions
                .insert(initiating_addr, initiating_entry(&local, &initiating_peer))
                .is_none()
        );

        assert_eq!(
            sessions.outbound_session_state(&established_addr),
            OutboundSessionState::Established
        );
        assert_eq!(
            sessions.outbound_session_state(&initiating_addr),
            OutboundSessionState::Pending
        );
        assert_eq!(
            sessions.outbound_session_state(&missing_addr),
            OutboundSessionState::Missing
        );
        assert!(sessions.should_skip_session_initiation(&established_addr));
        assert!(sessions.should_skip_session_initiation(&initiating_addr));
        assert!(!sessions.should_skip_session_initiation(&missing_addr));

        assert_eq!(
            sessions.tun_outbound_session_decision(&established_addr, 1500, 1280),
            TunOutboundSessionDecision::Established
        );

        let path_mtu = 1280;
        assert!(sessions.seed_session_datagram_path_mtu(&established_addr, path_mtu));
        let path_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as usize;
        assert_eq!(
            sessions.tun_outbound_session_decision(&established_addr, 1500, path_ipv6_mtu + 1),
            TunOutboundSessionDecision::EstablishedPathMtuExceeded {
                path_ipv6_mtu: path_ipv6_mtu as u32
            }
        );
        assert_eq!(
            sessions.tun_outbound_session_decision(&established_addr, 1500, path_ipv6_mtu),
            TunOutboundSessionDecision::Established
        );
        assert_eq!(
            sessions.tun_outbound_session_decision(&initiating_addr, 1500, 1280),
            TunOutboundSessionDecision::Pending
        );
        assert_eq!(
            sessions.tun_outbound_session_decision(&missing_addr, 1500, 1280),
            TunOutboundSessionDecision::Missing
        );
    }

    #[test]
    fn session_registry_owns_discovery_retry_restart_policy() {
        let local = Identity::generate();
        let established_peer = Identity::generate();
        let initiating_peer = Identity::generate();
        let established_addr = *established_peer.node_addr();
        let initiating_addr = *initiating_peer.node_addr();
        let missing_addr = node_addr(0x88);
        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(
                    established_addr,
                    established_entry(&local, &established_peer)
                )
                .is_none()
        );
        assert!(
            sessions
                .insert(initiating_addr, initiating_entry(&local, &initiating_peer))
                .is_none()
        );

        assert_eq!(
            sessions.prepare_retry_session_after_discovery(&established_addr),
            DiscoveryRetrySessionDecision::Established
        );
        assert!(
            sessions.get(&established_addr).is_some(),
            "established sessions must remain intact"
        );
        assert_eq!(
            sessions.prepare_retry_session_after_discovery(&initiating_addr),
            DiscoveryRetrySessionDecision::RestartedPending
        );
        assert!(
            sessions.get(&initiating_addr).is_none(),
            "pending setup should be removed so it can be rebuilt with fresh coords"
        );
        assert_eq!(
            sessions.prepare_retry_session_after_discovery(&missing_addr),
            DiscoveryRetrySessionDecision::Missing
        );
    }

    #[test]
    fn session_registry_owns_handshake_session_installation() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();
        let mmp_config = crate::config::SessionMmpConfig::default();

        let mut initiating_handshake =
            HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        initiating_handshake.set_local_epoch([1u8; 8]);
        assert!(
            sessions
                .install_initiating_session(
                    peer_addr,
                    peer.pubkey_full(),
                    initiating_handshake,
                    vec![0x11, 0x22],
                    1_000,
                    250,
                )
                .is_none()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("initiating session should be installed");
        assert!(entry.is_initiating());
        assert!(entry.is_initiator());
        assert_eq!(entry.handshake_payload(), Some([0x11, 0x22].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 1_250);

        let mut awaiting_handshake = HandshakeState::new_xk_responder(local.keypair());
        awaiting_handshake.set_local_epoch([2u8; 8]);
        assert!(
            sessions
                .install_awaiting_msg3_session(
                    peer_addr,
                    local.pubkey_full(),
                    awaiting_handshake,
                    vec![0x33],
                    2_000,
                    500,
                )
                .is_some(),
            "awaiting-msg3 install replaces the old initiating entry"
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("awaiting-msg3 session should be installed");
        assert!(entry.is_awaiting_msg3());
        assert!(!entry.is_initiator());
        assert_eq!(entry.handshake_payload(), Some([0x33].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 2_500);

        let (initiator_session, _) = make_xk_session_pair(&local, &peer);
        let mut entry = initiating_entry(&local, &peer);
        let _ = entry.take_state();
        assert!(
            sessions
                .install_established_initiator_session(
                    peer_addr,
                    entry,
                    initiator_session,
                    vec![0x44, 0x55],
                    3_000,
                    750,
                    3,
                    &mmp_config,
                )
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("established initiator session should be installed");
        assert!(entry.is_established());
        assert!(entry.is_initiator());
        assert_eq!(entry.coords_warmup_remaining(), 3);
        assert_eq!(entry.session_start_ms(), 3_000);
        assert_eq!(entry.last_activity(), 3_000);
        assert!(entry.mmp().is_some());
        assert_eq!(entry.handshake_payload(), Some([0x44, 0x55].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 3_750);

        let (_, responder_session) = make_xk_session_pair(&peer, &local);
        assert!(
            sessions
                .install_established_responder_session(
                    peer_addr,
                    peer.pubkey_full(),
                    responder_session,
                    4_000,
                    2,
                    &mmp_config,
                )
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("established responder session should be installed");
        assert!(entry.is_established());
        assert!(!entry.is_initiator());
        assert_eq!(entry.coords_warmup_remaining(), 2);
        assert_eq!(entry.session_start_ms(), 4_000);
        assert_eq!(entry.last_activity(), 4_000);
        assert!(entry.mmp().is_some());
        assert_eq!(*entry.remote_pubkey(), peer.pubkey_full());
        assert_eq!(entry.handshake_payload(), None);
    }

    #[test]
    fn session_registry_owns_rekey_session_installation_and_abandon() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();

        assert!(
            sessions
                .insert(peer_addr, established_entry(&local, &peer))
                .is_none()
        );
        let mut rekey_handshake = HandshakeState::new_xk_responder(local.keypair());
        rekey_handshake.set_local_epoch([3u8; 8]);
        assert!(sessions.install_rekey_responder_awaiting_msg3(
            &peer_addr,
            rekey_handshake,
            vec![0xaa],
            5_000,
            125,
        ));
        let entry = sessions
            .get(&peer_addr)
            .expect("rekey awaiting-msg3 state should remain installed");
        assert!(entry.has_rekey_in_progress());
        assert!(!entry.is_rekey_initiator());
        assert_eq!(entry.handshake_payload(), Some([0xaa].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 5_125);
        assert!(entry.is_rekey_dampened(5_100, 500));

        assert!(sessions.abandon_rekey(&peer_addr));
        let entry = sessions
            .get(&peer_addr)
            .expect("session should remain after abandon");
        assert!(!entry.has_rekey_in_progress());
        assert!(entry.pending_new_session().is_none());
        assert_eq!(entry.handshake_payload(), None);

        let (pending_session, _) = make_xk_session_pair(&local, &peer);
        let mut entry = established_entry(&local, &peer);
        entry.set_handshake_payload(vec![0xbb], 6_050);
        assert!(
            sessions
                .install_rekey_initiator_pending_session(
                    peer_addr,
                    entry,
                    pending_session,
                    vec![0xcc, 0xdd],
                    6_000,
                    250,
                )
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("initiator pending rekey should be installed");
        assert!(entry.pending_new_session().is_some());
        assert_eq!(entry.rekey_completed_ms(), 6_000);
        assert_eq!(entry.handshake_payload(), None);
        assert_eq!(entry.rekey_msg3_payload(), Some([0xcc, 0xdd].as_slice()));
        assert_eq!(entry.rekey_msg3_next_resend_ms(), 6_250);

        let (_, pending_session) = make_xk_session_pair(&peer, &local);
        let mut entry = established_entry(&local, &peer);
        entry.set_handshake_payload(vec![0xee], 7_050);
        assert!(
            sessions
                .install_rekey_responder_pending_session(peer_addr, entry, pending_session)
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("responder pending rekey should be installed");
        assert!(entry.pending_new_session().is_some());
        assert_eq!(entry.handshake_payload(), None);
        assert_eq!(entry.rekey_msg3_payload(), None);
    }

    #[test]
    fn session_runtime_receive_owns_fsp_open_bookkeeping_and_dispatch_metadata() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let (local_session, mut peer_sender) = make_xk_session_pair(&local, &peer);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(local_session),
            1_000,
            true,
        );
        entry.mark_established(1_000);
        entry.record_decrypt_failure();

        let endpoint_payload = b"endpoint runtime receive".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let counter = peer_sender.current_send_counter();
        let header = build_fsp_header(counter, 0, plaintext.len() as u16);
        let ciphertext = peer_sender
            .encrypt_with_aad(&plaintext, &header)
            .expect("test frame should encrypt");
        let mut wire = header.to_vec();
        wire.extend_from_slice(&ciphertext);
        let parsed = FspEncryptedHeader::parse(&wire).expect("test frame should parse");

        let outcome = SessionRuntimeReceive::new(
            &mut entry,
            &parsed,
            &wire[FSP_HEADER_SIZE..],
            1_280,
            true,
            2_000,
        )
        .open_established();

        match outcome {
            FspFrameOutcome::Authentic(message) => {
                assert_eq!(message.source_peer().node_addr(), peer.node_addr());
                assert_eq!(message.plaintext(), plaintext);
                assert_eq!(
                    message.msg_type(),
                    SessionMessageType::EndpointData.to_byte()
                );
                assert_eq!(message.inner_flags_byte(), 0);
                assert_eq!(message.timestamp(), 0x0102_0304);
                assert_eq!(message.body(), endpoint_payload);
                assert!(message.is_application_data());
            }
            other => panic!("expected authentic FSP frame, got {other:?}"),
        }
        assert_eq!(entry.consecutive_decrypt_failures(), 0);
        assert_eq!(entry.last_inbound_frame_ms(), 2_000);
    }

    #[test]
    fn established_fsp_wire_owns_ciphertext_offset_and_coord_warmup() {
        use crate::tree::TreeCoordinate;

        let source_addr = node_addr(0x01);
        let local_addr = node_addr(0x02);
        let root_addr = node_addr(0xf0);
        let source_coords = TreeCoordinate::from_addrs(vec![source_addr, root_addr]).unwrap();
        let local_coords = TreeCoordinate::from_addrs(vec![local_addr, root_addr]).unwrap();

        let header = build_fsp_header(42, FSP_FLAG_CP | FSP_FLAG_K, 20);
        let mut wire_bytes = header.to_vec();
        encode_coords(&source_coords, &mut wire_bytes);
        encode_coords(&local_coords, &mut wire_bytes);
        let ciphertext_offset = wire_bytes.len();
        wire_bytes.extend_from_slice(&[0xcc; 36]);

        let mut wire = EstablishedFspWire::parse(&wire_bytes, source_addr, local_addr)
            .expect("wire should parse with coord warmup");
        assert_eq!(wire.header.counter, 42);
        assert_eq!(wire.header.flags, FSP_FLAG_CP | FSP_FLAG_K);
        assert_eq!(wire.ciphertext, &wire_bytes[ciphertext_offset..]);
        assert!(wire.has_coord_warmup());

        let receive = wire.receive(1_280, true, 2_000);
        assert_eq!(receive.header.counter, 42);
        assert_eq!(receive.ciphertext, &wire_bytes[ciphertext_offset..]);
        assert_eq!(receive.path_mtu, 1_280);
        assert!(receive.ce_flag);
        assert_eq!(receive.now_ms, 2_000);

        let mut coord_cache = crate::cache::CoordCache::new(16, 1_000);
        wire.apply_coord_warmup(&mut coord_cache, 1_500);
        assert!(!wire.has_coord_warmup());
        assert_eq!(
            coord_cache
                .get(&source_addr, 1_500)
                .expect("source coords should be cached")
                .root_id(),
            &root_addr
        );
        assert_eq!(
            coord_cache
                .get(&local_addr, 1_500)
                .expect("local coords should be cached")
                .root_id(),
            &root_addr
        );

        assert!(matches!(
            EstablishedFspWire::parse(&wire_bytes[..FSP_HEADER_SIZE - 1], source_addr, local_addr),
            Err(EstablishedFspWireError::BadHeader)
        ));
        let mut truncated_coords = build_fsp_header(43, FSP_FLAG_CP, 20).to_vec();
        truncated_coords.extend_from_slice(&2u16.to_le_bytes());
        truncated_coords.extend_from_slice(&[0u8; 14]);
        assert!(matches!(
            EstablishedFspWire::parse(&truncated_coords, source_addr, local_addr),
            Err(EstablishedFspWireError::BadCoords(_))
        ));
    }

    #[test]
    fn session_registry_owns_early_encrypted_handshake_resend_budget() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let handshake = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1_000,
            true,
        );
        let payload = vec![0x10, 0x20, 0x30];
        entry.set_handshake_payload(payload.clone(), 1_500);

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*peer.node_addr(), entry);

        match sessions.prepare_handshake_resend_after_early_encrypted_data(peer.node_addr(), 2) {
            EarlyEncryptedHandshakeResend::Resend { payload: resend } => {
                assert_eq!(resend, payload);
            }
            other => panic!("expected resend decision, got {other:?}"),
        }
        assert!(sessions.record_handshake_resend(peer.node_addr(), 2_000));
        let entry = sessions
            .get(peer.node_addr())
            .expect("session should remain");
        assert_eq!(entry.resend_count(), 1);
        assert_eq!(entry.next_resend_at_ms(), 2_000);
        assert_eq!(entry.handshake_payload(), Some(payload.as_slice()));

        assert!(matches!(
            sessions.prepare_handshake_resend_after_early_encrypted_data(peer.node_addr(), 1),
            EarlyEncryptedHandshakeResend::BudgetExhausted
        ));
        let entry = sessions
            .get(peer.node_addr())
            .expect("session should remain");
        assert!(entry.handshake_payload().is_none());
        assert_eq!(entry.next_resend_at_ms(), 0);
        assert_eq!(
            entry.resend_count(),
            1,
            "clearing an exhausted payload must not rewrite resend history"
        );

        let missing = node_addr(0x77);
        assert!(matches!(
            sessions.prepare_handshake_resend_after_early_encrypted_data(&missing, 2),
            EarlyEncryptedHandshakeResend::NoPayload
        ));
        assert!(!sessions.record_handshake_resend(&missing, 3_000));
    }

    #[test]
    fn session_registry_owns_established_fsp_open_lookup_and_bookkeeping() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let (local_session, mut peer_sender) = make_xk_session_pair(&local, &peer);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(local_session),
            1_000,
            true,
        );
        entry.mark_established(1_000);
        entry.record_decrypt_failure();

        let endpoint_payload = b"registry runtime receive".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let counter = peer_sender.current_send_counter();
        let header = build_fsp_header(counter, 0, plaintext.len() as u16);
        let ciphertext = peer_sender
            .encrypt_with_aad(&plaintext, &header)
            .expect("test frame should encrypt");
        let mut wire = header.to_vec();
        wire.extend_from_slice(&ciphertext);
        let parsed = FspEncryptedHeader::parse(&wire).expect("test frame should parse");

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*peer.node_addr(), entry);

        let outcome = sessions.open_established_fsp_frame(
            peer.node_addr(),
            EstablishedFspReceive::new(&parsed, &wire[FSP_HEADER_SIZE..], 1_280, true, 2_000),
        );

        match outcome {
            FspFrameOutcome::Authentic(message) => {
                assert_eq!(message.source_peer().node_addr(), peer.node_addr());
                assert_eq!(
                    message.msg_type(),
                    SessionMessageType::EndpointData.to_byte()
                );
                assert_eq!(message.body(), endpoint_payload);
            }
            other => panic!("expected authentic FSP frame, got {other:?}"),
        }
        let entry = sessions
            .get(peer.node_addr())
            .expect("session should remain");
        assert_eq!(entry.consecutive_decrypt_failures(), 0);
        assert_eq!(entry.last_inbound_frame_ms(), 2_000);

        let missing = node_addr(0x77);
        let outcome = sessions.open_established_fsp_frame(
            &missing,
            EstablishedFspReceive::new(&parsed, &wire[FSP_HEADER_SIZE..], 1_280, false, 2_001),
        );
        assert!(matches!(outcome, FspFrameOutcome::UnknownSession));
    }

    #[test]
    fn authenticated_session_message_owns_endpoint_delivery_conversion() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let endpoint_payload = b"endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );

        let message = AuthenticatedSessionMessage::new(
            source_peer,
            plaintext,
            SessionMessageType::EndpointData.to_byte(),
            0,
            0x0102_0304,
        );

        assert_eq!(message.body(), endpoint_payload);
        let delivery = message.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);
    }

    #[test]
    fn authenticated_session_message_can_own_plaintext_inside_wire_buffer() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let endpoint_payload = b"buffer endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let mut buffer = b"outer-fmp-prefix".to_vec();
        let plaintext_offset = buffer.len();
        buffer.extend_from_slice(&plaintext);
        buffer.extend_from_slice(b"outer-fmp-trailer");

        let message = AuthenticatedSessionMessage::from_buffer(
            source_peer,
            buffer,
            plaintext_offset,
            plaintext.len(),
            SessionMessageType::EndpointData.to_byte(),
            0,
            0x0102_0304,
        );

        assert_eq!(message.plaintext(), plaintext);
        assert_eq!(message.body(), endpoint_payload);
        let delivery = message.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);
    }

    #[test]
    fn authenticated_session_dispatch_owns_route_ce_and_completion_facts() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"endpoint completion".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            true,
            AuthenticatedSessionMessage::new(
                source_peer,
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        assert_eq!(dispatch.source_addr(), &source_addr);
        assert_eq!(dispatch.previous_hop_addr(), &previous_hop_addr);
        assert!(dispatch.ce_flag());
        assert_eq!(
            dispatch.msg_type(),
            SessionMessageType::EndpointData.to_byte()
        );
        assert_eq!(dispatch.body(), endpoint_payload);
        assert_eq!(
            dispatch.receive_completion(),
            Some(SessionReceiveCompletion {
                source_addr,
                body_len: endpoint_payload.len()
            })
        );
        let commit = dispatch.commit();
        assert_eq!(commit.source_addr(), &source_addr);
        assert_eq!(
            commit.receive_completion(),
            Some(SessionReceiveCompletion {
                source_addr,
                body_len: endpoint_payload.len()
            })
        );
        let local = Identity::generate();
        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(source_addr, established_entry(&local, &peer));
        assert!(commit.record_receive(&mut sessions, 0x0bad_cafe));
        let entry = sessions.get(&source_addr).expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.last_activity(), 0x0bad_cafe);

        let delivery = dispatch.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);

        let report_plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::SenderReport.to_byte(),
            0,
            b"report",
        );
        let report_dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                report_plaintext,
                SessionMessageType::SenderReport.to_byte(),
                0,
                0x0102_0304,
            ),
        );
        assert_eq!(
            report_dispatch.receive_completion(),
            None,
            "MMP reports must not reset session idle/traffic counters"
        );
        let report_commit = report_dispatch.commit();
        assert_eq!(report_commit.source_addr(), &source_addr);
        assert_eq!(
            report_commit.receive_completion(),
            None,
            "MMP reports still flush pending packets without recording receive progress"
        );
        assert!(!report_commit.record_receive(&mut sessions, 0x0bad_f00d));
        let entry = sessions.get(&source_addr).expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.last_activity(), 0x0bad_cafe);
    }

    #[test]
    fn endpoint_data_fast_dispatch_finishes_receive_without_pending_flush() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"fast endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let finish = dispatch.dispatch_endpoint_data_fast(&mut node);
        assert_eq!(finish.pending_flush_dest(), None);
        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, endpoint_payload);
            }
            event => panic!("expected single endpoint data event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert!(
            !node.pending_session_traffic.has_traffic_for(&source_addr),
            "empty pending guard should keep the fast path synchronous"
        );
    }

    #[test]
    fn endpoint_data_fast_dispatch_reports_pending_flush_owner() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"fast endpoint pending".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let _endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));
        assert!(
            !node
                .pending_session_traffic
                .push_endpoint_data(source_addr, vec![0xaa], 8, 8)
                .destination_dropped()
        );

        let finish = dispatch.dispatch_endpoint_data_fast(&mut node);

        assert_eq!(finish.pending_flush_dest(), Some(source_addr));
        assert!(
            node.pending_session_traffic.has_traffic_for(&source_addr),
            "fast dispatch should report, not synchronously drain, pending traffic"
        );
    }

    #[tokio::test]
    async fn worker_direct_session_data_commits_before_endpoint_delivery() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let previous_hop = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let source_addr = *peer.node_addr();
        let endpoint_payload = b"worker decoded endpoint".to_vec();
        let plaintext_len = FSP_INNER_HEADER_SIZE + endpoint_payload.len();

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let direct = DecryptDirectSessionData::for_test(
            crate::node::decrypt_worker::DecryptFmpBookkeeping {
                source_peer: previous_hop_peer,
                transport_id: crate::transport::TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 2_000,
                packet_len: 256,
                fmp_counter: 11,
                inner_timestamp_ms: 22,
                fmp_flags: 0,
            },
            source_addr,
            previous_hop_peer,
            false,
            crate::node::session::FspReceiveSync {
                counter: 7,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 0x0102_0304,
                plaintext_len,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            endpoint_payload.len(),
            DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
                source_peer,
                endpoint_payload.clone(),
            )),
        );

        node.process_direct_session_data_from_worker(direct).await;

        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, endpoint_payload);
            }
            event => panic!("expected worker-decoded endpoint data event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.current_highest_counter(), Some(7));
    }

    #[tokio::test]
    async fn worker_direct_session_commit_updates_metadata_without_payload_bounce() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let body_len = b"already delivered".len();
        let plaintext_len = FSP_INNER_HEADER_SIZE + body_len;

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let commit = DecryptDirectSessionCommit::for_test(
            crate::node::decrypt_worker::DecryptFmpBookkeeping {
                source_peer,
                transport_id: crate::transport::TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 2_000,
                packet_len: 256,
                fmp_counter: 11,
                inner_timestamp_ms: 22,
                fmp_flags: 0,
            },
            source_addr,
            source_peer,
            false,
            crate::node::session::FspReceiveSync {
                counter: 7,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 0x0102_0304,
                plaintext_len,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            body_len,
            false,
        );

        node.process_direct_session_commit_from_worker(commit).await;

        assert!(
            endpoint_io.event_rx.try_recv().is_err(),
            "compact direct commit must not bounce payload bytes through rx_loop"
        );
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(entry.traffic_counters(), (0, 1, 0, body_len as u64));
        assert_eq!(entry.current_highest_counter(), Some(7));
    }

    #[test]
    fn session_runtime_receive_owns_decrypt_failure_recovery_gate() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        let plaintext_len = FSP_INNER_HEADER_SIZE + 32;
        let forged_ciphertext = vec![0u8; plaintext_len + crate::noise::TAG_SIZE];

        for attempt in 1..=DECRYPT_FAILURE_RECOVERY_THRESHOLD {
            let header = build_fsp_header(attempt as u64, 0, plaintext_len as u16);
            let mut wire = header.to_vec();
            wire.extend_from_slice(&forged_ciphertext);
            let parsed = FspEncryptedHeader::parse(&wire).expect("forged frame should parse");
            let outcome = SessionRuntimeReceive::new(
                &mut entry,
                &parsed,
                &wire[FSP_HEADER_SIZE..],
                1_280,
                false,
                2_000 + attempt as u64,
            )
            .open_established();

            match outcome {
                FspFrameOutcome::DecryptFailed {
                    counter,
                    consecutive,
                    recover_session,
                    ..
                } => {
                    assert_eq!(counter, attempt as u64);
                    assert_eq!(consecutive, attempt);
                    assert_eq!(
                        recover_session,
                        attempt == DECRYPT_FAILURE_RECOVERY_THRESHOLD
                    );
                }
                other => panic!("expected decrypt failure, got {other:?}"),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_wire_plan_owns_payload_sizing_and_worker_offsets() {
        use crate::node::wire::EncryptedHeader;
        use crate::node::wire::{FLAG_KEY_EPOCH, FLAG_SP, build_established_header};
        use crate::node::{PreparedFmpWorkerReservation, session::FspSendReservation};
        use crate::tree::TreeCoordinate;
        use crate::utils::index::SessionIndex;
        use ring::aead::{LessSafeKey, UnboundKey};

        fn test_cipher(byte: u8) -> LessSafeKey {
            let unbound =
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[byte; 32]).expect("test key");
            LessSafeKey::new(unbound)
        }

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let root_addr = node_addr(0x01);
        let source_coords = TreeCoordinate::from_addrs(vec![source_addr, root_addr]).unwrap();
        let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();
        let inner_plaintext = [0x55; 48];
        let fsp_counter = 0x0102_0304_0506_0708;
        let fmp_counter = 0x1112_1314_1516_1718;
        let fmp_flags = FLAG_SP | FLAG_KEY_EPOCH;
        let fsp_flags = FSP_FLAG_CP | FSP_FLAG_K;
        let fsp_header = build_fsp_header(fsp_counter, fsp_flags, inner_plaintext.len() as u16);
        let their_index = SessionIndex::new(0xA0B0_C0D0);
        let path_mtu = 1234;
        let default_ttl = 9;
        let timestamp_ms = 0x1122_3344;
        let plan = PipelinedEndpointWirePlan::new(
            &source_addr,
            &dest_addr,
            &inner_plaintext,
            Some(&source_coords),
            Some(&dest_coords),
            path_mtu,
            default_ttl,
        )
        .expect("valid pipelined endpoint plan");
        let coords_size = coords_wire_size(&source_coords) + coords_wire_size(&dest_coords);
        assert_eq!(
            plan.link_plaintext_len(),
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + coords_size + inner_plaintext.len()
        );
        assert_eq!(
            plan.fmp_payload_len() as usize,
            4 + plan.link_plaintext_len() + crate::noise::TAG_SIZE
        );
        let fmp_header =
            build_established_header(their_index, fmp_counter, fmp_flags, plan.fmp_payload_len());

        let wire = plan.build(fmp_header, fsp_header, timestamp_ms);

        assert_eq!(
            wire.link_plaintext_len,
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + coords_size + inner_plaintext.len()
        );
        assert_eq!(
            wire.fmp_inner_len,
            4 + wire.link_plaintext_len + crate::noise::TAG_SIZE
        );
        assert_eq!(
            wire.wire_capacity,
            ESTABLISHED_HEADER_SIZE + wire.fmp_inner_len + crate::noise::TAG_SIZE
        );
        assert_eq!(
            wire.wire_buf.len(),
            ESTABLISHED_HEADER_SIZE + 4 + wire.link_plaintext_len
        );

        let fmp = EncryptedHeader::parse(&wire.wire_buf).expect("FMP header parses");
        assert_eq!(fmp.receiver_idx, their_index);
        assert_eq!(fmp.counter, fmp_counter);
        assert_eq!(fmp.flags, fmp_flags);
        assert_eq!(fmp.payload_len as usize, wire.fmp_inner_len);

        let link_offset = ESTABLISHED_HEADER_SIZE + 4;
        assert_eq!(
            &wire.wire_buf[ESTABLISHED_HEADER_SIZE..link_offset],
            &timestamp_ms.to_le_bytes()
        );
        assert_eq!(
            wire.wire_buf[link_offset],
            LinkMessageType::SessionDatagram.to_byte()
        );
        assert_eq!(wire.wire_buf[link_offset + 1], default_ttl);
        assert_eq!(
            u16::from_le_bytes([
                wire.wire_buf[link_offset + 2],
                wire.wire_buf[link_offset + 3]
            ]),
            path_mtu
        );
        assert_eq!(
            &wire.wire_buf[link_offset + 4..link_offset + 20],
            source_addr.as_bytes()
        );
        assert_eq!(
            &wire.wire_buf[link_offset + 20..link_offset + 36],
            dest_addr.as_bytes()
        );

        assert_eq!(
            wire.fsp_aad_offset,
            link_offset + SESSION_DATAGRAM_HEADER_SIZE
        );
        let fsp =
            FspEncryptedHeader::parse(&wire.wire_buf[wire.fsp_aad_offset..]).expect("FSP header");
        assert_eq!(fsp.counter, fsp_counter);
        assert_eq!(fsp.flags, fsp_flags);
        assert_eq!(fsp.payload_len as usize, inner_plaintext.len());
        assert_eq!(
            wire.fsp_plaintext_offset,
            wire.fsp_aad_offset + FSP_HEADER_SIZE + coords_size
        );
        assert_eq!(&wire.wire_buf[wire.fsp_plaintext_offset..], inner_plaintext);

        let fmp_reservation = PreparedFmpWorkerReservation {
            counter: fmp_counter,
            header: fmp_header,
            cipher: test_cipher(7),
            predicted_bytes: wire.wire_capacity,
        };
        let fsp_reservation = FspSendReservation {
            counter: fsp_counter,
            header: fsp_header,
            cipher: test_cipher(8),
        };
        let worker_wire = wire.into_worker_wire(fmp_reservation, fsp_reservation);
        assert_eq!(worker_wire.fmp_counter, fmp_counter);
        assert_eq!(worker_wire.fsp_counter, fsp_counter);
        assert_eq!(
            worker_wire.fsp_seal.aad_offset,
            ESTABLISHED_HEADER_SIZE + 4 + SESSION_DATAGRAM_HEADER_SIZE
        );
        assert_eq!(
            worker_wire.fsp_seal.plaintext_offset,
            ESTABLISHED_HEADER_SIZE
                + 4
                + SESSION_DATAGRAM_HEADER_SIZE
                + FSP_HEADER_SIZE
                + coords_size
        );
        assert_eq!(
            worker_wire.wire_capacity,
            ESTABLISHED_HEADER_SIZE + plan.fmp_payload_len() as usize + crate::noise::TAG_SIZE
        );
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_dispatch_plan_owns_worker_policy_and_bookkeeping() {
        let dest_addr = node_addr(0x20);
        let relay_addr = node_addr(0x30);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let direct =
            PipelinedEndpointDispatchPlan::new(&send, dest_addr, 1234, 7, false).expect("direct");
        assert_eq!(direct.fsp_payload_len, inner_plaintext.len() as u16);
        assert!(direct.bulk_endpoint_data);
        assert!(direct.drop_on_backpressure);
        assert_eq!(direct.scheduling_weight, 7);
        let reservation = direct.fsp_reservation_input();
        assert_eq!(
            reservation,
            crate::node::FspWorkerSendReservationInput {
                flags: 0,
                payload_len: inner_plaintext.len() as u16,
                path_mtu: 1234
            }
        );
        let bookkeeping = direct.fsp_bookkeeping_input(0x0102_0304_0506_0708);
        assert_eq!(bookkeeping.data_bytes, Some(payload.len()));
        assert_eq!(bookkeeping.counter, 0x0102_0304_0506_0708);
        assert_eq!(bookkeeping.timestamp, send.timestamp);
        assert_eq!(
            bookkeeping.frame_bytes,
            inner_plaintext.len() + crate::noise::TAG_SIZE
        );
        assert_eq!(bookkeeping.touch_ms, Some(send.now_ms));
        assert_eq!(bookkeeping.next_hop, Some(dest_addr));

        let relayed =
            PipelinedEndpointDispatchPlan::new(&send, relay_addr, 1234, 7, false).expect("relay");
        assert!(relayed.bulk_endpoint_data);
        assert!(!relayed.drop_on_backpressure);

        let degraded_direct =
            PipelinedEndpointDispatchPlan::new(&send, dest_addr, 1234, 7, true).expect("degraded");
        assert!(degraded_direct.bulk_endpoint_data);
        assert!(!degraded_direct.drop_on_backpressure);

        let control_send = PipelinedEndpointSend {
            fsp_flags: FSP_FLAG_CP,
            ..send
        };
        let control = PipelinedEndpointDispatchPlan::new(&control_send, dest_addr, 1234, 7, false)
            .expect("control");
        assert!(!control.bulk_endpoint_data);
        assert!(!control.drop_on_backpressure);
    }

    #[test]
    fn session_fsp_send_plan_owns_flags_coords_wire_and_bookkeeping() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut session = make_xk_session(&local, &peer);
        let dest_addr = *peer.node_addr();
        let src_coords = crate::tree::TreeCoordinate::root(node_addr(0x11));
        let dst_coords = crate::tree::TreeCoordinate::root(node_addr(0x22));
        let inner_plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            1,
            b"hello",
        );
        let plan = SessionFspSendPlan::new(
            dest_addr,
            0x0102_0304,
            FSP_FLAG_CP | FSP_FLAG_K,
            &inner_plaintext,
            Some((&src_coords, &dst_coords)),
            SessionFspSendBookkeeping::Data {
                payload_len: 5,
                now_ms: 0x5566_7788,
            },
        );

        let counter_before = session.current_send_counter();
        let sealed = plan.seal(&mut session).expect("seal should succeed");
        assert_eq!(sealed.dest_addr(), dest_addr);
        assert_eq!(sealed.counter(), counter_before);
        assert_eq!(
            session.current_send_counter(),
            counter_before + 1,
            "sealing should consume exactly one FSP counter"
        );

        let (datagram, bookkeeping) = sealed.into_datagram(node_addr(0xaa), 7);
        assert_eq!(datagram.dest_addr, dest_addr);
        assert_eq!(datagram.ttl, 7);
        let header =
            FspEncryptedHeader::parse(&datagram.payload).expect("sealed payload has FSP header");
        assert_eq!(header.flags, FSP_FLAG_CP | FSP_FLAG_K);
        assert_eq!(header.counter, counter_before);
        assert_eq!(header.payload_len as usize, inner_plaintext.len());
        assert!(
            header.has_coords(),
            "send plan should carry coords-present flag and coords together"
        );
        let expected_coords_size = coords_wire_size(&src_coords) + coords_wire_size(&dst_coords);
        assert_eq!(
            datagram.payload.len(),
            FSP_HEADER_SIZE + expected_coords_size + inner_plaintext.len() + crate::noise::TAG_SIZE
        );
        assert_eq!(
            bookkeeping,
            FspSendBookkeepingInput::data(
                5,
                counter_before,
                0x0102_0304,
                inner_plaintext.len() + crate::noise::TAG_SIZE,
                0x5566_7788,
            )
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_send_target_owns_connected_udp_preference_and_fallback() {
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use std::net::SocketAddr;

        fn prepared(
            transport_id: TransportId,
            remote_addr: TransportAddr,
            #[cfg(any(target_os = "linux", target_os = "macos"))] connected_socket: Option<
                std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
            >,
        ) -> crate::node::FmpSendPreparation {
            crate::node::FmpSendPreparation {
                their_index: SessionIndex::new(0xA0B0_C0D0),
                transport_id,
                remote_addr,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                connected_socket,
                timestamp_ms: 123,
                flags: 0,
                payload_len: 16,
            }
        }

        let transport_id = TransportId::new(0x77);
        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );

        let fallback_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fallback_prepared = prepared(
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
        );
        assert!(
            PipelinedEndpointSendTarget::resolve(&udp, &fallback_prepared)
                .await
                .is_none(),
            "an unstarted UDP transport has no worker socket to own"
        );

        udp.start_async().await.expect("start UDP transport");
        let fallback_target = PipelinedEndpointSendTarget::resolve(&udp, &fallback_prepared)
            .await
            .expect("started UDP transport resolves numeric fallback");
        assert_eq!(fallback_target.socket_addr, fallback_addr);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(fallback_target.connected_socket.is_none());

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let peer_udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind peer udp");
            let peer_addr = peer_udp.local_addr().expect("peer udp addr");
            let connected = std::sync::Arc::new(
                crate::transport::udp::connected_peer::ConnectedPeerSocket::open(
                    "127.0.0.1:0".parse().unwrap(),
                    peer_addr,
                    1 << 20,
                    1 << 20,
                )
                .expect("open connected udp"),
            );
            let connected_prepared = prepared(
                transport_id,
                TransportAddr::from_string("invalid fallback target"),
                Some(connected.clone()),
            );
            let connected_target = PipelinedEndpointSendTarget::resolve(&udp, &connected_prepared)
                .await
                .expect("connected socket should avoid fallback resolution");
            assert_eq!(connected_target.socket_addr, peer_addr);
            assert!(std::sync::Arc::ptr_eq(
                connected_target.connected_socket.as_ref().unwrap(),
                &connected
            ));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_send_plan_owns_worker_job_and_bookkeeping_handoff() {
        use crate::node::wire::{FLAG_SP, build_established_header};
        use crate::node::{PreparedFmpWorkerReservation, session::FspSendReservation};
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use ring::aead::{LessSafeKey, UnboundKey};

        fn test_cipher(byte: u8) -> LessSafeKey {
            let unbound =
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[byte; 32]).expect("test key");
            LessSafeKey::new(unbound)
        }

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let path_mtu = 1234;
        let default_ttl = 9;
        let scheduling_weight = 7;
        let plan = PipelinedEndpointSendPlan::new(
            &source_addr,
            &send,
            dest_addr,
            path_mtu,
            default_ttl,
            scheduling_weight,
            false,
        )
        .expect("valid send plan");
        assert_eq!(
            plan.fsp_reservation_input(),
            crate::node::FspWorkerSendReservationInput {
                flags: 0,
                payload_len: inner_plaintext.len() as u16,
                path_mtu
            }
        );
        let fsp_payload_len = plan.fsp_reservation_input().payload_len;
        let expected_originated_bytes = plan.link_plaintext_len() + crate::noise::TAG_SIZE;

        let transport_id = TransportId::new(0x55);
        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fmp_prepared = crate::node::FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: plan.fmp_payload_len(),
        };
        let send_target = PipelinedEndpointSendTarget::resolve(&udp, &fmp_prepared)
            .await
            .expect("started UDP transport resolves send target");

        let fmp_counter = 0x1112_1314_1516_1718;
        let fsp_counter = 0x0102_0304_0506_0708;
        let fmp_header = build_established_header(
            fmp_prepared.their_index,
            fmp_counter,
            fmp_prepared.flags,
            plan.fmp_payload_len(),
        );
        let fsp_header = build_fsp_header(fsp_counter, send.fsp_flags, fsp_payload_len);
        let fmp_reservation = PreparedFmpWorkerReservation {
            counter: fmp_counter,
            header: fmp_header,
            cipher: test_cipher(7),
            predicted_bytes: ESTABLISHED_HEADER_SIZE
                + plan.fmp_payload_len() as usize
                + crate::noise::TAG_SIZE,
        };
        let fsp_reservation = FspSendReservation {
            counter: fsp_counter,
            header: fsp_header,
            cipher: test_cipher(8),
        };

        let prepared = plan.into_prepared_worker_send(
            &fmp_prepared,
            fmp_reservation,
            fsp_reservation,
            send_target,
            None,
        );

        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fmp_counter, fmp_counter);
        assert_eq!(prepared.fmp_timestamp_ms, fmp_prepared.timestamp_ms);
        assert_eq!(
            prepared.fmp_wire_capacity,
            ESTABLISHED_HEADER_SIZE + fmp_prepared.payload_len as usize + crate::noise::TAG_SIZE
        );
        assert_eq!(prepared.originated_bytes, expected_originated_bytes);

        assert_eq!(prepared.fsp_bookkeeping.data_bytes, Some(payload.len()));
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_counter);
        assert_eq!(prepared.fsp_bookkeeping.timestamp, send.timestamp);
        assert_eq!(
            prepared.fsp_bookkeeping.frame_bytes,
            inner_plaintext.len() + crate::noise::TAG_SIZE
        );
        assert_eq!(prepared.fsp_bookkeeping.touch_ms, Some(send.now_ms));
        assert_eq!(prepared.fsp_bookkeeping.next_hop, Some(dest_addr));

        assert_eq!(prepared.worker_job.counter, fmp_counter);
        assert!(prepared.worker_job.bulk_endpoint_data);
        assert!(prepared.worker_job.drop_on_backpressure);
        assert_eq!(prepared.worker_job.scheduling_weight, scheduling_weight);
        assert!(prepared.worker_job.queued_at.is_none());
        assert_eq!(
            &prepared.worker_job.wire_buf[..ESTABLISHED_HEADER_SIZE],
            &fmp_header
        );
        let fsp_seal = prepared.worker_job.fsp_seal.as_ref().expect("FSP seal");
        assert_eq!(fsp_seal.counter, fsp_counter);
        assert_eq!(
            fsp_seal.aad_offset,
            ESTABLISHED_HEADER_SIZE + 4 + SESSION_DATAGRAM_HEADER_SIZE
        );
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_runtime_send_plan_owns_route_and_fmp_preparation() {
        use crate::node::FmpSendPreparation;
        use crate::node::wire::FLAG_SP;
        use crate::transport::{TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let next_hop_addr = node_addr(0x30);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: FSP_FLAG_K,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let route = PipelinedEndpointRoutePlan::new(source_addr, next_hop_addr, 1234, 9, 7, false);
        let plan = route
            .build_send_plan(&send)
            .expect("route plan should build send plan");
        let fmp_payload_len = plan.fmp_payload_len();
        let transport_id = TransportId::new(0x55);
        let prepared = FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: fmp_payload_len,
        };
        let bad_prepared = FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: fmp_payload_len - 1,
        };

        let snapshot = crate::node::PeerRuntimeSendSnapshot::new(next_hop_addr, prepared, true);
        let bad_snapshot =
            crate::node::PeerRuntimeSendSnapshot::new(next_hop_addr, bad_prepared, true);

        let runtime = PipelinedEndpointRuntimeSendPlan::from_parts(route, plan, snapshot)
            .expect("matching route/send/FMP preparation should form runtime plan");

        assert_eq!(runtime.source_addr(), source_addr);
        assert_eq!(runtime.dest_addr(), dest_addr);
        assert_eq!(runtime.next_hop_addr(), next_hop_addr);
        assert_eq!(runtime.transport_id(), transport_id);
        assert_eq!(runtime.fmp_payload_len(), fmp_payload_len);
        assert_eq!(
            runtime.fsp_reservation_input(),
            crate::node::FspWorkerSendReservationInput {
                flags: FSP_FLAG_K,
                payload_len: inner_plaintext.len() as u16,
                path_mtu: 1234,
            }
        );
        assert_eq!(
            runtime.fmp_prepared().payload_len,
            runtime.fmp_payload_len()
        );
        assert_eq!(runtime.fmp_prepared().timestamp_ms, 0x0102_0304);

        let (route, plan) = runtime.into_parts_for_test();
        assert!(matches!(
            PipelinedEndpointRuntimeSendPlan::from_parts(route, plan, bad_snapshot),
            Err(PipelinedEndpointRuntimeSendPlanError::FmpPayloadMismatch {
                prepared_payload_len,
                plan_payload_len,
            }) if prepared_payload_len == fmp_payload_len - 1
                && plan_payload_len == fmp_payload_len
        ));
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_runtime_send_plan_owns_peer_route_snapshot_handoff() {
        use crate::node::wire::FLAG_SP;
        use crate::transport::{TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let next_hop_addr = node_addr(0x30);
        let other_next_hop_addr = node_addr(0x31);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: FSP_FLAG_K,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let route = PipelinedEndpointRoutePlan::new(source_addr, next_hop_addr, 1234, 9, 7, false);
        let plan = route
            .build_send_plan(&send)
            .expect("route plan should build send plan");
        let fmp_payload_len = plan.fmp_payload_len();
        let transport_id = TransportId::new(0x55);
        let remote_addr = TransportAddr::from_string("127.0.0.1:9");
        let route_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            next_hop_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr.clone(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );

        let runtime =
            PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(route, plan, route_snapshot)
                .expect("route snapshot should form runtime plan for the same next hop");

        assert_eq!(runtime.next_hop_addr(), next_hop_addr);
        assert_eq!(runtime.transport_id(), transport_id);
        assert_eq!(runtime.fmp_payload_len(), fmp_payload_len);
        assert_eq!(runtime.fmp_prepared().remote_addr, remote_addr);
        assert_eq!(runtime.fmp_prepared().flags, FLAG_SP);
        assert_eq!(runtime.fmp_prepared().timestamp_ms, 0x0102_0304);
        assert!(
            runtime.fmp_worker_send_available(),
            "runtime plan should carry worker availability derived from route snapshot"
        );

        let (route, plan) = runtime.into_parts_for_test();
        let mismatched_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            other_next_hop_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            TransportAddr::from_string("127.0.0.1:10"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );
        assert!(matches!(
            PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
                route,
                plan,
                mismatched_snapshot,
            ),
            Err(PipelinedEndpointRuntimeSendPlanError::RoutePeerMismatch {
                route_next_hop,
                peer_snapshot_addr,
            }) if route_next_hop == next_hop_addr
                && peer_snapshot_addr == other_next_hop_addr
        ));
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_peer_runtime_route_owns_snapshot_route_policy_and_send_plan() {
        use crate::node::wire::FLAG_SP;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let transport_id = TransportId::new(0x55);
        let route_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );
        let (packet_tx, _packet_rx) = packet_channel(4);
        let transport = TransportHandle::Udp(UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        ));
        let runtime_route =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false);
        assert_eq!(runtime_route.next_hop_addr(), dest_addr);
        assert_eq!(runtime_route.scheduling_weight(), 7);

        let runtime = runtime_route
            .into_runtime_send_plan(&send, &transport)
            .expect("peer runtime route owner should build the runtime send plan");

        assert_eq!(runtime.source_addr(), source_addr);
        assert_eq!(runtime.dest_addr(), dest_addr);
        assert_eq!(runtime.next_hop_addr(), dest_addr);
        assert_eq!(runtime.transport_id(), transport_id);
        assert_eq!(runtime.fmp_prepared().flags, FLAG_SP);
        assert!(runtime.fmp_worker_send_available());
        assert_eq!(
            runtime.fsp_reservation_input(),
            crate::node::FspWorkerSendReservationInput {
                flags: 0,
                payload_len: inner_plaintext.len() as u16,
                path_mtu: 1234,
            }
        );
        assert!(
            runtime.drop_on_backpressure(),
            "direct bulk endpoint traffic should keep explicit bulk-drop policy"
        );
        assert_eq!(runtime.scheduling_weight(), 7);

        let degraded_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );
        let degraded_runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, degraded_snapshot, 9, 7, true)
                .into_runtime_send_plan(&send, &transport)
                .expect("degraded direct route should still build runtime send plan");
        assert!(
            !degraded_runtime.drop_on_backpressure(),
            "blocked direct payload routes must not silently use bulk-drop policy"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_peer_runtime_route_request_owns_next_hop_snapshot_and_policy() {
        use crate::PeerIdentity;
        use crate::node::encrypt_worker;
        use crate::peer::ActivePeer;
        use crate::transport::{LinkId, TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x55);
        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string("127.0.0.1:9"),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

        let request = PipelinedEndpointPeerRuntimeRouteRequest::new(
            *node.node_addr(),
            dest_addr,
            Node::now_ms(),
            node.config.node.session.default_ttl,
        );
        let runtime_route = request
            .resolve(&mut node)
            .expect("route request should resolve configured active peer");

        assert_eq!(runtime_route.next_hop_addr(), dest_addr);
        assert_eq!(runtime_route.transport_id(), transport_id);
        assert_eq!(
            runtime_route.scheduling_weight(),
            encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
            "route request should capture configured-peer scheduling weight"
        );
        assert_eq!(runtime_route.default_ttl(), 13);
        assert!(
            !runtime_route.direct_path_blocks_direct_payload(),
            "healthy direct route should keep the explicit bulk-drop policy available"
        );

        let missing_dest = node_addr(0x99);
        assert!(matches!(
            PipelinedEndpointPeerRuntimeRouteRequest::new(
                *node.node_addr(),
                missing_dest,
                Node::now_ms(),
                node.config.node.session.default_ttl,
            )
            .resolve(&mut node),
            Err(PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr })
                if dest_addr == missing_dest
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_peer_runtime_send_request_owns_route_request_and_dispatch() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
                .is_none()
        );

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointPeerRuntimeSendRequest::new(
            *node.node_addr(),
            send,
            node.config.node.session.default_ttl,
        )
        .resolve_dispatch(&mut node)
        .await
        .expect("peer runtime send request should route and prepare dispatch")
        .expect("established direct peer should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            dispatch.fsp_reservation_input().path_mtu,
            1234,
            "send request should derive path MTU from the resolved peer transport"
        );
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "send request should reserve exactly one FSP counter"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "send request should reserve exactly one FMP counter"
        );

        let missing_dest = node_addr(0x99);
        let missing_send = PipelinedEndpointSend {
            dest_addr: &missing_dest,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        assert!(matches!(
            PipelinedEndpointPeerRuntimeSendRequest::new(
                *node.node_addr(),
                missing_send,
                node.config.node.session.default_ttl,
            )
            .resolve_dispatch(&mut node)
            .await,
            Err(PipelinedEndpointPeerRuntimeSendRequestError::Route(
                PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr }
            )) if dest_addr == missing_dest
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_peer_runtime_send_request_owns_commit_bookkeeping() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
                .is_none()
        );

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();
        let session_traffic_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .traffic_counters();
        let link_stats_before = node
            .peers
            .get(&dest_addr)
            .expect("active peer exists")
            .link_stats()
            .clone();
        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + inner_plaintext.len();
        let expected_originated_bytes = link_plaintext_len + crate::noise::TAG_SIZE;
        let expected_fmp_wire_capacity =
            ESTABLISHED_HEADER_SIZE + 4 + link_plaintext_len + crate::noise::TAG_SIZE * 2;

        let workers = crate::node::encrypt_worker::EncryptWorkerPool::spawn(1);
        let sent = PipelinedEndpointPeerRuntimeSendRequest::new(
            *node.node_addr(),
            send,
            node.config.node.session.default_ttl,
        )
        .execute(&mut node, &workers)
        .await
        .expect("peer runtime send request should commit prepared dispatch");

        assert!(sent, "established direct peer should dispatch");
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "send request should reserve exactly one FSP counter"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "send request should reserve exactly one FMP counter"
        );
        let session = node.sessions.get(&dest_addr).expect("session still exists");
        assert_eq!(
            session.traffic_counters().0,
            session_traffic_before.0 + 1,
            "send request commit should record FSP data packet bookkeeping"
        );
        assert_eq!(
            session.traffic_counters().2,
            session_traffic_before.2 + payload.len() as u64,
            "send request commit should record endpoint payload bytes"
        );
        assert_eq!(
            session.last_outbound_next_hop(),
            Some(dest_addr),
            "send request commit should record outbound next hop"
        );
        let link_stats_after = node
            .peers
            .get(&dest_addr)
            .expect("active peer still exists")
            .link_stats();
        assert_eq!(
            link_stats_after.packets_sent,
            link_stats_before.packets_sent + 1
        );
        assert_eq!(
            link_stats_after.bytes_sent,
            link_stats_before.bytes_sent + expected_fmp_wire_capacity as u64,
            "send request commit should record FMP wire capacity against the peer link"
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 1
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + expected_originated_bytes as u64
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn peer_runtime_endpoint_send_facade_owns_route_dispatch_and_commit() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x56);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
                .is_none()
        );

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();
        let session_traffic_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .traffic_counters();
        let link_stats_before = node
            .peers
            .get(&dest_addr)
            .expect("active peer exists")
            .link_stats()
            .clone();
        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + inner_plaintext.len();
        let expected_originated_bytes = link_plaintext_len + crate::noise::TAG_SIZE;
        let expected_fmp_wire_capacity =
            ESTABLISHED_HEADER_SIZE + 4 + link_plaintext_len + crate::noise::TAG_SIZE * 2;

        let workers = crate::node::encrypt_worker::EncryptWorkerPool::spawn(1);
        let sent = node
            .execute_peer_runtime_endpoint_send(send, &workers)
            .await
            .expect("peer runtime endpoint facade should route, reserve, and commit");

        assert!(sent, "established direct peer should dispatch");
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "peer runtime facade should reserve exactly one FSP counter"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "peer runtime facade should reserve exactly one FMP counter"
        );
        let session = node.sessions.get(&dest_addr).expect("session still exists");
        assert_eq!(
            session.traffic_counters().0,
            session_traffic_before.0 + 1,
            "peer runtime facade should record FSP data packet bookkeeping"
        );
        assert_eq!(
            session.traffic_counters().2,
            session_traffic_before.2 + payload.len() as u64,
            "peer runtime facade should record endpoint payload bytes"
        );
        assert_eq!(
            session.last_outbound_next_hop(),
            Some(dest_addr),
            "peer runtime facade should record outbound next hop"
        );
        let link_stats_after = node
            .peers
            .get(&dest_addr)
            .expect("active peer still exists")
            .link_stats();
        assert_eq!(
            link_stats_after.packets_sent,
            link_stats_before.packets_sent + 1
        );
        assert_eq!(
            link_stats_after.bytes_sent,
            link_stats_before.bytes_sent + expected_fmp_wire_capacity as u64,
            "peer runtime facade should record FMP wire capacity against the peer link"
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 1
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + expected_originated_bytes as u64
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn peer_runtime_endpoint_send_reuses_resolved_route_for_multiple_payloads() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x56);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
                .is_none()
        );

        let route = node
            .resolve_peer_runtime_endpoint_route(dest_addr, Node::now_ms())
            .expect("established direct peer should resolve once for a batch");
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();
        let session_traffic_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .traffic_counters();
        let link_stats_before = node
            .peers
            .get(&dest_addr)
            .expect("active peer exists")
            .link_stats()
            .clone();
        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + inner_plaintext.len();
        let expected_originated_bytes = link_plaintext_len + crate::noise::TAG_SIZE;
        let expected_fmp_wire_capacity =
            ESTABLISHED_HEADER_SIZE + 4 + link_plaintext_len + crate::noise::TAG_SIZE * 2;

        let workers = crate::node::encrypt_worker::EncryptWorkerPool::spawn(1);
        for offset in 0..2 {
            let send = PipelinedEndpointSend {
                dest_addr: &dest_addr,
                payload: &payload,
                now_ms: 0x1122_3344 + offset,
                timestamp: 0x5566_7788 + offset as u32,
                fsp_flags: 0,
                inner_plaintext: &inner_plaintext,
                my_coords: None,
                dest_coords: None,
            };
            let sent = node
                .execute_peer_runtime_endpoint_send_with_route(send, &route, &workers)
                .await
                .expect("reused endpoint route should dispatch");
            assert!(sent, "reused route should dispatch packet {offset}");
        }

        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 2,
            "reused route should still reserve one FSP counter per payload"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 2,
            "reused route should still reserve one FMP counter per payload"
        );
        let session = node.sessions.get(&dest_addr).expect("session still exists");
        assert_eq!(session.traffic_counters().0, session_traffic_before.0 + 2);
        assert_eq!(
            session.traffic_counters().2,
            session_traffic_before.2 + (payload.len() as u64 * 2)
        );
        assert_eq!(session.last_outbound_next_hop(), Some(dest_addr));
        let link_stats_after = node
            .peers
            .get(&dest_addr)
            .expect("active peer still exists")
            .link_stats();
        assert_eq!(
            link_stats_after.packets_sent,
            link_stats_before.packets_sent + 2
        );
        assert_eq!(
            link_stats_after.bytes_sent,
            link_stats_before.bytes_sent + expected_fmp_wire_capacity as u64 * 2
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 2
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + expected_originated_bytes as u64 * 2
        );
    }

    #[cfg(unix)]
    #[test]
    fn session_datagram_runtime_route_owns_next_hop_path_mtu_and_bookkeeping() {
        use crate::PeerIdentity;
        use crate::config::RoutingMode;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportHandle, TransportId};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let dest = Identity::generate();
        let transit = Identity::generate();
        let transit_identity = PeerIdentity::from_pubkey_full(transit.pubkey_full());
        let dest_addr = *dest.node_addr();
        let transit_addr = *transit_identity.node_addr();
        let transport_id = TransportId::new(0x57);

        let mut config = crate::config::Config::new();
        config.node.routing.mode = RoutingMode::ReplyLearned;
        let mut node = Node::with_identity(local, config).expect("node");

        let mut session = established_entry(&node.identity, &dest);
        session.mark_established(0x1000);
        session.init_mmp(&node.config.node.session_mmp);
        assert_eq!(
            session.mmp().expect("session mmp").path_mtu.current_mtu(),
            u16::MAX
        );
        assert!(node.sessions.insert(dest_addr, session).is_none());

        let active_peer = ActivePeer::with_session(
            transit_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &transit),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string("127.0.0.1:9"),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(transit_addr, active_peer);
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
                .is_none()
        );
        node.learn_reverse_route(dest_addr, transit_addr);

        let mut datagram = SessionDatagram::new(
            *node.node_addr(),
            dest_addr,
            vec![SessionMessageType::DataPacket.to_byte(), 0, 0, 0],
        )
        .with_ttl(9);
        let route = node
            .resolve_session_datagram_runtime_route(&mut datagram)
            .expect("learned transit route should resolve");

        assert_eq!(route.dest_addr(), dest_addr);
        assert_eq!(route.next_hop_addr(), transit_addr);
        assert_eq!(route.path_mtu(), 1234);
        assert!(
            route.source_mmp_seeded(),
            "route owner should seed the session source-side MMP path MTU"
        );
        assert_eq!(
            datagram.path_mtu, 1234,
            "route owner should min-fold the outgoing transport MTU into the datagram"
        );
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .and_then(|entry| entry.mmp())
                .expect("session mmp")
                .path_mtu
                .current_mtu(),
            1234
        );

        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let encoded_len = datagram.encode().len();
        route.record_success(&mut node, encoded_len);
        let session = node.sessions.get(&dest_addr).expect("session exists");
        assert_eq!(
            session.last_outbound_next_hop(),
            Some(transit_addr),
            "route owner should record the successful outbound next hop"
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 1
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + encoded_len as u64
        );

        let route = node
            .resolve_session_datagram_runtime_route(&mut datagram)
            .expect("learned transit route should still resolve");
        route.record_failure(&mut node);
        let snapshot = node.learned_route_table_snapshot(Node::now_ms());
        let learned = snapshot
            .destinations
            .iter()
            .find(|dest| dest.destination == dest_addr.to_string())
            .and_then(|dest| {
                dest.routes
                    .iter()
                    .find(|route| route.next_hop == transit_addr.to_string())
            })
            .expect("learned transit route should remain visible");
        assert_eq!(
            learned.failures, 1,
            "route owner should record send failure against the selected learned next hop"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_peer_runtime_send_owns_transport_path_mtu_route_plan_and_runtime_dispatch()
     {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use std::collections::HashMap;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let source_addr = node_addr(0x10);
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(dest_addr, established_entry(&local, &peer))
                .is_none()
        );

        let mut peers = crate::node::PeerLifecycleRegistry::default();
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&local, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &crate::mmp::MmpConfig::default(),
            Some([0x02; 8]),
        );
        peers.insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");

        let mut transports = HashMap::new();
        assert!(
            transports
                .insert(transport_id, crate::transport::TransportHandle::Udp(udp))
                .is_none()
        );

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot");
        let runtime_route =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false);

        let fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointPeerRuntimeSend::new(runtime_route, send)
            .resolve_dispatch(&transports, &mut sessions, &mut peers)
            .await
            .expect("peer runtime send owner should build runtime plan and dispatch")
            .expect("established peer runtime send should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            dispatch.fsp_reservation_input().path_mtu,
            1234,
            "peer runtime send owner should derive path MTU from the selected transport"
        );
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "peer runtime send owner should consume exactly one FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "peer runtime send owner should consume exactly one FMP counter"
        );

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_before);
        assert_eq!(prepared.fmp_counter, fmp_before);

        let missing_transport_send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let missing_transport_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0x2020),
            TransportId::new(0x99),
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            0,
            true,
        );
        let missing_transport_route = PipelinedEndpointPeerRuntimeRoute::new(
            source_addr,
            missing_transport_snapshot,
            9,
            7,
            false,
        );

        assert!(matches!(
            PipelinedEndpointPeerRuntimeSend::new(
                missing_transport_route,
                missing_transport_send,
            )
            .resolve_dispatch(&transports, &mut sessions, &mut peers)
            .await,
            Err(PipelinedEndpointPeerRuntimeSendError::RuntimeSend(
                PipelinedEndpointRuntimeSendError::TransportNotFound(id),
            )) if id == TransportId::new(0x99)
        ));
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after missing transport")
                .send_counter(),
            fsp_before + 1,
            "missing transport must fail before consuming another FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after missing transport")
                .current_send_counter(),
            fmp_before + 1,
            "missing transport must fail before consuming another FMP counter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_runtime_send_owns_transport_target_and_reservation_handoff() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use std::collections::HashMap;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let source_addr = node_addr(0x10);
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(dest_addr, established_entry(&local, &peer))
                .is_none()
        );

        let mut peers = crate::node::PeerLifecycleRegistry::default();
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&local, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &crate::mmp::MmpConfig::default(),
            Some([0x02; 8]),
        );
        peers.insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");

        let mut transports = HashMap::new();
        assert!(
            transports
                .insert(transport_id, crate::transport::TransportHandle::Udp(udp))
                .is_none()
        );

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot");
        let transport = transports
            .get(&transport_id)
            .expect("transport should exist for runtime plan");
        let runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false)
                .into_runtime_send_plan(&send, transport)
                .expect("runtime route should build send plan");

        let fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointRuntimeSend::new(runtime)
            .resolve_dispatch(&transports, &mut sessions, &mut peers)
            .await
            .expect("runtime send owner should resolve transport and reserve")
            .expect("established runtime send should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "runtime send owner should consume exactly one FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "runtime send owner should consume exactly one FMP counter"
        );

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_before);
        assert_eq!(prepared.fmp_counter, fmp_before);

        let missing_transport_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0x2020),
            TransportId::new(0x99),
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            0,
            true,
        );
        let missing_transport_route =
            PipelinedEndpointRoutePlan::new(source_addr, dest_addr, 1234, 9, 7, false);
        let missing_transport_plan = missing_transport_route
            .build_send_plan(&send)
            .expect("missing-transport send plan should build");
        let missing_transport_runtime = PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
            missing_transport_route,
            missing_transport_plan,
            missing_transport_snapshot,
        )
        .expect("missing-transport runtime should still build send plan");

        assert!(matches!(
            PipelinedEndpointRuntimeSend::new(missing_transport_runtime)
                .resolve_dispatch(&transports, &mut sessions, &mut peers)
                .await,
            Err(PipelinedEndpointRuntimeSendError::TransportNotFound(id))
                if id == TransportId::new(0x99)
        ));
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after missing transport")
                .send_counter(),
            fsp_before + 1,
            "missing transport must fail before consuming another FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after missing transport")
                .current_send_counter(),
            fmp_before + 1,
            "missing transport must fail before consuming another FMP counter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_runtime_send_attempt_owns_target_and_reservations() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let source_addr = node_addr(0x10);
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(dest_addr, established_entry(&local, &peer))
                .is_none()
        );

        let mut peers = crate::node::PeerLifecycleRegistry::default();
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&local, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &crate::mmp::MmpConfig::default(),
            Some([0x02; 8]),
        );
        peers.insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        let transport = TransportHandle::Udp(udp);
        let TransportHandle::Udp(udp) = &transport else {
            unreachable!("test transport is UDP");
        };

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot");
        let runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false)
                .into_runtime_send_plan(&send, &transport)
                .expect("runtime route should build send plan");
        let send_target = runtime
            .resolve_send_target(&udp)
            .await
            .expect("started UDP transport resolves send target");

        let fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointRuntimeSendAttempt::new(runtime, send_target)
            .reserve(&mut sessions, &mut peers)
            .expect("runtime send attempt should reserve from both registries")
            .expect("established runtime send attempt should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "attempt should consume exactly one FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "attempt should consume exactly one FMP counter"
        );

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_before);
        assert_eq!(prepared.fmp_counter, fmp_before);
        assert_eq!(prepared.worker_job.counter, fmp_before);

        let blocked_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            0,
            false,
        );
        let blocked_runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, blocked_snapshot, 9, 7, false)
                .into_runtime_send_plan(&send, &transport)
                .expect("blocked worker runtime should still build send plan");
        let blocked_target = blocked_runtime
            .resolve_send_target(&udp)
            .await
            .expect("started UDP transport resolves blocked send target");

        assert!(
            PipelinedEndpointRuntimeSendAttempt::new(blocked_runtime, blocked_target)
                .reserve(&mut sessions, &mut peers)
                .expect("unavailable worker is a recoverable no-dispatch result")
                .is_none()
        );
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after blocked attempt")
                .send_counter(),
            fsp_before + 1,
            "blocked attempt must not consume another FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after blocked attempt")
                .current_send_counter(),
            fmp_before + 1,
            "blocked attempt must not consume another FMP counter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_runtime_dispatch_owns_target_reservations_and_prepared_send() {
        use crate::node::wire::{FLAG_SP, build_established_header};
        use crate::node::{PreparedFmpWorkerReservation, session::FspSendReservation};
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use ring::aead::{LessSafeKey, UnboundKey};

        fn test_cipher(byte: u8) -> LessSafeKey {
            let unbound =
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[byte; 32]).expect("test key");
            LessSafeKey::new(unbound)
        }

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let next_hop_addr = node_addr(0x30);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let route = PipelinedEndpointRoutePlan::new(source_addr, next_hop_addr, 1234, 9, 7, false);
        let plan = route
            .build_send_plan(&send)
            .expect("route plan should build send plan");
        let expected_originated_bytes = plan.link_plaintext_len() + crate::noise::TAG_SIZE;
        let expected_fsp_reservation = plan.fsp_reservation_input();

        let transport_id = TransportId::new(0x55);
        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fmp_prepared = crate::node::FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: plan.fmp_payload_len(),
        };
        let snapshot = crate::node::PeerRuntimeSendSnapshot::new(next_hop_addr, fmp_prepared, true);
        let runtime = PipelinedEndpointRuntimeSendPlan::from_parts(route, plan, snapshot)
            .expect("matching route/send/FMP preparation should form runtime plan");

        let send_target = runtime
            .resolve_send_target(&udp)
            .await
            .expect("started UDP transport resolves send target");
        let fmp_counter = 0x1112_1314_1516_1718;
        let fsp_counter = 0x0102_0304_0506_0708;
        let fmp_header = build_established_header(
            runtime.fmp_prepared().their_index,
            fmp_counter,
            runtime.fmp_prepared().flags,
            runtime.fmp_payload_len(),
        );
        let fsp_header = build_fsp_header(
            fsp_counter,
            send.fsp_flags,
            expected_fsp_reservation.payload_len,
        );
        let fmp_reservation = PreparedFmpWorkerReservation {
            counter: fmp_counter,
            header: fmp_header,
            cipher: test_cipher(7),
            predicted_bytes: ESTABLISHED_HEADER_SIZE
                + runtime.fmp_payload_len() as usize
                + crate::noise::TAG_SIZE,
        };
        let fsp_reservation = FspSendReservation {
            counter: fsp_counter,
            header: fsp_header,
            cipher: test_cipher(8),
        };

        let dispatch = PipelinedEndpointRuntimeSendDispatch::new(
            runtime,
            send_target,
            fmp_reservation,
            fsp_reservation,
        );
        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), next_hop_addr);
        assert_eq!(dispatch.fsp_reservation_input(), expected_fsp_reservation);

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, next_hop_addr);
        assert_eq!(prepared.fmp_counter, fmp_counter);
        assert_eq!(prepared.fmp_timestamp_ms, 0x0102_0304);
        assert_eq!(prepared.originated_bytes, expected_originated_bytes);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_counter);
        assert_eq!(prepared.fsp_bookkeeping.next_hop, Some(next_hop_addr));
        assert_eq!(prepared.worker_job.counter, fmp_counter);
        assert!(prepared.worker_job.bulk_endpoint_data);
        assert!(!prepared.worker_job.drop_on_backpressure);
        assert_eq!(prepared.worker_job.scheduling_weight, 7);
        assert!(prepared.worker_job.queued_at.is_none());
        assert_eq!(
            &prepared.worker_job.wire_buf[..ESTABLISHED_HEADER_SIZE],
            &fmp_header
        );
    }

    #[test]
    fn pending_rekey_tiebreak_keeps_local_initiator_only_when_smaller() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        entry.set_pending_session(make_xk_session(&local, &peer));

        assert!(pending_rekey_wins_tiebreak(
            &node_addr(0x01),
            &node_addr(0x02),
            &entry
        ));
        assert!(!pending_rekey_wins_tiebreak(
            &node_addr(0x02),
            &node_addr(0x01),
            &entry
        ));
    }

    #[test]
    fn pending_rekey_tiebreak_does_not_keep_responder_pending() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_responder(local.keypair());
        entry.set_rekey_state(rekey, false);
        entry.set_pending_session(make_xk_session(&peer, &local));

        assert!(!pending_rekey_wins_tiebreak(
            &node_addr(0x01),
            &node_addr(0x02),
            &entry
        ));
    }

    #[test]
    fn duplicate_rekey_responder_ack_only_for_responder_in_progress() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let ack_payload = vec![0x42, 0x43];
        let rekey = HandshakeState::new_xk_responder(local.keypair());
        entry.set_rekey_state(rekey, false);
        entry.set_handshake_payload(ack_payload.clone(), 2000);

        assert_eq!(
            duplicate_rekey_responder_ack(&entry),
            Some(ack_payload),
            "a rekey responder awaiting msg3 should replay its SessionAck"
        );

        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        assert!(
            duplicate_rekey_responder_ack(&entry).is_none(),
            "local rekey initiators still use the dual-initiation tiebreak"
        );
    }

    #[test]
    fn decrypt_failure_recovery_rekey_requires_threshold_and_no_pending_rekey() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);

        assert!(!should_start_decrypt_failure_rekey(
            &entry,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD - 1
        ));
        assert!(should_start_decrypt_failure_rekey(
            &entry,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD
        ));

        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        assert!(!should_start_decrypt_failure_rekey(
            &entry,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD
        ));
        entry.abandon_rekey();

        entry.set_pending_session(make_xk_session(&local, &peer));
        assert!(!should_start_decrypt_failure_rekey(
            &entry,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD
        ));
    }

    #[test]
    fn stale_previous_epoch_failure_is_ignored_only_during_drain() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);

        let old_k_bit = entry.current_k_bit();
        assert!(!should_ignore_stale_epoch_drain_failure(&entry, old_k_bit));

        entry.set_pending_session(make_xk_session(&local, &peer));
        assert!(!should_ignore_stale_epoch_drain_failure(&entry, old_k_bit));

        assert!(entry.cutover_to_new_session(2000));
        assert_ne!(entry.current_k_bit(), old_k_bit);
        assert!(should_ignore_stale_epoch_drain_failure(&entry, old_k_bit));
        assert!(!should_ignore_stale_epoch_drain_failure(
            &entry,
            entry.current_k_bit()
        ));

        entry.complete_drain();
        assert!(!should_ignore_stale_epoch_drain_failure(&entry, old_k_bit));
    }

    #[test]
    fn recovery_rekey_keeps_old_session_usable_until_and_after_cutover() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let aad = b"fsp-test-aad";

        let (mut old_sender, old_receiver) = make_xk_session_pair(&peer, &local);
        let (mut new_sender, new_receiver) = make_xk_session_pair(&peer, &local);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(old_receiver),
            1000,
            false,
        );

        // Recovery starts as an in-place rekey. The old session must remain
        // current and usable while the replacement XK handshake is in flight.
        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        let (counter, ciphertext) =
            encrypt_frame(&mut old_sender, b"old packet while rekey pending", aad);
        assert_eq!(
            decrypt_current(&mut entry, &ciphertext, counter, aad).unwrap(),
            b"old packet while rekey pending"
        );

        // Once the new session is ready but before K-bit cutover, traffic
        // still uses the old session.
        entry.set_pending_session(new_receiver);
        let (counter, ciphertext) =
            encrypt_frame(&mut old_sender, b"old packet before cutover", aad);
        assert_eq!(
            decrypt_current(&mut entry, &ciphertext, counter, aad).unwrap(),
            b"old packet before cutover"
        );

        // After cutover, stale old-session packets are accepted through the
        // previous-session drain slot, while new-session packets decrypt on
        // the promoted current session.
        assert!(entry.cutover_to_new_session(2000));
        let (old_counter, old_ciphertext) =
            encrypt_frame(&mut old_sender, b"old packet after cutover", aad);
        assert!(decrypt_current(&mut entry, &old_ciphertext, old_counter, aad).is_err());
        assert_eq!(
            entry
                .previous_noise_session_mut()
                .expect("old session should be retained for drain")
                .decrypt_with_replay_check_and_aad(&old_ciphertext, old_counter, aad)
                .unwrap(),
            b"old packet after cutover"
        );

        let (new_counter, new_ciphertext) =
            encrypt_frame(&mut new_sender, b"new packet after cutover", aad);
        assert_eq!(
            decrypt_current(&mut entry, &new_ciphertext, new_counter, aad).unwrap(),
            b"new packet after cutover"
        );
    }
}
