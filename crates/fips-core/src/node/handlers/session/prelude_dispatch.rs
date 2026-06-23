use crate::discovery::nostr::{TraversalAnswer, TraversalOffer};
use crate::mmp::report::ReceiverReport;
use crate::mmp::{MAX_SESSION_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS, MmpMode};
use crate::node::decrypt_worker::{
    DecryptAuthenticatedFmpReceive, DecryptAuthenticatedSession, DecryptDirectSessionCommit,
    DecryptDirectSessionData, DecryptDirectSessionDelivery, DecryptFspFailureReport,
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
use crate::transport::PacketBuffer;
use crate::upper::icmp::FIPS_OVERHEAD;
use crate::{NodeAddr, PeerIdentity};
use secp256k1::PublicKey;
use std::borrow::Cow;
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
    buffer: PacketBuffer,
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
        plaintext: impl Into<PacketBuffer>,
        msg_type: u8,
        inner_flags_byte: u8,
        timestamp: u32,
    ) -> Self {
        let plaintext = plaintext.into();
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
        buffer: impl Into<PacketBuffer>,
        plaintext_offset: usize,
        plaintext_len: usize,
        msg_type: u8,
        inner_flags_byte: u8,
        timestamp: u32,
    ) -> Self {
        let buffer = buffer.into();
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
        // endpoint body to the front of the existing packet buffer and
        // truncate the trailing wire bytes instead of allocating a fresh
        // payload Vec.
        let body_offset = self.plaintext_offset + FSP_INNER_HEADER_SIZE;
        let body_len = self.body_len();
        self.buffer.keep_range(body_offset, body_len);
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
    previous_hop_addr: NodeAddr,
    body_len: usize,
    direct_path: bool,
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
                previous_hop_addr: self.previous_hop_addr,
                body_len: self.message.body_len(),
                direct_path: self.previous_hop_addr == self.source_addr,
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
        self.finish_receive_at(node, Node::now_ms())
    }

    fn finish_receive_at(&self, node: &mut Node, now_ms: u64) -> SessionDispatchFinish {
        // Only application data resets the idle timer and traffic counters —
        // MMP reports (SenderReport, ReceiverReport, PathMtuNotification) do not.
        let receive_recorded = self.record_receive(&mut node.sessions, now_ms);
        if receive_recorded
            && let Some(completion) = self.receive_completion
        {
            if let Some(peer) = node.peers.get_mut(&completion.previous_hop_addr) {
                peer.touch(now_ms);
            }

            if completion.direct_path
                && node.clear_session_direct_path_degraded(&completion.source_addr)
            {
                debug!(
                    src = %node.peer_display_name(&completion.source_addr),
                    "Authenticated direct endpoint data restored direct payload routing"
                );
            }

            let retry_peer = if completion.direct_path {
                completion.source_addr
            } else {
                completion.previous_hop_addr
            };
            node.clear_retry_unless_direct_refresh_needed(&retry_peer);
        }

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
#[derive(Clone, Copy)]
struct PipelinedEndpointSend<'a> {
    dest_addr: &'a NodeAddr,
    payload: &'a EndpointDataPayload,
    now_ms: u64,
    timestamp: u32,
    fsp_flags: u8,
    body: PipelinedEndpointWireBody<'a>,
    my_coords: Option<&'a crate::tree::TreeCoordinate>,
    dest_coords: Option<&'a crate::tree::TreeCoordinate>,
}

struct PreparedEndpointSessionMeta {
    dest_addr: NodeAddr,
    now_ms: u64,
    timestamp: u32,
    msg_type: u8,
    inner_flags: u8,
    fsp_flags: u8,
    my_coords: Option<crate::tree::TreeCoordinate>,
    dest_coords: Option<crate::tree::TreeCoordinate>,
}

struct PreparedEndpointSessionData<'a> {
    meta: PreparedEndpointSessionMeta,
    payload: &'a EndpointDataPayload,
}

struct PreparedOwnedEndpointSessionData {
    meta: PreparedEndpointSessionMeta,
    payload: EndpointDataPayload,
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

#[derive(Clone, Copy)]
enum PipelinedEndpointWireBody<'a> {
    #[cfg_attr(not(test), allow(dead_code))]
    InnerPlaintext(&'a [u8]),
    EndpointPayload {
        timestamp: u32,
        msg_type: u8,
        inner_flags: u8,
        payload: &'a [u8],
    },
}

#[cfg(unix)]
struct PipelinedEndpointWirePlan<'a> {
    source_addr: NodeAddr,
    dest_addr: NodeAddr,
    body: PipelinedEndpointWireBody<'a>,
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
#[derive(Clone)]
struct PipelinedEndpointSendTarget {
    socket: crate::transport::udp::socket::AsyncUdpSocket,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_socket:
        Option<std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
    socket_addr: std::net::SocketAddr,
}

#[cfg(unix)]
struct PipelinedEndpointBatchTarget {
    send_target: PipelinedEndpointSendTarget,
    path_mtu: u16,
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
    inner_plaintext: Cow<'a, [u8]>,
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
struct PipelinedEndpointRuntimeBatchSendAttempt<'a> {
    runtime_plans: Vec<PipelinedEndpointRuntimeSendPlan<'a>>,
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
struct PipelinedEndpointPeerRuntimeBatchSend;

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
    fsp_path_mtu: u16,
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

impl PreparedEndpointSessionMeta {
    fn pipelined<'a>(&'a self, payload: &'a EndpointDataPayload) -> PipelinedEndpointSend<'a> {
        PipelinedEndpointSend {
            dest_addr: &self.dest_addr,
            payload,
            now_ms: self.now_ms,
            timestamp: self.timestamp,
            fsp_flags: self.fsp_flags,
            body: PipelinedEndpointWireBody::EndpointPayload {
                timestamp: self.timestamp,
                msg_type: self.msg_type,
                inner_flags: self.inner_flags,
                payload: payload.as_slice(),
            },
            my_coords: self.my_coords.as_ref(),
            dest_coords: self.dest_coords.as_ref(),
        }
    }

    fn fallback_plan<'a>(&'a self, payload: &'a EndpointDataPayload) -> SessionFspSendPlan<'a> {
        let inner_plaintext = fsp_prepend_inner_header(
            self.timestamp,
            self.msg_type,
            self.inner_flags,
            payload.as_slice(),
        );
        SessionFspSendPlan::new_owned(
            self.dest_addr,
            self.timestamp,
            self.fsp_flags,
            inner_plaintext,
            self.my_coords.as_ref().zip(self.dest_coords.as_ref()),
            SessionFspSendBookkeeping::Data {
                payload_len: payload.len(),
                now_ms: self.now_ms,
            },
        )
    }
}

impl<'a> PreparedEndpointSessionData<'a> {
    fn pipelined(&self) -> PipelinedEndpointSend<'_> {
        self.meta.pipelined(self.payload)
    }

    fn fallback_plan(&self) -> SessionFspSendPlan<'_> {
        self.meta.fallback_plan(self.payload)
    }
}

impl PreparedOwnedEndpointSessionData {
    fn pipelined(&self) -> PipelinedEndpointSend<'_> {
        self.meta.pipelined(&self.payload)
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
        Self::from_inner_plaintext(
            dest_addr,
            timestamp,
            fsp_flags,
            Cow::Borrowed(inner_plaintext),
            coords,
            bookkeeping,
        )
    }

    fn new_owned(
        dest_addr: NodeAddr,
        timestamp: u32,
        fsp_flags: u8,
        inner_plaintext: Vec<u8>,
        coords: Option<(
            &'a crate::tree::TreeCoordinate,
            &'a crate::tree::TreeCoordinate,
        )>,
        bookkeeping: SessionFspSendBookkeeping,
    ) -> Self {
        Self::from_inner_plaintext(
            dest_addr,
            timestamp,
            fsp_flags,
            Cow::Owned(inner_plaintext),
            coords,
            bookkeeping,
        )
    }

    fn from_inner_plaintext(
        dest_addr: NodeAddr,
        timestamp: u32,
        fsp_flags: u8,
        inner_plaintext: Cow<'a, [u8]>,
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
                .encrypt_with_aad(self.inner_plaintext.as_ref(), &header)
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
