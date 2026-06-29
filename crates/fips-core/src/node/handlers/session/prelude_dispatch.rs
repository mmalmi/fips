use crate::discovery::nostr::{TraversalAnswer, TraversalOffer};
use crate::mmp::report::ReceiverReport;
use crate::mmp::{MAX_SESSION_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS, MmpMode};
use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::session_wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_FLAG_CP, FSP_FLAG_K, FSP_INNER_HEADER_SIZE,
    FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3,
    FSP_PORT_HEADER_SIZE, FSP_PORT_IPV6_SHIM, FspCommonPrefix,
};
use crate::node::wire::{FLAG_CE, FLAG_SP};
use crate::node::{
    EndpointDataDelivery, EndpointDataPayload, EndpointSendBatchCommand, EndpointSendCommand,
    LocalSessionPayload, Node, NodeEndpointCommand, NodeEndpointPeer, NodeEndpointRelayStatus,
    NodeError,
    SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD, SESSION_DIRECT_DEGRADED_MIN_SAMPLE,
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
use crate::transport::PacketBuffer;
use crate::{NodeAddr, PeerIdentity};
use secp256k1::PublicKey;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

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
pub(in crate::node) enum SessionFspSendContextError {
    NoSession,
    NotEstablished,
}

impl SessionFspSendContextError {
    pub(in crate::node) fn into_node_error(self, node_addr: NodeAddr) -> NodeError {
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
pub(in crate::node) struct SessionFspSendContext {
    pub(in crate::node) timestamp: u32,
    spin_bit: bool,
    current_k_bit: bool,
}

impl SessionFspSendContext {
    pub(in crate::node) fn inner_flags_byte(&self) -> u8 {
        FspInnerFlags {
            spin_bit: self.spin_bit,
        }
        .to_byte()
    }

    pub(in crate::node) fn fsp_flags(&self, include_coords: bool) -> u8 {
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

    #[cfg(test)]
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
    fn plaintext(&self) -> &[u8] {
        debug_assert!(self.plaintext_len >= FSP_INNER_HEADER_SIZE);
        &self.buffer[self.plaintext_offset..self.plaintext_offset + self.plaintext_len]
    }

    pub(in crate::node) fn msg_type(&self) -> u8 {
        self.msg_type
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
        // Only application data resets the idle timer and traffic counters —
        // MMP reports (SenderReport, ReceiverReport, PathMtuNotification) do not.
        let now_ms = Node::now_ms();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionDatagramRuntimeRoute {
    dest_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    path_mtu: u16,
}
