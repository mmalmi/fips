use crate::discovery::nostr::{TraversalAnswer, TraversalOffer};
use crate::mmp::report::ReceiverReport;
use crate::mmp::MmpMode;
use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::session_wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_INNER_HEADER_SIZE, FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1,
    FSP_PHASE_MSG2, FSP_PHASE_MSG3, FSP_PORT_HEADER_SIZE, FSP_PORT_IPV6_SHIM, FspCommonPrefix,
};
use crate::node::wire::{FLAG_CE, FLAG_SP};
use crate::node::{
    EndpointDataBulkBody, EndpointDataDelivery, LocalSessionPayload, Node, NodeEndpointControlCommand,
    NodeEndpointDataBatch, NodeEndpointPeer, NodeEndpointRelayStatus, NodeError,
    SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD, SESSION_DIRECT_DEGRADED_MIN_SAMPLE,
    SESSION_DIRECT_RECOVERY_LOSS_THRESHOLD,
};
use crate::noise::{
    HandshakeState, NoiseSession, XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE,
    XK_HANDSHAKE_MSG3_SIZE,
};
use crate::protocol::{
    CoordsRequired, MtuExceeded, PathBroken, PathMtuNotification, SessionAck, SessionDatagram,
    SessionMessageType, SessionMsg3, SessionReceiverReport, SessionSenderReport, SessionSetup,
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
enum OutboundSessionState {
    Established,
    Pending,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryRetrySessionDecision {
    Established,
    RestartedPending,
    Missing,
}

impl Node {
    fn dataplane_outbound_session_state(&self, dest_addr: &NodeAddr) -> OutboundSessionState {
        if self.dataplane_has_fsp_owner(dest_addr) {
            OutboundSessionState::Established
        } else if self.sessions.get(dest_addr).is_some() {
            OutboundSessionState::Pending
        } else {
            OutboundSessionState::Missing
        }
    }
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
            || self.msg_type == SessionMessageType::EndpointDataBulk.to_byte()
    }

    pub(in crate::node) fn into_endpoint_data_deliveries(mut self) -> Vec<EndpointDataDelivery> {
        if self.msg_type == SessionMessageType::EndpointDataBulk.to_byte() {
            let Some(lengths) =
                crate::node::session_wire::decode_fsp_endpoint_data_bulk_lengths(self.body())
            else {
                return Vec::new();
            };
            let body_offset = self.plaintext_offset + FSP_INNER_HEADER_SIZE;
            let body_len = self.body_len();
            if body_offset > 0 {
                assert!(self.buffer.trim_front(body_offset));
            }
            self.buffer.truncate(body_len);
            let source_peer = self.source_peer;
            let buffer = self.buffer;
            return crate::node::session_wire::split_fsp_endpoint_data_bulk_payload(
                buffer,
                &lengths,
            )
            .into_iter()
            .map(|payload| EndpointDataDelivery::new(source_peer, payload))
            .collect();
        }

        debug_assert_eq!(self.msg_type, SessionMessageType::EndpointData.to_byte());
        // Keep the receive hot path allocation-free after AEAD open by making
        // the endpoint body the visible packet window in the existing buffer.
        let body_offset = self.plaintext_offset + FSP_INNER_HEADER_SIZE;
        let body_len = self.body_len();
        if body_offset > 0 {
            assert!(self.buffer.trim_front(body_offset));
        }
        self.buffer.truncate(body_len);
        let source_peer = self.source_peer;
        vec![EndpointDataDelivery::new(source_peer, self.buffer)]
    }

    pub(in crate::node) fn into_ipv6_shim_packet(
        mut self,
        src_ipv6: [u8; 16],
        dst_ipv6: [u8; 16],
    ) -> Option<(PacketBuffer, bool)> {
        debug_assert_eq!(self.msg_type, SessionMessageType::DataPacket.to_byte());
        if self.body_len() < FSP_PORT_HEADER_SIZE {
            return None;
        }
        let service_payload_offset =
            self.plaintext_offset + FSP_INNER_HEADER_SIZE + FSP_PORT_HEADER_SIZE;
        let service_payload_len = self.body_len() - FSP_PORT_HEADER_SIZE;
        if !self.buffer.trim_front(service_payload_offset) {
            return None;
        }
        self.buffer.truncate(service_payload_len);

        if crate::upper::ipv6_shim::decompress_ipv6_in_place(
            &mut self.buffer,
            src_ipv6,
            dst_ipv6,
        ) {
            return Some((self.buffer, true));
        }

        crate::upper::ipv6_shim::decompress_ipv6(self.buffer.as_slice(), src_ipv6, dst_ipv6)
            .map(|packet| (PacketBuffer::new(packet), false))
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

#[derive(Debug, Default)]
struct SessionReceiveBatchCommit {
    previous_hops: Vec<NodeAddr>,
    direct_sources: Vec<NodeAddr>,
    retry_peers: Vec<NodeAddr>,
    pending_flush_sources: Vec<NodeAddr>,
}

impl SessionDispatchFinish {
    fn pending_flush_dest(&self) -> Option<NodeAddr> {
        self.pending_flush_dest
    }
}

impl SessionReceiveBatchCommit {
    fn push_unique(list: &mut Vec<NodeAddr>, addr: NodeAddr) {
        if !list.contains(&addr) {
            list.push(addr);
        }
    }

    fn push_receive_completion(&mut self, completion: SessionReceiveCompletion) {
        Self::push_unique(&mut self.previous_hops, completion.previous_hop_addr);
        let retry_peer = if completion.direct_path {
            Self::push_unique(&mut self.direct_sources, completion.source_addr);
            completion.source_addr
        } else {
            completion.previous_hop_addr
        };
        Self::push_unique(&mut self.retry_peers, retry_peer);
        Self::push_unique(&mut self.pending_flush_sources, completion.source_addr);
    }

    fn push_dispatch(&mut self, dispatch: &AuthenticatedSessionDispatch) {
        if let Some(completion) = dispatch.receive_completion() {
            self.push_receive_completion(completion);
        }
    }

    fn finish(self, node: &mut Node) -> Vec<NodeAddr> {
        if self.previous_hops.is_empty()
            && self.direct_sources.is_empty()
            && self.retry_peers.is_empty()
            && self.pending_flush_sources.is_empty()
        {
            return Vec::new();
        }

        let now_ms = Node::now_ms();
        for previous_hop in self.previous_hops {
            if let Some(peer) = node.peers.get_mut(&previous_hop) {
                peer.touch(now_ms);
            }
        }

        for source_addr in self.direct_sources {
            if node.clear_session_direct_path_degraded(&source_addr) {
                debug!(
                    src = %node.peer_display_name(&source_addr),
                    "Authenticated direct endpoint data restored direct payload routing"
                );
            }
        }

        for retry_peer in self.retry_peers {
            node.clear_retry_unless_direct_refresh_needed(&retry_peer);
        }

        for source_addr in &self.pending_flush_sources {
            clear_dataplane_confirmed_retransmits_for(node, source_addr);
        }

        self.pending_flush_sources
            .into_iter()
            .filter(|source_addr| node.pending_session_traffic.has_traffic_for(source_addr))
            .collect()
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
            || self.msg_type() == SessionMessageType::EndpointDataBulk.to_byte()
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
                direct_path: self.previous_hop_addr == self.source_addr,
            })
    }

    fn commit(&self) -> SessionDispatchCommit {
        SessionDispatchCommit {
            source_addr: self.source_addr,
            receive_completion: self.receive_completion(),
        }
    }

    fn into_endpoint_data_deliveries(self) -> Vec<EndpointDataDelivery> {
        self.message.into_endpoint_data_deliveries()
    }

    async fn dispatch(self, node: &mut Node) {
        // Reverse-route learning runs after the session-entry borrow drops.
        node.learn_reverse_route(*self.source_addr(), *self.previous_hop_addr());

        // Capture the dispatch facts now, before the EndpointData branch takes
        // ownership of the message and drains the inner header in place.
        let source_addr = *self.source_addr();
        let ce_flag = self.ce_flag();
        let msg_type = self.msg_type();
        let commit = self.commit();

        match SessionMessageType::from_byte(msg_type) {
            Some(SessionMessageType::DataPacket) => {
                let dst_port = {
                    let rest = self.body();
                    // msg_type 0x10: port-multiplexed service dispatch
                    if rest.len() < FSP_PORT_HEADER_SIZE {
                        debug!(len = rest.len(), "DataPacket too short for port header");
                        return;
                    }
                    u16::from_le_bytes([rest[2], rest[3]])
                };

                match dst_port {
                    FSP_PORT_IPV6_SHIM => {
                        use crate::FipsAddress;
                        let src_ipv6 = FipsAddress::from_node_addr(&source_addr).to_ipv6().octets();
                        let dst_ipv6 = FipsAddress::from_node_addr(node.node_addr())
                            .to_ipv6()
                            .octets();

                        match self.message.into_ipv6_shim_packet(src_ipv6, dst_ipv6) {
                            Some((mut packet, decompressed_in_place)) => {
                                crate::perf_profile::record_event(if decompressed_in_place {
                                    crate::perf_profile::Event::Ipv6ShimDecompressInPlace
                                } else {
                                    crate::perf_profile::Event::Ipv6ShimDecompressAllocated
                                });
                                if ce_flag {
                                    mark_ipv6_ecn_ce(packet.as_mut_slice());
                                    node.stats_mut().congestion.record_ce_received();
                                }
                                if node.external_packet_tx.is_some() {
                                    node.deliver_external_ipv6_packet(
                                        &source_addr,
                                        packet.into_vec(),
                                    );
                                } else if let Some(tun_tx) = &node.tun_tx {
                                    let _t = crate::perf_profile::Timer::start(
                                        crate::perf_profile::Stage::TunWrite,
                                    );
                                    if let Err(e) = tun_tx.send_with_lane(
                                        packet,
                                        crate::upper::tun::TunWriteLane::Priority,
                                    ) {
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
                node.deliver_endpoint_data_batch(self.into_endpoint_data_deliveries());
            }
            Some(SessionMessageType::EndpointDataBulk) => {
                node.deliver_endpoint_data_batch(self.into_endpoint_data_deliveries());
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

    fn dispatch_endpoint_data_batched(
        self,
        node: &mut Node,
        commit: &mut SessionReceiveBatchCommit,
    ) -> Vec<EndpointDataDelivery> {
        debug_assert!(self.is_endpoint_data());

        node.learn_reverse_route(*self.source_addr(), *self.previous_hop_addr());
        commit.push_dispatch(&self);
        self.into_endpoint_data_deliveries()
    }
}

impl SessionDispatchCommit {
    fn finish_receive(&self, node: &mut Node) -> SessionDispatchFinish {
        let now_ms = Node::now_ms();
        if let Some(completion) = self.receive_completion {
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
            clear_dataplane_confirmed_retransmits_for(node, &completion.source_addr);
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

fn clear_dataplane_confirmed_retransmits_for(node: &mut Node, source_addr: &NodeAddr) -> bool {
    let confirmed = node
        .dataplane
        .fsp_owner_activity(source_addr)
        .is_some_and(|activity| activity.current_epoch_confirmed());
    if !confirmed {
        return false;
    }

    node.sessions
        .get_mut(source_addr)
        .is_some_and(|entry| entry.clear_dataplane_confirmed_fsp_retransmits())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionDatagramRuntimeRoute {
    dest_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    path_mtu: u16,
}
