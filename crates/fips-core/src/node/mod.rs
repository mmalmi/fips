//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

mod acl;
mod bloom;
mod decrypt_worker;
mod discovery_rate_limit;
mod encrypt_worker;
mod handlers;
mod lifecycle;
mod rate_limit;
mod retry;
mod routing;
mod routing_error_rate_limit;
pub(crate) mod session;
pub(crate) mod session_wire;
pub(crate) mod stats;
pub(crate) mod stats_history;
#[cfg(test)]
mod tests;
mod tree;
pub(crate) mod wire;

use self::decrypt_worker::DecryptSessionKey;
use self::discovery_rate_limit::{DiscoveryBackoff, DiscoveryForwardRateLimiter};
use self::rate_limit::HandshakeRateLimiter;
use self::routing::{LearnedRouteTable, LearnedRouteTableSnapshot};
use self::routing_error_rate_limit::RoutingErrorRateLimiter;
#[cfg(unix)]
use self::wire::ESTABLISHED_HEADER_SIZE;
use self::wire::{
    FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, build_encrypted, build_established_header,
    prepend_inner_header,
};
use crate::bloom::{BloomFilter, BloomState};
use crate::cache::CoordCache;
use crate::config::{NostrDiscoveryPolicy, PeerConfig, RoutingMode};
#[cfg(unix)]
use crate::node::session::FspSendReservation;
use crate::node::session::SessionEntry;
use crate::node::session_wire::{FSP_PHASE_ESTABLISHED, FspCommonPrefix};
use crate::peer::{ActivePeer, PeerConnection};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::transport::ethernet::EthernetTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::tor::TorTransport;
use crate::transport::udp::UdpTransport;
#[cfg(feature = "webrtc-transport")]
use crate::transport::webrtc::WebRtcTransport;
use crate::transport::{
    ConnectionState, Link, LinkId, PacketRx, PacketTx, TransportAddr, TransportError,
    TransportHandle, TransportId,
};
use crate::tree::TreeState;
use crate::upper::hosts::HostMap;
use crate::upper::icmp_rate_limit::IcmpRateLimiter;
use crate::upper::tun::{TunError, TunOutboundRx, TunState, TunTx};
use crate::utils::index::{IndexAllocator, SessionIndex};
use crate::{
    Config, ConfigError, FipsAddress, Identity, IdentityError, LinkMessageType, NodeAddr,
    PeerIdentity, encode_npub,
};
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::thread::JoinHandle;
use thiserror::Error;
use tracing::{debug, warn};

const LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);
const SESSION_DIRECT_DEGRADED_HOLD_MS: u64 = 20_000;
const SESSION_DIRECT_DEGRADED_MIN_SAMPLE: u64 = 16;
const SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD: f64 = 0.08;
const SESSION_DIRECT_RECOVERY_LOSS_THRESHOLD: f64 = 0.02;
const ROUTING_FALLBACK_MIN_COST_ADVANTAGE: f64 = 0.25;
const ENDPOINT_EVENT_BACKLOG_HIGH_WATER: usize = 4096;

#[derive(Debug, Default)]
pub(in crate::node) struct LocalSendFailures {
    failures: HashMap<NodeAddr, std::time::Instant>,
}

impl LocalSendFailures {
    pub(in crate::node) fn note_send_outcome(
        &mut self,
        node_addr: &NodeAddr,
        result: &Result<usize, TransportError>,
        now: std::time::Instant,
    ) {
        match result {
            Ok(_) => {
                self.failures.remove(node_addr);
            }
            Err(error) if error.is_local_route_unavailable() => {
                self.record_failure(*node_addr, now);
            }
            Err(_) => {}
        }
    }

    pub(in crate::node) fn record_failure(&mut self, node_addr: NodeAddr, at: std::time::Instant) {
        self.failures.insert(node_addr, at);
    }

    pub(in crate::node) fn dead_timeout_for_peer(
        &self,
        node_addr: &NodeAddr,
        now: std::time::Instant,
        dead_timeout: std::time::Duration,
        fast_dead_timeout: std::time::Duration,
    ) -> std::time::Duration {
        match self.failures.get(node_addr).copied() {
            Some(t) if now.duration_since(t) <= LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW => {
                fast_dead_timeout.min(dead_timeout)
            }
            None => dead_timeout,
            Some(_) => dead_timeout,
        }
    }

    pub(in crate::node) fn purge_expired(&mut self, now: std::time::Instant) {
        self.failures
            .retain(|_, at| now.duration_since(*at) <= LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW);
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.failures.contains_key(node_addr)
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct SessionDirectDegradation {
    degraded_until_ms: HashMap<NodeAddr, u64>,
}

impl SessionDirectDegradation {
    pub(in crate::node) fn is_degraded(&mut self, dest: &NodeAddr, now_ms: u64) -> bool {
        match self.degraded_until_ms.get(dest).copied() {
            Some(until_ms) if until_ms > now_ms => true,
            Some(_) => {
                self.degraded_until_ms.remove(dest);
                false
            }
            None => false,
        }
    }

    pub(in crate::node) fn mark_degraded(
        &mut self,
        dest: NodeAddr,
        now_ms: u64,
        hold_ms: u64,
    ) -> bool {
        let until_ms = now_ms.saturating_add(hold_ms);
        let entry = self.degraded_until_ms.entry(dest).or_insert(0);
        let was_degraded = *entry > now_ms;
        *entry = (*entry).max(until_ms);
        !was_degraded
    }

    pub(in crate::node) fn clear(&mut self, dest: &NodeAddr) -> bool {
        self.degraded_until_ms.remove(dest).is_some()
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct DiscoveryFallbackTransit {
    blocked_peers: HashSet<NodeAddr>,
}

impl DiscoveryFallbackTransit {
    pub(in crate::node) fn set_allowed(&mut self, peer_addr: NodeAddr, allowed: bool) {
        if allowed {
            self.blocked_peers.remove(&peer_addr);
        } else {
            self.blocked_peers.insert(peer_addr);
        }
    }

    pub(in crate::node) fn allows_lookup_fallback_peer<F>(
        &self,
        peer_addr: &NodeAddr,
        target: &NodeAddr,
        transport_id: Option<TransportId>,
        mut is_bootstrap_transport: F,
    ) -> bool
    where
        F: FnMut(TransportId) -> bool,
    {
        if peer_addr == target {
            return true;
        }

        if self.blocked_peers.contains(peer_addr) {
            return false;
        }

        match transport_id {
            Some(transport_id) => !is_bootstrap_transport(transport_id),
            None => true,
        }
    }

    #[cfg(test)]
    pub(in crate::node) fn is_blocked(&self, peer_addr: &NodeAddr) -> bool {
        self.blocked_peers.contains(peer_addr)
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct BootstrapTransports {
    transport_ids: HashSet<TransportId>,
    peer_npubs: HashMap<TransportId, String>,
}

impl BootstrapTransports {
    pub(in crate::node) fn register(&mut self, transport_id: TransportId, peer_npub: String) {
        self.transport_ids.insert(transport_id);
        self.peer_npubs.insert(transport_id, peer_npub);
    }

    #[cfg(test)]
    pub(in crate::node) fn mark(&mut self, transport_id: TransportId) {
        self.transport_ids.insert(transport_id);
    }

    pub(in crate::node) fn remove(&mut self, transport_id: &TransportId) {
        self.transport_ids.remove(transport_id);
        self.peer_npubs.remove(transport_id);
    }

    pub(in crate::node) fn contains(&self, transport_id: &TransportId) -> bool {
        self.transport_ids.contains(transport_id)
    }

    pub(in crate::node) fn peer_npub(&self, transport_id: &TransportId) -> Option<&str> {
        self.peer_npubs.get(transport_id).map(String::as_str)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FmpPlaintextTrafficClass {
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EndpointPayloadTrafficClass {
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
}

#[cfg(unix)]
struct FmpWorkerSendReservation {
    counter: u64,
    header: [u8; ESTABLISHED_HEADER_SIZE],
    cipher: ring::aead::LessSafeKey,
}

#[cfg(unix)]
fn reserve_fmp_worker_send(
    session: &mut crate::noise::NoiseSession,
    their_index: crate::utils::index::SessionIndex,
    flags: u8,
    payload_len: u16,
) -> Result<Option<FmpWorkerSendReservation>, crate::noise::NoiseError> {
    let Some(cipher) = session.send_cipher_clone() else {
        return Ok(None);
    };
    let counter = session.take_send_counter()?;
    let header = build_established_header(their_index, counter, flags, payload_len);
    Ok(Some(FmpWorkerSendReservation {
        counter,
        header,
        cipher,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointCommandLane {
    Priority,
    Bulk,
}

fn classify_fmp_plaintext_traffic(plaintext: &[u8]) -> FmpPlaintextTrafficClass {
    let bulk_endpoint_data = fmp_plaintext_is_bulk_session_datagram(plaintext);
    // At this layer established FSP payloads are already end-to-end encrypted,
    // so a bulk SessionDatagram may still be TCP endpoint traffic. Keep it out
    // of the control lane, but only the pre-FSP endpoint path may mark known
    // non-TCP packets as discardable under sender backpressure.
    FmpPlaintextTrafficClass {
        bulk_endpoint_data,
        drop_on_backpressure: false,
    }
}

fn fmp_plaintext_is_bulk_session_datagram(plaintext: &[u8]) -> bool {
    if plaintext
        .first()
        .is_none_or(|ty| *ty != LinkMessageType::SessionDatagram.to_byte())
    {
        return false;
    }
    let Some(fsp_payload) = plaintext.get(crate::protocol::SESSION_DATAGRAM_HEADER_SIZE..) else {
        return false;
    };
    FspCommonPrefix::parse(fsp_payload).is_some_and(|prefix| {
        prefix.phase == FSP_PHASE_ESTABLISHED && !prefix.is_unencrypted() && !prefix.has_coords()
    })
}

fn classify_endpoint_payload(payload: &[u8]) -> EndpointPayloadTrafficClass {
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_ICMPV6: u8 = 58;

    match parse_endpoint_payload_ip_proto(payload) {
        Some((IPPROTO_ICMP, _)) => EndpointPayloadTrafficClass::default(),
        Some((IPPROTO_ICMPV6, _)) => EndpointPayloadTrafficClass::default(),
        Some((IPPROTO_TCP, offset)) => {
            let latency_sensitive = endpoint_tcp_payload_is_latency_sensitive(payload, offset);
            EndpointPayloadTrafficClass {
                bulk_endpoint_data: !latency_sensitive,
                drop_on_backpressure: false,
            }
        }
        _ => EndpointPayloadTrafficClass {
            bulk_endpoint_data: true,
            drop_on_backpressure: true,
        },
    }
}

#[cfg(test)]
pub(crate) fn endpoint_payload_is_latency_sensitive(payload: &[u8]) -> bool {
    !classify_endpoint_payload(payload).bulk_endpoint_data
}

#[cfg(test)]
pub(crate) fn endpoint_command_lane_for_payload(payload: &[u8]) -> EndpointCommandLane {
    if endpoint_payload_is_latency_sensitive(payload) {
        EndpointCommandLane::Priority
    } else {
        EndpointCommandLane::Bulk
    }
}

/// Endpoint payload bytes plus the traffic policy selected at app ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndpointDataPayload {
    bytes: Vec<u8>,
    traffic_class: EndpointPayloadTrafficClass,
}

impl EndpointDataPayload {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        let traffic_class = classify_endpoint_payload(&bytes);
        Self {
            bytes,
            traffic_class,
        }
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        if self.traffic_class.bulk_endpoint_data {
            EndpointCommandLane::Bulk
        } else {
            EndpointCommandLane::Priority
        }
    }

    pub(crate) fn bulk_endpoint_data(&self) -> bool {
        self.traffic_class.bulk_endpoint_data
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.traffic_class.drop_on_backpressure
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl From<Vec<u8>> for EndpointDataPayload {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// Outbound endpoint data plus the peer identity it is bound to.
#[derive(Debug)]
pub(crate) struct EndpointDataSend {
    dest_addr: NodeAddr,
    dest_pubkey: secp256k1::PublicKey,
    payload: EndpointDataPayload,
}

impl EndpointDataSend {
    pub(crate) fn new(remote: PeerIdentity, payload: EndpointDataPayload) -> Self {
        Self {
            dest_addr: *remote.node_addr(),
            dest_pubkey: remote.pubkey_full(),
            payload,
        }
    }

    pub(crate) fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    pub(crate) fn dest_pubkey(&self) -> secp256k1::PublicKey {
        self.dest_pubkey
    }

    pub(crate) fn payload(&self) -> &EndpointDataPayload {
        &self.payload
    }

    pub(crate) fn into_payload(self) -> EndpointDataPayload {
        self.payload
    }
}

/// Admission result for a bounded pending endpoint-data queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingEndpointDataQueueAdmission {
    dropped_oldest: bool,
}

impl PendingEndpointDataQueueAdmission {
    pub(crate) fn dropped_oldest(&self) -> bool {
        self.dropped_oldest
    }
}

/// Per-destination endpoint payloads waiting for session establishment.
#[derive(Debug, Default)]
pub(crate) struct PendingEndpointDataQueue {
    payloads: VecDeque<EndpointDataPayload>,
}

impl PendingEndpointDataQueue {
    pub(crate) fn push_bounded(
        &mut self,
        payload: EndpointDataPayload,
        capacity: usize,
    ) -> PendingEndpointDataQueueAdmission {
        let dropped_oldest = self.payloads.len() >= capacity;
        if dropped_oldest {
            self.payloads.pop_front();
        }
        self.payloads.push_back(payload);
        PendingEndpointDataQueueAdmission { dropped_oldest }
    }

    pub(crate) fn len(&self) -> usize {
        self.payloads.len()
    }

    pub(crate) fn into_payloads(self) -> VecDeque<EndpointDataPayload> {
        self.payloads
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &EndpointDataPayload> {
        self.payloads.iter()
    }
}

/// Admission result for a bounded pending TUN packet queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingTunPacketQueueAdmission {
    dropped_oldest: bool,
}

impl PendingTunPacketQueueAdmission {
    pub(crate) fn dropped_oldest(&self) -> bool {
        self.dropped_oldest
    }
}

/// Per-destination TUN packets waiting for session establishment.
#[derive(Debug, Default)]
pub(crate) struct PendingTunPacketQueue {
    packets: VecDeque<Vec<u8>>,
}

impl PendingTunPacketQueue {
    pub(crate) fn push_bounded(
        &mut self,
        packet: Vec<u8>,
        capacity: usize,
    ) -> PendingTunPacketQueueAdmission {
        let dropped_oldest = self.packets.len() >= capacity;
        if dropped_oldest {
            self.packets.pop_front();
        }
        self.packets.push_back(packet);
        PendingTunPacketQueueAdmission { dropped_oldest }
    }

    pub(crate) fn len(&self) -> usize {
        self.packets.len()
    }

    pub(crate) fn into_packets(self) -> VecDeque<Vec<u8>> {
        self.packets
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.packets.iter()
    }
}

/// Admission result for pending session-establishment traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingSessionTrafficAdmission {
    destination_dropped: bool,
    dropped_oldest: bool,
}

impl PendingSessionTrafficAdmission {
    pub(crate) fn destination_dropped(&self) -> bool {
        self.destination_dropped
    }

    pub(crate) fn dropped_oldest(&self) -> bool {
        self.dropped_oldest
    }
}

/// Queued TUN and endpoint traffic removed for one destination.
#[derive(Debug, Default)]
pub(crate) struct PendingDestinationTraffic {
    tun_packets: Option<PendingTunPacketQueue>,
    endpoint_data: Option<PendingEndpointDataQueue>,
}

impl PendingDestinationTraffic {
    pub(crate) fn tun_packets(&self) -> Option<&PendingTunPacketQueue> {
        self.tun_packets.as_ref()
    }

    pub(crate) fn into_tun_packets(self) -> Option<PendingTunPacketQueue> {
        self.tun_packets
    }

    pub(crate) fn endpoint_data(&self) -> Option<&PendingEndpointDataQueue> {
        self.endpoint_data.as_ref()
    }
}

/// Pending traffic waiting for session establishment.
#[derive(Debug, Default)]
pub(crate) struct PendingSessionTrafficQueues {
    tun_packets: HashMap<NodeAddr, PendingTunPacketQueue>,
    endpoint_data: HashMap<NodeAddr, PendingEndpointDataQueue>,
}

impl PendingSessionTrafficQueues {
    pub(crate) fn push_tun_packet(
        &mut self,
        dest_addr: NodeAddr,
        packet: Vec<u8>,
        max_destinations: usize,
        packets_per_dest: usize,
    ) -> PendingSessionTrafficAdmission {
        if !self.tun_packets.contains_key(&dest_addr) && self.tun_packets.len() >= max_destinations
        {
            return PendingSessionTrafficAdmission {
                destination_dropped: true,
                dropped_oldest: false,
            };
        }

        let admission = self
            .tun_packets
            .entry(dest_addr)
            .or_default()
            .push_bounded(packet, packets_per_dest);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest: admission.dropped_oldest(),
        }
    }

    pub(crate) fn push_endpoint_data(
        &mut self,
        dest_addr: NodeAddr,
        payload: impl Into<EndpointDataPayload>,
        max_destinations: usize,
        packets_per_dest: usize,
    ) -> PendingSessionTrafficAdmission {
        if !self.endpoint_data.contains_key(&dest_addr)
            && self.endpoint_data.len() >= max_destinations
        {
            return PendingSessionTrafficAdmission {
                destination_dropped: true,
                dropped_oldest: false,
            };
        }

        let admission = self
            .endpoint_data
            .entry(dest_addr)
            .or_default()
            .push_bounded(payload.into(), packets_per_dest);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest: admission.dropped_oldest(),
        }
    }

    pub(crate) fn remove_destination(&mut self, dest_addr: &NodeAddr) -> PendingDestinationTraffic {
        PendingDestinationTraffic {
            tun_packets: self.tun_packets.remove(dest_addr),
            endpoint_data: self.endpoint_data.remove(dest_addr),
        }
    }

    pub(crate) fn take_tun_packets(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<PendingTunPacketQueue> {
        self.tun_packets.remove(dest_addr)
    }

    pub(crate) fn take_endpoint_data(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<PendingEndpointDataQueue> {
        self.endpoint_data.remove(dest_addr)
    }

    pub(crate) fn has_traffic_for(&self, dest_addr: &NodeAddr) -> bool {
        self.tun_packets.contains_key(dest_addr) || self.endpoint_data.contains_key(dest_addr)
    }

    pub(crate) fn tun_packets_for(&self, dest_addr: &NodeAddr) -> Option<&PendingTunPacketQueue> {
        self.tun_packets.get(dest_addr)
    }

    pub(crate) fn endpoint_data_for(
        &self,
        dest_addr: &NodeAddr,
    ) -> Option<&PendingEndpointDataQueue> {
        self.endpoint_data.get(dest_addr)
    }

    pub(crate) fn tun_destination_count(&self) -> usize {
        self.tun_packets.len()
    }

    pub(crate) fn tun_packet_count(&self) -> usize {
        self.tun_packets.values().map(|q| q.len()).sum()
    }
}

fn endpoint_tcp_payload_is_latency_sensitive(payload: &[u8], tcp_offset: usize) -> bool {
    const TCP_MIN_HEADER_LEN: usize = 20;
    const TCP_FLAG_FIN: u8 = 0x01;
    const TCP_FLAG_SYN: u8 = 0x02;
    const TCP_FLAG_RST: u8 = 0x04;
    const INTERACTIVE_TCP_PAYLOAD_MAX: usize = 256;

    if payload.len() < tcp_offset + TCP_MIN_HEADER_LEN {
        return true;
    }

    let tcp_header_len = usize::from(payload[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < TCP_MIN_HEADER_LEN || payload.len() < tcp_offset + tcp_header_len {
        return true;
    }

    let flags = payload[tcp_offset + 13];
    if flags & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST) != 0 {
        return true;
    }

    let payload_len = endpoint_ip_payload_len(payload)
        .and_then(|ip_payload_len| ip_payload_len.checked_sub(tcp_header_len))
        .unwrap_or_else(|| payload.len().saturating_sub(tcp_offset + tcp_header_len));
    payload_len <= INTERACTIVE_TCP_PAYLOAD_MAX
}

fn endpoint_ip_payload_len(payload: &[u8]) -> Option<usize> {
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    let version_ihl = payload.first().copied()?;
    match version_ihl >> 4 {
        4 => {
            if payload.len() < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let header_len = usize::from(version_ihl & 0x0f) * 4;
            if header_len < IPV4_MIN_HEADER_LEN || payload.len() < header_len {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            total_len.checked_sub(header_len)
        }
        6 => {
            if payload.len() < IPV6_HEADER_LEN {
                return None;
            }
            Some(usize::from(u16::from_be_bytes([payload[4], payload[5]])))
        }
        _ => None,
    }
}

fn parse_endpoint_payload_ip_proto(payload: &[u8]) -> Option<(u8, usize)> {
    const IPV4_MIN_HEADER_LEN: usize = 20;

    let version_ihl = payload.first().copied()?;

    match version_ihl >> 4 {
        4 => {
            if payload.len() < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let header_len = usize::from(version_ihl & 0x0f) * 4;
            if header_len >= IPV4_MIN_HEADER_LEN && payload.len() >= header_len {
                Some((payload[9], header_len))
            } else {
                None
            }
        }
        6 => ipv6_payload_next_header(payload),
        _ => None,
    }
}

#[cfg(test)]
fn endpoint_payload_is_tcp(payload: &[u8]) -> bool {
    const IPPROTO_TCP: u8 = 6;
    parse_endpoint_payload_ip_proto(payload).is_some_and(|(proto, _)| proto == IPPROTO_TCP)
}

fn ipv6_payload_next_header(payload: &[u8]) -> Option<(u8, usize)> {
    const IPV6_HEADER_LEN: usize = 40;
    const IPV6_FRAGMENT_HEADER_LEN: usize = 8;

    if payload.len() < IPV6_HEADER_LEN || payload[0] >> 4 != 6 {
        return None;
    }

    let mut next_header = payload[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut extension_count = 0usize;
    while ipv6_extension_header_is_skippable(next_header) {
        if next_header == 44 {
            if payload.len() < offset + IPV6_FRAGMENT_HEADER_LEN {
                return None;
            }
            next_header = payload[offset];
            offset += IPV6_FRAGMENT_HEADER_LEN;
        } else if next_header == 51 {
            if payload.len() < offset + 2 {
                return None;
            }
            let header_len = (usize::from(payload[offset + 1]) + 2) * 4;
            if payload.len() < offset + header_len {
                return None;
            }
            next_header = payload[offset];
            offset += header_len;
        } else {
            if payload.len() < offset + 2 {
                return None;
            }
            let header_len = (usize::from(payload[offset + 1]) + 1) * 8;
            if payload.len() < offset + header_len {
                return None;
            }
            next_header = payload[offset];
            offset += header_len;
        }
        extension_count += 1;
        if extension_count > 8 {
            return None;
        }
    }

    Some((next_header, offset))
}

fn ipv6_extension_header_is_skippable(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 51 | 60 | 135)
}

/// Half-range of the symmetric jitter applied to per-session rekey timers.
///
/// Each FMP/FSP session draws an offset uniformly from
/// `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]` seconds at construction and
/// after each cutover. This preserves the configured mean interval while
/// reducing dual-initiation bursts in symmetric-start meshes.
pub(crate) const REKEY_JITTER_SECS: i64 = 15;

/// Errors related to node operations.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("node not started")]
    NotStarted,

    #[error("node already started")]
    AlreadyStarted,

    #[error("node already stopped")]
    AlreadyStopped,

    #[error("transport not found: {0}")]
    TransportNotFound(TransportId),

    #[error("no transport available for type: {0}")]
    NoTransportForType(String),

    #[error("link not found: {0}")]
    LinkNotFound(LinkId),

    #[error("connection not found: {0}")]
    ConnectionNotFound(LinkId),

    #[error("peer not found: {0:?}")]
    PeerNotFound(NodeAddr),

    #[error("peer already exists: {0:?}")]
    PeerAlreadyExists(NodeAddr),

    #[error("connection already exists for link: {0}")]
    ConnectionAlreadyExists(LinkId),

    #[error("invalid peer npub '{npub}': {reason}")]
    InvalidPeerNpub { npub: String, reason: String },

    #[error("discovery error: {0}")]
    Discovery(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("max connections exceeded: {max}")]
    MaxConnectionsExceeded { max: usize },

    #[error("max peers exceeded: {max}")]
    MaxPeersExceeded { max: usize },

    #[error("max links exceeded: {max}")]
    MaxLinksExceeded { max: usize },

    #[error("handshake incomplete for link {0}")]
    HandshakeIncomplete(LinkId),

    #[error("no session available for link {0}")]
    NoSession(LinkId),

    #[error("promotion failed for link {link_id}: {reason}")]
    PromotionFailed { link_id: LinkId, reason: String },

    #[error("send failed to {node_addr}: {reason}")]
    SendFailed { node_addr: NodeAddr, reason: String },

    #[error("mtu exceeded forwarding to {node_addr}: packet {packet_size} > mtu {mtu}")]
    MtuExceeded {
        node_addr: NodeAddr,
        packet_size: usize,
        mtu: u16,
    },

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("TUN error: {0}")]
    Tun(#[from] TunError),

    #[error("index allocation failed: {0}")]
    IndexAllocationFailed(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("transport error: {0}")]
    TransportError(String),

    #[error("local route unavailable: {0}")]
    LocalRouteUnavailable(String),

    #[error("bootstrap handoff failed: {0}")]
    BootstrapHandoff(String),
}

impl NodeError {
    pub(in crate::node) fn from_transport_error(error: TransportError) -> Self {
        if error.is_local_route_unavailable() {
            Self::LocalRouteUnavailable(error.to_string())
        } else {
            Self::TransportError(error.to_string())
        }
    }

    pub(in crate::node) fn is_local_route_unavailable(&self) -> bool {
        matches!(self, Self::LocalRouteUnavailable(_))
    }
}

/// Source-attributed packet delivered by a node running without a system TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDeliveredPacket {
    /// FIPS node address that originated the packet.
    pub source_node_addr: NodeAddr,
    /// Source Nostr public key when the node has learned it.
    pub source_npub: Option<String>,
    /// Destination FIPS address from the IPv6 packet.
    pub destination: FipsAddress,
    /// Full IPv6 packet after FIPS session decapsulation.
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone)]
struct IdentityCacheEntry {
    node_addr: NodeAddr,
    pubkey: secp256k1::PublicKey,
    npub: String,
    last_seen_ms: u64,
}

impl IdentityCacheEntry {
    fn new(
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        npub: String,
        last_seen_ms: u64,
    ) -> Self {
        Self {
            node_addr,
            pubkey,
            npub,
            last_seen_ms,
        }
    }
}

/// Prefix-indexed identity cache for FipsAddress/NodeAddr lookup.
#[derive(Debug, Default)]
pub(in crate::node) struct IdentityCache {
    entries: HashMap<[u8; 15], IdentityCacheEntry>,
}

impl IdentityCache {
    pub(in crate::node) fn prefix_for(node_addr: &NodeAddr) -> [u8; 15] {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&node_addr.as_bytes()[0..15]);
        prefix
    }

    pub(in crate::node) fn register(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        now_ms: u64,
        max_entries: usize,
    ) -> bool {
        let prefix = Self::prefix_for(&node_addr);
        if let Some(entry) = self.entries.get(&prefix)
            && entry.node_addr == node_addr
            && entry.pubkey == pubkey
        {
            return true;
        }

        let (xonly, _) = pubkey.x_only_public_key();
        let derived_node_addr = NodeAddr::from_pubkey(&xonly);
        if derived_node_addr != node_addr {
            debug!(
                claimed_node_addr = %node_addr,
                derived_node_addr = %derived_node_addr,
                "Rejected identity cache entry with mismatched public key"
            );
            return false;
        }

        if let Some(entry) = self.entries.get_mut(&prefix)
            && entry.node_addr == node_addr
        {
            entry.pubkey = pubkey;
            entry.last_seen_ms = now_ms;
            return true;
        }

        let npub = encode_npub(&xonly);
        self.entries.insert(
            prefix,
            IdentityCacheEntry::new(node_addr, pubkey, npub, now_ms),
        );
        self.evict_lru(max_entries);
        true
    }

    pub(in crate::node) fn lookup_by_prefix(
        &mut self,
        prefix: &[u8; 15],
        now_ms: u64,
    ) -> Option<(NodeAddr, secp256k1::PublicKey)> {
        let entry = self.entries.get_mut(prefix)?;
        entry.last_seen_ms = now_ms;
        Some((entry.node_addr, entry.pubkey))
    }

    pub(in crate::node) fn has_prefix_for(&self, node_addr: &NodeAddr) -> bool {
        self.entries.contains_key(&Self::prefix_for(node_addr))
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(in crate::node) fn iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &secp256k1::PublicKey, u64)> {
        self.entries
            .values()
            .map(|entry| (&entry.node_addr, &entry.pubkey, entry.last_seen_ms))
    }

    pub(in crate::node) fn pubkey_for_node_addr(
        &self,
        addr: &NodeAddr,
    ) -> Option<secp256k1::PublicKey> {
        self.entries
            .get(&Self::prefix_for(addr))
            .filter(|entry| &entry.node_addr == addr)
            .map(|entry| entry.pubkey)
    }

    pub(in crate::node) fn npub_for_node_addr(&self, addr: &NodeAddr) -> Option<String> {
        self.entries
            .get(&Self::prefix_for(addr))
            .filter(|entry| &entry.node_addr == addr)
            .map(|entry| entry.npub.clone())
    }

    fn evict_lru(&mut self, max_entries: usize) {
        if self.entries.len() > max_entries
            && let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen_ms)
                .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest_key);
        }
    }

    #[cfg(test)]
    pub(in crate::node) fn insert_for_test(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        npub: String,
        last_seen_ms: u64,
    ) {
        self.entries.insert(
            Self::prefix_for(&node_addr),
            IdentityCacheEntry::new(node_addr, pubkey, npub, last_seen_ms),
        );
    }
}

/// App-owned packet channels for embedding FIPS without a system TUN.
#[derive(Debug)]
pub struct ExternalPacketIo {
    /// Send outbound IPv6 packets into the node.
    pub outbound_tx: crate::upper::tun::TunOutboundTx,
    /// Receive inbound IPv6 packets delivered by FIPS sessions.
    pub inbound_rx: tokio::sync::mpsc::Receiver<NodeDeliveredPacket>,
}

/// App-owned endpoint data channels for embedding FIPS without a daemon.
#[derive(Debug)]
pub(crate) struct EndpointDataIo {
    /// Send latency-sensitive endpoint data and management commands into the
    /// node RX loop ahead of queued bulk endpoint data.
    pub(crate) priority_command_tx: tokio::sync::mpsc::Sender<NodeEndpointCommand>,
    /// Send endpoint data commands into the node RX loop.
    ///
    /// Bounded with a generous default so normal sender bursts do not
    /// stall on semaphore acquisition. macOS pacing happens at the UDP
    /// egress thread where the real Wi-Fi/interface bottleneck is visible;
    /// constraining this app queue instead caused the inner TCP flow to
    /// collapse under iperf. `FIPS_ENDPOINT_DATA_QUEUE_CAP` overrides the
    /// default for benches.
    pub(crate) command_tx: tokio::sync::mpsc::Sender<NodeEndpointCommand>,
    /// Receive endpoint data delivered by FIPS sessions.
    ///
    /// Unbounded so the rx_loop's send on inbound packet delivery is a
    /// wait-free push (no semaphore acquire), and so we can drop the
    /// per-packet cross-task relay that previously sat between the node
    /// task and the `FipsEndpoint::recv()` consumer. Backpressure is
    /// still visible through `endpoint_event_wait` latency and the
    /// `endpoint_event_backlog_high` pipeline event when the consumer falls
    /// materially behind.
    pub(crate) event_rx: EndpointEventReceiver,
    /// Clone of the event_tx exposed for in-process loopback (e.g.
    /// `FipsEndpoint::send` to self_npub). Lets the endpoint inject an
    /// event into the same queue without going through the encrypt /
    /// decrypt path, while keeping every consumer reading from a single
    /// channel.
    pub(crate) event_tx: EndpointEventSender,
}

/// Observable owner for endpoint events delivered to embedded applications.
#[derive(Debug, Clone)]
pub(crate) struct EndpointEventSender {
    tx: tokio::sync::mpsc::UnboundedSender<NodeEndpointEvent>,
    queued_messages: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub(crate) struct EndpointEventReceiver {
    rx: tokio::sync::mpsc::UnboundedReceiver<NodeEndpointEvent>,
    queued_messages: Arc<AtomicUsize>,
}

/// Delivery-side owner for endpoint data emitted by session receive handling.
///
/// The rx loop currently owns this runtime, but keeping sender, batching, and
/// backlog accounting behind one value makes the future peer/shard receive
/// runtime move explicit instead of threading endpoint-event fields through
/// `Node` packet handlers.
#[derive(Debug, Default)]
pub(in crate::node) struct EndpointEventRuntime {
    sender: Option<EndpointEventSender>,
    batch_depth: usize,
    batch: Vec<EndpointDataDelivery>,
}

impl EndpointEventSender {
    fn channel() -> (Self, EndpointEventReceiver) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let queued_messages = Arc::new(AtomicUsize::new(0));
        (
            Self {
                tx,
                queued_messages: Arc::clone(&queued_messages),
            },
            EndpointEventReceiver {
                rx,
                queued_messages,
            },
        )
    }

    pub(crate) fn send(
        &self,
        event: NodeEndpointEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        let count = event.message_count();
        let previous = self.queued_messages.fetch_add(count, Relaxed);
        let queued = previous.saturating_add(count);
        match self.tx.send(event) {
            Ok(()) => {
                if previous < ENDPOINT_EVENT_BACKLOG_HIGH_WATER
                    && queued >= ENDPOINT_EVENT_BACKLOG_HIGH_WATER
                {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::EndpointEventBacklogHigh,
                    );
                }
                Ok(())
            }
            Err(error) => {
                self.queued_messages.fetch_sub(count, Relaxed);
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn queued_messages(&self) -> usize {
        self.queued_messages.load(Relaxed)
    }
}

impl EndpointEventRuntime {
    fn attach(&mut self, sender: EndpointEventSender) {
        self.sender = Some(sender);
        self.batch_depth = 0;
        self.batch.clear();
    }

    pub(in crate::node) fn is_attached(&self) -> bool {
        self.sender.is_some()
    }

    pub(in crate::node) fn begin_batch(&mut self) {
        if self.is_attached() {
            self.batch_depth = self.batch_depth.saturating_add(1);
        }
    }

    pub(in crate::node) fn finish_batch(&mut self) {
        if self.batch_depth == 0 {
            return;
        }
        self.batch_depth -= 1;
        if self.batch_depth == 0 {
            self.flush_batch();
        }
    }

    pub(in crate::node) fn deliver_endpoint_data(
        &mut self,
        message: EndpointDataDelivery,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        if self.batch_depth > 0 {
            self.batch.push(message);
            return Ok(());
        }

        self.send(NodeEndpointEvent::Data {
            source_peer: message.source_peer,
            payload: message.payload,
            queued_at: crate::perf_profile::stamp(),
        })
    }

    fn flush_batch(&mut self) {
        let count = self.batch.len();
        if count == 0 {
            return;
        }

        let queued_at = crate::perf_profile::stamp();
        let event = if count == 1 {
            let message = self.batch.pop().expect("batch should contain message");
            NodeEndpointEvent::Data {
                source_peer: message.source_peer,
                payload: message.payload,
                queued_at,
            }
        } else {
            NodeEndpointEvent::DataBatch {
                messages: std::mem::take(&mut self.batch),
                queued_at,
            }
        };

        if let Err(error) = self.send(event) {
            debug!(
                error = %error,
                messages = count,
                "Failed to deliver endpoint data event batch"
            );
        }
    }

    fn send(
        &self,
        event: NodeEndpointEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        let Some(sender) = &self.sender else {
            return Ok(());
        };
        let _t_deliver =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
        sender.send(event)
    }
}

impl EndpointEventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<NodeEndpointEvent> {
        let event = self.rx.recv().await?;
        self.note_dequeued(&event);
        Some(event)
    }

    pub(crate) fn blocking_recv(&mut self) -> Option<NodeEndpointEvent> {
        let event = self.rx.blocking_recv()?;
        self.note_dequeued(&event);
        Some(event)
    }

    pub(crate) fn try_recv(
        &mut self,
    ) -> Result<NodeEndpointEvent, tokio::sync::mpsc::error::TryRecvError> {
        let event = self.rx.try_recv()?;
        self.note_dequeued(&event);
        Ok(event)
    }

    fn note_dequeued(&self, event: &NodeEndpointEvent) {
        let count = event.message_count();
        let _ = self
            .queued_messages
            .fetch_update(Relaxed, Relaxed, |current| {
                Some(current.saturating_sub(count))
            });
    }
}

fn endpoint_data_command_capacity(requested: usize) -> usize {
    if let Ok(raw) = std::env::var("FIPS_ENDPOINT_DATA_QUEUE_CAP")
        && let Ok(value) = raw.trim().parse::<usize>()
        && value > 0
    {
        return value;
    }

    requested.max(1).max(32_768)
}

/// Commands accepted by the node endpoint data service.
#[derive(Debug)]
pub(crate) enum NodeEndpointCommand {
    /// Send with an explicit response channel — used by callers that
    /// care whether the local-stack handoff succeeded (e.g.
    /// `blocking_send` waits for the runtime to accept the send).
    Send {
        command: EndpointSendCommand,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    /// **Fire-and-forget** variant of `Send` — no oneshot allocation,
    /// no per-packet result channel. Used by the data-plane fast path
    /// (`FipsEndpoint::send`) where the caller already discards the
    /// result. Saves one oneshot::channel() allocation per outbound
    /// packet on the application's send hot path.
    SendOneway { command: EndpointSendCommand },
    /// Fire-and-forget batch of endpoint payloads that already share the same
    /// peer and command lane. This keeps bursty embedded dataplanes from
    /// paying one mpsc send/wake per packet while preserving the priority/bulk
    /// split without repeating the resolved peer identity in every payload.
    SendBatchOneway {
        command: EndpointSendBatchCommand,
        lane: EndpointCommandLane,
    },
    PeerSnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointPeer>>,
    },
    RelaySnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointRelayStatus>>,
    },
    UpdateRelays {
        advert_relays: Vec<String>,
        dm_relays: Vec<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    /// Replace the runtime peer list. Newly added auto-connect peers get
    /// `initiate_peer_connection` immediately; removed peers are dropped
    /// from the retry queue (the regular liveness timeout reaps any active
    /// session). Existing entries are kept and their `addresses` field is
    /// refreshed so the next retry sees the latest hints.
    UpdatePeers {
        peers: Vec<crate::config::PeerConfig>,
        response_tx: tokio::sync::oneshot::Sender<Result<UpdatePeersOutcome, NodeError>>,
    },
}

/// Message payload for outbound endpoint data handed from an embedded
/// application into the node rx loop.
#[derive(Debug)]
pub(crate) struct EndpointSendCommand {
    send: EndpointDataSend,
    queued_at: Option<std::time::Instant>,
}

impl EndpointSendCommand {
    pub(crate) fn new(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<std::time::Instant>,
    ) -> Self {
        Self {
            send: EndpointDataSend::new(remote, EndpointDataPayload::new(payload)),
            queued_at,
        }
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.send.payload().lane()
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.send.payload().drop_on_backpressure()
    }

    pub(crate) fn into_parts(self) -> (EndpointDataSend, Option<std::time::Instant>) {
        (self.send, self.queued_at)
    }
}

/// Batch of endpoint payloads to one resolved peer.
#[derive(Debug)]
pub(crate) struct EndpointSendBatchCommand {
    remote: PeerIdentity,
    payloads: Vec<EndpointDataPayload>,
    queued_at: Option<std::time::Instant>,
}

impl EndpointSendBatchCommand {
    pub(crate) fn new(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<std::time::Instant>,
    ) -> Option<Self> {
        if payloads.is_empty() {
            return None;
        }
        Some(Self {
            remote,
            payloads,
            queued_at,
        })
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.payloads[0].lane()
    }

    pub(crate) fn len(&self) -> usize {
        self.payloads.len()
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.payloads
            .iter()
            .all(EndpointDataPayload::drop_on_backpressure)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PeerIdentity,
        Vec<EndpointDataPayload>,
        Option<std::time::Instant>,
    ) {
        (self.remote, self.payloads, self.queued_at)
    }
}

impl NodeEndpointCommand {
    pub(crate) fn send(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<std::time::Instant>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    ) -> Self {
        Self::Send {
            command: EndpointSendCommand::new(remote, payload, queued_at),
            response_tx,
        }
    }

    pub(crate) fn send_oneway(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<std::time::Instant>,
    ) -> Self {
        Self::SendOneway {
            command: EndpointSendCommand::new(remote, payload, queued_at),
        }
    }

    pub(crate) fn send_batch_oneway(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<std::time::Instant>,
        lane: EndpointCommandLane,
    ) -> Option<Self> {
        debug_assert!(payloads.iter().all(|payload| payload.lane() == lane));
        let command = EndpointSendBatchCommand::new(remote, payloads, queued_at)?;
        debug_assert_eq!(command.lane(), lane);
        Some(Self::SendBatchOneway { command, lane })
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        match self {
            Self::Send { command, .. } | Self::SendOneway { command } => command.lane(),
            Self::SendBatchOneway { lane, .. } => *lane,
            Self::PeerSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. } => EndpointCommandLane::Priority,
        }
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        match self {
            Self::SendOneway { command } => {
                command.lane() == EndpointCommandLane::Bulk && command.drop_on_backpressure()
            }
            Self::SendBatchOneway { command, lane } => {
                *lane == EndpointCommandLane::Bulk && command.drop_on_backpressure()
            }
            Self::Send { .. }
            | Self::PeerSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. } => false,
        }
    }

    pub(crate) fn drain_cost(&self) -> usize {
        match self {
            Self::SendBatchOneway { command, .. } => command.len().max(1),
            Self::Send { .. }
            | Self::SendOneway { .. }
            | Self::PeerSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. } => 1,
        }
    }
}

/// Reports what changed in response to `UpdatePeers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UpdatePeersOutcome {
    pub(crate) added: usize,
    pub(crate) removed: usize,
    pub(crate) updated: usize,
    pub(crate) unchanged: usize,
}

/// Authenticated endpoint data emitted by the session receive path.
///
/// Keeping source identity and payload together makes the delivery-side
/// ownership boundary explicit for the current rx loop and for a future
/// peer/session runtime that can move endpoint-data delivery off the bounce path.
#[derive(Debug)]
pub(crate) struct EndpointDataDelivery {
    pub(crate) source_peer: PeerIdentity,
    pub(crate) payload: Vec<u8>,
}

impl EndpointDataDelivery {
    pub(crate) fn new(source_peer: PeerIdentity, payload: Vec<u8>) -> Self {
        Self {
            source_peer,
            payload,
        }
    }
}

/// Endpoint data events emitted by the node session receive path.
#[derive(Debug)]
pub(crate) enum NodeEndpointEvent {
    Data {
        source_peer: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<std::time::Instant>,
    },
    DataBatch {
        messages: Vec<EndpointDataDelivery>,
        queued_at: Option<std::time::Instant>,
    },
}

impl NodeEndpointEvent {
    fn message_count(&self) -> usize {
        match self {
            NodeEndpointEvent::Data { .. } => 1,
            NodeEndpointEvent::DataBatch { messages, .. } => messages.len(),
        }
    }
}

/// Authenticated peer state exposed to embedded endpoint callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEndpointPeer {
    pub(crate) npub: String,
    pub(crate) connected: bool,
    pub(crate) transport_addr: Option<String>,
    pub(crate) transport_type: Option<String>,
    pub(crate) link_id: u64,
    pub(crate) srtt_ms: Option<u64>,
    pub(crate) packets_sent: u64,
    pub(crate) packets_recv: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_recv: u64,
    pub(crate) rekey_in_progress: bool,
    pub(crate) rekey_draining: bool,
    pub(crate) current_k_bit: Option<bool>,
    pub(crate) direct_probe_pending: bool,
    pub(crate) direct_probe_after_ms: Option<u64>,
    pub(crate) direct_probe_retry_count: u32,
    pub(crate) direct_probe_auto_reconnect: bool,
    pub(crate) direct_probe_expires_at_ms: Option<u64>,
    pub(crate) nostr_traversal_consecutive_failures: u32,
    pub(crate) nostr_traversal_in_cooldown: bool,
    pub(crate) nostr_traversal_cooldown_until_ms: Option<u64>,
    pub(crate) nostr_traversal_last_observed_skew_ms: Option<i64>,
}

/// Live Nostr relay state exposed to embedded endpoint callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEndpointRelayStatus {
    pub(crate) url: String,
    pub(crate) status: String,
}

/// Node operational state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    /// Created but not started.
    Created,
    /// Starting up (initializing transports).
    Starting,
    /// Fully operational.
    Running,
    /// Shutting down.
    Stopping,
    /// Stopped.
    Stopped,
}

impl NodeState {
    /// Check if node is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, NodeState::Running)
    }

    /// Check if node can be started.
    pub fn can_start(&self) -> bool {
        matches!(self, NodeState::Created | NodeState::Stopped)
    }

    /// Check if node can be stopped.
    pub fn can_stop(&self) -> bool {
        matches!(self, NodeState::Running)
    }
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NodeState::Created => "created",
            NodeState::Starting => "starting",
            NodeState::Running => "running",
            NodeState::Stopping => "stopping",
            NodeState::Stopped => "stopped",
        };
        write!(f, "{}", s)
    }
}

/// Recent request tracking for dedup and reverse-path forwarding.
///
/// When a LookupRequest is forwarded through a node, the node stores the
/// request_id and which peer sent it. When the corresponding LookupResponse
/// arrives, it's forwarded back to that peer (reverse-path forwarding).
/// The `response_forwarded` flag prevents response routing loops.
#[derive(Clone, Debug)]
pub(crate) struct RecentRequest {
    /// The peer who sent this request to us.
    pub(crate) from_peer: NodeAddr,
    /// When we received this request (Unix milliseconds).
    pub(crate) timestamp_ms: u64,
    /// Whether we've already forwarded a response for this request.
    /// Prevents response routing loops when convergent request paths
    /// create bidirectional entries in recent_requests.
    pub(crate) response_forwarded: bool,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            from_peer,
            timestamp_ms,
            response_forwarded: false,
        }
    }

    /// Check if this entry has expired (older than expiry_ms).
    pub(crate) fn is_expired(&self, current_time_ms: u64, expiry_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.timestamp_ms) > expiry_ms
    }
}

/// Admission result for recent discovery request tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecentDiscoveryRequestAdmission {
    accepted: bool,
    deduplicated: bool,
    cache_full: bool,
}

impl RecentDiscoveryRequestAdmission {
    pub(crate) fn accepted(&self) -> bool {
        self.accepted
    }

    pub(crate) fn deduplicated(&self) -> bool {
        self.deduplicated
    }

    pub(crate) fn cache_full(&self) -> bool {
        self.cache_full
    }
}

/// Reverse-path forwarding decision for a LookupResponse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecentResponseForward {
    Missing,
    AlreadyForwarded,
    Forward { from_peer: NodeAddr },
}

/// Recent discovery requests used for dedup and reverse-path forwarding.
#[derive(Debug, Default)]
pub(crate) struct RecentDiscoveryRequests {
    entries: HashMap<u64, RecentRequest>,
}

impl RecentDiscoveryRequests {
    pub(crate) fn record_request(
        &mut self,
        request_id: u64,
        from_peer: NodeAddr,
        now_ms: u64,
        max_entries: usize,
    ) -> RecentDiscoveryRequestAdmission {
        if self.entries.contains_key(&request_id) {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: true,
                cache_full: false,
            };
        }

        if self.entries.len() >= max_entries {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: false,
                cache_full: true,
            };
        }

        self.entries
            .insert(request_id, RecentRequest::new(from_peer, now_ms));
        RecentDiscoveryRequestAdmission {
            accepted: true,
            deduplicated: false,
            cache_full: false,
        }
    }

    pub(crate) fn claim_response_forward(&mut self, request_id: u64) -> RecentResponseForward {
        let Some(recent) = self.entries.get_mut(&request_id) else {
            return RecentResponseForward::Missing;
        };

        if recent.response_forwarded {
            return RecentResponseForward::AlreadyForwarded;
        }

        recent.response_forwarded = true;
        RecentResponseForward::Forward {
            from_peer: recent.from_peer,
        }
    }

    pub(crate) fn purge_expired(&mut self, current_time_ms: u64, expiry_ms: u64) {
        self.entries
            .retain(|_, entry| !entry.is_expired(current_time_ms, expiry_ms));
    }

    #[cfg(test)]
    pub(crate) fn insert(
        &mut self,
        request_id: u64,
        request: RecentRequest,
    ) -> Option<RecentRequest> {
        self.entries.insert(request_id, request)
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, request_id: &u64) -> bool {
        self.entries.contains_key(request_id)
    }

    pub(crate) fn get(&self, request_id: &u64) -> Option<&RecentRequest> {
        self.entries.get(request_id)
    }

    #[cfg(test)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &RecentRequest> {
        self.entries.values()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Key for reverse address dispatch.
type AddrKey = (TransportId, TransportAddr);

/// Reverse index from `(transport, remote address)` to active/pending link.
#[derive(Debug, Default)]
pub(in crate::node) struct LinkAddressIndex {
    entries: HashMap<AddrKey, LinkId>,
}

impl LinkAddressIndex {
    pub(in crate::node) fn insert(&mut self, key: AddrKey, link_id: LinkId) -> Option<LinkId> {
        self.entries.insert(key, link_id)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove(&mut self, key: &AddrKey) -> Option<LinkId> {
        self.entries.remove(key)
    }

    pub(in crate::node) fn remove_if_points_to(&mut self, key: &AddrKey, link_id: &LinkId) -> bool {
        if self.entries.get(key) == Some(link_id) {
            self.entries.remove(key);
            true
        } else {
            false
        }
    }

    pub(in crate::node) fn lookup(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.entries.get(&(transport_id, addr.clone())).copied()
    }

    #[cfg(test)]
    pub(in crate::node) fn get(&self, key: &AddrKey) -> Option<&LinkId> {
        self.entries.get(key)
    }

    pub(in crate::node) fn contains_key(&self, key: &AddrKey) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Link storage plus reverse dispatch index.
#[derive(Debug, Default)]
pub(in crate::node) struct LinkRegistry {
    links: HashMap<LinkId, Link>,
    by_addr: LinkAddressIndex,
}

impl LinkRegistry {
    pub(in crate::node) fn insert(&mut self, link_id: LinkId, link: Link) -> Option<Link> {
        debug_assert_eq!(link_id, link.link_id());
        let previous = self.links.insert(link_id, link);
        if let Some(previous) = &previous {
            let previous_key = (previous.transport_id(), previous.remote_addr().clone());
            self.by_addr.remove_if_points_to(&previous_key, &link_id);
        }

        let link = self
            .links
            .get(&link_id)
            .expect("link inserted above should be present");
        self.by_addr
            .insert((link.transport_id(), link.remote_addr().clone()), link_id);
        previous
    }

    pub(in crate::node) fn insert_addr(&mut self, key: AddrKey, link_id: LinkId) -> Option<LinkId> {
        self.by_addr.insert(key, link_id)
    }

    pub(in crate::node) fn remove(&mut self, link_id: &LinkId) -> Option<Link> {
        let link = self.links.remove(link_id)?;
        let key = (link.transport_id(), link.remote_addr().clone());
        self.by_addr.remove_if_points_to(&key, link_id);
        Some(link)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove_addr(&mut self, key: &AddrKey) -> Option<LinkId> {
        self.by_addr.remove(key)
    }

    pub(in crate::node) fn lookup_addr(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.by_addr.lookup(transport_id, addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn get_addr(&self, key: &AddrKey) -> Option<&LinkId> {
        self.by_addr.get(key)
    }

    pub(in crate::node) fn contains_addr(&self, key: &AddrKey) -> bool {
        self.by_addr.contains_key(key)
    }

    pub(in crate::node) fn get(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    pub(in crate::node) fn get_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, link_id: &LinkId) -> bool {
        self.links.contains_key(link_id)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.links.len()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    #[cfg(test)]
    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&LinkId, &Link)> {
        self.links.iter()
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
}

/// Per-transport kernel drop tracking for congestion detection.
///
/// Sampled every tick (1s). The `dropping` flag indicates whether new
/// kernel drops were observed since the previous sample.
#[derive(Debug, Default)]
struct TransportDropState {
    /// Previous `recv_drops` sample (cumulative counter).
    prev_drops: u64,
    /// True if drops increased since the last sample.
    dropping: bool,
}

#[derive(Debug, Default)]
pub(in crate::node) struct TransportDropTracker {
    states: HashMap<TransportId, TransportDropState>,
}

impl TransportDropTracker {
    pub(in crate::node) fn any_dropping(&self) -> bool {
        self.states.values().any(|state| state.dropping)
    }

    pub(in crate::node) fn sample(
        &mut self,
        transport_id: TransportId,
        recv_drops: Option<u64>,
    ) -> bool {
        let state = self.states.entry(transport_id).or_default();
        let Some(current) = recv_drops else {
            return false;
        };

        let new_drops = current > state.prev_drops;
        let rising_edge = new_drops && !state.dropping;
        state.dropping = new_drops;
        state.prev_drops = current;
        rising_edge
    }

    pub(in crate::node) fn remove(&mut self, transport_id: &TransportId) {
        self.states.remove(transport_id);
    }

    #[cfg(test)]
    pub(in crate::node) fn set_for_test(
        &mut self,
        transport_id: TransportId,
        prev_drops: u64,
        dropping: bool,
    ) {
        self.states.insert(
            transport_id,
            TransportDropState {
                prev_drops,
                dropping,
            },
        );
    }
}

/// State for a link waiting for transport-level connection establishment.
///
/// For connection-oriented transports (TCP, Tor), the transport connect runs
/// asynchronously. This struct holds the data needed to complete the handshake
/// once the connection is ready.
struct PendingConnect {
    /// The link that was created for this connection.
    link_id: LinkId,
    /// Which transport is being used.
    transport_id: TransportId,
    /// The remote address being connected to.
    remote_addr: TransportAddr,
    /// The peer identity (for handshake initiation).
    peer_identity: PeerIdentity,
}

/// Active FMP receiver-index registry keyed by `(transport_id, our_index)`.
#[derive(Debug, Default)]
pub(in crate::node) struct SessionIndexRegistry {
    entries: HashMap<(TransportId, u32), NodeAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct RemovedSessionIndex {
    pub(in crate::node) owner: NodeAddr,
    pub(in crate::node) owner_has_remaining_index: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum PeerSessionIndexKind {
    Current,
    Rekey,
    Pending,
    Previous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct PeerSessionIndex {
    pub(in crate::node) kind: PeerSessionIndexKind,
    pub(in crate::node) key: (TransportId, u32),
    pub(in crate::node) index: SessionIndex,
}

#[derive(Debug)]
pub(in crate::node) struct RemovedActivePeer {
    pub(in crate::node) peer: ActivePeer,
    pub(in crate::node) session_indices: Vec<PeerSessionIndex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct RegisteredPeerSessionIndex {
    pub(in crate::node) session_index: PeerSessionIndex,
    pub(in crate::node) previous_owner: Option<NodeAddr>,
}

#[derive(Debug)]
pub(in crate::node) struct InsertedActivePeer {
    pub(in crate::node) previous_peer: Option<ActivePeer>,
    pub(in crate::node) current_session_index: Option<RegisteredPeerSessionIndex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum CurrentSessionIndexRegistration {
    MissingActivePeer,
    MissingTransportId,
    MissingLocalIndex,
    AlreadyRegistered(PeerSessionIndex),
    Repaired(RegisteredPeerSessionIndex),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct ReplacedActivePeerCurrentSession {
    pub(in crate::node) old_link_id: LinkId,
    pub(in crate::node) old_session_index: Option<PeerSessionIndex>,
    pub(in crate::node) new_session_index: RegisteredPeerSessionIndex,
    pub(in crate::node) replay_suppressed_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct AuthenticatedFmpReceiveBookkeeping {
    pub(in crate::node) address_changed: bool,
    pub(in crate::node) path_bookkeeping_recorded: bool,
    pub(in crate::node) mmp_recorded: bool,
    pub(in crate::node) spin_rtt: Option<std::time::Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum PeerRuntimeReceiveError {
    MissingInnerTimestamp,
}

pub(in crate::node) struct AuthenticatedFmpPlaintext<'a> {
    source_peer: PeerIdentity,
    transport_id: TransportId,
    remote_addr: &'a TransportAddr,
    packet_timestamp_ms: u64,
    packet_len: usize,
    fmp_counter: u64,
    fmp_flags: u8,
    plaintext: &'a [u8],
}

pub(in crate::node) struct PeerRuntimeReceive<'a> {
    source_peer: PeerIdentity,
    transport_id: TransportId,
    remote_addr: &'a TransportAddr,
    packet_timestamp_ms: u64,
    packet_len: usize,
    fmp_counter: u64,
    inner_timestamp_ms: u32,
    ce_flag: bool,
    sp_flag: bool,
    link_message: &'a [u8],
}

pub(in crate::node) struct PeerRuntimeReceiveDispatch<'a> {
    source_peer: PeerIdentity,
    ce_flag: bool,
    link_message: &'a [u8],
    bookkeeping: Option<AuthenticatedFmpReceiveBookkeeping>,
}

pub(in crate::node) struct AuthenticatedLinkMessage<'a> {
    source_peer: PeerIdentity,
    msg_type: u8,
    payload: &'a [u8],
    ce_flag: bool,
}

pub(in crate::node) struct AuthenticatedSessionDatagram<'a> {
    previous_hop_peer: PeerIdentity,
    payload: &'a [u8],
    ce_flag: bool,
}

pub(in crate::node) struct LocalSessionPayload<'a> {
    source_addr: NodeAddr,
    previous_hop_peer: PeerIdentity,
    payload: &'a [u8],
    path_mtu: u16,
    ce_flag: bool,
}

pub(in crate::node) struct EncryptedSessionPayload<'a> {
    source_addr: NodeAddr,
    previous_hop_peer: PeerIdentity,
    payload: &'a [u8],
    path_mtu: u16,
    ce_flag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FmpSendBookkeeping {
    pub(in crate::node) mmp_recorded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum FmpSendPreparationError {
    MissingPeer,
    MissingTheirIndex,
    MissingTransportId,
    MissingCurrentAddr,
    MissingNoiseSession,
    PayloadLengthMismatch,
    CounterReservationFailed,
    EncryptionFailed,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum PeerRuntimeRouteDecisionError {
    NoRoute {
        dest_addr: NodeAddr,
    },
    FmpPreparation {
        next_hop_addr: NodeAddr,
        error: FmpSendPreparationError,
    },
}

#[derive(Clone)]
pub(in crate::node) struct FmpSendPreparation {
    pub(in crate::node) their_index: SessionIndex,
    pub(in crate::node) transport_id: TransportId,
    pub(in crate::node) remote_addr: TransportAddr,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) connected_socket:
        Option<Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
    pub(in crate::node) timestamp_ms: u32,
    pub(in crate::node) flags: u8,
    pub(in crate::node) payload_len: u16,
}

#[derive(Clone)]
pub(in crate::node) struct PeerRuntimeRouteSnapshot {
    node_addr: NodeAddr,
    their_index: SessionIndex,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_socket: Option<Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
    timestamp_ms: u32,
    base_flags: u8,
    fmp_worker_send_available: bool,
}

#[cfg(unix)]
pub(in crate::node) struct PeerRuntimeRouteDecision {
    next_hop_addr: NodeAddr,
    peer_snapshot: PeerRuntimeRouteSnapshot,
    scheduling_weight: u8,
    direct_path_blocks_direct_payload: bool,
}

impl<'a> AuthenticatedFmpPlaintext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn new(
        source_peer: PeerIdentity,
        transport_id: TransportId,
        remote_addr: &'a TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        fmp_flags: u8,
        plaintext: &'a [u8],
    ) -> Self {
        Self {
            source_peer,
            transport_id,
            remote_addr,
            packet_timestamp_ms,
            packet_len,
            fmp_counter,
            fmp_flags,
            plaintext,
        }
    }

    pub(in crate::node) fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    pub(in crate::node) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    pub(in crate::node) fn remote_addr(&self) -> &'a TransportAddr {
        self.remote_addr
    }

    pub(in crate::node) fn packet_timestamp_ms(&self) -> u64 {
        self.packet_timestamp_ms
    }
}

impl<'a> PeerRuntimeReceive<'a> {
    const INNER_TIMESTAMP_LEN: usize = 4;

    pub(in crate::node) fn from_authenticated_fmp_plaintext(
        receive: AuthenticatedFmpPlaintext<'a>,
    ) -> Result<Self, PeerRuntimeReceiveError> {
        let AuthenticatedFmpPlaintext {
            source_peer,
            transport_id,
            remote_addr,
            packet_timestamp_ms,
            packet_len,
            fmp_counter,
            fmp_flags,
            plaintext,
        } = receive;

        if plaintext.len() < Self::INNER_TIMESTAMP_LEN {
            return Err(PeerRuntimeReceiveError::MissingInnerTimestamp);
        }

        let inner_timestamp_ms =
            u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        let link_message = &plaintext[Self::INNER_TIMESTAMP_LEN..];

        Ok(Self {
            source_peer,
            transport_id,
            remote_addr,
            packet_timestamp_ms,
            packet_len,
            fmp_counter,
            inner_timestamp_ms,
            ce_flag: fmp_flags & FLAG_CE != 0,
            sp_flag: fmp_flags & FLAG_SP != 0,
            link_message,
        })
    }

    pub(in crate::node) fn record_bookkeeping(
        &self,
        peers: &mut PeerLifecycleRegistry,
        now: std::time::Instant,
        path_bookkeeping_allowed: bool,
    ) -> PeerRuntimeReceiveDispatch<'a> {
        let node_addr = self.source_peer.node_addr();
        let bookkeeping = peers.record_authenticated_fmp_receive(
            node_addr,
            self.transport_id,
            self.remote_addr,
            self.packet_timestamp_ms,
            self.packet_len,
            self.fmp_counter,
            self.inner_timestamp_ms,
            self.ce_flag,
            self.sp_flag,
            now,
            path_bookkeeping_allowed,
        );

        PeerRuntimeReceiveDispatch {
            source_peer: self.source_peer,
            ce_flag: self.ce_flag,
            link_message: self.link_message,
            bookkeeping,
        }
    }
}

impl<'a> PeerRuntimeReceiveDispatch<'a> {
    #[cfg(test)]
    pub(in crate::node) fn source_peer(&self) -> PeerIdentity {
        self.source_peer
    }

    pub(in crate::node) fn node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    #[cfg(test)]
    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    #[cfg(test)]
    pub(in crate::node) fn link_message(&self) -> &'a [u8] {
        self.link_message
    }

    pub(in crate::node) fn into_link_message(self) -> Option<AuthenticatedLinkMessage<'a>> {
        let (&msg_type, payload) = self.link_message.split_first()?;
        Some(AuthenticatedLinkMessage {
            source_peer: self.source_peer,
            msg_type,
            payload,
            ce_flag: self.ce_flag,
        })
    }

    pub(in crate::node) fn address_changed(&self) -> bool {
        self.bookkeeping
            .is_some_and(|update| update.address_changed)
    }

    #[cfg(test)]
    pub(in crate::node) fn bookkeeping(&self) -> Option<AuthenticatedFmpReceiveBookkeeping> {
        self.bookkeeping
    }
}

impl<'a> AuthenticatedLinkMessage<'a> {
    pub(in crate::node) fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    pub(in crate::node) fn msg_type(&self) -> u8 {
        self.msg_type
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    #[cfg(test)]
    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(in crate::node) fn into_session_datagram(self) -> AuthenticatedSessionDatagram<'a> {
        debug_assert_eq!(self.msg_type, LinkMessageType::SessionDatagram.to_byte());
        AuthenticatedSessionDatagram::new(self.source_peer, self.payload, self.ce_flag)
    }
}

impl<'a> AuthenticatedSessionDatagram<'a> {
    pub(in crate::node) fn new(
        previous_hop_peer: PeerIdentity,
        payload: &'a [u8],
        ce_flag: bool,
    ) -> Self {
        Self {
            previous_hop_peer,
            payload,
            ce_flag,
        }
    }

    pub(in crate::node) fn previous_hop_addr(&self) -> &NodeAddr {
        self.previous_hop_peer.node_addr()
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(in crate::node) fn local_session_payload(
        &self,
        source_addr: NodeAddr,
        payload: &'a [u8],
        path_mtu: u16,
    ) -> LocalSessionPayload<'a> {
        LocalSessionPayload::new(
            source_addr,
            self.previous_hop_peer,
            payload,
            path_mtu,
            self.ce_flag,
        )
    }
}

impl<'a> LocalSessionPayload<'a> {
    pub(in crate::node) fn new(
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        payload: &'a [u8],
        path_mtu: u16,
        ce_flag: bool,
    ) -> Self {
        Self {
            source_addr,
            previous_hop_peer,
            payload,
            path_mtu,
            ce_flag,
        }
    }

    pub(in crate::node) fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    #[cfg(test)]
    pub(in crate::node) fn previous_hop_addr(&self) -> &NodeAddr {
        self.previous_hop_peer.node_addr()
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(in crate::node) fn into_encrypted(self) -> EncryptedSessionPayload<'a> {
        EncryptedSessionPayload {
            source_addr: self.source_addr,
            previous_hop_peer: self.previous_hop_peer,
            payload: self.payload,
            path_mtu: self.path_mtu,
            ce_flag: self.ce_flag,
        }
    }
}

impl<'a> EncryptedSessionPayload<'a> {
    pub(in crate::node) fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    pub(in crate::node) fn previous_hop_addr(&self) -> &NodeAddr {
        self.previous_hop_peer.node_addr()
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(in crate::node) fn path_mtu(&self) -> u16 {
        self.path_mtu
    }

    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
    }
}

impl PeerRuntimeRouteSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn new(
        node_addr: NodeAddr,
        their_index: SessionIndex,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        #[cfg(any(target_os = "linux", target_os = "macos"))] connected_socket: Option<
            Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
        >,
        timestamp_ms: u32,
        base_flags: u8,
        fmp_worker_send_available: bool,
    ) -> Self {
        Self {
            node_addr,
            their_index,
            transport_id,
            remote_addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket,
            timestamp_ms,
            base_flags,
            fmp_worker_send_available,
        }
    }

    pub(in crate::node) fn node_addr(&self) -> NodeAddr {
        self.node_addr
    }

    pub(in crate::node) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    #[cfg(test)]
    pub(in crate::node) fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    pub(in crate::node) fn path_mtu(&self, transport: &TransportHandle) -> u16 {
        debug_assert_eq!(transport.transport_id(), self.transport_id);
        transport.link_mtu(&self.remote_addr)
    }

    pub(in crate::node) fn prepare_send_snapshot(
        &self,
        ce_flag: bool,
        payload_len: u16,
    ) -> PeerRuntimeSendSnapshot {
        let mut flags = self.base_flags;
        if ce_flag {
            flags |= FLAG_CE;
        }

        PeerRuntimeSendSnapshot::new(
            self.node_addr,
            FmpSendPreparation {
                their_index: self.their_index,
                transport_id: self.transport_id,
                remote_addr: self.remote_addr.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                connected_socket: self.connected_socket.clone(),
                timestamp_ms: self.timestamp_ms,
                flags,
                payload_len,
            },
            self.fmp_worker_send_available,
        )
    }
}

#[cfg(unix)]
impl PeerRuntimeRouteDecision {
    pub(in crate::node) fn new(
        next_hop_addr: NodeAddr,
        peer_snapshot: PeerRuntimeRouteSnapshot,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Self {
        debug_assert_eq!(next_hop_addr, peer_snapshot.node_addr());
        Self {
            next_hop_addr,
            peer_snapshot,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        }
    }

    #[cfg(test)]
    pub(in crate::node) fn next_hop_addr(&self) -> NodeAddr {
        self.next_hop_addr
    }

    #[cfg(test)]
    pub(in crate::node) fn peer_snapshot(&self) -> &PeerRuntimeRouteSnapshot {
        &self.peer_snapshot
    }

    #[cfg(test)]
    pub(in crate::node) fn scheduling_weight(&self) -> u8 {
        self.scheduling_weight
    }

    #[cfg(test)]
    pub(in crate::node) fn direct_path_blocks_direct_payload(&self) -> bool {
        self.direct_path_blocks_direct_payload
    }

    pub(in crate::node) fn into_parts(self) -> (PeerRuntimeRouteSnapshot, u8, bool) {
        let Self {
            next_hop_addr,
            peer_snapshot,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        } = self;
        debug_assert_eq!(next_hop_addr, peer_snapshot.node_addr());
        (
            peer_snapshot,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        )
    }
}

pub(in crate::node) struct PeerRuntimeSendSnapshot {
    node_addr: NodeAddr,
    fmp_prepared: FmpSendPreparation,
    fmp_worker_send_available: bool,
}

impl PeerRuntimeSendSnapshot {
    pub(in crate::node) fn new(
        node_addr: NodeAddr,
        fmp_prepared: FmpSendPreparation,
        fmp_worker_send_available: bool,
    ) -> Self {
        Self {
            node_addr,
            fmp_prepared,
            fmp_worker_send_available,
        }
    }

    #[cfg(test)]
    pub(in crate::node) fn node_addr(&self) -> NodeAddr {
        self.node_addr
    }

    pub(in crate::node) fn fmp_prepared(&self) -> &FmpSendPreparation {
        &self.fmp_prepared
    }

    pub(in crate::node) fn fmp_worker_send_available(&self) -> bool {
        self.fmp_worker_send_available
    }
}

pub(in crate::node) struct PreparedFmpInlineSend {
    pub(in crate::node) counter: u64,
    #[cfg(test)]
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) wire_packet: Vec<u8>,
}

#[cfg(unix)]
pub(in crate::node) struct PreparedFmpWorkerReservation {
    pub(in crate::node) counter: u64,
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) cipher: ring::aead::LessSafeKey,
    pub(in crate::node) predicted_bytes: usize,
}

#[cfg(unix)]
pub(in crate::node) struct PreparedFmpWorkerSend {
    pub(in crate::node) counter: u64,
    #[cfg(test)]
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) cipher: ring::aead::LessSafeKey,
    pub(in crate::node) wire_buf: Vec<u8>,
    pub(in crate::node) predicted_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::node) struct ConnectedUdpActivationPlan {
    pub(in crate::node) candidates: Vec<NodeAddr>,
    pub(in crate::node) installed_count: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum ConnectedUdpInstallResult {
    MissingPeer,
    NotEligible,
    Installed,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum ConnectedUdpClearResult {
    MissingPeer,
    AlreadyClear,
    Cleared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct LinkDeadDirectPathDegradation {
    pub(in crate::node) link_id: LinkId,
    pub(in crate::node) connected_udp_cleared: bool,
}

impl SessionIndexRegistry {
    pub(in crate::node) fn insert(
        &mut self,
        key: (TransportId, u32),
        node_addr: NodeAddr,
    ) -> Option<NodeAddr> {
        self.entries.insert(key, node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove(&mut self, key: &(TransportId, u32)) -> Option<NodeAddr> {
        self.entries.remove(key)
    }

    pub(in crate::node) fn remove_with_owner_state(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<RemovedSessionIndex> {
        let owner = self.entries.remove(key)?;
        let owner_has_remaining_index = self.peer_has_any_index(&owner);
        Some(RemovedSessionIndex {
            owner,
            owner_has_remaining_index,
        })
    }

    pub(in crate::node) fn lookup(&self, key: (TransportId, u32)) -> Option<NodeAddr> {
        self.entries.get(&key).copied()
    }

    pub(in crate::node) fn peer_has_any_index(&self, node_addr: &NodeAddr) -> bool {
        self.entries.values().any(|other| other == node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn get(&self, key: &(TransportId, u32)) -> Option<&NodeAddr> {
        self.entries.get(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, key: &(TransportId, u32)) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Active peer storage plus receiver-index dispatch.
#[derive(Debug, Default)]
pub(in crate::node) struct ActivePeerRegistry {
    peers: HashMap<NodeAddr, ActivePeer>,
    by_session_index: SessionIndexRegistry,
}

impl ActivePeerRegistry {
    pub(in crate::node) fn insert(
        &mut self,
        node_addr: NodeAddr,
        peer: ActivePeer,
    ) -> Option<ActivePeer> {
        debug_assert_eq!(&node_addr, peer.node_addr());
        self.peers.insert(node_addr, peer)
    }

    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.peers.remove(node_addr)
    }

    pub(in crate::node) fn get(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.peers.get(node_addr)
    }

    pub(in crate::node) fn get_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_addr)
    }

    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.peers.contains_key(node_addr)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.peers.len()
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    pub(in crate::node) fn values_mut(&mut self) -> impl Iterator<Item = &mut ActivePeer> {
        self.peers.values_mut()
    }

    pub(in crate::node) fn keys(&self) -> impl Iterator<Item = &NodeAddr> {
        self.peers.keys()
    }

    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &ActivePeer)> {
        self.peers.iter()
    }

    pub(in crate::node) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&NodeAddr, &mut ActivePeer)> {
        self.peers.iter_mut()
    }

    pub(in crate::node) fn insert_session_index(
        &mut self,
        key: (TransportId, u32),
        node_addr: NodeAddr,
    ) -> Option<NodeAddr> {
        self.by_session_index.insert(key, node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove_session_index(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<NodeAddr> {
        self.by_session_index.remove(key)
    }

    pub(in crate::node) fn remove_session_index_with_owner_state(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<RemovedSessionIndex> {
        self.by_session_index.remove_with_owner_state(key)
    }

    pub(in crate::node) fn lookup_session_index(
        &self,
        key: (TransportId, u32),
    ) -> Option<NodeAddr> {
        self.by_session_index.lookup(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn peer_has_any_session_index(&self, node_addr: &NodeAddr) -> bool {
        self.by_session_index.peer_has_any_index(node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn get_session_index(&self, key: &(TransportId, u32)) -> Option<&NodeAddr> {
        self.by_session_index.get(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_session_index(&self, key: &(TransportId, u32)) -> bool {
        self.by_session_index.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn session_index_is_empty(&self) -> bool {
        self.by_session_index.is_empty()
    }
}

impl<'a> IntoIterator for &'a ActivePeerRegistry {
    type Item = (&'a NodeAddr, &'a ActivePeer);
    type IntoIter = std::collections::hash_map::Iter<'a, NodeAddr, ActivePeer>;

    fn into_iter(self) -> Self::IntoIter {
        self.peers.iter()
    }
}

/// Peer lifecycle storage for handshake and active phases.
#[derive(Debug, Default)]
pub(in crate::node) struct PeerLifecycleRegistry {
    connections: HashMap<LinkId, PeerConnection>,
    active: ActivePeerRegistry,
}

impl PeerLifecycleRegistry {
    fn active_peer_current_session_index(peer: &ActivePeer) -> Option<PeerSessionIndex> {
        let transport_id = peer.transport_id()?;
        let index = peer.our_index()?;
        Some(PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: (transport_id, index.as_u32()),
            index,
        })
    }

    fn active_peer_session_indices(peer: &ActivePeer) -> Vec<PeerSessionIndex> {
        let Some(transport_id) = peer.transport_id() else {
            return Vec::new();
        };

        let mut indices = Vec::with_capacity(4);
        if let Some(current) = Self::active_peer_current_session_index(peer) {
            indices.push(current);
        }
        let mut push_index = |kind: PeerSessionIndexKind, index: Option<SessionIndex>| {
            let Some(index) = index else {
                return;
            };
            let key = (transport_id, index.as_u32());
            if indices
                .iter()
                .any(|existing: &PeerSessionIndex| existing.key == key)
            {
                return;
            }
            indices.push(PeerSessionIndex { kind, key, index });
        };

        push_index(PeerSessionIndexKind::Rekey, peer.rekey_our_index());
        push_index(PeerSessionIndexKind::Pending, peer.pending_our_index());
        push_index(PeerSessionIndexKind::Previous, peer.previous_our_index());
        indices
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn connected_udp_activation_candidate(peer: &ActivePeer) -> bool {
        peer.is_healthy()
            && peer.noise_session().is_some()
            && peer.transport_id().is_some()
            && peer.current_addr().is_some()
            && peer.connected_udp().is_none()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn connected_udp_activation_order(mut candidates: Vec<(NodeAddr, bool)>) -> Vec<NodeAddr> {
        candidates.sort_by_key(|(addr, is_configured)| (!*is_configured, *addr));
        candidates.into_iter().map(|(addr, _)| addr).collect()
    }

    pub(in crate::node) fn insert_connection(
        &mut self,
        link_id: LinkId,
        connection: PeerConnection,
    ) -> Option<PeerConnection> {
        debug_assert_eq!(link_id, connection.link_id());
        self.connections.insert(link_id, connection)
    }

    pub(in crate::node) fn remove_connection(
        &mut self,
        link_id: &LinkId,
    ) -> Option<PeerConnection> {
        self.connections.remove(link_id)
    }

    pub(in crate::node) fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.connections.get(link_id)
    }

    pub(in crate::node) fn get_connection_mut(
        &mut self,
        link_id: &LinkId,
    ) -> Option<&mut PeerConnection> {
        self.connections.get_mut(link_id)
    }

    pub(in crate::node) fn contains_connection(&self, link_id: &LinkId) -> bool {
        self.connections.contains_key(link_id)
    }

    pub(in crate::node) fn connection_len(&self) -> usize {
        self.connections.len()
    }

    pub(in crate::node) fn connection_is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    pub(in crate::node) fn connection_values(&self) -> impl Iterator<Item = &PeerConnection> {
        self.connections.values()
    }

    pub(in crate::node) fn connection_iter(
        &self,
    ) -> impl Iterator<Item = (&LinkId, &PeerConnection)> {
        self.connections.iter()
    }

    #[cfg(test)]
    pub(in crate::node) fn connection_keys(&self) -> impl Iterator<Item = &LinkId> {
        self.connections.keys()
    }

    #[cfg(test)]
    pub(in crate::node) fn insert(
        &mut self,
        node_addr: NodeAddr,
        peer: ActivePeer,
    ) -> Option<ActivePeer> {
        self.active.insert(node_addr, peer)
    }

    pub(in crate::node) fn insert_with_current_session_index(
        &mut self,
        node_addr: NodeAddr,
        peer: ActivePeer,
    ) -> InsertedActivePeer {
        let current_session_index = Self::active_peer_current_session_index(&peer);
        let previous_peer = self.active.insert(node_addr, peer);
        let current_session_index = current_session_index.map(|session_index| {
            let previous_owner = self
                .active
                .insert_session_index(session_index.key, node_addr);
            RegisteredPeerSessionIndex {
                session_index,
                previous_owner,
            }
        });
        InsertedActivePeer {
            previous_peer,
            current_session_index,
        }
    }

    pub(in crate::node) fn ensure_current_session_index_registered(
        &mut self,
        node_addr: &NodeAddr,
    ) -> CurrentSessionIndexRegistration {
        let Some(peer) = self.active.get(node_addr) else {
            return CurrentSessionIndexRegistration::MissingActivePeer;
        };
        let Some(transport_id) = peer.transport_id() else {
            return CurrentSessionIndexRegistration::MissingTransportId;
        };
        let Some(our_index) = peer.our_index() else {
            return CurrentSessionIndexRegistration::MissingLocalIndex;
        };
        let session_index = PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: (transport_id, our_index.as_u32()),
            index: our_index,
        };

        match self.active.lookup_session_index(session_index.key) {
            Some(existing) if existing == *node_addr => {
                CurrentSessionIndexRegistration::AlreadyRegistered(session_index)
            }
            expected_previous_owner => {
                let previous_owner = self
                    .active
                    .insert_session_index(session_index.key, *node_addr);
                debug_assert_eq!(previous_owner, expected_previous_owner);
                CurrentSessionIndexRegistration::Repaired(RegisteredPeerSessionIndex {
                    session_index,
                    previous_owner,
                })
            }
        }
    }

    pub(in crate::node) fn replace_current_session_and_path(
        &mut self,
        node_addr: &NodeAddr,
        new_session: crate::noise::NoiseSession,
        new_our_index: SessionIndex,
        new_their_index: SessionIndex,
        new_link_id: LinkId,
        new_transport_id: TransportId,
        new_addr: &TransportAddr,
        new_remote_epoch: Option<[u8; 8]>,
        connected_at_ms: u64,
    ) -> Option<ReplacedActivePeerCurrentSession> {
        let new_session_index = PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: (new_transport_id, new_our_index.as_u32()),
            index: new_our_index,
        };
        let (old_link_id, old_session_index, replay_suppressed_count) = {
            let peer = self.active.get_mut(node_addr)?;
            let previous_current_index = Self::active_peer_current_session_index(peer);
            let old_link_id = peer.link_id();
            let replay_suppressed_count = peer.replay_suppressed_count();
            let replaced_our_index =
                peer.replace_session(new_session, new_our_index, new_their_index);
            debug_assert_eq!(
                previous_current_index.map(|old| old.index),
                replaced_our_index
            );
            peer.set_link_id(new_link_id);
            peer.set_current_addr(new_transport_id, new_addr);
            if new_remote_epoch.is_some() {
                peer.set_remote_epoch(new_remote_epoch);
            }
            peer.mark_connected(connected_at_ms);
            (
                old_link_id,
                previous_current_index.filter(|old| old.key != new_session_index.key),
                replay_suppressed_count,
            )
        };

        let previous_owner = self
            .active
            .insert_session_index(new_session_index.key, *node_addr);
        Some(ReplacedActivePeerCurrentSession {
            old_link_id,
            old_session_index,
            new_session_index: RegisteredPeerSessionIndex {
                session_index: new_session_index,
                previous_owner,
            },
            replay_suppressed_count,
        })
    }

    pub(in crate::node) fn install_pending_rekey_session_and_index(
        &mut self,
        node_addr: &NodeAddr,
        pending_session: crate::noise::NoiseSession,
        pending_our_index: SessionIndex,
        pending_their_index: SessionIndex,
        initiated_by_local: bool,
        remote_epoch: Option<[u8; 8]>,
    ) -> Option<RegisteredPeerSessionIndex> {
        let pending_session_index = {
            let peer = self.active.get_mut(node_addr)?;
            let transport_id = peer.transport_id()?;
            let session_index = PeerSessionIndex {
                kind: PeerSessionIndexKind::Pending,
                key: (transport_id, pending_our_index.as_u32()),
                index: pending_our_index,
            };
            if remote_epoch.is_some() {
                peer.set_remote_epoch(remote_epoch);
            }
            peer.set_pending_session(
                pending_session,
                pending_our_index,
                pending_their_index,
                initiated_by_local,
            );
            if !initiated_by_local {
                peer.record_peer_rekey();
            }
            session_index
        };

        let previous_owner = self
            .active
            .insert_session_index(pending_session_index.key, *node_addr);
        Some(RegisteredPeerSessionIndex {
            session_index: pending_session_index,
            previous_owner,
        })
    }

    pub(in crate::node) fn record_authenticated_fmp_receive(
        &mut self,
        node_addr: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        inner_timestamp_ms: u32,
        ce_flag: bool,
        sp_flag: bool,
        now: std::time::Instant,
        path_bookkeeping_allowed: bool,
    ) -> Option<AuthenticatedFmpReceiveBookkeeping> {
        let peer = self.active.get_mut(node_addr)?;
        peer.reset_decrypt_failures();

        let mut result = AuthenticatedFmpReceiveBookkeeping {
            address_changed: false,
            path_bookkeeping_recorded: false,
            mmp_recorded: false,
            spin_rtt: None,
        };
        if !path_bookkeeping_allowed {
            return Some(result);
        }

        result.address_changed = peer.set_current_addr(transport_id, remote_addr);
        peer.link_stats_mut()
            .record_recv(packet_len, packet_timestamp_ms);
        peer.touch(packet_timestamp_ms);
        result.path_bookkeeping_recorded = true;
        if let Some(mmp) = peer.mmp_mut() {
            mmp.receiver
                .record_recv(fmp_counter, inner_timestamp_ms, packet_len, ce_flag, now);
            result.spin_rtt = mmp.spin_bit.rx_observe(sp_flag, fmp_counter, now);
            result.mmp_recorded = true;
        }

        Some(result)
    }

    pub(in crate::node) fn record_fmp_send_bookkeeping(
        &mut self,
        node_addr: &NodeAddr,
        fmp_counter: u64,
        timestamp_ms: u32,
        bytes_sent: usize,
    ) -> Option<FmpSendBookkeeping> {
        let peer = self.active.get_mut(node_addr)?;
        peer.link_stats_mut().record_sent(bytes_sent);

        let mut result = FmpSendBookkeeping {
            mmp_recorded: false,
        };
        if let Some(mmp) = peer.mmp_mut() {
            mmp.sender
                .record_sent(fmp_counter, timestamp_ms, bytes_sent);
            result.mmp_recorded = true;
        }
        Some(result)
    }

    pub(in crate::node) fn prepare_fmp_send(
        &self,
        node_addr: &NodeAddr,
        ce_flag: bool,
        payload_len: u16,
    ) -> Result<FmpSendPreparation, FmpSendPreparationError> {
        let peer = self
            .active
            .get(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        Self::fmp_send_preparation_from_peer(peer, ce_flag, payload_len)
    }

    fn fmp_send_preparation_from_peer(
        peer: &ActivePeer,
        ce_flag: bool,
        payload_len: u16,
    ) -> Result<FmpSendPreparation, FmpSendPreparationError> {
        let snapshot = Self::peer_runtime_route_snapshot_from_peer(*peer.node_addr(), peer)?
            .prepare_send_snapshot(ce_flag, payload_len);
        Ok(snapshot.fmp_prepared)
    }

    fn peer_runtime_route_snapshot_from_peer(
        node_addr: NodeAddr,
        peer: &ActivePeer,
    ) -> Result<PeerRuntimeRouteSnapshot, FmpSendPreparationError> {
        let their_index = peer
            .their_index()
            .ok_or(FmpSendPreparationError::MissingTheirIndex)?;
        let transport_id = peer
            .transport_id()
            .ok_or(FmpSendPreparationError::MissingTransportId)?;
        let remote_addr = peer
            .current_addr()
            .cloned()
            .ok_or(FmpSendPreparationError::MissingCurrentAddr)?;
        let noise_session = peer
            .noise_session()
            .ok_or(FmpSendPreparationError::MissingNoiseSession)?;

        let timestamp_ms = peer.session_elapsed_ms();
        let sp_flag = peer.mmp().map(|mmp| mmp.spin_bit.tx_bit()).unwrap_or(false);
        let mut base_flags = if sp_flag { FLAG_SP } else { 0 };
        if peer.current_k_bit() {
            base_flags |= FLAG_KEY_EPOCH;
        }

        Ok(PeerRuntimeRouteSnapshot::new(
            node_addr,
            their_index,
            transport_id,
            remote_addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            peer.connected_udp(),
            timestamp_ms,
            base_flags,
            noise_session.has_send_cipher(),
        ))
    }

    #[cfg(unix)]
    pub(in crate::node) fn prepare_peer_runtime_route_snapshot(
        &self,
        node_addr: &NodeAddr,
    ) -> Result<PeerRuntimeRouteSnapshot, FmpSendPreparationError> {
        let peer = self
            .active
            .get(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        Self::peer_runtime_route_snapshot_from_peer(*node_addr, peer)
    }

    #[cfg(all(unix, test))]
    pub(in crate::node) fn prepare_peer_runtime_send_snapshot(
        &self,
        node_addr: &NodeAddr,
        ce_flag: bool,
        payload_len: u16,
    ) -> Result<PeerRuntimeSendSnapshot, FmpSendPreparationError> {
        Ok(self
            .prepare_peer_runtime_route_snapshot(node_addr)?
            .prepare_send_snapshot(ce_flag, payload_len))
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_prepared_fmp_worker_send(
        &mut self,
        node_addr: &NodeAddr,
        prepared: &FmpSendPreparation,
    ) -> Result<Option<PreparedFmpWorkerReservation>, FmpSendPreparationError> {
        let peer = self
            .active
            .get_mut(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        let session = peer
            .noise_session_mut()
            .ok_or(FmpSendPreparationError::MissingNoiseSession)?;
        let reservation = reserve_fmp_worker_send(
            session,
            prepared.their_index,
            prepared.flags,
            prepared.payload_len,
        )
        .map_err(|_| FmpSendPreparationError::CounterReservationFailed)?;

        Ok(reservation.map(|reservation| {
            let predicted_bytes =
                ESTABLISHED_HEADER_SIZE + prepared.payload_len as usize + crate::noise::TAG_SIZE;
            PreparedFmpWorkerReservation {
                counter: reservation.counter,
                header: reservation.header,
                cipher: reservation.cipher,
                predicted_bytes,
            }
        }))
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_peer_runtime_fmp_worker_send(
        &mut self,
        snapshot: &PeerRuntimeSendSnapshot,
    ) -> Result<Option<PreparedFmpWorkerReservation>, FmpSendPreparationError> {
        self.reserve_prepared_fmp_worker_send(&snapshot.node_addr, snapshot.fmp_prepared())
    }

    #[cfg(unix)]
    pub(in crate::node) fn prepare_fmp_worker_send(
        &mut self,
        node_addr: &NodeAddr,
        prepared: &FmpSendPreparation,
        plaintext: &[u8],
    ) -> Result<Option<PreparedFmpWorkerSend>, FmpSendPreparationError> {
        const INNER_TS_LEN: usize = 4;
        let expected_payload_len = INNER_TS_LEN + plaintext.len();
        if prepared.payload_len as usize != expected_payload_len {
            return Err(FmpSendPreparationError::PayloadLengthMismatch);
        }

        Ok(self
            .reserve_prepared_fmp_worker_send(node_addr, prepared)?
            .map(|reservation| {
                let header = reservation.header;
                let wire_len = ESTABLISHED_HEADER_SIZE + prepared.payload_len as usize;
                let mut wire_buf = Vec::with_capacity(reservation.predicted_bytes);
                wire_buf.extend_from_slice(&header);
                wire_buf.extend_from_slice(&prepared.timestamp_ms.to_le_bytes());
                wire_buf.extend_from_slice(plaintext);
                debug_assert_eq!(wire_buf.len(), wire_len);

                PreparedFmpWorkerSend {
                    counter: reservation.counter,
                    #[cfg(test)]
                    header,
                    cipher: reservation.cipher,
                    wire_buf,
                    predicted_bytes: reservation.predicted_bytes,
                }
            }))
    }

    pub(in crate::node) fn seal_prepared_fmp_inline_send(
        &mut self,
        node_addr: &NodeAddr,
        prepared: &FmpSendPreparation,
        inner_plaintext: &[u8],
    ) -> Result<PreparedFmpInlineSend, FmpSendPreparationError> {
        let peer = self
            .active
            .get_mut(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        let session = peer
            .noise_session_mut()
            .ok_or(FmpSendPreparationError::MissingNoiseSession)?;
        let counter = session.current_send_counter();
        let header = build_established_header(
            prepared.their_index,
            counter,
            prepared.flags,
            prepared.payload_len,
        );
        let ciphertext = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);
            session
                .encrypt_with_aad(inner_plaintext, &header)
                .map_err(|_| FmpSendPreparationError::EncryptionFailed)?
        };
        let wire_packet = build_encrypted(&header, &ciphertext);
        Ok(PreparedFmpInlineSend {
            counter,
            #[cfg(test)]
            header,
            wire_packet,
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn connected_udp_activation_plan(
        &self,
        configured_peers: &ConfiguredPeerSendWeights,
    ) -> ConnectedUdpActivationPlan {
        let candidates = self
            .active
            .iter()
            .filter_map(|(addr, peer)| {
                Self::connected_udp_activation_candidate(peer)
                    .then_some((*addr, configured_peers.contains(addr)))
            })
            .collect();
        let candidates = Self::connected_udp_activation_order(candidates);
        let installed_count = self
            .active
            .values()
            .filter(|peer| peer.connected_udp().is_some())
            .count();

        ConnectedUdpActivationPlan {
            candidates,
            installed_count,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn install_connected_udp_if_eligible(
        &mut self,
        node_addr: &NodeAddr,
        socket: std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
        drain: crate::transport::udp::peer_drain::PeerRecvDrain,
    ) -> ConnectedUdpInstallResult {
        let Some(peer) = self.active.get_mut(node_addr) else {
            return ConnectedUdpInstallResult::MissingPeer;
        };
        if !Self::connected_udp_activation_candidate(peer) {
            return ConnectedUdpInstallResult::NotEligible;
        }
        peer.set_connected_udp(socket, drain);
        ConnectedUdpInstallResult::Installed
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn clear_connected_udp_for_peer(
        &mut self,
        node_addr: &NodeAddr,
    ) -> ConnectedUdpClearResult {
        let Some(peer) = self.active.get_mut(node_addr) else {
            return ConnectedUdpClearResult::MissingPeer;
        };
        if peer.connected_udp().is_none() {
            return ConnectedUdpClearResult::AlreadyClear;
        }
        peer.clear_connected_udp();
        ConnectedUdpClearResult::Cleared
    }

    pub(in crate::node) fn mark_link_dead_direct_path(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Option<LinkDeadDirectPathDegradation> {
        let peer = self.active.get_mut(node_addr)?;
        let link_id = peer.link_id();
        peer.mark_stale();
        let connected_udp_cleared = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let had_connected_udp = peer.connected_udp().is_some();
                peer.clear_connected_udp();
                had_connected_udp
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                false
            }
        };

        Some(LinkDeadDirectPathDegradation {
            link_id,
            connected_udp_cleared,
        })
    }

    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.active.remove(node_addr)
    }

    pub(in crate::node) fn remove_with_session_indices(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Option<RemovedActivePeer> {
        let peer = self.active.remove(node_addr)?;
        let session_indices = Self::active_peer_session_indices(&peer);
        Some(RemovedActivePeer {
            peer,
            session_indices,
        })
    }

    pub(in crate::node) fn get(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.active.get(node_addr)
    }

    pub(in crate::node) fn get_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.active.get_mut(node_addr)
    }

    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.active.contains_key(node_addr)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.active.len()
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &ActivePeer> {
        self.active.values()
    }

    pub(in crate::node) fn values_mut(&mut self) -> impl Iterator<Item = &mut ActivePeer> {
        self.active.values_mut()
    }

    pub(in crate::node) fn keys(&self) -> impl Iterator<Item = &NodeAddr> {
        self.active.keys()
    }

    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &ActivePeer)> {
        self.active.iter()
    }

    #[cfg(test)]
    pub(in crate::node) fn insert_session_index(
        &mut self,
        key: (TransportId, u32),
        node_addr: NodeAddr,
    ) -> Option<NodeAddr> {
        self.active.insert_session_index(key, node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove_session_index(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<NodeAddr> {
        self.active.remove_session_index(key)
    }

    pub(in crate::node) fn remove_session_index_with_owner_state(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<RemovedSessionIndex> {
        self.active.remove_session_index_with_owner_state(key)
    }

    pub(in crate::node) fn lookup_session_index(
        &self,
        key: (TransportId, u32),
    ) -> Option<NodeAddr> {
        self.active.lookup_session_index(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn get_session_index(&self, key: &(TransportId, u32)) -> Option<&NodeAddr> {
        self.active.get_session_index(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_session_index(&self, key: &(TransportId, u32)) -> bool {
        self.active.contains_session_index(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn session_index_is_empty(&self) -> bool {
        self.active.session_index_is_empty()
    }
}

impl<'a> IntoIterator for &'a PeerLifecycleRegistry {
    type Item = (&'a NodeAddr, &'a ActivePeer);
    type IntoIter = std::collections::hash_map::Iter<'a, NodeAddr, ActivePeer>;

    fn into_iter(self) -> Self::IntoIter {
        self.active.peers.iter()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FspSendBookkeepingInput {
    pub(in crate::node) data_bytes: Option<usize>,
    pub(in crate::node) counter: u64,
    pub(in crate::node) timestamp: u32,
    pub(in crate::node) frame_bytes: usize,
    pub(in crate::node) touch_ms: Option<u64>,
    pub(in crate::node) next_hop: Option<NodeAddr>,
}

impl FspSendBookkeepingInput {
    pub(in crate::node) fn data(
        data_bytes: usize,
        counter: u64,
        timestamp: u32,
        frame_bytes: usize,
        touch_ms: u64,
    ) -> Self {
        Self {
            data_bytes: Some(data_bytes),
            counter,
            timestamp,
            frame_bytes,
            touch_ms: Some(touch_ms),
            next_hop: None,
        }
    }

    pub(in crate::node) fn control(counter: u64, timestamp: u32, frame_bytes: usize) -> Self {
        Self {
            data_bytes: None,
            counter,
            timestamp,
            frame_bytes,
            touch_ms: None,
            next_hop: None,
        }
    }

    pub(in crate::node) fn with_next_hop(mut self, next_hop: NodeAddr) -> Self {
        self.next_hop = Some(next_hop);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FspSendBookkeeping {
    pub(in crate::node) data_recorded: bool,
    pub(in crate::node) mmp_recorded: bool,
    pub(in crate::node) touched: bool,
    pub(in crate::node) next_hop_recorded: bool,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FspWorkerSendReservationInput {
    pub(in crate::node) flags: u8,
    pub(in crate::node) payload_len: u16,
    pub(in crate::node) path_mtu: u16,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum FspWorkerSendReservationError {
    MissingSession,
    NotEstablished,
    CounterReservationFailed,
}

/// End-to-end FSP session storage keyed by remote node address.
#[derive(Default)]
pub(in crate::node) struct SessionRegistry {
    sessions: HashMap<NodeAddr, SessionEntry>,
    worker_registrations: DecryptSessionRegistrations,
}

impl SessionRegistry {
    pub(in crate::node) fn insert(
        &mut self,
        node_addr: NodeAddr,
        entry: SessionEntry,
    ) -> Option<SessionEntry> {
        self.sessions.insert(node_addr, entry)
    }

    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr) -> Option<SessionEntry> {
        self.sessions.remove(node_addr)
    }

    pub(in crate::node) fn get(&self, node_addr: &NodeAddr) -> Option<&SessionEntry> {
        self.sessions.get(node_addr)
    }

    pub(in crate::node) fn get_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut SessionEntry> {
        self.sessions.get_mut(node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.sessions.contains_key(node_addr)
    }

    pub(in crate::node) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.sessions.len()
    }

    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &SessionEntry)> {
        self.sessions.iter()
    }

    pub(in crate::node) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&NodeAddr, &mut SessionEntry)> {
        self.sessions.iter_mut()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &SessionEntry> {
        self.sessions.values()
    }

    pub(in crate::node) fn record_fsp_send_bookkeeping(
        &mut self,
        node_addr: &NodeAddr,
        input: FspSendBookkeepingInput,
    ) -> Option<FspSendBookkeeping> {
        let entry = self.sessions.get_mut(node_addr)?;
        let mut result = FspSendBookkeeping {
            data_recorded: false,
            mmp_recorded: false,
            touched: false,
            next_hop_recorded: false,
        };

        if let Some(next_hop) = input.next_hop {
            entry.record_outbound_next_hop(next_hop);
            result.next_hop_recorded = true;
        }
        if let Some(data_bytes) = input.data_bytes {
            entry.record_sent(data_bytes);
            result.data_recorded = true;
        }
        if let Some(mmp) = entry.mmp_mut() {
            mmp.sender
                .record_sent(input.counter, input.timestamp, input.frame_bytes);
            result.mmp_recorded = true;
        }
        if let Some(touch_ms) = input.touch_ms {
            entry.touch(touch_ms);
            result.touched = true;
        }

        Some(result)
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_endpoint_data_fsp_worker_send(
        &mut self,
        node_addr: &NodeAddr,
        input: FspWorkerSendReservationInput,
    ) -> Result<Option<FspSendReservation>, FspWorkerSendReservationError> {
        let entry = self
            .sessions
            .get_mut(node_addr)
            .ok_or(FspWorkerSendReservationError::MissingSession)?;
        if let Some(mmp) = entry.mmp_mut() {
            mmp.path_mtu.seed_source_mtu(input.path_mtu);
        }
        if !entry.is_established() {
            return Err(FspWorkerSendReservationError::NotEstablished);
        }
        entry
            .reserve_fsp_worker_send(input.flags, input.payload_len)
            .map_err(|_| FspWorkerSendReservationError::CounterReservationFailed)
    }

    pub(in crate::node) fn record_worker_registration(
        &mut self,
        session_key: DecryptSessionKey,
        accepted: bool,
    ) -> bool {
        self.worker_registrations
            .record_worker_registration(session_key, accepted)
    }

    pub(in crate::node) fn unregister_worker_session_if_registered(
        &mut self,
        session_key: &DecryptSessionKey,
    ) -> bool {
        self.worker_registrations
            .unregister_if_registered(session_key)
    }

    pub(in crate::node) fn is_worker_registered(&self, session_key: &DecryptSessionKey) -> bool {
        self.worker_registrations.is_registered(session_key)
    }

    #[cfg(test)]
    pub(in crate::node) fn worker_registration_is_empty(&self) -> bool {
        self.worker_registrations.is_empty()
    }
}

impl<'a> IntoIterator for &'a SessionRegistry {
    type Item = (&'a NodeAddr, &'a SessionEntry);
    type IntoIter = std::collections::hash_map::Iter<'a, NodeAddr, SessionEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.sessions.iter()
    }
}

/// Rx-loop mirror of sessions accepted by decrypt-worker shards.
#[derive(Debug, Default)]
pub(in crate::node) struct DecryptSessionRegistrations {
    sessions: HashSet<DecryptSessionKey>,
}

impl DecryptSessionRegistrations {
    pub(in crate::node) fn record_worker_registration(
        &mut self,
        session_key: DecryptSessionKey,
        accepted: bool,
    ) -> bool {
        if !accepted {
            return false;
        }
        self.sessions.insert(session_key);
        true
    }

    pub(in crate::node) fn unregister_if_registered(
        &mut self,
        session_key: &DecryptSessionKey,
    ) -> bool {
        self.sessions.remove(session_key)
    }

    pub(in crate::node) fn is_registered(&self, session_key: &DecryptSessionKey) -> bool {
        self.sessions.contains(session_key)
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Send-scheduling policy derived from the configured peer roster.
#[derive(Debug, Default)]
pub(in crate::node) struct ConfiguredPeerSendWeights {
    entries: HashMap<NodeAddr, u8>,
}

impl ConfiguredPeerSendWeights {
    pub(in crate::node) fn from_config(config: &Config) -> Self {
        let entries = config
            .peers()
            .iter()
            .filter_map(|peer| {
                PeerIdentity::from_npub(&peer.npub).ok().map(|identity| {
                    (
                        *identity.node_addr(),
                        encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
                    )
                })
            })
            .collect();
        Self { entries }
    }

    pub(in crate::node) fn weight_for(&self, peer_addr: &NodeAddr) -> u8 {
        self.entries
            .get(peer_addr)
            .copied()
            .unwrap_or(encrypt_worker::DEFAULT_SEND_WEIGHT)
    }

    pub(in crate::node) fn contains(&self, peer_addr: &NodeAddr) -> bool {
        self.entries.contains_key(peer_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Pending outbound FMP handshakes keyed by `(transport_id, our_index)`.
#[derive(Debug, Default)]
pub(in crate::node) struct PendingOutboundHandshakes {
    entries: HashMap<(TransportId, u32), LinkId>,
}

impl PendingOutboundHandshakes {
    pub(in crate::node) fn insert(
        &mut self,
        key: (TransportId, u32),
        link_id: LinkId,
    ) -> Option<LinkId> {
        self.entries.insert(key, link_id)
    }

    pub(in crate::node) fn remove(&mut self, key: &(TransportId, u32)) -> Option<LinkId> {
        self.entries.remove(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn get(&self, key: &(TransportId, u32)) -> Option<&LinkId> {
        self.entries.get(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, key: &(TransportId, u32)) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(in crate::node) fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&(TransportId, u32), &mut LinkId) -> bool,
    {
        self.entries.retain(f);
    }

    pub(in crate::node) fn match_msg2(
        &self,
        transport_id: TransportId,
        receiver_idx: u32,
    ) -> Option<((TransportId, u32), LinkId)> {
        let exact_key = (transport_id, receiver_idx);
        if let Some(link_id) = self.entries.get(&exact_key).copied() {
            return Some((exact_key, link_id));
        }

        let mut matches = self
            .entries
            .iter()
            .filter(|((_, idx), _)| *idx == receiver_idx);
        match (matches.next(), matches.next()) {
            (Some((fallback_key, link_id)), None) => Some((*fallback_key, *link_id)),
            _ => None,
        }
    }
}

/// A running FIPS node instance.
///
/// This is the top-level container holding all node state.
///
/// ## Peer Lifecycle
///
/// Peers go through two phases:
/// 1. **Connection phase** (`connections`): Handshake in progress, indexed by LinkId
/// 2. **Active phase** (`peers`): Authenticated, indexed by NodeAddr
///
/// The link registry dispatches incoming packets to the right connection before
/// authentication completes.
// Discovery lookup constants moved to config: node.discovery.attempt_timeouts_secs, node.discovery.ttl
pub struct Node {
    // === Identity ===
    /// This node's cryptographic identity.
    identity: Identity,

    /// Random epoch generated at startup for peer restart detection.
    /// Exchanged inside Noise handshake messages so peers can detect restarts.
    startup_epoch: [u8; 8],

    /// Instant when the node was created, for uptime reporting.
    started_at: std::time::Instant,

    // === Configuration ===
    /// Loaded configuration.
    config: Config,

    // === State ===
    /// Node operational state.
    state: NodeState,

    /// Whether this is a leaf-only node.
    is_leaf_only: bool,

    // === Spanning Tree ===
    /// Local spanning tree state.
    tree_state: TreeState,

    // === Bloom Filter ===
    /// Local Bloom filter state.
    bloom_state: BloomState,

    // === Routing ===
    /// Address -> coordinates cache (from session setup and discovery).
    coord_cache: CoordCache,
    /// Locally learned reverse-path next-hop hints.
    learned_routes: LearnedRouteTable,
    /// Destinations whose direct first-hop path is temporarily suspect because
    /// session-layer MMP observed sustained loss while using that direct path.
    session_direct_degradation: SessionDirectDegradation,
    /// Recent discovery requests for dedup and reverse-path forwarding.
    recent_requests: RecentDiscoveryRequests,
    /// Per-destination path MTU lookup, keyed by FipsAddress (mirrors
    /// `coord_cache.entries[*].path_mtu`). Sync read-only access from
    /// the TUN reader/writer threads at TCP MSS clamp time so the
    /// SYN/SYN-ACK clamp can use the smaller of the local-egress floor
    /// and the learned per-destination path MTU.
    path_mtu_lookup: Arc<std::sync::RwLock<HashMap<crate::FipsAddress, u16>>>,

    // === Transports & Links ===
    /// Active transports (owned by Node).
    transports: HashMap<TransportId, TransportHandle>,
    /// Per-transport kernel drop tracking for congestion detection.
    transport_drops: TransportDropTracker,
    /// Active links plus reverse address dispatch index.
    links: LinkRegistry,

    // === Packet Channel ===
    /// Packet sender for transports.
    packet_tx: Option<PacketTx>,
    /// Packet receiver (for event loop).
    packet_rx: Option<PacketRx>,

    // === Peer Lifecycle ===
    /// Pending handshake connections plus authenticated peers.
    peers: PeerLifecycleRegistry,

    // === End-to-End Sessions ===
    /// Session table for end-to-end encrypted sessions.
    /// Keyed by remote NodeAddr.
    sessions: SessionRegistry,

    // === Identity Cache ===
    /// Maps FipsAddress prefix bytes (bytes 1-15) to cached peer identity data.
    /// Enables reverse lookup from IPv6 destination to session/routing identity.
    identity_cache: IdentityCache,

    // === Pending TUN Packets ===
    /// TUN packets and endpoint payloads queued while waiting for session establishment.
    pending_session_traffic: PendingSessionTrafficQueues,
    // === Pending Discovery Lookups ===
    /// Tracks in-flight discovery lookups and owns dedupe/cap admission.
    pending_lookups: handlers::discovery::PendingDiscoveryLookups,

    // === Resource Limits ===
    /// Maximum connections (0 = unlimited).
    max_connections: usize,
    /// Maximum peers (0 = unlimited).
    max_peers: usize,
    /// Maximum links (0 = unlimited).
    max_links: usize,

    // === Counters ===
    /// Next link ID to allocate.
    next_link_id: u64,
    /// Next transport ID to allocate.
    next_transport_id: u32,

    // === Node Statistics ===
    /// Routing, forwarding, discovery, and error signal counters.
    stats: stats::NodeStats,

    /// Time-series history of node-level metrics (1s/1m rings).
    stats_history: stats_history::StatsHistory,

    // === TUN Interface ===
    /// TUN device state.
    tun_state: TunState,
    /// TUN interface name (for cleanup).
    tun_name: Option<String>,
    /// TUN packet sender channel.
    tun_tx: Option<TunTx>,
    /// Receiver for outbound packets from the TUN reader.
    tun_outbound_rx: Option<TunOutboundRx>,
    /// App-owned packet sink used by embedded/no-TUN integrations.
    external_packet_tx: Option<tokio::sync::mpsc::Sender<NodeDeliveredPacket>>,
    /// Endpoint data command receiver used by embedded/no-daemon integrations.
    endpoint_priority_command_rx: Option<tokio::sync::mpsc::Receiver<NodeEndpointCommand>>,
    /// Bulk endpoint data command receiver used by embedded/no-daemon integrations.
    endpoint_command_rx: Option<tokio::sync::mpsc::Receiver<NodeEndpointCommand>>,
    /// Endpoint data event delivery runtime used by embedded/no-daemon integrations.
    endpoint_events: EndpointEventRuntime,
    /// Off-task FMP-encrypt + UDP-send worker pool. `None` if not yet
    /// spawned (set up in `start()` once transports are running).
    /// `Some(pool)` once available; the pool internally holds
    /// per-worker mpsc senders and round-robins jobs across them.
    /// See `node::encrypt_worker` for the rationale and layout.
    encrypt_workers: Option<encrypt_worker::EncryptWorkerPool>,
    /// Off-task FMP + FSP decrypt + delivery worker pool. Mirror of
    /// `encrypt_workers` for the receive side.
    decrypt_workers: Option<decrypt_worker::DecryptWorkerPool>,
    /// Fallback channel: decrypt worker bounces non-fast-path packets
    /// (anything that's not bulk EndpointData) back here for rx_loop
    /// to handle via the legacy path. Drained by rx_loop with a bounded
    /// priority lane ahead of bounded bulk plaintext fallbacks.
    decrypt_fallback_rx: Option<decrypt_worker::DecryptWorkerFallbackReceivers>,
    decrypt_fallback_tx: decrypt_worker::DecryptWorkerFallbackSender,
    /// TUN reader thread handle.
    tun_reader_handle: Option<JoinHandle<()>>,
    /// TUN writer thread handle.
    tun_writer_handle: Option<JoinHandle<()>>,
    /// Shutdown pipe: writing to this fd unblocks the TUN reader thread on macOS.
    /// On Linux, deleting the interface via netlink serves the same purpose.
    #[cfg(target_os = "macos")]
    tun_shutdown_fd: Option<std::os::unix::io::RawFd>,

    // === DNS Responder ===
    /// Receiver for resolved identities from the DNS responder.
    dns_identity_rx: Option<crate::upper::dns::DnsIdentityRx>,
    /// DNS responder task handle.
    dns_task: Option<tokio::task::JoinHandle<()>>,

    // === Index-Based Session Dispatch ===
    /// Allocator for session indices.
    index_allocator: IndexAllocator,
    /// Pending outbound handshakes by our sender_idx.
    /// Tracks which LinkId corresponds to which session index.
    pending_outbound: PendingOutboundHandshakes,

    // === Rate Limiting ===
    /// Rate limiter for msg1 processing (DoS protection).
    msg1_rate_limiter: HandshakeRateLimiter,
    /// Rate limiter for ICMP Packet Too Big messages.
    icmp_rate_limiter: IcmpRateLimiter,
    /// Rate limiter for routing error signals (CoordsRequired / PathBroken).
    routing_error_rate_limiter: RoutingErrorRateLimiter,
    /// Rate limiter for source-side CoordsRequired/PathBroken responses.
    coords_response_rate_limiter: RoutingErrorRateLimiter,
    /// Backoff for failed discovery lookups (originator-side).
    discovery_backoff: DiscoveryBackoff,
    /// Rate limiter for forwarded discovery requests (transit-side).
    discovery_forward_limiter: DiscoveryForwardRateLimiter,

    // === Pending Transport Connects ===
    /// Links waiting for transport-level connection establishment before
    /// sending handshake msg1. For connection-oriented transports (TCP, Tor),
    /// the transport connect runs in the background; the tick handler polls
    /// connection_state() and initiates the handshake when connected.
    pending_connects: Vec<PendingConnect>,

    // === Connection Retry ===
    /// Retry state for peers whose outbound connections have failed.
    /// Keyed by NodeAddr. Entries are created when a handshake times out
    /// or fails, and removed on successful promotion or when max retries
    /// are exhausted.
    retry_pending: retry::PendingRouteRetries,

    /// Optional Nostr/STUN overlay discovery coordinator for `udp:nat` peers.
    nostr_discovery: Option<Arc<crate::discovery::nostr::NostrDiscovery>>,
    /// mDNS / DNS-SD responder + browser for local-link peer discovery.
    /// Identity is unverified at this layer — the Noise XX handshake
    /// initiated against an mDNS-observed endpoint is what proves the
    /// peer holds the matching private key.
    lan_discovery: Option<Arc<crate::discovery::lan::LanDiscovery>>,
    /// Same-host JSON registry under `~/.fips/instances`. Records are
    /// loopback routing hints only; peer identity is still verified by the
    /// Noise handshake.
    local_instance_registry: Option<crate::discovery::local::LocalInstanceRegistry>,
    local_instance_started_at_ms: Option<u64>,
    last_local_instance_publish_ms: Option<u64>,
    last_local_instance_scan_ms: Option<u64>,
    /// Wall-clock ms when Nostr discovery successfully started, used to
    /// schedule the one-shot startup advert sweep after a settle delay.
    /// `None` until discovery comes up; remains `None` if discovery is
    /// disabled or failed to start.
    nostr_discovery_started_at_ms: Option<u64>,
    /// Whether the one-shot startup advert sweep has run. Set to true
    /// after the first sweep fires (under `policy: open`); thereafter
    /// only the per-tick `queue_open_discovery_retries` continues.
    startup_open_discovery_sweep_done: bool,
    /// Per-peer UDP transports adopted from NAT traversal handoff plus the
    /// originating peer npub for protocol-mismatch cooldown bookkeeping.
    bootstrap_transports: BootstrapTransports,
    /// Peers that should not be used as reply-learned fallback transit for
    /// other destinations. Direct lookups to the peer are still permitted.
    discovery_fallback_transit: DiscoveryFallbackTransit,

    // === Periodic Parent Re-evaluation ===
    /// Timestamp of last periodic parent re-evaluation (for pacing).
    last_parent_reeval: Option<crate::time::Instant>,

    // === Congestion Logging ===
    /// Timestamp of last congestion detection log (rate-limited to 5s).
    last_congestion_log: Option<std::time::Instant>,

    // === Mesh Size Estimate ===
    /// Cached estimated mesh size (computed once per tick from bloom filters).
    estimated_mesh_size: Option<u64>,
    /// Timestamp of last mesh size log emission.
    last_mesh_size_log: Option<std::time::Instant>,

    // === Bloom Self-Plausibility ===
    /// Rate-limit state for the self-plausibility WARN. Fires at most
    /// once per 60s globally when our own outgoing FilterAnnounce has
    /// an FPR above `node.bloom.max_inbound_fpr`, signalling either
    /// aggregation drift or an ingress bypass.
    last_self_warn: Option<std::time::Instant>,

    // === Local Outbound Liveness ===
    /// Set per peer when a `transport.send` returned a local-side io error
    /// (`NetworkUnreachable` / `HostUnreachable` / `AddrNotAvailable`),
    /// cleared on the next successful send to that peer. Used by
    /// `check_link_heartbeats` to compress only that peer's dead-timeout to
    /// `fast_link_dead_timeout_secs` while its outbound is observed broken.
    local_send_failures: LocalSendFailures,
    /// Set when the rx loop could not complete its 1s maintenance work
    /// inside the watchdog timeout. Link-dead detection may be valid during
    /// overload, but traversal cooldown should not punish a path just because
    /// our own scheduler/worker queue was late.
    last_rx_loop_maintenance_timeout_at: Option<std::time::Instant>,

    // === Display Names ===
    /// Human-readable names for configured peers (alias or short npub).
    /// Populated at startup from peer config.
    peer_aliases: HashMap<NodeAddr, String>,
    /// Scheduler weight for explicitly configured peers. Built when config
    /// changes so the packet hot path only does a NodeAddr hash lookup.
    configured_peer_send_weights: ConfiguredPeerSendWeights,

    /// Reloadable peer ACL state from standard allow/deny files.
    peer_acl: acl::PeerAclReloader,

    // === Host Map ===
    /// Static hostname → npub mapping for DNS resolution.
    /// Built at construction from peer aliases and /etc/fips/hosts.
    host_map: Arc<HostMap>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let identity = config.create_identity()?;
        let node_addr = *identity.node_addr();
        let is_leaf_only = config.is_leaf_only();

        let (decrypt_fallback_tx, decrypt_fallback_rx) =
            decrypt_worker::decrypt_worker_fallback_channels();
        let decrypt_fallback_rx = Some(decrypt_fallback_rx);

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let mut bloom_state = if is_leaf_only {
            BloomState::leaf_only(node_addr)
        } else {
            BloomState::new(node_addr)
        };
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;
        let backoff_base_secs = config.node.discovery.backoff_base_secs;
        let backoff_max_secs = config.node.discovery.backoff_max_secs;
        let forward_min_interval_secs = config.node.discovery.forward_min_interval_secs;

        let (host_map, peer_acl) = Self::host_map_and_peer_acl(&config);
        let configured_peer_send_weights = ConfiguredPeerSendWeights::from_config(&config);

        Ok(Self {
            identity,
            startup_epoch,
            started_at: std::time::Instant::now(),
            config,
            state: NodeState::Created,
            is_leaf_only,
            tree_state,
            bloom_state,
            coord_cache,
            learned_routes: LearnedRouteTable::default(),
            session_direct_degradation: SessionDirectDegradation::default(),
            recent_requests: RecentDiscoveryRequests::default(),
            transports: HashMap::new(),
            transport_drops: TransportDropTracker::default(),
            links: LinkRegistry::default(),
            packet_tx: None,
            packet_rx: None,
            peers: PeerLifecycleRegistry::default(),
            sessions: SessionRegistry::default(),
            identity_cache: IdentityCache::default(),
            pending_session_traffic: PendingSessionTrafficQueues::default(),
            pending_lookups: handlers::discovery::PendingDiscoveryLookups::default(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            stats_history: stats_history::StatsHistory::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            external_packet_tx: None,
            endpoint_priority_command_rx: None,
            endpoint_command_rx: None,
            endpoint_events: EndpointEventRuntime::default(),
            encrypt_workers: None,
            decrypt_workers: None,
            decrypt_fallback_tx,
            decrypt_fallback_rx,
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(target_os = "macos")]
            tun_shutdown_fd: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            pending_outbound: PendingOutboundHandshakes::default(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            discovery_backoff: DiscoveryBackoff::with_params(backoff_base_secs, backoff_max_secs),
            discovery_forward_limiter: DiscoveryForwardRateLimiter::with_interval(
                std::time::Duration::from_secs(forward_min_interval_secs),
            ),
            pending_connects: Vec::new(),
            retry_pending: retry::PendingRouteRetries::default(),
            nostr_discovery: None,
            nostr_discovery_started_at_ms: None,
            lan_discovery: None,
            local_instance_registry: None,
            local_instance_started_at_ms: None,
            last_local_instance_publish_ms: None,
            last_local_instance_scan_ms: None,
            startup_open_discovery_sweep_done: false,
            bootstrap_transports: BootstrapTransports::default(),
            discovery_fallback_transit: DiscoveryFallbackTransit::default(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            local_send_failures: LocalSendFailures::default(),
            last_rx_loop_maintenance_timeout_at: None,
            peer_aliases: HashMap::new(),
            configured_peer_send_weights,
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Create a node with a specific identity.
    ///
    /// This constructor validates cross-field config invariants before
    /// constructing the node, same as [`Node::new`].
    pub fn with_identity(identity: Identity, config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let node_addr = *identity.node_addr();

        let (decrypt_fallback_tx, decrypt_fallback_rx) =
            decrypt_worker::decrypt_worker_fallback_channels();
        let decrypt_fallback_rx = Some(decrypt_fallback_rx);

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        let mut bloom_state = BloomState::new(node_addr);
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;

        let (host_map, peer_acl) = Self::host_map_and_peer_acl(&config);
        let configured_peer_send_weights = ConfiguredPeerSendWeights::from_config(&config);

        Ok(Self {
            identity,
            startup_epoch,
            started_at: std::time::Instant::now(),
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state,
            bloom_state,
            coord_cache,
            learned_routes: LearnedRouteTable::default(),
            session_direct_degradation: SessionDirectDegradation::default(),
            recent_requests: RecentDiscoveryRequests::default(),
            transports: HashMap::new(),
            transport_drops: TransportDropTracker::default(),
            links: LinkRegistry::default(),
            packet_tx: None,
            packet_rx: None,
            peers: PeerLifecycleRegistry::default(),
            sessions: SessionRegistry::default(),
            identity_cache: IdentityCache::default(),
            pending_session_traffic: PendingSessionTrafficQueues::default(),
            pending_lookups: handlers::discovery::PendingDiscoveryLookups::default(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            stats_history: stats_history::StatsHistory::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            external_packet_tx: None,
            endpoint_priority_command_rx: None,
            endpoint_command_rx: None,
            endpoint_events: EndpointEventRuntime::default(),
            encrypt_workers: None,
            decrypt_workers: None,
            decrypt_fallback_tx,
            decrypt_fallback_rx,
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(target_os = "macos")]
            tun_shutdown_fd: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            pending_outbound: PendingOutboundHandshakes::default(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            discovery_backoff: DiscoveryBackoff::new(),
            discovery_forward_limiter: DiscoveryForwardRateLimiter::new(),
            pending_connects: Vec::new(),
            retry_pending: retry::PendingRouteRetries::default(),
            nostr_discovery: None,
            nostr_discovery_started_at_ms: None,
            lan_discovery: None,
            local_instance_registry: None,
            local_instance_started_at_ms: None,
            last_local_instance_publish_ms: None,
            last_local_instance_scan_ms: None,
            startup_open_discovery_sweep_done: false,
            bootstrap_transports: BootstrapTransports::default(),
            discovery_fallback_transit: DiscoveryFallbackTransit::default(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            local_send_failures: LocalSendFailures::default(),
            last_rx_loop_maintenance_timeout_at: None,
            peer_aliases: HashMap::new(),
            configured_peer_send_weights,
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.is_leaf_only = true;
        node.bloom_state = BloomState::leaf_only(*node.identity.node_addr());
        Ok(node)
    }

    fn host_map_and_peer_acl(config: &Config) -> (Arc<HostMap>, acl::PeerAclReloader) {
        let base_host_map = HostMap::from_peer_configs(config.peers());
        if !config.node.system_files_enabled {
            return (
                Arc::new(base_host_map.clone()),
                acl::PeerAclReloader::memory_only(base_host_map),
            );
        }

        let mut host_map = base_host_map.clone();
        let hosts_path = std::path::PathBuf::from(crate::upper::hosts::DEFAULT_HOSTS_PATH);
        let hosts_file = HostMap::load_hosts_file(std::path::Path::new(
            crate::upper::hosts::DEFAULT_HOSTS_PATH,
        ));
        host_map.merge(hosts_file);
        let peer_acl = acl::PeerAclReloader::with_alias_sources(
            std::path::PathBuf::from(acl::DEFAULT_PEERS_ALLOW_PATH),
            std::path::PathBuf::from(acl::DEFAULT_PEERS_DENY_PATH),
            base_host_map,
            hosts_path,
        );
        (Arc::new(host_map), peer_acl)
    }

    #[cfg(unix)]
    fn send_weight_for_peer(&self, peer_addr: &NodeAddr) -> u8 {
        self.configured_peer_send_weights.weight_for(peer_addr)
    }

    #[cfg(unix)]
    pub(in crate::node) fn resolve_peer_runtime_route_decision(
        &mut self,
        dest_addr: &NodeAddr,
        now_ms: u64,
    ) -> Result<PeerRuntimeRouteDecision, PeerRuntimeRouteDecisionError> {
        let Some(next_hop_addr) = self.find_next_hop(dest_addr).map(|peer| *peer.node_addr())
        else {
            return Err(PeerRuntimeRouteDecisionError::NoRoute {
                dest_addr: *dest_addr,
            });
        };

        let peer_snapshot = self
            .peers
            .prepare_peer_runtime_route_snapshot(&next_hop_addr)
            .map_err(|error| PeerRuntimeRouteDecisionError::FmpPreparation {
                next_hop_addr,
                error,
            })?;
        let scheduling_weight = self.send_weight_for_peer(&next_hop_addr);
        let direct_path_blocks_direct_payload = next_hop_addr == *dest_addr
            && self.session_direct_path_blocks_direct_payload(dest_addr, now_ms);

        Ok(PeerRuntimeRouteDecision::new(
            next_hop_addr,
            peer_snapshot,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        ))
    }

    /// Create transport instances from configuration.
    ///
    /// Returns a vector of TransportHandles for all configured transports.
    async fn create_transports(&mut self, packet_tx: &PacketTx) -> Vec<TransportHandle> {
        let mut transports = Vec::new();

        // Collect UDP configs with optional names to avoid borrow conflicts
        let udp_instances: Vec<_> = self
            .config
            .transports
            .udp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        // Create UDP transport instances
        for (name, udp_config) in udp_instances {
            let transport_id = self.allocate_transport_id();
            let udp = UdpTransport::new(transport_id, name, udp_config, packet_tx.clone());
            transports.push(TransportHandle::Udp(udp));
        }

        #[cfg(feature = "sim-transport")]
        {
            let sim_instances: Vec<_> = self
                .config
                .transports
                .sim
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            for (name, sim_config) in sim_instances {
                let transport_id = self.allocate_transport_id();
                let sim = crate::transport::sim::SimTransport::new(
                    transport_id,
                    name,
                    sim_config,
                    packet_tx.clone(),
                );
                transports.push(TransportHandle::Sim(sim));
            }
        }

        // Create Ethernet transport instances where raw-socket support exists.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let eth_instances: Vec<_> = self
                .config
                .transports
                .ethernet
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();
            let xonly = self.identity.pubkey();
            for (name, eth_config) in eth_instances {
                let mut eth_config = eth_config;
                if eth_config.discovery_scope.is_none() {
                    eth_config.discovery_scope = self.lan_discovery_scope();
                }
                let transport_id = self.allocate_transport_id();
                let mut eth =
                    EthernetTransport::new(transport_id, name, eth_config, packet_tx.clone());
                eth.set_local_pubkey(xonly);
                transports.push(TransportHandle::Ethernet(eth));
            }
        }

        // Create TCP transport instances
        let tcp_instances: Vec<_> = self
            .config
            .transports
            .tcp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tcp_config) in tcp_instances {
            let transport_id = self.allocate_transport_id();
            let tcp = TcpTransport::new(transport_id, name, tcp_config, packet_tx.clone());
            transports.push(TransportHandle::Tcp(tcp));
        }

        // Create Tor transport instances
        let tor_instances: Vec<_> = self
            .config
            .transports
            .tor
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tor_config) in tor_instances {
            let transport_id = self.allocate_transport_id();
            let tor = TorTransport::new(transport_id, name, tor_config, packet_tx.clone());
            transports.push(TransportHandle::Tor(tor));
        }

        let webrtc_instances: Vec<_> = self
            .config
            .transports
            .webrtc
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        #[cfg(feature = "webrtc-transport")]
        {
            for (name, webrtc_config) in webrtc_instances {
                let transport_id = self.allocate_transport_id();
                match WebRtcTransport::new(
                    transport_id,
                    name,
                    webrtc_config,
                    packet_tx.clone(),
                    &self.identity,
                    &self.config.node.discovery.nostr,
                ) {
                    Ok(webrtc) => transports.push(TransportHandle::WebRtc(Box::new(webrtc))),
                    Err(err) => {
                        warn!(
                            transport_id = %transport_id,
                            error = %err,
                            "failed to initialize WebRTC transport"
                        );
                    }
                }
            }
        }
        #[cfg(not(feature = "webrtc-transport"))]
        if !webrtc_instances.is_empty() {
            warn!("WebRTC transport configured but this build lacks WebRTC transport support");
        }

        // Create BLE transport instances
        #[cfg(bluer_available)]
        {
            let ble_instances: Vec<_> = self
                .config
                .transports
                .ble
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            #[cfg(all(bluer_available, not(test)))]
            for (name, ble_config) in ble_instances {
                let transport_id = self.allocate_transport_id();
                let adapter = ble_config.adapter().to_string();
                let mtu = ble_config.mtu();
                match crate::transport::ble::io::BluerIo::new(&adapter, mtu).await {
                    Ok(io) => {
                        let mut ble = crate::transport::ble::BleTransport::new(
                            transport_id,
                            name,
                            ble_config,
                            io,
                            packet_tx.clone(),
                        );
                        ble.set_local_pubkey(self.identity.pubkey().serialize());
                        transports.push(TransportHandle::Ble(ble));
                    }
                    Err(e) => {
                        tracing::warn!(adapter = %adapter, error = %e, "failed to initialize BLE adapter");
                    }
                }
            }

            #[cfg(any(not(bluer_available), test))]
            if !ble_instances.is_empty() {
                #[cfg(not(test))]
                tracing::warn!("BLE transport configured but this build lacks BlueZ support");
            }
        }

        transports
    }

    /// Find an operational transport that matches the given transport type name.
    ///
    /// Adopted UDP bootstrap transports are point-to-point sockets handed off
    /// from Nostr/STUN traversal. They must not be reused for ordinary
    /// `udp host:port` dials discovered through static config, mDNS, or overlay
    /// adverts: on macOS a `send_to` through the wrong adopted socket can fail
    /// with `EINVAL`, and even on platforms that allow it the packet would use
    /// the wrong 5-tuple/NAT mapping. Prefer configured transports and make the
    /// choice deterministic by lowest transport id instead of HashMap order.
    fn find_transport_for_type(&self, transport_type: &str) -> Option<TransportId> {
        self.transports
            .iter()
            .filter(|(id, handle)| {
                handle.transport_type().name == transport_type
                    && handle.is_operational()
                    && !self.bootstrap_transports.contains(id)
            })
            .min_by_key(|(id, _)| id.as_u32())
            .map(|(id, _)| *id)
    }

    /// Resolve an Ethernet peer address ("interface/mac") to a transport ID
    /// and binary TransportAddr.
    ///
    /// Finds the Ethernet transport instance bound to the named interface
    /// and parses the MAC portion into a 6-byte TransportAddr.
    #[allow(unused_variables)]
    fn resolve_ethernet_addr(
        &self,
        addr_str: &str,
    ) -> Result<(TransportId, TransportAddr), NodeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let (iface, mac_str) = addr_str.split_once('/').ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "invalid Ethernet address format '{}': expected 'interface/mac'",
                    addr_str
                ))
            })?;

            // Find the Ethernet transport bound to this interface
            let transport_id = self
                .transports
                .iter()
                .find(|(_, handle)| {
                    handle.transport_type().name == "ethernet"
                        && handle.is_operational()
                        && handle.interface_name() == Some(iface)
                })
                .map(|(id, _)| *id)
                .ok_or_else(|| {
                    NodeError::NoTransportForType(format!(
                        "no operational Ethernet transport for interface '{}'",
                        iface
                    ))
                })?;

            let mac = crate::transport::ethernet::parse_mac_string(mac_str).map_err(|e| {
                NodeError::NoTransportForType(format!("invalid MAC in '{}': {}", addr_str, e))
            })?;

            Ok((transport_id, TransportAddr::from_bytes(&mac)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(NodeError::NoTransportForType(
                "Ethernet transport is not supported on this platform".to_string(),
            ))
        }
    }

    /// Resolve a BLE address string (`"adapter/AA:BB:CC:DD:EE:FF"`) to a
    /// (TransportId, TransportAddr) pair by finding the BLE transport
    /// instance matching the adapter name.
    #[cfg(bluer_available)]
    fn resolve_ble_addr(&self, addr_str: &str) -> Result<(TransportId, TransportAddr), NodeError> {
        let ta = TransportAddr::from_string(addr_str);
        let adapter = crate::transport::ble::addr::adapter_from_addr(&ta).ok_or_else(|| {
            NodeError::NoTransportForType(format!(
                "invalid BLE address format '{}': expected 'adapter/mac'",
                addr_str
            ))
        })?;

        // Find the BLE transport for this adapter
        let transport_id = self
            .transports
            .iter()
            .find(|(_, handle)| handle.transport_type().name == "ble" && handle.is_operational())
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "no operational BLE transport for adapter '{}'",
                    adapter
                ))
            })?;

        // Validate the address format
        crate::transport::ble::addr::BleAddr::parse(addr_str).map_err(|e| {
            NodeError::NoTransportForType(format!("invalid BLE address '{}': {}", addr_str, e))
        })?;

        Ok((transport_id, TransportAddr::from_string(addr_str)))
    }

    // === Identity Accessors ===

    /// Get this node's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get this node's NodeAddr.
    pub fn node_addr(&self) -> &NodeAddr {
        self.identity.node_addr()
    }

    /// Get this node's npub.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    /// Return a human-readable display name for a NodeAddr.
    ///
    /// Lookup order:
    /// 1. Host map hostname (from peer aliases + /etc/fips/hosts)
    /// 2. Configured peer alias or short npub (from startup map)
    /// 3. Active peer's short npub (e.g., inbound peer not in config)
    /// 4. Session endpoint's short npub (end-to-end, may not be direct peer)
    /// 5. Truncated NodeAddr hex (unknown address)
    pub(crate) fn peer_display_name(&self, addr: &NodeAddr) -> String {
        if let Some(hostname) = self.host_map.lookup_hostname(addr) {
            return hostname.to_string();
        }
        if let Some(name) = self.peer_aliases.get(addr) {
            return name.clone();
        }
        if let Some(peer) = self.peers.get(addr) {
            return peer.identity().short_npub();
        }
        if let Some(entry) = self.sessions.get(addr) {
            let (xonly, _) = entry.remote_pubkey().x_only_public_key();
            return PeerIdentity::from_pubkey(xonly).short_npub();
        }
        addr.short_hex()
    }

    /// Tear down a receiver-index entry **and** keep the shard-owned
    /// decrypt-worker state coherent: removes the same `cache_key`
    /// from the registered-sessions tracking set and tells the
    /// assigned shard worker to drop its `OwnedSessionState` entry.
    ///
    /// Use this instead of a bare session-index removal at every
    /// session-lifecycle teardown site (rekey cross-connection swap, peer
    /// disconnect, dispatch session-rotation) so the peer index, connected UDP
    /// state, and decrypt-worker state remain coherent. The
    /// follow-up `RegisterSession` for the NEW key (if any) will then
    /// install the fresh state on the same shard.
    pub(in crate::node) fn deregister_session_index(&mut self, cache_key: (TransportId, u32)) {
        // Remove the index and ask the peer registry for the remaining-owner
        // state in one step. Rekey drain depends on seeing the NEW index that
        // was already installed for the same peer.
        let removed_index = self.peers.remove_session_index_with_owner_state(&cache_key);
        let session_key = DecryptSessionKey::from(cache_key);
        if self
            .sessions
            .unregister_worker_session_if_registered(&session_key)
            && let Some(workers) = self.decrypt_workers.as_ref()
        {
            workers.unregister_session(session_key);
        }
        // Tear down the per-peer connected UDP socket *only* if no
        // other receiver-index entry still resolves to this peer.
        // Rekey drain calls into this helper with the OLD session
        // index while the NEW index is already installed and points
        // at the same peer — there the connect()-ed 5-tuple is
        // still valid for the new session and we must not close it.
        // Peer-teardown sites (CrossConnection swap, stale-index
        // fall-through in encrypted.rs, disconnect handler) call
        // here when this is the peer's last index, so the connected
        // socket goes away with the peer.
        if let Some(removed_index) = removed_index {
            if !removed_index.owner_has_remaining_index {
                self.clear_connected_udp_for_peer(&removed_index.owner);
            }
        }
    }

    /// Ensure the current FMP receive index resolves to this peer.
    ///
    /// Rekey msg1/msg2 handlers pre-register the pending index before
    /// cutover, but losing that registration in a debug build used to
    /// panic in the cutover path. Repairing the map here is safe: the
    /// peer has already promoted the pending session, and the decrypt
    /// worker registration immediately after cutover depends on the
    /// same `(transport_id, our_index)` key.
    pub(in crate::node) fn ensure_current_session_index_registered(
        &mut self,
        node_addr: &NodeAddr,
        context: &'static str,
    ) -> bool {
        match self
            .peers
            .ensure_current_session_index_registered(node_addr)
        {
            CurrentSessionIndexRegistration::MissingActivePeer => false,
            CurrentSessionIndexRegistration::MissingTransportId => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    context,
                    "Cannot register current session index without transport id"
                );
                false
            }
            CurrentSessionIndexRegistration::MissingLocalIndex => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    context,
                    "Cannot register current session index without local index"
                );
                false
            }
            CurrentSessionIndexRegistration::AlreadyRegistered(_) => true,
            CurrentSessionIndexRegistration::Repaired(registered) => {
                if let Some(existing) = registered.previous_owner {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        previous_owner = %self.peer_display_name(&existing),
                        transport_id = %registered.session_index.key.0,
                        our_index = %registered.session_index.index,
                        context,
                        "Repairing current session index with stale owner"
                    );
                } else {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        transport_id = %registered.session_index.key.0,
                        our_index = %registered.session_index.index,
                        context,
                        "Repairing missing current session index"
                    );
                }
                true
            }
        }
    }

    pub(in crate::node) fn log_active_peer_insert_result(
        &self,
        node_addr: &NodeAddr,
        inserted: &InsertedActivePeer,
        context: &'static str,
    ) {
        if let Some(previous_peer) = inserted.previous_peer.as_ref() {
            debug!(
                peer = %self.peer_display_name(node_addr),
                previous_link_id = %previous_peer.link_id(),
                context,
                "Replaced active peer storage during lifecycle insert"
            );
        }

        match inserted.current_session_index {
            Some(registered) => {
                if let Some(previous_owner) = registered.previous_owner {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        previous_owner = %self.peer_display_name(&previous_owner),
                        transport_id = %registered.session_index.key.0,
                        our_index = %registered.session_index.index,
                        context,
                        "Replaced current session-index owner during lifecycle insert"
                    );
                }
            }
            None => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    context,
                    "Inserted active peer without a current session index"
                );
            }
        }
    }

    pub(in crate::node) fn log_active_peer_session_replacement_result(
        &self,
        node_addr: &NodeAddr,
        replacement: &ReplacedActivePeerCurrentSession,
        context: &'static str,
    ) {
        if replacement.replay_suppressed_count > 0 {
            debug!(
                peer = %self.peer_display_name(node_addr),
                count = replacement.replay_suppressed_count,
                context,
                "Suppressed replay detections during link transition"
            );
        }

        if let Some(previous_owner) = replacement.new_session_index.previous_owner {
            debug!(
                peer = %self.peer_display_name(node_addr),
                previous_owner = %self.peer_display_name(&previous_owner),
                transport_id = %replacement.new_session_index.session_index.key.0,
                our_index = %replacement.new_session_index.session_index.index,
                context,
                "Replaced current session-index owner during session replacement"
            );
        }
    }

    pub(in crate::node) fn log_registered_peer_session_index_result(
        &self,
        node_addr: &NodeAddr,
        registered: &RegisteredPeerSessionIndex,
        context: &'static str,
    ) {
        if let Some(previous_owner) = registered.previous_owner {
            debug!(
                peer = %self.peer_display_name(node_addr),
                previous_owner = %self.peer_display_name(&previous_owner),
                transport_id = %registered.session_index.key.0,
                our_index = %registered.session_index.index,
                index_kind = ?registered.session_index.kind,
                context,
                "Replaced session-index owner during lifecycle registration"
            );
        }
    }

    // === Configuration ===

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Calculate the effective IPv6 MTU that can be sent over FIPS.
    ///
    /// Delegates to `upper::icmp::effective_ipv6_mtu()` with this node's
    /// transport MTU. Returns the maximum IPv6 packet size (including
    /// IPv6 header) that can be transmitted through the FIPS mesh.
    pub fn effective_ipv6_mtu(&self) -> u16 {
        crate::upper::icmp::effective_ipv6_mtu(self.transport_mtu())
    }

    /// Get the transport MTU governing the global TUN-boundary MSS clamp.
    ///
    /// Returns the **minimum** MTU across all operational transports, or
    /// 1280 (IPv6 minimum) as fallback. Used for initial TUN configuration
    /// where a specific egress transport isn't yet known: the resulting
    /// `effective_ipv6_mtu` (transport_mtu - 77) and `max_mss`
    /// (effective_mtu - 60) form a conservative ceiling that fits ANY
    /// configured-transport's egress, eliminating PMTU-D black holes that
    /// would otherwise occur when a flow's actual egress is smaller than
    /// the clamp ceiling assumed at TUN init.
    ///
    /// Returning the smallest (rather than the first-iterated, which used
    /// to vary across HashMap iteration order + async-startup race) makes
    /// the clamp deterministic across daemon restarts.
    ///
    /// See `ISSUE-2026-0011` for the empirical investigation.
    pub fn transport_mtu(&self) -> u16 {
        let min_operational = self
            .transports
            .values()
            .filter(|h| h.is_operational())
            .map(|h| h.mtu())
            .min();
        if let Some(mtu) = min_operational {
            return mtu;
        }
        // Fallback to config: try UDP first, then Ethernet
        if let Some((_, cfg)) = self.config.transports.udp.iter().next() {
            return cfg.mtu();
        }
        1280
    }

    // === State ===

    /// Get the node state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Get the node uptime.
    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Check if node is operational.
    pub fn is_running(&self) -> bool {
        self.state.is_operational()
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
    }

    // === Tree State ===

    /// Get the tree state.
    pub fn tree_state(&self) -> &TreeState {
        &self.tree_state
    }

    /// Get mutable tree state.
    pub fn tree_state_mut(&mut self) -> &mut TreeState {
        &mut self.tree_state
    }

    // === Bloom State ===

    /// Get the Bloom filter state.
    pub fn bloom_state(&self) -> &BloomState {
        &self.bloom_state
    }

    /// Get mutable Bloom filter state.
    pub fn bloom_state_mut(&mut self) -> &mut BloomState {
        &mut self.bloom_state
    }

    // === Mesh Size Estimate ===

    /// Get the cached estimated mesh size.
    pub fn estimated_mesh_size(&self) -> Option<u64> {
        self.estimated_mesh_size
    }

    /// Compute and cache the estimated mesh size from bloom filters.
    ///
    /// Uses the spanning tree partition: parent's filter covers nodes reachable
    /// upward, children's filters cover subtrees downward. The OR-union of
    /// those filters plus self approximates total network size without
    /// double-counting overlapping filters.
    pub(crate) fn compute_mesh_size(&mut self) {
        let my_addr = *self.tree_state.my_node_addr();
        let parent_id = *self.tree_state.my_declaration().parent_id();
        let is_root = self.tree_state.is_root();

        let max_fpr = self.config.node.bloom.max_inbound_fpr;
        let mut child_count: u32 = 0;
        let mut union: Option<BloomFilter> = None;

        let add_to_union = |union: &mut Option<BloomFilter>, filter: &BloomFilter| match union {
            None => *union = Some(filter.clone()),
            Some(existing) => {
                // Size-class mismatch is skipped rather than fatal.
                let _ = existing.merge(filter);
            }
        };

        // Parent's filter: nodes reachable upward through the tree.
        if !is_root
            && let Some(parent) = self.peers.get(&parent_id)
            && let Some(filter) = parent.inbound_filter()
        {
            add_to_union(&mut union, filter);
        }

        // Children's filters: each child's subtree is ideally disjoint; OR is
        // idempotent when filters overlap.
        for (peer_addr, peer) in &self.peers {
            if peer_addr == &parent_id {
                continue;
            }
            if let Some(decl) = self.tree_state.peer_declaration(peer_addr)
                && *decl.parent_id() == my_addr
            {
                child_count += 1;
                if let Some(filter) = peer.inbound_filter() {
                    add_to_union(&mut union, filter);
                }
            }
        }

        let Some(mut union) = union else {
            self.estimated_mesh_size = None;
            return;
        };
        union.insert(&my_addr);

        // If the union is saturated or above the FPR cap, refuse to estimate
        // rather than publish a biased aggregate.
        let Some(union_estimate) = union.estimated_count(max_fpr) else {
            self.estimated_mesh_size = None;
            return;
        };

        let size = union_estimate.round() as u64;
        self.estimated_mesh_size = Some(size);

        // Periodic logging (reuse MMP default interval: 30s)
        let now = std::time::Instant::now();
        let should_log = match self.last_mesh_size_log {
            None => true,
            Some(last) => {
                now.duration_since(last)
                    >= std::time::Duration::from_secs(self.config.node.mmp.log_interval_secs)
            }
        };
        if should_log {
            tracing::debug!(
                estimated_mesh_size = size,
                peers = self.peers.len(),
                children = child_count,
                "Mesh size estimate"
            );
            self.last_mesh_size_log = Some(now);
        }
    }

    // === Coord Cache ===

    /// Get the coordinate cache.
    pub fn coord_cache(&self) -> &CoordCache {
        &self.coord_cache
    }

    /// Get mutable coordinate cache.
    pub fn coord_cache_mut(&mut self) -> &mut CoordCache {
        &mut self.coord_cache
    }

    // === Node Statistics ===

    /// Get the node statistics.
    pub fn stats(&self) -> &stats::NodeStats {
        &self.stats
    }

    /// Get mutable node statistics.
    pub(crate) fn stats_mut(&mut self) -> &mut stats::NodeStats {
        &mut self.stats
    }

    /// Get the stats history collector.
    pub fn stats_history(&self) -> &stats_history::StatsHistory {
        &self.stats_history
    }

    /// Sample the current node state into the stats history ring.
    /// Called once per tick from the RX loop.
    pub(crate) fn record_stats_history(&mut self) {
        let fwd = &self.stats.forwarding;
        let peers_with_mmp: Vec<f64> = self
            .peers
            .values()
            .filter_map(|p| p.mmp().map(|m| m.metrics.loss_rate()))
            .collect();
        let loss_rate = if peers_with_mmp.is_empty() {
            0.0
        } else {
            peers_with_mmp.iter().sum::<f64>() / peers_with_mmp.len() as f64
        };

        let snap = stats_history::Snapshot {
            mesh_size: self.estimated_mesh_size,
            tree_depth: self.tree_state.my_coords().depth() as u32,
            peer_count: self.peers.len() as u64,
            parent_switches_total: self.stats.tree.parent_switches,
            bytes_in_total: fwd.received_bytes,
            bytes_out_total: fwd.forwarded_bytes + fwd.originated_bytes,
            packets_in_total: fwd.received_packets,
            packets_out_total: fwd.forwarded_packets + fwd.originated_packets,
            loss_rate,
            active_sessions: self.sessions.len() as u64,
        };

        let now = std::time::Instant::now();
        let peer_snaps: Vec<stats_history::PeerSnapshot> = self
            .peers
            .values()
            .map(|p| {
                let stats = p.link_stats();
                let (srtt_ms, loss_rate, ecn_ce) = match p.mmp() {
                    Some(m) => (
                        m.metrics.srtt_ms(),
                        Some(m.metrics.loss_rate()),
                        m.receiver.ecn_ce_count() as u64,
                    ),
                    None => (None, None, 0),
                };
                stats_history::PeerSnapshot {
                    node_addr: *p.node_addr(),
                    last_seen: now,
                    srtt_ms,
                    loss_rate,
                    bytes_in_total: stats.bytes_recv,
                    bytes_out_total: stats.bytes_sent,
                    packets_in_total: stats.packets_recv,
                    packets_out_total: stats.packets_sent,
                    ecn_ce_total: ecn_ce,
                }
            })
            .collect();

        self.stats_history.tick(now, &snap, &peer_snaps);
    }

    // === TUN Interface ===

    /// Get the TUN state.
    pub fn tun_state(&self) -> TunState {
        self.tun_state
    }

    /// Get the TUN interface name, if active.
    pub fn tun_name(&self) -> Option<&str> {
        self.tun_name.as_deref()
    }

    // === Resource Limits ===

    /// Set the maximum number of connections (handshake phase).
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    /// Set the maximum number of peers (authenticated).
    pub fn set_max_peers(&mut self, max: usize) {
        self.max_peers = max;
    }

    /// Returns false when starting more outbound work would exceed a resource
    /// cap. A cap of `0` means uncapped.
    pub(crate) fn outbound_admission_check(&self) -> bool {
        let connection_used = self
            .peers
            .connection_len()
            .saturating_add(self.pending_connects.len());
        let peer_allowed = self.max_peers == 0 || self.peers.len() < self.max_peers;
        let connection_allowed =
            self.max_connections == 0 || connection_used < self.max_connections;
        let link_allowed = self.max_links == 0 || self.links.len() < self.max_links;
        peer_allowed && connection_allowed && link_allowed
    }

    /// Admission for public/open-discovery outbound work. This includes the
    /// general connection/link caps and, when open Nostr discovery is enabled,
    /// the configured non-peer budget.
    pub(crate) fn open_discovery_outbound_admission_check(&self) -> bool {
        if !self.outbound_admission_check() {
            return false;
        }

        let nostr = &self.config.node.discovery.nostr;
        if !nostr.enabled || nostr.policy != NostrDiscoveryPolicy::Open {
            return true;
        }

        let configured_npubs = self
            .config
            .peers()
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();
        self.open_discovery_enqueue_budget(&configured_npubs) > 0
    }

    /// Like `outbound_admission_check`, but for racing a better path to a
    /// peer that is already authenticated. This may temporarily add a
    /// connection/link, but it does not consume a new peer slot.
    pub(crate) fn outbound_direct_refresh_admission_check(&self) -> bool {
        let connection_used = self
            .peers
            .connection_len()
            .saturating_add(self.pending_connects.len());
        let connection_allowed =
            self.max_connections == 0 || connection_used < self.max_connections;
        let link_allowed = self.max_links == 0 || self.links.len() < self.max_links;
        connection_allowed && link_allowed
    }

    /// Set the maximum number of links.
    pub fn set_max_links(&mut self, max: usize) {
        self.max_links = max;
    }

    // === Counts ===

    /// Number of pending connections (handshake in progress).
    pub fn connection_count(&self) -> usize {
        self.peers.connection_len()
    }

    /// Number of authenticated peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Number of active transports.
    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }

    // === Transport Management ===

    /// Allocate a new transport ID.
    pub fn allocate_transport_id(&mut self) -> TransportId {
        let id = TransportId::new(self.next_transport_id);
        self.next_transport_id += 1;
        id
    }

    /// Get a transport by ID.
    pub fn get_transport(&self, id: &TransportId) -> Option<&TransportHandle> {
        self.transports.get(id)
    }

    /// Get mutable transport by ID.
    pub fn get_transport_mut(&mut self, id: &TransportId) -> Option<&mut TransportHandle> {
        self.transports.get_mut(id)
    }

    /// Iterate over transport IDs.
    pub fn transport_ids(&self) -> impl Iterator<Item = &TransportId> {
        self.transports.keys()
    }

    /// Get the packet receiver for the event loop.
    pub fn packet_rx(&mut self) -> Option<&mut PacketRx> {
        self.packet_rx.as_mut()
    }

    // === Link Management ===

    /// Allocate a new link ID.
    pub fn allocate_link_id(&mut self) -> LinkId {
        let id = LinkId::new(self.next_link_id);
        self.next_link_id += 1;
        id
    }

    /// Add a link.
    pub fn add_link(&mut self, link: Link) -> Result<(), NodeError> {
        if self.max_links > 0 && self.links.len() >= self.max_links {
            return Err(NodeError::MaxLinksExceeded {
                max: self.max_links,
            });
        }
        let link_id = link.link_id();

        self.links.insert(link_id, link);
        Ok(())
    }

    /// Get a link by ID.
    pub fn get_link(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Get a mutable link by ID.
    pub fn get_link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    /// Find link ID by transport address.
    pub fn find_link_by_addr(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.links.lookup_addr(transport_id, addr)
    }

    /// Remove a link.
    ///
    /// Only removes the reverse address dispatch entry if it still points to this
    /// link. In cross-connection scenarios, a newer link may have replaced the
    /// entry for the same address.
    pub fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        self.links.remove(link_id)
    }

    pub(crate) fn cleanup_bootstrap_transport_if_unused(&mut self, transport_id: TransportId) {
        if !self.bootstrap_transports.contains(&transport_id) {
            return;
        }

        let transport_in_use = self
            .links
            .values()
            .any(|link| link.transport_id() == transport_id)
            || self
                .peers
                .connection_values()
                .any(|conn| conn.transport_id() == Some(transport_id))
            || self
                .peers
                .values()
                .any(|peer| peer.transport_id() == Some(transport_id))
            || self
                .pending_connects
                .iter()
                .any(|pending| pending.transport_id == transport_id);

        if transport_in_use {
            return;
        }

        tracing::debug!(
            transport_id = %transport_id,
            "bootstrap transport has no remaining references; dropping"
        );

        self.bootstrap_transports.remove(&transport_id);
        self.transport_drops.remove(&transport_id);
        self.transports.remove(&transport_id);
    }

    /// Iterate over all links.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    // === Connection Management (Handshake Phase) ===

    /// Add a pending connection.
    pub fn add_connection(&mut self, connection: PeerConnection) -> Result<(), NodeError> {
        let link_id = connection.link_id();

        if self.peers.contains_connection(&link_id) {
            return Err(NodeError::ConnectionAlreadyExists(link_id));
        }

        if self.max_connections > 0 && self.peers.connection_len() >= self.max_connections {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections,
            });
        }

        self.peers.insert_connection(link_id, connection);
        Ok(())
    }

    /// Get a connection by LinkId.
    pub fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.peers.get_connection(link_id)
    }

    /// Get a mutable connection by LinkId.
    pub fn get_connection_mut(&mut self, link_id: &LinkId) -> Option<&mut PeerConnection> {
        self.peers.get_connection_mut(link_id)
    }

    /// Remove a connection.
    pub fn remove_connection(&mut self, link_id: &LinkId) -> Option<PeerConnection> {
        self.peers.remove_connection(link_id)
    }

    /// Iterate over all connections.
    pub fn connections(&self) -> impl Iterator<Item = &PeerConnection> {
        self.peers.connection_values()
    }

    // === Peer Management (Active Phase) ===

    /// Get a peer by NodeAddr.
    pub fn get_peer(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.peers.get(node_addr)
    }

    /// Get a mutable peer by NodeAddr.
    pub fn get_peer_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_addr)
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.peers.remove(node_addr)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    /// Reference to the Nostr discovery handle if discovery is enabled.
    /// Used by control queries (`show_peers` per-peer Nostr-traversal
    /// state) to read failure-state without taking shared ownership.
    pub fn nostr_discovery_handle(&self) -> Option<&crate::discovery::nostr::NostrDiscovery> {
        self.nostr_discovery.as_deref()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeAddr> {
        self.peers.keys()
    }

    /// Iterate over peers that can send traffic.
    pub fn sendable_peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values().filter(|p| p.can_send())
    }

    /// Number of peers that can send traffic.
    pub fn sendable_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.can_send()).count()
    }

    pub(crate) fn set_discovery_fallback_transit_allowed(
        &mut self,
        peer_addr: NodeAddr,
        allowed: bool,
    ) {
        self.discovery_fallback_transit
            .set_allowed(peer_addr, allowed);
    }

    pub(crate) fn configured_discovery_fallback_transit(
        &self,
        peer_addr: &NodeAddr,
    ) -> Option<bool> {
        self.configured_peer(peer_addr)
            .map(|peer| peer.discovery_fallback_transit)
    }

    pub(crate) fn configured_peer(&self, peer_addr: &NodeAddr) -> Option<&PeerConfig> {
        self.config.peers().iter().find(|peer| {
            PeerIdentity::from_npub(&peer.npub)
                .ok()
                .is_some_and(|identity| identity.node_addr() == peer_addr)
        })
    }

    pub(in crate::node) fn active_peer_uses_configured_static_udp_path(
        &self,
        peer_addr: &NodeAddr,
    ) -> bool {
        let Some(peer_config) = self.configured_peer(peer_addr) else {
            return false;
        };

        peer_config.addresses.iter().any(|candidate| {
            candidate.seen_at_ms.is_none()
                && candidate.transport.eq_ignore_ascii_case("udp")
                && self.active_peer_matches_candidate(peer_addr, candidate)
        })
    }

    pub(crate) fn discovery_fallback_transit_for_promotion(&self, peer_addr: &NodeAddr) -> bool {
        if let Some(retry_state) = self.retry_pending.get(peer_addr) {
            return retry_state.peer_config.discovery_fallback_transit;
        }

        if let Some(allowed) = self.configured_discovery_fallback_transit(peer_addr) {
            return allowed;
        }

        self.config.node.discovery.nostr.policy != crate::config::NostrDiscoveryPolicy::Open
    }

    // === End-to-End Sessions ===

    /// Get a session by remote NodeAddr.
    /// Disable the discovery forward rate limiter (for tests).
    #[cfg(test)]
    pub(crate) fn disable_discovery_forward_rate_limit(&mut self) {
        self.discovery_forward_limiter
            .set_interval(std::time::Duration::ZERO);
    }

    #[cfg(test)]
    pub(crate) fn get_session(&self, remote: &NodeAddr) -> Option<&SessionEntry> {
        self.sessions.get(remote)
    }

    /// Get a mutable session by remote NodeAddr.
    #[cfg(test)]
    pub(crate) fn get_session_mut(&mut self, remote: &NodeAddr) -> Option<&mut SessionEntry> {
        self.sessions.get_mut(remote)
    }

    /// Remove a session.
    #[cfg(test)]
    pub(crate) fn remove_session(&mut self, remote: &NodeAddr) -> Option<SessionEntry> {
        self.sessions.remove(remote)
    }

    /// Read the path_mtu_lookup entry for a destination FipsAddress.
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_get(&self, fips_addr: &crate::FipsAddress) -> Option<u16> {
        self.path_mtu_lookup
            .read()
            .ok()
            .and_then(|map| map.get(fips_addr).copied())
    }

    /// Write a path_mtu_lookup entry directly (for tests that pre-seed the map).
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_insert(&self, fips_addr: crate::FipsAddress, mtu: u16) {
        if let Ok(mut map) = self.path_mtu_lookup.write() {
            map.insert(fips_addr, mtu);
        }
    }

    /// Number of end-to-end sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Iterate over all session entries (for control queries).
    pub(crate) fn session_entries(&self) -> impl Iterator<Item = (&NodeAddr, &SessionEntry)> {
        self.sessions.iter()
    }

    // === Identity Cache ===

    /// Register a node in the identity cache for FipsAddress → NodeAddr lookup.
    pub(crate) fn register_identity(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
    ) -> bool {
        // Endpoint sends pass the same PeerIdentity on every packet. Once
        // validated, avoid re-deriving NodeAddr from the public key in the
        // data path; that hash showed up in macOS sender profiles.
        self.identity_cache.register(
            node_addr,
            pubkey,
            Self::now_ms(),
            self.config.node.cache.identity_size,
        )
    }

    /// Look up a destination by FipsAddress prefix (bytes 1-15 of the IPv6 address).
    pub(crate) fn lookup_by_fips_prefix(
        &mut self,
        prefix: &[u8; 15],
    ) -> Option<(NodeAddr, secp256k1::PublicKey)> {
        self.identity_cache.lookup_by_prefix(prefix, Self::now_ms())
    }

    /// Check if a node's identity is in the cache (without LRU touch).
    pub(crate) fn has_cached_identity(&self, addr: &NodeAddr) -> bool {
        self.identity_cache.has_prefix_for(addr)
    }

    /// Number of identity cache entries.
    pub fn identity_cache_len(&self) -> usize {
        self.identity_cache.len()
    }

    /// Iterate over identity cache entries.
    ///
    /// Returns `(NodeAddr, PublicKey, last_seen_ms)` for each cached identity.
    /// Used by the `show_identity_cache` control query.
    pub fn identity_cache_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &secp256k1::PublicKey, u64)> {
        self.identity_cache.iter()
    }

    /// Configured maximum identity cache size.
    pub fn identity_cache_max(&self) -> usize {
        self.config.node.cache.identity_size
    }

    /// Number of pending discovery lookups.
    pub fn pending_lookup_count(&self) -> usize {
        self.pending_lookups.len()
    }

    /// Iterate over pending discovery lookups for diagnostics.
    pub fn pending_lookups_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &handlers::discovery::PendingLookup)> {
        self.pending_lookups.iter()
    }

    /// Number of recent discovery requests tracked.
    pub fn recent_request_count(&self) -> usize {
        self.recent_requests.len()
    }

    /// Count of destinations with queued TUN packets awaiting session setup.
    pub fn pending_tun_destinations(&self) -> usize {
        self.pending_session_traffic.tun_destination_count()
    }

    /// Total TUN packets queued across all destinations.
    pub fn pending_tun_total_packets(&self) -> usize {
        self.pending_session_traffic.tun_packet_count()
    }

    /// Iterate over retry state for diagnostics.
    pub fn retry_state_iter(&self) -> impl Iterator<Item = (&NodeAddr, &retry::RetryState)> {
        self.retry_pending.iter()
    }

    // === Routing ===

    /// Check if a peer is a tree neighbor (parent or child in the spanning tree).
    ///
    /// Returns true if the peer is our current tree parent, or if the peer
    /// has declared us as their parent (making them our child).
    pub(crate) fn is_tree_peer(&self, peer_addr: &NodeAddr) -> bool {
        // Peer is our parent
        if !self.tree_state.is_root() && self.tree_state.my_declaration().parent_id() == peer_addr {
            return true;
        }
        // Peer is our child (their declaration names us as parent)
        if let Some(decl) = self.tree_state.peer_declaration(peer_addr)
            && decl.parent_id() == self.node_addr()
        {
            return true;
        }
        false
    }

    /// Find next hop for a destination node address.
    ///
    /// Routing priority:
    /// 1. Destination is self → `None` (local delivery)
    /// 2. Destination is a healthy direct peer → that peer. A known fallback
    ///    next-hop may beat a non-static direct path when it has a meaningful
    ///    link-quality advantage; operator-configured static UDP peers stay
    ///    pinned to direct while healthy.
    /// 3. Reply-learned routes in `reply_learned` mode. These are locally
    ///    observed reverse paths, selected with weighted multipath plus
    ///    periodic coordinate/tree exploration.
    /// 4. Bloom filter candidates with cached dest coords → among peers whose
    ///    bloom filter contains the destination, pick the one that minimizes
    ///    tree distance to the destination, with
    ///    `(link_cost, tree_distance_to_dest, node_addr)` tie-breaking.
    ///    The self-distance check ensures only peers strictly closer to the
    ///    destination than us are considered (prevents routing loops).
    /// 5. Greedy tree routing fallback (requires cached dest coords)
    /// 6. No route → `None`
    ///
    /// Both the bloom filter and tree routing paths require cached destination
    /// coordinates (checked in `coord_cache`). Without coordinates, the node
    /// cannot make loop-free forwarding decisions. The caller should signal
    /// `CoordsRequired` back to the source when `None` is returned for a
    /// non-local destination.
    pub fn find_next_hop(&mut self, dest_node_addr: &NodeAddr) -> Option<&ActivePeer> {
        // 1. Local delivery
        if dest_node_addr == self.node_addr() {
            return None;
        }
        let now_ms = Self::now_ms();
        let direct_session_degraded =
            self.session_direct_path_blocks_direct_payload(dest_node_addr, now_ms);

        let healthy_direct_route = self
            .peers
            .get(dest_node_addr)
            .filter(|peer| peer.is_healthy() && !direct_session_degraded)
            .map(|_| *dest_node_addr);
        if let Some(direct_addr) = healthy_direct_route
            && self
                .peers
                .get(&direct_addr)
                .is_some_and(|peer| peer.link_cost() <= 1.0 + ROUTING_FALLBACK_MIN_COST_ADVANTAGE)
        {
            return self.peers.get(&direct_addr);
        }
        let direct_payload_eligible = healthy_direct_route.is_some();
        let payload_candidate_can_send = |addr: &NodeAddr, peer: &ActivePeer| {
            if addr == dest_node_addr {
                direct_payload_eligible
            } else {
                peer.is_healthy()
            }
        };

        // A healthy direct path is not automatically the best path. A
        // hotspot/NAT hairpin can remain sendable with high RTT or mild loss;
        // in that case a lower-cost mesh next-hop should carry traffic while
        // direct probes continue in the background.
        let fallback_beats_direct = |node: &Self, fallback_addr: NodeAddr| {
            node.route_candidate_beats_direct(healthy_direct_route, fallback_addr)
        };

        let sendable_learned_peers = if self.config.node.routing.mode == RoutingMode::ReplyLearned {
            Some(
                self.peers
                    .iter()
                    .filter(|(addr, peer)| payload_candidate_can_send(addr, peer))
                    .map(|(addr, _)| *addr)
                    .collect::<HashSet<_>>(),
            )
        } else {
            None
        };

        // 3. Optional reply-learned routing. These entries are not peer
        // claims; they are local observations of which peer carried traffic
        // or a verified lookup response back from the destination. Most
        // packets use weighted multipath over learned routes, but periodic
        // fallback exploration lets coord/bloom/tree routes discover better
        // candidates.
        let explore_fallback = sendable_learned_peers.as_ref().is_some_and(|sendable| {
            self.learned_routes.should_explore_fallback(
                dest_node_addr,
                now_ms,
                self.config.node.routing.learned_fallback_explore_interval,
                |addr| sendable.contains(addr),
            )
        });
        if let Some(sendable) = &sendable_learned_peers
            && !explore_fallback
        {
            let eligible = sendable
                .iter()
                .copied()
                .filter(|addr| fallback_beats_direct(self, *addr))
                .collect::<HashSet<_>>();
            if !eligible.is_empty()
                && let Some(next_hop_addr) =
                    self.learned_routes
                        .select_next_hop(dest_node_addr, now_ms, |addr| eligible.contains(addr))
            {
                return self.peers.get(&next_hop_addr);
            }
        }

        // Look up cached destination coordinates (required by both bloom and tree paths).
        let Some(dest_coords) = self
            .coord_cache
            .get_and_touch(dest_node_addr, now_ms)
            .cloned()
        else {
            if (healthy_direct_route.is_none() || explore_fallback)
                && let Some(sendable) = &sendable_learned_peers
                && let Some(next_hop_addr) =
                    self.learned_routes
                        .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
            {
                return self.peers.get(&next_hop_addr);
            }
            if let Some(direct_addr) = healthy_direct_route {
                return self.peers.get(&direct_addr);
            }
            return None;
        };

        // 4. Bloom filter candidates — requires dest_coords for loop-free selection.
        //    If no candidate is strictly closer, fall through to tree routing.
        let coordinate_route_addr = {
            let candidates: Vec<&ActivePeer> = self
                .peers
                .iter()
                .filter(|(addr, peer)| {
                    payload_candidate_can_send(addr, peer) && peer.may_reach(dest_node_addr)
                })
                .map(|(_, peer)| peer)
                .collect();
            if !candidates.is_empty() {
                self.select_best_candidate(&candidates, &dest_coords)
                    .map(|peer| *peer.node_addr())
            } else {
                None
            }
        };
        if let Some(next_hop_addr) = coordinate_route_addr
            && fallback_beats_direct(self, next_hop_addr)
        {
            return self.peers.get(&next_hop_addr);
        }

        // 5. Greedy tree routing fallback
        let tree_route_addr = self.select_tree_payload_candidate(
            &dest_coords,
            dest_node_addr,
            direct_payload_eligible,
        );
        if let Some(next_hop_addr) = tree_route_addr
            && fallback_beats_direct(self, next_hop_addr)
        {
            return self.peers.get(&next_hop_addr);
        }

        if explore_fallback {
            return sendable_learned_peers.as_ref().and_then(|sendable| {
                self.learned_routes
                    .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
                    .and_then(|next_hop_addr| self.peers.get(&next_hop_addr))
            });
        }

        if let Some(direct_addr) = healthy_direct_route {
            return self.peers.get(&direct_addr);
        }

        if let Some(sendable) = &sendable_learned_peers
            && let Some(next_hop_addr) =
                self.learned_routes
                    .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
        {
            return self.peers.get(&next_hop_addr);
        }

        None
    }

    pub(in crate::node) fn find_transit_next_hop(
        &mut self,
        dest_node_addr: &NodeAddr,
        previous_hop: &NodeAddr,
    ) -> Option<NodeAddr> {
        if dest_node_addr == self.node_addr() {
            return None;
        }

        if dest_node_addr != previous_hop
            && self
                .peers
                .get(dest_node_addr)
                .is_some_and(|peer| peer.is_healthy())
        {
            return Some(*dest_node_addr);
        }

        let next_hop_addr = *self.find_next_hop(dest_node_addr)?.node_addr();
        if &next_hop_addr == previous_hop {
            self.record_route_failure(*dest_node_addr, next_hop_addr);
            return None;
        }
        Some(next_hop_addr)
    }

    fn route_candidate_beats_direct(
        &self,
        healthy_direct_route: Option<NodeAddr>,
        candidate_addr: NodeAddr,
    ) -> bool {
        let Some(direct_addr) = healthy_direct_route else {
            return true;
        };
        if candidate_addr == direct_addr {
            return false;
        }

        let Some(direct) = self.peers.get(&direct_addr) else {
            return true;
        };
        if self.active_peer_uses_configured_static_udp_path(&direct_addr) {
            return false;
        }
        let Some(candidate) = self.peers.get(&candidate_addr) else {
            return false;
        };
        if !candidate.is_healthy() {
            return false;
        }

        let direct_cost = direct.link_cost();
        let candidate_cost = candidate.link_cost();
        candidate_cost + ROUTING_FALLBACK_MIN_COST_ADVANTAGE < direct_cost
    }

    fn select_tree_payload_candidate(
        &self,
        dest_coords: &crate::tree::TreeCoordinate,
        direct_dest: &NodeAddr,
        direct_payload_eligible: bool,
    ) -> Option<NodeAddr> {
        if self.tree_state.my_coords().root_id() != dest_coords.root_id() {
            return None;
        }

        let my_distance = self.tree_state.my_coords().distance_to(dest_coords);
        let mut best: Option<(NodeAddr, usize)> = None;

        for (peer_addr, peer) in &self.peers {
            if peer_addr == direct_dest {
                if !direct_payload_eligible {
                    continue;
                }
            } else if !peer.is_healthy() {
                continue;
            }

            let Some(peer_coords) = self.tree_state.peer_coords(peer_addr) else {
                continue;
            };
            let distance = peer_coords.distance_to(dest_coords);
            if distance >= my_distance {
                continue;
            }

            let dominated = match &best {
                None => true,
                Some((best_id, best_dist)) => {
                    distance < *best_dist || (distance == *best_dist && peer_addr < best_id)
                }
            };
            if dominated {
                best = Some((*peer_addr, distance));
            }
        }

        best.map(|(peer_addr, _)| peer_addr)
    }

    pub(in crate::node) fn session_direct_path_is_degraded(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_degradation.is_degraded(dest, now_ms)
    }

    pub(in crate::node) fn session_direct_path_blocks_direct_payload(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_path_is_degraded(dest, now_ms)
            && !self.active_peer_uses_configured_static_udp_path(dest)
    }

    pub(in crate::node) fn mark_session_direct_path_degraded(
        &mut self,
        dest: NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_degradation
            .mark_degraded(dest, now_ms, SESSION_DIRECT_DEGRADED_HOLD_MS)
    }

    pub(in crate::node) fn clear_session_direct_path_degraded(&mut self, dest: &NodeAddr) -> bool {
        self.session_direct_degradation.clear(dest)
    }

    pub(in crate::node) fn learn_reverse_route(
        &mut self,
        destination: NodeAddr,
        next_hop: NodeAddr,
    ) {
        if self.config.node.routing.mode != RoutingMode::ReplyLearned
            || destination == *self.node_addr()
        {
            return;
        }
        let now_ms = Self::now_ms();
        self.learned_routes.learn(
            destination,
            next_hop,
            now_ms,
            self.config.node.routing.learned_ttl_secs,
            self.config.node.routing.max_learned_routes_per_dest,
        );
    }

    pub(in crate::node) fn record_route_failure(
        &mut self,
        destination: NodeAddr,
        next_hop: NodeAddr,
    ) {
        if self.config.node.routing.mode != RoutingMode::ReplyLearned {
            return;
        }
        self.learned_routes.record_failure(&destination, &next_hop);
    }

    pub(crate) fn learned_route_table_snapshot(&self, now_ms: u64) -> LearnedRouteTableSnapshot {
        self.learned_routes.snapshot(now_ms)
    }

    pub(in crate::node) fn purge_learned_routes(&mut self, now_ms: u64) {
        self.learned_routes.purge_expired(now_ms);
    }

    /// Select the best peer from a set of bloom filter candidates.
    ///
    /// Uses distance from each candidate's tree coordinates to the destination
    /// as the primary metric (after link_cost). Only selects peers that are
    /// strictly closer to the destination than we are (self-distance check
    /// prevents routing loops).
    ///
    /// Ordering: `(link_cost, distance_to_dest, node_addr)`.
    fn select_best_candidate<'a>(
        &'a self,
        candidates: &[&'a ActivePeer],
        dest_coords: &crate::tree::TreeCoordinate,
    ) -> Option<&'a ActivePeer> {
        let my_distance = self.tree_state.my_coords().distance_to(dest_coords);

        let mut best: Option<(&ActivePeer, f64, usize)> = None;

        for &candidate in candidates {
            if !candidate.can_send() {
                continue;
            }

            let cost = candidate.link_cost();

            let dist = self
                .tree_state
                .peer_coords(candidate.node_addr())
                .map(|pc| pc.distance_to(dest_coords))
                .unwrap_or(usize::MAX);

            // Self-distance check: only consider peers strictly closer
            // to the destination than we are (prevents routing loops)
            if dist >= my_distance {
                continue;
            }

            let dominated = match &best {
                None => true,
                Some((_, best_cost, best_dist)) => {
                    cost < *best_cost
                        || (cost == *best_cost && dist < *best_dist)
                        || (cost == *best_cost
                            && dist == *best_dist
                            && candidate.node_addr() < best.as_ref().unwrap().0.node_addr())
                }
            };

            if dominated {
                best = Some((candidate, cost, dist));
            }
        }

        best.map(|(peer, _, _)| peer)
    }

    /// Check if a destination is in any peer's bloom filter.
    pub fn destination_in_filters(&self, dest: &NodeAddr) -> Vec<&ActivePeer> {
        self.peers.values().filter(|p| p.may_reach(dest)).collect()
    }

    /// Get the TUN packet sender channel.
    ///
    /// Returns None if TUN is not active or the node hasn't been started.
    pub fn tun_tx(&self) -> Option<&TunTx> {
        self.tun_tx.as_ref()
    }

    /// Attach app-owned packet I/O for embedded operation without a system TUN.
    ///
    /// This must be called before [`Node::start`] and requires `tun.enabled =
    /// false`. Outbound packets sent to the returned sender are processed by the
    /// normal session pipeline. Inbound packets delivered by FIPS sessions are
    /// sent to the returned receiver with source attribution.
    pub fn attach_external_packet_io(
        &mut self,
        capacity: usize,
    ) -> Result<ExternalPacketIo, NodeError> {
        if self.state != NodeState::Created {
            return Err(NodeError::Config(ConfigError::Validation(
                "external packet I/O must be attached before node start".to_string(),
            )));
        }
        if self.config.tun.enabled {
            return Err(NodeError::Config(ConfigError::Validation(
                "external packet I/O requires tun.enabled=false".to_string(),
            )));
        }

        let capacity = capacity.max(1);
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(capacity);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(capacity);
        self.tun_outbound_rx = Some(outbound_rx);
        self.external_packet_tx = Some(inbound_tx);

        Ok(ExternalPacketIo {
            outbound_tx,
            inbound_rx,
        })
    }

    /// Attach app-owned endpoint data I/O for embedded operation.
    ///
    /// Commands sent to the returned sender are processed by the node RX loop.
    /// Incoming endpoint data is emitted as source-attributed events.
    pub(crate) fn attach_endpoint_data_io(
        &mut self,
        capacity: usize,
    ) -> Result<EndpointDataIo, NodeError> {
        if self.state != NodeState::Created {
            return Err(NodeError::Config(ConfigError::Validation(
                "endpoint data I/O must be attached before node start".to_string(),
            )));
        }

        let command_capacity = endpoint_data_command_capacity(capacity);
        let (priority_command_tx, priority_command_rx) =
            tokio::sync::mpsc::channel(command_capacity);
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(command_capacity);
        // Inbound endpoint-data events use an unbounded channel — see
        // `EndpointDataIo::event_rx` docs for the rationale (kills the
        // per-packet semaphore + the cross-task relay task that used to
        // sit on top of this channel).
        let (event_tx, event_rx) = EndpointEventSender::channel();
        self.endpoint_priority_command_rx = Some(priority_command_rx);
        self.endpoint_command_rx = Some(command_rx);
        self.endpoint_events.attach(event_tx.clone());

        Ok(EndpointDataIo {
            priority_command_tx,
            command_tx,
            event_rx,
            event_tx,
        })
    }

    pub(in crate::node) fn begin_endpoint_event_batch(&mut self) {
        self.endpoint_events.begin_batch();
    }

    pub(in crate::node) fn finish_endpoint_event_batch(&mut self) {
        self.endpoint_events.finish_batch();
    }

    pub(in crate::node) fn deliver_endpoint_event_message(
        &mut self,
        message: EndpointDataDelivery,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        self.endpoint_events.deliver_endpoint_data(message)
    }

    pub(crate) fn pubkey_for_node_addr(&self, addr: &NodeAddr) -> Option<secp256k1::PublicKey> {
        self.identity_cache.pubkey_for_node_addr(addr)
    }

    pub(crate) fn npub_for_node_addr(&self, addr: &NodeAddr) -> Option<String> {
        self.identity_cache.npub_for_node_addr(addr)
    }

    pub(in crate::node) fn deliver_external_ipv6_packet(
        &self,
        src_addr: &NodeAddr,
        packet: Vec<u8>,
    ) {
        let Some(external_packet_tx) = &self.external_packet_tx else {
            return;
        };
        if packet.len() < 40 {
            return;
        }
        let Ok(destination) = FipsAddress::from_slice(&packet[24..40]) else {
            return;
        };
        let delivered = NodeDeliveredPacket {
            source_node_addr: *src_addr,
            source_npub: self.npub_for_node_addr(src_addr),
            destination,
            packet,
        };
        if let Err(error) = external_packet_tx.try_send(delivered) {
            debug!(error = %error, "Failed to deliver packet to external app sink");
        }
    }

    // === Sending ===

    /// Encrypt and send a link-layer message to an authenticated peer.
    ///
    /// The plaintext should include the message type byte followed by the
    /// message-specific payload (e.g., `[0x50, reason]` for Disconnect).
    ///
    /// The send path prepends a 4-byte session-relative timestamp (inner
    /// header) before encryption. The full 16-byte outer header is used
    /// as AAD for the AEAD construction.
    ///
    /// This is the standard path for sending any link-layer control message
    /// to a peer over their encrypted Noise session.
    pub(super) async fn send_encrypted_link_message(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        self.send_encrypted_link_message_with_ce(node_addr, plaintext, false)
            .await
    }

    /// Update one peer's local-outbound-broken signal from a `transport.send`
    /// outcome. Sets a per-peer timestamp on local-side io errors
    /// (NetworkUnreachable / HostUnreachable / AddrNotAvailable); clears that
    /// peer on success. The reaper consults this in `check_link_heartbeats` to
    /// switch only that peer to `fast_link_dead_timeout_secs`.
    pub(in crate::node) fn note_local_send_outcome(
        &mut self,
        node_addr: &NodeAddr,
        result: &Result<usize, TransportError>,
    ) {
        self.local_send_failures
            .note_send_outcome(node_addr, result, std::time::Instant::now());
    }

    /// Return the active dead-timeout for one peer after considering recent
    /// local route failures. The fast-dead signal is intentionally short-lived:
    /// on the UDP worker path a send call can return before the kernel result
    /// is observed, so a stale route error must not compress liveness for the
    /// whole normal dead-timeout window.
    pub(in crate::node) fn local_send_failure_dead_timeout_for_peer(
        &self,
        node_addr: &NodeAddr,
        now: std::time::Instant,
        dead_timeout: std::time::Duration,
        fast_dead_timeout: std::time::Duration,
    ) -> std::time::Duration {
        self.local_send_failures.dead_timeout_for_peer(
            node_addr,
            now,
            dead_timeout,
            fast_dead_timeout,
        )
    }

    pub(in crate::node) fn purge_expired_local_send_failures(&mut self, now: std::time::Instant) {
        self.local_send_failures.purge_expired(now);
    }

    pub(in crate::node) fn mark_rx_loop_maintenance_timeout(&mut self) {
        self.last_rx_loop_maintenance_timeout_at = Some(std::time::Instant::now());
    }

    pub(in crate::node) fn rx_loop_maintenance_timed_out_recently(&self) -> bool {
        let Some(t) = self.last_rx_loop_maintenance_timeout_at else {
            return false;
        };
        let grace = std::time::Duration::from_secs(self.config.node.link_dead_timeout_secs.max(1));
        std::time::Instant::now().duration_since(t) <= grace
    }

    fn map_fmp_send_preparation_error(
        node_addr: NodeAddr,
        error: FmpSendPreparationError,
    ) -> NodeError {
        match error {
            FmpSendPreparationError::MissingPeer => NodeError::PeerNotFound(node_addr),
            FmpSendPreparationError::MissingTheirIndex => NodeError::SendFailed {
                node_addr,
                reason: "no their_index".into(),
            },
            FmpSendPreparationError::MissingTransportId => NodeError::SendFailed {
                node_addr,
                reason: "no transport_id".into(),
            },
            FmpSendPreparationError::MissingCurrentAddr => NodeError::SendFailed {
                node_addr,
                reason: "no current_addr".into(),
            },
            FmpSendPreparationError::MissingNoiseSession => NodeError::SendFailed {
                node_addr,
                reason: "no noise session".into(),
            },
            FmpSendPreparationError::PayloadLengthMismatch => NodeError::SendFailed {
                node_addr,
                reason: "payload length mismatch".into(),
            },
            FmpSendPreparationError::CounterReservationFailed => NodeError::SendFailed {
                node_addr,
                reason: "counter reservation failed".into(),
            },
            FmpSendPreparationError::EncryptionFailed => NodeError::SendFailed {
                node_addr,
                reason: "encryption failed".into(),
            },
        }
    }

    #[cfg(unix)]
    fn map_fsp_worker_send_reservation_error(
        node_addr: NodeAddr,
        error: FspWorkerSendReservationError,
    ) -> NodeError {
        match error {
            FspWorkerSendReservationError::MissingSession => NodeError::SendFailed {
                node_addr,
                reason: "no session".into(),
            },
            FspWorkerSendReservationError::NotEstablished => NodeError::SendFailed {
                node_addr,
                reason: "session not established".into(),
            },
            FspWorkerSendReservationError::CounterReservationFailed => NodeError::SendFailed {
                node_addr,
                reason: "session counter reservation failed".into(),
            },
        }
    }

    /// Like `send_encrypted_link_message` but allows setting the FMP CE flag.
    ///
    /// Used by the forwarding path to relay congestion signals hop-by-hop.
    pub(super) async fn send_encrypted_link_message_with_ce(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        // The inner-plaintext layout is `[ts:4 LE][plaintext...]`, so
        // its length is exactly `INNER_TS_LEN + plaintext.len()` — no
        // need to build the Vec just to measure it. The worker path uses
        // this length to size the wire buffer directly; the legacy path
        // below still materialises a separate `inner_plaintext` Vec for
        // the inline encrypt-and-send call.
        const INNER_TS_LEN: usize = 4;
        let inner_len = INNER_TS_LEN + plaintext.len();
        let payload_len = inner_len as u16;
        let prepared = self
            .peers
            .prepare_fmp_send(node_addr, ce_flag, payload_len)
            .map_err(|e| Self::map_fmp_send_preparation_error(*node_addr, e))?;

        // **Unix UDP send fast path.** On Unix, the encrypt-worker pool
        // is spawned at lifecycle start (workers = num_cpus) in
        // production, so this branch is taken for every authentic send on
        // every UDP-transported established session. The AEAD work +
        // sendmsg syscall run on a dedicated OS thread; the rx_loop only
        // builds the wire buffer + reserves the counter inline.
        //
        // Other transport kinds (BLE, TCP, sim, ethernet) fall
        // through to the inline encrypt + transport.send path
        // below — those don't have raw-fd / sendmmsg / UDP_GSO
        // benefits to expose through the worker pool, so the simpler
        // synchronous send is the right shape for them.
        //
        // Windows intentionally stays on the inline tokio UDP send path:
        // lifecycle::start does not spawn these raw-fd workers there, and
        // tests may still set `encrypt_workers` manually.
        //
        // The `encrypt_workers.is_some()` check below is true in Unix
        // production (lifecycle::start spawns the pool); it stays checked
        // rather than `expect()`-ed because unit tests construct `Node`
        // without calling `start()`.
        let transport_for_send = self
            .transports
            .get(&prepared.transport_id)
            .ok_or(NodeError::TransportNotFound(prepared.transport_id))?;
        match transport_for_send.connection_state(&prepared.remote_addr) {
            ConnectionState::Connected => {}
            other => {
                if matches!(other, ConnectionState::None) {
                    let _ = transport_for_send.connect(&prepared.remote_addr).await;
                }
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("transport connection not ready: {:?}", other),
                });
            }
        }
        #[cfg(unix)]
        {
            let is_udp = matches!(transport_for_send, TransportHandle::Udp(_));
            if let Some(workers) = self.encrypt_workers.as_ref().cloned()
                && is_udp
            {
                let transport = transport_for_send;
                // Snapshot the per-peer connected UDP socket before
                // resolving the fallback address. On the established
                // steady-state path this socket already carries the
                // kernel peer address, so re-parsing the configured
                // transport address and touching the DNS cache on every
                // packet is pure overhead on the sender hot path.
                let send_target = {
                    if let TransportHandle::Udp(udp) = transport {
                        let socket_addr = {
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            {
                                match prepared.connected_socket.as_ref() {
                                    Some(socket) => Some(socket.peer_addr()),
                                    None => {
                                        udp.resolve_for_off_task(&prepared.remote_addr).await.ok()
                                    }
                                }
                            }
                            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                            {
                                udp.resolve_for_off_task(&prepared.remote_addr).await.ok()
                            }
                        };
                        match (udp.async_socket(), socket_addr) {
                            (Some(socket), Some(socket_addr)) => Some((socket, socket_addr)),
                            _ => None,
                        }
                    } else {
                        None
                    }
                };
                if let Some((socket, socket_addr)) = send_target {
                    // Worker sends reserve their FMP counter only after
                    // the worker target is known. If the off-task path is
                    // unavailable, the inline path below remains the sole
                    // counter owner for this packet.
                    if let Some(worker_send) = self
                        .peers
                        .prepare_fmp_worker_send(node_addr, &prepared, plaintext)
                        .map_err(|e| Self::map_fmp_send_preparation_error(*node_addr, e))?
                    {
                        let reserved_counter = worker_send.counter;
                        let predicted_bytes = worker_send.predicted_bytes;
                        // Lifecycle send bookkeeping uses the predicted
                        // wire size, exact for ChaCha20-Poly1305 because the
                        // tag is constant 16 bytes. When `connected_socket`
                        // is `Some`, the worker sends on it without a
                        // destination sockaddr, so the kernel skips the
                        // per-packet sockaddr + route + neighbor resolve.
                        let _ = self.peers.record_fmp_send_bookkeeping(
                            node_addr,
                            reserved_counter,
                            prepared.timestamp_ms,
                            predicted_bytes,
                        );
                        let scheduling_weight = self.send_weight_for_peer(node_addr);
                        let traffic_class = classify_fmp_plaintext_traffic(plaintext);
                        workers.dispatch(self::encrypt_worker::FmpSendJob {
                            cipher: worker_send.cipher,
                            counter: reserved_counter,
                            wire_buf: worker_send.wire_buf,
                            fsp_seal: None,
                            send_target: self::encrypt_worker::SelectedSendTarget::new(
                                socket,
                                #[cfg(any(target_os = "linux", target_os = "macos"))]
                                prepared.connected_socket.clone(),
                                socket_addr,
                            ),
                            bulk_endpoint_data: traffic_class.bulk_endpoint_data,
                            drop_on_backpressure: traffic_class.drop_on_backpressure,
                            scheduling_weight,
                            queued_at: crate::perf_profile::stamp(),
                        });
                        return Ok(());
                    }
                }
            }
        }

        // Inline (legacy) path: encrypt + send on the rx_loop.
        // Build the inner plaintext lazily here — the worker path
        // above never reaches this point, so the prepend_inner_header
        // alloc is avoided in the fast path.
        let inner_plaintext = prepend_inner_header(prepared.timestamp_ms, plaintext);
        let inline = self
            .peers
            .seal_prepared_fmp_inline_send(node_addr, &prepared, &inner_plaintext)
            .map_err(|e| Self::map_fmp_send_preparation_error(*node_addr, e))?;

        // Re-borrow peer for stats update after sending
        let send_result = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
            let transport = self
                .transports
                .get(&prepared.transport_id)
                .ok_or(NodeError::TransportNotFound(prepared.transport_id))?;
            transport
                .send(&prepared.remote_addr, &inline.wire_packet)
                .await
        };
        self.note_local_send_outcome(node_addr, &send_result);
        let bytes_sent = send_result.map_err(|e| match e {
            TransportError::MtuExceeded { packet_size, mtu } => NodeError::MtuExceeded {
                node_addr: *node_addr,
                packet_size,
                mtu,
            },
            other => NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!("transport send: {}", other),
            },
        })?;

        // Update send statistics
        let _ = self.peers.record_fmp_send_bookkeeping(
            node_addr,
            inline.counter,
            prepared.timestamp_ms,
            bytes_sent,
        );

        Ok(())
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("node_addr", self.node_addr())
            .field("state", &self.state)
            .field("is_leaf_only", &self.is_leaf_only)
            .field("connections", &self.connection_count())
            .field("peers", &self.peer_count())
            .field("links", &self.link_count())
            .field("transports", &self.transport_count())
            .finish()
    }
}
