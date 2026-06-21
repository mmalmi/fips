use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::node) struct FmpPlaintextTrafficClass {
    pub(in crate::node) bulk_endpoint_data: bool,
    pub(in crate::node) drop_on_backpressure: bool,
}

/// Priority/bulk lane selected for an app-owned endpoint payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EndpointPayloadLane {
    #[default]
    Priority,
    Bulk,
}

impl EndpointPayloadLane {
    fn command_lane(self) -> EndpointCommandLane {
        match self {
            Self::Priority => EndpointCommandLane::Priority,
            Self::Bulk => EndpointCommandLane::Bulk,
        }
    }
}

/// Traffic policy selected for an app-owned endpoint payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointPayloadClass {
    lane: EndpointPayloadLane,
    drop_on_backpressure: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::node) struct EndpointFlowDispatchKey(u64);

impl EndpointFlowDispatchKey {
    pub(in crate::node) fn get(self) -> u64 {
        self.0
    }
}

impl EndpointPayloadClass {
    pub fn lane(self) -> EndpointPayloadLane {
        self.lane
    }

    pub fn is_latency_sensitive(self) -> bool {
        self.lane == EndpointPayloadLane::Priority
    }

    pub fn drop_on_backpressure(self) -> bool {
        self.drop_on_backpressure
    }
}

#[cfg(unix)]
pub(in crate::node) struct FmpWorkerSendReservation {
    pub(in crate::node) counter: u64,
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) cipher: ring::aead::LessSafeKey,
}

#[cfg(unix)]
pub(in crate::node) fn reserve_fmp_worker_send(
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

pub(in crate::node) fn classify_fmp_plaintext_traffic(
    plaintext: &[u8],
) -> FmpPlaintextTrafficClass {
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

pub(in crate::node) fn fmp_plaintext_is_bulk_session_datagram(plaintext: &[u8]) -> bool {
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

pub(in crate::node) fn endpoint_flow_dispatch_key(
    payload: &[u8],
) -> Option<EndpointFlowDispatchKey> {
    endpoint_payload_flow_parts(payload).map(|parts| EndpointFlowDispatchKey(parts.hash()))
}

/// Classify an app-owned endpoint payload for queue admission and pressure policy.
pub fn classify_endpoint_payload(payload: &[u8]) -> EndpointPayloadClass {
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_ICMPV6: u8 = 58;

    match parse_endpoint_payload_ip_proto(payload) {
        Some((IPPROTO_ICMP, _)) => EndpointPayloadClass::default(),
        Some((IPPROTO_ICMPV6, _)) => EndpointPayloadClass::default(),
        Some((IPPROTO_TCP, offset)) => {
            let latency_sensitive = endpoint_tcp_payload_is_latency_sensitive(payload, offset);
            EndpointPayloadClass {
                lane: if latency_sensitive {
                    EndpointPayloadLane::Priority
                } else {
                    EndpointPayloadLane::Bulk
                },
                drop_on_backpressure: false,
            }
        }
        _ => EndpointPayloadClass {
            lane: EndpointPayloadLane::Bulk,
            drop_on_backpressure: true,
        },
    }
}

/// Return true when an app-owned endpoint payload should retain priority-lane progress.
///
/// Embedders that stage packets before calling `FipsEndpoint::send*_to_peer`
/// can use this to apply the same priority/bulk policy as the FIPS endpoint
/// command queue without duplicating IP/TCP parsing.
pub fn endpoint_payload_is_latency_sensitive(payload: &[u8]) -> bool {
    classify_endpoint_payload(payload).is_latency_sensitive()
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
    traffic_class: EndpointPayloadClass,
}

impl EndpointDataPayload {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        let traffic_class = classify_endpoint_payload(&bytes);
        Self {
            bytes,
            traffic_class,
        }
    }

    pub(crate) fn from_classified(bytes: Vec<u8>, traffic_class: EndpointPayloadClass) -> Self {
        Self {
            bytes,
            traffic_class,
        }
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.traffic_class.lane().command_lane()
    }

    pub(crate) fn bulk_endpoint_data(&self) -> bool {
        self.traffic_class.lane() == EndpointPayloadLane::Bulk
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.traffic_class.drop_on_backpressure()
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    fn pending_pressure_rank(&self) -> u8 {
        endpoint_payload_pending_pressure_rank(self.traffic_class)
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
    dropped_queued: bool,
    dropped_incoming: bool,
}

impl PendingEndpointDataQueueAdmission {
    #[cfg(test)]
    pub(crate) fn dropped_oldest(&self) -> bool {
        self.dropped_queued
    }

    pub(crate) fn dropped_payload(&self) -> bool {
        self.dropped_queued || self.dropped_incoming
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
        let capacity = capacity.max(1);
        if self.payloads.len() < capacity {
            self.payloads.push_back(payload);
            return PendingEndpointDataQueueAdmission {
                dropped_queued: false,
                dropped_incoming: false,
            };
        }

        let incoming_rank = payload.pending_pressure_rank();
        let Some((drop_index, queued_rank)) = self.pending_pressure_drop_candidate() else {
            self.payloads.push_back(payload);
            return PendingEndpointDataQueueAdmission {
                dropped_queued: false,
                dropped_incoming: false,
            };
        };
        if incoming_rank > queued_rank {
            return PendingEndpointDataQueueAdmission {
                dropped_queued: false,
                dropped_incoming: true,
            };
        }

        let _ = self.payloads.remove(drop_index);
        self.payloads.push_back(payload);
        PendingEndpointDataQueueAdmission {
            dropped_queued: true,
            dropped_incoming: false,
        }
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

    fn pending_pressure_drop_candidate(&self) -> Option<(usize, u8)> {
        pending_pressure_drop_candidate(
            self.payloads
                .iter()
                .enumerate()
                .map(|(index, payload)| (index, payload.pending_pressure_rank())),
        )
    }
}

/// Admission result for a bounded pending TUN packet queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingTunPacketQueueAdmission {
    dropped_queued: bool,
    dropped_incoming: bool,
}

impl PendingTunPacketQueueAdmission {
    #[cfg(test)]
    pub(crate) fn dropped_oldest(&self) -> bool {
        self.dropped_queued
    }

    pub(crate) fn dropped_packet(&self) -> bool {
        self.dropped_queued || self.dropped_incoming
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
        let capacity = capacity.max(1);
        if self.packets.len() < capacity {
            self.packets.push_back(packet);
            return PendingTunPacketQueueAdmission {
                dropped_queued: false,
                dropped_incoming: false,
            };
        }

        let incoming_rank =
            endpoint_payload_pending_pressure_rank(classify_endpoint_payload(&packet));
        let Some((drop_index, queued_rank)) = self.pending_pressure_drop_candidate() else {
            self.packets.push_back(packet);
            return PendingTunPacketQueueAdmission {
                dropped_queued: false,
                dropped_incoming: false,
            };
        };
        if incoming_rank > queued_rank {
            return PendingTunPacketQueueAdmission {
                dropped_queued: false,
                dropped_incoming: true,
            };
        }

        let _ = self.packets.remove(drop_index);
        self.packets.push_back(packet);
        PendingTunPacketQueueAdmission {
            dropped_queued: true,
            dropped_incoming: false,
        }
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

    fn pending_pressure_drop_candidate(&self) -> Option<(usize, u8)> {
        pending_pressure_drop_candidate(self.packets.iter().enumerate().map(|(index, packet)| {
            (
                index,
                endpoint_payload_pending_pressure_rank(classify_endpoint_payload(packet)),
            )
        }))
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
    pending_destinations: HashSet<NodeAddr>,
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
        self.pending_destinations.insert(dest_addr);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest: admission.dropped_packet(),
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
        self.pending_destinations.insert(dest_addr);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest: admission.dropped_payload(),
        }
    }

    pub(crate) fn remove_destination(&mut self, dest_addr: &NodeAddr) -> PendingDestinationTraffic {
        self.pending_destinations.remove(dest_addr);
        PendingDestinationTraffic {
            tun_packets: self.tun_packets.remove(dest_addr),
            endpoint_data: self.endpoint_data.remove(dest_addr),
        }
    }

    pub(crate) fn take_tun_packets(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<PendingTunPacketQueue> {
        let packets = self.tun_packets.remove(dest_addr);
        if packets.is_some() && !self.endpoint_data.contains_key(dest_addr) {
            self.pending_destinations.remove(dest_addr);
        }
        packets
    }

    pub(crate) fn take_endpoint_data(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<PendingEndpointDataQueue> {
        let payloads = self.endpoint_data.remove(dest_addr);
        if payloads.is_some() && !self.tun_packets.contains_key(dest_addr) {
            self.pending_destinations.remove(dest_addr);
        }
        payloads
    }

    pub(crate) fn has_traffic_for(&self, dest_addr: &NodeAddr) -> bool {
        self.pending_destinations.contains(dest_addr)
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

fn endpoint_payload_pending_pressure_rank(traffic_class: EndpointPayloadClass) -> u8 {
    if traffic_class.drop_on_backpressure() {
        2
    } else if traffic_class.lane() == EndpointPayloadLane::Bulk {
        1
    } else {
        0
    }
}

fn pending_pressure_drop_candidate(
    ranks: impl Iterator<Item = (usize, u8)>,
) -> Option<(usize, u8)> {
    let mut candidate = None;
    for (index, rank) in ranks {
        match candidate {
            Some((_candidate_index, candidate_rank)) if candidate_rank >= rank => {}
            _ => candidate = Some((index, rank)),
        }
    }
    candidate
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

#[derive(Clone, Copy)]
struct EndpointFlowParts<'a> {
    version: u8,
    proto: u8,
    src: &'a [u8],
    dst: &'a [u8],
    ports: Option<[u8; 4]>,
}

impl EndpointFlowParts<'_> {
    fn hash(self) -> u64 {
        let mut h = EndpointFlowHasher::default();
        h.write_u8(self.version);
        h.write_u8(self.proto);
        h.write(self.src);
        h.write(self.dst);
        if let Some(ports) = self.ports {
            h.write(&ports);
        }
        h.finish()
    }
}

#[derive(Clone, Copy)]
struct EndpointFlowHasher(u64);

impl Default for EndpointFlowHasher {
    fn default() -> Self {
        Self(0x9ae1_6a3b_2f90_404f)
    }
}

impl EndpointFlowHasher {
    fn write_u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x1000_0000_01b3);
            self.0 ^= self.0 >> 32;
        }
    }

    fn finish(self) -> u64 {
        self.0
    }
}

fn endpoint_payload_flow_parts(payload: &[u8]) -> Option<EndpointFlowParts<'_>> {
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    let version = payload.first().copied()? >> 4;
    match version {
        4 => {
            if payload.len() < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let header_len = usize::from(payload[0] & 0x0f) * 4;
            if header_len < IPV4_MIN_HEADER_LEN || payload.len() < header_len {
                return None;
            }
            let fragment_bits = u16::from_be_bytes([payload[6], payload[7]]) & 0x3fff;
            Some(EndpointFlowParts {
                version,
                proto: payload[9],
                src: &payload[12..16],
                dst: &payload[16..20],
                ports: if fragment_bits == 0 {
                    endpoint_transport_ports(payload, payload[9], header_len)
                } else {
                    None
                },
            })
        }
        6 => {
            if payload.len() < IPV6_HEADER_LEN {
                return None;
            }
            let (proto, offset, fragmented) = ipv6_payload_next_header_with_fragment(payload)?;
            Some(EndpointFlowParts {
                version,
                proto,
                src: &payload[8..24],
                dst: &payload[24..40],
                ports: if fragmented {
                    None
                } else {
                    endpoint_transport_ports(payload, proto, offset)
                },
            })
        }
        _ => None,
    }
}

fn endpoint_transport_ports(payload: &[u8], proto: u8, transport_offset: usize) -> Option<[u8; 4]> {
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const IPPROTO_SCTP: u8 = 132;

    if !matches!(proto, IPPROTO_TCP | IPPROTO_UDP | IPPROTO_SCTP) {
        return None;
    }
    let ports = payload.get(transport_offset..transport_offset + 4)?;
    Some([ports[0], ports[1], ports[2], ports[3]])
}

#[cfg(test)]
pub(in crate::node) fn endpoint_payload_is_tcp(payload: &[u8]) -> bool {
    const IPPROTO_TCP: u8 = 6;
    parse_endpoint_payload_ip_proto(payload).is_some_and(|(proto, _)| proto == IPPROTO_TCP)
}

fn ipv6_payload_next_header(payload: &[u8]) -> Option<(u8, usize)> {
    ipv6_payload_next_header_with_fragment(payload)
        .map(|(next_header, offset, _)| (next_header, offset))
}

fn ipv6_payload_next_header_with_fragment(payload: &[u8]) -> Option<(u8, usize, bool)> {
    const IPV6_HEADER_LEN: usize = 40;
    const IPV6_FRAGMENT_HEADER_LEN: usize = 8;

    if payload.len() < IPV6_HEADER_LEN || payload[0] >> 4 != 6 {
        return None;
    }

    let mut next_header = payload[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut extension_count = 0usize;
    let mut fragmented = false;
    while ipv6_extension_header_is_skippable(next_header) {
        if next_header == 44 {
            if payload.len() < offset + IPV6_FRAGMENT_HEADER_LEN {
                return None;
            }
            fragmented = true;
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

    Some((next_header, offset, fragmented))
}

fn ipv6_extension_header_is_skippable(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 51 | 60 | 135)
}
