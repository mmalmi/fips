use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::node) struct FmpPlaintextTrafficClass {
    pub(in crate::node) bulk_endpoint_data: bool,
    pub(in crate::node) drop_on_backpressure: bool,
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

/// Endpoint payload bytes selected at app ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndpointDataPayload {
    bytes: Vec<u8>,
}

impl EndpointDataPayload {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
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
#[derive(Debug)]
pub(crate) struct PendingEndpointData {
    payload: EndpointDataPayload,
    enqueued_at_ms: u64,
}

impl PendingEndpointData {
    pub(crate) fn new(payload: EndpointDataPayload, enqueued_at_ms: u64) -> Self {
        Self {
            payload,
            enqueued_at_ms,
        }
    }

    pub(crate) fn payload(&self) -> &EndpointDataPayload {
        &self.payload
    }

    pub(crate) fn enqueued_at_ms(&self) -> u64 {
        self.enqueued_at_ms
    }

    pub(crate) fn into_payload(self) -> EndpointDataPayload {
        self.payload
    }
}

/// Per-destination endpoint payloads waiting for session establishment.
#[derive(Debug, Default)]
pub(crate) struct PendingEndpointDataQueue {
    payloads: VecDeque<PendingEndpointData>,
}

impl PendingEndpointDataQueue {
    pub(crate) fn push_bounded(
        &mut self,
        payload: EndpointDataPayload,
        enqueued_at_ms: u64,
        capacity: usize,
    ) -> PendingEndpointDataQueueAdmission {
        let dropped_oldest = self.payloads.len() >= capacity;
        if dropped_oldest {
            self.payloads.pop_front();
        }
        self.payloads
            .push_back(PendingEndpointData::new(payload, enqueued_at_ms));
        PendingEndpointDataQueueAdmission { dropped_oldest }
    }

    pub(crate) fn len(&self) -> usize {
        self.payloads.len()
    }

    pub(crate) fn into_pending_payloads(self) -> VecDeque<PendingEndpointData> {
        self.payloads
    }

    fn append_payloads(&mut self, payloads: &mut VecDeque<PendingEndpointData>) {
        self.payloads.append(payloads);
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &EndpointDataPayload> {
        self.payloads.iter().map(PendingEndpointData::payload)
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
#[derive(Debug)]
pub(crate) struct PendingTunPacket {
    packet: Vec<u8>,
    queued_at_ms: u64,
}

impl PendingTunPacket {
    fn new(packet: Vec<u8>, queued_at_ms: u64) -> Self {
        Self {
            packet,
            queued_at_ms,
        }
    }

    fn is_stale(&self, now_ms: u64, max_age_ms: u64) -> bool {
        now_ms.saturating_sub(self.queued_at_ms) > max_age_ms
    }

    pub(crate) fn into_packet(self) -> Vec<u8> {
        self.packet
    }
}

/// Per-destination TUN packets waiting for session establishment.
#[derive(Debug, Default)]
pub(crate) struct PendingTunPacketQueue {
    packets: VecDeque<PendingTunPacket>,
}

impl PendingTunPacketQueue {
    pub(crate) fn push_bounded(
        &mut self,
        packet: Vec<u8>,
        queued_at_ms: u64,
        capacity: usize,
    ) -> PendingTunPacketQueueAdmission {
        let dropped_oldest = self.packets.len() >= capacity;
        if dropped_oldest {
            self.packets.pop_front();
        }
        self.packets
            .push_back(PendingTunPacket::new(packet, queued_at_ms));
        PendingTunPacketQueueAdmission { dropped_oldest }
    }

    pub(crate) fn len(&self) -> usize {
        self.packets.len()
    }

    pub(crate) fn into_packets(self) -> VecDeque<Vec<u8>> {
        self.packets
            .into_iter()
            .map(|packet| packet.packet)
            .collect()
    }

    pub(crate) fn into_fresh_packets(
        self,
        now_ms: u64,
        max_age_ms: u64,
    ) -> (VecDeque<PendingTunPacket>, usize) {
        let mut fresh = VecDeque::with_capacity(self.packets.len());
        let mut stale = 0usize;
        for packet in self.packets {
            if packet.is_stale(now_ms, max_age_ms) {
                stale = stale.saturating_add(1);
            } else {
                fresh.push_back(packet);
            }
        }
        (fresh, stale)
    }

    fn append_packets(&mut self, packets: &mut VecDeque<PendingTunPacket>) {
        self.packets.append(packets);
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

        let admission = self.tun_packets.entry(dest_addr).or_default().push_bounded(
            packet,
            crate::time::now_ms(),
            packets_per_dest,
        );
        self.pending_destinations.insert(dest_addr);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest: admission.dropped_oldest(),
        }
    }

    pub(crate) fn push_endpoint_data_with_enqueued_at_ms(
        &mut self,
        dest_addr: NodeAddr,
        payload: impl Into<EndpointDataPayload>,
        max_destinations: usize,
        packets_per_dest: usize,
        enqueued_at_ms: u64,
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
            .push_bounded(payload.into(), enqueued_at_ms, packets_per_dest);
        self.pending_destinations.insert(dest_addr);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest: admission.dropped_oldest(),
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

    pub(crate) fn restore_tun_packets(
        &mut self,
        dest_addr: NodeAddr,
        mut packets: VecDeque<PendingTunPacket>,
    ) {
        if packets.is_empty() {
            return;
        }
        self.tun_packets
            .entry(dest_addr)
            .or_default()
            .append_packets(&mut packets);
        self.pending_destinations.insert(dest_addr);
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

    pub(crate) fn restore_endpoint_data(
        &mut self,
        dest_addr: NodeAddr,
        mut payloads: VecDeque<PendingEndpointData>,
    ) {
        if payloads.is_empty() {
            return;
        }
        self.endpoint_data
            .entry(dest_addr)
            .or_default()
            .append_payloads(&mut payloads);
        self.pending_destinations.insert(dest_addr);
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
