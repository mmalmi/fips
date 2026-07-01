use super::*;

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

/// Per-destination endpoint data batch waiting for session establishment.
#[derive(Debug)]
pub(crate) struct PendingEndpointData {
    payloads: Vec<Vec<u8>>,
    enqueued_at_ms: u64,
}

impl PendingEndpointData {
    pub(crate) fn new_batch(payloads: Vec<Vec<u8>>, enqueued_at_ms: u64) -> Option<Self> {
        if payloads.is_empty() {
            return None;
        }
        Some(Self {
            payloads,
            enqueued_at_ms,
        })
    }

    fn packet_count(&self) -> usize {
        self.payloads.len()
    }

    pub(crate) fn enqueued_at_ms(&self) -> u64 {
        self.enqueued_at_ms
    }

    pub(crate) fn into_payloads(self) -> Vec<Vec<u8>> {
        self.payloads
    }
}

/// Per-destination endpoint payloads waiting for session establishment.
#[derive(Debug, Default)]
pub(crate) struct PendingEndpointDataQueue {
    batches: VecDeque<PendingEndpointData>,
    packet_count: usize,
}

impl PendingEndpointDataQueue {
    pub(crate) fn push_batch_bounded(
        &mut self,
        mut payloads: Vec<Vec<u8>>,
        enqueued_at_ms: u64,
        capacity: usize,
    ) -> bool {
        if payloads.is_empty() {
            return false;
        }

        let capacity = capacity.max(1);
        let mut dropped_oldest = false;
        if payloads.len() > capacity {
            let drop_from_new = payloads.len().saturating_sub(capacity);
            payloads.drain(..drop_from_new);
            self.batches.clear();
            self.packet_count = 0;
            dropped_oldest = true;
        } else {
            let required_room = self
                .packet_count
                .saturating_add(payloads.len())
                .saturating_sub(capacity);
            if required_room > 0 {
                self.drop_oldest_packets(required_room);
                dropped_oldest = true;
            }
        }

        let packet_count = payloads.len();
        if let Some(batch) = PendingEndpointData::new_batch(payloads, enqueued_at_ms) {
            self.packet_count = self.packet_count.saturating_add(packet_count);
            self.batches.push_back(batch);
        }
        dropped_oldest
    }

    fn drop_oldest_packets(&mut self, mut count: usize) {
        while count > 0 {
            let Some(front) = self.batches.front_mut() else {
                self.packet_count = 0;
                return;
            };
            let front_count = front.packet_count();
            if front_count <= count {
                count -= front_count;
                self.packet_count = self.packet_count.saturating_sub(front_count);
                self.batches.pop_front();
            } else {
                front.payloads.drain(..count);
                self.packet_count = self.packet_count.saturating_sub(count);
                count = 0;
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.packet_count
    }

    pub(crate) fn into_pending_payloads(self) -> VecDeque<PendingEndpointData> {
        self.batches
    }

    fn append_payloads(&mut self, payloads: &mut VecDeque<PendingEndpointData>) {
        let appended_count = payloads
            .iter()
            .map(PendingEndpointData::packet_count)
            .sum::<usize>();
        self.packet_count = self.packet_count.saturating_add(appended_count);
        self.batches.append(payloads);
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
    ) -> bool {
        let dropped_oldest = self.packets.len() >= capacity;
        if dropped_oldest {
            self.packets.pop_front();
        }
        self.packets
            .push_back(PendingTunPacket::new(packet, queued_at_ms));
        dropped_oldest
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

        let dropped_oldest = self.tun_packets.entry(dest_addr).or_default().push_bounded(
            packet,
            crate::time::now_ms(),
            packets_per_dest,
        );
        self.pending_destinations.insert(dest_addr);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest,
        }
    }

    pub(crate) fn push_endpoint_data_batch_with_enqueued_at_ms(
        &mut self,
        dest_addr: NodeAddr,
        payloads: Vec<Vec<u8>>,
        max_destinations: usize,
        packets_per_dest: usize,
        enqueued_at_ms: u64,
    ) -> PendingSessionTrafficAdmission {
        if payloads.is_empty() {
            return PendingSessionTrafficAdmission {
                destination_dropped: false,
                dropped_oldest: false,
            };
        }
        if !self.endpoint_data.contains_key(&dest_addr)
            && self.endpoint_data.len() >= max_destinations
        {
            return PendingSessionTrafficAdmission {
                destination_dropped: true,
                dropped_oldest: false,
            };
        }

        let dropped_oldest = self
            .endpoint_data
            .entry(dest_addr)
            .or_default()
            .push_batch_bounded(payloads, enqueued_at_ms, packets_per_dest);
        self.pending_destinations.insert(dest_addr);
        PendingSessionTrafficAdmission {
            destination_dropped: false,
            dropped_oldest,
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
