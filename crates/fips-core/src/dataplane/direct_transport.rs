const DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC: [u8; 4] = *b"DFP1";
const DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN: usize = 20;
const DIRECT_FSP_TRANSPORT_REASSEMBLY_TTL_MS: u64 = 2_000;
const DIRECT_FSP_TRANSPORT_REASSEMBLY_PRUNE_INTERVAL_MS: u64 =
    DIRECT_FSP_TRANSPORT_REASSEMBLY_TTL_MS / 4;
const DIRECT_FSP_TRANSPORT_MAX_REASSEMBLY_RECORDS: usize = 512;
const DIRECT_FSP_TRANSPORT_MAX_REASSEMBLED_LEN: usize = 72 * 1024;
const DIRECT_FSP_TRANSPORT_MAX_FRAGMENTS: usize = 128;

#[derive(Debug)]
enum DataplaneDirectFspTransportOutput {
    Whole(PacketOutput),
    Segments(DataplaneDirectFspTransportSegments),
    MtuExceeded(PacketOutput),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DataplaneDirectFspTransportSegmentation {
    header: FspWireHeader,
    max_fragment_payload: usize,
    fragment_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneDirectFspTransportSegment {
    header: [u8; DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN],
    payload_range: std::ops::Range<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneDirectFspTransportSegments {
    output: PacketOutput,
    segments: Vec<DataplaneDirectFspTransportSegment>,
}

impl DataplaneDirectFspTransportSegments {
    fn len(&self) -> usize {
        self.segments.len()
    }

    fn payload_len(&self, index: usize) -> usize {
        let segment = &self.segments[index];
        DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN + segment.payload_range.len()
    }

    fn payload_slices<'a>(
        &'a self,
        index: usize,
        out: &mut [Option<&'a [u8]>; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES],
    ) -> usize {
        out.fill(None);
        let segment = &self.segments[index];
        out[0] = Some(segment.header.as_slice());
        out[1] = Some(&self.output.payload()[segment.payload_range.clone()]);
        2
    }

    fn contiguous_payload(&self, index: usize) -> Vec<u8> {
        let segment = &self.segments[index];
        let mut payload = Vec::with_capacity(self.payload_len(index));
        payload.extend_from_slice(&segment.header);
        payload.extend_from_slice(&self.output.payload()[segment.payload_range.clone()]);
        payload
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DataplaneDirectFspFragmentKey {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    record_id: u64,
}

#[derive(Debug)]
struct DataplaneDirectFspFragmentPayload {
    buffer: PacketBuffer,
    range: std::ops::Range<usize>,
}

#[derive(Debug)]
struct DataplaneDirectFspReassembly {
    created_at_ms: u64,
    total_len: usize,
    received_bytes: usize,
    received_count: usize,
    fragments: Vec<Option<DataplaneDirectFspFragmentPayload>>,
}

impl DataplaneDirectFspReassembly {
    fn new(total_len: usize, fragment_count: usize, created_at_ms: u64) -> Self {
        Self {
            created_at_ms,
            total_len,
            received_bytes: 0,
            received_count: 0,
            fragments: (0..fragment_count).map(|_| None).collect(),
        }
    }

    fn matches(&self, total_len: usize, fragment_count: usize) -> bool {
        self.total_len == total_len && self.fragments.len() == fragment_count
    }

    fn insert(&mut self, index: usize, payload: DataplaneDirectFspFragmentPayload) -> bool {
        let Some(slot) = self.fragments.get_mut(index) else {
            return false;
        };
        if slot.is_some() {
            return true;
        }
        let payload_len = payload.range.len();
        if self.received_bytes.saturating_add(payload_len) > self.total_len {
            return false;
        }
        self.received_bytes = self.received_bytes.saturating_add(payload_len);
        self.received_count = self.received_count.saturating_add(1);
        *slot = Some(payload);
        true
    }

    fn is_complete(&self) -> bool {
        self.received_count == self.fragments.len() && self.received_bytes == self.total_len
    }

    fn into_payload(self) -> Option<PacketBuffer> {
        if !self.is_complete() {
            return None;
        }
        let mut payload = Vec::with_capacity(self.total_len);
        for fragment in self.fragments {
            let DataplaneDirectFspFragmentPayload { buffer, range } = fragment?;
            payload.extend_from_slice(&buffer.as_slice()[range]);
        }
        (payload.len() == self.total_len).then_some(PacketBuffer::new(payload))
    }
}

#[derive(Debug, Default)]
pub(crate) struct DataplaneDirectFspReassembler {
    entries: HashMap<DataplaneDirectFspFragmentKey, DataplaneDirectFspReassembly>,
    next_prune_at_ms: u64,
}

#[derive(Debug)]
enum DataplaneDirectFspReassemblyResult {
    Pending,
    Complete(ReceivedPacket),
    Dropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DataplaneDirectFspFragmentHeader {
    record_id: u64,
    total_len: usize,
    fragment_index: usize,
    fragment_count: usize,
}

impl DataplaneDirectFspReassembler {
    fn ingest_fragment(&mut self, mut packet: ReceivedPacket) -> DataplaneDirectFspReassemblyResult {
        debug_assert!(dataplane_direct_fsp_transport_fragment_is_fragment(
            packet.data.as_slice()
        ));
        let Some(header) =
            parse_direct_fsp_transport_fragment_header_after_magic(packet.data.as_slice())
        else {
            return DataplaneDirectFspReassemblyResult::Dropped;
        };
        if !valid_direct_fsp_transport_fragment_header(header) {
            return DataplaneDirectFspReassemblyResult::Dropped;
        }
        let key = DataplaneDirectFspFragmentKey {
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            record_id: header.record_id,
        };
        self.prune_expired_if_due(packet.timestamp_ms);
        self.remove_expired_entry(&key, packet.timestamp_ms);

        let fragment_payload_len = packet
            .data
            .len()
            .saturating_sub(DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN);
        if fragment_payload_len == 0 {
            return DataplaneDirectFspReassemblyResult::Dropped;
        }
        let fragment_payload_range = DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN
            ..DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN + fragment_payload_len;
        let fragment_payload = DataplaneDirectFspFragmentPayload {
            buffer: std::mem::take(&mut packet.data),
            range: fragment_payload_range,
        };
        if !self.entries.contains_key(&key) {
            self.reserve_capacity_for_new_record(packet.timestamp_ms);
        }
        let entry = self.entries.entry(key.clone()).or_insert_with(|| {
            DataplaneDirectFspReassembly::new(
                header.total_len,
                header.fragment_count,
                packet.timestamp_ms,
            )
        });
        if !entry.matches(header.total_len, header.fragment_count) {
            *entry = DataplaneDirectFspReassembly::new(
                header.total_len,
                header.fragment_count,
                packet.timestamp_ms,
            );
        }
        if !entry.insert(header.fragment_index, fragment_payload) {
            self.entries.remove(&key);
            return DataplaneDirectFspReassemblyResult::Dropped;
        }
        if !entry.is_complete() {
            return DataplaneDirectFspReassemblyResult::Pending;
        }

        let Some(entry) = self.entries.remove(&key) else {
            return DataplaneDirectFspReassemblyResult::Dropped;
        };
        let Some(payload) = entry.into_payload() else {
            return DataplaneDirectFspReassemblyResult::Dropped;
        };
        packet.data = payload;
        DataplaneDirectFspReassemblyResult::Complete(packet)
    }

    fn prune_expired_if_due(&mut self, now_ms: u64) {
        if self.entries.is_empty() {
            self.schedule_next_prune(now_ms);
            return;
        }
        if now_ms < self.next_prune_at_ms {
            return;
        }
        self.prune_expired(now_ms);
        self.schedule_next_prune(now_ms);
    }

    fn reserve_capacity_for_new_record(&mut self, now_ms: u64) {
        if self.entries.len() < DIRECT_FSP_TRANSPORT_MAX_REASSEMBLY_RECORDS {
            return;
        }
        self.prune_expired(now_ms);
        self.schedule_next_prune(now_ms);
        if self.entries.len() >= DIRECT_FSP_TRANSPORT_MAX_REASSEMBLY_RECORDS {
            self.remove_oldest();
        }
    }

    fn remove_expired_entry(&mut self, key: &DataplaneDirectFspFragmentKey, now_ms: u64) {
        if self
            .entries
            .get(key)
            .is_some_and(|entry| Self::entry_is_expired(entry, now_ms))
        {
            self.entries.remove(key);
        }
    }

    fn prune_expired(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, entry| !Self::entry_is_expired(entry, now_ms));
    }

    fn entry_is_expired(entry: &DataplaneDirectFspReassembly, now_ms: u64) -> bool {
        now_ms.saturating_sub(entry.created_at_ms) > DIRECT_FSP_TRANSPORT_REASSEMBLY_TTL_MS
    }

    fn schedule_next_prune(&mut self, now_ms: u64) {
        self.next_prune_at_ms =
            now_ms.saturating_add(DIRECT_FSP_TRANSPORT_REASSEMBLY_PRUNE_INTERVAL_MS);
    }

    fn remove_oldest(&mut self) {
        let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.created_at_ms)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        self.entries.remove(&oldest);
    }
}

fn dataplane_direct_fsp_transport_fragment_is_fragment(data: &[u8]) -> bool {
    data.len() >= DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC.len()
        && data[..DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC.len()]
            == DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC
}

#[cfg(test)]
fn parse_direct_fsp_transport_fragment_header(
    data: &[u8],
) -> Option<DataplaneDirectFspFragmentHeader> {
    if !dataplane_direct_fsp_transport_fragment_is_fragment(data)
    {
        return None;
    }
    parse_direct_fsp_transport_fragment_header_after_magic(data)
}

fn parse_direct_fsp_transport_fragment_header_after_magic(
    data: &[u8],
) -> Option<DataplaneDirectFspFragmentHeader> {
    if data.len() < DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN {
        return None;
    }
    let record_id = u64::from_le_bytes(data[4..12].try_into().ok()?);
    let total_len = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
    let fragment_index = u16::from_le_bytes(data[16..18].try_into().ok()?) as usize;
    let fragment_count = u16::from_le_bytes(data[18..20].try_into().ok()?) as usize;
    Some(DataplaneDirectFspFragmentHeader {
        record_id,
        total_len,
        fragment_index,
        fragment_count,
    })
}

fn valid_direct_fsp_transport_fragment_header(
    header: DataplaneDirectFspFragmentHeader,
) -> bool {
    header.total_len > 0
        && header.total_len <= DIRECT_FSP_TRANSPORT_MAX_REASSEMBLED_LEN
        && header.fragment_count > 1
        && header.fragment_count <= DIRECT_FSP_TRANSPORT_MAX_FRAGMENTS
        && header.fragment_count <= header.total_len
        && header.fragment_index < header.fragment_count
}

fn dataplane_direct_fsp_transport_output(
    output: PacketOutput,
) -> DataplaneDirectFspTransportOutput {
    let segmentation = match dataplane_direct_fsp_transport_segmentation(&output) {
        Ok(Some(segmentation)) => segmentation,
        Ok(None) => return DataplaneDirectFspTransportOutput::Whole(output),
        Err(()) => return DataplaneDirectFspTransportOutput::MtuExceeded(output),
    };
    let mut segments = Vec::with_capacity(segmentation.fragment_count);
    for fragment_index in 0..segmentation.fragment_count {
        let start = fragment_index * segmentation.max_fragment_payload;
        let end = start
            .saturating_add(segmentation.max_fragment_payload)
            .min(output.payload_len());
        let mut segment_header = [0u8; DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN];
        segment_header[..4].copy_from_slice(&DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC);
        segment_header[4..12].copy_from_slice(&segmentation.header.counter().to_le_bytes());
        segment_header[12..16].copy_from_slice(&(output.payload_len() as u32).to_le_bytes());
        segment_header[16..18].copy_from_slice(&(fragment_index as u16).to_le_bytes());
        segment_header[18..20].copy_from_slice(&(segmentation.fragment_count as u16).to_le_bytes());
        segments.push(DataplaneDirectFspTransportSegment {
            header: segment_header,
            payload_range: start..end,
        });
    }
    DataplaneDirectFspTransportOutput::Segments(DataplaneDirectFspTransportSegments {
        output,
        segments,
    })
}

fn dataplane_direct_fsp_transport_segmentation(
    output: &PacketOutput,
) -> Result<Option<DataplaneDirectFspTransportSegmentation>, ()> {
    let Some(header) = dataplane_direct_fsp_transport_header(output) else {
        return Ok(None);
    };
    let path_mtu = output.path_mtu() as usize;
    if output.payload_len() <= path_mtu {
        return Ok(None);
    }
    if output.payload_len() > DIRECT_FSP_TRANSPORT_MAX_REASSEMBLED_LEN {
        return Err(());
    }
    let max_fragment_payload = path_mtu
        .checked_sub(DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN)
        .filter(|len| *len > 0)
        .ok_or(())?;
    let fragment_count = output.payload_len().div_ceil(max_fragment_payload);
    if fragment_count <= 1
        || fragment_count > u16::MAX as usize
        || fragment_count > DIRECT_FSP_TRANSPORT_MAX_FRAGMENTS
    {
        return Err(());
    }
    Ok(Some(DataplaneDirectFspTransportSegmentation {
        header,
        max_fragment_payload,
        fragment_count,
    }))
}

fn dataplane_direct_fsp_transport_header(output: &PacketOutput) -> Option<FspWireHeader> {
    if output.owner().protocol() != PacketProtocol::Fsp
        || output.target() != OutputTarget::Transport
    {
        return None;
    }
    let header = FspWireHeader::parse(output.payload()).ok()?;
    (header.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT != 0)
        .then_some(header)
}
