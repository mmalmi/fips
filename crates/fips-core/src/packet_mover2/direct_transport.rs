const DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC: [u8; 4] = *b"DFP1";
const DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN: usize = 20;
const DIRECT_FSP_TRANSPORT_REASSEMBLY_TTL_MS: u64 = 2_000;
const DIRECT_FSP_TRANSPORT_MAX_REASSEMBLY_RECORDS: usize = 64;
const DIRECT_FSP_TRANSPORT_MAX_REASSEMBLED_LEN: usize = 72 * 1024;
const DIRECT_FSP_TRANSPORT_MAX_FRAGMENTS: usize = 128;

#[derive(Debug)]
enum PacketMover2DirectFspTransportOutput {
    Whole(PacketOutput),
    Segments(Vec<PacketOutput>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PacketMover2DirectFspTransportSegmentation {
    max_fragment_payload: usize,
    fragment_count: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PacketMover2DirectFspFragmentKey {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    record_id: u64,
}

#[derive(Debug)]
struct PacketMover2DirectFspReassembly {
    created_at_ms: u64,
    total_len: usize,
    received_bytes: usize,
    received_count: usize,
    fragments: Vec<Option<PacketBuffer>>,
}

impl PacketMover2DirectFspReassembly {
    fn new(total_len: usize, fragment_count: usize, created_at_ms: u64) -> Self {
        Self {
            created_at_ms,
            total_len,
            received_bytes: 0,
            received_count: 0,
            fragments: vec![None; fragment_count],
        }
    }

    fn matches(&self, total_len: usize, fragment_count: usize) -> bool {
        self.total_len == total_len && self.fragments.len() == fragment_count
    }

    fn insert(&mut self, index: usize, payload: PacketBuffer) -> bool {
        let Some(slot) = self.fragments.get_mut(index) else {
            return false;
        };
        if slot.is_some() {
            return true;
        }
        if payload.is_empty()
            || self.received_bytes.saturating_add(payload.len()) > self.total_len
        {
            return false;
        }
        self.received_bytes = self.received_bytes.saturating_add(payload.len());
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
            payload.extend_from_slice(fragment?.as_slice());
        }
        (payload.len() == self.total_len).then_some(payload.into())
    }
}

#[derive(Debug, Default)]
pub(crate) struct PacketMover2DirectFspReassembler {
    entries: HashMap<PacketMover2DirectFspFragmentKey, PacketMover2DirectFspReassembly>,
}

#[derive(Debug)]
enum PacketMover2DirectFspReassemblyResult {
    NotFragment(ReceivedPacket),
    Pending,
    Complete(ReceivedPacket),
    Dropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PacketMover2DirectFspFragmentHeader {
    record_id: u64,
    total_len: usize,
    fragment_index: usize,
    fragment_count: usize,
}

impl PacketMover2DirectFspReassembler {
    fn ingest(&mut self, mut packet: ReceivedPacket) -> PacketMover2DirectFspReassemblyResult {
        let Some(header) = parse_direct_fsp_transport_fragment_header(packet.data.as_slice()) else {
            return PacketMover2DirectFspReassemblyResult::NotFragment(packet);
        };
        if !valid_direct_fsp_transport_fragment_header(header) {
            return PacketMover2DirectFspReassemblyResult::Dropped;
        }
        self.prune(packet.timestamp_ms);
        if self.entries.len() >= DIRECT_FSP_TRANSPORT_MAX_REASSEMBLY_RECORDS {
            self.remove_oldest();
        }

        let key = PacketMover2DirectFspFragmentKey {
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            record_id: header.record_id,
        };
        let mut fragment_payload = std::mem::take(&mut packet.data);
        fragment_payload.drain(..DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN);
        let entry = self.entries.entry(key.clone()).or_insert_with(|| {
            PacketMover2DirectFspReassembly::new(
                header.total_len,
                header.fragment_count,
                packet.timestamp_ms,
            )
        });
        if !entry.matches(header.total_len, header.fragment_count) {
            *entry = PacketMover2DirectFspReassembly::new(
                header.total_len,
                header.fragment_count,
                packet.timestamp_ms,
            );
        }
        if !entry.insert(header.fragment_index, fragment_payload) {
            self.entries.remove(&key);
            return PacketMover2DirectFspReassemblyResult::Dropped;
        }
        if !entry.is_complete() {
            return PacketMover2DirectFspReassemblyResult::Pending;
        }

        let Some(entry) = self.entries.remove(&key) else {
            return PacketMover2DirectFspReassemblyResult::Dropped;
        };
        let Some(payload) = entry.into_payload() else {
            return PacketMover2DirectFspReassemblyResult::Dropped;
        };
        packet.data = payload;
        PacketMover2DirectFspReassemblyResult::Complete(packet)
    }

    fn prune(&mut self, now_ms: u64) {
        self.entries.retain(|_, entry| {
            now_ms.saturating_sub(entry.created_at_ms) <= DIRECT_FSP_TRANSPORT_REASSEMBLY_TTL_MS
        });
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

fn packet_mover2_direct_fsp_transport_fragment_is_fragment(data: &[u8]) -> bool {
    data.len() >= DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC.len()
        && data[..DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC.len()]
            == DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC
}

fn parse_direct_fsp_transport_fragment_header(
    data: &[u8],
) -> Option<PacketMover2DirectFspFragmentHeader> {
    if !packet_mover2_direct_fsp_transport_fragment_is_fragment(data)
        || data.len() < DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN
    {
        return None;
    }
    let record_id = u64::from_le_bytes(data[4..12].try_into().ok()?);
    let total_len = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
    let fragment_index = u16::from_le_bytes(data[16..18].try_into().ok()?) as usize;
    let fragment_count = u16::from_le_bytes(data[18..20].try_into().ok()?) as usize;
    Some(PacketMover2DirectFspFragmentHeader {
        record_id,
        total_len,
        fragment_index,
        fragment_count,
    })
}

fn valid_direct_fsp_transport_fragment_header(
    header: PacketMover2DirectFspFragmentHeader,
) -> bool {
    header.total_len > 0
        && header.total_len <= DIRECT_FSP_TRANSPORT_MAX_REASSEMBLED_LEN
        && header.fragment_count > 1
        && header.fragment_count <= DIRECT_FSP_TRANSPORT_MAX_FRAGMENTS
        && header.fragment_count <= header.total_len
        && header.fragment_index < header.fragment_count
}

fn packet_mover2_direct_fsp_transport_output(
    output: PacketOutput,
) -> Result<PacketMover2DirectFspTransportOutput, PacketOutput> {
    let segmentation = match packet_mover2_direct_fsp_transport_segmentation(&output) {
        Ok(Some(segmentation)) => segmentation,
        Ok(None) => return Ok(PacketMover2DirectFspTransportOutput::Whole(output)),
        Err(()) => return Err(output),
    };
    let header = match packet_mover2_direct_fsp_transport_header(&output) {
        Some(header) => header,
        None => return Ok(PacketMover2DirectFspTransportOutput::Whole(output)),
    };

    let mut segments = Vec::with_capacity(segmentation.fragment_count);
    for fragment_index in 0..segmentation.fragment_count {
        let start = fragment_index * segmentation.max_fragment_payload;
        let end = start
            .saturating_add(segmentation.max_fragment_payload)
            .min(output.payload_len());
        let mut segment =
            Vec::with_capacity(DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN + end - start);
        segment.extend_from_slice(&DIRECT_FSP_TRANSPORT_FRAGMENT_MAGIC);
        segment.extend_from_slice(&header.counter().to_le_bytes());
        segment.extend_from_slice(&(output.payload_len() as u32).to_le_bytes());
        segment.extend_from_slice(&(fragment_index as u16).to_le_bytes());
        segment.extend_from_slice(&(segmentation.fragment_count as u16).to_le_bytes());
        segment.extend_from_slice(&output.payload()[start..end]);
        segments.push(packet_output_with_payload(&output, segment.into()));
    }
    Ok(PacketMover2DirectFspTransportOutput::Segments(segments))
}

fn packet_mover2_direct_fsp_transport_max_datagram_len(
    output: &PacketOutput,
) -> Result<Option<usize>, ()> {
    let Some(segmentation) = packet_mover2_direct_fsp_transport_segmentation(output)? else {
        return Ok(None);
    };
    Ok(Some(
        DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN + segmentation.max_fragment_payload,
    ))
}

fn packet_mover2_direct_fsp_transport_segmentation(
    output: &PacketOutput,
) -> Result<Option<PacketMover2DirectFspTransportSegmentation>, ()> {
    if packet_mover2_direct_fsp_transport_header(output).is_none() {
        return Ok(None);
    }
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
    Ok(Some(PacketMover2DirectFspTransportSegmentation {
        max_fragment_payload,
        fragment_count,
    }))
}

fn packet_mover2_direct_fsp_transport_header(output: &PacketOutput) -> Option<FspWireHeader> {
    if output.owner().protocol() != PacketProtocol::Fsp
        || output.target() != OutputTarget::Transport
    {
        return None;
    }
    let header = FspWireHeader::parse(output.payload()).ok()?;
    (header.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT != 0)
        .then_some(header)
}

fn packet_output_with_payload(template: &PacketOutput, payload: PacketBuffer) -> PacketOutput {
    PacketOutput {
        owner: template.owner,
        counter: template.counter,
        ingress_seq: template.ingress_seq,
        lane: template.lane,
        target: template.target,
        source_path: template.source_path.clone(),
        previous_hop: template.previous_hop,
        ce_flag: template.ce_flag,
        path_mtu: template.path_mtu,
        source_peer: template.source_peer,
        path: template.path.clone(),
        activity_tick: template.activity_tick,
        fmp_timestamp_ms: template.fmp_timestamp_ms,
        source_wire_len: template.source_wire_len,
        fsp_send_receipt: template.fsp_send_receipt,
        payload,
    }
}
