#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketMover2RuntimeSummary {
    raw_ingress_dropped: usize,
    inbound_admitted: usize,
    inbound_dropped: usize,
    outbound_admitted: usize,
    outbound_dropped: usize,
    completions: usize,
    dispatched: usize,
    outputs: usize,
    outputs_sent: usize,
    outputs_dropped: usize,
    drops: usize,
}

impl PacketMover2RuntimeSummary {
    pub(crate) fn raw_ingress_dropped(self) -> usize {
        self.raw_ingress_dropped
    }

    pub(crate) fn inbound_admitted(self) -> usize {
        self.inbound_admitted
    }

    pub(crate) fn inbound_dropped(self) -> usize {
        self.inbound_dropped
    }

    pub(crate) fn outbound_admitted(self) -> usize {
        self.outbound_admitted
    }

    pub(crate) fn outbound_dropped(self) -> usize {
        self.outbound_dropped
    }

    pub(crate) fn completions(self) -> usize {
        self.completions
    }

    pub(crate) fn dispatched(self) -> usize {
        self.dispatched
    }

    pub(crate) fn outputs(self) -> usize {
        self.outputs
    }

    pub(crate) fn outputs_sent(self) -> usize {
        self.outputs_sent
    }

    pub(crate) fn outputs_dropped(self) -> usize {
        self.outputs_dropped
    }

    pub(crate) fn drops(self) -> usize {
        self.drops
    }

    pub(crate) fn has_activity(self) -> bool {
        self.raw_ingress_dropped > 0
            || self.inbound_admitted > 0
            || self.inbound_dropped > 0
            || self.outbound_admitted > 0
            || self.outbound_dropped > 0
            || self.completions > 0
            || self.dispatched > 0
            || self.outputs > 0
            || self.outputs_sent > 0
            || self.outputs_dropped > 0
            || self.drops > 0
    }

    pub(crate) fn has_failures(self) -> bool {
        self.raw_ingress_dropped > 0
            || self.inbound_dropped > 0
            || self.outbound_dropped > 0
            || self.outputs_dropped > 0
            || self.drops > 0
    }

    fn absorb(&mut self, other: Self) {
        self.raw_ingress_dropped = self
            .raw_ingress_dropped
            .saturating_add(other.raw_ingress_dropped);
        self.inbound_admitted = self.inbound_admitted.saturating_add(other.inbound_admitted);
        self.inbound_dropped = self.inbound_dropped.saturating_add(other.inbound_dropped);
        self.outbound_admitted = self
            .outbound_admitted
            .saturating_add(other.outbound_admitted);
        self.outbound_dropped = self
            .outbound_dropped
            .saturating_add(other.outbound_dropped);
        self.completions = self.completions.saturating_add(other.completions);
        self.dispatched = self.dispatched.saturating_add(other.dispatched);
        self.outputs = self.outputs.saturating_add(other.outputs);
        self.outputs_sent = self.outputs_sent.saturating_add(other.outputs_sent);
        self.outputs_dropped = self.outputs_dropped.saturating_add(other.outputs_dropped);
        self.drops = self.drops.saturating_add(other.drops);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2RuntimeTurn<'a> {
    summary: PacketMover2RuntimeSummary,
    raw_ingress_drops: &'a [PacketMover2RawIngressDrop],
    output_drops: &'a [PacketMover2OutputDrop],
    outputs: &'a [PacketOutput],
    drops: &'a [PacketDrop],
}

impl PacketMover2RuntimeTurn<'_> {
    pub(crate) fn summary(&self) -> PacketMover2RuntimeSummary {
        self.summary
    }

    pub(crate) fn raw_ingress_drops(&self) -> &[PacketMover2RawIngressDrop] {
        self.raw_ingress_drops
    }

    pub(crate) fn output_drops(&self) -> &[PacketMover2OutputDrop] {
        self.output_drops
    }

    pub(crate) fn outputs(&self) -> &[PacketOutput] {
        self.outputs
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        self.drops
    }
}

fn reserved_live_outbound_progress_limit(
    endpoint_limit: usize,
    tun_limit: usize,
    outbound_limit: usize,
) -> usize {
    if outbound_limit == 0 {
        return 0;
    }
    let endpoint_reserve = usize::from(endpoint_limit > 0);
    let tun_reserve = usize::from(tun_limit > 0);
    outbound_limit.min(endpoint_reserve.saturating_add(tun_reserve))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FmpIngressReceipt {
    source_addr: NodeAddr,
    source_peer: crate::PeerIdentity,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_timestamp_ms: u64,
    packet_len: usize,
    fmp_counter: u64,
    fmp_flags: u8,
    inner_timestamp_ms: u32,
}

impl PacketMover2FmpIngressReceipt {
    fn from_output(output: &PacketOutput) -> Option<Self> {
        if output.owner().protocol() != PacketProtocol::Fmp {
            return None;
        }
        let source_addr = output.owner().node_addr();
        let source_peer = output.source_peer()?;
        if source_peer.node_addr() != &source_addr {
            return None;
        }
        let Some(TransportPath::Live {
            transport_id,
            remote_addr,
        }) = output.source_path()
        else {
            return None;
        };
        let packet_timestamp_ms = output.activity_tick?.get();
        let packet_len = output.source_wire_len()?;
        let header = FmpWireHeader::parse(output.payload()).ok()?;
        let plaintext = output.opened_payload()?;
        if plaintext.len() < 4 {
            return None;
        }
        let inner_timestamp_ms =
            u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        Some(Self {
            source_addr,
            source_peer,
            transport_id: *transport_id,
            remote_addr: remote_addr.clone(),
            packet_timestamp_ms,
            packet_len,
            fmp_counter: header.counter(),
            fmp_flags: header.flags(),
            inner_timestamp_ms,
        })
    }

    pub(crate) fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    pub(crate) fn source_peer(&self) -> crate::PeerIdentity {
        self.source_peer
    }

    pub(crate) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    pub(crate) fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    pub(crate) fn packet_timestamp_ms(&self) -> u64 {
        self.packet_timestamp_ms
    }

    pub(crate) fn packet_len(&self) -> usize {
        self.packet_len
    }

    pub(crate) fn fmp_counter(&self) -> u64 {
        self.fmp_counter
    }

    pub(crate) fn inner_timestamp_ms(&self) -> u32 {
        self.inner_timestamp_ms
    }

    pub(crate) fn fmp_flags(&self) -> u8 {
        self.fmp_flags
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FmpLinkIngress {
    receipt: PacketMover2FmpIngressReceipt,
    output: PacketOutput,
    msg_type: Option<u8>,
}

impl PacketMover2FmpLinkIngress {
    fn from_output(output: PacketOutput) -> Result<Self, PacketOutput> {
        let Some(plaintext) = output.opened_payload() else {
            return Err(output);
        };
        let Some(receipt) = PacketMover2FmpIngressReceipt::from_output(&output) else {
            return Err(output);
        };
        let msg_type = plaintext.get(4).copied();
        Ok(Self {
            receipt,
            output,
            msg_type,
        })
    }

    pub(crate) fn receipt(&self) -> &PacketMover2FmpIngressReceipt {
        &self.receipt
    }

    pub(crate) fn msg_type(&self) -> Option<u8> {
        self.msg_type
    }

    pub(crate) fn payload(&self) -> &[u8] {
        let plaintext = self
            .output
            .opened_payload()
            .expect("link ingress is constructed only from opened FMP output");
        if self.msg_type.is_some() {
            &plaintext[5..]
        } else {
            &[]
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspCoordWarmup {
    source: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
    local: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
}

impl PacketMover2FspCoordWarmup {
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

    pub(crate) fn source(&self) -> Option<(NodeAddr, &crate::tree::TreeCoordinate)> {
        self.source.as_ref().map(|(addr, coords)| (*addr, coords))
    }

    pub(crate) fn local(&self) -> Option<(NodeAddr, &crate::tree::TreeCoordinate)> {
        self.local.as_ref().map(|(addr, coords)| (*addr, coords))
    }

    pub(crate) fn apply_to(self, coord_cache: &mut crate::cache::CoordCache, now_ms: u64) {
        if let Some((addr, coords)) = self.source {
            coord_cache.insert(addr, coords, now_ms);
        }
        if let Some((addr, coords)) = self.local {
            coord_cache.insert(addr, coords, now_ms);
        }
    }
}

impl Default for PacketMover2FspCoordWarmup {
    fn default() -> Self {
        Self {
            source: None,
            local: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspLocalSessionIngress {
    source_addr: NodeAddr,
    previous_hop_addr: NodeAddr,
    ce_flag: bool,
    path_mtu: u16,
    payload: PacketBuffer,
}

impl PacketMover2FspLocalSessionIngress {
    fn new(
        source_addr: NodeAddr,
        previous_hop_addr: NodeAddr,
        ce_flag: bool,
        path_mtu: u16,
        payload: PacketBuffer,
    ) -> Self {
        Self {
            source_addr,
            previous_hop_addr,
            ce_flag,
            path_mtu,
            payload,
        }
    }

    pub(crate) fn source_addr(&self) -> NodeAddr {
        self.source_addr
    }

    pub(crate) fn previous_hop_addr(&self) -> NodeAddr {
        self.previous_hop_addr
    }

    pub(crate) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(crate) fn path_mtu(&self) -> u16 {
        self.path_mtu
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn into_parts(self) -> (NodeAddr, NodeAddr, bool, u16, PacketBuffer) {
        (
            self.source_addr,
            self.previous_hop_addr,
            self.ce_flag,
            self.path_mtu,
            self.payload,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspSessionIngress {
    source_addr: NodeAddr,
    source_peer: crate::PeerIdentity,
    previous_hop_addr: NodeAddr,
    ce_flag: bool,
    receive_sync: FspReceiveSync,
    activity_tick: Option<ActivityTick>,
    timestamp_ms: u32,
    msg_type: u8,
    inner_flags: u8,
    plaintext: PacketBuffer,
}

impl PacketMover2FspSessionIngress {
    fn from_output(output: PacketOutput) -> Result<Self, PacketOutput> {
        let source_addr = output.owner().node_addr();
        let Some(source_peer) = output.source_peer() else {
            return Err(output);
        };
        if source_peer.node_addr() != &source_addr {
            return Err(output);
        }
        let previous_hop_addr = output.previous_hop().unwrap_or(source_addr);
        let ce_flag = output.ce_flag();
        let header = match FspWireHeader::parse(output.payload()) {
            Ok(header) => header,
            Err(_) => return Err(output),
        };
        let path_mtu = output.path_mtu();
        let activity_tick = output.activity_tick;
        let (timestamp_ms, msg_type, inner_flags, plaintext_len) = {
            let Some(plaintext) = output.opened_payload() else {
                return Err(output);
            };
            let Some((timestamp_ms, msg_type, inner_flags, _body)) =
                crate::node::session_wire::fsp_strip_inner_header(plaintext)
            else {
                return Err(output);
            };
            (timestamp_ms, msg_type, inner_flags, plaintext.len())
        };
        let receive_sync = FspReceiveSync {
            counter: output.counter(),
            received_k_bit: header.flags() & crate::node::session_wire::FSP_FLAG_K != 0,
            timestamp: timestamp_ms,
            plaintext_len,
            ce_flag,
            path_mtu,
            spin_bit: inner_flags & 0x01 != 0,
        };
        let plaintext = match output.into_opened_payload() {
            Ok(plaintext) => plaintext,
            Err(output) => return Err(output),
        };
        Ok(Self {
            source_addr,
            source_peer,
            previous_hop_addr,
            ce_flag,
            receive_sync,
            activity_tick,
            timestamp_ms,
            msg_type,
            inner_flags,
            plaintext,
        })
    }

    pub(crate) fn source_addr(&self) -> NodeAddr {
        self.source_addr
    }

    pub(crate) fn previous_hop_addr(&self) -> NodeAddr {
        self.previous_hop_addr
    }

    pub(crate) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(crate) fn received_k_bit(&self) -> bool {
        self.receive_sync.received_k_bit
    }

    pub(crate) fn timestamp_ms(&self) -> u32 {
        self.timestamp_ms
    }

    pub(crate) fn activity_tick(&self) -> Option<ActivityTick> {
        self.activity_tick
    }

    pub(crate) fn msg_type(&self) -> u8 {
        self.msg_type
    }

    pub(crate) fn inner_flags(&self) -> u8 {
        self.inner_flags
    }

    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        NodeAddr,
        crate::PeerIdentity,
        NodeAddr,
        bool,
        Option<ActivityTick>,
        u32,
        u8,
        u8,
        PacketBuffer,
    ) {
        (
            self.source_addr,
            self.source_peer,
            self.previous_hop_addr,
            self.ce_flag,
            self.activity_tick,
            self.timestamp_ms,
            self.msg_type,
            self.inner_flags,
            self.plaintext,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspEndpointDataCommit {
    source_addr: NodeAddr,
    previous_hop_addr: NodeAddr,
    received_k_bit: bool,
    direct_path: bool,
}

impl PacketMover2FspEndpointDataCommit {
    pub(crate) fn source_addr(self) -> NodeAddr {
        self.source_addr
    }

    pub(crate) fn previous_hop_addr(self) -> NodeAddr {
        self.previous_hop_addr
    }

    pub(crate) fn received_k_bit(self) -> bool {
        self.received_k_bit
    }

    pub(crate) fn direct_path(self) -> bool {
        self.direct_path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspEndpointDataCommitRun {
    commit: PacketMover2FspEndpointDataCommit,
    len: usize,
}

impl PacketMover2FspEndpointDataCommitRun {
    fn new(commit: PacketMover2FspEndpointDataCommit, len: usize) -> Self {
        Self { commit, len }
    }

    pub(crate) fn commit(self) -> PacketMover2FspEndpointDataCommit {
        self.commit
    }

    pub(crate) fn len(self) -> usize {
        self.len
    }

    fn try_extend(&mut self, commit: PacketMover2FspEndpointDataCommit, len: usize) -> bool {
        if self.commit != commit {
            return false;
        }
        self.len = self.len.saturating_add(len);
        true
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PacketMover2FspEndpointDataIngress {
    commit: PacketMover2FspEndpointDataCommit,
    msg_type: u8,
    body_len: usize,
    receive_sync: FspReceiveSync,
    activity_tick: Option<ActivityTick>,
    packet_run: FipsEndpointDirectPacketRun,
}

impl PacketMover2FspEndpointDataIngress {
    fn from_output(output: PacketOutput) -> Result<Self, PacketOutput> {
        let source_addr = output.owner().node_addr();
        let Some(source_peer) = output.source_peer() else {
            return Err(output);
        };
        if source_peer.node_addr() != &source_addr {
            return Err(output);
        }

        let previous_hop_addr = output.previous_hop().unwrap_or(source_addr);
        let ce_flag = output.ce_flag();
        let header = match FspWireHeader::parse(output.payload()) {
            Ok(header) => header,
            Err(_) => return Err(output),
        };
        let path_mtu = output.path_mtu();
        let activity_tick = output.activity_tick;
        let (timestamp_ms, inner_flags, plaintext_len, body_len, ranges) = {
            let Some(plaintext) = output.opened_payload() else {
                return Err(output);
            };
            let Some((timestamp_ms, msg_type, inner_flags, body)) =
                crate::node::session_wire::fsp_strip_inner_header(plaintext)
            else {
                return Err(output);
            };
            if msg_type != crate::protocol::SessionMessageType::EndpointDataBulk.to_byte()
            {
                return Err(output);
            }
            let Some(ranges) = crate::node::session_wire::decode_fsp_endpoint_data_bulk_ranges(body)
            else {
                return Err(output);
            };
            (timestamp_ms, inner_flags, plaintext.len(), body.len(), ranges)
        };
        let receive_sync = FspReceiveSync {
            counter: output.counter(),
            received_k_bit: header.flags() & crate::node::session_wire::FSP_FLAG_K != 0,
            timestamp: timestamp_ms,
            plaintext_len,
            ce_flag,
            path_mtu,
            spin_bit: inner_flags & 0x01 != 0,
        };
        let mut payload = output.into_opened_payload()?;
        payload.drain(..FSP_INNER_HEADER_SIZE);
        payload.truncate(body_len);
        let packet_run = FipsEndpointDirectPacketRun::from_segmented_payload(
            FipsEndpointDirectPacketRunMeta::new(
                source_peer,
                previous_hop_addr,
                receive_sync.received_k_bit,
                previous_hop_addr == source_addr,
                crate::time::now_ms(),
            ),
            payload,
            ranges,
        );

        Ok(Self {
            commit: PacketMover2FspEndpointDataCommit {
                source_addr,
                previous_hop_addr,
                received_k_bit: receive_sync.received_k_bit,
                direct_path: previous_hop_addr == source_addr,
            },
            msg_type: crate::protocol::SessionMessageType::EndpointDataBulk.to_byte(),
            body_len,
            receive_sync,
            activity_tick,
            packet_run,
        })
    }

    pub(crate) fn commit(&self) -> PacketMover2FspEndpointDataCommit {
        self.commit
    }

    fn len(&self) -> usize {
        self.packet_run.len()
    }

    pub(crate) fn into_direct_packet_run(self) -> FipsEndpointDirectPacketRun {
        self.packet_run
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PacketMover2EndpointDataBulk {
    commit_runs: Vec<PacketMover2FspEndpointDataCommitRun>,
    packet_runs: Vec<FipsEndpointDirectPacketRun>,
    len: usize,
}

impl PacketMover2EndpointDataBulk {
    pub(crate) fn from_ingress(ingress: PacketMover2FspEndpointDataIngress) -> Self {
        let len = ingress.len();
        let commit = ingress.commit();
        Self {
            commit_runs: vec![PacketMover2FspEndpointDataCommitRun::new(commit, len)],
            packet_runs: vec![ingress.into_direct_packet_run()],
            len,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn push(&mut self, ingress: PacketMover2FspEndpointDataIngress) {
        let len = ingress.len();
        let commit = ingress.commit();
        if !self
            .commit_runs
            .last_mut()
            .is_some_and(|run| run.try_extend(commit, len))
        {
            self.commit_runs
                .push(PacketMover2FspEndpointDataCommitRun::new(commit, len));
        }
        self.push_direct_packet_run(ingress.into_direct_packet_run());
        self.len = self.len.saturating_add(len);
    }

    pub(crate) fn extend(&mut self, other: Self) {
        for run in other.commit_runs {
            if !self
                .commit_runs
                .last_mut()
                .is_some_and(|last| last.try_extend(run.commit(), run.len()))
            {
                self.commit_runs.push(run);
            }
        }
        self.len = self.len.saturating_add(other.len);
        for run in other.packet_runs {
            self.push_direct_packet_run(run);
        }
    }

    pub(crate) fn commit_runs(&self) -> &[PacketMover2FspEndpointDataCommitRun] {
        &self.commit_runs
    }

    pub(crate) fn direct_packet_run_count(&self) -> usize {
        self.packet_runs.len()
    }

    pub(crate) fn into_direct_packet_batch(self) -> FipsEndpointDirectPacketBatch {
        FipsEndpointDirectPacketBatch::from_packet_runs(self.packet_runs)
    }

    pub(crate) fn take_direct_packet_batch(&mut self) -> FipsEndpointDirectPacketBatch {
        FipsEndpointDirectPacketBatch::from_packet_runs(std::mem::take(&mut self.packet_runs))
    }

    fn push_direct_packet_run(&mut self, run: FipsEndpointDirectPacketRun) {
        if let Some(last) = self.packet_runs.last_mut() {
            match last.try_append_run(run) {
                Ok(()) => return,
                Err(run) => self.packet_runs.push(run),
            }
        } else {
            self.packet_runs.push(run);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PacketMover2LiveNodeTurn {
    summary: PacketMover2RuntimeSummary,
    fmp_control_ingress: Vec<PacketMover2FmpControlIngress>,
    fmp_ingress_receipts: Vec<PacketMover2FmpIngressReceipt>,
    fmp_link_ingress: Vec<PacketMover2FmpLinkIngress>,
    fsp_coord_warmups: Vec<PacketMover2FspCoordWarmup>,
    fsp_local_session_ingress: Vec<PacketMover2FspLocalSessionIngress>,
    endpoint_data_bulk: Vec<PacketMover2EndpointDataBulk>,
    fsp_session_ingress: Vec<PacketMover2FspSessionIngress>,
    raw_ingress_drops: Vec<PacketMover2RawIngressDrop>,
    tun_outbound_drops: Vec<PacketMover2TunOutboundDrop>,
    endpoint_data_drops: Vec<PacketMover2EndpointDataDrop>,
    tun_source_drained: usize,
    endpoint_source_drained: usize,
    deferred_endpoint_data_batches_count: usize,
    tun_deferred_packets: usize,
    output_drops: Vec<PacketMover2OutputDrop>,
    drops: Vec<PacketDrop>,
    transport_planned: usize,
    transport_sent: usize,
    transport_dropped: usize,
    transport_sent_receipts: Vec<PacketMover2TransportSentReceipt>,
}

impl PacketMover2LiveNodeTurn {
    fn from_runtime_turn(turn: &PacketMover2RuntimeTurn<'_>) -> Self {
        Self {
            summary: turn.summary(),
            raw_ingress_drops: turn.raw_ingress_drops().to_vec(),
            output_drops: turn.output_drops().to_vec(),
            drops: turn.drops().to_vec(),
            ..Default::default()
        }
    }

    pub(crate) fn summary(&self) -> PacketMover2RuntimeSummary {
        self.summary
    }

    pub(crate) fn raw_ingress_drops(&self) -> &[PacketMover2RawIngressDrop] {
        &self.raw_ingress_drops
    }

    pub(crate) fn fmp_control_ingress(&self) -> &[PacketMover2FmpControlIngress] {
        &self.fmp_control_ingress
    }

    pub(crate) fn take_fmp_control_ingress(&mut self) -> Vec<PacketMover2FmpControlIngress> {
        std::mem::take(&mut self.fmp_control_ingress)
    }

    pub(crate) fn fmp_ingress_receipts(&self) -> &[PacketMover2FmpIngressReceipt] {
        &self.fmp_ingress_receipts
    }

    pub(crate) fn take_fmp_ingress_receipts(&mut self) -> Vec<PacketMover2FmpIngressReceipt> {
        std::mem::take(&mut self.fmp_ingress_receipts)
    }

    pub(crate) fn fmp_link_ingress(&self) -> &[PacketMover2FmpLinkIngress] {
        &self.fmp_link_ingress
    }

    pub(crate) fn take_fmp_link_ingress(&mut self) -> Vec<PacketMover2FmpLinkIngress> {
        std::mem::take(&mut self.fmp_link_ingress)
    }

    pub(crate) fn fsp_coord_warmups(&self) -> &[PacketMover2FspCoordWarmup] {
        &self.fsp_coord_warmups
    }

    pub(crate) fn take_fsp_coord_warmups(&mut self) -> Vec<PacketMover2FspCoordWarmup> {
        std::mem::take(&mut self.fsp_coord_warmups)
    }

    pub(crate) fn fsp_local_session_ingress(&self) -> &[PacketMover2FspLocalSessionIngress] {
        &self.fsp_local_session_ingress
    }

    pub(crate) fn take_fsp_local_session_ingress(
        &mut self,
    ) -> Vec<PacketMover2FspLocalSessionIngress> {
        std::mem::take(&mut self.fsp_local_session_ingress)
    }

    pub(crate) fn take_endpoint_data_bulk(&mut self) -> Vec<PacketMover2EndpointDataBulk> {
        std::mem::take(&mut self.endpoint_data_bulk)
    }

    pub(crate) fn endpoint_data_bulk(&self) -> &[PacketMover2EndpointDataBulk] {
        &self.endpoint_data_bulk
    }

    pub(crate) fn endpoint_data_bulk_count(&self) -> usize {
        self.endpoint_data_bulk
            .iter()
            .map(PacketMover2EndpointDataBulk::len)
            .sum()
    }

    pub(crate) fn fsp_session_ingress(&self) -> &[PacketMover2FspSessionIngress] {
        &self.fsp_session_ingress
    }

    pub(crate) fn take_fsp_session_ingress(&mut self) -> Vec<PacketMover2FspSessionIngress> {
        std::mem::take(&mut self.fsp_session_ingress)
    }

    pub(crate) fn tun_outbound_drops(&self) -> &[PacketMover2TunOutboundDrop] {
        &self.tun_outbound_drops
    }

    pub(crate) fn endpoint_data_drops(&self) -> &[PacketMover2EndpointDataDrop] {
        &self.endpoint_data_drops
    }

    pub(crate) fn tun_source_drained(&self) -> usize {
        self.tun_source_drained
    }

    pub(crate) fn endpoint_source_drained(&self) -> usize {
        self.endpoint_source_drained
    }

    pub(crate) fn deferred_endpoint_data_batches_count(&self) -> usize {
        self.deferred_endpoint_data_batches_count
    }

    pub(crate) fn tun_deferred_packets(&self) -> usize {
        self.tun_deferred_packets
    }

    pub(crate) fn output_drops(&self) -> &[PacketMover2OutputDrop] {
        &self.output_drops
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        &self.drops
    }

    pub(crate) fn transport_planned(&self) -> usize {
        self.transport_planned
    }

    pub(crate) fn transport_sent(&self) -> usize {
        self.transport_sent
    }

    pub(crate) fn transport_dropped(&self) -> usize {
        self.transport_dropped
    }

    pub(crate) fn take_transport_sent_receipts(&mut self) -> Vec<PacketMover2TransportSentReceipt> {
        std::mem::take(&mut self.transport_sent_receipts)
    }

    pub(crate) fn has_activity(&self) -> bool {
        self.summary.has_activity()
            || !self.fmp_control_ingress.is_empty()
            || !self.fmp_ingress_receipts.is_empty()
            || !self.fmp_link_ingress.is_empty()
            || !self.fsp_coord_warmups.is_empty()
            || !self.fsp_local_session_ingress.is_empty()
            || !self.endpoint_data_bulk.is_empty()
            || !self.fsp_session_ingress.is_empty()
            || !self.raw_ingress_drops.is_empty()
            || !self.tun_outbound_drops.is_empty()
            || !self.endpoint_data_drops.is_empty()
            || self.tun_source_drained > 0
            || self.endpoint_source_drained > 0
            || self.deferred_endpoint_data_batches_count > 0
            || self.tun_deferred_packets > 0
            || !self.output_drops.is_empty()
            || !self.drops.is_empty()
            || self.transport_planned > 0
            || self.transport_sent > 0
            || self.transport_dropped > 0
            || !self.transport_sent_receipts.is_empty()
    }

    pub(crate) fn has_failures(&self) -> bool {
        self.summary.has_failures()
            || !self.raw_ingress_drops.is_empty()
            || !self.tun_outbound_drops.is_empty()
            || !self.endpoint_data_drops.is_empty()
            || !self.output_drops.is_empty()
            || !self.drops.is_empty()
            || self.transport_dropped > 0
    }

    fn absorb(&mut self, mut other: Self) {
        self.summary.absorb(other.summary);
        self.fmp_control_ingress
            .append(&mut other.fmp_control_ingress);
        self.fmp_ingress_receipts
            .append(&mut other.fmp_ingress_receipts);
        self.fmp_link_ingress.append(&mut other.fmp_link_ingress);
        self.fsp_coord_warmups.append(&mut other.fsp_coord_warmups);
        self.fsp_local_session_ingress
            .append(&mut other.fsp_local_session_ingress);
        self.endpoint_data_bulk
            .append(&mut other.endpoint_data_bulk);
        self.fsp_session_ingress
            .append(&mut other.fsp_session_ingress);
        self.raw_ingress_drops.append(&mut other.raw_ingress_drops);
        self.tun_outbound_drops
            .append(&mut other.tun_outbound_drops);
        self.endpoint_data_drops
            .append(&mut other.endpoint_data_drops);
        self.tun_source_drained = self
            .tun_source_drained
            .saturating_add(other.tun_source_drained);
        self.endpoint_source_drained = self
            .endpoint_source_drained
            .saturating_add(other.endpoint_source_drained);
        self.deferred_endpoint_data_batches_count = self
            .deferred_endpoint_data_batches_count
            .saturating_add(other.deferred_endpoint_data_batches_count);
        self.tun_deferred_packets = self
            .tun_deferred_packets
            .saturating_add(other.tun_deferred_packets);
        self.output_drops.append(&mut other.output_drops);
        self.drops.append(&mut other.drops);
        self.transport_planned = self
            .transport_planned
            .saturating_add(other.transport_planned);
        self.transport_sent = self.transport_sent.saturating_add(other.transport_sent);
        self.transport_dropped = self
            .transport_dropped
            .saturating_add(other.transport_dropped);
        self.transport_sent_receipts
            .append(&mut other.transport_sent_receipts);
    }
}
