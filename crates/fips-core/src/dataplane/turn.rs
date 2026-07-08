#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataplaneRuntimeSummary {
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

impl DataplaneRuntimeSummary {
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
pub(crate) struct DataplaneRuntimeTurn<'a> {
    summary: DataplaneRuntimeSummary,
    raw_ingress_drops: &'a [DataplaneRawIngressDrop],
    output_drops: &'a [DataplaneOutputDrop],
    outputs: &'a [PacketOutput],
    drops: &'a [PacketDrop],
}

impl DataplaneRuntimeTurn<'_> {
    pub(crate) fn summary(&self) -> DataplaneRuntimeSummary {
        self.summary
    }

    pub(crate) fn raw_ingress_drops(&self) -> &[DataplaneRawIngressDrop] {
        self.raw_ingress_drops
    }

    pub(crate) fn output_drops(&self) -> &[DataplaneOutputDrop] {
        self.output_drops
    }

    #[cfg(test)]
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
pub(crate) struct DataplaneFmpIngressReceipt {
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

impl DataplaneFmpIngressReceipt {
    fn from_output(output: &PacketOutput) -> Option<Self> {
        if output.owner().protocol() != PacketProtocol::Fmp {
            return None;
        }
        let source_addr = output.owner().node_addr();
        let source_peer = output.source_peer()?;
        if source_peer.node_addr() != &source_addr {
            return None;
        }
        let source_path = output.source_path()?;
        let transport_id = source_path.transport_id;
        let remote_addr = source_path.remote_addr.clone();
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
            transport_id,
            remote_addr,
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
pub(crate) struct DataplaneFmpLinkIngress {
    receipt: DataplaneFmpIngressReceipt,
    output: PacketOutput,
    msg_type: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneFmpLinkIngressFields {
    receipt: DataplaneFmpIngressReceipt,
    msg_type: Option<u8>,
}

impl DataplaneFmpLinkIngress {
    fn parse(output: &PacketOutput) -> Option<DataplaneFmpLinkIngressFields> {
        let plaintext = output.opened_payload()?;
        let receipt = DataplaneFmpIngressReceipt::from_output(output)?;
        let msg_type = plaintext.get(4).copied();
        Some(DataplaneFmpLinkIngressFields { receipt, msg_type })
    }

    fn from_fields(output: PacketOutput, fields: DataplaneFmpLinkIngressFields) -> Self {
        Self {
            receipt: fields.receipt,
            output,
            msg_type: fields.msg_type,
        }
    }

    pub(crate) fn receipt(&self) -> &DataplaneFmpIngressReceipt {
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataplaneFspCoordWarmup {
    source: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
    local: Option<(NodeAddr, crate::tree::TreeCoordinate)>,
}

impl DataplaneFspCoordWarmup {
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

    pub(crate) fn apply_to(self, coord_cache: &mut crate::cache::CoordCache, now_ms: u64) {
        if let Some((addr, coords)) = self.source {
            coord_cache.insert(addr, coords, now_ms);
        }
        if let Some((addr, coords)) = self.local {
            coord_cache.insert(addr, coords, now_ms);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFspLocalSessionIngress {
    source_addr: NodeAddr,
    previous_hop_addr: NodeAddr,
    ce_flag: bool,
    path_mtu: u16,
    payload: PacketBuffer,
}

impl DataplaneFspLocalSessionIngress {
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
pub(crate) struct DataplaneFspSessionIngress {
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

impl DataplaneFspSessionIngress {
    fn take_from_output(output: &mut PacketOutput) -> Option<Self> {
        let source_addr = output.owner().node_addr();
        let source_peer = output.source_peer()?;
        if source_peer.node_addr() != &source_addr {
            return None;
        }
        let previous_hop_addr = output.previous_hop().unwrap_or(source_addr);
        let ce_flag = output.ce_flag();
        let header = match FspWireHeader::parse(output.payload()) {
            Ok(header) => header,
            Err(_) => return None,
        };
        let path_mtu = output.path_mtu();
        let activity_tick = output.activity_tick;
        let (timestamp_ms, msg_type, inner_flags, plaintext_len) = {
            let plaintext = output.opened_payload()?;
            let (timestamp_ms, msg_type, inner_flags, _body) =
                crate::node::session_wire::fsp_strip_inner_header(plaintext)?;
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
        let plaintext = output.take_opened_payload()?;
        Some(Self {
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

    pub(crate) fn received_k_bit(&self) -> bool {
        self.receive_sync.received_k_bit
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
pub(crate) struct DataplaneFspEndpointDataCommit {
    source_addr: NodeAddr,
    previous_hop_addr: NodeAddr,
    received_k_bit: bool,
    direct_path: bool,
}

impl DataplaneFspEndpointDataCommit {
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
pub(crate) struct DataplaneFspEndpointDataCommitRun {
    commit: DataplaneFspEndpointDataCommit,
    len: usize,
}

impl DataplaneFspEndpointDataCommitRun {
    fn new(commit: DataplaneFspEndpointDataCommit, len: usize) -> Self {
        Self { commit, len }
    }

    pub(crate) fn commit(self) -> DataplaneFspEndpointDataCommit {
        self.commit
    }

    pub(crate) fn len(self) -> usize {
        self.len
    }

    fn try_extend(&mut self, commit: DataplaneFspEndpointDataCommit, len: usize) -> bool {
        if self.commit != commit {
            return false;
        }
        self.len = self.len.saturating_add(len);
        true
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DataplaneFspEndpointDataIngress {
    commit: DataplaneFspEndpointDataCommit,
    body_len: usize,
    receive_sync: FspReceiveSync,
    activity_tick: Option<ActivityTick>,
    packet_run: FipsEndpointDirectPacketRun,
}

impl DataplaneFspEndpointDataIngress {
    fn take_from_output(output: &mut PacketOutput, enqueued_at_ms: u64) -> Option<Self> {
        let source_addr = output.owner().node_addr();
        let source_peer = output.source_peer()?;
        if source_peer.node_addr() != &source_addr {
            return None;
        }

        let previous_hop_addr = output.previous_hop().unwrap_or(source_addr);
        let ce_flag = output.ce_flag();
        let header = match FspWireHeader::parse(output.payload()) {
            Ok(header) => header,
            Err(_) => return None,
        };
        let path_mtu = output.path_mtu();
        let activity_tick = output.activity_tick;
        let (timestamp_ms, inner_flags, plaintext_len, body_len) = {
            let plaintext = output.opened_payload()?;
            let (timestamp_ms, msg_type, inner_flags, body) =
                crate::node::session_wire::fsp_strip_inner_header(plaintext)?;
            if msg_type != crate::protocol::SessionMessageType::EndpointData.to_byte() {
                return None;
            };
            (timestamp_ms, inner_flags, plaintext.len(), body.len())
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
        let mut payload = output.take_opened_payload()?;
        assert!(payload.trim_front(FSP_INNER_HEADER_SIZE));
        payload.truncate(body_len);
        let ranges = std::iter::once(0..body_len).collect();
        let packet_run = FipsEndpointDirectPacketRun::from_segmented_payload(
            FipsEndpointDirectPacketRunMeta::new(
                source_peer,
                previous_hop_addr,
                receive_sync.received_k_bit,
                previous_hop_addr == source_addr,
                enqueued_at_ms,
            ),
            payload,
            ranges,
        );

        Some(Self {
            commit: DataplaneFspEndpointDataCommit {
                source_addr,
                previous_hop_addr,
                received_k_bit: receive_sync.received_k_bit,
                direct_path: previous_hop_addr == source_addr,
            },
            body_len,
            receive_sync,
            activity_tick,
            packet_run,
        })
    }

    pub(crate) fn commit(&self) -> DataplaneFspEndpointDataCommit {
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
pub(crate) struct DataplaneEndpointDataBatch {
    commit_runs: Vec<DataplaneFspEndpointDataCommitRun>,
    packet_runs: Vec<FipsEndpointDirectPacketRun>,
    len: usize,
}

impl DataplaneEndpointDataBatch {
    pub(crate) fn from_ingress(ingress: DataplaneFspEndpointDataIngress) -> Self {
        let len = ingress.len();
        let commit = ingress.commit();
        Self {
            commit_runs: vec![DataplaneFspEndpointDataCommitRun::new(commit, len)],
            packet_runs: vec![ingress.into_direct_packet_run()],
            len,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn push(&mut self, ingress: DataplaneFspEndpointDataIngress) {
        let len = ingress.len();
        let commit = ingress.commit();
        if !self
            .commit_runs
            .last_mut()
            .is_some_and(|run| run.try_extend(commit, len))
        {
            self.commit_runs
                .push(DataplaneFspEndpointDataCommitRun::new(commit, len));
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

    pub(crate) fn commit_runs(&self) -> &[DataplaneFspEndpointDataCommitRun] {
        &self.commit_runs
    }

    pub(crate) fn packet_count(&self) -> usize {
        self.packet_runs
            .iter()
            .map(FipsEndpointDirectPacketRun::len)
            .sum()
    }

    pub(crate) fn take_direct_packet_batch(&mut self) -> FipsEndpointDirectPacketBatch {
        FipsEndpointDirectPacketBatch::from_packet_runs(std::mem::take(&mut self.packet_runs))
    }

    fn push_direct_packet_run(&mut self, run: FipsEndpointDirectPacketRun) {
        if let Some(last) = self.packet_runs.last_mut() {
            if last.matches_append_meta(&run) {
                last.append_run(run);
            } else {
                self.packet_runs.push(run);
            }
        } else {
            self.packet_runs.push(run);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneFspAuthenticatedIngressRun {
    EndpointDataBatch,
    Sessions { count: usize },
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DataplaneFspAuthenticatedIngress {
    runs: Vec<DataplaneFspAuthenticatedIngressRun>,
    endpoint_data_batches: Vec<DataplaneEndpointDataBatch>,
    sessions: Vec<DataplaneFspSessionIngress>,
}

impl DataplaneFspAuthenticatedIngress {
    pub(crate) fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.runs.clear();
        self.endpoint_data_batches.clear();
        self.sessions.clear();
    }

    pub(crate) fn append(&mut self, other: &mut Self) {
        self.runs.append(&mut other.runs);
        self.endpoint_data_batches
            .append(&mut other.endpoint_data_batches);
        self.sessions.append(&mut other.sessions);
    }

    pub(crate) fn push_endpoint_data_batch(&mut self, bulk: DataplaneEndpointDataBatch) {
        if matches!(
            self.runs.last(),
            Some(DataplaneFspAuthenticatedIngressRun::EndpointDataBatch)
        ) {
            self.endpoint_data_batches
                .last_mut()
                .expect("endpoint-data run has a batch")
                .extend(bulk);
        } else {
            self.endpoint_data_batches.push(bulk);
            self.runs
                .push(DataplaneFspAuthenticatedIngressRun::EndpointDataBatch);
        }
    }

    pub(crate) fn push_session(&mut self, ingress: DataplaneFspSessionIngress) {
        self.sessions.push(ingress);
        match self.runs.last_mut() {
            Some(DataplaneFspAuthenticatedIngressRun::Sessions { count }) => {
                *count = count.saturating_add(1);
            }
            _ => self
                .runs
                .push(DataplaneFspAuthenticatedIngressRun::Sessions { count: 1 }),
        }
    }

    pub(crate) fn endpoint_data_batches_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut DataplaneEndpointDataBatch> {
        self.endpoint_data_batches.iter_mut()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<DataplaneFspAuthenticatedIngressRun>,
        Vec<DataplaneEndpointDataBatch>,
        Vec<DataplaneFspSessionIngress>,
    ) {
        (self.runs, self.endpoint_data_batches, self.sessions)
    }

    pub(crate) fn endpoint_data_packet_count(&self) -> usize {
        self.endpoint_data_batches
            .iter()
            .map(DataplaneEndpointDataBatch::len)
            .sum()
    }

    pub(crate) fn endpoint_data_batch_count(&self) -> usize {
        self.endpoint_data_batches.len()
    }

    pub(crate) fn fsp_session_ingress_count(&self) -> usize {
        self.sessions.len()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DataplaneLiveNodeTurn {
    summary: DataplaneRuntimeSummary,
    fmp_control_ingress: Vec<DataplaneFmpControlIngress>,
    fmp_ingress_receipts: Vec<DataplaneFmpIngressReceipt>,
    fmp_link_ingress: Vec<DataplaneFmpLinkIngress>,
    fsp_coord_warmups: Vec<DataplaneFspCoordWarmup>,
    fsp_local_session_ingress: Vec<DataplaneFspLocalSessionIngress>,
    fsp_authenticated_ingress: DataplaneFspAuthenticatedIngress,
    raw_ingress_drops: Vec<DataplaneRawIngressDrop>,
    tun_outbound_drops: Vec<DataplaneTunOutboundDrop>,
    endpoint_data_drops: Vec<DataplaneEndpointDataDrop>,
    tun_source_drained: usize,
    endpoint_source_drained: usize,
    deferred_endpoint_data_batches_count: usize,
    tun_deferred_packets: usize,
    output_drops: Vec<DataplaneOutputDrop>,
    drops: Vec<PacketDrop>,
    transport_planned: usize,
    transport_sent: usize,
    transport_dropped: usize,
    transport_sent_receipts: Vec<DataplaneTransportSentReceipt>,
}

impl DataplaneLiveNodeTurn {
    fn from_runtime_turn(turn: &DataplaneRuntimeTurn<'_>) -> Self {
        Self {
            summary: turn.summary(),
            raw_ingress_drops: turn.raw_ingress_drops().to_vec(),
            output_drops: turn.output_drops().to_vec(),
            drops: turn.drops().to_vec(),
            ..Default::default()
        }
    }

    pub(crate) fn summary(&self) -> DataplaneRuntimeSummary {
        self.summary
    }

    pub(crate) fn raw_ingress_drops(&self) -> &[DataplaneRawIngressDrop] {
        &self.raw_ingress_drops
    }

    pub(crate) fn fmp_control_ingress(&self) -> &[DataplaneFmpControlIngress] {
        &self.fmp_control_ingress
    }

    pub(crate) fn take_fmp_control_ingress(&mut self) -> Vec<DataplaneFmpControlIngress> {
        std::mem::take(&mut self.fmp_control_ingress)
    }

    pub(crate) fn take_fmp_ingress_receipts(&mut self) -> Vec<DataplaneFmpIngressReceipt> {
        std::mem::take(&mut self.fmp_ingress_receipts)
    }

    pub(crate) fn fmp_link_ingress(&self) -> &[DataplaneFmpLinkIngress] {
        &self.fmp_link_ingress
    }

    pub(crate) fn take_fmp_link_ingress(&mut self) -> Vec<DataplaneFmpLinkIngress> {
        std::mem::take(&mut self.fmp_link_ingress)
    }

    pub(crate) fn fsp_coord_warmups(&self) -> &[DataplaneFspCoordWarmup] {
        &self.fsp_coord_warmups
    }

    pub(crate) fn take_fsp_coord_warmups(&mut self) -> Vec<DataplaneFspCoordWarmup> {
        std::mem::take(&mut self.fsp_coord_warmups)
    }

    pub(crate) fn fsp_local_session_ingress(&self) -> &[DataplaneFspLocalSessionIngress] {
        &self.fsp_local_session_ingress
    }

    pub(crate) fn take_fsp_local_session_ingress(
        &mut self,
    ) -> Vec<DataplaneFspLocalSessionIngress> {
        std::mem::take(&mut self.fsp_local_session_ingress)
    }

    pub(crate) fn take_fsp_authenticated_ingress(
        &mut self,
    ) -> DataplaneFspAuthenticatedIngress {
        std::mem::take(&mut self.fsp_authenticated_ingress)
    }

    pub(crate) fn endpoint_data_packet_count(&self) -> usize {
        self.fsp_authenticated_ingress.endpoint_data_packet_count()
    }

    pub(crate) fn endpoint_data_batch_count(&self) -> usize {
        self.fsp_authenticated_ingress.endpoint_data_batch_count()
    }

    pub(crate) fn fsp_session_ingress_count(&self) -> usize {
        self.fsp_authenticated_ingress.fsp_session_ingress_count()
    }

    pub(crate) fn tun_outbound_drops(&self) -> &[DataplaneTunOutboundDrop] {
        &self.tun_outbound_drops
    }

    pub(crate) fn endpoint_data_drops(&self) -> &[DataplaneEndpointDataDrop] {
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

    pub(crate) fn output_drops(&self) -> &[DataplaneOutputDrop] {
        &self.output_drops
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        &self.drops
    }

    pub(crate) fn transport_sent(&self) -> usize {
        self.transport_sent
    }

    pub(crate) fn transport_dropped(&self) -> usize {
        self.transport_dropped
    }

    pub(crate) fn take_transport_sent_receipts(&mut self) -> Vec<DataplaneTransportSentReceipt> {
        std::mem::take(&mut self.transport_sent_receipts)
    }

    pub(crate) fn has_activity(&self) -> bool {
        self.summary.has_activity()
            || !self.fmp_control_ingress.is_empty()
            || !self.fmp_ingress_receipts.is_empty()
            || !self.fmp_link_ingress.is_empty()
            || !self.fsp_coord_warmups.is_empty()
            || !self.fsp_local_session_ingress.is_empty()
            || !self.fsp_authenticated_ingress.is_empty()
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
        self.fsp_authenticated_ingress
            .append(&mut other.fsp_authenticated_ingress);
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
