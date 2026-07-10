
#[derive(Debug, Default)]
pub(crate) struct DataplaneLiveOutboundFirsts {
    pub(crate) initial_outbound: Option<OutboundPacket>,
    pub(crate) endpoint_data_batch: Option<NodeEndpointDataBatch>,
    pub(crate) tun_packet: Option<Vec<u8>>,
    pub(crate) collect_transport_sent_receipts: bool,
}

pub(crate) struct DataplaneRouteTableOutboundSource<'a> {
    first_endpoint_data_batch: Option<NodeEndpointDataBatch>,
    first_tun_packet: Option<Vec<u8>>,
    endpoint_data_rx: &'a mut EndpointDataBatchRx,
    endpoint_limit: usize,
    tun_outbound_rx: &'a mut TunOutboundRx,
    tun_limit: usize,
    routes: &'a DataplaneLiveRouteTable,
    buffers: &'a mut DataplaneRouteTableOutboundBuffers,
    endpoint_stale_data_drop_ms: u64,
}

#[derive(Default)]
struct DataplaneRouteTableOutboundBuffers {
    endpoint_drops: Vec<DataplaneEndpointDataDrop>,
    deferred_endpoint_data_batches: Vec<NodeEndpointDataBatch>,
    tun_drops: Vec<DataplaneTunOutboundDrop>,
    tun_deferred_packets: Vec<Vec<u8>>,
}

impl DataplaneRouteTableOutboundBuffers {
    fn has_activity(&self) -> bool {
        !self.endpoint_drops.is_empty()
            || !self.deferred_endpoint_data_batches.is_empty()
            || !self.tun_drops.is_empty()
            || !self.tun_deferred_packets.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataplaneOutboundSource {
    Endpoint,
    Tun,
}

#[derive(Default)]
struct DataplaneOutboundAdmissionCounts {
    endpoint: usize,
    tun: usize,
}

impl DataplaneOutboundAdmissionCounts {
    fn record(&mut self, source: DataplaneOutboundSource, admitted: usize) {
        match source {
            DataplaneOutboundSource::Endpoint => {
                self.endpoint = self.endpoint.saturating_add(admitted);
            }
            DataplaneOutboundSource::Tun => {
                self.tun = self.tun.saturating_add(admitted);
            }
        }
    }
}

struct DataplaneOutboundAdmission<'a> {
    driver: &'a mut DataplaneTurnDriver,
    summary: &'a mut DataplaneRuntimeSummary,
    trace_enabled: bool,
    counts: &'a mut DataplaneOutboundAdmissionCounts,
}

impl DataplaneOutboundAdmission<'_> {
    fn packet(&mut self, source: DataplaneOutboundSource, packet: OutboundPacket) {
        let admitted_before = self.admitted_before();
        self.driver.admit_outbound_packet(packet, self.summary);
        self.record(source, admitted_before);
    }

    fn batch(&mut self, source: DataplaneOutboundSource, packets: Vec<OutboundPacket>) {
        let admitted_before = self.admitted_before();
        self.driver.admit_outbound_packet_batch(packets, self.summary);
        self.record(source, admitted_before);
    }

    fn admitted_before(&self) -> usize {
        if self.trace_enabled {
            self.summary.outbound_admitted
        } else {
            0
        }
    }

    fn record(&mut self, source: DataplaneOutboundSource, admitted_before: usize) {
        if self.trace_enabled {
            self.counts.record(
                source,
                self.summary
                    .outbound_admitted
                    .saturating_sub(admitted_before),
            );
        }
    }
}

impl<'a> DataplaneRouteTableOutboundSource<'a> {
    fn new(
        endpoint_data_rx: &'a mut EndpointDataBatchRx,
        endpoint_limit: usize,
        tun_outbound_rx: &'a mut TunOutboundRx,
        tun_limit: usize,
        routes: &'a DataplaneLiveRouteTable,
        buffers: &'a mut DataplaneRouteTableOutboundBuffers,
    ) -> Self {
        Self {
            first_endpoint_data_batch: None,
            first_tun_packet: None,
            endpoint_data_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            routes,
            buffers,
            endpoint_stale_data_drop_ms: crate::node::ENDPOINT_STALE_DATA_DROP_MS,
        }
    }

    fn with_firsts(mut self, firsts: DataplaneLiveOutboundFirsts) -> Self {
        self.first_endpoint_data_batch = firsts.endpoint_data_batch;
        self.first_tun_packet = firsts.tun_packet;
        self
    }

    fn take_firsts(&mut self) -> DataplaneLiveOutboundFirsts {
        DataplaneLiveOutboundFirsts {
            endpoint_data_batch: self.first_endpoint_data_batch.take(),
            tun_packet: self.first_tun_packet.take(),
            ..Default::default()
        }
    }
}

impl DataplaneRouteTableOutboundSource<'_> {
    fn cache_first_tun_packet(&mut self) {
        if self.first_tun_packet.is_none() && let Ok(packet) = self.tun_outbound_rx.try_recv() {
            self.first_tun_packet = Some(packet);
        }
    }

    fn drain_endpoint_batched(
        &mut self,
        limit: usize,
        admission: &mut DataplaneOutboundAdmission<'_>,
    ) -> usize {
        let mut drained_cost = 0usize;
        let mut timing = None;
        if drained_cost < limit
            && let Some(batch) = self.first_endpoint_data_batch.take()
        {
            drained_cost = drained_cost.saturating_add(batch.drain_cost());
            self.route_or_drop_endpoint_data_batch(
                batch,
                endpoint_drain_timing(&mut timing),
                admission,
            );
        }
        while drained_cost < limit {
            let Ok(batch) = self.endpoint_data_rx.try_recv() else {
                break;
            };
            drained_cost = drained_cost.saturating_add(batch.drain_cost());
            self.route_or_drop_endpoint_data_batch(
                batch,
                endpoint_drain_timing(&mut timing),
                admission,
            );
        }
        drained_cost
    }

    fn route_or_drop_endpoint_data_batch(
        &mut self,
        batch: NodeEndpointDataBatch,
        timing: (u64, ActivityTick),
        admission: &mut DataplaneOutboundAdmission<'_>,
    ) {
        let (now_ms, activity_tick) = timing;
        let drop_count = stale_endpoint_data_drop_count(
            &batch,
            now_ms,
            self.endpoint_stale_data_drop_ms,
        );
        if drop_count > 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::EndpointDataBatchDropped,
                drop_count as u64,
            );
            drop_stale_endpoint_data_batch(batch, &mut self.buffers.endpoint_drops);
            return;
        }

        route_endpoint_data_batch_with_route_table(
            batch,
            self.routes,
            &mut self.buffers.endpoint_drops,
            &mut self.buffers.deferred_endpoint_data_batches,
            activity_tick,
            |packets| {
                admission.batch(DataplaneOutboundSource::Endpoint, packets);
            },
        );
    }

    fn drain_tun_batched(
        &mut self,
        limit: usize,
        admission: &mut DataplaneOutboundAdmission<'_>,
    ) -> usize {
        let mut drained = 0usize;
        let mut first_routed = None;
        let mut routed_batch = Vec::new();
        let activity_tick = ActivityTick::new(crate::time::now_ms());
        self.cache_first_tun_packet();
        while drained < limit {
            let packet = if let Some(packet) = self.first_tun_packet.take() {
                packet
            } else {
                let Ok(packet) = self.tun_outbound_rx.try_recv() else {
                    break;
                };
                packet
            };
            route_tun_outbound_packet_with_route_table(
                packet,
                self.routes,
                activity_tick,
                &mut self.buffers.tun_drops,
                &mut self.buffers.tun_deferred_packets,
                |packet| collect_tun_routed_packet(packet, &mut first_routed, &mut routed_batch),
            );
            drained += 1;
        }
        flush_tun_routed_packets(first_routed, routed_batch, admission);
        drained
    }

    fn drain_outbound_batched(
        &mut self,
        limit: usize,
        admission: &mut DataplaneOutboundAdmission<'_>,
    ) -> (usize, usize, usize) {
        let endpoint_limit = self.endpoint_limit.min(limit);
        let endpoint_drained = self.drain_endpoint_batched(endpoint_limit, admission);
        let reserved_drained = endpoint_drained.min(endpoint_limit);
        let remaining = limit.saturating_sub(reserved_drained);
        let tun_limit = self.tun_limit.min(remaining);
        let tun_drained = self.drain_tun_batched(tun_limit, admission);
        (
            endpoint_drained.saturating_add(tun_drained),
            endpoint_drained,
            tun_drained,
        )
    }
}

fn endpoint_drain_timing(timing: &mut Option<(u64, ActivityTick)>) -> (u64, ActivityTick) {
    *timing.get_or_insert_with(|| {
        let now_ms = crate::time::now_ms();
        (now_ms, ActivityTick::new(now_ms))
    })
}

fn collect_tun_routed_packet(
    packet: OutboundPacket,
    first: &mut Option<OutboundPacket>,
    batch: &mut Vec<OutboundPacket>,
) {
    if batch.is_empty() {
        if first.is_none() {
            *first = Some(packet);
            return;
        }
        if let Some(first) = first.take() {
            batch.push(first);
        }
    }
    batch.push(packet);
}

fn flush_tun_routed_packets(
    first: Option<OutboundPacket>,
    batch: Vec<OutboundPacket>,
    admission: &mut DataplaneOutboundAdmission<'_>,
) {
    if batch.is_empty() {
        if let Some(packet) = first {
            admission.packet(DataplaneOutboundSource::Tun, packet);
        }
    } else {
        admission.batch(DataplaneOutboundSource::Tun, batch);
    }
}

impl DataplaneRawIngressSource for VecDeque<DataplaneRawIngress> {
    fn drain_raw_ingress<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(DataplaneRawIngress),
    {
        let mut drained = 0;
        while drained < limit {
            let Some(packet) = self.pop_front() else {
                break;
            };
            push(packet);
            drained += 1;
        }
        drained
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneRawIngressDropReason {
    Wire(WirePreflightError),
    Unrouted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneRawIngressDrop {
    protocol: PacketProtocol,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    payload_len: usize,
    fmp_receiver_idx: Option<u32>,
    reason: DataplaneRawIngressDropReason,
}

impl DataplaneRawIngressDrop {
    fn from_packet(
        packet: DataplaneRawIngress,
        reason: DataplaneRawIngressDropReason,
    ) -> Self {
        Self {
            protocol: packet.protocol,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr,
            payload_len: packet.payload.len(),
            fmp_receiver_idx: (packet.protocol == PacketProtocol::Fmp)
                .then(|| FmpWireHeader::parse(packet.payload.as_slice()).ok())
                .flatten()
                .map(|header| header.receiver_idx()),
            reason,
        }
    }

    pub(crate) fn protocol(&self) -> PacketProtocol {
        self.protocol
    }

    pub(crate) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    pub(crate) fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn fmp_receiver_idx(&self) -> Option<u32> {
        self.fmp_receiver_idx
    }

    pub(crate) fn reason(&self) -> DataplaneRawIngressDropReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneOutputError {
    Unavailable,
    NoRoute,
    InvalidPacket,
    MtuExceeded { mtu: u16 },
    TransportFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneOutputDrop {
    owner: OwnerId,
    send_token: Option<u64>,
    payload_len: usize,
    reason: DataplaneOutputError,
}

impl DataplaneOutputDrop {
    pub(crate) fn from_output(output: &PacketOutput, reason: DataplaneOutputError) -> Self {
        Self {
            owner: output.owner,
            send_token: output.send_token,
            payload_len: output.payload.len(),
            reason,
        }
    }

    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn send_token(&self) -> Option<u64> {
        self.send_token
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> DataplaneOutputError {
        self.reason
    }
}

impl PacketOutput {
    pub(crate) fn opened_payload(&self) -> Option<&[u8]> {
        let offset = usize::from(self.opened_payload_offset);
        if offset == 0 {
            return None;
        }
        self.payload.as_slice().get(offset..)
    }

    fn take_opened_payload(&mut self) -> Option<PacketBuffer> {
        let offset = usize::from(self.opened_payload_offset);
        if offset == 0 || !self.payload.trim_front(offset) {
            return None;
        }
        Some(std::mem::take(&mut self.payload))
    }
}

pub(crate) trait DataplaneOutputSink {
    fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<DataplaneOutputDrop>) -> usize
    where
        I: IntoIterator<Item = PacketOutput>;
}

#[derive(Debug)]
struct DataplaneLiveOutputSink<'a> {
    transport: &'a mut DataplaneTransportSendGroups,
}

impl<'a> DataplaneLiveOutputSink<'a> {
    fn new(transport: &'a mut DataplaneTransportSendGroups) -> Self {
        Self { transport }
    }
}

impl DataplaneOutputSink for DataplaneLiveOutputSink<'_> {
    fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<DataplaneOutputDrop>) -> usize
    where
        I: IntoIterator<Item = PacketOutput>,
    {
        let mut sent = 0usize;
        for output in outputs {
            let mut drop =
                DataplaneOutputDrop::from_output(&output, DataplaneOutputError::Unavailable);
            match self.queue_transport_output(output) {
                Ok(()) => sent = sent.saturating_add(1),
                Err(reason) => {
                    drop.reason = reason;
                    drops.push(drop);
                }
            }
        }
        sent
    }
}

impl DataplaneLiveOutputSink<'_> {
    fn queue_transport_output(&mut self, output: PacketOutput) -> Result<(), DataplaneOutputError> {
        match output.target {
            OutputTarget::Transport => {
                let Some(path) = output.path.as_ref() else {
                    return Err(DataplaneOutputError::NoRoute);
                };
                let transport_id = path.transport_id;
                let remote_addr = path.remote_addr.clone();
                self.transport
                    .push_transport(transport_id, remote_addr, output);
                Ok(())
            }
            OutputTarget::SessionIngress { .. }
            | OutputTarget::SessionPayload { .. } => Err(DataplaneOutputError::NoRoute),
        }
    }
}

fn dataplane_output_error_from_session_handoff(
    error: DataplaneSessionHandoffError,
) -> DataplaneOutputError {
    match error {
        DataplaneSessionHandoffError::InvalidPacket => DataplaneOutputError::InvalidPacket,
        DataplaneSessionHandoffError::NoRoute => DataplaneOutputError::NoRoute,
    }
}
