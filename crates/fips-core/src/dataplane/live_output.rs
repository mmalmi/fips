
#[derive(Debug, Default)]
pub(crate) struct DataplaneLiveOutboundFirsts {
    pub(crate) initial_outbound: Option<OutboundPacket>,
    pub(crate) endpoint_data_batch: Option<NodeEndpointDataBatch>,
    pub(crate) tun_packet: Option<Vec<u8>>,
    pub(crate) collect_transport_sent_receipts: bool,
}

pub(crate) struct DataplaneRouteTableOutboundSource<'a, Routes> {
    first_endpoint_data_batch: Option<NodeEndpointDataBatch>,
    first_tun_packet: Option<Vec<u8>>,
    endpoint_data_rx: &'a mut EndpointDataBatchRx,
    endpoint_limit: usize,
    tun_outbound_rx: &'a mut TunOutboundRx,
    tun_limit: usize,
    routes: &'a mut Routes,
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

pub(crate) enum DataplaneRoutedOutbound {
    Packet(OutboundPacket),
    Batch(Vec<OutboundPacket>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataplaneOutboundSource {
    Endpoint,
    Tun,
}

impl<'a, Routes> DataplaneRouteTableOutboundSource<'a, Routes> {
    fn new(
        endpoint_data_rx: &'a mut EndpointDataBatchRx,
        endpoint_limit: usize,
        tun_outbound_rx: &'a mut TunOutboundRx,
        tun_limit: usize,
        routes: &'a mut Routes,
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

impl<Routes> DataplaneRouteTableOutboundSource<'_, Routes>
where
    Routes: DataplaneEndpointDataRouter + DataplaneTunOutboundRouter,
{
    fn cache_first_tun_packet(&mut self) {
        if self.first_tun_packet.is_none() && let Ok(packet) = self.tun_outbound_rx.try_recv() {
            self.first_tun_packet = Some(packet);
        }
    }

    fn drain_endpoint_batched<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(DataplaneOutboundSource, DataplaneRoutedOutbound),
    {
        let mut drained_cost = 0usize;
        if drained_cost < limit {
            if let Some(batch) = self.first_endpoint_data_batch.take() {
                drained_cost = drained_cost.saturating_add(batch.drain_cost());
                self.route_or_drop_endpoint_data_batch(batch, &mut push);
            }
        }
        while drained_cost < limit {
            let Ok(batch) = self.endpoint_data_rx.try_recv() else {
                break;
            };
            drained_cost = drained_cost.saturating_add(batch.drain_cost());
            self.route_or_drop_endpoint_data_batch(batch, &mut push);
        }
        drained_cost
    }

    fn route_or_drop_endpoint_data_batch<F>(
        &mut self,
        batch: NodeEndpointDataBatch,
        mut push: F,
    ) where
        F: FnMut(DataplaneOutboundSource, DataplaneRoutedOutbound),
    {
        let drop_count = stale_endpoint_data_drop_count(
            &batch,
            crate::time::now_ms(),
            self.endpoint_stale_data_drop_ms,
        );
        if drop_count > 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::EndpointDataBulkDropped,
                drop_count as u64,
            );
            drop_stale_endpoint_data_batch(batch, &mut self.buffers.endpoint_drops);
            return;
        }

        route_endpoint_data_batch_with_router(
            batch,
            self.routes,
            &mut self.buffers.endpoint_drops,
            &mut self.buffers.deferred_endpoint_data_batches,
            |packets| push(DataplaneOutboundSource::Endpoint, DataplaneRoutedOutbound::Batch(packets)),
        );
    }

    fn drain_tun_batched<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(DataplaneOutboundSource, DataplaneRoutedOutbound),
    {
        let mut drained = 0usize;
        let mut routed_packets = TunRoutedPacketCollector::default();
        let mut routed_drops = Vec::new();
        let activity_tick = ActivityTick::new(crate::time::now_ms());
        self.cache_first_tun_packet();
        if drained < limit {
            if let Some(packet) = self.first_tun_packet.take() {
                route_tun_outbound_packet_with_router(
                    packet,
                    self.routes,
                    activity_tick,
                    &mut self.buffers.tun_drops,
                    &mut self.buffers.tun_deferred_packets,
                    |packet| routed_packets.collect(packet, &mut routed_drops),
                );
                drained += 1;
            }
        }
        while drained < limit {
            let Ok(packet) = self.tun_outbound_rx.try_recv() else {
                break;
            };
            route_tun_outbound_packet_with_router(
                packet,
                self.routes,
                activity_tick,
                &mut self.buffers.tun_drops,
                &mut self.buffers.tun_deferred_packets,
                |packet| routed_packets.collect(packet, &mut routed_drops),
            );
            drained += 1;
        }
        routed_packets.flush(&mut routed_drops, &mut |routed| {
            push(DataplaneOutboundSource::Tun, routed);
        });
        self.buffers.tun_drops.append(&mut routed_drops);
        drained
    }

    fn drain_outbound_batched<F>(&mut self, limit: usize, mut push: F) -> (usize, usize, usize)
    where
        F: FnMut(DataplaneOutboundSource, DataplaneRoutedOutbound),
    {
        let endpoint_limit = self.endpoint_limit.min(limit);
        let endpoint_drained = self.drain_endpoint_batched(endpoint_limit, &mut push);
        let reserved_drained = endpoint_drained.min(endpoint_limit);
        let remaining = limit.saturating_sub(reserved_drained);
        let tun_limit = self.tun_limit.min(remaining);
        let tun_drained = self.drain_tun_batched(tun_limit, push);
        (
            endpoint_drained.saturating_add(tun_drained),
            endpoint_drained,
            tun_drained,
        )
    }
}

#[derive(Default)]
struct TunRoutedPacketCollector {
    first_session_packet: Option<OutboundPacket>,
    session_batch: Vec<OutboundPacket>,
    endpoint: Option<TunEndpointDataCollector>,
}

struct TunEndpointDataCollector {
    route: DataplaneEndpointDataRoute,
    activity_tick: ActivityTick,
    builder: EndpointDataBulkBodyBuilder,
}

impl TunRoutedPacketCollector {
    fn collect(
        &mut self,
        packet: DataplaneTunRoutedPacket,
        drops: &mut Vec<DataplaneTunOutboundDrop>,
    ) {
        match packet {
            DataplaneTunRoutedPacket::Session(packet) => {
                self.flush_endpoint(drops);
                self.collect_session(packet);
            }
            DataplaneTunRoutedPacket::EndpointData {
                route,
                packet,
                activity_tick,
            } => self.collect_endpoint(route, packet, activity_tick, drops),
        }
    }

    fn collect_endpoint(
        &mut self,
        route: DataplaneEndpointDataRoute,
        packet: Vec<u8>,
        activity_tick: ActivityTick,
        drops: &mut Vec<DataplaneTunOutboundDrop>,
    ) {
        let route_changed = self
            .endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.route != route || endpoint.activity_tick != activity_tick);
        if route_changed {
            self.flush_endpoint(drops);
        }

        if self.endpoint.is_none() {
            self.endpoint = Some(TunEndpointDataCollector {
                route: route.clone(),
                activity_tick,
                builder: EndpointDataBulkBodyBuilder::new(),
            });
        }

        let payload_len = packet.len();
        let should_flush = self
            .endpoint
            .as_ref()
            .is_some_and(|endpoint| !endpoint.builder.can_push_packet(&packet));
        if should_flush {
            self.flush_endpoint(drops);
            self.endpoint = Some(TunEndpointDataCollector {
                route: route.clone(),
                activity_tick,
                builder: EndpointDataBulkBodyBuilder::new(),
            });
        }

        let endpoint = self
            .endpoint
            .as_mut()
            .expect("endpoint collector should exist");
        if !endpoint.builder.push_packet(&packet) {
            drops.push(DataplaneTunOutboundDrop::with_payload_len(
                Vec::new(),
                payload_len,
                DataplaneTunOutboundDropReason::InvalidPacket,
            ));
        }
    }

    fn collect_session(&mut self, packet: OutboundPacket) {
        collect_tun_session_packet(
            packet,
            &mut self.first_session_packet,
            &mut self.session_batch,
        );
    }

    fn flush_endpoint(&mut self, drops: &mut Vec<DataplaneTunOutboundDrop>) {
        let Some(endpoint) = self.endpoint.take() else {
            return;
        };
        let Some(body) = endpoint.builder.finish() else {
            return;
        };
        let routed = endpoint
            .route
            .route_bulk_bodies_with_activity_tick(vec![body], endpoint.activity_tick);
        for packet in routed.routed {
            self.collect_session(packet);
        }
        for (payload_len, reason) in routed.dropped {
            drops.push(DataplaneTunOutboundDrop::with_payload_len(
                Vec::new(),
                payload_len,
                tun_drop_reason_for_endpoint_data_drop(reason),
            ));
        }
    }

    fn flush<F>(&mut self, drops: &mut Vec<DataplaneTunOutboundDrop>, push: &mut F)
    where
        F: FnMut(DataplaneRoutedOutbound),
    {
        self.flush_endpoint(drops);
        flush_tun_session_packets(
            self.first_session_packet.take(),
            std::mem::take(&mut self.session_batch),
            push,
        );
    }
}

fn collect_tun_session_packet(
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

fn flush_tun_session_packets<F>(
    first: Option<OutboundPacket>,
    batch: Vec<OutboundPacket>,
    push: &mut F,
) where
    F: FnMut(DataplaneRoutedOutbound),
{
    if batch.is_empty() {
        if let Some(packet) = first {
            push(DataplaneRoutedOutbound::Packet(packet));
        }
    } else {
        push(DataplaneRoutedOutbound::Batch(batch));
    }
}

fn tun_drop_reason_for_endpoint_data_drop(
    reason: DataplaneEndpointDataDropReason,
) -> DataplaneTunOutboundDropReason {
    match reason {
        DataplaneEndpointDataDropReason::InvalidPayload => {
            DataplaneTunOutboundDropReason::InvalidPacket
        }
        DataplaneEndpointDataDropReason::NoRoute => DataplaneTunOutboundDropReason::NoRoute,
        DataplaneEndpointDataDropReason::StaleQueuedBatch => {
            DataplaneTunOutboundDropReason::NoRoute
        }
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
    path: TransportPath,
    payload_len: usize,
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
            path: packet.path,
            payload_len: packet.payload.len(),
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

    pub(crate) fn path(&self) -> TransportPath {
        self.path.clone()
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> DataplaneRawIngressDropReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneOutputError {
    Unavailable,
    Backpressure,
    StaleQueuedBulk,
    NoRoute,
    InvalidPacket,
    MtuExceeded,
    TransportFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneOutputDrop {
    owner: OwnerId,
    counter: u64,
    ingress_seq: u64,
    target: OutputTarget,
    path: Option<TransportPath>,
    payload_len: usize,
    reason: DataplaneOutputError,
}

impl DataplaneOutputDrop {
    pub(crate) fn from_output(output: &PacketOutput, reason: DataplaneOutputError) -> Self {
        Self {
            owner: output.owner,
            counter: output.counter,
            ingress_seq: output.ingress_seq,
            target: output.target,
            path: output.path.clone(),
            payload_len: output.payload.len(),
            reason,
        }
    }

    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn ingress_seq(&self) -> u64 {
        self.ingress_seq
    }

    pub(crate) fn target(&self) -> OutputTarget {
        self.target
    }

    pub(crate) fn path(&self) -> Option<TransportPath> {
        self.path.clone()
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
        match self.owner.protocol {
            PacketProtocol::Fmp => self.payload.get(FMP_ESTABLISHED_HEADER_SIZE..),
            PacketProtocol::Fsp => {
                let header = FspWireHeader::parse(&self.payload).ok()?;
                self.payload.get(header.ciphertext_offset()..)
            }
        }
    }

    pub(crate) fn into_opened_payload(mut self) -> Result<PacketBuffer, Self> {
        match self.take_opened_payload() {
            Some(payload) => Ok(payload),
            None => Err(self),
        }
    }

    fn opened_payload_header_len(&self) -> Option<usize> {
        let header_len = match self.owner.protocol {
            PacketProtocol::Fmp => FMP_ESTABLISHED_HEADER_SIZE,
            PacketProtocol::Fsp => match FspWireHeader::parse(&self.payload) {
                Ok(header) => header.ciphertext_offset(),
                Err(_) => return None,
            },
        };
        if self.payload.len() < header_len {
            return None;
        }
        Some(header_len)
    }

    fn take_opened_payload(&mut self) -> Option<PacketBuffer> {
        let header_len = self.opened_payload_header_len()?;
        if !self.payload.trim_front(header_len) {
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

pub(crate) trait DataplaneTunOutput {
    fn send_tun(
        &mut self,
        output: &PacketOutput,
        payload: PacketBuffer,
    ) -> Result<(), DataplaneOutputError>;

    fn send_tun_batch(
        &mut self,
        outputs: &mut Vec<(PacketOutput, PacketBuffer)>,
        drops: &mut Vec<DataplaneOutputDrop>,
    ) -> usize {
        let mut sent = 0usize;
        for (output, payload) in outputs.drain(..) {
            let mut drop =
                DataplaneOutputDrop::from_output(&output, DataplaneOutputError::Unavailable);
            match self.send_tun(&output, payload) {
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

impl<T: DataplaneTunOutput + ?Sized> DataplaneTunOutput for &mut T {
    fn send_tun(
        &mut self,
        output: &PacketOutput,
        payload: PacketBuffer,
    ) -> Result<(), DataplaneOutputError> {
        (**self).send_tun(output, payload)
    }
}

#[derive(Debug)]
pub(crate) struct DataplaneTunTxOutput<'a> {
    tx: &'a crate::upper::tun::TunTx,
}

impl<'a> DataplaneTunTxOutput<'a> {
    pub(crate) fn new(tx: &'a crate::upper::tun::TunTx) -> Self {
        Self { tx }
    }
}

impl DataplaneTunOutput for DataplaneTunTxOutput<'_> {
    fn send_tun(
        &mut self,
        output: &PacketOutput,
        payload: PacketBuffer,
    ) -> Result<(), DataplaneOutputError> {
        let lane = match output.lane() {
            Lane::Priority => crate::upper::tun::TunWriteLane::Priority,
            Lane::Bulk => crate::upper::tun::TunWriteLane::Bulk,
        };
        self.tx
            .send_with_lane(payload, lane)
            .map_err(|error| dataplane_output_error_for_tun_write(error.kind()))
    }

    fn send_tun_batch(
        &mut self,
        outputs: &mut Vec<(PacketOutput, PacketBuffer)>,
        drops: &mut Vec<DataplaneOutputDrop>,
    ) -> usize {
        if outputs.is_empty() {
            return 0;
        }

        let mut output_meta = Vec::with_capacity(outputs.len());
        let mut packets = Vec::with_capacity(outputs.len());
        for (output, payload) in outputs.drain(..) {
            let lane = tun_write_lane_for_output(&output);
            output_meta.push(output);
            packets.push((payload, lane));
        }

        let failures = self.tx.send_batch_with_lanes(packets);
        let failure_count = failures.len();
        for failure in failures {
            if let Some(output) = output_meta.get(failure.index) {
                drops.push(DataplaneOutputDrop::from_output(
                    output,
                    dataplane_output_error_for_tun_write(failure.kind),
                ));
            }
        }
        output_meta.len().saturating_sub(failure_count)
    }
}

fn tun_write_lane_for_output(output: &PacketOutput) -> crate::upper::tun::TunWriteLane {
    match output.lane() {
        Lane::Priority => crate::upper::tun::TunWriteLane::Priority,
        Lane::Bulk => crate::upper::tun::TunWriteLane::Bulk,
    }
}

fn dataplane_output_error_for_tun_write(
    kind: crate::upper::tun::TunWriteErrorKind,
) -> DataplaneOutputError {
    match kind {
        crate::upper::tun::TunWriteErrorKind::Closed => DataplaneOutputError::Unavailable,
        crate::upper::tun::TunWriteErrorKind::BulkFull => DataplaneOutputError::Backpressure,
    }
}

pub(crate) trait DataplaneEndpointOutput {
    fn send_endpoint(
        &mut self,
        output: &PacketOutput,
        payload: PacketBuffer,
    ) -> Result<(), DataplaneOutputError>;

    fn send_endpoint_batch(
        &mut self,
        outputs: &mut Vec<(PacketOutput, PacketBuffer)>,
        drops: &mut Vec<DataplaneOutputDrop>,
    ) -> usize {
        let mut sent = 0usize;
        for (output, payload) in outputs.drain(..) {
            let mut drop =
                DataplaneOutputDrop::from_output(&output, DataplaneOutputError::Unavailable);
            match self.send_endpoint(&output, payload) {
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

impl<T: DataplaneEndpointOutput + ?Sized> DataplaneEndpointOutput for &mut T {
    fn send_endpoint(
        &mut self,
        output: &PacketOutput,
        payload: PacketBuffer,
    ) -> Result<(), DataplaneOutputError> {
        (**self).send_endpoint(output, payload)
    }
}

#[derive(Debug)]
pub(crate) struct DataplaneEndpointEventOutput<'a> {
    tx: &'a EndpointEventSender,
}

impl<'a> DataplaneEndpointEventOutput<'a> {
    pub(crate) fn new(tx: &'a EndpointEventSender) -> Self {
        Self { tx }
    }
}

impl DataplaneEndpointOutput for DataplaneEndpointEventOutput<'_> {
    fn send_endpoint(
        &mut self,
        output: &PacketOutput,
        payload: PacketBuffer,
    ) -> Result<(), DataplaneOutputError> {
        let source_addr = output.owner().node_addr();
        let Some(source_peer) = output.source_peer() else {
            return Err(DataplaneOutputError::NoRoute);
        };
        if source_peer.node_addr() != &source_addr {
            return Err(DataplaneOutputError::NoRoute);
        }

        self.tx
            .send(NodeEndpointEvent {
                messages: vec![EndpointDataDelivery {
                    source_peer,
                    payload,
                    enqueued_at_ms: crate::time::now_ms(),
                }],
                queued_at: crate::perf_profile::stamp(),
            })
            .map_err(|_| DataplaneOutputError::Unavailable)
    }

    fn send_endpoint_batch(
        &mut self,
        outputs: &mut Vec<(PacketOutput, PacketBuffer)>,
        drops: &mut Vec<DataplaneOutputDrop>,
    ) -> usize {
        let mut messages = Vec::with_capacity(outputs.len());
        let mut unavailable_drops = Vec::with_capacity(outputs.len());
        let enqueued_at_ms = crate::time::now_ms();
        for (output, payload) in outputs.drain(..) {
            let source_addr = output.owner().node_addr();
            let Some(source_peer) = output.source_peer() else {
                drops.push(DataplaneOutputDrop::from_output(
                    &output,
                    DataplaneOutputError::NoRoute,
                ));
                continue;
            };
            if source_peer.node_addr() != &source_addr {
                drops.push(DataplaneOutputDrop::from_output(
                    &output,
                    DataplaneOutputError::NoRoute,
                ));
                continue;
            }

            unavailable_drops.push(DataplaneOutputDrop::from_output(
                &output,
                DataplaneOutputError::Unavailable,
            ));
            messages.push(EndpointDataDelivery {
                source_peer,
                payload,
                enqueued_at_ms,
            });
        }
        if messages.is_empty() {
            return 0;
        }

        let sent = messages.len();
        match self.tx.send(NodeEndpointEvent {
            messages,
            queued_at: crate::perf_profile::stamp(),
        }) {
            Ok(()) => sent,
            Err(_) => {
                drops.append(&mut unavailable_drops);
                0
            }
        }
    }
}

#[derive(Debug)]
struct DataplaneLiveOutputSink<'a, Tun, Endpoint> {
    tun: Tun,
    endpoint: Endpoint,
    transport: &'a mut DataplaneTransportSendGroups,
    stale_bulk_output_drop_ms: u64,
}

impl<'a, Tun, Endpoint> DataplaneLiveOutputSink<'a, Tun, Endpoint> {
    fn new(
        tun: Tun,
        endpoint: Endpoint,
        transport: &'a mut DataplaneTransportSendGroups,
    ) -> Self {
        Self {
            tun,
            endpoint,
            transport,
            stale_bulk_output_drop_ms: crate::node::ENDPOINT_STALE_DATA_DROP_MS,
        }
    }
}

impl<Tun, Endpoint> DataplaneOutputSink for DataplaneLiveOutputSink<'_, Tun, Endpoint>
where
    Tun: DataplaneTunOutput,
    Endpoint: DataplaneEndpointOutput,
{
    fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<DataplaneOutputDrop>) -> usize
    where
        I: IntoIterator<Item = PacketOutput>,
    {
        let mut sent = 0usize;
        let mut endpoint_batch = Vec::new();
        let mut tun_batch = Vec::new();
        for output in outputs {
            match output.target() {
                OutputTarget::Endpoint => {
                    if !tun_batch.is_empty() {
                        sent =
                            sent.saturating_add(self.tun.send_tun_batch(&mut tun_batch, drops));
                    }
                    match self.prepare_opened_output(output, drops) {
                        Some(endpoint) => endpoint_batch.push(endpoint),
                        None => {
                            if !endpoint_batch.is_empty() {
                                sent = sent.saturating_add(
                                    self.endpoint
                                        .send_endpoint_batch(&mut endpoint_batch, drops),
                                );
                            }
                        }
                    }
                    continue;
                }
                OutputTarget::Tun => {
                    if !endpoint_batch.is_empty() {
                        sent = sent.saturating_add(
                            self.endpoint
                                .send_endpoint_batch(&mut endpoint_batch, drops),
                        );
                    }
                    if let Some(tun) = self.prepare_opened_output(output, drops) {
                        tun_batch.push(tun);
                    }
                    continue;
                }
                _ => {}
            }

            if !endpoint_batch.is_empty() {
                sent = sent.saturating_add(
                    self.endpoint
                        .send_endpoint_batch(&mut endpoint_batch, drops),
                );
            }
            if !tun_batch.is_empty() {
                sent = sent.saturating_add(self.tun.send_tun_batch(&mut tun_batch, drops));
            }
            let mut drop =
                DataplaneOutputDrop::from_output(&output, DataplaneOutputError::Unavailable);
            match self.send_unbatched_output(output) {
                Ok(()) => sent = sent.saturating_add(1),
                Err(reason) => {
                    drop.reason = reason;
                    drops.push(drop);
                }
            }
        }
        if !endpoint_batch.is_empty() {
            sent = sent.saturating_add(
                self.endpoint
                    .send_endpoint_batch(&mut endpoint_batch, drops),
            );
        }
        if !tun_batch.is_empty() {
            sent = sent.saturating_add(self.tun.send_tun_batch(&mut tun_batch, drops));
        }
        sent
    }
}

impl<Tun, Endpoint> DataplaneLiveOutputSink<'_, Tun, Endpoint>
where
    Tun: DataplaneTunOutput,
    Endpoint: DataplaneEndpointOutput,
{
    fn prepare_opened_output(
        &mut self,
        mut output: PacketOutput,
        drops: &mut Vec<DataplaneOutputDrop>,
    ) -> Option<(PacketOutput, PacketBuffer)> {
        if stale_bulk_output(&output, self.stale_bulk_output_drop_ms) {
            record_stale_bulk_output_drop(output.target());
            drops.push(DataplaneOutputDrop::from_output(
                &output,
                DataplaneOutputError::StaleQueuedBulk,
            ));
            return None;
        }
        let payload = match output.target() {
            OutputTarget::Tun | OutputTarget::Endpoint => output.take_opened_payload(),
            OutputTarget::Transport
            | OutputTarget::SessionIngress { .. }
            | OutputTarget::SessionPayload { .. } => None,
        };
        match payload {
            Some(payload) => Some((output, payload)),
            None => {
                drops.push(DataplaneOutputDrop::from_output(
                    &output,
                    DataplaneOutputError::Unavailable,
                ));
                None
            }
        }
    }

    fn send_unbatched_output(
        &mut self,
        output: PacketOutput,
    ) -> Result<(), DataplaneOutputError> {
        if stale_bulk_output(&output, self.stale_bulk_output_drop_ms) {
            record_stale_bulk_output_drop(output.target());
            return Err(DataplaneOutputError::StaleQueuedBulk);
        }

        match output.target {
            OutputTarget::Transport => {
                let Some((transport_id, remote_addr)) =
                    output.path.as_ref().and_then(|path| match path {
                        TransportPath::Live {
                            transport_id,
                            remote_addr,
                        } => Some((*transport_id, remote_addr.clone())),
                    })
                else {
                    return Err(DataplaneOutputError::NoRoute);
                };
                self.transport
                    .send_transport(transport_id, remote_addr, output)
            }
            OutputTarget::SessionIngress { .. }
            | OutputTarget::SessionPayload { .. }
            | OutputTarget::Tun
            | OutputTarget::Endpoint => Err(DataplaneOutputError::NoRoute),
        }
    }
}

fn stale_bulk_output(output: &PacketOutput, max_age_ms: u64) -> bool {
    output.lane() == Lane::Bulk
        && max_age_ms > 0
        && matches!(output.target(), OutputTarget::Tun | OutputTarget::Endpoint)
        && output
            .activity_tick
            .is_some_and(|tick| crate::time::now_ms().saturating_sub(tick.get()) > max_age_ms)
}

fn record_stale_bulk_output_drop(target: OutputTarget) {
    let event = match target {
        OutputTarget::Tun => crate::perf_profile::Event::TunWriteBulkDropped,
        OutputTarget::Endpoint => crate::perf_profile::Event::EndpointEventBulkDropped,
        OutputTarget::Transport
        | OutputTarget::SessionIngress { .. }
        | OutputTarget::SessionPayload { .. } => return,
    };
    crate::perf_profile::record_event(event);
}

fn dataplane_output_error_from_session_handoff(
    error: DataplaneSessionHandoffError,
) -> DataplaneOutputError {
    match error {
        DataplaneSessionHandoffError::InvalidPacket => DataplaneOutputError::InvalidPacket,
        DataplaneSessionHandoffError::NoRoute => DataplaneOutputError::NoRoute,
    }
}
