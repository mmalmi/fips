
#[derive(Debug, Default)]
pub(crate) struct PacketMover2LiveOutboundFirsts {
    endpoint_priority: Option<NodeEndpointCommand>,
    endpoint_bulk: Option<NodeEndpointCommand>,
    tun_packet: Option<Vec<u8>>,
}

impl PacketMover2LiveOutboundFirsts {
    pub(crate) fn with_endpoint_priority(mut self, command: Option<NodeEndpointCommand>) -> Self {
        self.endpoint_priority = command;
        self
    }

    pub(crate) fn with_endpoint_bulk(mut self, command: Option<NodeEndpointCommand>) -> Self {
        self.endpoint_bulk = command;
        self
    }

    pub(crate) fn with_tun_packet(mut self, packet: Option<Vec<u8>>) -> Self {
        self.tun_packet = packet;
        self
    }
}

pub(crate) struct PacketMover2RouteTableOutboundSource<'a, Routes> {
    first_endpoint_priority: Option<NodeEndpointCommand>,
    first_endpoint_bulk: Option<NodeEndpointCommand>,
    first_tun_packet: Option<Vec<u8>>,
    endpoint_priority_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    endpoint_bulk_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    endpoint_limit: usize,
    tun_outbound_rx: &'a mut TunOutboundRx,
    tun_limit: usize,
    routes: &'a mut Routes,
    endpoint_drops: Vec<PacketMover2EndpointCommandDrop>,
    endpoint_deferred_commands: Vec<NodeEndpointCommand>,
    endpoint_routed_destinations: Vec<PacketMover2EndpointRoutedDestination>,
    tun_drops: Vec<PacketMover2TunOutboundDrop>,
    endpoint_drained: usize,
    tun_drained: usize,
    endpoint_stale_bulk_drop_ms: u64,
}

#[derive(Default)]
struct PacketMover2RouteTableOutboundBuffers {
    endpoint_drops: Vec<PacketMover2EndpointCommandDrop>,
    endpoint_deferred_commands: Vec<NodeEndpointCommand>,
    endpoint_routed_destinations: Vec<PacketMover2EndpointRoutedDestination>,
    tun_drops: Vec<PacketMover2TunOutboundDrop>,
}

impl<'a, Routes> PacketMover2RouteTableOutboundSource<'a, Routes> {
    pub(crate) fn new(
        endpoint_priority_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &'a mut TunOutboundRx,
        tun_limit: usize,
        routes: &'a mut Routes,
    ) -> Self {
        Self {
            first_endpoint_priority: None,
            first_endpoint_bulk: None,
            first_tun_packet: None,
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            routes,
            endpoint_drops: Vec::new(),
            endpoint_deferred_commands: Vec::new(),
            endpoint_routed_destinations: Vec::new(),
            tun_drops: Vec::new(),
            endpoint_drained: 0,
            tun_drained: 0,
            endpoint_stale_bulk_drop_ms: crate::node::endpoint_stale_bulk_drop_ms(),
        }
    }

    pub(crate) fn with_firsts(mut self, firsts: PacketMover2LiveOutboundFirsts) -> Self {
        self.first_endpoint_priority = firsts.endpoint_priority;
        self.first_endpoint_bulk = firsts.endpoint_bulk;
        self.first_tun_packet = firsts.tun_packet;
        self
    }

    fn with_report_buffers(mut self, buffers: PacketMover2RouteTableOutboundBuffers) -> Self {
        self.endpoint_drops = buffers.endpoint_drops;
        self.endpoint_deferred_commands = buffers.endpoint_deferred_commands;
        self.endpoint_routed_destinations = buffers.endpoint_routed_destinations;
        self.tun_drops = buffers.tun_drops;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint_stale_bulk_drop_ms(mut self, max_age_ms: u64) -> Self {
        self.endpoint_stale_bulk_drop_ms = max_age_ms;
        self
    }

    fn take_report_buffers(&mut self) -> PacketMover2RouteTableOutboundBuffers {
        PacketMover2RouteTableOutboundBuffers {
            endpoint_drops: std::mem::take(&mut self.endpoint_drops),
            endpoint_deferred_commands: std::mem::take(&mut self.endpoint_deferred_commands),
            endpoint_routed_destinations: std::mem::take(&mut self.endpoint_routed_destinations),
            tun_drops: std::mem::take(&mut self.tun_drops),
        }
    }

    fn take_endpoint_command_drops(&mut self) -> Vec<PacketMover2EndpointCommandDrop> {
        std::mem::take(&mut self.endpoint_drops)
    }

    fn take_endpoint_deferred_commands(&mut self) -> Vec<NodeEndpointCommand> {
        std::mem::take(&mut self.endpoint_deferred_commands)
    }

    fn take_endpoint_routed_destinations(
        &mut self,
    ) -> Vec<PacketMover2EndpointRoutedDestination> {
        std::mem::take(&mut self.endpoint_routed_destinations)
    }

    fn take_tun_outbound_drops(&mut self) -> Vec<PacketMover2TunOutboundDrop> {
        std::mem::take(&mut self.tun_drops)
    }

    fn take_firsts(&mut self) -> PacketMover2LiveOutboundFirsts {
        PacketMover2LiveOutboundFirsts::default()
            .with_endpoint_priority(self.first_endpoint_priority.take())
            .with_endpoint_bulk(self.first_endpoint_bulk.take())
            .with_tun_packet(self.first_tun_packet.take())
    }

    fn endpoint_drained(&self) -> usize {
        self.endpoint_drained
    }

    fn tun_drained(&self) -> usize {
        self.tun_drained
    }
}

impl<Routes> PacketMover2RouteTableOutboundSource<'_, Routes>
where
    Routes: PacketMover2EndpointCommandRouter + PacketMover2TunOutboundRouter,
{
    fn cache_first_tun_packet_priority_first(&mut self) {
        if self.first_tun_packet.is_none()
            && let Ok(packet) = self.tun_outbound_rx.try_recv_priority_first()
        {
            self.first_tun_packet = Some(packet);
        }
    }

    fn first_tun_packet_is_priority(&mut self) -> bool {
        self.cache_first_tun_packet_priority_first();
        self.first_tun_packet
            .as_deref()
            .is_some_and(tun_packet_is_priority)
    }

    fn drain_endpoint<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
    {
        let mut drained_cost = 0usize;
        let mut stale_bulk_drop_trigger_drained = false;
        if drained_cost < limit {
            if let Some(command) = self.first_endpoint_priority.take() {
                stale_bulk_drop_trigger_drained |= command.triggers_stale_bulk_drop();
                drained_cost = drained_cost.saturating_add(command.drain_cost());
                route_endpoint_command_with_router(
                    command,
                    self.routes,
                    &mut self.endpoint_drops,
                    &mut self.endpoint_deferred_commands,
                    &mut self.endpoint_routed_destinations,
                    &mut push,
                );
            }
        }
        while drained_cost < limit {
            let Ok(command) = self.endpoint_priority_rx.try_recv() else {
                break;
            };
            stale_bulk_drop_trigger_drained |= command.triggers_stale_bulk_drop();
            drained_cost = drained_cost.saturating_add(command.drain_cost());
            route_endpoint_command_with_router(
                command,
                self.routes,
                &mut self.endpoint_drops,
                &mut self.endpoint_deferred_commands,
                &mut self.endpoint_routed_destinations,
                &mut push,
            );
        }
        let mut tun_priority_waiting = false;
        let mut tun_liveness_waiting = false;
        if drained_cost < limit {
            tun_priority_waiting = self.first_tun_packet_is_priority();
            tun_liveness_waiting = tun_priority_waiting
                && self
                    .first_tun_packet
                    .as_deref()
                    .is_some_and(crate::node::endpoint_payload_is_liveness_probe);
            stale_bulk_drop_trigger_drained |= tun_liveness_waiting;
        }
        if stale_bulk_drop_trigger_drained {
            let mut drop_limit = limit.saturating_sub(drained_cost);
            if tun_liveness_waiting {
                drop_limit = drop_limit.saturating_sub(1);
            }
            let dropped_cost = self.drop_stale_bulk_endpoint_commands(drop_limit);
            drained_cost = drained_cost.saturating_add(dropped_cost.min(drop_limit));
            return drained_cost;
        }
        if tun_priority_waiting {
            return drained_cost;
        }
        if drained_cost < limit {
            if let Some(command) = self.first_endpoint_bulk.take() {
                drained_cost = drained_cost.saturating_add(command.drain_cost());
                self.route_or_drop_bulk_endpoint_command(
                    command,
                    stale_bulk_drop_trigger_drained,
                    &mut push,
                );
            }
        }
        while drained_cost < limit {
            let Ok(command) = self.endpoint_bulk_rx.try_recv() else {
                break;
            };
            drained_cost = drained_cost.saturating_add(command.drain_cost());
            self.route_or_drop_bulk_endpoint_command(
                command,
                stale_bulk_drop_trigger_drained,
                &mut push,
            );
        }
        drained_cost
    }

    fn drop_stale_bulk_endpoint_commands(&mut self, limit: usize) -> usize {
        let mut drained_cost = 0usize;
        let now_ms = crate::time::now_ms();
        while drained_cost < limit {
            let command = match self.first_endpoint_bulk.take() {
                Some(command) => command,
                None => match self.endpoint_bulk_rx.try_recv() {
                    Ok(command) => command,
                    Err(_) => break,
                },
            };
            let drop_count = stale_bulk_endpoint_command_drop_count(
                &command,
                now_ms,
                self.endpoint_stale_bulk_drop_ms,
            );
            if drop_count == 0 {
                self.first_endpoint_bulk = Some(command);
                break;
            }

            drained_cost = drained_cost.saturating_add(command.drain_cost());
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::EndpointCommandBulkDropped,
                drop_count as u64,
            );
            drop_stale_bulk_endpoint_command(command, &mut self.endpoint_drops);
        }
        drained_cost
    }

    fn route_or_drop_bulk_endpoint_command<F>(
        &mut self,
        command: NodeEndpointCommand,
        stale_bulk_drop_trigger_drained: bool,
        mut push: F,
    ) where
        F: FnMut(OutboundPacket),
    {
        if stale_bulk_drop_trigger_drained {
            let drop_count = stale_bulk_endpoint_command_drop_count(
                &command,
                crate::time::now_ms(),
                self.endpoint_stale_bulk_drop_ms,
            );
            if drop_count > 0 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::EndpointCommandBulkDropped,
                    drop_count as u64,
                );
                drop_stale_bulk_endpoint_command(command, &mut self.endpoint_drops);
                return;
            }
        }

        route_endpoint_command_with_router(
            command,
            self.routes,
            &mut self.endpoint_drops,
            &mut self.endpoint_deferred_commands,
            &mut self.endpoint_routed_destinations,
            &mut push,
        );
    }

    fn drain_tun<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
    {
        let mut drained = 0usize;
        self.cache_first_tun_packet_priority_first();
        if self
            .first_tun_packet
            .as_deref()
            .is_some_and(crate::node::endpoint_payload_is_liveness_probe)
            && limit > 1
        {
            drained = drained.saturating_add(
                self.tun_outbound_rx
                    .drop_stale_bulk(self.endpoint_stale_bulk_drop_ms, limit.saturating_sub(1)),
            );
        }
        if drained < limit {
            if let Some(packet) = self.first_tun_packet.take() {
                route_tun_outbound_packet_with_router(
                    packet,
                    self.routes,
                    &mut self.tun_drops,
                    &mut push,
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
                &mut self.tun_drops,
                &mut push,
            );
            drained += 1;
        }
        drained
    }
}

impl<Routes> PacketMover2OutboundSource for PacketMover2RouteTableOutboundSource<'_, Routes>
where
    Routes: PacketMover2EndpointCommandRouter + PacketMover2TunOutboundRouter,
{
    fn drain_outbound<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
    {
        let endpoint_limit = self.endpoint_limit.min(limit);
        let endpoint_drained = self.drain_endpoint(endpoint_limit, &mut push);
        self.endpoint_drained = self.endpoint_drained.saturating_add(endpoint_drained);
        let remaining = limit.saturating_sub(endpoint_drained.min(endpoint_limit));
        let tun_limit = self.tun_limit.min(remaining);
        let tun_drained = self.drain_tun(tun_limit, push);
        self.tun_drained = self.tun_drained.saturating_add(tun_drained);
        endpoint_drained.saturating_add(tun_drained)
    }
}

fn tun_packet_is_priority(packet: &[u8]) -> bool {
    crate::node::endpoint_payload_is_liveness_probe(packet)
        || crate::node::endpoint_payload_is_latency_sensitive(packet)
}

impl PacketMover2RawIngressSource for VecDeque<PacketMover2RawIngress> {
    fn drain_raw_ingress<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(PacketMover2RawIngress),
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

impl PacketMover2OutboundSource for VecDeque<OutboundPacket> {
    fn drain_outbound<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
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
pub(crate) enum PacketMover2RawIngressDropReason {
    Wire(WirePreflightError),
    Unrouted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2RawIngressDrop {
    protocol: PacketProtocol,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    path: TransportPath,
    payload_len: usize,
    reason: PacketMover2RawIngressDropReason,
}

impl PacketMover2RawIngressDrop {
    fn from_packet(
        packet: PacketMover2RawIngress,
        reason: PacketMover2RawIngressDropReason,
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

    pub(crate) fn reason(&self) -> PacketMover2RawIngressDropReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2OutputError {
    Unavailable,
    Backpressure,
    StaleQueuedBulk,
    NoRoute,
    InvalidPacket,
    MtuExceeded,
    TransportFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2OutputDrop {
    owner: OwnerId,
    counter: u64,
    ingress_seq: u64,
    target: OutputTarget,
    path: Option<TransportPath>,
    payload_len: usize,
    reason: PacketMover2OutputError,
}

impl PacketMover2OutputDrop {
    pub(crate) fn from_output(output: &PacketOutput, reason: PacketMover2OutputError) -> Self {
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

    pub(crate) fn reason(&self) -> PacketMover2OutputError {
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
        let header_len = match self.owner.protocol {
            PacketProtocol::Fmp => FMP_ESTABLISHED_HEADER_SIZE,
            PacketProtocol::Fsp => match FspWireHeader::parse(&self.payload) {
                Ok(header) => header.ciphertext_offset(),
                Err(_) => return Err(self),
            },
        };
        if self.payload.len() < header_len {
            return Err(self);
        }
        self.payload.drain(..header_len);
        Ok(self.payload)
    }
}

pub(crate) trait PacketMover2OutputSink {
    fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError>;

    fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<PacketMover2OutputDrop>) -> usize
    where
        I: IntoIterator<Item = PacketOutput>,
    {
        let mut sent = 0;
        for output in outputs {
            let mut drop =
                PacketMover2OutputDrop::from_output(&output, PacketMover2OutputError::Unavailable);
            match self.send(output) {
                Ok(()) => sent += 1,
                Err(reason) => {
                    drop.reason = reason;
                    drops.push(drop);
                }
            }
        }
        sent
    }
}

pub(crate) trait PacketMover2TunOutput {
    fn send_tun(
        &mut self,
        output: &PacketOutput,
        payload: &[u8],
    ) -> Result<(), PacketMover2OutputError>;
}

impl<T: PacketMover2TunOutput + ?Sized> PacketMover2TunOutput for &mut T {
    fn send_tun(
        &mut self,
        output: &PacketOutput,
        payload: &[u8],
    ) -> Result<(), PacketMover2OutputError> {
        (**self).send_tun(output, payload)
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2TunTxOutput<'a> {
    tx: &'a crate::upper::tun::TunTx,
}

impl<'a> PacketMover2TunTxOutput<'a> {
    pub(crate) fn new(tx: &'a crate::upper::tun::TunTx) -> Self {
        Self { tx }
    }
}

impl PacketMover2TunOutput for PacketMover2TunTxOutput<'_> {
    fn send_tun(
        &mut self,
        output: &PacketOutput,
        payload: &[u8],
    ) -> Result<(), PacketMover2OutputError> {
        let lane = match output.lane() {
            Lane::Priority => crate::upper::tun::TunWriteLane::Priority,
            Lane::Bulk => crate::upper::tun::TunWriteLane::Bulk,
        };
        self.tx
            .send_with_lane(payload.to_vec(), lane)
            .map_err(|error| match error.kind() {
                crate::upper::tun::TunWriteErrorKind::Closed => {
                    PacketMover2OutputError::Unavailable
                }
                crate::upper::tun::TunWriteErrorKind::BulkFull => {
                    PacketMover2OutputError::Backpressure
                }
            })
    }
}

pub(crate) trait PacketMover2EndpointOutput {
    fn send_endpoint(
        &mut self,
        output: &PacketOutput,
        payload: &[u8],
    ) -> Result<(), PacketMover2OutputError>;
}

impl<T: PacketMover2EndpointOutput + ?Sized> PacketMover2EndpointOutput for &mut T {
    fn send_endpoint(
        &mut self,
        output: &PacketOutput,
        payload: &[u8],
    ) -> Result<(), PacketMover2OutputError> {
        (**self).send_endpoint(output, payload)
    }
}

pub(crate) trait PacketMover2EndpointIdentityResolver {
    fn resolve_endpoint_peer(&mut self, source_addr: &NodeAddr) -> Option<PeerIdentity>;
}

impl<F> PacketMover2EndpointIdentityResolver for F
where
    F: FnMut(&NodeAddr) -> Option<PeerIdentity>,
{
    fn resolve_endpoint_peer(&mut self, source_addr: &NodeAddr) -> Option<PeerIdentity> {
        self(source_addr)
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2EndpointEventOutput<'a, Resolver> {
    tx: &'a EndpointEventSender,
    resolver: Resolver,
}

impl<'a, Resolver> PacketMover2EndpointEventOutput<'a, Resolver> {
    pub(crate) fn new(tx: &'a EndpointEventSender, resolver: Resolver) -> Self {
        Self { tx, resolver }
    }
}

impl<Resolver> PacketMover2EndpointOutput for PacketMover2EndpointEventOutput<'_, Resolver>
where
    Resolver: PacketMover2EndpointIdentityResolver,
{
    fn send_endpoint(
        &mut self,
        output: &PacketOutput,
        payload: &[u8],
    ) -> Result<(), PacketMover2OutputError> {
        let Some(source_addr) = output.owner().node_addr() else {
            return Err(PacketMover2OutputError::NoRoute);
        };
        let Some(source_peer) = self.resolver.resolve_endpoint_peer(&source_addr) else {
            return Err(PacketMover2OutputError::NoRoute);
        };
        if source_peer.node_addr() != &source_addr {
            return Err(PacketMover2OutputError::NoRoute);
        }

        self.tx
            .send(NodeEndpointEvent::Data {
                source_peer,
                payload: payload.to_vec().into(),
                enqueued_at_ms: crate::time::now_ms(),
                queued_at: crate::perf_profile::stamp(),
            })
            .map_err(|_| PacketMover2OutputError::Unavailable)
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2LiveOutputSink<Tun, Endpoint, Transport> {
    tun: Tun,
    endpoint: Endpoint,
    transport: Transport,
    stale_bulk_output_drop_ms: u64,
}

impl<Tun, Endpoint, Transport> PacketMover2LiveOutputSink<Tun, Endpoint, Transport> {
    pub(crate) fn new(tun: Tun, endpoint: Endpoint, transport: Transport) -> Self {
        Self {
            tun,
            endpoint,
            transport,
            stale_bulk_output_drop_ms: crate::node::endpoint_stale_bulk_drop_ms(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_stale_bulk_output_drop_ms(mut self, max_age_ms: u64) -> Self {
        self.stale_bulk_output_drop_ms = max_age_ms;
        self
    }
}

impl<Tun, Endpoint, Transport> PacketMover2OutputSink
    for PacketMover2LiveOutputSink<Tun, Endpoint, Transport>
where
    Tun: PacketMover2TunOutput,
    Endpoint: PacketMover2EndpointOutput,
    Transport: PacketMover2TransportOutput,
{
    fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError> {
        if stale_bulk_output(&output, self.stale_bulk_output_drop_ms) {
            record_stale_bulk_output_drop(output.target());
            return Err(PacketMover2OutputError::StaleQueuedBulk);
        }

        match output.target {
            OutputTarget::Tun => {
                let payload = output
                    .opened_payload()
                    .ok_or(PacketMover2OutputError::Unavailable)?;
                self.tun.send_tun(&output, payload)
            }
            OutputTarget::Endpoint => {
                let payload = output
                    .opened_payload()
                    .ok_or(PacketMover2OutputError::Unavailable)?;
                self.endpoint.send_endpoint(&output, payload)
            }
            OutputTarget::Transport => {
                let Some((transport_id, remote_addr)) =
                    output.path.as_ref().and_then(|path| match path {
                        TransportPath::Live {
                            transport_id,
                            remote_addr,
                        } => Some((*transport_id, remote_addr.clone())),
                        TransportPath::Scratch(_) => None,
                    })
                else {
                    return Err(PacketMover2OutputError::NoRoute);
                };
                self.transport
                    .send_transport(transport_id, remote_addr, output)
            }
            OutputTarget::SessionIngress { .. } | OutputTarget::SessionPayload { .. } => {
                Err(PacketMover2OutputError::NoRoute)
            }
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

fn packet_mover2_output_error_from_session_handoff(
    error: PacketMover2SessionHandoffError,
) -> PacketMover2OutputError {
    match error {
        PacketMover2SessionHandoffError::InvalidPacket => PacketMover2OutputError::InvalidPacket,
        PacketMover2SessionHandoffError::NoRoute => PacketMover2OutputError::NoRoute,
    }
}
