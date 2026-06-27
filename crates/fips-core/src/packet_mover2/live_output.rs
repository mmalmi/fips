
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
            tun_drops: Vec::new(),
        }
    }

    pub(crate) fn with_firsts(mut self, firsts: PacketMover2LiveOutboundFirsts) -> Self {
        self.first_endpoint_priority = firsts.endpoint_priority;
        self.first_endpoint_bulk = firsts.endpoint_bulk;
        self.first_tun_packet = firsts.tun_packet;
        self
    }

    fn take_endpoint_command_drops(&mut self) -> Vec<PacketMover2EndpointCommandDrop> {
        std::mem::take(&mut self.endpoint_drops)
    }

    fn take_endpoint_deferred_commands(&mut self) -> Vec<NodeEndpointCommand> {
        std::mem::take(&mut self.endpoint_deferred_commands)
    }

    fn take_tun_outbound_drops(&mut self) -> Vec<PacketMover2TunOutboundDrop> {
        std::mem::take(&mut self.tun_drops)
    }
}

impl<Routes> PacketMover2RouteTableOutboundSource<'_, Routes>
where
    Routes: PacketMover2EndpointCommandRouter + PacketMover2TunOutboundRouter,
{
    fn drain_endpoint<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
    {
        let mut drained_cost = 0usize;
        if drained_cost < limit {
            if let Some(command) = self.first_endpoint_priority.take() {
                drained_cost = drained_cost.saturating_add(command.drain_cost());
                route_endpoint_command_with_router(
                    command,
                    self.routes,
                    &mut self.endpoint_drops,
                    &mut self.endpoint_deferred_commands,
                    &mut push,
                );
            }
        }
        while drained_cost < limit {
            let Ok(command) = self.endpoint_priority_rx.try_recv() else {
                break;
            };
            drained_cost = drained_cost.saturating_add(command.drain_cost());
            route_endpoint_command_with_router(
                command,
                self.routes,
                &mut self.endpoint_drops,
                &mut self.endpoint_deferred_commands,
                &mut push,
            );
        }
        if drained_cost < limit {
            if let Some(command) = self.first_endpoint_bulk.take() {
                drained_cost = drained_cost.saturating_add(command.drain_cost());
                route_endpoint_command_with_router(
                    command,
                    self.routes,
                    &mut self.endpoint_drops,
                    &mut self.endpoint_deferred_commands,
                    &mut push,
                );
            }
        }
        while drained_cost < limit {
            let Ok(command) = self.endpoint_bulk_rx.try_recv() else {
                break;
            };
            drained_cost = drained_cost.saturating_add(command.drain_cost());
            route_endpoint_command_with_router(
                command,
                self.routes,
                &mut self.endpoint_drops,
                &mut self.endpoint_deferred_commands,
                &mut push,
            );
        }
        drained_cost
    }

    fn drain_tun<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
    {
        let mut drained = 0;
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
        let remaining = limit.saturating_sub(endpoint_drained.min(endpoint_limit));
        let tun_limit = self.tun_limit.min(remaining);
        let tun_drained = self.drain_tun(tun_limit, push);
        endpoint_drained.saturating_add(tun_drained)
    }
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
            PacketProtocol::Fsp => self.payload.get(FSP_HEADER_SIZE..),
        }
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
        _output: &PacketOutput,
        payload: &[u8],
    ) -> Result<(), PacketMover2OutputError> {
        self.tx
            .send(payload.to_vec())
            .map_err(|_| PacketMover2OutputError::Unavailable)
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
                queued_at: crate::perf_profile::stamp(),
            })
            .map_err(|_| PacketMover2OutputError::Unavailable)
    }
}

pub(crate) trait PacketMover2TransportOutput {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError>;
}

impl<T: PacketMover2TransportOutput + ?Sized> PacketMover2TransportOutput for &mut T {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError> {
        (**self).send_transport(transport_id, remote_addr, output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2TransportSendPlan {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    output: PacketOutput,
}

impl PacketMover2TransportSendPlan {
    pub(crate) fn new(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Self {
        Self {
            transport_id,
            remote_addr,
            output,
        }
    }

    pub(crate) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    pub(crate) fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    pub(crate) fn output(&self) -> &PacketOutput {
        &self.output
    }
}

#[derive(Debug, Default)]
pub(crate) struct PacketMover2TransportSendPlanOutput {
    plans: Vec<PacketMover2TransportSendPlan>,
}

impl PacketMover2TransportSendPlanOutput {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn plans(&self) -> &[PacketMover2TransportSendPlan] {
        &self.plans
    }

    pub(crate) fn take_plans(&mut self) -> Vec<PacketMover2TransportSendPlan> {
        std::mem::take(&mut self.plans)
    }
}

impl PacketMover2TransportOutput for PacketMover2TransportSendPlanOutput {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError> {
        self.plans.push(PacketMover2TransportSendPlan::new(
            transport_id,
            remote_addr,
            output,
        ));
        Ok(())
    }
}

pub(crate) trait PacketMover2TransportResolver {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle>;
}

impl PacketMover2TransportResolver for HashMap<TransportId, TransportHandle> {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        self.get(&transport_id)
    }
}

impl<T: PacketMover2TransportResolver + ?Sized> PacketMover2TransportResolver for &T {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        (**self).resolve_packet_mover2_transport(transport_id)
    }
}

pub(crate) async fn send_packet_mover2_transport_plans<R, I>(
    transports: &R,
    plans: I,
    drops: &mut Vec<PacketMover2OutputDrop>,
) -> usize
where
    R: PacketMover2TransportResolver + ?Sized,
    I: IntoIterator<Item = PacketMover2TransportSendPlan>,
{
    let mut sent = 0;
    for plan in plans {
        let mut drop = PacketMover2OutputDrop::from_output(
            plan.output(),
            PacketMover2OutputError::Unavailable,
        );
        let Some(transport) = transports.resolve_packet_mover2_transport(plan.transport_id) else {
            drop.reason = PacketMover2OutputError::NoRoute;
            drops.push(drop);
            continue;
        };
        match transport
            .send(plan.remote_addr(), plan.output().payload())
            .await
        {
            Ok(_) => sent += 1,
            Err(error) => {
                drop.reason = packet_mover2_output_error_for_transport(&error);
                drops.push(drop);
            }
        }
    }
    sent
}

fn packet_mover2_output_error_for_transport(error: &TransportError) -> PacketMover2OutputError {
    match error {
        TransportError::MtuExceeded { .. } => PacketMover2OutputError::MtuExceeded,
        error if error.is_local_route_unavailable() => PacketMover2OutputError::NoRoute,
        TransportError::NotStarted | TransportError::NotSupported(_) => {
            PacketMover2OutputError::Unavailable
        }
        _ => PacketMover2OutputError::TransportFailed,
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2LiveOutputSink<Tun, Endpoint, Transport> {
    tun: Tun,
    endpoint: Endpoint,
    transport: Transport,
}

impl<Tun, Endpoint, Transport> PacketMover2LiveOutputSink<Tun, Endpoint, Transport> {
    pub(crate) fn new(tun: Tun, endpoint: Endpoint, transport: Transport) -> Self {
        Self {
            tun,
            endpoint,
            transport,
        }
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
            OutputTarget::SessionIngress { .. } => Err(PacketMover2OutputError::NoRoute),
            OutputTarget::SessionPayload { local_addr } => {
                match packet_mover2_fsp_payload_delivery(&output, local_addr)
                    .map_err(packet_mover2_output_error_from_session_handoff)?
                {
                    PacketMover2FspPayloadDelivery::Tun(packet) => self.tun.send_tun(&output, &packet),
                    PacketMover2FspPayloadDelivery::Endpoint(payload) => {
                        self.endpoint.send_endpoint(&output, &payload)
                    }
                }
            }
        }
    }
}

fn packet_mover2_output_error_from_session_handoff(
    error: PacketMover2SessionHandoffError,
) -> PacketMover2OutputError {
    match error {
        PacketMover2SessionHandoffError::InvalidPacket => PacketMover2OutputError::InvalidPacket,
        PacketMover2SessionHandoffError::NoRoute => PacketMover2OutputError::NoRoute,
    }
}
