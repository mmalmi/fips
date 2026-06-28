#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2RawIngress {
    protocol: PacketProtocol,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    path: TransportPath,
    fsp_source: Option<NodeAddr>,
    previous_hop: Option<NodeAddr>,
    ce_flag: bool,
    path_mtu: u16,
    activity_tick: Option<ActivityTick>,
    payload: PacketBuffer,
}

impl PacketMover2RawIngress {
    pub(crate) fn from_received(
        protocol: PacketProtocol,
        path: TransportPath,
        packet: ReceivedPacket,
    ) -> Self {
        Self {
            protocol,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr,
            path,
            fsp_source: None,
            previous_hop: None,
            ce_flag: false,
            path_mtu: u16::MAX,
            activity_tick: Some(ActivityTick::new(packet.timestamp_ms)),
            payload: packet.data,
        }
    }

    pub(crate) fn from_live_received(protocol: PacketProtocol, packet: ReceivedPacket) -> Self {
        let path = TransportPath::live(packet.transport_id, packet.remote_addr.clone());
        Self::from_received(protocol, path, packet)
    }

    pub(crate) fn with_fsp_source(mut self, source_addr: NodeAddr) -> Self {
        self.fsp_source = Some(source_addr);
        self
    }

    pub(crate) fn with_previous_hop(mut self, previous_hop: NodeAddr) -> Self {
        self.previous_hop = Some(previous_hop);
        self
    }

    pub(crate) fn with_ce_flag(mut self, ce_flag: bool) -> Self {
        self.ce_flag = ce_flag;
        self
    }

    pub(crate) fn with_path_mtu(mut self, path_mtu: u16) -> Self {
        self.path_mtu = path_mtu;
        self
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

    pub(crate) fn fsp_source(&self) -> Option<NodeAddr> {
        self.fsp_source
    }

    pub(crate) fn previous_hop(&self) -> Option<NodeAddr> {
        self.previous_hop
    }

    pub(crate) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(crate) fn path_mtu(&self) -> u16 {
        self.path_mtu
    }

    pub(crate) fn activity_tick(&self) -> Option<ActivityTick> {
        self.activity_tick
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2IngressHeader {
    Fmp(FmpWireHeader),
    Fsp(FspWireHeader),
}

impl PacketMover2IngressHeader {
    pub(crate) fn counter(self) -> u64 {
        match self {
            Self::Fmp(header) => header.counter(),
            Self::Fsp(header) => header.counter(),
        }
    }

    pub(crate) fn flags(self) -> u8 {
        match self {
            Self::Fmp(header) => header.flags(),
            Self::Fsp(header) => header.flags(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2IngressRoute {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    output: OutputTarget,
}

impl PacketMover2IngressRoute {
    pub(crate) fn new(owner: OwnerId, generation: u64, output: OutputTarget) -> Self {
        Self {
            owner,
            generation,
            class: PacketClass::Bulk,
            output,
        }
    }

    pub(crate) fn with_class(mut self, class: PacketClass) -> Self {
        self.class = class;
        self
    }
}

pub(crate) trait PacketMover2IngressRouter {
    fn route(
        &mut self,
        packet: &PacketMover2RawIngress,
        header: PacketMover2IngressHeader,
    ) -> Option<PacketMover2IngressRoute>;
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FmpIngressRouteKey {
    transport_id: TransportId,
    receiver_idx: u32,
}

impl FmpIngressRouteKey {
    fn new(transport_id: TransportId, receiver_idx: u32) -> Self {
        Self {
            transport_id,
            receiver_idx,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct PacketMover2LiveRouteTable {
    fmp: HashMap<FmpIngressRouteKey, PacketMover2IngressRoute>,
    fsp: HashMap<NodeAddr, PacketMover2IngressRoute>,
    tun_outbound: HashMap<FipsTunDestinationPrefix, PacketMover2TunDestinationRoute>,
    endpoint: HashMap<NodeAddr, PacketMover2EndpointCommandRoute>,
}

impl PacketMover2LiveRouteTable {
    pub(crate) fn register_fmp(
        &mut self,
        transport_id: TransportId,
        receiver_idx: u32,
        route: PacketMover2IngressRoute,
    ) -> Option<PacketMover2IngressRoute> {
        self.fmp
            .insert(FmpIngressRouteKey::new(transport_id, receiver_idx), route)
    }

    pub(crate) fn unregister_fmp(
        &mut self,
        transport_id: TransportId,
        receiver_idx: u32,
    ) -> Option<PacketMover2IngressRoute> {
        self.fmp
            .remove(&FmpIngressRouteKey::new(transport_id, receiver_idx))
    }

    pub(crate) fn register_fsp(
        &mut self,
        source_addr: NodeAddr,
        route: PacketMover2IngressRoute,
    ) -> Option<PacketMover2IngressRoute> {
        self.fsp.insert(source_addr, route)
    }

    pub(crate) fn unregister_fsp(
        &mut self,
        source_addr: NodeAddr,
    ) -> Option<PacketMover2IngressRoute> {
        self.fsp.remove(&source_addr)
    }

    pub(crate) fn register_tun_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: PacketMover2TunDestinationRoute,
    ) -> Option<PacketMover2TunDestinationRoute> {
        self.tun_outbound
            .insert(FipsTunDestinationPrefix::from_node_addr(dest_addr), route)
    }

    pub(crate) fn unregister_tun_destination(
        &mut self,
        dest_addr: NodeAddr,
    ) -> Option<PacketMover2TunDestinationRoute> {
        self.tun_outbound
            .remove(&FipsTunDestinationPrefix::from_node_addr(dest_addr))
    }

    pub(crate) fn register_endpoint_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: PacketMover2EndpointCommandRoute,
    ) -> Option<PacketMover2EndpointCommandRoute> {
        self.endpoint.insert(dest_addr, route)
    }

    pub(crate) fn unregister_endpoint_destination(
        &mut self,
        dest_addr: NodeAddr,
    ) -> Option<PacketMover2EndpointCommandRoute> {
        self.endpoint.remove(&dest_addr)
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> usize {
        let before =
            self.fmp.len() + self.fsp.len() + self.tun_outbound.len() + self.endpoint.len();
        self.fmp.retain(|_, route| route.owner != owner);
        self.fsp.retain(|_, route| route.owner != owner);
        self.tun_outbound
            .retain(|_, route| route.owner() != owner);
        self.endpoint.retain(|_, route| route.owner() != owner);
        let after =
            self.fmp.len() + self.fsp.len() + self.tun_outbound.len() + self.endpoint.len();
        before.saturating_sub(after)
    }

    pub(crate) fn refresh_owner_generation(&mut self, owner: OwnerId, generation: u64) -> usize {
        let mut refreshed = 0usize;
        for route in self.fmp.values_mut() {
            if route.owner == owner {
                route.generation = generation;
                refreshed = refreshed.saturating_add(1);
            }
        }
        for route in self.fsp.values_mut() {
            if route.owner == owner {
                route.generation = generation;
                refreshed = refreshed.saturating_add(1);
            }
        }
        for route in self.tun_outbound.values_mut() {
            if route.owner() == owner {
                route.refresh_generation(generation);
                refreshed = refreshed.saturating_add(1);
            }
        }
        for route in self.endpoint.values_mut() {
            if route.owner() == owner {
                route.refresh_generation(generation);
                refreshed = refreshed.saturating_add(1);
            }
        }
        refreshed
    }
}

impl PacketMover2IngressRouter for PacketMover2LiveRouteTable {
    fn route(
        &mut self,
        packet: &PacketMover2RawIngress,
        header: PacketMover2IngressHeader,
    ) -> Option<PacketMover2IngressRoute> {
        match (packet.protocol, header) {
            (PacketProtocol::Fmp, PacketMover2IngressHeader::Fmp(header)) => self
                .fmp
                .get(&FmpIngressRouteKey::new(
                    packet.transport_id,
                    header.receiver_idx(),
                ))
                .copied(),
            (PacketProtocol::Fsp, PacketMover2IngressHeader::Fsp(_)) => packet
                .fsp_source
                .and_then(|source_addr| self.fsp.get(&source_addr).copied()),
            _ => None,
        }
    }
}

impl PacketMover2TunOutboundRouter for PacketMover2LiveRouteTable {
    fn route_tun_outbound(
        &mut self,
        packet: &[u8],
    ) -> Result<PacketMover2TunOutboundRoute, PacketMover2TunOutboundDropReason> {
        let dest = FipsTunDestinationPrefix::from_ipv6_packet(packet)?;
        self.tun_outbound
            .get(&dest)
            .ok_or(PacketMover2TunOutboundDropReason::NoRoute)?
            .route_packet(packet)
    }
}

impl PacketMover2EndpointCommandRouter for PacketMover2LiveRouteTable {
    fn route_endpoint_command_payload(
        &mut self,
        request: PacketMover2EndpointCommandPayload<'_>,
    ) -> Result<OutboundPacket, PacketMover2EndpointCommandDropReason> {
        self.endpoint
            .get(&request.dest_addr())
            .ok_or(PacketMover2EndpointCommandDropReason::NoRoute)?
            .route_request(request)
    }

    fn route_endpoint_command_owned_payload(
        &mut self,
        request: PacketMover2EndpointCommandOwnedPayload,
    ) -> Result<
        OutboundPacket,
        (
            PacketMover2EndpointCommandOwnedPayload,
            PacketMover2EndpointCommandDropReason,
        ),
    > {
        let Some(route) = self.endpoint.get(&request.dest_addr()) else {
            return Err((request, PacketMover2EndpointCommandDropReason::NoRoute));
        };
        route.route_owned_request(request)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PacketMover2LiveIngressPacket {
    protocol: PacketProtocol,
    fsp_source: Option<NodeAddr>,
    packet: ReceivedPacket,
}

impl PacketMover2LiveIngressPacket {
    pub(crate) fn fmp(packet: ReceivedPacket) -> Self {
        Self {
            protocol: PacketProtocol::Fmp,
            fsp_source: None,
            packet,
        }
    }

    pub(crate) fn fsp(packet: ReceivedPacket, source_addr: NodeAddr) -> Self {
        Self {
            protocol: PacketProtocol::Fsp,
            fsp_source: Some(source_addr),
            packet,
        }
    }

    fn into_raw_ingress(self) -> PacketMover2RawIngress {
        let raw = PacketMover2RawIngress::from_live_received(self.protocol, self.packet);
        match self.fsp_source {
            Some(source_addr) => raw.with_fsp_source(source_addr),
            None => raw,
        }
    }
}

pub(crate) trait PacketMover2LiveIngressDrain {
    fn drain_live_ingress<F>(&mut self, limit: usize, push: F) -> usize
    where
        F: FnMut(PacketMover2LiveIngressPacket);
}

impl PacketMover2LiveIngressDrain for VecDeque<PacketMover2LiveIngressPacket> {
    fn drain_live_ingress<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(PacketMover2LiveIngressPacket),
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

#[derive(Clone, Debug)]
pub(crate) struct PacketMover2LiveRawIngressSource<S> {
    source: S,
}

impl<S> PacketMover2LiveRawIngressSource<S> {
    pub(crate) fn new(source: S) -> Self {
        Self { source }
    }

    #[cfg(test)]
    pub(crate) fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }
}

impl<S: PacketMover2LiveIngressDrain> PacketMover2RawIngressSource
    for PacketMover2LiveRawIngressSource<S>
{
    fn drain_raw_ingress<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(PacketMover2RawIngress),
    {
        self.source
            .drain_live_ingress(limit, |packet| push(packet.into_raw_ingress()))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PacketMover2FmpControlIngress {
    phase: u8,
    packet: ReceivedPacket,
}

impl PacketMover2FmpControlIngress {
    fn new(phase: u8, packet: ReceivedPacket) -> Self {
        Self { phase, packet }
    }

    pub(crate) fn phase(&self) -> u8 {
        self.phase
    }

    pub(crate) fn packet(&self) -> &ReceivedPacket {
        &self.packet
    }

    pub(crate) fn into_packet(self) -> ReceivedPacket {
        self.packet
    }
}

/// Drains live transport packets from `PacketRx` as FMP link ingress.
///
/// FSP ingress needs authenticated source context, so it must enter through a
/// source that can attach `with_fsp_source`.
pub(crate) struct PacketMover2FmpPacketRxSource<'a> {
    rx: &'a mut PacketRx,
    first: Option<ReceivedPacket>,
    control_ingress: Vec<PacketMover2FmpControlIngress>,
}

impl<'a> PacketMover2FmpPacketRxSource<'a> {
    pub(crate) fn new(rx: &'a mut PacketRx) -> Self {
        Self {
            rx,
            first: None,
            control_ingress: Vec::new(),
        }
    }

    pub(crate) fn with_first(rx: &'a mut PacketRx, first: Option<ReceivedPacket>) -> Self {
        Self {
            rx,
            first,
            control_ingress: Vec::new(),
        }
    }

    pub(crate) fn take_control_ingress(&mut self) -> Vec<PacketMover2FmpControlIngress> {
        std::mem::take(&mut self.control_ingress)
    }

    fn push_packet<F>(&mut self, packet: ReceivedPacket, push: &mut F) -> bool
    where
        F: FnMut(PacketMover2RawIngress),
    {
        match classify_live_fmp_packet(&packet) {
            LiveFmpPacketClass::Established => {
                push(PacketMover2RawIngress::from_live_received(
                    PacketProtocol::Fmp,
                    packet,
                ));
                true
            }
            LiveFmpPacketClass::Control { phase } => {
                self.control_ingress
                    .push(PacketMover2FmpControlIngress::new(phase, packet));
                false
            }
            LiveFmpPacketClass::RawDrop => {
                push(PacketMover2RawIngress::from_live_received(
                    PacketProtocol::Fmp,
                    packet,
                ));
                true
            }
        }
    }
}

impl PacketMover2RawIngressSource for PacketMover2FmpPacketRxSource<'_> {
    fn drain_raw_ingress<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(PacketMover2RawIngress),
    {
        let mut drained = 0;
        while drained < limit {
            let Some(packet) = self.first.take().or_else(|| self.rx.try_recv().ok()) else {
                break;
            };
            let keep_draining = self.push_packet(packet, &mut push);
            drained += 1;
            if !keep_draining {
                break;
            }
        }
        drained
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveFmpPacketClass {
    Established,
    Control { phase: u8 },
    RawDrop,
}

fn classify_live_fmp_packet(packet: &ReceivedPacket) -> LiveFmpPacketClass {
    if packet.data.len() < FMP_COMMON_PREFIX_SIZE {
        return LiveFmpPacketClass::RawDrop;
    }
    let Some(first) = packet.data.first().copied() else {
        return LiveFmpPacketClass::RawDrop;
    };
    let version = first >> 4;
    let phase = first & 0x0f;
    if version == FMP_VERSION && phase == FMP_PHASE_ESTABLISHED {
        LiveFmpPacketClass::Established
    } else if version != FMP_VERSION || matches!(phase, FMP_PHASE_MSG1 | FMP_PHASE_MSG2) {
        LiveFmpPacketClass::Control { phase }
    } else {
        LiveFmpPacketClass::RawDrop
    }
}

pub(crate) trait PacketMover2RawIngressSource {
    fn drain_raw_ingress<F>(&mut self, limit: usize, push: F) -> usize
    where
        F: FnMut(PacketMover2RawIngress);
}

pub(crate) trait PacketMover2OutboundSource {
    fn drain_outbound<F>(&mut self, limit: usize, push: F) -> usize
    where
        F: FnMut(OutboundPacket);
}
