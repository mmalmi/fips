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

#[derive(Clone, Debug, Default)]
pub(crate) struct PacketMover2EstablishedFastIngressSnapshot {
    fmp: Arc<RwLock<Arc<HashMap<FmpIngressRouteKey, PacketMover2IngressRoute>>>>,
}

impl PacketMover2EstablishedFastIngressSnapshot {
    fn register_fmp(
        &self,
        transport_id: TransportId,
        receiver_idx: u32,
        route: PacketMover2IngressRoute,
    ) {
        self.update_fmp(|routes| {
            routes.insert(FmpIngressRouteKey::new(transport_id, receiver_idx), route);
        });
    }

    fn unregister_owner(&self, owner: OwnerId) {
        self.update_fmp(|routes| {
            routes.retain(|_, route| route.owner != owner);
        });
    }

    fn fmp_routes(&self) -> Arc<HashMap<FmpIngressRouteKey, PacketMover2IngressRoute>> {
        self.fmp
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn lookup_fmp_in(
        routes: &HashMap<FmpIngressRouteKey, PacketMover2IngressRoute>,
        transport_id: TransportId,
        receiver_idx: u32,
    ) -> Option<PacketMover2IngressRoute> {
        routes
            .get(&FmpIngressRouteKey::new(transport_id, receiver_idx))
            .copied()
    }

    fn update_fmp<F>(&self, update: F)
    where
        F: FnOnce(&mut HashMap<FmpIngressRouteKey, PacketMover2IngressRoute>),
    {
        let mut guard = self
            .fmp
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut routes = (**guard).clone();
        update(&mut routes);
        *guard = Arc::new(routes);
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2FastIngressBatch {
    packets: Vec<SocketPacket>,
    reservation: Option<PacketMover2FastIngressReservation>,
}

impl PacketMover2FastIngressBatch {
    fn new(
        packets: Vec<SocketPacket>,
        reservation: PacketMover2FastIngressReservation,
    ) -> Self {
        Self {
            packets,
            reservation: Some(reservation),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.packets.len()
    }

    pub(crate) fn absorb(&mut self, other: Self) {
        self.packets.extend(other.into_packets());
    }

    fn into_packets(mut self) -> Vec<SocketPacket> {
        if let Some(reservation) = self.reservation.take() {
            reservation.release();
        }
        std::mem::take(&mut self.packets)
    }
}

pub(crate) type PacketMover2FastIngressRx =
    tokio::sync::mpsc::Receiver<PacketMover2FastIngressBatch>;

#[derive(Clone, Debug)]
struct PacketMover2FastIngressQueue {
    queued_packets: Arc<std::sync::atomic::AtomicUsize>,
    packet_capacity: usize,
}

impl PacketMover2FastIngressQueue {
    fn new(packet_capacity: usize) -> Self {
        Self {
            queued_packets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            packet_capacity: packet_capacity.max(1),
        }
    }

    fn reserve_prefix(&self, requested: usize) -> Option<PacketMover2FastIngressReservation> {
        if requested == 0 {
            return None;
        }

        let mut current = self.queued_packets.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let available = self.packet_capacity.saturating_sub(current);
            let granted = requested.min(available);
            if granted == 0 {
                return None;
            }
            match self.queued_packets.compare_exchange_weak(
                current,
                current + granted,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(PacketMover2FastIngressReservation {
                        queue: self.clone(),
                        count: granted,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn release(&self, count: usize) {
        if count == 0 {
            return;
        }
        let previous = self
            .queued_packets
            .fetch_sub(count, std::sync::atomic::Ordering::Relaxed);
        debug_assert!(
            previous >= count,
            "packet_mover2 fast ingress queued packet accounting underflow"
        );
    }
}

#[derive(Debug)]
struct PacketMover2FastIngressReservation {
    queue: PacketMover2FastIngressQueue,
    count: usize,
}

impl PacketMover2FastIngressReservation {
    fn len(&self) -> usize {
        self.count
    }

    fn truncate(&mut self, retained: usize) {
        if retained >= self.count {
            return;
        }
        let released = self.count - retained;
        self.count = retained;
        self.queue.release(released);
    }

    fn release(mut self) {
        self.release_now();
    }

    fn release_now(&mut self) {
        let count = std::mem::take(&mut self.count);
        self.queue.release(count);
    }
}

impl Drop for PacketMover2FastIngressReservation {
    fn drop(&mut self) {
        self.release_now();
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2EstablishedFastIngressSink {
    routes: PacketMover2EstablishedFastIngressSnapshot,
    queue: PacketMover2FastIngressQueue,
    tx: tokio::sync::mpsc::Sender<PacketMover2FastIngressBatch>,
}

impl PacketMover2EstablishedFastIngressSink {
    fn channel(
        routes: PacketMover2EstablishedFastIngressSnapshot,
        packet_capacity: usize,
    ) -> (Self, PacketMover2FastIngressRx) {
        let packet_capacity = packet_capacity.max(1);
        let (tx, rx) = tokio::sync::mpsc::channel(packet_capacity);
        (
            Self {
                routes,
                queue: PacketMover2FastIngressQueue::new(packet_capacity),
                tx,
            },
            rx,
        )
    }

    fn socket_packet_from_received(
        routes: &HashMap<FmpIngressRouteKey, PacketMover2IngressRoute>,
        packet: ReceivedPacket,
    ) -> Result<SocketPacket, ReceivedPacket> {
        let Ok(header) = FmpWireHeader::parse(&packet.data) else {
            return Err(packet);
        };
        let Some(route) = PacketMover2EstablishedFastIngressSnapshot::lookup_fmp_in(
            routes,
            packet.transport_id,
            header.receiver_idx(),
        )
        else {
            return Err(packet);
        };

        let source_path = TransportPath::live(packet.transport_id, packet.remote_addr.clone());
        let activity_tick = ActivityTick::new(packet.timestamp_ms);
        let mut socket_packet = SocketPacket::new(
            route.owner,
            route.generation,
            header.counter(),
            route.class,
            route.output,
            packet.data,
        )
        .with_source_path(source_path)
        .with_activity_tick(activity_tick)
        .with_wire_flags(header.flags());
        socket_packet = socket_packet.with_path_mtu(u16::MAX);
        Ok(socket_packet)
    }
}

impl PacketFastIngressSink for PacketMover2EstablishedFastIngressSink {
    fn try_ingest_batch(&self, packets: &mut Vec<ReceivedPacket>) -> usize {
        if packets.is_empty() || self.tx.is_closed() {
            return 0;
        }

        let mut reservation = match self.queue.reserve_prefix(packets.len()) {
            Some(reservation) => reservation,
            None => return 0,
        };
        let permit = match self.tx.try_reserve() {
            Ok(permit) => permit,
            Err(_) => {
                reservation.release();
                return 0;
            }
        };
        let routes = self.routes.fmp_routes();
        let mut misses = Vec::with_capacity(packets.len());
        let mut fast_packets = Vec::with_capacity(reservation.len().min(packets.len()));
        let fast_limit = reservation.len();
        for packet in std::mem::take(packets) {
            if fast_packets.len() >= fast_limit {
                misses.push(packet);
                continue;
            }
            match Self::socket_packet_from_received(&routes, packet) {
                Ok(packet) => fast_packets.push(packet),
                Err(packet) => misses.push(packet),
            }
        }
        *packets = misses;

        let accepted = fast_packets.len();
        reservation.truncate(accepted);
        if accepted == 0 {
            reservation.release();
            return 0;
        }
        permit.send(PacketMover2FastIngressBatch::new(
            fast_packets,
            reservation,
        ));
        accepted
    }
}

#[derive(Debug, Default)]
pub(crate) struct PacketMover2LiveRouteTable {
    fmp: HashMap<FmpIngressRouteKey, PacketMover2IngressRoute>,
    fsp: HashMap<NodeAddr, PacketMover2IngressRoute>,
    tun_outbound: HashMap<FipsTunDestinationPrefix, PacketMover2TunDestinationRoute>,
    endpoint: HashMap<NodeAddr, PacketMover2EndpointDataRoute>,
    established_fast_ingress: PacketMover2EstablishedFastIngressSnapshot,
}

impl PacketMover2LiveRouteTable {
    pub(crate) fn established_fast_ingress_snapshot(
        &self,
    ) -> PacketMover2EstablishedFastIngressSnapshot {
        self.established_fast_ingress.clone()
    }

    pub(crate) fn register_fmp(
        &mut self,
        transport_id: TransportId,
        receiver_idx: u32,
        route: PacketMover2IngressRoute,
    ) {
        self.fmp
            .insert(FmpIngressRouteKey::new(transport_id, receiver_idx), route);
        self.established_fast_ingress
            .register_fmp(transport_id, receiver_idx, route);
    }

    pub(crate) fn register_fsp(
        &mut self,
        source_addr: NodeAddr,
        route: PacketMover2IngressRoute,
    ) {
        self.fsp.insert(source_addr, route);
    }

    pub(crate) fn register_tun_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: PacketMover2TunDestinationRoute,
    ) {
        self.tun_outbound
            .insert(FipsTunDestinationPrefix::from_node_addr(dest_addr), route);
    }

    pub(crate) fn register_endpoint_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: PacketMover2EndpointDataRoute,
    ) {
        self.endpoint.insert(dest_addr, route);
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> usize {
        let before =
            self.fmp.len() + self.fsp.len() + self.tun_outbound.len() + self.endpoint.len();
        self.fmp.retain(|_, route| route.owner != owner);
        self.fsp.retain(|_, route| route.owner != owner);
        self.tun_outbound
            .retain(|_, route| route.owner() != owner);
        self.endpoint.retain(|_, route| route.owner() != owner);
        self.established_fast_ingress.unregister_owner(owner);
        let after =
            self.fmp.len() + self.fsp.len() + self.tun_outbound.len() + self.endpoint.len();
        before.saturating_sub(after)
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
        dest: FipsTunDestinationPrefix,
    ) -> Result<PacketMover2TunOutboundRoute, PacketMover2TunOutboundDropReason> {
        self.tun_outbound
            .get(&dest)
            .ok_or(PacketMover2TunOutboundDropReason::NoRoute)?
            .route_packet(packet)
    }
}

impl PacketMover2EndpointDataRouter for PacketMover2LiveRouteTable {
    fn route_endpoint_data_batch(
        &mut self,
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
    ) -> PacketMover2EndpointDataBatchRoute {
        let Some(route) = self.endpoint.get(remote.node_addr()) else {
            return PacketMover2EndpointDataBatchRoute::deferred(payloads);
        };
        route.route_batch(payloads)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2DirectFspSource {
    pub(crate) source_addr: NodeAddr,
    pub(crate) path_mtu: u16,
}

pub(crate) trait PacketMover2FspSourceClassifier {
    fn direct_fsp_source(
        &mut self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<PacketMover2DirectFspSource>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PacketMover2NoDirectFspSources;

impl PacketMover2FspSourceClassifier for PacketMover2NoDirectFspSources {
    fn direct_fsp_source(
        &mut self,
        _transport_id: TransportId,
        _remote_addr: &TransportAddr,
    ) -> Option<PacketMover2DirectFspSource> {
        None
    }
}

impl PacketMover2FspSourceClassifier
    for std::collections::HashMap<(TransportId, TransportAddr), PacketMover2DirectFspSource>
{
    fn direct_fsp_source(
        &mut self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<PacketMover2DirectFspSource> {
        self.get(&(transport_id, remote_addr.clone())).copied()
    }
}

/// Drains live transport packets from `PacketRx` as PM2 ingress.
///
/// FSP direct transport ingress needs authenticated source context, so callers
/// pass a current transport-address classifier. Unflagged established packets
/// stay on the FMP path.
pub(crate) struct PacketMover2FmpPacketRxSource<'a, C = PacketMover2NoDirectFspSources> {
    rx: &'a mut PacketRx,
    first: Option<ReceivedPacket>,
    direct_fsp_sources: C,
    control_ingress: Vec<PacketMover2FmpControlIngress>,
}

impl<'a> PacketMover2FmpPacketRxSource<'a, PacketMover2NoDirectFspSources> {
    pub(crate) fn with_first(rx: &'a mut PacketRx, first: Option<ReceivedPacket>) -> Self {
        Self::with_first_and_direct_fsp_sources(rx, first, PacketMover2NoDirectFspSources)
    }
}

impl<'a, C> PacketMover2FmpPacketRxSource<'a, C>
where
    C: PacketMover2FspSourceClassifier,
{
    pub(crate) fn with_first_and_direct_fsp_sources(
        rx: &'a mut PacketRx,
        first: Option<ReceivedPacket>,
        direct_fsp_sources: C,
    ) -> Self {
        Self {
            rx,
            first,
            direct_fsp_sources,
            control_ingress: Vec::new(),
        }
    }

    pub(crate) fn take_control_ingress(&mut self) -> Vec<PacketMover2FmpControlIngress> {
        std::mem::take(&mut self.control_ingress)
    }

    fn push_packet<F>(
        direct_fsp_sources: &mut C,
        control_ingress: &mut Vec<PacketMover2FmpControlIngress>,
        packet: ReceivedPacket,
        push: &mut F,
    ) -> bool
    where
        F: FnMut(PacketMover2RawIngress),
    {
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::TransportRxLoopOwnedWait,
            packet.trace_rx_loop_owned_at,
        );
        if let Some(raw) = classify_direct_fsp_packet(direct_fsp_sources, &packet) {
            push(raw);
            return true;
        }
        match classify_live_fmp_packet(&packet) {
            LiveFmpPacketClass::Established => {
                push(PacketMover2RawIngress::from_live_received(
                    PacketProtocol::Fmp,
                    packet,
                ));
                true
            }
            LiveFmpPacketClass::Control { phase } => {
                control_ingress.push(PacketMover2FmpControlIngress::new(phase, packet));
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

impl<C> PacketMover2RawIngressSource for PacketMover2FmpPacketRxSource<'_, C>
where
    C: PacketMover2FspSourceClassifier,
{
    fn drain_raw_ingress<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(PacketMover2RawIngress),
    {
        let mut drained = 0;
        let Self {
            rx,
            first,
            direct_fsp_sources,
            control_ingress,
        } = self;

        if drained < limit
            && let Some(packet) = first.take()
        {
            let keep_draining =
                Self::push_packet(direct_fsp_sources, control_ingress, packet, &mut push);
            drained += 1;
            if !keep_draining {
                return drained;
            }
        }
        drained += rx.drain_ready(limit.saturating_sub(drained), |packet| {
            Self::push_packet(direct_fsp_sources, control_ingress, packet, &mut push)
        });
        drained
    }
}

fn classify_direct_fsp_packet<C>(
    direct_fsp_sources: &mut C,
    packet: &ReceivedPacket,
) -> Option<PacketMover2RawIngress>
where
    C: PacketMover2FspSourceClassifier,
{
    let prefix = FspWireHeader::parse(&packet.data).ok()?;
    if prefix.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT == 0 {
        return None;
    }
    let source = direct_fsp_sources.direct_fsp_source(packet.transport_id, &packet.remote_addr)?;
    Some(
        PacketMover2RawIngress::from_live_received(PacketProtocol::Fsp, packet.clone())
            .with_fsp_source(source.source_addr)
            .with_previous_hop(source.source_addr)
            .with_path_mtu(source.path_mtu),
    )
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

pub(crate) trait PacketMover2CompletionSource {
    fn drain_completions_into(
        &mut self,
        limit: usize,
        completions: &mut Vec<CryptoCompletion>,
    ) -> usize;

    fn drain_completion_batches_into(
        &mut self,
        limit: usize,
        completion_batches: &mut Vec<CryptoCompletionBatch>,
    ) -> usize {
        let mut completions = Vec::new();
        let drained = self.drain_completions_into(limit, &mut completions);
        CryptoCompletionBatch::drain_completion_vec_into_batches(
            &mut completions,
            completion_batches,
        );
        drained
    }
}
