#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneRawIngress {
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

impl DataplaneRawIngress {
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
pub(crate) enum DataplaneIngressHeader {
    Fmp(FmpWireHeader),
    Fsp(FspWireHeader),
}

impl DataplaneIngressHeader {
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
pub(crate) struct DataplaneIngressRoute {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    output: OutputTarget,
}

impl DataplaneIngressRoute {
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

pub(crate) trait DataplaneIngressRouter {
    fn route(
        &mut self,
        packet: &DataplaneRawIngress,
        header: DataplaneIngressHeader,
    ) -> Option<DataplaneIngressRoute>;
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
pub(crate) struct DataplaneEstablishedFastIngressSnapshot {
    fmp: Arc<RwLock<Arc<HashMap<FmpIngressRouteKey, DataplaneIngressRoute>>>>,
    fsp: Arc<RwLock<Arc<HashMap<NodeAddr, DataplaneIngressRoute>>>>,
    direct_fsp: Arc<
        RwLock<Arc<HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>>>,
    >,
}

impl DataplaneEstablishedFastIngressSnapshot {
    fn register_fmp(
        &self,
        transport_id: TransportId,
        receiver_idx: u32,
        route: DataplaneIngressRoute,
    ) {
        self.update_fmp(|routes| {
            routes.insert(FmpIngressRouteKey::new(transport_id, receiver_idx), route);
        });
    }

    fn register_fsp(&self, source_addr: NodeAddr, route: DataplaneIngressRoute) {
        self.update_fsp(|routes| {
            routes.insert(source_addr, route);
        });
    }

    fn set_direct_fsp_sources<DirectSources>(&self, sources: DirectSources)
    where
        DirectSources:
            Into<Arc<HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>>>,
    {
        *self
            .direct_fsp
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = sources.into();
    }

    fn unregister_owner(&self, owner: OwnerId) {
        self.update_fmp(|routes| {
            routes.retain(|_, route| route.owner != owner);
        });
        self.update_fsp(|routes| {
            routes.retain(|_, route| route.owner != owner);
        });
    }

    fn fmp_routes(&self) -> Arc<HashMap<FmpIngressRouteKey, DataplaneIngressRoute>> {
        self.fmp
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn fsp_routes(&self) -> Arc<HashMap<NodeAddr, DataplaneIngressRoute>> {
        self.fsp
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn direct_fsp_sources(
        &self,
    ) -> Arc<HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>> {
        self.direct_fsp
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn lookup_fmp_in(
        routes: &HashMap<FmpIngressRouteKey, DataplaneIngressRoute>,
        transport_id: TransportId,
        receiver_idx: u32,
    ) -> Option<DataplaneIngressRoute> {
        routes
            .get(&FmpIngressRouteKey::new(transport_id, receiver_idx))
            .copied()
    }

    fn lookup_fsp_in(
        routes: &HashMap<NodeAddr, DataplaneIngressRoute>,
        source_addr: NodeAddr,
    ) -> Option<DataplaneIngressRoute> {
        routes.get(&source_addr).copied()
    }

    fn update_fmp<F>(&self, update: F)
    where
        F: FnOnce(&mut HashMap<FmpIngressRouteKey, DataplaneIngressRoute>),
    {
        let mut guard = self
            .fmp
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut routes = (**guard).clone();
        update(&mut routes);
        *guard = Arc::new(routes);
    }

    fn update_fsp<F>(&self, update: F)
    where
        F: FnOnce(&mut HashMap<NodeAddr, DataplaneIngressRoute>),
    {
        let mut guard = self
            .fsp
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut routes = (**guard).clone();
        update(&mut routes);
        *guard = Arc::new(routes);
    }
}

#[derive(Debug)]
pub(crate) struct DataplaneFastIngressRun {
    owner: OwnerId,
    lane: Lane,
    packets: Vec<SocketPacket>,
}

impl DataplaneFastIngressRun {
    fn new(packet: SocketPacket) -> Self {
        let owner = packet.owner;
        let lane = packet.lane();
        Self {
            owner,
            lane,
            packets: vec![packet],
        }
    }

    fn len(&self) -> usize {
        self.packets.len()
    }

    fn matches_packet(&self, packet: &SocketPacket) -> bool {
        self.owner == packet.owner && self.lane == packet.lane()
    }

    fn push(&mut self, packet: SocketPacket) -> Result<(), SocketPacket> {
        if !self.matches_packet(&packet) {
            return Err(packet);
        }
        self.packets.push(packet);
        Ok(())
    }

    fn append(&mut self, other: Self) -> Result<(), Self> {
        if self.owner != other.owner || self.lane != other.lane {
            return Err(other);
        }
        self.packets.extend(other.packets);
        Ok(())
    }

    fn into_parts(self) -> (OwnerId, Lane, Vec<SocketPacket>) {
        (self.owner, self.lane, self.packets)
    }

    fn into_packets(self) -> Vec<SocketPacket> {
        self.packets
    }
}

#[derive(Debug)]
pub(crate) struct DataplaneFastIngressBatch {
    runs: Vec<DataplaneFastIngressRun>,
    packet_count: usize,
    reservation: Option<DataplaneFastIngressReservation>,
}

impl DataplaneFastIngressBatch {
    fn new(
        runs: Vec<DataplaneFastIngressRun>,
        reservation: DataplaneFastIngressReservation,
    ) -> Self {
        let packet_count = runs.iter().map(DataplaneFastIngressRun::len).sum();
        Self {
            runs,
            packet_count,
            reservation: Some(reservation),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.packet_count
    }

    pub(crate) fn absorb(&mut self, other: Self) {
        for run in other.into_runs() {
            self.push_run(run);
        }
    }

    fn push_run(&mut self, run: DataplaneFastIngressRun) {
        let run_len = run.len();
        if let Some(last) = self.runs.last_mut() {
            match last.append(run) {
                Ok(()) => {
                    self.packet_count = self.packet_count.saturating_add(run_len);
                    return;
                }
                Err(run) => self.runs.push(run),
            }
        } else {
            self.runs.push(run);
        }
        self.packet_count = self.packet_count.saturating_add(run_len);
    }

    fn into_runs(mut self) -> Vec<DataplaneFastIngressRun> {
        if let Some(reservation) = self.reservation.take() {
            reservation.release();
        }
        self.packet_count = 0;
        std::mem::take(&mut self.runs)
    }

    fn into_packets(self) -> Vec<SocketPacket> {
        self.into_runs()
            .into_iter()
            .flat_map(DataplaneFastIngressRun::into_packets)
            .collect()
    }
}

pub(crate) type DataplaneFastIngressRx =
    tokio::sync::mpsc::Receiver<DataplaneFastIngressBatch>;

#[derive(Clone, Debug)]
struct DataplaneFastIngressQueue {
    queued_packets: Arc<std::sync::atomic::AtomicUsize>,
    packet_capacity: usize,
}

impl DataplaneFastIngressQueue {
    fn new(packet_capacity: usize) -> Self {
        Self {
            queued_packets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            packet_capacity: packet_capacity.max(1),
        }
    }

    fn reserve_prefix(&self, requested: usize) -> Option<DataplaneFastIngressReservation> {
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
                    return Some(DataplaneFastIngressReservation {
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
            "dataplane fast ingress queued packet accounting underflow"
        );
    }
}

#[derive(Debug)]
struct DataplaneFastIngressReservation {
    queue: DataplaneFastIngressQueue,
    count: usize,
}

impl DataplaneFastIngressReservation {
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

impl Drop for DataplaneFastIngressReservation {
    fn drop(&mut self) {
        self.release_now();
    }
}

#[derive(Debug)]
pub(crate) struct DataplaneEstablishedFastIngressSink {
    routes: DataplaneEstablishedFastIngressSnapshot,
    queue: DataplaneFastIngressQueue,
    tx: tokio::sync::mpsc::Sender<DataplaneFastIngressBatch>,
    direct_fsp_reassembler: std::sync::Mutex<DataplaneDirectFspReassembler>,
}

impl DataplaneEstablishedFastIngressSink {
    fn channel(
        routes: DataplaneEstablishedFastIngressSnapshot,
        packet_capacity: usize,
    ) -> (Self, DataplaneFastIngressRx) {
        let packet_capacity = packet_capacity.max(1);
        let (tx, rx) = tokio::sync::mpsc::channel(packet_capacity);
        (
            Self {
                routes,
                queue: DataplaneFastIngressQueue::new(packet_capacity),
                tx,
                direct_fsp_reassembler: std::sync::Mutex::new(
                    DataplaneDirectFspReassembler::default(),
                ),
            },
            rx,
        )
    }

    fn fmp_socket_packet_from_received(
        routes: &HashMap<FmpIngressRouteKey, DataplaneIngressRoute>,
        packet: ReceivedPacket,
    ) -> Result<SocketPacket, ReceivedPacket> {
        let Ok(header) = FmpWireHeader::parse(&packet.data) else {
            return Err(packet);
        };
        let Some(route) = DataplaneEstablishedFastIngressSnapshot::lookup_fmp_in(
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

    fn direct_fsp_socket_packet_from_received(
        direct_sources: &HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>,
        fsp_routes: &HashMap<NodeAddr, DataplaneIngressRoute>,
        packet: ReceivedPacket,
    ) -> DataplaneFastIngressDirectFspResult {
        let Some(source) =
            lookup_direct_fsp_source(direct_sources, packet.transport_id, &packet.remote_addr)
        else {
            return DataplaneFastIngressDirectFspResult::Miss(packet);
        };
        Self::direct_fsp_socket_packet_from_whole(source, fsp_routes, packet)
    }

    fn direct_fsp_socket_packet_from_whole(
        source: DataplaneDirectFspSource,
        fsp_routes: &HashMap<NodeAddr, DataplaneIngressRoute>,
        packet: ReceivedPacket,
    ) -> DataplaneFastIngressDirectFspResult {
        let Ok(header) = FspWireHeader::parse(&packet.data) else {
            return DataplaneFastIngressDirectFspResult::Miss(packet);
        };
        if header.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT == 0 {
            return DataplaneFastIngressDirectFspResult::Miss(packet);
        }
        let Some(route) = DataplaneEstablishedFastIngressSnapshot::lookup_fsp_in(
            fsp_routes,
            source.source_addr,
        ) else {
            return DataplaneFastIngressDirectFspResult::Miss(packet);
        };

        let source_path = TransportPath::live(packet.transport_id, packet.remote_addr.clone());
        let activity_tick = ActivityTick::new(packet.timestamp_ms);
        let socket_packet = SocketPacket::new(
            route.owner,
            route.generation,
            header.counter(),
            route.class,
            route.output,
            packet.data,
        )
        .with_source_path(source_path)
        .with_previous_hop(source.source_addr)
        .with_path_mtu(source.path_mtu)
        .with_activity_tick(activity_tick)
        .with_wire_flags(header.flags());
        DataplaneFastIngressDirectFspResult::Fast(socket_packet)
    }

    fn direct_fsp_socket_packet(
        &self,
        direct_sources: &HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>,
        fsp_routes: &HashMap<NodeAddr, DataplaneIngressRoute>,
        packet: ReceivedPacket,
    ) -> DataplaneFastIngressDirectFspResult {
        if !dataplane_direct_fsp_transport_fragment_is_fragment(packet.data.as_slice()) {
            return Self::direct_fsp_socket_packet_from_received(direct_sources, fsp_routes, packet);
        }
        let Some(source) =
            lookup_direct_fsp_source(direct_sources, packet.transport_id, &packet.remote_addr)
        else {
            return DataplaneFastIngressDirectFspResult::Miss(packet);
        };
        if !fsp_routes.contains_key(&source.source_addr) {
            return DataplaneFastIngressDirectFspResult::Miss(packet);
        }
        if packet.data.len() > source.path_mtu as usize {
            return DataplaneFastIngressDirectFspResult::Consumed;
        }

        let mut reassembler = self
            .direct_fsp_reassembler
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match reassembler.ingest(packet) {
            DataplaneDirectFspReassemblyResult::NotFragment(packet) => {
                Self::direct_fsp_socket_packet_from_whole(source, fsp_routes, packet)
            }
            DataplaneDirectFspReassemblyResult::Pending
            | DataplaneDirectFspReassemblyResult::Dropped => {
                DataplaneFastIngressDirectFspResult::Consumed
            }
            DataplaneDirectFspReassemblyResult::Complete(packet) => {
                Self::direct_fsp_socket_packet_from_whole(source, fsp_routes, packet)
            }
        }
    }

    fn direct_fsp_fragment_packet(
        &self,
        direct_sources: &HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>,
        fsp_routes: &HashMap<NodeAddr, DataplaneIngressRoute>,
        packet: ReceivedPacket,
    ) -> DataplaneFastIngressDirectFragmentResult {
        if !dataplane_direct_fsp_transport_fragment_is_fragment(packet.data.as_slice()) {
            return DataplaneFastIngressDirectFragmentResult::Miss(packet);
        }
        let Some(source) =
            lookup_direct_fsp_source(direct_sources, packet.transport_id, &packet.remote_addr)
        else {
            return DataplaneFastIngressDirectFragmentResult::Miss(packet);
        };
        if !fsp_routes.contains_key(&source.source_addr) {
            return DataplaneFastIngressDirectFragmentResult::Miss(packet);
        }
        if packet.data.len() > source.path_mtu as usize {
            return DataplaneFastIngressDirectFragmentResult::Consumed;
        }

        let mut reassembler = self
            .direct_fsp_reassembler
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match reassembler.ingest(packet) {
            DataplaneDirectFspReassemblyResult::NotFragment(packet) => {
                DataplaneFastIngressDirectFragmentResult::Miss(packet)
            }
            DataplaneDirectFspReassemblyResult::Pending
            | DataplaneDirectFspReassemblyResult::Dropped => {
                DataplaneFastIngressDirectFragmentResult::Consumed
            }
            DataplaneDirectFspReassemblyResult::Complete(packet) => {
                DataplaneFastIngressDirectFragmentResult::Complete(packet)
            }
        }
    }
}

enum DataplaneFastIngressDirectFspResult {
    Fast(SocketPacket),
    Consumed,
    Miss(ReceivedPacket),
}

enum DataplaneFastIngressDirectFragmentResult {
    Consumed,
    Complete(ReceivedPacket),
    Miss(ReceivedPacket),
}

impl PacketFastIngressSink for DataplaneEstablishedFastIngressSink {
    fn try_ingest_batch(&self, packets: &mut Vec<ReceivedPacket>) -> usize {
        if packets.is_empty() || self.tx.is_closed() {
            return 0;
        }

        let routes = self.routes.fmp_routes();
        let fsp_routes = self.routes.fsp_routes();
        let direct_sources = self.routes.direct_fsp_sources();

        let mut consumed_inputs = 0usize;
        let mut candidates = Vec::with_capacity(packets.len());
        for packet in std::mem::take(packets) {
            match self.direct_fsp_fragment_packet(&direct_sources, &fsp_routes, packet) {
                DataplaneFastIngressDirectFragmentResult::Consumed => {
                    consumed_inputs = consumed_inputs.saturating_add(1);
                }
                DataplaneFastIngressDirectFragmentResult::Complete(packet) => {
                    consumed_inputs = consumed_inputs.saturating_add(1);
                    candidates.push((packet, 0usize));
                }
                DataplaneFastIngressDirectFragmentResult::Miss(packet) => {
                    candidates.push((packet, 1usize));
                }
            }
        }

        if candidates.is_empty() {
            return consumed_inputs;
        }

        let candidate_count = candidates.len();
        let mut reservation = match self.queue.reserve_prefix(candidate_count) {
            Some(reservation) => reservation,
            None => {
                packets.extend(candidates.into_iter().map(|(packet, _)| packet));
                return consumed_inputs;
            }
        };
        let permit = match self.tx.try_reserve() {
            Ok(permit) => permit,
            Err(_) => {
                reservation.release();
                packets.extend(candidates.into_iter().map(|(packet, _)| packet));
                return consumed_inputs;
            }
        };
        let mut misses = Vec::with_capacity(candidate_count);
        let mut fast_runs = Vec::new();
        let mut accepted_inputs = 0usize;
        let mut accepted_fast_packets = 0usize;
        let fast_limit = reservation.len();
        for (packet, input_count) in candidates {
            if accepted_fast_packets >= fast_limit {
                misses.push(packet);
                continue;
            }
            match self.direct_fsp_socket_packet(&direct_sources, &fsp_routes, packet) {
                DataplaneFastIngressDirectFspResult::Fast(packet) => {
                    accepted_inputs = accepted_inputs.saturating_add(input_count);
                    accepted_fast_packets = accepted_fast_packets.saturating_add(1);
                    push_fast_ingress_packet_run(&mut fast_runs, packet);
                }
                DataplaneFastIngressDirectFspResult::Consumed => {
                    accepted_inputs = accepted_inputs.saturating_add(input_count);
                }
                DataplaneFastIngressDirectFspResult::Miss(packet) => {
                    match Self::fmp_socket_packet_from_received(&routes, packet) {
                        Ok(packet) => {
                            accepted_inputs = accepted_inputs.saturating_add(input_count);
                            accepted_fast_packets = accepted_fast_packets.saturating_add(1);
                            push_fast_ingress_packet_run(&mut fast_runs, packet);
                        }
                        Err(packet) => misses.push(packet),
                    }
                }
            }
        }
        *packets = misses;

        reservation.truncate(accepted_fast_packets);
        if accepted_fast_packets == 0 {
            reservation.release();
            return consumed_inputs.saturating_add(accepted_inputs);
        }
        permit.send(DataplaneFastIngressBatch::new(
            fast_runs,
            reservation,
        ));
        consumed_inputs.saturating_add(accepted_inputs)
    }
}

fn push_fast_ingress_packet_run(
    runs: &mut Vec<DataplaneFastIngressRun>,
    packet: SocketPacket,
) {
    if let Some(last) = runs.last_mut() {
        match last.push(packet) {
            Ok(()) => return,
            Err(packet) => runs.push(DataplaneFastIngressRun::new(packet)),
        }
    } else {
        runs.push(DataplaneFastIngressRun::new(packet));
    }
}

#[derive(Debug, Default)]
pub(crate) struct DataplaneLiveRouteTable {
    fmp: HashMap<FmpIngressRouteKey, DataplaneIngressRoute>,
    fsp: HashMap<NodeAddr, DataplaneIngressRoute>,
    tun_outbound: HashMap<FipsTunDestinationPrefix, DataplaneTunDestinationRoute>,
    endpoint: HashMap<NodeAddr, DataplaneEndpointDataRoute>,
    established_fast_ingress: DataplaneEstablishedFastIngressSnapshot,
}

impl DataplaneLiveRouteTable {
    pub(crate) fn established_fast_ingress_snapshot(
        &self,
    ) -> DataplaneEstablishedFastIngressSnapshot {
        self.established_fast_ingress.clone()
    }

    pub(crate) fn register_fmp(
        &mut self,
        transport_id: TransportId,
        receiver_idx: u32,
        route: DataplaneIngressRoute,
    ) {
        self.fmp
            .insert(FmpIngressRouteKey::new(transport_id, receiver_idx), route);
        self.established_fast_ingress
            .register_fmp(transport_id, receiver_idx, route);
    }

    pub(crate) fn register_fsp(
        &mut self,
        source_addr: NodeAddr,
        route: DataplaneIngressRoute,
    ) {
        self.fsp.insert(source_addr, route);
        self.established_fast_ingress
            .register_fsp(source_addr, route);
    }

    pub(crate) fn set_established_fast_ingress_direct_fsp_sources<DirectSources>(
        &self,
        sources: DirectSources,
    ) where
        DirectSources:
            Into<Arc<HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>>>,
    {
        self.established_fast_ingress
            .set_direct_fsp_sources(sources);
    }

    pub(crate) fn register_tun_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: DataplaneTunDestinationRoute,
    ) {
        self.tun_outbound
            .insert(FipsTunDestinationPrefix::from_node_addr(dest_addr), route);
    }

    pub(crate) fn register_endpoint_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: DataplaneEndpointDataRoute,
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

impl DataplaneIngressRouter for DataplaneLiveRouteTable {
    fn route(
        &mut self,
        packet: &DataplaneRawIngress,
        header: DataplaneIngressHeader,
    ) -> Option<DataplaneIngressRoute> {
        match (packet.protocol, header) {
            (PacketProtocol::Fmp, DataplaneIngressHeader::Fmp(header)) => self
                .fmp
                .get(&FmpIngressRouteKey::new(
                    packet.transport_id,
                    header.receiver_idx(),
                ))
                .copied(),
            (PacketProtocol::Fsp, DataplaneIngressHeader::Fsp(_)) => packet
                .fsp_source
                .and_then(|source_addr| self.fsp.get(&source_addr).copied()),
            _ => None,
        }
    }
}

impl DataplaneTunOutboundRouter for DataplaneLiveRouteTable {
    fn route_tun_outbound(
        &mut self,
        packet: &[u8],
        dest: FipsTunDestinationPrefix,
    ) -> Result<DataplaneTunOutboundRoute, DataplaneTunOutboundDropReason> {
        self.tun_outbound
            .get(&dest)
            .ok_or(DataplaneTunOutboundDropReason::NoRoute)?
            .route_packet(packet)
    }
}

impl DataplaneEndpointDataRouter for DataplaneLiveRouteTable {
    fn route_endpoint_data_batch(
        &mut self,
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        activity_tick: ActivityTick,
    ) -> DataplaneEndpointDataBatchRoute {
        let Some(route) = self.endpoint.get(remote.node_addr()) else {
            return DataplaneEndpointDataBatchRoute::deferred(payloads);
        };
        route.route_payloads(payloads, activity_tick)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DataplaneFmpControlIngress {
    phase: u8,
    packet: ReceivedPacket,
}

impl DataplaneFmpControlIngress {
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
pub(crate) struct DataplaneDirectFspSource {
    pub(crate) source_addr: NodeAddr,
    pub(crate) path_mtu: u16,
}

pub(crate) trait DataplaneFspSourceClassifier {
    fn direct_fsp_source(
        &mut self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<DataplaneDirectFspSource>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DataplaneNoDirectFspSources;

impl DataplaneFspSourceClassifier for DataplaneNoDirectFspSources {
    fn direct_fsp_source(
        &mut self,
        _transport_id: TransportId,
        _remote_addr: &TransportAddr,
    ) -> Option<DataplaneDirectFspSource> {
        None
    }
}

impl DataplaneFspSourceClassifier
    for std::collections::HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>
{
    fn direct_fsp_source(
        &mut self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<DataplaneDirectFspSource> {
        lookup_direct_fsp_source(self, transport_id, remote_addr)
    }
}

impl DataplaneFspSourceClassifier
    for Arc<HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>>
{
    fn direct_fsp_source(
        &mut self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<DataplaneDirectFspSource> {
        lookup_direct_fsp_source(self.as_ref(), transport_id, remote_addr)
    }
}

fn lookup_direct_fsp_source(
    direct_sources: &HashMap<(TransportId, TransportAddr), DataplaneDirectFspSource>,
    transport_id: TransportId,
    remote_addr: &TransportAddr,
) -> Option<DataplaneDirectFspSource> {
    if let Some(source) = direct_sources.get(&(transport_id, remote_addr.clone())).copied() {
        return Some(source);
    }

    let remote_socket_addr = direct_fsp_socket_addr(remote_addr)?;
    let remote_ip = remote_socket_addr.ip();
    let mut match_source = None;
    for ((candidate_transport_id, candidate_addr), source) in direct_sources {
        if *candidate_transport_id != transport_id
            || direct_fsp_socket_addr(candidate_addr).map(|addr| addr.ip()) != Some(remote_ip)
        {
            continue;
        }
        match match_source {
            None => match_source = Some(*source),
            Some(mut existing) if existing.source_addr == source.source_addr => {
                existing.path_mtu = existing.path_mtu.min(source.path_mtu);
                match_source = Some(existing);
            }
            Some(_) => return None,
        }
    }
    if match_source.is_some() {
        return match_source;
    }

    let remote_port = remote_socket_addr.port();
    for ((candidate_transport_id, candidate_addr), source) in direct_sources {
        if *candidate_transport_id != transport_id {
            continue;
        }
        let Some(candidate_socket_addr) = direct_fsp_socket_addr(candidate_addr) else {
            continue;
        };
        if !candidate_socket_addr.ip().is_unspecified()
            || candidate_socket_addr.port() != remote_port
        {
            continue;
        }
        match match_source {
            None => match_source = Some(*source),
            Some(mut existing) if existing.source_addr == source.source_addr => {
                existing.path_mtu = existing.path_mtu.min(source.path_mtu);
                match_source = Some(existing);
            }
            Some(_) => return None,
        }
    }
    match_source
}

fn direct_fsp_socket_addr(addr: &TransportAddr) -> Option<std::net::SocketAddr> {
    addr.as_str()?.parse::<std::net::SocketAddr>().ok()
}

/// Drains live transport packets from `PacketRx` as dataplane ingress.
///
/// FSP direct transport ingress needs authenticated source context, so callers
/// pass a current transport-address classifier. Unflagged established packets
/// stay on the FMP path.
pub(crate) struct DataplaneFmpPacketRxSource<'a, C = DataplaneNoDirectFspSources> {
    rx: &'a mut PacketRx,
    first: Option<ReceivedPacket>,
    direct_fsp_sources: C,
    direct_fsp_reassembler: Option<&'a mut DataplaneDirectFspReassembler>,
    control_ingress: Vec<DataplaneFmpControlIngress>,
}

impl<'a, C> DataplaneFmpPacketRxSource<'a, C>
where
    C: DataplaneFspSourceClassifier,
{
    pub(crate) fn with_first_and_direct_fsp_sources(
        rx: &'a mut PacketRx,
        first: Option<ReceivedPacket>,
        direct_fsp_sources: C,
    ) -> Self {
        Self::with_first_direct_fsp_sources_and_reassembler(rx, first, direct_fsp_sources, None)
    }

    pub(crate) fn with_first_direct_fsp_sources_and_reassembler(
        rx: &'a mut PacketRx,
        first: Option<ReceivedPacket>,
        direct_fsp_sources: C,
        direct_fsp_reassembler: Option<&'a mut DataplaneDirectFspReassembler>,
    ) -> Self {
        Self {
            rx,
            first,
            direct_fsp_sources,
            direct_fsp_reassembler,
            control_ingress: Vec::new(),
        }
    }

    pub(crate) fn take_control_ingress(&mut self) -> Vec<DataplaneFmpControlIngress> {
        std::mem::take(&mut self.control_ingress)
    }

    fn push_packet<F>(
        direct_fsp_sources: &mut C,
        direct_fsp_reassembler: Option<&mut DataplaneDirectFspReassembler>,
        control_ingress: &mut Vec<DataplaneFmpControlIngress>,
        packet: ReceivedPacket,
        push: &mut F,
    ) -> bool
    where
        F: FnMut(DataplaneRawIngress),
    {
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::TransportRxLoopOwnedWait,
            packet.trace_rx_loop_owned_at,
        );
        let mut from_direct_fragment = false;
        let packet = match direct_fsp_reassembler {
            Some(reassembler)
                if dataplane_direct_fsp_transport_fragment_is_fragment(packet.data.as_slice()) =>
            {
                let Some(source) =
                    direct_fsp_sources.direct_fsp_source(packet.transport_id, &packet.remote_addr)
                else {
                    return true;
                };
                if packet.data.len() > source.path_mtu as usize {
                    return true;
                }
                match reassembler.ingest(packet) {
                    DataplaneDirectFspReassemblyResult::NotFragment(packet) => packet,
                    DataplaneDirectFspReassemblyResult::Pending => return true,
                    DataplaneDirectFspReassemblyResult::Complete(packet) => {
                        from_direct_fragment = true;
                        packet
                    }
                    DataplaneDirectFspReassemblyResult::Dropped => return true,
                }
            }
            _ if dataplane_direct_fsp_transport_fragment_is_fragment(packet.data.as_slice()) => {
                return true;
            }
            _ => packet,
        };
        if let Some(raw) = classify_direct_fsp_packet(direct_fsp_sources, &packet) {
            push(raw);
            return true;
        }
        if from_direct_fragment {
            return true;
        }
        match classify_live_fmp_packet(&packet) {
            LiveFmpPacketClass::Established => {
                push(DataplaneRawIngress::from_live_received(
                    PacketProtocol::Fmp,
                    packet,
                ));
                true
            }
            LiveFmpPacketClass::Control { phase } => {
                control_ingress.push(DataplaneFmpControlIngress::new(phase, packet));
                false
            }
            LiveFmpPacketClass::RawDrop => {
                push(DataplaneRawIngress::from_live_received(
                    PacketProtocol::Fmp,
                    packet,
                ));
                true
            }
        }
    }
}

impl<C> DataplaneRawIngressSource for DataplaneFmpPacketRxSource<'_, C>
where
    C: DataplaneFspSourceClassifier,
{
    fn drain_raw_ingress<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(DataplaneRawIngress),
    {
        let mut drained = 0;
        let Self {
            rx,
            first,
            direct_fsp_sources,
            direct_fsp_reassembler,
            control_ingress,
        } = self;

        if drained < limit
            && let Some(packet) = first.take()
        {
            let keep_draining = Self::push_packet(
                direct_fsp_sources,
                direct_fsp_reassembler
                    .as_mut()
                    .map(|reassembler| &mut **reassembler),
                control_ingress,
                packet,
                &mut push,
            );
            drained += 1;
            if !keep_draining {
                return drained;
            }
        }
        drained += rx.drain_ready(limit.saturating_sub(drained), |packet| {
            Self::push_packet(
                direct_fsp_sources,
                direct_fsp_reassembler
                    .as_mut()
                    .map(|reassembler| &mut **reassembler),
                control_ingress,
                packet,
                &mut push,
            )
        });
        drained
    }
}

fn classify_direct_fsp_packet<C>(
    direct_fsp_sources: &mut C,
    packet: &ReceivedPacket,
) -> Option<DataplaneRawIngress>
where
    C: DataplaneFspSourceClassifier,
{
    let prefix = FspWireHeader::parse(&packet.data).ok()?;
    if prefix.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT == 0 {
        return None;
    }
    let source = direct_fsp_sources.direct_fsp_source(packet.transport_id, &packet.remote_addr)?;
    Some(
        DataplaneRawIngress::from_live_received(PacketProtocol::Fsp, packet.clone())
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

pub(crate) trait DataplaneRawIngressSource {
    fn drain_raw_ingress<F>(&mut self, limit: usize, push: F) -> usize
    where
        F: FnMut(DataplaneRawIngress);
}

pub(crate) trait DataplaneCompletionSource {
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
