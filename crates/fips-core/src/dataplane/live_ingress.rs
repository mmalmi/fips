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

    pub(crate) fn with_path_mtu(mut self, path_mtu: u16) -> Self {
        self.path_mtu = path_mtu;
        self
    }

}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneIngressHeader {
    Fmp(FmpWireHeader),
    Fsp(FspWireHeader),
}

impl DataplaneIngressHeader {
    pub(crate) fn open_metadata(self) -> (u64, u16, u8) {
        match self {
            Self::Fmp(header) => (
                header.counter(),
                header.ciphertext_offset(),
                header.flags(),
            ),
            Self::Fsp(header) => (
                header.counter(),
                header.ciphertext_offset(),
                header.flags(),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneReceiveEpoch {
    Current,
    Pending,
    Previous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneIngressRoute {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    output: OutputTarget,
    receive_epoch: DataplaneReceiveEpoch,
}

impl DataplaneIngressRoute {
    pub(crate) fn new(owner: OwnerId, generation: u64, output: OutputTarget) -> Self {
        Self {
            owner,
            generation,
            class: PacketClass::Bulk,
            output,
            receive_epoch: DataplaneReceiveEpoch::Current,
        }
    }

    pub(crate) fn with_class(mut self, class: PacketClass) -> Self {
        self.class = class;
        self
    }

    pub(crate) fn with_receive_epoch(mut self, receive_epoch: DataplaneReceiveEpoch) -> Self {
        self.receive_epoch = receive_epoch;
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
    direct_fsp: Arc<RwLock<DataplaneDirectFspSources>>,
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

    fn set_direct_fsp_sources(&self, sources: DataplaneDirectFspSources) {
        *self
            .direct_fsp
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = sources;
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

    fn direct_fsp_sources(&self) -> DataplaneDirectFspSources {
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

    fn matches_run(&self, other: &Self) -> bool {
        self.owner == other.owner && self.lane == other.lane
    }

    fn push(&mut self, packet: SocketPacket) {
        debug_assert!(self.matches_packet(&packet));
        self.packets.push(packet);
    }

    fn append(&mut self, other: Self) {
        debug_assert!(self.matches_run(&other));
        self.packets.extend(other.packets);
    }

    fn into_parts(self) -> (OwnerId, Lane, Vec<SocketPacket>) {
        (self.owner, self.lane, self.packets)
    }

}

#[derive(Debug)]
pub(crate) struct DataplaneFastIngressBatch {
    runs: Vec<DataplaneFastIngressRun>,
    packet_count: usize,
    reservations: Vec<DataplaneFastIngressReservation>,
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
            reservations: vec![reservation],
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.packet_count
    }

    pub(crate) fn absorb(&mut self, mut other: Self) {
        self.reservations.append(&mut other.reservations);
        for run in std::mem::take(&mut other.runs) {
            self.push_run(run);
        }
        other.packet_count = 0;
    }

    fn push_run(&mut self, run: DataplaneFastIngressRun) {
        let run_len = run.len();
        if let Some(last) = self.runs.last_mut() {
            if last.matches_run(&run) {
                last.append(run);
            } else {
                self.runs.push(run);
            }
        } else {
            self.runs.push(run);
        }
        self.packet_count = self.packet_count.saturating_add(run_len);
    }

    fn into_runs(mut self) -> Vec<DataplaneFastIngressRun> {
        for reservation in std::mem::take(&mut self.reservations) {
            reservation.release();
        }
        self.packet_count = 0;
        std::mem::take(&mut self.runs)
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
        let Ok(header) = FmpWireHeader::parse(packet.data.as_slice()) else {
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
            header.ciphertext_offset(),
            route.class,
            route.output,
            packet.data,
        )
        .with_source_path(source_path)
        .with_activity_tick(activity_tick)
        .with_receive_epoch(route.receive_epoch)
        .with_wire_flags(header.flags());
        socket_packet = socket_packet.with_path_mtu(u16::MAX);
        Ok(socket_packet)
    }

    fn direct_fsp_socket_packet_from_received(
        direct_sources: &DataplaneDirectFspSources,
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
        let Ok(header) = FspWireHeader::parse(packet.data.as_slice()) else {
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
            header.ciphertext_offset(),
            route.class,
            route.output,
            packet.data,
        )
        .with_source_path(source_path)
        .with_previous_hop(source.source_addr)
        .with_path_mtu(source.path_mtu)
        .with_activity_tick(activity_tick)
        .with_receive_epoch(route.receive_epoch)
        .with_wire_flags(header.flags());
        DataplaneFastIngressDirectFspResult::Fast(socket_packet)
    }

    fn direct_fsp_socket_packet(
        &self,
        direct_sources: &DataplaneDirectFspSources,
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
        match reassembler.ingest_fragment(packet) {
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
        direct_sources: &DataplaneDirectFspSources,
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
        match reassembler.ingest_fragment(packet) {
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
        if last.matches_packet(&packet) {
            last.push(packet);
        } else {
            runs.push(DataplaneFastIngressRun::new(packet));
        }
    } else {
        runs.push(DataplaneFastIngressRun::new(packet));
    }
}

#[derive(Debug, Default)]
pub(crate) struct DataplaneLiveRouteTable {
    fmp: HashMap<FmpIngressRouteKey, DataplaneIngressRoute>,
    fsp: HashMap<NodeAddr, DataplaneIngressRoute>,
    tun_outbound: HashMap<FipsTunDestinationPrefix, DataplaneTunOutboundRoute>,
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

    pub(crate) fn set_established_fast_ingress_direct_fsp_sources(
        &self,
        sources: DataplaneDirectFspSources,
    ) {
        self.established_fast_ingress
            .set_direct_fsp_sources(sources);
    }

    pub(crate) fn register_tun_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: DataplaneTunOutboundRoute,
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

impl DataplaneLiveRouteTable {
    fn route_tun_outbound(
        &self,
        packet: &[u8],
        dest: FipsTunDestinationPrefix,
    ) -> Result<&DataplaneTunOutboundRoute, DataplaneTunOutboundDropReason> {
        self.tun_outbound
            .get(&dest)
            .ok_or(DataplaneTunOutboundDropReason::NoRoute)?
            .route_packet(packet)
    }

    fn route_endpoint_data_batch(
        &self,
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
    packet: ReceivedPacket,
}

impl DataplaneFmpControlIngress {
    fn new(packet: ReceivedPacket) -> Self {
        Self { packet }
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

// `None` keeps a key ambiguous after conflicting sources are merged.
type DataplaneDirectFspSourceMatch = Option<DataplaneDirectFspSource>;

#[derive(Clone, Debug, Default)]
pub(crate) struct DataplaneDirectFspTransportSources {
    pub(crate) exact: HashMap<TransportAddr, DataplaneDirectFspSource>,
    by_ip: HashMap<std::net::IpAddr, DataplaneDirectFspSourceMatch>,
    by_wildcard_port: HashMap<u16, DataplaneDirectFspSourceMatch>,
}

pub(crate) type DataplaneDirectFspSources =
    Arc<HashMap<TransportId, DataplaneDirectFspTransportSources>>;

pub(crate) fn dataplane_direct_fsp_sources_from_exact(
    sources: impl IntoIterator<Item = (TransportId, TransportAddr, DataplaneDirectFspSource)>,
) -> DataplaneDirectFspSources {
    let mut exact_candidates = HashMap::<
        TransportId,
        HashMap<TransportAddr, DataplaneDirectFspSourceMatch>,
    >::new();
    for (transport_id, remote_addr, source) in sources {
        merge_dataplane_direct_fsp_source(
            exact_candidates.entry(transport_id).or_default(),
            remote_addr,
            source,
        );
    }

    let mut by_transport = HashMap::with_capacity(exact_candidates.len());
    for (transport_id, candidates) in exact_candidates {
        let mut indexed = DataplaneDirectFspTransportSources::default();
        for (remote_addr, source) in candidates {
            let Some(source) = source else {
                continue;
            };
            if let Some(socket_addr) = direct_fsp_socket_addr(&remote_addr) {
                if socket_addr.ip().is_unspecified() {
                    merge_dataplane_direct_fsp_source(
                        &mut indexed.by_wildcard_port,
                        socket_addr.port(),
                        source,
                    );
                } else {
                    merge_dataplane_direct_fsp_source(
                        &mut indexed.by_ip,
                        socket_addr.ip(),
                        source,
                    );
                }
            }
            indexed.exact.insert(remote_addr, source);
        }
        by_transport.insert(transport_id, indexed);
    }

    Arc::new(by_transport)
}

pub(crate) fn lookup_direct_fsp_source(
    direct_fsp_sources: &DataplaneDirectFspSources,
    transport_id: TransportId,
    remote_addr: &TransportAddr,
) -> Option<DataplaneDirectFspSource> {
    let transport_sources = direct_fsp_sources.get(&transport_id)?;
    if let Some(source) = transport_sources.exact.get(remote_addr).copied() {
        return Some(source);
    }

    let remote_socket_addr = direct_fsp_socket_addr(remote_addr)?;
    if !remote_socket_addr.ip().is_unspecified()
        && let Some(source) = transport_sources.by_ip.get(&remote_socket_addr.ip())
    {
        return *source;
    }
    transport_sources
        .by_wildcard_port
        .get(&remote_socket_addr.port())
        .copied()
        .flatten()
}

fn merge_dataplane_direct_fsp_source<K: Eq + std::hash::Hash>(
    sources: &mut HashMap<K, DataplaneDirectFspSourceMatch>,
    key: K,
    source: DataplaneDirectFspSource,
) {
    let matched = sources.entry(key).or_insert(Some(source));
    match matched {
        Some(existing) if existing.source_addr == source.source_addr => {
            existing.path_mtu = existing.path_mtu.min(source.path_mtu);
        }
        _ => *matched = None,
    }
}

/// Drains live transport packets from `PacketRx` as dataplane ingress.
///
/// FSP direct transport ingress needs authenticated source context, so callers
/// pass a current transport-address classifier. Unflagged established packets
/// stay on the FMP path.
pub(crate) struct DataplaneFmpPacketRxSource<'a> {
    rx: &'a mut PacketRx,
    first: Option<ReceivedPacket>,
    direct_fsp_sources: DataplaneDirectFspSources,
    direct_fsp_reassembler: Option<&'a mut DataplaneDirectFspReassembler>,
    control_ingress: Vec<DataplaneFmpControlIngress>,
}

impl<'a> DataplaneFmpPacketRxSource<'a> {
    pub(crate) fn with_first_direct_fsp_sources_and_reassembler(
        rx: &'a mut PacketRx,
        first: Option<ReceivedPacket>,
        direct_fsp_sources: DataplaneDirectFspSources,
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
        direct_fsp_sources: &DataplaneDirectFspSources,
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
                let Some(source) = lookup_direct_fsp_source(
                    direct_fsp_sources,
                    packet.transport_id,
                    &packet.remote_addr,
                )
                else {
                    return true;
                };
                if packet.data.len() > source.path_mtu as usize {
                    return true;
                }
                match reassembler.ingest_fragment(packet) {
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
            LiveFmpPacketClass::Control => {
                control_ingress.push(DataplaneFmpControlIngress::new(packet));
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

impl DataplaneRawIngressSource for DataplaneFmpPacketRxSource<'_> {
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

fn classify_direct_fsp_packet(
    direct_fsp_sources: &DataplaneDirectFspSources,
    packet: &ReceivedPacket,
) -> Option<DataplaneRawIngress>
{
    let prefix = FspWireHeader::parse(packet.data.as_slice()).ok()?;
    if prefix.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT == 0 {
        return None;
    }
    let source =
        lookup_direct_fsp_source(direct_fsp_sources, packet.transport_id, &packet.remote_addr)?;
    Some(
        DataplaneRawIngress::from_live_received(PacketProtocol::Fsp, packet.clone())
            .with_fsp_source(source.source_addr)
            .with_previous_hop(source.source_addr)
            .with_path_mtu(source.path_mtu),
    )
}

fn direct_fsp_socket_addr(addr: &TransportAddr) -> Option<std::net::SocketAddr> {
    addr.as_str()?.parse::<std::net::SocketAddr>().ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveFmpPacketClass {
    Established,
    Control,
    RawDrop,
}

fn classify_live_fmp_packet(packet: &ReceivedPacket) -> LiveFmpPacketClass {
    if packet.data.len() < FMP_COMMON_PREFIX_SIZE {
        return LiveFmpPacketClass::RawDrop;
    }
    let Some(first) = packet.data.as_slice().first().copied() else {
        return LiveFmpPacketClass::RawDrop;
    };
    let version = first >> 4;
    let phase = first & 0x0f;
    if version == FMP_VERSION && phase == FMP_PHASE_ESTABLISHED {
        LiveFmpPacketClass::Established
    } else if version != FMP_VERSION || matches!(phase, FMP_PHASE_MSG1 | FMP_PHASE_MSG2) {
        LiveFmpPacketClass::Control
    } else {
        LiveFmpPacketClass::RawDrop
    }
}

pub(crate) trait DataplaneRawIngressSource {
    fn drain_raw_ingress<F>(&mut self, limit: usize, push: F) -> usize
    where
        F: FnMut(DataplaneRawIngress);
}
