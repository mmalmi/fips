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
        send_token: Option<u64>,
    ) -> DataplaneEndpointDataBatchRoute {
        let Some(route) = self.endpoint.get(remote.node_addr()) else {
            return DataplaneEndpointDataBatchRoute::deferred(payloads);
        };
        route.route_payloads(payloads, activity_tick, send_token)
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
