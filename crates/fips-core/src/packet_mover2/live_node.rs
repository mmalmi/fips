#[derive(Debug)]
pub(crate) struct PacketMover2LiveNode<W = CopyCryptoWorker> {
    driver: PacketMover2TurnDriver<W>,
    routes: PacketMover2LiveRouteTable,
    deferred_endpoint_commands: Vec<NodeEndpointCommand>,
}

impl<W: StatelessCryptoWorker> PacketMover2LiveNode<W> {
    pub(crate) fn new(config: AdmissionConfig, worker: W) -> Self {
        Self {
            driver: PacketMover2TurnDriver::new(config, worker),
            routes: PacketMover2LiveRouteTable::default(),
            deferred_endpoint_commands: Vec::new(),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.driver.register_owner(owner, config);
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.driver.owner_mut(owner)
    }

    pub(crate) fn routes(&self) -> &PacketMover2LiveRouteTable {
        &self.routes
    }

    pub(crate) fn routes_mut(&mut self) -> &mut PacketMover2LiveRouteTable {
        &mut self.routes
    }

    pub(crate) fn driver_mut(&mut self) -> &mut PacketMover2TurnDriver<W> {
        &mut self.driver
    }

    pub(crate) fn deferred_endpoint_commands(&self) -> &[NodeEndpointCommand] {
        &self.deferred_endpoint_commands
    }

    pub(crate) fn take_deferred_endpoint_commands(&mut self) -> Vec<NodeEndpointCommand> {
        std::mem::take(&mut self.deferred_endpoint_commands)
    }

    pub(crate) async fn pump_turn<RI, Resolver, Transports>(
        &mut self,
        raw_ingress: &mut RI,
        raw_ingress_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        endpoint_resolver: Resolver,
        transports: &Transports,
        crypto_limit: usize,
    ) -> PacketMover2LiveNodeTurn
    where
        RI: PacketMover2RawIngressSource,
        Resolver: PacketMover2EndpointIdentityResolver,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        self.driver
            .pump_aead_live_node_route_table_turn(
                raw_ingress,
                &mut self.routes,
                raw_ingress_limit,
                endpoint_priority_rx,
                endpoint_bulk_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                &mut self.deferred_endpoint_commands,
                tun_tx,
                endpoint_tx,
                endpoint_resolver,
                transports,
                crypto_limit,
            )
            .await
    }

    pub(crate) async fn pump_packet_rx_turn<Resolver, Transports>(
        &mut self,
        packet_rx: &mut PacketRx,
        packet_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        endpoint_resolver: Resolver,
        transports: &Transports,
        crypto_limit: usize,
    ) -> PacketMover2LiveNodeTurn
    where
        Resolver: PacketMover2EndpointIdentityResolver,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        self.driver
            .pump_aead_live_node_packet_rx_route_table_turn(
                packet_rx,
                &mut self.routes,
                packet_limit,
                endpoint_priority_rx,
                endpoint_bulk_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                &mut self.deferred_endpoint_commands,
                tun_tx,
                endpoint_tx,
                endpoint_resolver,
                transports,
                crypto_limit,
            )
            .await
    }
}
