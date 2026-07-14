use super::*;

/// Builder for an embedded FIPS endpoint.
#[derive(Debug, Clone)]
pub struct FipsEndpointBuilder {
    config: Config,
    identity_nsec: Option<String>,
    discovery_scope: Option<String>,
    local_rendezvous: bool,
    local_instance_roles: Vec<crate::discovery::local::LocalInstanceCapability>,
    disable_system_networking: bool,
    packet_channel_capacity: usize,
    #[cfg(feature = "host-ble-transport")]
    host_ble: Option<HostBleAttachment>,
    #[cfg(feature = "host-ble-transport")]
    host_ble_config: Option<crate::config::BleConfig>,
}

#[cfg(feature = "host-ble-transport")]
#[derive(Clone)]
struct HostBleAttachment(Arc<std::sync::Mutex<Option<crate::transport::ble::host::HostBleIo>>>);

#[cfg(feature = "host-ble-transport")]
impl std::fmt::Debug for HostBleAttachment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostBleAttachment(..)")
    }
}

const DEFAULT_ENDPOINT_PACKET_CHANNEL_CAPACITY: usize = 4096;

impl Default for FipsEndpointBuilder {
    fn default() -> Self {
        Self {
            config: Config::new(),
            identity_nsec: None,
            discovery_scope: None,
            local_rendezvous: false,
            local_instance_roles: Vec::new(),
            disable_system_networking: true,
            packet_channel_capacity: DEFAULT_ENDPOINT_PACKET_CHANNEL_CAPACITY,
            #[cfg(feature = "host-ble-transport")]
            host_ble: None,
            #[cfg(feature = "host-ble-transport")]
            host_ble_config: None,
        }
    }
}

impl FipsEndpointBuilder {
    /// Start from an explicit FIPS config.
    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Use an `nsec` or hex secret for the endpoint identity.
    pub fn identity_nsec(mut self, nsec: impl Into<String>) -> Self {
        self.identity_nsec = Some(nsec.into());
        self
    }

    /// Set an application-level discovery scope.
    ///
    /// When the builder owns the default empty connectivity config, this also
    /// enables scoped Nostr discovery, open same-scope peer discovery, local
    /// LAN candidates, host-wide loopback rendezvous, and a UDP NAT advert.
    /// If an explicit transport or Nostr config was supplied, the explicit
    /// config is left in control and the scope is retained as endpoint
    /// metadata; call [`Self::local_rendezvous`] to opt that endpoint into
    /// same-host composition.
    pub fn discovery_scope(mut self, scope: impl Into<String>) -> Self {
        self.discovery_scope = Some(scope.into());
        self
    }

    /// Enable host-wide authenticated loopback composition.
    pub fn local_rendezvous(mut self) -> Self {
        self.local_rendezvous = true;
        self
    }

    /// Advertise a portless same-host role, such as `nostr.pubsub/1`.
    /// Empty, oversized, and excess names are ignored.
    pub fn local_role(mut self, name: impl Into<String>, priority: i16) -> Self {
        let name = name.into().trim().to_string();
        if crate::discovery::local_udp::local_capability_name_is_valid(&name)
            && self.local_instance_roles.len()
                < crate::discovery::local_udp::LOCAL_CAPABILITY_MAX_COUNT
        {
            self.local_instance_roles.push(
                crate::discovery::local::LocalInstanceCapability::role(name)
                    .with_priority(priority),
            );
        }
        self
    }

    /// Disable FIPS-owned TUN and DNS system integration.
    pub fn without_system_tun(mut self) -> Self {
        self.disable_system_networking = true;
        self
    }

    /// Set the app packet/data channel capacity.
    pub fn packet_channel_capacity(mut self, capacity: usize) -> Self {
        self.packet_channel_capacity = capacity.max(1);
        self
    }

    /// Attach one platform-command BLE adapter to this endpoint.
    ///
    /// Cloned builders share a single-use attachment; only the first bind can
    /// consume it. The platform adapter must be pumping commands before bind.
    #[cfg(feature = "host-ble-transport")]
    pub fn host_ble(
        mut self,
        io: crate::transport::ble::host::HostBleIo,
        config: crate::config::BleConfig,
    ) -> Self {
        self.host_ble = Some(HostBleAttachment(Arc::new(std::sync::Mutex::new(Some(io)))));
        self.host_ble_config = Some(config);
        self
    }

    pub(super) fn prepared_config(&self) -> Config {
        let mut config = self.config.clone();
        if let Some(nsec) = &self.identity_nsec {
            config.node.identity = IdentityConfig {
                nsec: Some(nsec.clone()),
                persistent: false,
            };
        }
        if self.disable_system_networking {
            config.tun.enabled = false;
            config.dns.enabled = false;
            config.node.system_files_enabled = false;
        }
        if self.local_rendezvous {
            config.node.discovery.local.enabled = true;
        }
        if let Some(scope) = self.discovery_scope.as_deref() {
            if config
                .node
                .discovery
                .lan
                .scope
                .as_deref()
                .is_none_or(|scope| scope.trim().is_empty())
            {
                config.node.discovery.lan.scope = Some(scope.to_string());
            }
            apply_default_scoped_discovery(&mut config, scope);
        }
        #[cfg(feature = "host-ble-transport")]
        if let Some(ble_config) = &self.host_ble_config {
            config.transports.ble = crate::config::TransportInstances::Single(ble_config.clone());
        }
        config
    }

    /// Bind and start the embedded endpoint.
    pub async fn bind(self) -> Result<FipsEndpoint, FipsEndpointError> {
        self.bind_inner(None).await
    }

    /// Bind with a bounded receiver for direct dataplane endpoint packet runs.
    pub async fn bind_with_direct_receiver(
        self,
    ) -> Result<(FipsEndpoint, FipsEndpointDirectReceiver), FipsEndpointError> {
        let (sink, receiver) = FipsEndpointDirectReceiver::channel();
        let endpoint = self.bind_with_direct_sink(sink).await?;
        Ok((endpoint, receiver))
    }

    /// Bind and start the endpoint with a direct dataplane endpoint-data sink.
    ///
    /// Decrypted dataplane endpoint output is delivered to `sink` synchronously from
    /// the dataplane output path. Generic endpoint events, including loopback sends
    /// and non-dataplane delivery, continue to use the regular receive queue.
    pub async fn bind_with_direct_sink<S>(self, sink: S) -> Result<FipsEndpoint, FipsEndpointError>
    where
        S: FipsEndpointDirectSink,
    {
        self.bind_inner(Some(EndpointDirectSink::new(sink))).await
    }

    async fn bind_inner(
        self,
        direct_sink: Option<EndpointDirectSink>,
    ) -> Result<FipsEndpoint, FipsEndpointError> {
        let config = self.prepared_config();

        let mut node = Node::new(config)?;
        node.set_local_instance_roles(self.local_instance_roles);
        #[cfg(feature = "host-ble-transport")]
        if let Some(attachment) = &self.host_ble {
            let io = attachment
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .ok_or(FipsEndpointError::HostBleAdapterConsumed)?;
            node.set_host_ble_io(io);
        }
        let identity = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
        let npub = identity.npub();
        let node_addr = *identity.node_addr();
        let address = *identity.address();
        let packet_io = node.attach_external_packet_io(self.packet_channel_capacity)?;
        let endpoint_data_io = match direct_sink {
            Some(sink) => {
                node.attach_endpoint_data_io_with_direct_sink(self.packet_channel_capacity, sink)?
            }
            None => node.attach_endpoint_data_io(self.packet_channel_capacity)?,
        };
        node.start().await?;
        let local_capability_directory = node.local_capability_directory();

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = spawn_node_task(node, shutdown_rx);
        let endpoint_control_tx = endpoint_data_io.control_tx;
        let endpoint_data_batches = endpoint_data_io.data_batch_tx;
        let inbound_service_tx = endpoint_data_io.service_event_tx;

        Ok(FipsEndpoint {
            identity,
            npub,
            node_addr,
            address,
            discovery_scope: self.discovery_scope,
            local_capability_directory,
            outbound_packets: packet_io.outbound_tx,
            delivered_packets: Arc::new(Mutex::new(packet_io.inbound_rx)),
            endpoint_control_tx,
            endpoint_data_batches,
            inbound_endpoint_tx: endpoint_data_io.event_tx,
            inbound_endpoint_rx: Arc::new(Mutex::new(EndpointReceiveState::new(
                endpoint_data_io.event_rx,
            ))),
            inbound_service_tx,
            inbound_service_rx: Arc::new(Mutex::new(ServiceReceiveState::new(
                endpoint_data_io.service_event_rx,
            ))),
            registered_services: Arc::new(StdMutex::new(HashMap::new())),
            service_channel_capacity: self.packet_channel_capacity,
            shutdown_tx: std::sync::Mutex::new(Some(shutdown_tx)),
            task: std::sync::Mutex::new(Some(task)),
        })
    }
}
