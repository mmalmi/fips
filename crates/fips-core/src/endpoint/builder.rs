use super::*;

/// Builder for an embedded FIPS endpoint.
#[derive(Debug, Clone)]
pub struct FipsEndpointBuilder {
    config: Config,
    identity_nsec: Option<String>,
    discovery_scope: Option<String>,
    local_ethernet_interfaces: Vec<String>,
    disable_system_networking: bool,
    packet_channel_capacity: usize,
}

const DEFAULT_ENDPOINT_PACKET_CHANNEL_CAPACITY: usize = 8192;

impl Default for FipsEndpointBuilder {
    fn default() -> Self {
        Self {
            config: Config::new(),
            identity_nsec: None,
            discovery_scope: None,
            local_ethernet_interfaces: Vec::new(),
            disable_system_networking: true,
            packet_channel_capacity: DEFAULT_ENDPOINT_PACKET_CHANNEL_CAPACITY,
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
    /// LAN candidates, and a UDP NAT advert. If an explicit transport or
    /// Nostr config was supplied, the explicit config is left in control and
    /// the scope is retained as endpoint metadata.
    pub fn discovery_scope(mut self, scope: impl Into<String>) -> Self {
        self.discovery_scope = Some(scope.into());
        self
    }

    /// Enable host-local Ethernet discovery on a private L2 interface.
    ///
    /// This is intended for veth/TAP interfaces attached to a per-host bridge
    /// shared by FIPS-aware applications. The endpoint announces Ethernet
    /// beacons, listens for matching peers, auto-connects to them, and accepts
    /// inbound handshakes over the interface.
    pub fn local_ethernet(mut self, interface: impl Into<String>) -> Self {
        self.local_ethernet_interfaces.push(interface.into());
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
        config.node.buffers.packet_channel = self.packet_channel_capacity;
        if let Some(scope) = self.discovery_scope.as_deref() {
            config.node.discovery.lan.scope = Some(scope.to_string());
            config.node.discovery.local.enabled = true;
            apply_default_scoped_discovery(&mut config, scope);
        }
        for interface in &self.local_ethernet_interfaces {
            add_endpoint_ethernet_transport(
                &mut config,
                interface,
                self.discovery_scope.as_deref(),
            );
        }
        config
    }

    /// Bind and start the embedded endpoint.
    pub async fn bind(self) -> Result<FipsEndpoint, FipsEndpointError> {
        endpoint_debug_log("FipsEndpointBuilder::bind begin");
        let config = self.prepared_config();
        endpoint_debug_log("FipsEndpointBuilder::bind config prepared");

        let mut node = Node::new(config)?;
        endpoint_debug_log("FipsEndpointBuilder::bind node created");
        let identity = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
        let npub = identity.npub();
        let node_addr = *identity.node_addr();
        let address = *identity.address();
        let packet_io = node.attach_external_packet_io(self.packet_channel_capacity)?;
        endpoint_debug_log("FipsEndpointBuilder::bind packet io attached");
        let endpoint_data_io = node.attach_endpoint_data_io(self.packet_channel_capacity)?;
        endpoint_debug_log("FipsEndpointBuilder::bind endpoint data io attached");
        endpoint_debug_log("FipsEndpointBuilder::bind node.start begin");
        node.start().await?;
        endpoint_debug_log("FipsEndpointBuilder::bind node.start complete");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = spawn_node_task(node, shutdown_rx);
        endpoint_debug_log("FipsEndpointBuilder::bind node task spawned");
        let endpoint_priority_commands = endpoint_data_io.priority_command_tx;
        let endpoint_commands = endpoint_data_io.command_tx;
        #[cfg(unix)]
        let endpoint_bulk_send_runtime = endpoint_data_io.bulk_send_runtime;

        Ok(FipsEndpoint {
            identity,
            npub,
            node_addr,
            address,
            discovery_scope: self.discovery_scope,
            outbound_packets: packet_io.outbound_tx,
            delivered_packets: Arc::new(Mutex::new(packet_io.inbound_rx)),
            endpoint_priority_commands,
            endpoint_commands,
            #[cfg(unix)]
            endpoint_bulk_send_runtime,
            inbound_endpoint_tx: endpoint_data_io.event_tx,
            inbound_endpoint_rx: Arc::new(Mutex::new(EndpointReceiveState::new(
                endpoint_data_io.event_rx,
            ))),
            peer_identity_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            shutdown_tx: std::sync::Mutex::new(Some(shutdown_tx)),
            task: std::sync::Mutex::new(Some(task)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_packet_channel_capacity_default_is_fixed() {
        let config = FipsEndpointBuilder::default().prepared_config();
        assert_eq!(
            config.node.buffers.packet_channel,
            DEFAULT_ENDPOINT_PACKET_CHANNEL_CAPACITY
        );
    }

    #[test]
    fn explicit_endpoint_packet_channel_capacity_applies_to_transport_node_buffer() {
        let config = FipsEndpointBuilder::default()
            .packet_channel_capacity(16_384)
            .prepared_config();
        assert_eq!(config.node.buffers.packet_channel, 16_384);
    }

    #[test]
    fn explicit_endpoint_packet_channel_capacity_keeps_minimum() {
        let config = FipsEndpointBuilder::default()
            .packet_channel_capacity(0)
            .prepared_config();
        assert_eq!(config.node.buffers.packet_channel, 1);
    }
}
