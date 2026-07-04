use super::*;

impl Node {
    fn new_dataplane_node() -> DataplaneNode {
        DataplaneLiveNode::new(AdmissionConfig::new(1024, 4096))
    }

    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let identity = config.create_identity()?;
        let node_addr = *identity.node_addr();
        let is_leaf_only = config.is_leaf_only();

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let mut bloom_state = if is_leaf_only {
            BloomState::leaf_only(node_addr)
        } else {
            BloomState::new(node_addr)
        };
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;
        let backoff_base_secs = config.node.discovery.backoff_base_secs;
        let backoff_max_secs = config.node.discovery.backoff_max_secs;
        let forward_min_interval_secs = config.node.discovery.forward_min_interval_secs;

        let (host_map, peer_acl) = Self::host_map_and_peer_acl(&config);
        let configured_peer_send_weights = ConfiguredPeerSendWeights::from_config(&config);

        Ok(Self {
            identity,
            startup_epoch,
            started_at: std::time::Instant::now(),
            config,
            state: NodeState::Created,
            is_leaf_only,
            tree_state,
            bloom_state,
            coord_cache,
            learned_routes: LearnedRouteTable::default(),
            session_direct_degradation: SessionDirectDegradation::default(),
            recent_requests: RecentDiscoveryRequests::default(),
            transports: HashMap::new(),
            udp_transport_resolution_cache: lifecycle::UdpTransportResolutionCache::default(),
            transport_drops: TransportDropTracker::default(),
            transport_socket_drops: TransportDropTracker::default(),
            transport_namespace_drops: TransportDropTracker::default(),
            links: LinkRegistry::default(),
            packet_tx: None,
            packet_rx: None,
            dataplane: Self::new_dataplane_node(),
            dataplane_fast_ingress_rx: None,
            dataplane_transport_send_worker: Default::default(),
            peers: PeerLifecycleRegistry::default(),
            sessions: SessionRegistry::default(),
            identity_cache: IdentityCache::default(),
            pending_session_traffic: PendingSessionTrafficQueues::default(),
            pending_lookups: handlers::discovery::PendingDiscoveryLookups::default(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            stats_history: stats_history::StatsHistory::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            external_packet_tx: None,
            endpoint_control_rx: None,
            endpoint_data_rx: None,
            endpoint_events: EndpointEventRuntime::default(),
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(target_os = "macos")]
            tun_shutdown_fd: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            pending_outbound: PendingOutboundHandshakes::default(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            discovery_backoff: DiscoveryBackoff::with_params(backoff_base_secs, backoff_max_secs),
            discovery_forward_limiter: DiscoveryForwardRateLimiter::with_interval(
                std::time::Duration::from_secs(forward_min_interval_secs),
            ),
            pending_connects: Vec::new(),
            retry_pending: retry::PendingRouteRetries::default(),
            nostr_discovery: None,
            nostr_discovery_started_at_ms: None,
            lan_discovery: None,
            local_instance_registry: None,
            local_instance_started_at_ms: None,
            last_local_instance_publish_ms: None,
            last_local_instance_scan_ms: None,
            startup_open_discovery_sweep_done: false,
            bootstrap_transports: BootstrapTransports::default(),
            discovery_fallback_transit: DiscoveryFallbackTransit::default(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            local_send_failures: LocalSendFailures::default(),
            last_rx_loop_maintenance_timeout_at: None,
            peer_aliases: HashMap::new(),
            configured_peer_send_weights,
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Create a node with a specific identity.
    ///
    /// This constructor validates cross-field config invariants before
    /// constructing the node, same as [`Node::new`].
    pub fn with_identity(identity: Identity, config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let node_addr = *identity.node_addr();

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        let mut bloom_state = BloomState::new(node_addr);
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;

        let (host_map, peer_acl) = Self::host_map_and_peer_acl(&config);
        let configured_peer_send_weights = ConfiguredPeerSendWeights::from_config(&config);

        Ok(Self {
            identity,
            startup_epoch,
            started_at: std::time::Instant::now(),
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state,
            bloom_state,
            coord_cache,
            learned_routes: LearnedRouteTable::default(),
            session_direct_degradation: SessionDirectDegradation::default(),
            recent_requests: RecentDiscoveryRequests::default(),
            transports: HashMap::new(),
            udp_transport_resolution_cache: lifecycle::UdpTransportResolutionCache::default(),
            transport_drops: TransportDropTracker::default(),
            transport_socket_drops: TransportDropTracker::default(),
            transport_namespace_drops: TransportDropTracker::default(),
            links: LinkRegistry::default(),
            packet_tx: None,
            packet_rx: None,
            dataplane: Self::new_dataplane_node(),
            dataplane_fast_ingress_rx: None,
            dataplane_transport_send_worker: Default::default(),
            peers: PeerLifecycleRegistry::default(),
            sessions: SessionRegistry::default(),
            identity_cache: IdentityCache::default(),
            pending_session_traffic: PendingSessionTrafficQueues::default(),
            pending_lookups: handlers::discovery::PendingDiscoveryLookups::default(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            stats_history: stats_history::StatsHistory::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            external_packet_tx: None,
            endpoint_control_rx: None,
            endpoint_data_rx: None,
            endpoint_events: EndpointEventRuntime::default(),
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(target_os = "macos")]
            tun_shutdown_fd: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            pending_outbound: PendingOutboundHandshakes::default(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            discovery_backoff: DiscoveryBackoff::new(),
            discovery_forward_limiter: DiscoveryForwardRateLimiter::new(),
            pending_connects: Vec::new(),
            retry_pending: retry::PendingRouteRetries::default(),
            nostr_discovery: None,
            nostr_discovery_started_at_ms: None,
            lan_discovery: None,
            local_instance_registry: None,
            local_instance_started_at_ms: None,
            last_local_instance_publish_ms: None,
            last_local_instance_scan_ms: None,
            startup_open_discovery_sweep_done: false,
            bootstrap_transports: BootstrapTransports::default(),
            discovery_fallback_transit: DiscoveryFallbackTransit::default(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            local_send_failures: LocalSendFailures::default(),
            last_rx_loop_maintenance_timeout_at: None,
            peer_aliases: HashMap::new(),
            configured_peer_send_weights,
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.is_leaf_only = true;
        node.bloom_state = BloomState::leaf_only(*node.identity.node_addr());
        Ok(node)
    }

    pub(super) fn host_map_and_peer_acl(config: &Config) -> (Arc<HostMap>, acl::PeerAclReloader) {
        let base_host_map = HostMap::from_peer_configs(config.peers());
        if !config.node.system_files_enabled {
            return (
                Arc::new(base_host_map.clone()),
                acl::PeerAclReloader::memory_only(base_host_map),
            );
        }

        let mut host_map = base_host_map.clone();
        let hosts_path = std::path::PathBuf::from(crate::upper::hosts::DEFAULT_HOSTS_PATH);
        let hosts_file = HostMap::load_hosts_file(std::path::Path::new(
            crate::upper::hosts::DEFAULT_HOSTS_PATH,
        ));
        host_map.merge(hosts_file);
        let peer_acl = acl::PeerAclReloader::with_alias_sources(
            std::path::PathBuf::from(acl::DEFAULT_PEERS_ALLOW_PATH),
            std::path::PathBuf::from(acl::DEFAULT_PEERS_DENY_PATH),
            base_host_map,
            hosts_path,
        );
        (Arc::new(host_map), peer_acl)
    }

    /// Create transport instances from configuration.
    ///
    /// Returns a vector of TransportHandles for all configured transports.
    pub(super) async fn create_transports(&mut self, packet_tx: &PacketTx) -> Vec<TransportHandle> {
        let mut transports = Vec::new();

        // Collect UDP configs with optional names to avoid borrow conflicts
        let udp_instances: Vec<_> = self
            .config
            .transports
            .udp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        // Create UDP transport instances
        for (name, udp_config) in udp_instances {
            let transport_id = self.allocate_transport_id();
            let udp = UdpTransport::new(transport_id, name, udp_config, packet_tx.clone());
            transports.push(TransportHandle::Udp(udp));
        }

        #[cfg(feature = "sim-transport")]
        {
            let sim_instances: Vec<_> = self
                .config
                .transports
                .sim
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            for (name, sim_config) in sim_instances {
                let transport_id = self.allocate_transport_id();
                let sim = crate::transport::sim::SimTransport::new(
                    transport_id,
                    name,
                    sim_config,
                    packet_tx.clone(),
                );
                transports.push(TransportHandle::Sim(sim));
            }
        }

        // Create Ethernet transport instances where raw-socket support exists.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let eth_instances: Vec<_> = self
                .config
                .transports
                .ethernet
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();
            let xonly = self.identity.pubkey();
            for (name, eth_config) in eth_instances {
                let mut eth_config = eth_config;
                if eth_config.discovery_scope.is_none() {
                    eth_config.discovery_scope = self.lan_discovery_scope();
                }
                let transport_id = self.allocate_transport_id();
                let mut eth =
                    EthernetTransport::new(transport_id, name, eth_config, packet_tx.clone());
                eth.set_local_pubkey(xonly);
                transports.push(TransportHandle::Ethernet(eth));
            }
        }

        // Create TCP transport instances
        let tcp_instances: Vec<_> = self
            .config
            .transports
            .tcp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tcp_config) in tcp_instances {
            let transport_id = self.allocate_transport_id();
            let tcp = TcpTransport::new(transport_id, name, tcp_config, packet_tx.clone());
            transports.push(TransportHandle::Tcp(tcp));
        }

        // Create Tor transport instances
        let tor_instances: Vec<_> = self
            .config
            .transports
            .tor
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tor_config) in tor_instances {
            let transport_id = self.allocate_transport_id();
            let tor = TorTransport::new(transport_id, name, tor_config, packet_tx.clone());
            transports.push(TransportHandle::Tor(tor));
        }

        let webrtc_instances: Vec<_> = self
            .config
            .transports
            .webrtc
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        #[cfg(feature = "webrtc-transport")]
        {
            for (name, webrtc_config) in webrtc_instances {
                let transport_id = self.allocate_transport_id();
                match WebRtcTransport::new(
                    transport_id,
                    name,
                    webrtc_config,
                    packet_tx.clone(),
                    &self.identity,
                    &self.config.node.discovery.nostr,
                ) {
                    Ok(webrtc) => transports.push(TransportHandle::WebRtc(Box::new(webrtc))),
                    Err(err) => {
                        warn!(
                            transport_id = %transport_id,
                            error = %err,
                            "failed to initialize WebRTC transport"
                        );
                    }
                }
            }
        }
        #[cfg(not(feature = "webrtc-transport"))]
        if !webrtc_instances.is_empty() {
            warn!("WebRTC transport configured but this build lacks WebRTC transport support");
        }

        // Create BLE transport instances
        #[cfg(bluer_available)]
        {
            let ble_instances: Vec<_> = self
                .config
                .transports
                .ble
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            #[cfg(all(bluer_available, not(test)))]
            for (name, ble_config) in ble_instances {
                let transport_id = self.allocate_transport_id();
                let adapter = ble_config.adapter().to_string();
                let mtu = ble_config.mtu();
                match crate::transport::ble::io::BluerIo::new(&adapter, mtu).await {
                    Ok(io) => {
                        let mut ble = crate::transport::ble::BleTransport::new(
                            transport_id,
                            name,
                            ble_config,
                            io,
                            packet_tx.clone(),
                        );
                        ble.set_local_pubkey(self.identity.pubkey().serialize());
                        transports.push(TransportHandle::Ble(ble));
                    }
                    Err(e) => {
                        tracing::warn!(adapter = %adapter, error = %e, "failed to initialize BLE adapter");
                    }
                }
            }

            #[cfg(any(not(bluer_available), test))]
            if !ble_instances.is_empty() {
                #[cfg(not(test))]
                tracing::warn!("BLE transport configured but this build lacks BlueZ support");
            }
        }

        transports
    }

    /// Find an operational transport that matches the given transport type name.
    ///
    /// Adopted UDP bootstrap transports are point-to-point sockets handed off
    /// from Nostr/STUN traversal. They must not be reused for ordinary
    /// `udp host:port` dials discovered through static config, mDNS, or overlay
    /// adverts: on macOS a `send_to` through the wrong adopted socket can fail
    /// with `EINVAL`, and even on platforms that allow it the packet would use
    /// the wrong 5-tuple/NAT mapping. Prefer configured transports and make the
    /// choice deterministic by lowest transport id instead of HashMap order.
    pub(super) fn find_transport_for_type(&self, transport_type: &str) -> Option<TransportId> {
        self.transports
            .iter()
            .filter(|(id, handle)| {
                handle.transport_type().name == transport_type
                    && handle.is_operational()
                    && !self.bootstrap_transports.contains(id)
            })
            .min_by_key(|(id, _)| id.as_u32())
            .map(|(id, _)| *id)
    }

    /// Resolve an Ethernet peer address ("interface/mac") to a transport ID
    /// and binary TransportAddr.
    ///
    /// Finds the Ethernet transport instance bound to the named interface
    /// and parses the MAC portion into a 6-byte TransportAddr.
    #[allow(unused_variables)]
    pub(super) fn resolve_ethernet_addr(
        &self,
        addr_str: &str,
    ) -> Result<(TransportId, TransportAddr), NodeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let (iface, mac_str) = addr_str.split_once('/').ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "invalid Ethernet address format '{}': expected 'interface/mac'",
                    addr_str
                ))
            })?;

            // Find the Ethernet transport bound to this interface
            let transport_id = self
                .transports
                .iter()
                .find(|(_, handle)| {
                    handle.transport_type().name == "ethernet"
                        && handle.is_operational()
                        && handle.interface_name() == Some(iface)
                })
                .map(|(id, _)| *id)
                .ok_or_else(|| {
                    NodeError::NoTransportForType(format!(
                        "no operational Ethernet transport for interface '{}'",
                        iface
                    ))
                })?;

            let mac = crate::transport::ethernet::parse_mac_string(mac_str).map_err(|e| {
                NodeError::NoTransportForType(format!("invalid MAC in '{}': {}", addr_str, e))
            })?;

            Ok((transport_id, TransportAddr::from_bytes(&mac)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(NodeError::NoTransportForType(
                "Ethernet transport is not supported on this platform".to_string(),
            ))
        }
    }

    /// Resolve a BLE address string (`"adapter/AA:BB:CC:DD:EE:FF"`) to a
    /// (TransportId, TransportAddr) pair by finding the BLE transport
    /// instance matching the adapter name.
    #[cfg(bluer_available)]
    pub(super) fn resolve_ble_addr(
        &self,
        addr_str: &str,
    ) -> Result<(TransportId, TransportAddr), NodeError> {
        let ta = TransportAddr::from_string(addr_str);
        let adapter = crate::transport::ble::addr::adapter_from_addr(&ta).ok_or_else(|| {
            NodeError::NoTransportForType(format!(
                "invalid BLE address format '{}': expected 'adapter/mac'",
                addr_str
            ))
        })?;

        // Find the BLE transport for this adapter
        let transport_id = self
            .transports
            .iter()
            .find(|(_, handle)| handle.transport_type().name == "ble" && handle.is_operational())
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "no operational BLE transport for adapter '{}'",
                    adapter
                ))
            })?;

        // Validate the address format
        crate::transport::ble::addr::BleAddr::parse(addr_str).map_err(|e| {
            NodeError::NoTransportForType(format!("invalid BLE address '{}': {}", addr_str, e))
        })?;

        Ok((transport_id, TransportAddr::from_string(addr_str)))
    }
}
