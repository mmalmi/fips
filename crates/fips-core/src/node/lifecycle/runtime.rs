use super::*;

impl Node {
    // === State Transitions ===

    /// Start the node.
    ///
    /// Initializes the TUN interface (if configured), spawns I/O threads,
    /// and transitions to the Running state.
    pub async fn start(&mut self) -> Result<(), NodeError> {
        node_start_debug_log("Node::start begin");
        if !self.state.can_start() {
            return Err(NodeError::AlreadyStarted);
        }
        self.state = NodeState::Starting;
        node_start_debug_log("Node::start state set to starting");

        // Create packet channel for transport -> Node communication
        let packet_buffer_size = self.config.node.buffers.packet_channel;
        let (mut packet_tx, packet_rx) = packet_channel(packet_buffer_size);
        self.dataplane_fast_ingress_rx = Some(
            self.dataplane
                .attach_established_fast_ingress(&mut packet_tx),
        );
        self.packet_tx = Some(packet_tx.clone());
        self.packet_rx = Some(packet_rx);
        node_start_debug_log("Node::start packet channel created");

        // Initialize transports first (before TUN, before Nostr discovery).
        node_start_debug_log("Node::start create transports begin");
        let transport_handles = self.create_transports(&packet_tx).await;
        node_start_debug_log(format!(
            "Node::start create transports complete count={}",
            transport_handles.len()
        ));

        for mut handle in transport_handles {
            let transport_id = handle.transport_id();
            let transport_type = handle.transport_type().name;
            let name = handle.name().map(|s| s.to_string());

            node_start_debug_log(format!(
                "Node::start transport start begin id={} type={} name={:?}",
                transport_id, transport_type, name
            ));
            match handle.start().await {
                Ok(()) => {
                    node_start_debug_log(format!(
                        "Node::start transport start ok id={} type={}",
                        transport_id, transport_type
                    ));
                    self.udp_transport_resolution_cache.clear();
                    self.transports.insert(transport_id, handle);
                }
                Err(e) => {
                    node_start_debug_log(format!(
                        "Node::start transport start error id={} type={} error={}",
                        transport_id, transport_type, e
                    ));
                    if let Some(ref n) = name {
                        warn!(transport_type, name = %n, error = %e, "Transport failed to start");
                    } else {
                        warn!(transport_type, error = %e, "Transport failed to start");
                    }
                }
            }
        }

        if !self.transports.is_empty() {
            info!(count = self.transports.len(), "Transports initialized");
        }

        if self.config.node.discovery.nostr.enabled {
            node_start_debug_log("Node::start nostr discovery start begin");
            match NostrDiscovery::start(&self.identity, self.config.node.discovery.nostr.clone())
                .await
            {
                Ok(runtime) => {
                    node_start_debug_log("Node::start nostr discovery runtime created");
                    if let Err(err) = self.refresh_overlay_advert(&runtime).await {
                        warn!(error = %err, "Failed to publish initial Nostr overlay advert");
                    }
                    node_start_debug_log("Node::start nostr overlay advert refreshed");
                    self.nostr_discovery = Some(runtime);
                    self.nostr_discovery_started_at_ms = Some(Self::now_ms());
                    info!("Nostr overlay discovery enabled");
                }
                Err(err) => {
                    node_start_debug_log(format!(
                        "Node::start nostr discovery start error error={}",
                        err
                    ));
                    warn!(error = %err, "Failed to start Nostr overlay discovery");
                }
            }
        }

        // mDNS / DNS-SD LAN discovery. Independent of Nostr — runs even
        // when Nostr is disabled, since it gives us sub-second pairing
        // on the same link without any relay or NAT-traversal roundtrip.
        if self.config.node.discovery.lan.enabled {
            node_start_debug_log("Node::start lan discovery start begin");
            let advertised_udp_port = self
                .transports
                .values()
                .filter(|h| h.is_operational())
                .filter(|h| h.transport_type().name == "udp")
                .find_map(|h| h.local_addr().map(|addr| addr.port()))
                .unwrap_or(0);
            let scope = self.lan_discovery_scope();
            match crate::discovery::lan::LanDiscovery::start(
                &self.identity,
                scope,
                advertised_udp_port,
                self.config.node.discovery.lan.clone(),
            )
            .await
            {
                Ok(runtime) => {
                    node_start_debug_log("Node::start lan discovery start ok");
                    self.lan_discovery = Some(runtime);
                    info!("LAN mDNS discovery enabled");
                }
                Err(err) => {
                    node_start_debug_log(format!(
                        "Node::start lan discovery start error error={}",
                        err
                    ));
                    debug!(error = %err, "LAN mDNS discovery not started");
                }
            }
        }

        self.start_local_instance_discovery();
        self.poll_local_instance_discovery().await;

        // Connect to static peers before TUN is active
        // This allows handshake messages to be sent before we start accepting packets
        node_start_debug_log("Node::start initiate peer connections begin");
        self.initiate_peer_connections().await;
        node_start_debug_log("Node::start initiate peer connections complete");

        // Initialize TUN interface last, after transports and peers are ready
        if self.config.tun.enabled {
            node_start_debug_log("Node::start tun init begin");
            let address = *self.identity.address();
            match TunDevice::create(&self.config.tun, address).await {
                Ok(device) => {
                    let mtu = device.mtu();
                    let name = device.name().to_string();
                    let our_addr = *device.address();

                    info!("TUN device active:");
                    info!("     name: {}", name);
                    info!("  address: {}", device.address());
                    info!("      mtu: {}", mtu);

                    // Calculate max MSS for TCP clamping
                    let effective_mtu = self.effective_ipv6_mtu();
                    let max_mss = effective_mtu.saturating_sub(40).saturating_sub(20); // IPv6 + TCP headers

                    info!("effective MTU: {} bytes", effective_mtu);
                    debug!("   max TCP MSS: {} bytes", max_mss);

                    // On macOS, create a shutdown pipe. Writing to it unblocks the
                    // reader thread's select() loop without closing the TUN fd
                    // (which would cause a double-close when TunDevice drops).
                    #[cfg(target_os = "macos")]
                    let (shutdown_read_fd, shutdown_write_fd) = {
                        let mut fds = [0i32; 2];
                        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                            return Err(NodeError::Tun(crate::upper::tun::TunError::Configure(
                                "failed to create shutdown pipe".into(),
                            )));
                        }
                        (fds[0], fds[1])
                    };

                    // Create writer (dups the fd for independent write access).
                    // Pass path_mtu_lookup so inbound SYN-ACK clamp can read
                    // per-destination path MTU learned via discovery.
                    let (writer, tun_tx) =
                        device.create_writer(max_mss, self.path_mtu_lookup.clone())?;

                    // Spawn writer thread
                    let writer_handle = thread::spawn(move || {
                        writer.run();
                    });

                    // Clone tun_tx for the reader
                    let reader_tun_tx = tun_tx.clone();

                    // Create outbound channel for TUN reader → Node
                    let tun_channel_size = self.config.node.buffers.tun_channel;
                    let (outbound_tx, outbound_rx) =
                        crate::upper::tun::tun_outbound_channel(tun_channel_size);

                    // Spawn reader thread
                    let transport_mtu = self.transport_mtu();
                    let path_mtu_lookup = self.path_mtu_lookup.clone();
                    #[cfg(target_os = "macos")]
                    let reader_handle = thread::spawn(move || {
                        run_tun_reader(
                            device,
                            mtu,
                            our_addr,
                            reader_tun_tx,
                            outbound_tx,
                            transport_mtu,
                            path_mtu_lookup,
                            shutdown_read_fd,
                        );
                    });
                    #[cfg(not(target_os = "macos"))]
                    let reader_handle = thread::spawn(move || {
                        run_tun_reader(
                            device,
                            mtu,
                            our_addr,
                            reader_tun_tx,
                            outbound_tx,
                            transport_mtu,
                            path_mtu_lookup,
                        );
                    });

                    self.tun_state = TunState::Active;
                    self.tun_name = Some(name);
                    self.tun_tx = Some(tun_tx);
                    self.tun_outbound_rx = Some(outbound_rx);
                    self.tun_reader_handle = Some(reader_handle);
                    self.tun_writer_handle = Some(writer_handle);
                    #[cfg(target_os = "macos")]
                    {
                        self.tun_shutdown_fd = Some(shutdown_write_fd);
                    }
                }
                Err(e) => {
                    self.tun_state = TunState::Failed;
                    warn!(error = %e, "Failed to initialize TUN, continuing without it");
                }
            }
            node_start_debug_log("Node::start tun init complete");
        }

        // Initialize DNS responder (independent of TUN).
        //
        // Default bind_addr is "::1" (IPv6 loopback). The shipped
        // fips-dns-setup configures systemd-resolved via a global
        // /etc/systemd/resolved.conf.d/fips.conf drop-in pointing at
        // [::1]:5354, which sidesteps a Linux IPV6_PKTINFO behaviour
        // where self-destined traffic to fips0's address is attributed
        // to fips0 in PKTINFO and gets silently dropped by the
        // mesh-interface filter in src/upper/dns.rs.
        //
        // For mesh-reachable resolution (rare), set bind_addr: "::"
        // in fips.yaml. The mesh-interface filter remains active to
        // prevent hosts-file alias enumeration in that mode.
        // `IPV6_V6ONLY=0` is set explicitly so IPv4 clients on
        // 127.0.0.1 still reach us regardless of kernel sysctl
        // defaults — but only when bind is on a wildcard / IPv6 path.
        if self.config.dns.enabled {
            node_start_debug_log("Node::start dns init begin");
            let addr_str = self.config.dns.bind_addr();
            match addr_str.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    let bind = std::net::SocketAddr::new(ip, self.config.dns.port());
                    match Self::bind_dns_socket(bind) {
                        Ok(socket) => {
                            let dns_channel_size = self.config.node.buffers.dns_channel;
                            let (identity_tx, identity_rx) =
                                tokio::sync::mpsc::channel(dns_channel_size);
                            let dns_ttl = self.config.dns.ttl();
                            let base_hosts = crate::upper::hosts::HostMap::from_peer_configs(
                                self.config.peers(),
                            );
                            let reloader = if self.config.node.system_files_enabled {
                                let hosts_path = std::path::PathBuf::from(
                                    crate::upper::hosts::DEFAULT_HOSTS_PATH,
                                );
                                crate::upper::hosts::HostMapReloader::new(base_hosts, hosts_path)
                            } else {
                                crate::upper::hosts::HostMapReloader::memory_only(base_hosts)
                            };
                            // Resolve the TUN ifindex so the responder can
                            // drop queries arriving on the mesh interface
                            // (fips0). Without this, the `::` bind exposes
                            // /etc/fips/hosts alias probing to any mesh peer.
                            // When TUN isn't enabled or the name can't be
                            // resolved, `None` disables the filter (there
                            // is no mesh surface to defend anyway).
                            let mesh_ifindex = Self::lookup_mesh_ifindex(self.config.tun.name());
                            info!(
                                bind = %bind,
                                hosts = reloader.hosts().len(),
                                mesh_ifindex = ?mesh_ifindex,
                                "DNS responder started for .fips domain (auto-reload enabled)"
                            );
                            let handle = tokio::spawn(crate::upper::dns::run_dns_responder(
                                socket,
                                identity_tx,
                                dns_ttl,
                                reloader,
                                mesh_ifindex,
                            ));
                            self.dns_identity_rx = Some(identity_rx);
                            self.dns_task = Some(handle);
                        }
                        Err(e) => {
                            warn!(bind = %bind, error = %e, "Failed to start DNS responder");
                        }
                    }
                }
                Err(e) => {
                    warn!(addr = %addr_str, error = %e, "Invalid dns.bind_addr; DNS responder not started");
                }
            }
            node_start_debug_log("Node::start dns init complete");
        }

        self.state = NodeState::Running;
        node_start_debug_log("Node::start running");
        info!("Node started:");
        info!("       state: {}", self.state);
        info!("  transports: {}", self.transports.len());
        info!(" connections: {}", self.peers.connection_len());
        Ok(())
    }

    /// Bind a UDP socket for the DNS responder.
    ///
    /// For IPv6 binds (including `::`), sets `IPV6_V6ONLY=0` so the socket
    /// also accepts IPv4-mapped addresses. This guarantees dual-stack
    /// delivery regardless of `net.ipv6.bindv6only` sysctl on the host —
    /// v4 clients on 127.0.0.1 and v6 clients on the fips0 address both
    /// land on the same socket.
    ///
    /// Also enables `IPV6_RECVPKTINFO` on IPv6 sockets so the responder
    /// can learn the arrival interface per packet. The responder uses that
    /// to drop queries arriving on the mesh TUN, closing the hosts-file
    /// probing side-channel created by the `::` bind.
    pub(super) fn bind_dns_socket(
        addr: std::net::SocketAddr,
    ) -> Result<tokio::net::UdpSocket, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6() {
            sock.set_only_v6(false)?;
            #[cfg(unix)]
            Self::set_recv_pktinfo_v6(&sock)?;
        }
        sock.set_nonblocking(true)?;
        sock.bind(&addr.into())?;
        tokio::net::UdpSocket::from_std(sock.into())
    }

    /// Enable `IPV6_RECVPKTINFO` on an IPv6 UDP socket.
    ///
    /// After this setsockopt, each `recvmsg()` call on the socket receives
    /// an `IPV6_PKTINFO` control message containing the arrival interface
    /// index, which the DNS responder uses for its mesh-interface filter.
    #[cfg(unix)]
    pub(super) fn set_recv_pktinfo_v6(sock: &socket2::Socket) -> Result<(), std::io::Error> {
        use std::os::fd::AsRawFd;
        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Resolve the mesh TUN interface index by name.
    ///
    /// Returns `None` if the interface does not exist (e.g. TUN disabled
    /// or not yet created). A `None` result disables the DNS responder's
    /// mesh-interface filter — safe, because if there is no fips0 there
    /// is no mesh exposure to defend against.
    pub(super) fn lookup_mesh_ifindex(name: &str) -> Option<u32> {
        #[cfg(unix)]
        {
            let c_name = std::ffi::CString::new(name).ok()?;
            let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if idx == 0 { None } else { Some(idx) }
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            None
        }
    }

    /// Stop the node.
    ///
    /// Shuts down TUN interface, stops I/O threads, and transitions to
    /// the Stopped state.
    pub async fn stop(&mut self) -> Result<(), NodeError> {
        if !self.state.can_stop() {
            return Err(NodeError::NotStarted);
        }
        self.state = NodeState::Stopping;
        info!(state = %self.state, "Node stopping");

        // Stop DNS responder
        if let Some(handle) = self.dns_task.take() {
            handle.abort();
            debug!("DNS responder stopped");
        }

        // Send disconnect notifications to all active peers before closing transports
        self.send_disconnect_to_all_peers(DisconnectReason::Shutdown)
            .await;

        // Stop Nostr overlay discovery background work and withdraw any advert.
        if let Some(bootstrap) = self.nostr_discovery.take()
            && let Err(e) = bootstrap.shutdown().await
        {
            warn!(error = %e, "Failed to shutdown Nostr overlay discovery");
        }

        // Tear down LAN mDNS responder + browser. Best-effort: the
        // OS will eventually time the advert out via its TTL even if
        // we don't get a clean unregister out before the daemon exits.
        if let Some(lan) = self.lan_discovery.take() {
            lan.shutdown().await;
        }

        if let Some(registry) = self.local_instance_registry.take()
            && let Err(err) = registry.remove()
        {
            debug!(error = %err, "failed to remove same-host FIPS instance record");
        }

        // Shutdown transports (they're packet producers)
        let transport_ids: Vec<_> = self.transports.keys().cloned().collect();
        for transport_id in transport_ids {
            if let Some(mut handle) = self.transports.remove(&transport_id) {
                self.udp_transport_resolution_cache.clear();
                let transport_type = handle.transport_type().name;
                match handle.stop().await {
                    Ok(()) => {
                        info!(transport_id = %transport_id, transport_type, "Transport stopped");
                    }
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            transport_type,
                            error = %e,
                            "Transport stop failed"
                        );
                    }
                }
            }
        }

        // Drop packet channels
        self.packet_tx.take();
        self.packet_rx.take();

        // Shutdown TUN interface
        if let Some(name) = self.tun_name.take() {
            info!(name = %name, "Shutting down TUN interface");

            // Drop the tun_tx to signal the writer to stop
            self.tun_tx.take();

            // Delete the interface (on Linux, causes reader to get EFAULT)
            if let Err(e) = shutdown_tun_interface(&name).await {
                warn!(name = %name, error = %e, "Failed to shutdown TUN interface");
            }

            // On macOS, signal the reader thread to exit by writing to the
            // shutdown pipe. The reader's select() will wake up and break.
            #[cfg(target_os = "macos")]
            if let Some(fd) = self.tun_shutdown_fd.take() {
                unsafe {
                    libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1);
                    libc::close(fd);
                }
            }

            // Wait for threads to finish
            if let Some(handle) = self.tun_reader_handle.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.tun_writer_handle.take() {
                let _ = handle.join();
            }

            self.tun_state = TunState::Disabled;
        }

        self.state = NodeState::Stopped;
        info!(state = %self.state, "Node stopped");
        Ok(())
    }

    /// Send disconnect notifications to all active peers.
    ///
    /// Best-effort: send failures are logged and ignored since the transport
    /// may already be degraded. This runs before transports are shut down.
    pub(super) async fn send_disconnect_to_all_peers(&mut self, reason: DisconnectReason) {
        // Collect node_addrs to avoid borrow conflict with send helper
        let peer_addrs: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.can_send() && peer.has_session())
            .map(|(addr, _)| *addr)
            .collect();

        if peer_addrs.is_empty() {
            debug!(
                total_peers = self.peers.len(),
                "No sendable peers for disconnect notification"
            );
            return;
        }

        let mut sent = 0usize;
        for node_addr in &peer_addrs {
            if self.send_disconnect_to_peer(node_addr, reason).await {
                sent += 1;
            }
        }

        info!(sent, total = peer_addrs.len(), reason = %reason, "Sent disconnect notifications");
    }

    /// Send a Disconnect notification to one peer, swallowing transport failures.
    pub(super) async fn send_disconnect_to_peer(
        &mut self,
        node_addr: &NodeAddr,
        reason: DisconnectReason,
    ) -> bool {
        let plaintext = Disconnect::new(reason).encode();
        match self
            .send_dataplane_fmp_link_plaintext(node_addr, &plaintext, false)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to send disconnect (transport may be down)"
                );
                false
            }
        }
    }
}
