impl Node {
    fn dataplane_configured_static_udp_source_addrs(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: crate::transport::TransportId,
    ) -> Vec<crate::transport::TransportAddr> {
        let Some(peer_config) = self.configured_peer(peer_node_addr) else {
            return Vec::new();
        };
        let Some(transport) = self.transports.get(&transport_id) else {
            return Vec::new();
        };
        if transport.transport_type().name != "udp" {
            return Vec::new();
        }

        let mut addrs = Vec::new();
        for candidate in &peer_config.addresses {
            if !candidate.is_configured()
                || !candidate.transport.eq_ignore_ascii_case("udp")
                || candidate.addr.eq_ignore_ascii_case("nat")
            {
                continue;
            }

            let candidate_addr = crate::transport::TransportAddr::from_string(&candidate.addr);
            let mut added_resolved_addr = false;
            if let Some(socket_addr) = transport.resolved_udp_socket_addr_if_cached(&candidate_addr)
                && let Some((candidate_transport_id, _)) =
                    self.find_udp_transport_for_remote_addr(socket_addr, candidate.provenance)
                && candidate_transport_id == transport_id
            {
                let resolved_addr = crate::transport::TransportAddr::from_socket_addr(socket_addr);
                if !addrs.iter().any(|existing| existing == &resolved_addr) {
                    addrs.push(resolved_addr);
                }
                added_resolved_addr = true;
            }
            if added_resolved_addr {
                continue;
            }

            if let Some(wildcard_addrs) = dataplane_static_udp_port_wildcard_addrs(&candidate.addr)
            {
                for wildcard_addr in wildcard_addrs {
                    if !addrs.iter().any(|existing| existing == &wildcard_addr) {
                        addrs.push(wildcard_addr);
                    }
                }
            }
        }
        addrs
    }

    pub(in crate::node) fn sync_dataplane_fsp_owner_from_current_session(
        &mut self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> bool {
        self.sync_dataplane_fsp_owner_from_current_session_via(
            node_addr,
            None,
            coords_warmup_remaining,
        )
    }

    pub(in crate::node) fn sync_dataplane_fsp_owner_from_current_session_via(
        &mut self,
        node_addr: &NodeAddr,
        proven_next_hop: Option<NodeAddr>,
        coords_warmup_remaining: u8,
    ) -> bool {
        let Some(snapshot) = self
            .sessions
            .get(node_addr)
            .and_then(Self::dataplane_fsp_owner_session_snapshot)
        else {
            self.remove_dataplane_fsp_owner(node_addr);
            return false;
        };
        self.sync_dataplane_fsp_owner_from_session_snapshot(
            node_addr,
            snapshot,
            proven_next_hop,
            coords_warmup_remaining,
        )
    }

    fn sync_dataplane_fsp_owner_from_session_snapshot(
        &mut self,
        node_addr: &NodeAddr,
        snapshot: DataplaneFspOwnerSessionSnapshot,
        proven_next_hop: Option<NodeAddr>,
        coords_warmup_remaining: u8,
    ) -> bool {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneFspOwnerSync);
        crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneFspOwnerSyncCall);

        let Some(seed) = self.dataplane_fsp_owner_seed_from_snapshot(
            node_addr,
            snapshot,
            proven_next_hop,
            coords_warmup_remaining,
        ) else {
            self.remove_dataplane_fsp_owner(node_addr);
            return false;
        };
        self.apply_dataplane_fsp_owner_seed(seed)
    }

    fn apply_dataplane_fsp_owner_seed(&mut self, seed: DataplaneFspOwnerSeed) -> bool {
        self.dataplane
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let next_hop_ready = seed
            .wrap
            .map(DataplaneFspWrapRoute::next_hop_addr)
            .is_none_or(|next_hop| self.dataplane_has_fmp_owner(&next_hop));
        let synced = self
            .dataplane
            .install_owner_fsp_session_routes(
                seed.owner,
                seed.config,
                seed.keys,
                seed.routes,
                seed.wrap,
                seed.path,
            )
            .is_ok()
            && next_hop_ready;
        if synced && let Some(path_mtu) = seed.direct_path_mtu {
            let _ = self
                .dataplane
                .seed_fsp_path_mtu(seed.owner.node_addr(), path_mtu);
        }
        if synced {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DataplaneFspOwnerSyncApplied,
            );
        }
        synced
    }

    pub(in crate::node) fn remove_dataplane_fsp_owner(&mut self, node_addr: &NodeAddr) {
        self.dataplane
            .unregister_owner(OwnerId::fsp_node(*node_addr));
    }

    fn dataplane_fmp_owner_seed(&self, node_addr: &NodeAddr) -> Option<DataplaneFmpOwnerSeed> {
        let peer = self.peers.get(node_addr)?;
        let session = peer.noise_session()?;
        let transport_id = peer.transport_id()?;
        let remote_addr = peer.current_addr()?.clone();
        let receiver_idx = peer.our_index()?.as_u32();
        let mut receive_indices =
            vec![(transport_id, receiver_idx, DataplaneReceiveEpoch::Current)];
        for (route_transport_id, index, epoch) in [
            (
                peer.pending_our_index().map(|index| (transport_id, index)),
                DataplaneReceiveEpoch::Pending,
            ),
            (
                peer.previous_our_index()
                    .map(|index| (peer.previous_transport_id().unwrap_or(transport_id), index)),
                DataplaneReceiveEpoch::Previous,
            ),
        ]
        .into_iter()
        .filter_map(|(indexed_transport, epoch)| {
            indexed_transport
                .map(|(route_transport_id, index)| (route_transport_id, index.as_u32(), epoch))
        }) {
            if !receive_indices
                .iter()
                .any(|(existing_transport, existing_index, _)| {
                    *existing_transport == route_transport_id && *existing_index == index
                })
            {
                receive_indices.push((route_transport_id, index, epoch));
            }
        }
        let fmp_send_headers = peer.their_index().map(|their_index| {
            let mut flags = 0;
            if peer.current_k_bit() {
                flags |= FLAG_KEY_EPOCH;
            }
            (their_index.as_u32(), flags)
        });
        let fmp_mmp_is_initiator = peer.fmp_mmp_is_initiator();
        let generation = peer.session_generation();
        let session_start_ms = Self::now_ms().wrapping_sub(u64::from(peer.session_elapsed_ms()));
        let source_peer = *peer.identity();
        let current_k_bit = peer.current_k_bit();
        let previous_draining_k_bit = peer.is_draining().then_some(!current_k_bit);
        let open = Arc::new(session.recv_cipher_clone()?);
        let seal = Arc::new(session.send_cipher_clone()?);
        let counter_authority = session.send_counter_authority();
        let mut routes = DataplaneLiveOwnerRoutes::new();
        for (route_transport_id, receiver_idx, receive_epoch) in receive_indices.iter().copied() {
            routes.push_fmp_ingress(
                route_transport_id,
                receiver_idx,
                DataplaneIngressRoute::new(
                    OwnerId::fmp_node(*node_addr),
                    generation,
                    OutputTarget::SessionIngress {
                        local_addr: *self.node_addr(),
                    },
                )
                .with_class(PacketClass::Bulk)
                .with_receive_epoch(receive_epoch),
            );
        }
        let mut config = self
            .dataplane_owner_config(generation)
            .with_send_counter_authority(counter_authority)
            .with_fmp_session_start_ms(session_start_ms)
            .with_fmp_epoch(current_k_bit, previous_draining_k_bit)
            .with_source_peer(source_peer);
        if let Some((receiver_idx, flags)) = fmp_send_headers {
            config = config.with_fmp_send_headers(receiver_idx, flags);
        }
        config = config.with_fmp_mmp(self.config.node.mmp.clone(), fmp_mmp_is_initiator);

        Some(DataplaneFmpOwnerSeed {
            owner: OwnerId::fmp_node(*node_addr),
            config,
            keys: OwnerCryptoKeys::new(open, seal),
            path: TransportPath::live(transport_id, remote_addr),
            routes,
        })
    }

    fn dataplane_fsp_owner_session_snapshot(
        session: &SessionEntry,
    ) -> Option<DataplaneFspOwnerSessionSnapshot> {
        let (open, seal) = session.fsp_crypto_keys()?;
        let counter_authority = session.send_counter_authority()?;
        let source_peer = session.remote_identity()?;
        let current_k_bit = session.current_k_bit();
        Some(DataplaneFspOwnerSessionSnapshot {
            open,
            seal,
            counter_authority,
            session_start_ms: session.session_start_ms(),
            current_k_bit,
            previous_draining_k_bit: session.is_draining().then_some(!current_k_bit),
            source_peer,
            is_initiator: session.is_initiator(),
        })
    }

    fn dataplane_fsp_owner_seed_from_snapshot(
        &mut self,
        node_addr: &NodeAddr,
        snapshot: DataplaneFspOwnerSessionSnapshot,
        proven_next_hop: Option<NodeAddr>,
        coords_warmup_remaining: u8,
    ) -> Option<DataplaneFspOwnerSeed> {
        let mut fsp_flags = 0;
        if snapshot.current_k_bit {
            fsp_flags |= crate::node::session_wire::FSP_FLAG_K;
        }
        let generation = snapshot.session_start_ms.max(1);
        let inner_flags = crate::protocol::FspInnerFlags { spin_bit: false }.to_byte();
        let coords_prefix = self.dataplane_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        let route_update = self.dataplane_fsp_owner_routes(
            node_addr,
            generation,
            fsp_flags,
            inner_flags,
            proven_next_hop,
        );

        let mut config = self
            .dataplane_owner_config(generation)
            .with_send_counter_authority(snapshot.counter_authority)
            .with_fsp_session_start_ms(snapshot.session_start_ms)
            .with_fsp_send_headers(fsp_flags, inner_flags)
            .with_fsp_epoch(snapshot.current_k_bit, snapshot.previous_draining_k_bit)
            .with_source_peer(snapshot.source_peer);
        config = config.with_fsp_mmp(self.config.node.session_mmp.clone(), snapshot.is_initiator);
        if coords_warmup_remaining > 0 {
            config = config.with_fsp_coords_warmup(coords_warmup_remaining, coords_prefix);
        }
        Some(DataplaneFspOwnerSeed {
            owner: OwnerId::fsp_node(*node_addr),
            config,
            keys: OwnerCryptoKeys::new(Arc::new(snapshot.open), Arc::new(snapshot.seal)),
            routes: route_update.routes,
            wrap: route_update.wrap,
            path: route_update.path,
            direct_path_mtu: route_update.direct_path_mtu,
        })
    }

    fn dataplane_fsp_coords_prefix(
        &self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> Vec<u8> {
        if coords_warmup_remaining == 0 {
            return Vec::new();
        }
        self.dataplane_fsp_coords_prefix_for_dest(node_addr)
    }

    fn dataplane_fsp_coords_prefix_for_dest(&self, node_addr: &NodeAddr) -> Vec<u8> {
        let src = self.tree_state.my_coords().clone();
        let dst = self.get_dest_coords(node_addr);
        let mut prefix = Vec::with_capacity(
            crate::protocol::coords_wire_size(&src) + crate::protocol::coords_wire_size(&dst),
        );
        crate::protocol::encode_coords(&src, &mut prefix);
        crate::protocol::encode_coords(&dst, &mut prefix);
        prefix
    }

    fn dataplane_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
        generation: u64,
        fsp_flags: u8,
        inner_flags: u8,
        proven_next_hop: Option<NodeAddr>,
    ) -> DataplaneFspOwnerRouteUpdate {
        let owner = OwnerId::fsp_node(*node_addr);
        // A live direct peer is stronger than a routed handshake ingress. A
        // SessionAck can race direct-link promotion and return through a
        // transit peer; pinning that transient ingress would leave payload on
        // the routed branch after the direct carrier is already usable.
        let selected_next_hop = self
            .find_next_hop(node_addr)
            .map(|peer| *peer.node_addr());
        let selected_direct = (selected_next_hop == Some(*node_addr)).then_some(*node_addr);

        // Otherwise, a Noise-authenticated handshake ingress remains the
        // strongest route evidence while its adjacent FMP path can still send.
        // Traversal liveness may briefly be stale before endpoint traffic
        // refreshes it; falling back here can seed the new FSP owner onto an
        // unproven branch.
        let proven_next_hop = proven_next_hop.filter(|next_hop| {
            self.peers
                .get(next_hop)
                .is_some_and(|peer| peer.can_send())
                && self.dataplane_has_fmp_owner(next_hop)
        });
        let Some(next_hop) = selected_direct
            .or(proven_next_hop)
            .or(selected_next_hop)
        else {
            return DataplaneFspOwnerRouteUpdate {
                routes: DataplaneLiveOwnerRoutes::new(),
                wrap: None,
                path: None,
                direct_path_mtu: None,
                next_hop: None,
            };
        };
        let mut direct_path_mtu = None;
        let direct_fsp_negotiated = self
            .sessions
            .get(node_addr)
            .is_some_and(SessionEntry::remote_supports_direct_fsp_transport);
        let (wrap, path) = if next_hop == *node_addr && direct_fsp_negotiated {
            match self.dataplane_direct_fsp_path(node_addr) {
                Some((path, path_mtu)) => {
                    direct_path_mtu = Some(path_mtu);
                    (None, Some(path))
                }
                None => (self.dataplane_fsp_wrap_route_to(node_addr, next_hop), None),
            }
        } else {
            (self.dataplane_fsp_wrap_route_to(node_addr, next_hop), None)
        };
        if wrap.is_none() && path.is_none() {
            return DataplaneFspOwnerRouteUpdate {
                routes: DataplaneLiveOwnerRoutes::new(),
                wrap: None,
                path: None,
                direct_path_mtu: None,
                next_hop: Some(next_hop),
            };
        };
        let mut routes = DataplaneLiveOwnerRoutes::new();
        routes.push_fsp_ingress(
            *node_addr,
            DataplaneIngressRoute::new(
                owner,
                generation,
                OutputTarget::SessionPayload {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        );
        let tun = DataplaneTunOutboundRoute::fsp_ipv6_shim(
            owner,
            generation,
            PacketClass::Bulk,
            fsp_flags,
            inner_flags,
        )
        .with_max_packet_len(self.dataplane_tun_max_packet_len(node_addr));
        routes.push_tun_destination(*node_addr, tun);

        let mut endpoint =
            DataplaneEndpointDataRoute::fsp(owner, generation, fsp_flags, inner_flags);
        if direct_path_mtu.is_some() {
            endpoint = endpoint.with_direct_transport();
        }
        routes.push_endpoint_destination(*node_addr, endpoint);

        DataplaneFspOwnerRouteUpdate {
            routes,
            wrap,
            path,
            direct_path_mtu,
            next_hop: Some(next_hop),
        }
    }

    fn dataplane_direct_fsp_path(&self, dest_addr: &NodeAddr) -> Option<(TransportPath, u16)> {
        let peer = self.peers.get(dest_addr)?;
        let transport_id = peer.transport_id()?;
        let remote_addr = peer.send_addr()?.clone();
        let path_mtu = self
            .transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu());
        Some((TransportPath::live(transport_id, remote_addr), path_mtu))
    }

    fn dataplane_fsp_wrap_route_to(
        &mut self,
        dest_addr: &NodeAddr,
        next_hop: NodeAddr,
    ) -> Option<DataplaneFspWrapRoute> {
        let send_context = self.dataplane.fmp_owner_send_context(&next_hop)?;
        let active_path = self
            .dataplane
            .owner_active_path(OwnerId::fmp_node(next_hop))
            .ok()??;
        let transport_id = active_path.transport_id;
        let remote_addr = active_path.remote_addr.clone();
        let fmp_flags = send_context.flags();
        let path_mtu = self
            .transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu());
        let wrap = DataplaneFspWrapRoute::new(
            OwnerId::fmp_node(next_hop),
            send_context.generation(),
            send_context.receiver_idx(),
            *self.node_addr(),
            *dest_addr,
        )
        .with_fmp_flags(fmp_flags)
        .with_ttl(self.config.node.session.default_ttl)
        .with_path_mtu(path_mtu);
        Some(wrap)
    }

    fn dataplane_tun_max_packet_len(&self, dest_addr: &NodeAddr) -> usize {
        let effective_mtu = self.effective_ipv6_mtu() as usize;
        self.dataplane
            .fsp_owner_activity(dest_addr)
            .and_then(|activity| activity.current_path_mtu())
            .map(crate::upper::icmp::effective_ipv6_mtu)
            .map(usize::from)
            .filter(|path_ipv6_mtu| *path_ipv6_mtu < effective_mtu)
            .unwrap_or(effective_mtu)
    }

    fn dataplane_owner_config(&self, generation: u64) -> OwnerConfig {
        let in_flight_limit = self.config.node.limits.max_pending_inbound.max(1);
        OwnerConfig::new(generation, in_flight_limit)
    }

    pub(in crate::node) fn dataplane_fmp_output_drop_error(
        &self,
        node_addr: NodeAddr,
        drop: &DataplaneOutputDrop,
    ) -> NodeError {
        match drop.reason() {
            DataplaneOutputError::MtuExceeded { mtu } => NodeError::MtuExceeded {
                node_addr,
                packet_size: drop.payload_len(),
                mtu,
            },
            DataplaneOutputError::NoRoute => {
                NodeError::LocalRouteUnavailable("dataplane transport route unavailable".into())
            }
            reason => NodeError::SendFailed {
                node_addr,
                reason: format!("dataplane transport output failed: {:?}", reason),
            },
        }
    }
}
