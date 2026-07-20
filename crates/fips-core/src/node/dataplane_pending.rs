impl Node {
    async fn process_dataplane_pending_outbound_bookkeeping(&mut self) -> usize {
        let mut processed = 0usize;
        // Pending flush callers already own the packet they are trying to send.
        // If dataplane defers it again, drain it here and let the caller queue/recover.
        for _packet in self.dataplane.take_deferred_tun_packets() {
            processed += 1;
        }
        for batch in self.dataplane.take_deferred_endpoint_data_batches() {
            self.requeue_deferred_endpoint_data_batch(batch);
            processed += 1;
        }
        processed
    }

    pub(in crate::node) fn sync_dataplane_fmp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        let Some(seed) = self.dataplane_fmp_owner_seed(node_addr) else {
            self.mark_dataplane_direct_fsp_sources_dirty();
            self.remove_dataplane_fmp_owner(node_addr);
            self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(node_addr);
            return false;
        };

        self.dataplane
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let synced = self
            .dataplane
            .install_owner_fmp_session_routes(
                seed.owner,
                seed.config,
                seed.keys,
                seed.path,
                seed.routes,
            )
            .is_ok();
        if synced {
            self.mark_dataplane_direct_fsp_sources_dirty();
            self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(node_addr);
        }
        synced
    }

    pub(in crate::node) fn remove_dataplane_fmp_owner(&mut self, node_addr: &NodeAddr) {
        self.dataplane
            .unregister_owner(OwnerId::fmp_node(*node_addr));
    }

    pub(in crate::node) fn dataplane_has_fmp_owner(&self, node_addr: &NodeAddr) -> bool {
        self.dataplane.has_owner(OwnerId::fmp_node(*node_addr))
    }

    pub(in crate::node) fn refresh_dataplane_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
    ) -> bool {
        self.refresh_dataplane_fsp_owner_routes_via(node_addr, None)
    }

    pub(in crate::node) fn refresh_dataplane_fsp_owner_routes_retaining_current(
        &mut self,
        node_addr: &NodeAddr,
    ) -> bool {
        let current_next_hop = self
            .dataplane
            .fsp_owner_next_hop(node_addr)
            .filter(|next_hop| self.dataplane_has_fmp_owner(next_hop));
        self.refresh_dataplane_fsp_owner_routes_via(node_addr, current_next_hop)
    }

    fn refresh_dataplane_fsp_owner_routes_via(
        &mut self,
        node_addr: &NodeAddr,
        preferred_next_hop: Option<NodeAddr>,
    ) -> bool {
        let owner = OwnerId::fsp_node(*node_addr);
        let Some(send_context) = self.dataplane.fsp_owner_send_context(node_addr) else {
            return false;
        };
        let update = self.dataplane_fsp_owner_routes(
            node_addr,
            send_context.generation(),
            send_context.fsp_flags(),
            send_context.inner_flags(),
            preferred_next_hop,
        );
        let route_ready = update.wrap.is_some() || update.path.is_some();
        let next_hop_ready = update.path.is_some()
            || update
                .next_hop
                .is_some_and(|next_hop| self.dataplane_has_fmp_owner(&next_hop));
        if !(route_ready && next_hop_ready)
            && self
                .dataplane
                .fsp_owner_next_hop(node_addr)
                .is_some_and(|next_hop| self.dataplane_has_fmp_owner(&next_hop))
        {
            return false;
        }
        let direct_path_mtu = update.direct_path_mtu;
        let refreshed = self
            .dataplane
            .replace_owner_fsp_routes(owner, update.routes, update.wrap, update.path)
            .is_ok()
            && route_ready
            && next_hop_ready;
        if refreshed && let Some(path_mtu) = direct_path_mtu {
            let _ = self.dataplane.seed_fsp_path_mtu(*node_addr, path_mtu);
        }
        refreshed
    }

    pub(in crate::node) fn refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(
        &mut self,
        next_hop_addr: &NodeAddr,
    ) -> usize {
        let destinations = self.dataplane.fsp_owner_destinations();
        let mut refreshed = 0usize;
        for dest in destinations {
            let current_next_hop = self.dataplane.fsp_owner_next_hop(&dest);
            let current_uses_next_hop = current_next_hop == Some(*next_hop_addr);
            let current_is_ready = current_next_hop
                .is_some_and(|current| self.dataplane_has_fmp_owner(&current));
            if current_is_ready && !current_uses_next_hop {
                continue;
            }
            let would_use_next_hop = self
                .find_next_hop(&dest)
                .is_some_and(|peer| peer.node_addr() == next_hop_addr);
            if !(current_uses_next_hop || would_use_next_hop) {
                continue;
            }
            let route_ready = if current_is_ready {
                self.refresh_dataplane_fsp_owner_routes_retaining_current(&dest)
            } else {
                self.refresh_dataplane_fsp_owner_routes(&dest)
            };
            if route_ready || current_uses_next_hop {
                refreshed = refreshed.saturating_add(1);
            }
        }
        refreshed
    }

    pub(in crate::node) fn refresh_dataplane_fsp_owner_routes_with_coords_warmup(
        &mut self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> bool {
        let owner = OwnerId::fsp_node(*node_addr);
        let coords_prefix = self.dataplane_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        let warmup_applied = self
            .dataplane
            .set_owner_fsp_coords_warmup(owner, coords_warmup_remaining, coords_prefix)
            .is_ok();
        self.refresh_dataplane_fsp_owner_routes(node_addr) && warmup_applied
    }

    pub(in crate::node) fn apply_dataplane_fsp_path_mtu_signal(
        &mut self,
        node_addr: &NodeAddr,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<
        crate::dataplane::DataplaneFspPathMtuApplyResult,
        crate::dataplane::DataplaneFspMmpSkip,
    > {
        let result = self
            .dataplane
            .apply_fsp_path_mtu_signal(*node_addr, path_mtu, now)?;
        if matches!(
            result,
            crate::dataplane::DataplaneFspPathMtuApplyResult::Changed(_)
        ) {
            let _ = self.refresh_dataplane_fsp_owner_routes(node_addr);
        }
        Ok(result)
    }

    pub(in crate::node) fn set_dataplane_fsp_owner_epoch(
        &mut self,
        node_addr: &NodeAddr,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> bool {
        self.dataplane
            .set_owner_fsp_epoch(
                OwnerId::fsp_node(*node_addr),
                current_k_bit,
                previous_draining_k_bit,
            )
            .is_ok()
    }

    pub(in crate::node) fn install_dataplane_fsp_pending_receive_epoch(
        &mut self,
        node_addr: &NodeAddr,
        pending_k_bit: bool,
        open: ring::aead::LessSafeKey,
    ) -> bool {
        self.dataplane
            .install_owner_fsp_pending_receive_epoch(
                OwnerId::fsp_node(*node_addr),
                pending_k_bit,
                std::sync::Arc::new(open),
            )
            .is_ok()
    }

    pub(in crate::node) fn install_dataplane_fmp_pending_receive_epoch(
        &mut self,
        node_addr: &NodeAddr,
        pending_k_bit: bool,
        open: ring::aead::LessSafeKey,
    ) -> bool {
        self.dataplane
            .install_owner_fmp_pending_receive_epoch(
                OwnerId::fmp_node(*node_addr),
                pending_k_bit,
                std::sync::Arc::new(open),
            )
            .is_ok()
    }

    pub(in crate::node) fn clear_dataplane_fmp_pending_receive_epoch(
        &mut self,
        node_addr: &NodeAddr,
    ) -> bool {
        self.dataplane
            .clear_fmp_owner_pending_receive_epoch(node_addr)
    }

    pub(in crate::node) fn promote_dataplane_authenticated_pending_fmp_epoch(
        &mut self,
        node_addr: &NodeAddr,
        received_k_bit: bool,
    ) -> bool {
        if !self
            .dataplane
            .fmp_owner_has_pending_receive_epoch(node_addr, received_k_bit)
        {
            return false;
        }
        let Some(previous_index) = self
            .peers
            .get_mut(node_addr)
            .and_then(|peer| peer.handle_peer_kbit_flip())
        else {
            return false;
        };
        let _ = previous_index;
        self.ensure_current_session_index_registered(
            node_addr,
            "responder authenticated FMP rekey cutover",
        );
        let synced = self.sync_dataplane_fmp_owner(node_addr);
        self.complete_authenticated_direct_path_refresh_after_rekey(node_addr);
        synced
    }

    pub(in crate::node) fn promote_dataplane_authenticated_pending_fsp_epoch(
        &mut self,
        node_addr: &NodeAddr,
        received_k_bit: bool,
    ) -> bool {
        if !self
            .dataplane
            .fsp_owner_has_pending_receive_epoch(node_addr, received_k_bit)
        {
            return false;
        }
        let now_ms = Self::now_ms();
        let promoted = {
            let Some(session) = self.sessions.get_mut(node_addr) else {
                return false;
            };
            session.cutover_to_authenticated_pending_epoch(now_ms, received_k_bit)
        };
        if !promoted {
            return false;
        }

        self.sync_dataplane_fsp_owner_from_current_session(node_addr, 0)
    }

    pub(in crate::node) fn dataplane_fsp_owner_epoch(
        session: &SessionEntry,
    ) -> (bool, Option<bool>) {
        let current_k_bit = session.current_k_bit();
        (
            current_k_bit,
            session.is_draining().then_some(!current_k_bit),
        )
    }

    pub(in crate::node) fn dataplane_has_fsp_owner(&self, node_addr: &NodeAddr) -> bool {
        self.dataplane.has_owner(OwnerId::fsp_node(*node_addr))
    }

    pub(in crate::node) fn mark_dataplane_direct_fsp_sources_dirty(&mut self) {
        self.dataplane_direct_fsp_sources_dirty = true;
    }

    pub(in crate::node) fn dataplane_direct_fsp_sources_for_rx_turn(
        &mut self,
    ) -> crate::dataplane::DataplaneDirectFspSources {
        if self.dataplane_direct_fsp_sources_dirty {
            let sources = self.dataplane_direct_fsp_sources();
            self.dataplane
                .set_established_fast_ingress_direct_fsp_sources(sources.clone());
            self.dataplane_direct_fsp_sources = sources;
            self.dataplane_direct_fsp_sources_dirty = false;
        }
        self.dataplane_direct_fsp_sources.clone()
    }

    pub(in crate::node) fn dataplane_direct_fsp_sources(
        &self,
    ) -> crate::dataplane::DataplaneDirectFspSources {
        let mut sources = Vec::new();
        for (node_addr, peer) in &self.peers {
            let (Some(transport_id), Some(remote_addr)) =
                (peer.transport_id(), peer.current_addr().cloned())
            else {
                continue;
            };
            let path_mtu = self
                .transports
                .get(&transport_id)
                .map(|transport| transport.link_mtu(&remote_addr))
                .unwrap_or_else(|| self.transport_mtu());
            sources.push((
                transport_id,
                remote_addr,
                DataplaneDirectFspSource {
                    source_addr: *node_addr,
                    path_mtu,
                },
            ));

            for static_addr in
                self.dataplane_configured_static_udp_source_addrs(node_addr, transport_id)
            {
                let path_mtu = self
                    .transports
                    .get(&transport_id)
                    .map(|transport| transport.link_mtu(&static_addr))
                    .unwrap_or(path_mtu);
                sources.push((
                    transport_id,
                    static_addr,
                    DataplaneDirectFspSource {
                        source_addr: *node_addr,
                        path_mtu,
                    },
                ));
            }
        }
        crate::dataplane::dataplane_direct_fsp_sources_from_exact(sources)
    }
}
