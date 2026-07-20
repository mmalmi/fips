impl Node {
    const PENDING_TUN_PACKET_FLUSH_MAX_AGE_MS: u64 = 2_000;
    const PENDING_ENDPOINT_DATA_FLUSH_BATCH_MAX: usize = 16;

    fn deliver_endpoint_data_batch(&mut self, deliveries: Vec<EndpointDataDelivery>) {
        if deliveries.is_empty() {
            return;
        }
        if !self.endpoint_events.is_attached() {
            trace!(
                messages = deliveries.len(),
                "Endpoint data batch received without an attached endpoint"
            );
            return;
        }

        let count = deliveries.len();
        if let Err(error) = self.endpoint_events.deliver_endpoint_data_batch(deliveries) {
            debug!(
                messages = count,
                error = %error,
                "Failed to deliver endpoint data event batch"
            );
        }
    }

    fn deliver_endpoint_service_datagram_batch(
        &mut self,
        deliveries: Vec<EndpointServiceDatagramDelivery>,
    ) {
        if deliveries.is_empty() {
            return;
        }
        let count = deliveries.len();
        if self.endpoint_services.deliver(deliveries).is_err() {
            debug!(
                messages = count,
                "Failed to deliver endpoint service datagram batch"
            );
        }
    }

    /// Send a non-data session message (reports, notifications) over an established session.
    ///
    /// Similar to endpoint/TUN dataplane data sends, but:
    /// - Takes an explicit `msg_type` byte (0x11, 0x12, 0x13, etc.)
    /// - Never includes COORDS_PRESENT (reports are lightweight)
    /// - Reads spin bit from MMP state for the inner header
    /// - Records the send in MMP sender state
    pub(in crate::node) async fn send_session_msg(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        self.send_dataplane_fsp_session_msg(dest_addr, msg_type, payload)
            .await
    }

    /// Send a standalone CoordsWarmup message to warm transit node caches.
    ///
    /// Constructs an encrypted FSP message with CP flag set and
    /// msg_type=CoordsWarmup. Transit nodes extract the cleartext
    /// coordinates via `try_warm_coord_cache()` (same as CP-flagged data
    /// packets). The encrypted inner payload is the 6-byte inner header
    /// with no application data.
    pub(in crate::node) async fn send_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        self.send_dataplane_fsp_coords_warmup(dest_addr).await?;

        debug!(dest = %self.peer_display_name(dest_addr), "Sent standalone CoordsWarmup");
        Ok(())
    }

    /// Route and send a SessionDatagram through the mesh.
    ///
    /// Finds the next hop for the destination, seeds dataplane owner path_mtu from
    /// the first-hop transport MTU, and sends as an encrypted link message.
    pub(in crate::node) async fn send_session_datagram(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<(), NodeError> {
        let runtime_route = self.resolve_session_datagram_runtime_route(datagram)?;

        self.send_session_datagram_on_runtime_route(datagram, runtime_route)
            .await
    }

    pub(in crate::node) async fn send_session_datagram_reply(
        &mut self,
        datagram: &mut SessionDatagram,
        previous_hop_addr: &NodeAddr,
        dest_coords: &crate::tree::TreeCoordinate,
    ) -> Result<NodeAddr, NodeError> {
        let dest_addr = datagram.dest_addr;
        // Before msg3 authenticates the source, admit only one strict tree-progress
        // hop derived from this setup; never consult learned or cached routes.
        let coordinate_route = if dest_coords.node_addr() == &dest_addr {
            let my_distance = self.tree_state.my_coords().distance_to(dest_coords);
            let previous_distance = self
                .tree_state
                .peer_coords(previous_hop_addr)
                .map_or(usize::MAX, |coords| coords.distance_to(dest_coords));
            if previous_distance < my_distance {
                Some(*previous_hop_addr)
            } else {
                let direct_payload_eligible = self
                    .peers
                    .get(&dest_addr)
                    .is_some_and(|peer| peer.is_healthy());
                self.select_tree_payload_candidate(
                    dest_coords,
                    &dest_addr,
                    direct_payload_eligible,
                )
            }
        } else {
            None
        };

        let next_hop_addr = coordinate_route.unwrap_or(*previous_hop_addr);
        let runtime_route = self.prepare_session_datagram_runtime_route(datagram, next_hop_addr);
        self.send_session_datagram_on_runtime_route(datagram, runtime_route)
            .await?;
        Ok(next_hop_addr)
    }

    async fn send_session_datagram_on_runtime_route(
        &mut self,
        datagram: &SessionDatagram,
        runtime_route: SessionDatagramRuntimeRoute,
    ) -> Result<(), NodeError> {
        let encoded = datagram.encode();
        if let Err(err) = self
            .send_dataplane_fmp_link_plaintext(&runtime_route.next_hop_addr, &encoded, false)
            .await
        {
            let dest_addr = runtime_route.dest_addr;
            let next_hop_addr = runtime_route.next_hop_addr;
            self.record_route_failure(dest_addr, next_hop_addr);
            self.recover_direct_payload_send_failure(dest_addr, next_hop_addr, &err);
            return Err(err);
        }
        self.stats_mut().forwarding.record_originated(encoded.len());
        Ok(())
    }

    pub(in crate::node) fn recover_direct_payload_send_failure(
        &mut self,
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        err: &NodeError,
    ) {
        if next_hop_addr != dest_addr || !err.is_local_route_unavailable() {
            return;
        }
        let now_ms = Self::now_ms();
        self.mark_session_direct_path_degraded(dest_addr, now_ms);
        self.schedule_local_route_retry(dest_addr, now_ms);
    }

    pub(in crate::node) fn resolve_session_handshake_runtime_route(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<SessionDatagramRuntimeRoute, NodeError> {
        let dest_addr = datagram.dest_addr;
        if self
            .peers
            .get(&dest_addr)
            .is_some_and(|peer| peer.is_healthy() && peer.can_send())
        {
            return Ok(self.prepare_session_datagram_runtime_route(datagram, dest_addr));
        }

        // Once Noise msg2 authenticates an ingress branch, the final msg3
        // must follow that same branch. Ordinary learned-route weighting may
        // prefer a different seed between handshake phases; sending msg3
        // there leaves the initiator locally established while the responder
        // keeps retransmitting msg2 forever. A still-sendable adjacent hop is
        // sufficient here because explicit send failure releases the pin.
        if self.config.node.routing.mode == crate::config::RoutingMode::ReplyLearned {
            let sendable = self
                .peers
                .iter()
                .filter(|(_, peer)| peer.can_send())
                .map(|(addr, _)| *addr)
                .collect::<std::collections::HashSet<_>>();
            if let Some(next_hop_addr) =
                self.learned_routes
                    .select_handshake_route(&dest_addr, Self::now_ms(), |addr| {
                        sendable.contains(addr)
                    })
            {
                return Ok(self.prepare_session_datagram_runtime_route(datagram, next_hop_addr));
            }
        }

        let prefix = FspCommonPrefix::parse(&datagram.payload);
        let inner = datagram.payload.get(FSP_COMMON_PREFIX_SIZE..);
        let carried_dest_coords = match (prefix.map(|prefix| prefix.phase), inner) {
            (Some(FSP_PHASE_MSG1), Some(inner)) => SessionSetup::decode(inner)
                .ok()
                .map(|setup| setup.dest_coords),
            (Some(FSP_PHASE_MSG2), Some(inner)) => SessionAck::decode(inner)
                .ok()
                .map(|ack| ack.dest_coords),
            _ => None,
        };
        let current_root = *self.tree_state.my_coords().root_id();
        let usable_carried_coords = carried_dest_coords.filter(|coords| {
            coords.node_addr() == &dest_addr && coords.root_id() == &current_root
        });
        let usable_dest_coords = usable_carried_coords.or_else(|| {
            self.coord_cache
                .get_and_touch(&dest_addr, Self::now_ms())
                .filter(|coords| {
                    coords.node_addr() == &dest_addr && coords.root_id() == &current_root
                })
                .cloned()
        });
        if let Some(dest_coords) = usable_dest_coords {
            if let Some(next_hop_addr) =
                self.select_tree_payload_candidate(&dest_coords, &dest_addr, false)
            {
                return Ok(self.prepare_session_datagram_runtime_route(datagram, next_hop_addr));
            }
            return Err(NodeError::SendFailed {
                node_addr: dest_addr,
                reason: "no loop-free route to destination".into(),
            });
        }

        self.resolve_generic_session_datagram_runtime_route(datagram)
    }

    pub(in crate::node) fn resolve_session_datagram_runtime_route(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<SessionDatagramRuntimeRoute, NodeError> {
        if FspCommonPrefix::parse(&datagram.payload).is_some_and(|prefix| {
            matches!(
                prefix.phase,
                FSP_PHASE_MSG1 | FSP_PHASE_MSG2 | FSP_PHASE_MSG3
            )
        }) {
            return self.resolve_session_handshake_runtime_route(datagram);
        }
        self.resolve_generic_session_datagram_runtime_route(datagram)
    }

    fn resolve_generic_session_datagram_runtime_route(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<SessionDatagramRuntimeRoute, NodeError> {
        let dest_addr = datagram.dest_addr;
        let direct_peer = self
            .peers
            .get(&dest_addr)
            .filter(|peer| peer.is_healthy() && peer.can_send())
            .map(|peer| *peer.node_addr());
        let next_hop_addr = direct_peer
            .or_else(|| self.find_next_hop(&dest_addr).map(|peer| *peer.node_addr()))
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: dest_addr,
                reason: "no route to destination".into(),
            })?;

        Ok(self.prepare_session_datagram_runtime_route(datagram, next_hop_addr))
    }

    fn prepare_session_datagram_runtime_route(
        &mut self,
        datagram: &mut SessionDatagram,
        next_hop_addr: NodeAddr,
    ) -> SessionDatagramRuntimeRoute {
        let dest_addr = datagram.dest_addr;
        let mut path_mtu = datagram.path_mtu;
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            path_mtu = if let Some(addr) = peer.send_addr() {
                path_mtu.min(transport.link_mtu(addr))
            } else {
                path_mtu.min(transport.mtu())
            };
        }
        datagram.path_mtu = path_mtu;

        let _ = self.dataplane.seed_fsp_path_mtu(dest_addr, path_mtu);

        SessionDatagramRuntimeRoute {
            dest_addr,
            next_hop_addr,
            path_mtu,
        }
    }

    /// Look up destination coordinates from available caches.
    ///
    /// Returns our own coordinates as a fallback (the SessionSetup will
    /// carry src_coords for return path routing; empty dest_coords
    /// would fail wire encoding since TreeCoordinate requires ≥1 entry).
    pub(in crate::node) fn get_dest_coords(&self, dest: &NodeAddr) -> crate::tree::TreeCoordinate {
        let now_ms = Self::now_ms();
        if let Some(coords) = self.coord_cache.get(dest, now_ms) {
            return coords.clone();
        }
        // Fallback: use our own coordinates. The SessionSetup dest_coords
        // field cannot be empty (wire format requires ≥1 entry). Using our
        // own coords is safe — transit routers will still cache them, and
        // the destination will return its actual coords in the SessionAck.
        self.tree_state.my_coords().clone()
    }

    /// Current Unix time in milliseconds.
    pub(in crate::node) fn now_ms() -> u64 {
        crate::time::now_ms()
    }

    pub(in crate::node) async fn handle_dataplane_deferred_tun_packet(
        &mut self,
        ipv6_packet: Vec<u8>,
    ) {
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            return;
        }

        let effective_mtu = self.effective_ipv6_mtu() as usize;
        if ipv6_packet.len() > effective_mtu {
            self.send_icmpv6_packet_too_big(&ipv6_packet, effective_mtu as u32);
            return;
        }

        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&ipv6_packet[25..40]);
        let (dest_addr, dest_pubkey) = match self.lookup_by_fips_prefix(&prefix) {
            Some((addr, pk)) => (addr, pk),
            None => {
                self.send_icmpv6_dest_unreachable(&ipv6_packet);
                return;
            }
        };

        self.queue_dataplane_unrouted_tun_packet(dest_addr, dest_pubkey, ipv6_packet)
            .await;
    }

    async fn queue_dataplane_unrouted_tun_packet(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: secp256k1::PublicKey,
        ipv6_packet: Vec<u8>,
    ) {
        match self.dataplane_outbound_session_state(&dest_addr) {
            OutboundSessionState::Established => {
                if self.find_next_hop(&dest_addr).is_some()
                {
                    match self
                        .send_dataplane_cached_tun_packet(&dest_addr, ipv6_packet.clone())
                        .await
                    {
                        Ok(()) | Err(NodeError::MtuExceeded { .. }) => return,
                        Err(_) => {}
                    }
                }
                self.queue_pending_tun_packet(dest_addr, ipv6_packet);
                self.maybe_initiate_path_recovery_lookup(&dest_addr).await;
            }
            OutboundSessionState::Pending => {
                self.queue_pending_tun_packet(dest_addr, ipv6_packet);
                let should_discover = self.config.node.routing.mode
                    == crate::config::RoutingMode::ReplyLearned
                    || self.find_next_hop(&dest_addr).is_none();
                if should_discover {
                    self.maybe_initiate_lookup(&dest_addr).await;
                }
            }
            OutboundSessionState::Missing => {
                if self.find_next_hop(&dest_addr).is_none() {
                    self.queue_pending_tun_packet(dest_addr, ipv6_packet);
                    self.maybe_initiate_lookup(&dest_addr).await;
                    return;
                }
                match self.initiate_session(dest_addr, dest_pubkey).await {
                    Ok(()) => {}
                    Err(NodeError::SendFailed { node_addr, reason })
                        if node_addr == dest_addr && reason == "no route to destination" =>
                    {
                        self.queue_pending_tun_packet(dest_addr, ipv6_packet);
                        self.maybe_initiate_lookup(&dest_addr).await;
                        return;
                    }
                    Err(error) => {
                        debug!(dest = %self.peer_display_name(&dest_addr), error = %error, "Failed to initiate deferred TUN session");
                        return;
                    }
                }
                self.queue_pending_tun_packet(dest_addr, ipv6_packet);
            }
        }
    }

    /// Send ICMPv6 Destination Unreachable back through TUN.
    pub(in crate::node) fn send_icmpv6_dest_unreachable(&self, original_packet: &[u8]) {
        use crate::FipsAddress;
        use crate::upper::icmp::{
            DestUnreachableCode, build_dest_unreachable, should_send_icmp_error,
        };

        if !should_send_icmp_error(original_packet) {
            return;
        }

        let our_ipv6 = FipsAddress::from_node_addr(self.node_addr()).to_ipv6();
        if let Some(response) =
            build_dest_unreachable(original_packet, DestUnreachableCode::NoRoute, our_ipv6)
            && let Some(tun_tx) = &self.tun_tx
        {
            let _ = tun_tx.send(response);
        }
    }

    /// Send ICMPv6 Packet Too Big back through TUN.
    ///
    /// Rate-limited per source address to prevent ICMP floods from
    /// misconfigured applications sending repeated oversized packets.
    pub(in crate::node) fn send_icmpv6_packet_too_big(&mut self, original_packet: &[u8], mtu: u32) {
        use crate::upper::icmp::build_packet_too_big;
        use std::net::Ipv6Addr;

        // Extract source address for rate limiting
        if original_packet.len() < 40 {
            return;
        }
        let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[8..24]).unwrap());

        // Rate limit ICMP PTB messages per source
        if !self.icmp_rate_limiter.should_send(src_addr) {
            debug!(
                src = %src_addr,
                "Rate limiting ICMP Packet Too Big"
            );
            return;
        }

        // Use the original packet's *destination* as the ICMP source so the
        // kernel sees the PTB coming from a remote router, not from itself.
        // Linux ignores PTBs whose source matches a local address, which
        // causes a PMTUD blackhole when both src and ICMP-src are local.
        let dest_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[24..40]).unwrap());
        if let Some(response) = build_packet_too_big(original_packet, mtu, dest_addr)
            && let Some(tun_tx) = &self.tun_tx
        {
            debug!(
                original_src = %src_addr,
                original_dst = %dest_addr,
                packet_size = original_packet.len(),
                reported_mtu = mtu,
                "Sending ICMP Packet Too Big"
            );
            let _ = tun_tx.send(response);
        }
    }

    /// Queue a packet while waiting for session establishment.
    fn queue_pending_tun_packet(&mut self, dest_addr: NodeAddr, packet: Vec<u8>) {
        let admission = self.pending_session_traffic.push_tun_packet(
            dest_addr,
            packet,
            self.config.node.session.pending_max_destinations,
            self.config.node.session.pending_packets_per_dest,
        );
        if admission.destination_dropped() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PendingTunDestinationDropped,
            );
            return;
        }
        if admission.dropped_oldest() {
            crate::perf_profile::record_pending_tun_session_oldest_drop();
        }
    }

    fn queue_pending_endpoint_data_batch_with_enqueued_at_ms(
        &mut self,
        dest_addr: NodeAddr,
        payloads: Vec<EndpointDataPayload>,
        enqueued_at_ms: u64,
    ) {
        let admission = self
            .pending_session_traffic
            .push_endpoint_data_batch_with_enqueued_at_ms(
                dest_addr,
                payloads,
                self.config.node.session.pending_max_destinations,
                self.config.node.session.pending_packets_per_dest,
                enqueued_at_ms,
            );
        if admission.destination_dropped() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PendingEndpointDestinationDropped,
            );
            return;
        }
        if admission.dropped_oldest() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PendingEndpointPacketDropped,
            );
        }
    }

    /// Flush pending packets for a destination whose session just reached Established.
    pub(in crate::node) async fn flush_pending_packets(&mut self, dest_addr: &NodeAddr) {
        if !self.pending_session_traffic.has_traffic_for(dest_addr) {
            return;
        }
        if !self.dataplane_has_fsp_owner(dest_addr) {
            debug!(
                dest = %self.peer_display_name(dest_addr),
                "Skipping pending packet flush because dataplane FSP owner is not registered"
            );
            return;
        }

        if let Some(packets) = self.pending_session_traffic.take_tun_packets(dest_addr) {
            let (mut packets, stale_count) = packets.into_fresh_packets(
                Self::now_ms(),
                Self::PENDING_TUN_PACKET_FLUSH_MAX_AGE_MS,
            );
            if stale_count > 0 {
                crate::perf_profile::record_pending_tun_session_stale_drops(stale_count as u64);
                debug!(
                    dest = %self.peer_display_name(dest_addr),
                    dropped = stale_count,
                    "Dropped stale queued TUN packets before session flush"
                );
            }
            while let Some(packet) = packets.pop_front() {
                if let Err(e) = self
                    .send_dataplane_cached_tun_packet(dest_addr, packet.packet().to_vec())
                    .await
                {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued TUN packet");
                    packets.push_front(packet);
                    self.pending_session_traffic
                        .restore_tun_packets(*dest_addr, packets);
                    break;
                }
            }
        }

        if let Some(payloads) = self.pending_session_traffic.take_endpoint_data(dest_addr) {
            let mut payloads = payloads.into_pending_payloads();
            while let Some(pending) = payloads.pop_front() {
                let enqueued_at_ms = pending.enqueued_at_ms();
                let mut pending_payloads = pending.into_payloads().into_iter();
                while let Some(first_payload) = pending_payloads.next() {
                    let mut batch = vec![first_payload];
                    while batch.len() < Self::PENDING_ENDPOINT_DATA_FLUSH_BATCH_MAX {
                        let Some(payload) = pending_payloads.next() else {
                            break;
                        };
                        batch.push(payload);
                    }

                    if let Err(e) = self
                        .send_dataplane_cached_endpoint_payloads(dest_addr, batch.clone())
                        .await
                    {
                        debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued endpoint data");
                        let mut restore = std::collections::VecDeque::new();
                        if let Some(pending) = crate::node::PendingEndpointData::new_batch(
                            batch,
                            enqueued_at_ms,
                        ) {
                            restore.push_back(pending);
                        }
                        let remaining = pending_payloads.collect::<Vec<_>>();
                        if let Some(pending) = crate::node::PendingEndpointData::new_batch(
                            remaining,
                            enqueued_at_ms,
                        ) {
                            restore.push_back(pending);
                        }
                        restore.append(&mut payloads);
                        self.pending_session_traffic
                            .restore_endpoint_data(*dest_addr, restore);
                        return;
                    }
                }
            }
        }
    }

    /// Retry session initiation after discovery provided coordinates.
    ///
    /// Called when a LookupResponse arrives and we have pending TUN packets or
    /// endpoint data for the discovered target. The coord_cache now has coords, so
    /// `find_next_hop()` should succeed and the SessionSetup can be sent.
    pub(in crate::node) async fn retry_session_after_discovery(&mut self, dest_addr: NodeAddr) {
        // Look up the destination's public key from the identity cache
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&dest_addr.as_bytes()[0..15]);
        let dest_pubkey = match self.lookup_by_fips_prefix(&prefix) {
            Some((_, pk)) => pk,
            None => {
                debug!(dest = %self.peer_display_name(&dest_addr), "Discovery complete but no identity for session retry");
                return;
            }
        };

        if self.sessions.should_skip_session_initiation(&dest_addr) {
            return;
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {
                debug!(dest = %self.peer_display_name(&dest_addr), "Session initiated after discovery");
            }
            Err(e) => {
                debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Session retry after discovery failed");
            }
        }
    }

    /// Retry queued traffic that could not be submitted after its session and
    /// route became available. A transient local dataplane/transport failure
    /// must not strand the restored queue until another discovery response.
    pub(in crate::node) async fn retry_pending_session_traffic(&mut self) {
        let destinations: Vec<NodeAddr> = self
            .pending_session_traffic
            .destinations()
            .filter(|dest_addr| {
                self.sessions
                    .get(dest_addr)
                    .is_some_and(|session| session.is_established())
            })
            .collect();

        for dest_addr in destinations {
            if self.find_next_hop(&dest_addr).is_some() {
                self.flush_pending_packets(&dest_addr).await;
            }
        }
    }
}
