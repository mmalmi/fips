impl Node {
    const PENDING_TUN_PACKET_FLUSH_MAX_AGE_MS: u64 = 2_000;

    fn deliver_endpoint_data(&mut self, delivery: EndpointDataDelivery) {
        let src_addr = *delivery.source_peer.node_addr();
        if !self.endpoint_events.is_attached() {
            trace!(
                src = %self.peer_display_name(&src_addr),
                "Endpoint data received without an attached endpoint"
            );
            return;
        }

        if let Err(error) = self.deliver_endpoint_event_message(delivery) {
            debug!(
                src = %self.peer_display_name(&src_addr),
                error = %error,
                "Failed to deliver endpoint data event"
            );
        }
    }

    /// Send a non-data session message (reports, notifications) over an established session.
    ///
    /// Similar to `send_session_data()` but:
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
        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let timestamp = send_context.timestamp;

        // Build inner flags with spin bit
        let inner_flags = send_context.inner_flags_byte();
        let k_flags = send_context.fsp_flags(false);

        // FSP inner header + plaintext
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, payload);

        self.send_session_fsp_plan(SessionFspSendPlan::new(
            *dest_addr,
            timestamp,
            k_flags,
            &inner_plaintext,
            None,
            SessionFspSendBookkeeping::Control,
        ))
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
        let now_ms = Self::now_ms();

        let my_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let timestamp = send_context.timestamp;

        // FSP inner header only, no body payload
        let msg_type = SessionMessageType::CoordsWarmup.to_byte();
        let inner_flags = send_context.inner_flags_byte();
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &[]);

        self.send_session_fsp_plan(SessionFspSendPlan::new(
            *dest_addr,
            timestamp,
            0,
            &inner_plaintext,
            Some((&my_coords, &dest_coords)),
            SessionFspSendBookkeeping::Control,
        ))
        .await?;

        debug!(dest = %self.peer_display_name(dest_addr), "Sent standalone CoordsWarmup");
        Ok(())
    }

    /// Route and send a SessionDatagram through the mesh.
    ///
    /// Finds the next hop for the destination, seeds path_mtu from the
    /// first-hop transport MTU, and sends as an encrypted link message.
    pub(in crate::node) async fn send_session_datagram(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<(), NodeError> {
        let runtime_route = self.resolve_session_datagram_runtime_route(datagram)?;

        let encoded = datagram.encode();
        if let Err(err) = self
            .send_encrypted_link_message(&runtime_route.next_hop_addr(), &encoded)
            .await
        {
            let dest_addr = runtime_route.dest_addr();
            let next_hop_addr = runtime_route.next_hop_addr();
            runtime_route.record_failure(self);
            self.recover_direct_payload_send_failure(dest_addr, next_hop_addr, &err);
            return Err(err);
        }
        runtime_route.record_success(self, encoded.len());
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

    fn resolve_session_datagram_runtime_route(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<SessionDatagramRuntimeRoute, NodeError> {
        let dest_addr = datagram.dest_addr;
        let next_hop_addr = match self.find_next_hop(&dest_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                return Err(NodeError::SendFailed {
                    node_addr: dest_addr,
                    reason: "no route to destination".into(),
                });
            }
        };

        let mut path_mtu = datagram.path_mtu;
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            path_mtu = if let Some(addr) = peer.current_addr() {
                path_mtu.min(transport.link_mtu(addr))
            } else {
                path_mtu.min(transport.mtu())
            };
        }
        datagram.path_mtu = path_mtu;

        let source_mmp_seeded = self
            .sessions
            .seed_session_datagram_path_mtu(&dest_addr, path_mtu);

        Ok(SessionDatagramRuntimeRoute::new(
            dest_addr,
            next_hop_addr,
            path_mtu,
            source_mmp_seeded,
        ))
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

    // === TUN Outbound (Data Plane) ===

    /// Handle an outbound IPv6 packet from the TUN reader.
    ///
    /// Extracts the destination FipsAddress, looks up the NodeAddr and PublicKey
    /// from the identity cache, and either sends through an established session
    /// or initiates a new one (queuing the packet until established).
    ///
    /// Also performs MTU checking: if the packet (plus FIPS overhead) exceeds
    /// the transport MTU, an ICMP Packet Too Big message is sent back to the
    /// source and the packet is dropped.
    pub(in crate::node) async fn handle_tun_outbound(&mut self, ipv6_packet: Vec<u8>) {
        // Validate IPv6 header
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            return;
        }

        // Check if packet will fit after FIPS encapsulation
        let effective_mtu = self.effective_ipv6_mtu() as usize;
        if ipv6_packet.len() > effective_mtu {
            self.send_icmpv6_packet_too_big(&ipv6_packet, effective_mtu as u32);
            return;
        }

        // Extract destination FipsAddress prefix (IPv6 dest bytes 1-15)
        // IPv6 header: bytes 24-39 are dest addr, so prefix = bytes 25-39
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&ipv6_packet[25..40]);

        // Look up in identity cache
        let (dest_addr, dest_pubkey) = match self.lookup_by_fips_prefix(&prefix) {
            Some((addr, pk)) => (addr, pk),
            None => {
                self.send_icmpv6_dest_unreachable(&ipv6_packet);
                return;
            }
        };

        match self.sessions.tun_outbound_session_decision(
            &dest_addr,
            effective_mtu,
            ipv6_packet.len(),
        ) {
            TunOutboundSessionDecision::Established => {
                if let Err(e) = self.send_ipv6_packet(&dest_addr, &ipv6_packet).await {
                    if Self::session_send_needs_path_recovery(&e, &dest_addr) {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            error = %e,
                            "Established TUN session lost route; queueing packet and probing fallback"
                        );
                        self.queue_pending_packet(dest_addr, ipv6_packet);
                        self.maybe_initiate_lookup(&dest_addr).await;
                    } else {
                        debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to send TUN packet via session");
                    }
                }
                return;
            }
            TunOutboundSessionDecision::EstablishedPathMtuExceeded { path_ipv6_mtu } => {
                self.send_icmpv6_packet_too_big(&ipv6_packet, path_ipv6_mtu);
                return;
            }
            TunOutboundSessionDecision::Pending => {
                self.queue_pending_packet(dest_addr, ipv6_packet);
                let should_discover = self.config.node.routing.mode
                    == crate::config::RoutingMode::ReplyLearned
                    || self.find_next_hop(&dest_addr).is_none();
                if should_discover {
                    self.maybe_initiate_lookup(&dest_addr).await;
                }
                return;
            }
            TunOutboundSessionDecision::Missing => {}
        }

        // No session: initiate one and queue the packet.
        // If session initiation fails (no route), trigger discovery and
        // queue the packet for retry when discovery completes.
        if let Err(e) = self.initiate_session(dest_addr, dest_pubkey).await {
            debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to initiate session, trying discovery");
            self.maybe_initiate_lookup(&dest_addr).await;
            self.queue_pending_packet(dest_addr, ipv6_packet);
            return;
        }
        self.queue_pending_packet(dest_addr, ipv6_packet);
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
    fn queue_pending_packet(&mut self, dest_addr: NodeAddr, packet: Vec<u8>) {
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
            crate::perf_profile::record_event(crate::perf_profile::Event::PendingTunPacketDropped);
        }
    }

    /// Queue endpoint data while waiting for session establishment.
    fn queue_pending_endpoint_data(
        &mut self,
        dest_addr: NodeAddr,
        payload: impl Into<EndpointDataPayload>,
    ) {
        let admission = self.pending_session_traffic.push_endpoint_data(
            dest_addr,
            payload,
            self.config.node.session.pending_max_destinations,
            self.config.node.session.pending_packets_per_dest,
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

        if let Some(packets) = self.pending_session_traffic.take_tun_packets(dest_addr) {
            let (packets, stale_count) = packets.into_fresh_packets(
                Self::now_ms(),
                Self::PENDING_TUN_PACKET_FLUSH_MAX_AGE_MS,
            );
            if stale_count > 0 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::PendingTunPacketDropped,
                    stale_count as u64,
                );
                debug!(
                    dest = %self.peer_display_name(dest_addr),
                    dropped = stale_count,
                    "Dropped stale queued TUN packets before session flush"
                );
            }
            for packet in packets {
                if let Err(e) = self.send_ipv6_packet(dest_addr, &packet).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued TUN packet");
                    break;
                }
            }
        }

        if let Some(payloads) = self.pending_session_traffic.take_endpoint_data(dest_addr) {
            for payload in payloads.into_payloads() {
                if let Err(e) = self.send_session_endpoint_data(dest_addr, &payload).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued endpoint data");
                    break;
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

        match self
            .sessions
            .prepare_retry_session_after_discovery(&dest_addr)
        {
            DiscoveryRetrySessionDecision::Established => {
                return;
            }
            DiscoveryRetrySessionDecision::RestartedPending => {
                debug!(
                    dest = %self.peer_display_name(&dest_addr),
                    "Restarting pending session after discovery refreshed route"
                );
            }
            DiscoveryRetrySessionDecision::Missing => {}
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
}
