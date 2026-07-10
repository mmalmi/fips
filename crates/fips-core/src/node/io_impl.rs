use super::*;

impl Node {
    /// Get the TUN packet sender channel.
    ///
    /// Returns None if TUN is not active or the node hasn't been started.
    pub fn tun_tx(&self) -> Option<&TunTx> {
        self.tun_tx.as_ref()
    }

    /// Attach app-owned packet I/O for embedded operation without a system TUN.
    ///
    /// This must be called before [`Node::start`] and requires `tun.enabled =
    /// false`. Outbound packets sent to the returned sender are processed by the
    /// normal session pipeline. Inbound packets delivered by FIPS sessions are
    /// sent to the returned receiver with source attribution.
    pub fn attach_external_packet_io(
        &mut self,
        capacity: usize,
    ) -> Result<ExternalPacketIo, NodeError> {
        if self.state != NodeState::Created {
            return Err(NodeError::Config(ConfigError::Validation(
                "external packet I/O must be attached before node start".to_string(),
            )));
        }
        if self.config.tun.enabled {
            return Err(NodeError::Config(ConfigError::Validation(
                "external packet I/O requires tun.enabled=false".to_string(),
            )));
        }

        let capacity = capacity.max(1);
        let (outbound_tx, outbound_rx) = crate::upper::tun::tun_outbound_channel(capacity);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(capacity);
        self.tun_outbound_rx = Some(outbound_rx);
        self.external_packet_tx = Some(inbound_tx);

        Ok(ExternalPacketIo {
            outbound_tx,
            inbound_rx,
        })
    }

    /// Attach app-owned endpoint data I/O for embedded operation.
    ///
    /// Commands sent to the returned sender are processed by the node RX loop.
    /// Incoming endpoint data is emitted as source-attributed events.
    pub(crate) fn attach_endpoint_data_io(
        &mut self,
        capacity: usize,
    ) -> Result<EndpointDataIo, NodeError> {
        self.attach_endpoint_data_io_inner(capacity, None)
    }

    pub(crate) fn attach_endpoint_data_io_with_direct_sink(
        &mut self,
        capacity: usize,
        direct_sink: EndpointDirectSink,
    ) -> Result<EndpointDataIo, NodeError> {
        self.attach_endpoint_data_io_inner(capacity, Some(direct_sink))
    }

    fn attach_endpoint_data_io_inner(
        &mut self,
        capacity: usize,
        direct_sink: Option<EndpointDirectSink>,
    ) -> Result<EndpointDataIo, NodeError> {
        if self.state != NodeState::Created {
            return Err(NodeError::Config(ConfigError::Validation(
                "endpoint data I/O must be attached before node start".to_string(),
            )));
        }

        let command_capacity = capacity.max(1);
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(command_capacity);
        let (data_batch_tx, data_rx) = endpoint_data_batch_channel(command_capacity);
        // Endpoint events use one bounded app-data channel. Protocol/control
        // progress is reserved before endpoint payload delivery reaches this
        // queue.
        let (event_tx, event_rx) =
            EndpointEventSender::channel_with_direct_sink(capacity, direct_sink);
        let (service_event_tx, service_event_rx) = EndpointServiceEventSender::channel(capacity);
        self.endpoint_control_rx = Some(control_rx);
        self.endpoint_data_rx = Some(data_rx);
        self.endpoint_events.attach(event_tx.clone());

        Ok(EndpointDataIo {
            control_tx,
            data_batch_tx,
            event_rx,
            event_tx,
            service_event_rx,
            service_event_tx,
        })
    }

    pub(crate) fn pubkey_for_node_addr(&self, addr: &NodeAddr) -> Option<secp256k1::PublicKey> {
        self.identity_cache.pubkey_for_node_addr(addr)
    }

    pub(crate) fn npub_for_node_addr(&self, addr: &NodeAddr) -> Option<String> {
        self.identity_cache.npub_for_node_addr(addr)
    }

    pub(in crate::node) fn deliver_external_ipv6_packet(
        &self,
        src_addr: &NodeAddr,
        packet: Vec<u8>,
    ) {
        let Some(external_packet_tx) = &self.external_packet_tx else {
            return;
        };
        if packet.len() < 40 {
            return;
        }
        let Ok(destination) = FipsAddress::from_slice(&packet[24..40]) else {
            return;
        };
        let delivered = NodeDeliveredPacket {
            source_node_addr: *src_addr,
            source_npub: self.npub_for_node_addr(src_addr),
            destination,
            packet,
        };
        if let Err(error) = external_packet_tx.try_send(delivered) {
            debug!(error = %error, "Failed to deliver packet to external app sink");
        }
    }

    /// Update one peer's local-outbound-broken signal from a `transport.send`
    /// outcome. Sets a per-peer timestamp on local-side io errors
    /// (NetworkUnreachable / HostUnreachable / AddrNotAvailable); clears that
    /// peer on success. The reaper consults this in `check_link_heartbeats` to
    /// switch only that peer to `fast_link_dead_timeout_secs`.
    pub(in crate::node) fn note_local_send_outcome(
        &mut self,
        node_addr: &NodeAddr,
        result: &Result<usize, TransportError>,
    ) {
        self.local_send_failures
            .note_send_outcome(node_addr, result, std::time::Instant::now());
    }

    /// Update local-outbound liveness from a candidate/probe send.
    ///
    /// A failed probe to an alternate stale address must not compress the
    /// live path's dead timeout. Only the active current path, or a peer with
    /// no usable current path, gets the fast-dead signal.
    pub(in crate::node) fn note_candidate_send_outcome(
        &mut self,
        node_addr: &NodeAddr,
        candidate_addr: &TransportAddr,
        result: &Result<usize, TransportError>,
    ) {
        if result.is_ok() {
            self.note_local_send_outcome(node_addr, result);
            return;
        }

        let candidate_is_active_path = self
            .peers
            .get(node_addr)
            .is_none_or(|peer| !peer.can_send() || peer.current_addr() == Some(candidate_addr));
        if candidate_is_active_path {
            self.note_local_send_outcome(node_addr, result);
        }
    }

    /// Return the active dead-timeout for one peer after considering recent
    /// local route failures. The fast-dead signal is intentionally short-lived:
    /// on the UDP worker path a send call can return before the kernel result
    /// is observed, so a stale route error must not compress liveness for the
    /// whole normal dead-timeout window.
    pub(in crate::node) fn local_send_failure_dead_timeout_for_peer(
        &self,
        node_addr: &NodeAddr,
        now: std::time::Instant,
        dead_timeout: std::time::Duration,
        fast_dead_timeout: std::time::Duration,
    ) -> std::time::Duration {
        self.local_send_failures.dead_timeout_for_peer(
            node_addr,
            now,
            dead_timeout,
            fast_dead_timeout,
        )
    }

    pub(in crate::node) fn purge_expired_local_send_failures(&mut self, now: std::time::Instant) {
        self.local_send_failures.purge_expired(now);
    }

    pub(in crate::node) fn mark_rx_loop_maintenance_timeout(&mut self) {
        self.last_rx_loop_maintenance_timeout_at = Some(std::time::Instant::now());
    }

    pub(in crate::node) fn rx_loop_maintenance_timed_out_recently(&self) -> bool {
        let Some(t) = self.last_rx_loop_maintenance_timeout_at else {
            return false;
        };
        let grace = std::time::Duration::from_secs(self.config.node.link_dead_timeout_secs.max(1));
        std::time::Instant::now().duration_since(t) <= grace
    }
}
