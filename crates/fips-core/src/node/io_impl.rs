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
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(capacity);
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
        if self.state != NodeState::Created {
            return Err(NodeError::Config(ConfigError::Validation(
                "endpoint data I/O must be attached before node start".to_string(),
            )));
        }

        let command_capacity = endpoint_data_command_capacity(capacity);
        let (priority_command_tx, priority_command_rx) =
            tokio::sync::mpsc::channel(command_capacity);
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(command_capacity);
        // Endpoint events keep priority delivery wait-free and bound bulk
        // backlog by the caller's packet-channel capacity.
        let (event_tx, event_rx) = EndpointEventSender::channel(capacity);
        #[cfg(unix)]
        let (bulk_send_runtime, bulk_feedback_rx) = EndpointBulkSendRuntime::channel(capacity);
        #[cfg(not(unix))]
        let (_bulk_feedback_tx, bulk_feedback_rx) =
            tokio::sync::mpsc::channel(endpoint_data_command_capacity(capacity).max(1));
        self.endpoint_priority_command_rx = Some(priority_command_rx);
        self.endpoint_command_rx = Some(command_rx);
        self.endpoint_events.attach(event_tx.clone());
        self.endpoint_bulk_feedback_rx = Some(bulk_feedback_rx);
        #[cfg(unix)]
        {
            self.endpoint_bulk_send_runtime = Some(bulk_send_runtime.clone());
        }

        Ok(EndpointDataIo {
            priority_command_tx,
            command_tx,
            event_rx,
            event_tx,
            #[cfg(unix)]
            bulk_send_runtime,
        })
    }

    pub(in crate::node) fn begin_endpoint_event_batch(&mut self) {
        self.endpoint_events.begin_batch();
    }

    pub(in crate::node) fn finish_endpoint_event_batch(&mut self) {
        self.endpoint_events.finish_batch();
    }

    #[allow(clippy::result_large_err)]
    pub(in crate::node) fn deliver_endpoint_event_message(
        &mut self,
        message: EndpointDataDelivery,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        self.endpoint_events.deliver_endpoint_data(message)
    }

    pub(in crate::node) fn decrypt_direct_session_delivery_sink(
        &self,
    ) -> decrypt_worker::DecryptDirectSessionDeliverySink {
        decrypt_worker::DecryptDirectSessionDeliverySink::new(
            self.tun_tx.clone(),
            self.external_packet_tx.clone(),
            self.endpoint_events.sender(),
        )
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
