//! RX event loop and packet dispatch.

use crate::control::queries;
use crate::control::{ControlSocket, commands};
use crate::node::aead_pool::AeadInboundElem;
use crate::node::handlers::encrypted::InboundClassify;
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use crate::node::{Node, NodeError};
use crate::transport::ReceivedPacket;
use crate::transport::TransportHandle;
use std::time::Duration;
use tracing::{debug, info, warn};

impl Node {
    /// Run the receive event loop.
    ///
    /// Processes packets from all transports, dispatching based on
    /// the phase field in the 4-byte common prefix:
    /// - Phase 0x0: Encrypted frame (session data)
    /// - Phase 0x1: Handshake message 1 (initiator -> responder)
    /// - Phase 0x2: Handshake message 2 (responder -> initiator)
    ///
    /// Also processes outbound IPv6 packets from the TUN reader for session
    /// encapsulation and routing through the mesh.
    ///
    /// Also processes DNS-resolved identities for identity cache population.
    ///
    /// Also runs a periodic tick (1s) to clean up stale handshake connections
    /// that never received a response. This prevents resource leaks when peers
    /// are unreachable.
    ///
    /// This method takes ownership of the packet_rx channel and runs
    /// until the channel is closed (typically when stop() is called).
    pub async fn run_rx_loop(&mut self) -> Result<(), NodeError> {
        let mut packet_rx = self.packet_rx.take().ok_or(NodeError::NotStarted)?;
        // Take the AEAD-pool completion receiver if the pool is enabled.
        // We hold it in a local so a `select!` arm can `&mut` it without
        // racing the `&self`-borrow of `aead_pool` in the submit path.
        let mut aead_completion_rx = self.aead_completion_rx.take();

        // Take the TUN outbound receiver, or create a dummy channel that never
        // produces messages (when TUN is disabled). Holding the sender prevents
        // the channel from closing.
        let (mut tun_outbound_rx, _tun_guard) = match self.tun_outbound_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                (rx, Some(tx))
            }
        };

        // Take the DNS identity receiver, or create a dummy channel (when DNS
        // is disabled). Same pattern as TUN outbound.
        let (mut dns_identity_rx, _dns_guard) = match self.dns_identity_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                (rx, Some(tx))
            }
        };

        // Take the endpoint-data command receiver, or create a dummy channel
        // when the embedded endpoint API is not in use.
        let (mut endpoint_command_rx, _endpoint_command_guard) =
            match self.endpoint_command_rx.take() {
                Some(rx) => (rx, None),
                None => {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    (rx, Some(tx))
                }
            };

        let mut tick =
            tokio::time::interval(Duration::from_secs(self.config.node.tick_interval_secs));

        // Set up control socket channel
        let (control_tx, mut control_rx) =
            tokio::sync::mpsc::channel::<crate::control::ControlMessage>(32);

        if self.config.node.control.enabled {
            let config = self.config.node.control.clone();
            let tx = control_tx.clone();
            tokio::spawn(async move {
                match ControlSocket::bind(&config) {
                    Ok(socket) => {
                        socket.accept_loop(tx).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to bind control socket");
                    }
                }
            });
        }
        // Drop unused sender to avoid keeping channel open if control is disabled
        drop(control_tx);

        info!("RX event loop started");

        loop {
            tokio::select! {
                biased;
                packet = packet_rx.recv() => {
                    let p = match packet {
                        Some(p) => p,
                        None => break, // channel closed
                    };
                    if aead_completion_rx.is_some() {
                        // Pool is enabled: classify this packet and
                        // anything else already queued, then dispatch.
                        self.handle_inbound_with_pool(p, &mut packet_rx).await;
                    } else {
                        // Legacy inline path.
                        self.process_packet(p).await;
                        let mut drained = 0;
                        while drained < 256 {
                            match packet_rx.try_recv() {
                                Ok(p) => {
                                    self.process_packet(p).await;
                                    drained += 1;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    // Flush any batched sends triggered by inbound
                    // packets (e.g. forwarded SessionDatagrams, MMP
                    // reports, tree announces).
                    self.flush_pending_sends().await;
                }
                // Pool completion arm. The `if let` guard makes this arm
                // a no-op (`std::future::pending`) when the pool is
                // disabled, so legacy nodes pay no scheduler cost for it.
                Some(decrypted_batch) = async {
                    match aead_completion_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    for elem in decrypted_batch {
                        self.apply_decrypted_elem(elem).await;
                    }
                    // Drain any further completed batches that landed
                    // while we were processing the first.
                    if let Some(rx) = aead_completion_rx.as_mut() {
                        let mut drained = 0;
                        while drained < 16 {
                            match rx.try_recv() {
                                Some(b) => {
                                    for elem in b {
                                        self.apply_decrypted_elem(elem).await;
                                    }
                                    drained += 1;
                                }
                                None => break,
                            }
                        }
                    }
                    self.flush_pending_sends().await;
                }
                Some(ipv6_packet) = tun_outbound_rx.recv() => {
                    self.handle_tun_outbound(ipv6_packet).await;
                    let mut drained = 0;
                    while drained < 256 {
                        match tun_outbound_rx.try_recv() {
                            Ok(p) => {
                                self.handle_tun_outbound(p).await;
                                drained += 1;
                            }
                            Err(_) => break,
                        }
                    }
                    // Flush any trailing batched sends so the last
                    // packets of a burst don't sit in the per-transport
                    // sendmmsg buffer waiting for the threshold.
                    self.flush_pending_sends().await;
                }
                Some(identity) = dns_identity_rx.recv() => {
                    debug!(
                        node_addr = %identity.node_addr,
                        "Registering identity from DNS resolution"
                    );
                    self.register_identity(identity.node_addr, identity.pubkey);
                }
                Some(command) = endpoint_command_rx.recv() => {
                    self.handle_endpoint_data_command(command).await;
                    // Same drain pattern: when the application is shoving
                    // tunnel data in via send_oneway, several Send commands
                    // typically queue up between scheduler hops.
                    let mut drained = 0;
                    while drained < 256 {
                        match endpoint_command_rx.try_recv() {
                            Ok(c) => {
                                self.handle_endpoint_data_command(c).await;
                                drained += 1;
                            }
                            Err(_) => break,
                        }
                    }
                    // Flush any trailing batched sends from the
                    // per-transport sendmmsg buffer.
                    self.flush_pending_sends().await;
                }
                Some((request, response_tx)) = control_rx.recv() => {
                    let response = if request.command.starts_with("show_") {
                        queries::dispatch(self, &request.command, request.params.as_ref())
                    } else {
                        commands::dispatch(
                            self,
                            &request.command,
                            request.params.as_ref(),
                        ).await
                    };
                    let _ = response_tx.send(response);
                }
                _ = tick.tick() => {
                    self.check_timeouts();
                    let now_ms = Self::now_ms();
                    self.reload_peer_acl();
                    self.poll_pending_connects().await;
                    self.poll_nostr_discovery().await;
                    self.resend_pending_handshakes(now_ms).await;
                    self.resend_pending_rekeys(now_ms).await;
                    self.resend_pending_session_handshakes(now_ms).await;
                    self.purge_idle_sessions(now_ms);
                    self.purge_learned_routes(now_ms);
                    self.process_pending_retries(now_ms).await;
                    self.check_tree_state().await;
                    self.check_bloom_state().await;
                    self.compute_mesh_size();
                    self.record_stats_history();
                    self.check_mmp_reports().await;
                    self.check_session_mmp_reports().await;
                    self.check_link_heartbeats().await;
                    self.check_rekey().await;
                    self.check_session_rekey().await;
                    self.check_pending_lookups(now_ms).await;
                    self.poll_transport_discovery().await;
                    self.sample_transport_congestion();
                }
            }
        }

        info!("RX event loop stopped (channel closed)");
        Ok(())
    }

    /// Drain `packet_rx` (starting with `first`), classify each packet
    /// for the parallel-decrypt pool, and dispatch.
    ///
    /// Order rules within one drain batch:
    ///   • AEAD-eligible packets are accumulated into `aead_batch` and
    ///     submitted together at the end as a single `DecryptJob`. The
    ///     pool processes batch elements in `Vec` order, so per-peer
    ///     ordering is preserved within a batch.
    ///   • Inline packets (handshake, unknown session, K-bit-flip needed,
    ///     ciphers not yet keyed) run through `process_packet` *first*,
    ///     synchronously, before submitting the AEAD batch. This
    ///     preserves the legacy "msg2 establishes session, established
    ///     frame on the new session sees it" ordering when both arrive
    ///     in the same drain cycle.
    ///   • Replays are dropped silently — they don't deserve a worker
    ///     slot.
    async fn handle_inbound_with_pool(
        &mut self,
        first: ReceivedPacket,
        packet_rx: &mut crate::transport::PacketRx,
    ) {
        let mut aead_batch: Vec<AeadInboundElem> = Vec::with_capacity(64);
        let mut inline_packets: Vec<ReceivedPacket> = Vec::new();

        // Classify the first packet, then drain anything else that's
        // already queued. The 256-cap matches the legacy non-pool path.
        match self.classify_inbound_packet(first) {
            InboundClassify::Aead(e) => aead_batch.push(e),
            InboundClassify::Inline(p) => inline_packets.push(p),
            InboundClassify::Replay => {}
        }
        let mut drained = 0;
        while drained < 256 {
            match packet_rx.try_recv() {
                Ok(p) => {
                    match self.classify_inbound_packet(p) {
                        InboundClassify::Aead(e) => aead_batch.push(e),
                        InboundClassify::Inline(p) => inline_packets.push(p),
                        InboundClassify::Replay => {}
                    }
                    drained += 1;
                }
                Err(_) => break,
            }
        }

        // Run inline packets first. The intended invariant is "any
        // session that an aead packet in this batch refers to was
        // already established on a previous tick; any session being
        // established by an inline packet THIS tick will be picked up by
        // future ticks' aead packets, not packets in this same batch."
        // The classifier enforces this by punting unknown-session
        // packets to inline, so re-handshake transitions interleave
        // correctly.
        for p in inline_packets {
            self.process_packet(p).await;
        }

        if !aead_batch.is_empty()
            && let Some(pool) = self.aead_pool.as_ref()
        {
            pool.submit_batch(aead_batch).await;
        }
    }

    /// Flush any pending batched sends across all transports. Each
    /// transport may buffer outbound packets (the UDP transport uses
    /// `sendmmsg(2)` to amortise per-syscall overhead); this drains
    /// whatever's still buffered so trailing packets in a burst don't
    /// sit in the buffer past a drain cycle. Cheap when there's
    /// nothing to flush — each transport just checks an empty queue.
    async fn flush_pending_sends(&self) {
        for transport in self.transports.values() {
            // Avoid hard-coding the UDP-only check here so future
            // transports can opt into batching by overriding
            // `flush_pending_send`.
            if matches!(transport, TransportHandle::Udp(_)) {
                transport.flush_pending_send().await;
            }
        }
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the phase field in the 4-byte common prefix.
    async fn process_packet(&mut self, packet: ReceivedPacket) {
        if packet.data.len() < COMMON_PREFIX_SIZE {
            return; // Drop packets too short for common prefix
        }

        let prefix = match CommonPrefix::parse(&packet.data) {
            Some(p) => p,
            None => return, // Malformed prefix
        };

        if prefix.version != FMP_VERSION {
            debug!(
                version = prefix.version,
                transport_id = %packet.transport_id,
                "Unknown FMP version, dropping"
            );

            // If the packet arrived on an adopted Nostr-NAT bootstrap
            // transport, the originating peer is necessarily on a
            // different FMP-protocol version than us — the discovery
            // sweep would otherwise re-traverse them every cycle even
            // though no msg1/msg2 exchange can ever succeed. Bump the
            // discovery-layer cooldown to the long protocol-mismatch
            // window and emit a single WARN per fresh observation.
            if self.bootstrap_transports.contains(&packet.transport_id)
                && let Some(npub) = self
                    .bootstrap_transport_npubs
                    .get(&packet.transport_id)
                    .cloned()
                && let Some(handle) = self.nostr_discovery_handle()
            {
                let now_ms = Self::now_ms();
                let cooldown_secs = handle.protocol_mismatch_cooldown_secs();
                if handle.record_protocol_mismatch(&npub, now_ms) {
                    warn!(
                        peer_npub = %npub,
                        transport_id = %packet.transport_id,
                        peer_version = prefix.version,
                        our_version = FMP_VERSION,
                        cooldown_secs,
                        "Nostr-discovered peer speaks a different FMP version; suppressing retraversal"
                    );
                }
            }
            return;
        }

        match prefix.phase {
            PHASE_ESTABLISHED => {
                self.handle_encrypted_frame(packet).await;
            }
            PHASE_MSG1 => {
                self.handle_msg1(packet).await;
            }
            PHASE_MSG2 => {
                self.handle_msg2(packet).await;
            }
            _ => {
                debug!(
                    phase = prefix.phase,
                    transport_id = %packet.transport_id,
                    "Unknown FMP phase, dropping"
                );
            }
        }
    }
}
