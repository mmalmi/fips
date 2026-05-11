//! RX event loop and packet dispatch.

use crate::control::queries;
use crate::control::{ControlSocket, commands};
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

        // Take the decrypt worker fallback receiver if a worker pool
        // is in use. The worker pushes non-fast-path packets (anything
        // that's not bulk EndpointData) here for the legacy dispatch.
        let (mut decrypt_fallback_rx, _decrypt_fallback_guard) =
            match self.decrypt_fallback_rx.take() {
                Some(rx) => (rx, None),
                None => {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
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
        // Optional perf profiler (FIPS_PERF=1). No-op otherwise.
        crate::perf_profile::maybe_spawn_reporter();

        loop {
            tokio::select! {
                biased;
                packet = packet_rx.recv() => {
                    match packet {
                        Some(p) => self.process_packet(p).await,
                        None => break, // channel closed
                    }
                    // Drain remaining ready inbound packets in a tight loop
                    // before yielding back to select! — every yield is a
                    // futex hop on tokio's multi-thread scheduler, and at
                    // line rate the kernel UDP queue typically has several
                    // datagrams available per wake. Caps at a batch
                    // boundary so other branches (tick, control) eventually
                    // get a turn even under sustained load.
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
                    // Flush any batched sends triggered by inbound
                    // packets (e.g. forwarded SessionDatagrams, MMP
                    // reports, tree announces).
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
                Some(fallback) = decrypt_fallback_rx.recv() => {
                    // Decrypt worker bounced a packet back for
                    // FSP-layer dispatch after handling the FMP layer.
                    // Hand the FMP plaintext to the canonical
                    // post-decrypt processor — same code path the
                    // test-mode in-line decrypt below takes, so
                    // per-peer bookkeeping (peer.touch,
                    // link_stats.record_recv, mmp.receiver.record_recv,
                    // set_current_addr) and link-layer dispatch run
                    // identically in both modes.
                    //
                    // CE/SP flag extraction: the FMP outer header's
                    // flags byte rides through the worker on
                    // `DecryptJob.fmp_flags` and out via
                    // `DecryptFallback.fmp_flags`. Without this the
                    // worker path drops ECN CE propagation and
                    // spin-bit RTT observation on every packet —
                    // both of which only fire on these two flag
                    // bits and both of which were previously
                    // hardcoded to `false` here.
                    let ce_flag =
                        fallback.fmp_flags & crate::node::wire::FLAG_CE != 0;
                    let sp_flag =
                        fallback.fmp_flags & crate::node::wire::FLAG_SP != 0;
                    // Slice into the original wire buffer — zero
                    // alloc, zero copy. The worker bounce used to
                    // `to_vec()` ~1500 bytes per packet (~225 MB/sec
                    // memory bandwidth at 150k pps); now we just
                    // index.
                    let plaintext = &fallback.packet_data[fallback.fmp_plaintext_offset
                        ..fallback.fmp_plaintext_offset + fallback.fmp_plaintext_len];
                    self.process_authentic_fmp_plaintext(
                        &fallback.source_node_addr,
                        fallback.transport_id,
                        &fallback.remote_addr,
                        fallback.timestamp_ms,
                        fallback.packet_len,
                        fallback.fmp_counter,
                        ce_flag,
                        sp_flag,
                        plaintext,
                    )
                    .await;
                }
                _ = tick.tick() => {
                    self.check_timeouts();
                    let now_ms = Self::now_ms();
                    self.reload_peer_acl();
                    self.poll_pending_connects().await;
                    self.poll_nostr_discovery().await;
                    self.poll_lan_discovery().await;
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
                    self.activate_connected_udp_sessions().await;
                }
            }
        }

        info!("RX event loop stopped (channel closed)");
        Ok(())
    }

    /// Flush any pending batched sends across all transports. Today
    /// every transport's `flush_pending_send` is a no-op — the UDP
    /// transport's per-transport `pending_send` buffer was removed
    /// when the bulk data path moved into `encrypt_worker` (which
    /// does its own target-grouped `sendmmsg(2)` directly). The
    /// call sites are retained so any future batched transport can
    /// opt in by overriding `flush_pending_send` without touching
    /// the rx_loop.
    async fn flush_pending_sends(&self) {
        for transport in self.transports.values() {
            if matches!(transport, TransportHandle::Udp(_)) {
                transport.flush_pending_send().await;
            }
        }
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the phase field in the 4-byte common prefix.
    async fn process_packet(&mut self, packet: ReceivedPacket) {
        let _t_total = crate::perf_profile::Timer::start(crate::perf_profile::Stage::ProcessPacket);
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
