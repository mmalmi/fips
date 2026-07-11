//! SessionDatagram forwarding handler.
//!
//! Handles incoming SessionDatagram (0x00) link messages: decodes the
//! envelope, enforces hop limits, performs coordinate cache warming from
//! plaintext session-layer headers, routes to the next hop or delivers
//! locally, and generates error signals on routing failure.

use crate::NodeAddr;
use crate::node::route_impl::TransitNextHopPlan;
use crate::node::session_wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_HEADER_SIZE, FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1, FSP_PHASE_MSG2,
    FspCommonPrefix, parse_encrypted_coords,
};
use crate::node::{
    AuthenticatedFmpReceiveFacts, AuthenticatedLinkMessage, AuthenticatedSessionDatagram, FLAG_CE,
    LocalSessionPayload, Node, NodeError,
};
use crate::protocol::{
    CoordsRequired, LinkMessageType, MtuExceeded, PathBroken, SessionAck, SessionDatagram,
    SessionDatagramRef, SessionSetup,
};
use crate::transport::PacketBuffer;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Keep several transport-sized sends admitted while AEAD workers and the
/// socket lane make progress. The receive loop bounds an ingress turn at 512
/// packets; half of that budget is a deep enough pipeline without letting a
/// single forwarding flush monopolize the node loop.
const FORWARDING_IN_FLIGHT_TRANSPORT_BATCHES: usize = 4;

struct PreparedSessionForward {
    next_hop_addr: NodeAddr,
    src_addr: NodeAddr,
    dest_addr: NodeAddr,
    outgoing_ce: bool,
    received_len: usize,
    encoded_len: usize,
    plaintext: PacketBuffer,
}

include!("forwarding_deferred.rs");
include!("forwarding_terminal.rs");

struct PreparedSessionForwardRoute {
    next_hop_addr: NodeAddr,
    src_addr: NodeAddr,
    dest_addr: NodeAddr,
    outgoing_ce: bool,
    received_len: usize,
    ttl: u8,
    path_mtu: u16,
}

enum PreparedSessionDatagram {
    Forward(PreparedSessionForwardRoute),
    NoRoute {
        datagram: SessionDatagram,
        received_len: usize,
        loop_failure: Option<NodeAddr>,
    },
    Done,
}

impl Node {
    /// Handle an incoming SessionDatagram from a peer.
    ///
    /// Called by `dispatch_link_message` for msg_type 0x00. The payload has
    /// already had its msg_type byte stripped by dispatch, and the previous
    /// hop is the authenticated peer that sent the enclosing link message.
    ///
    /// Hot path: borrows `payload` via `SessionDatagramRef` (zero copy)
    /// for the common local-delivery case. The owning `SessionDatagram`
    /// is built only when forwarding (rare in steady-state benches with
    /// direct peers).
    pub(in crate::node) async fn handle_session_datagram(
        &mut self,
        datagram: AuthenticatedSessionDatagram<'_>,
    ) {
        let payload = datagram.payload;
        match self.prepare_session_datagram(datagram).await {
            PreparedSessionDatagram::Forward(route) => {
                let plaintext = {
                    let _timer = crate::perf_profile::Timer::start(
                        crate::perf_profile::Stage::TransitEncode,
                    );
                    copy_forwarded_session_datagram(payload, route.ttl, route.path_mtu)
                };
                let forward = route.with_plaintext(PacketBuffer::new(plaintext));
                let result = self
                    .send_dataplane_fmp_link_plaintext(
                        &forward.next_hop_addr,
                        forward.plaintext.as_slice(),
                        forward.outgoing_ce,
                    )
                    .await;
                self.finish_prepared_session_forward(forward, result, true)
                    .await;
            }
            PreparedSessionDatagram::NoRoute {
                datagram,
                received_len,
                loop_failure,
            } => {
                self.finish_session_datagram_no_route(datagram, received_len, loop_failure)
                    .await;
            }
            PreparedSessionDatagram::Done => {}
        }
    }

    pub(in crate::node) async fn handle_dataplane_fmp_link_ingress_batch(
        &mut self,
        ingresses: Vec<crate::dataplane::DataplaneFmpLinkIngress>,
    ) -> usize {
        let mut processed = 0usize;
        let flush_limit = forwarding_submission_limit(self.dataplane_transport_send_batch_packets);
        let mut forwards = Vec::with_capacity(ingresses.len().min(flush_limit));
        for ingress in ingresses {
            let receipt = ingress.receipt();
            let fmp = AuthenticatedFmpReceiveFacts::from_dataplane_receipt(receipt);
            self.record_authenticated_fmp_receive_facts(fmp, Some(receipt.source_addr()));
            let Some(msg_type) = ingress.msg_type() else {
                processed = processed.saturating_add(1);
                continue;
            };
            if msg_type == LinkMessageType::SessionDatagram.to_byte() {
                let datagram = AuthenticatedSessionDatagram::new(
                    fmp.source_peer,
                    ingress.payload(),
                    fmp.fmp_flags & FLAG_CE != 0,
                );
                if self.session_datagram_is_transit_candidate(&datagram) {
                    match self.prepare_session_datagram(datagram).await {
                        PreparedSessionDatagram::Forward(route) => {
                            let (plaintext, rewritten) = {
                                let _timer = crate::perf_profile::Timer::start(
                                    crate::perf_profile::Stage::TransitEncode,
                                );
                                let mut plaintext = ingress
                                    .into_link_plaintext()
                                    .expect("opened FMP ingress must retain its plaintext owner");
                                let rewritten = rewrite_forwarded_session_datagram(
                                    &mut plaintext,
                                    route.ttl,
                                    route.path_mtu,
                                );
                                (plaintext, rewritten)
                            };
                            debug_assert!(
                                rewritten,
                                "validated transit datagram must be rewriteable"
                            );
                            if rewritten {
                                let forward = route.with_plaintext(plaintext);
                                forwards.push(forward);
                                if forward_run_reached_limit(forwards.len(), flush_limit) {
                                    self.flush_prepared_session_forwards(&mut forwards).await;
                                }
                            }
                        }
                        PreparedSessionDatagram::NoRoute {
                            datagram,
                            received_len,
                            loop_failure,
                        } => {
                            self.flush_prepared_session_forwards(&mut forwards).await;
                            self.drain_deferred_session_forwards().await;
                            self.finish_session_datagram_no_route(
                                datagram,
                                received_len,
                                loop_failure,
                            )
                            .await;
                        }
                        PreparedSessionDatagram::Done => {}
                    }
                } else {
                    self.flush_prepared_session_forwards(&mut forwards).await;
                    self.drain_deferred_session_forwards().await;
                    self.handle_session_datagram(datagram).await;
                }
            } else {
                self.flush_prepared_session_forwards(&mut forwards).await;
                self.drain_deferred_session_forwards().await;
                self.dispatch_link_message(AuthenticatedLinkMessage::new(
                    fmp.source_peer,
                    msg_type,
                    ingress.payload(),
                    fmp.fmp_flags & FLAG_CE != 0,
                ))
                .await;
            }
            processed = processed.saturating_add(1);
        }
        self.flush_prepared_session_forwards(&mut forwards).await;
        processed
    }

    /// Pure preflight for the batching decision. Valid non-local traffic goes
    /// to the transit planner; local delivery, malformed input, and TTL drops
    /// stay scalar after earlier runs finish. The planner returns no-route as
    /// a deferred action so that action also runs only after the prior flush.
    fn session_datagram_is_transit_candidate(
        &self,
        datagram: &AuthenticatedSessionDatagram<'_>,
    ) -> bool {
        let Ok(decoded) = SessionDatagramRef::decode(datagram.payload) else {
            return false;
        };
        if decoded.ttl == 0 || decoded.dest_addr == *self.node_addr() {
            return false;
        }
        true
    }

    async fn flush_prepared_session_forwards(
        &mut self,
        forwards: &mut Vec<PreparedSessionForward>,
    ) {
        if forwards.is_empty() {
            return;
        }
        // These two stages are intentionally one sample per forwarding run,
        // not one sample per packet. Receipt accounting may finish on a later
        // RX-loop turn; this timer covers bounded admission and the first pump.
        let _total_timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::TransitTotal);
        let mut waiting = std::mem::take(forwards);
        while !waiting.is_empty() {
            let waiting_len = waiting.len();
            let mut outbound = Vec::with_capacity(waiting.len());
            let mut blocked = Vec::new();
            let activity_tick = crate::dataplane::ActivityTick::new(Self::now_ms());
            for mut forward in waiting {
                let lane = forwarding_lane(&forward);
                if !self.deferred_session_forwards.has_capacity(&forward, lane) {
                    blocked.push(forward);
                    continue;
                }
                let next_hop_addr = forward.next_hop_addr;
                let outgoing_ce = forward.outgoing_ce;
                let plaintext = std::mem::take(&mut forward.plaintext);
                match self.prepare_dataplane_fmp_link_outbound(
                    next_hop_addr,
                    plaintext,
                    outgoing_ce,
                    activity_tick,
                ) {
                    Ok((packet, send_token)) => {
                        let inserted = self
                            .deferred_session_forwards
                            .insert(send_token, forward, lane);
                        debug_assert!(inserted, "forwarding capacity changed without an await");
                        outbound.push(packet);
                    }
                    Err(error) => self
                        .deferred_session_forwards
                        .push_completed(forward, Err(error)),
                }
            }

            if !outbound.is_empty() {
                let crypto_limit = outbound.len();
                let turn = {
                    let _submit_timer = crate::perf_profile::Timer::start(
                        crate::perf_profile::Stage::TransitSubmit,
                    );
                    self.pump_dataplane_pending_outbound_firsts(
                        crate::dataplane::DataplaneLiveOutboundFirsts {
                            initial_outbound_batch: outbound,
                            collect_transport_sent_receipts: true,
                            ..Default::default()
                        },
                        0,
                        0,
                        crypto_limit,
                    )
                    .await
                };
                self.defer_dataplane_control_turn(turn);
            }
            self.finish_completed_session_forwards().await;

            if blocked.is_empty() {
                break;
            }
            if blocked.len() == waiting_len {
                self.drain_one_deferred_session_forward_turn().await;
            }
            waiting = blocked;
        }
    }

    async fn prepare_session_datagram(
        &mut self,
        datagram: AuthenticatedSessionDatagram<'_>,
    ) -> PreparedSessionDatagram {
        let AuthenticatedSessionDatagram {
            previous_hop_peer,
            payload,
            ce_flag: incoming_ce,
        } = datagram;
        let previous_hop = *previous_hop_peer.node_addr();

        self.stats_mut().forwarding.record_received(payload.len());

        let decode_result = {
            let _timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::SessionDatagramDecode,
            );
            SessionDatagramRef::decode(payload)
        };
        let datagram_ref = match decode_result {
            Ok(dg) => dg,
            Err(e) => {
                self.stats_mut()
                    .forwarding
                    .record_decode_error(payload.len());
                debug!(error = %e, "Malformed SessionDatagram");
                return PreparedSessionDatagram::Done;
            }
        };

        // TTL enforcement: decrement and drop if exhausted. The TTL
        // value here is post-decrement (saturating sub).
        if datagram_ref.ttl == 0 {
            self.stats_mut()
                .forwarding
                .record_ttl_exhausted(payload.len());
            debug!(
                src = %datagram_ref.src_addr,
                dest = %datagram_ref.dest_addr,
                "SessionDatagram TTL exhausted, dropping"
            );
            return PreparedSessionDatagram::Done;
        }
        let new_ttl = datagram_ref.ttl - 1;

        // Coordinate cache warming from plaintext session-layer headers
        // — works directly on the ref, no allocation.
        {
            let _timer =
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::CoordCacheWarm);
            self.try_warm_coord_cache_ref(&datagram_ref);
        }

        // Local delivery: dispatch to session layer handlers. No alloc,
        // no copy — `handle_session_payload` takes `payload` by borrow.
        if datagram_ref.dest_addr == *self.node_addr() {
            self.stats_mut().forwarding.record_delivered(payload.len());
            self.handle_session_payload(LocalSessionPayload::new(
                datagram_ref.src_addr,
                previous_hop,
                datagram_ref.payload,
            ))
            .await;
            return PreparedSessionDatagram::Done;
        }

        // Find next hop toward destination. Transit forwarding must not send
        // a non-local datagram back to the hop it arrived from; learned
        // reverse routes are observations, not loop-free source routes.
        let next_hop_plan = {
            let _timer =
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::TransitRoute);
            self.plan_transit_next_hop(&datagram_ref.dest_addr, &previous_hop)
        };
        let next_hop_addr = match next_hop_plan {
            TransitNextHopPlan::Route(next_hop_addr) => next_hop_addr,
            plan @ (TransitNextHopPlan::Loop(_) | TransitNextHopPlan::NoRoute) => {
                let loop_failure = match plan {
                    TransitNextHopPlan::Loop(next_hop_addr) => Some(next_hop_addr),
                    _ => None,
                };
                return PreparedSessionDatagram::NoRoute {
                    datagram: owned_session_datagram_from_ref(
                        &datagram_ref,
                        new_ttl,
                        datagram_ref.path_mtu,
                    ),
                    received_len: payload.len(),
                    loop_failure,
                };
            }
        };

        // Apply path_mtu min() from the outgoing link's transport MTU
        let mut path_mtu = datagram_ref.path_mtu;
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            if let Some(addr) = peer.current_addr() {
                path_mtu = path_mtu.min(transport.link_mtu(addr));
            } else {
                path_mtu = path_mtu.min(transport.mtu());
            }
        }

        // ECN CE relay: propagate incoming CE and detect local congestion
        let local_congestion = self.detect_congestion(&next_hop_addr);
        let outgoing_ce = incoming_ce || local_congestion;
        debug!(
            previous_hop = %previous_hop,
            src = %datagram_ref.src_addr,
            dest = %datagram_ref.dest_addr,
            next_hop = %next_hop_addr,
            bytes = payload.len(),
            incoming_ce,
            local_congestion,
            outgoing_ce,
            "Forwarding SessionDatagram"
        );
        if local_congestion {
            self.stats_mut().congestion.record_congestion_detected();
            let now = Instant::now();
            let should_log = self
                .last_congestion_log
                .map(|t| now.duration_since(t) >= Duration::from_secs(5))
                .unwrap_or(true);
            if should_log {
                self.last_congestion_log = Some(now);
                warn!(next_hop = %next_hop_addr, "Congestion detected, CE flag set on forwarded packet");
            }
        }

        PreparedSessionDatagram::Forward(PreparedSessionForwardRoute {
            next_hop_addr,
            src_addr: datagram_ref.src_addr,
            dest_addr: datagram_ref.dest_addr,
            outgoing_ce,
            received_len: payload.len(),
            ttl: new_ttl,
            path_mtu,
        })
    }

    async fn finish_session_datagram_no_route(
        &mut self,
        datagram: SessionDatagram,
        received_len: usize,
        loop_failure: Option<NodeAddr>,
    ) {
        if let Some(next_hop_addr) = loop_failure {
            self.record_route_failure(datagram.dest_addr, next_hop_addr);
        }
        self.stats_mut()
            .forwarding
            .record_drop_no_route(received_len);
        debug!(
            src = %self.peer_display_name(&datagram.src_addr),
            dest = %self.peer_display_name(&datagram.dest_addr),
            bytes = received_len,
            "Dropping transit SessionDatagram: no route to destination"
        );
        self.send_routing_error(&datagram).await;
    }

    async fn finish_prepared_session_forward(
        &mut self,
        forward: PreparedSessionForward,
        result: Result<(), NodeError>,
        record_route_failure: bool,
    ) {
        let PreparedSessionForward {
            next_hop_addr,
            src_addr,
            dest_addr,
            outgoing_ce,
            received_len,
            encoded_len,
            plaintext: _,
        } = forward;
        if let Err(e) = result {
            if record_route_failure {
                self.record_route_failure(dest_addr, next_hop_addr);
            }
            match e {
                NodeError::MtuExceeded { mtu, .. } => {
                    self.stats_mut()
                        .forwarding
                        .record_drop_mtu_exceeded(received_len);
                    let datagram = SessionDatagram::new(src_addr, dest_addr, Vec::new());
                    self.send_mtu_exceeded_error(&datagram, mtu).await;
                }
                _ => {
                    self.stats_mut()
                        .forwarding
                        .record_drop_send_error(received_len);
                    debug!(
                        next_hop = %next_hop_addr,
                        dest = %dest_addr,
                        error = %e,
                        "Failed to forward SessionDatagram"
                    );
                }
            }
        } else {
            self.stats_mut().forwarding.record_forwarded(encoded_len);
            if outgoing_ce {
                self.stats_mut().congestion.record_ce_forwarded();
            }
        }
    }

    /// Attempt to warm the coordinate cache from session-layer payload headers.
    ///
    /// Transit routers parse the 4-byte FSP common prefix to identify message
    /// type, then extract plaintext coordinate fields from:
    /// - SessionSetup (phase 0x1): src_coords + dest_coords
    /// - SessionAck (phase 0x2): src_coords
    /// - Encrypted with CP flag (phase 0x0): cleartext coords between header and ciphertext
    ///
    /// Decode failures are logged and silently ignored — they don't block
    /// forwarding.
    /// Zero-copy coord-cache warming — works directly on a borrowed
    /// [`SessionDatagramRef`] without materialising an owned
    /// `SessionDatagram`. Called on every incoming session datagram on
    /// the hot path.
    fn try_warm_coord_cache_ref(&mut self, datagram: &SessionDatagramRef<'_>) {
        let prefix = match FspCommonPrefix::parse(datagram.payload) {
            Some(p) => p,
            None => return,
        };

        let inner = &datagram.payload[FSP_COMMON_PREFIX_SIZE..];

        let now_ms = Self::now_ms();

        match prefix.phase {
            FSP_PHASE_MSG1 => match SessionSetup::decode(inner) {
                Ok(setup) => {
                    self.coord_cache_mut()
                        .insert(datagram.src_addr, setup.src_coords, now_ms);
                    self.coord_cache_mut()
                        .insert(datagram.dest_addr, setup.dest_coords, now_ms);
                    debug!(
                        src = %datagram.src_addr,
                        dest = %datagram.dest_addr,
                        "Cached coords from SessionSetup"
                    );
                }
                Err(e) => {
                    debug!(error = %e, "Failed to decode SessionSetup for cache warming");
                }
            },
            FSP_PHASE_MSG2 => match SessionAck::decode(inner) {
                Ok(ack) => {
                    self.coord_cache_mut()
                        .insert(datagram.src_addr, ack.src_coords, now_ms);
                    self.coord_cache_mut()
                        .insert(datagram.dest_addr, ack.dest_coords, now_ms);
                    debug!(
                        src = %datagram.src_addr,
                        dest = %datagram.dest_addr,
                        "Cached coords from SessionAck"
                    );
                }
                Err(e) => {
                    debug!(error = %e, "Failed to decode SessionAck for cache warming");
                }
            },
            FSP_PHASE_ESTABLISHED if prefix.has_coords() => {
                // CP flag set: coords in cleartext between header and ciphertext.
                // Parse coords from the cleartext section after the 12-byte header.
                // inner starts after the 4-byte prefix, so we need 8 more bytes
                // for the counter (header is 12 total = 4 prefix + 8 counter).
                let coord_data = &datagram.payload[FSP_HEADER_SIZE..];
                match parse_encrypted_coords(coord_data) {
                    Ok((src_coords, dest_coords, _bytes_consumed)) => {
                        if let Some(coords) = src_coords {
                            self.coord_cache_mut()
                                .insert(datagram.src_addr, coords, now_ms);
                        }
                        if let Some(coords) = dest_coords {
                            self.coord_cache_mut()
                                .insert(datagram.dest_addr, coords, now_ms);
                        }
                        debug!(
                            src = %datagram.src_addr,
                            dest = %datagram.dest_addr,
                            "Cached coords from encrypted message"
                        );
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to parse coords for cache warming");
                    }
                }
            }
            _ => {
                // Phase 0x0 without CP, error signals, unknown: no coords to cache
            }
        }
    }

    /// Generate and send a routing error signal back to the datagram's source.
    ///
    /// If we have cached coords for the destination, send PathBroken (we know
    /// where it is but can't reach it). Otherwise send CoordsRequired (we
    /// don't know where it is).
    ///
    /// If we can't route the error back to the source either, drop silently.
    /// No cascading errors.
    async fn send_routing_error(&mut self, original: &SessionDatagram) {
        // Rate limit: one error signal per destination per 100ms
        if !self
            .routing_error_rate_limiter
            .should_send(&original.dest_addr)
        {
            return;
        }

        let my_addr = *self.node_addr();

        let now_ms = Self::now_ms();

        let error_payload =
            if let Some(coords) = self.coord_cache().get(&original.dest_addr, now_ms) {
                let coords = coords.clone();
                PathBroken::new(original.dest_addr, my_addr)
                    .with_last_coords(coords)
                    .encode()
            } else {
                CoordsRequired::new(original.dest_addr, my_addr).encode()
            };

        let error_dg = SessionDatagram::new(my_addr, original.src_addr, error_payload)
            .with_ttl(self.config.node.session.default_ttl);

        let next_hop_addr = match self.find_next_hop(&original.src_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                debug!(
                    src = %original.src_addr,
                    dest = %original.dest_addr,
                    "Cannot route error signal back to source, dropping"
                );
                return;
            }
        };

        let encoded = error_dg.encode();
        if let Err(e) = self
            .send_dataplane_fmp_link_plaintext(&next_hop_addr, &encoded, false)
            .await
        {
            debug!(
                next_hop = %next_hop_addr,
                error = %e,
                "Failed to send routing error signal"
            );
        } else {
            debug!(
                original_dest = %original.dest_addr,
                error_dest = %original.src_addr,
                "Sent routing error signal"
            );
        }
    }

    /// Generate and send an MtuExceeded error signal back to the datagram's source.
    ///
    /// Called when dataplane FMP-link output fails with
    /// `NodeError::MtuExceeded` during forwarding. The signal tells the
    /// source the bottleneck MTU so it can immediately reduce its path MTU.
    async fn send_mtu_exceeded_error(&mut self, original: &SessionDatagram, bottleneck_mtu: u16) {
        // Rate limit: reuse routing_error_rate_limiter keyed on dest_addr
        if !self
            .routing_error_rate_limiter
            .should_send(&original.dest_addr)
        {
            return;
        }

        let my_addr = *self.node_addr();

        let error_payload = MtuExceeded::new(original.dest_addr, my_addr, bottleneck_mtu).encode();

        let error_dg = SessionDatagram::new(my_addr, original.src_addr, error_payload)
            .with_ttl(self.config.node.session.default_ttl);

        let next_hop_addr = match self.find_next_hop(&original.src_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                debug!(
                    src = %original.src_addr,
                    dest = %original.dest_addr,
                    "Cannot route MtuExceeded signal back to source, dropping"
                );
                return;
            }
        };

        let encoded = error_dg.encode();
        if let Err(e) = self
            .send_dataplane_fmp_link_plaintext(&next_hop_addr, &encoded, false)
            .await
        {
            debug!(
                next_hop = %next_hop_addr,
                error = %e,
                "Failed to send MtuExceeded error signal"
            );
        } else {
            debug!(
                original_dest = %original.dest_addr,
                error_dest = %original.src_addr,
                bottleneck_mtu,
                "Sent MtuExceeded error signal"
            );
        }
    }

    /// Detect congestion for CE marking on forwarded datagrams.
    ///
    /// Checks two signal sources:
    /// 1. Outgoing link MMP metrics (loss rate, ETX) against configured thresholds
    /// 2. Local transport congestion (kernel drops on any transport)
    ///
    /// Returns `true` if any signal indicates congestion.
    pub(in crate::node) fn detect_congestion(&self, next_hop: &NodeAddr) -> bool {
        if !self.config.node.ecn.enabled {
            return false;
        }
        // Outgoing link MMP metrics
        if let Some(metrics) = self
            .dataplane
            .fmp_link_metrics(next_hop, std::time::Instant::now())
            && (metrics.loss_rate >= self.config.node.ecn.loss_threshold
                || metrics.etx >= self.config.node.ecn.etx_threshold)
        {
            return true;
        }
        // Local transport congestion (kernel drops)
        self.transport_drops.any_dropping()
    }

    /// Sample transport congestion indicators.
    ///
    /// Called from the tick handler (1s interval). For each transport,
    /// queries the cumulative kernel drop counter and sets the `dropping`
    /// flag if new drops occurred since the previous sample.
    pub(in crate::node) fn sample_transport_congestion(&mut self) {
        let mut new_drop_events = Vec::new();
        for (&tid, transport) in &self.transports {
            let congestion = transport.congestion();
            let drop_delta = self.transport_drops.sample(tid, congestion.recv_drops);
            let socket_drop_delta = self
                .transport_socket_drops
                .sample(tid, congestion.socket_recv_drops);
            let namespace_drop_delta = self
                .transport_namespace_drops
                .sample(tid, congestion.namespace_recv_drops);
            if drop_delta.is_some() || socket_drop_delta.is_some() || namespace_drop_delta.is_some()
            {
                new_drop_events.push((
                    tid,
                    drop_delta.unwrap_or(0),
                    socket_drop_delta.unwrap_or(0),
                    namespace_drop_delta.unwrap_or(0),
                ));
            }
        }
        for (tid, drop_delta, socket_drop_delta, namespace_drop_delta) in new_drop_events {
            if drop_delta > 0 {
                self.stats_mut().congestion.record_kernel_drop_event();
                crate::perf_profile::record_udp_kernel_drops(drop_delta);
            }
            crate::perf_profile::record_udp_socket_kernel_drops(socket_drop_delta);
            crate::perf_profile::record_udp_namespace_rcvbuf_errors(namespace_drop_delta);
            warn!(
                transport_id = tid.as_u32(),
                drops = drop_delta,
                socket_drops = socket_drop_delta,
                namespace_rcvbuf_errors = namespace_drop_delta,
                "Kernel recv drops observed on transport"
            );
        }
    }
}

impl PreparedSessionForwardRoute {
    fn with_plaintext(self, plaintext: PacketBuffer) -> PreparedSessionForward {
        let encoded_len = plaintext.len();
        PreparedSessionForward {
            next_hop_addr: self.next_hop_addr,
            src_addr: self.src_addr,
            dest_addr: self.dest_addr,
            outgoing_ce: self.outgoing_ce,
            received_len: self.received_len,
            encoded_len,
            plaintext,
        }
    }
}

include!("forwarding_helpers.rs");

#[cfg(test)]
mod forwarding_fast_path_tests {
    use super::*;
    include!("forwarding_deferred_tests.rs");

    #[test]
    fn borrowed_forward_encoder_matches_owned_session_datagram_encode() {
        let src = NodeAddr::from_bytes([0x11; 16]);
        let dest = NodeAddr::from_bytes([0x22; 16]);
        let datagram = SessionDatagram::new(src, dest, vec![1, 2, 3, 4, 5])
            .with_ttl(12)
            .with_path_mtu(1400);
        let encoded = datagram.encode();
        let decoded = SessionDatagramRef::decode(&encoded[1..]).expect("decode datagram");

        let forwarded_ttl = 11;
        let forwarded_mtu = 1280;
        let borrowed = copy_forwarded_session_datagram(&encoded[1..], forwarded_ttl, forwarded_mtu);
        let owned = SessionDatagram {
            src_addr: decoded.src_addr,
            dest_addr: decoded.dest_addr,
            ttl: forwarded_ttl,
            path_mtu: forwarded_mtu,
            payload: decoded.payload.to_vec(),
        }
        .encode();

        assert_eq!(borrowed, owned);
    }

    #[test]
    fn owned_forward_rewrite_preserves_packet_allocation_and_payload() {
        let datagram = SessionDatagram::new(
            NodeAddr::from_bytes([0x33; 16]),
            NodeAddr::from_bytes([0x44; 16]),
            vec![9, 8, 7, 6, 5],
        )
        .with_ttl(20)
        .with_path_mtu(1450);
        let mut plaintext = PacketBuffer::new(datagram.encode());
        let allocation = plaintext.as_slice().as_ptr();

        assert!(rewrite_forwarded_session_datagram(&mut plaintext, 19, 1280));
        assert_eq!(plaintext.as_slice().as_ptr(), allocation);

        let decoded = SessionDatagramRef::decode(&plaintext.as_slice()[1..]).expect("decode");
        assert_eq!(decoded.ttl, 19);
        assert_eq!(decoded.path_mtu, 1280);
        assert_eq!(decoded.src_addr, datagram.src_addr);
        assert_eq!(decoded.dest_addr, datagram.dest_addr);
        assert_eq!(decoded.payload, datagram.payload);
    }

    #[test]
    fn route_failure_is_claimed_once_per_pair_and_flush() {
        let dest = NodeAddr::from_bytes([0x11; 16]);
        let next_hop = NodeAddr::from_bytes([0x22; 16]);
        let other_hop = NodeAddr::from_bytes([0x33; 16]);
        let mut failed_routes = std::collections::HashSet::new();

        assert!(claim_route_failure_once(
            &mut failed_routes,
            dest,
            next_hop,
            true
        ));
        assert!(!claim_route_failure_once(
            &mut failed_routes,
            dest,
            next_hop,
            true
        ));
        assert!(!claim_route_failure_once(
            &mut failed_routes,
            dest,
            next_hop,
            false
        ));
        assert!(claim_route_failure_once(
            &mut failed_routes,
            dest,
            other_hop,
            true
        ));

        let mut next_flush = std::collections::HashSet::new();
        assert!(claim_route_failure_once(
            &mut next_flush,
            dest,
            next_hop,
            true
        ));
    }

    #[test]
    fn forwarding_submission_window_pipelines_four_transport_batches() {
        let limit = forwarding_submission_limit(64);
        assert_eq!(limit, 256);
        assert!(!forward_run_reached_limit(255, limit));
        assert!(forward_run_reached_limit(256, limit));

        let minimum = forwarding_submission_limit(0);
        assert_eq!(minimum, 4);
        assert!(forward_run_reached_limit(4, minimum));
        assert_eq!(forwarding_submission_limit(usize::MAX), 256);
    }

    #[test]
    fn only_valid_nonlocal_datagrams_are_transit_candidates() {
        let node = Node::new(crate::Config::new()).expect("test node");
        let peer_identity_full = fips_identity::Identity::generate();
        let previous_hop = crate::PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
        let source = *previous_hop.node_addr();

        let local = SessionDatagram::new(source, *node.node_addr(), vec![1, 2, 3]).encode();
        let local = AuthenticatedSessionDatagram::new(previous_hop, &local[1..], false);
        assert!(!node.session_datagram_is_transit_candidate(&local));

        let unknown_dest = NodeAddr::from_bytes([0x55; 16]);
        let no_route = SessionDatagram::new(source, unknown_dest, vec![4, 5, 6]).encode();
        let no_route = AuthenticatedSessionDatagram::new(previous_hop, &no_route[1..], false);
        assert!(node.session_datagram_is_transit_candidate(&no_route));

        let ttl_zero = SessionDatagram::new(source, unknown_dest, vec![7, 8, 9])
            .with_ttl(0)
            .encode();
        let ttl_zero = AuthenticatedSessionDatagram::new(previous_hop, &ttl_zero[1..], false);
        assert!(!node.session_datagram_is_transit_candidate(&ttl_zero));
    }

    #[tokio::test]
    async fn no_route_drop_action_is_deferred_until_after_planning() {
        let mut node = Node::new(crate::Config::new()).expect("test node");
        let peer_identity_full = fips_identity::Identity::generate();
        let previous_hop = crate::PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
        let source = *previous_hop.node_addr();
        let unknown_dest = NodeAddr::from_bytes([0x66; 16]);
        let encoded = SessionDatagram::new(source, unknown_dest, vec![1, 2, 3]).encode();
        let datagram = AuthenticatedSessionDatagram::new(previous_hop, &encoded[1..], false);

        let PreparedSessionDatagram::NoRoute {
            datagram,
            received_len,
            loop_failure,
        } = node.prepare_session_datagram(datagram).await
        else {
            panic!("unknown destination should produce deferred no-route action");
        };
        assert_eq!(node.stats().forwarding.received_packets, 1);
        assert_eq!(node.stats().forwarding.drop_no_route_packets, 0);

        node.finish_session_datagram_no_route(datagram, received_len, loop_failure)
            .await;
        assert_eq!(node.stats().forwarding.drop_no_route_packets, 1);
    }
}
