use super::endpoint_traffic::classify_fmp_plaintext_traffic;
use super::*;
use crate::packet_mover2::{
    ActivityTick, OutboundPacket, OutboundPostSeal, OutputTarget, OwnerConfig, OwnerCryptoKeys,
    OwnerId, PacketClass, PacketMover2EndpointCommandRoute, PacketMover2FspWrapRoute,
    PacketMover2IngressRoute, PacketMover2LiveEndpointRoute, PacketMover2LiveFmpIngressRoute,
    PacketMover2LiveFspIngressRoute, PacketMover2LiveNodeTurn, PacketMover2LiveOutboundFirsts,
    PacketMover2LiveOwnerRoutes, PacketMover2LiveTunRoute, PacketMover2OutputDrop,
    PacketMover2OutputError, PacketMover2TunDestinationRoute, PacketMover2TunOutboundRoute,
    TransportPath,
};
use crate::protocol::SessionMessageType;

const PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS: usize = 2;
const PACKET_MOVER2_PENDING_OUTBOUND_COMPLETION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);
const PACKET_MOVER2_DEFAULT_OWNER_BULK_IN_FLIGHT_LIMIT: usize = 64;
const PACKET_MOVER2_DEFAULT_OWNER_RELIABLE_BULK_IN_FLIGHT_LIMIT: usize = 64;

struct PacketMover2FmpOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    path: TransportPath,
    routes: PacketMover2LiveOwnerRoutes,
}

struct PacketMover2FspOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    routes: PacketMover2LiveOwnerRoutes,
    next_hop: Option<NodeAddr>,
}

impl Node {
    pub(in crate::node) async fn send_packet_mover2_fmp_link_plaintext(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        if !self.sync_packet_mover2_fmp_owner(node_addr) {
            return if self.peers.get(node_addr).is_none() {
                Err(NodeError::PeerNotFound(*node_addr))
            } else {
                Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: "packet_mover2 FMP owner unavailable".into(),
                })
            };
        }

        let (receiver_idx, mut flags, generation) = {
            let peer = self
                .peers
                .get(node_addr)
                .ok_or(NodeError::PeerNotFound(*node_addr))?;
            let receiver_idx = peer.their_index().ok_or_else(|| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "no their_index".into(),
            })?;
            let mut flags = if peer.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()) {
                FLAG_SP
            } else {
                0
            };
            if peer.current_k_bit() {
                flags |= FLAG_KEY_EPOCH;
            }
            (receiver_idx.as_u32(), flags, peer.session_generation())
        };
        if ce_flag {
            flags |= FLAG_CE;
        }

        let outbound = OutboundPacket::fmp(
            OwnerId::fmp_node(*node_addr),
            generation,
            packet_mover2_fmp_link_class(plaintext),
            receiver_idx,
            flags,
            plaintext.to_vec(),
        )
        .with_activity_tick(ActivityTick::new(Self::now_ms()));
        let mut turn = self
            .pump_packet_mover2_initial_outbound(outbound, 1, true)
            .await;
        for continuation in 0..=PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS {
            if turn.transport_sent() == 1 && turn.transport_dropped() == 0 {
                let mut sent_outputs = turn.take_transport_sent_outputs();
                if sent_outputs.len() != 1 {
                    return Err(NodeError::SendFailed {
                        node_addr: *node_addr,
                        reason: format!(
                            "packet_mover2 FMP send transport receipt mismatch: {:?}",
                            turn.summary()
                        ),
                    });
                }
                let output = sent_outputs.pop().expect("checked one sent output");
                let timestamp_ms =
                    output
                        .fmp_timestamp_ms()
                        .ok_or_else(|| NodeError::SendFailed {
                            node_addr: *node_addr,
                            reason: "packet_mover2 FMP timestamp missing".into(),
                        })?;
                let bytes_sent = output.payload_len();
                let _ = self.peers.record_fmp_send_bookkeeping(
                    node_addr,
                    output.counter(),
                    timestamp_ms,
                    bytes_sent,
                );
                let send_result: Result<usize, TransportError> = Ok(bytes_sent);
                self.note_local_send_outcome(node_addr, &send_result);
                return Ok(());
            }

            if turn.transport_sent() > 0 || turn.summary().outputs_sent() > 0 {
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!(
                        "packet_mover2 FMP send unexpected output shape: {:?}",
                        turn.summary()
                    ),
                });
            }
            if let Some(drop) = turn.output_drops().first() {
                return Err(self.packet_mover2_fmp_output_drop_error(*node_addr, drop));
            }
            if let Some(drop) = turn.drops().first() {
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("packet_mover2 FMP send drop: {:?}", drop.reason()),
                });
            }

            let summary = turn.summary();
            let deferred = turn.endpoint_deferred_commands() > 0;
            let needs_continuation = Self::packet_mover2_pending_outbound_needs_continuation(&turn);
            if deferred || !needs_continuation {
                let reason = if deferred {
                    "deferred without transport output"
                } else {
                    "made no transport output progress"
                };
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("packet_mover2 FMP send {reason}: {:?}", summary),
                });
            }
            if continuation == PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS {
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!(
                        "packet_mover2 FMP send exhausted pending outbound continuation turns: {:?}",
                        summary
                    ),
                });
            }

            if needs_continuation && summary.outputs() == 0 {
                self.wait_for_packet_mover2_completion().await;
            }
            turn = self
                .pump_packet_mover2_pending_outbound_firsts(
                    PacketMover2LiveOutboundFirsts::default()
                        .with_transport_sent_output_collection(true),
                    0,
                    0,
                    1,
                )
                .await;
        }

        unreachable!("bounded FMP outbound continuation loop must return")
    }

    pub(in crate::node) async fn send_packet_mover2_pending_tun_packet(
        &mut self,
        dest_addr: &NodeAddr,
        packet: Vec<u8>,
    ) -> Result<(), NodeError> {
        if !self.sync_packet_mover2_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "packet_mover2 FSP owner unavailable for queued TUN packet".into(),
            });
        }

        let turn = self
            .pump_packet_mover2_pending_outbound_firsts(
                PacketMover2LiveOutboundFirsts::default().with_tun_packet(Some(packet)),
                0,
                1,
                1,
            )
            .await;
        self.finish_packet_mover2_pending_outbound_turn(dest_addr, "queued TUN packet", turn)
            .await
            .map(|_| ())
    }

    pub(in crate::node) async fn send_packet_mover2_pending_endpoint_payloads(
        &mut self,
        dest_addr: &NodeAddr,
        payloads: Vec<EndpointDataPayload>,
        lane: EndpointCommandLane,
        enqueued_at_ms: u64,
    ) -> Result<(), NodeError> {
        if payloads.is_empty() {
            return Ok(());
        }
        debug_assert!(payloads.iter().all(|payload| payload.lane() == lane));
        if !self.sync_packet_mover2_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "packet_mover2 FSP owner unavailable for queued endpoint data".into(),
            });
        }
        let Some(remote) = self.packet_mover2_peer_identity(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "packet_mover2 endpoint identity unavailable for queued endpoint data"
                    .into(),
            });
        };

        let payload_count = payloads.len();
        let command = if payload_count == 1 {
            let payload = payloads
                .into_iter()
                .next()
                .expect("checked pending endpoint payload");
            NodeEndpointCommand::send_payload_oneway_with_enqueued_at_ms(
                remote,
                payload,
                None,
                enqueued_at_ms,
            )
        } else {
            NodeEndpointCommand::send_batch_oneway_with_enqueued_at_ms(
                remote,
                payloads,
                None,
                lane,
                enqueued_at_ms,
            )
            .expect("checked pending endpoint payload batch")
        };
        let firsts = match lane {
            EndpointCommandLane::Priority => {
                PacketMover2LiveOutboundFirsts::default().with_endpoint_priority(Some(command))
            }
            EndpointCommandLane::Bulk => {
                PacketMover2LiveOutboundFirsts::default().with_endpoint_bulk(Some(command))
            }
        };
        let turn = self
            .pump_packet_mover2_pending_outbound_firsts(firsts, payload_count, 0, payload_count)
            .await;
        self.finish_packet_mover2_pending_outbound_turn(dest_addr, "queued endpoint data", turn)
            .await
            .map(|_| ())
    }

    pub(in crate::node) async fn send_packet_mover2_fsp_session_msg(
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
        self.send_packet_mover2_fsp_control_outbound(
            dest_addr,
            msg_type,
            send_context.fsp_flags(false),
            send_context.inner_flags_byte(),
            payload,
            None,
            now_ms,
            send_context.timestamp,
            "FSP control message",
        )
        .await
    }

    pub(in crate::node) async fn send_packet_mover2_fsp_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let coords_prefix = self.packet_mover2_fsp_coords_prefix_for_dest(dest_addr);
        self.send_packet_mover2_fsp_control_outbound(
            dest_addr,
            SessionMessageType::CoordsWarmup.to_byte(),
            crate::node::session_wire::FSP_FLAG_CP,
            send_context.inner_flags_byte(),
            &[],
            Some(coords_prefix),
            now_ms,
            send_context.timestamp,
            "FSP coords warmup",
        )
        .await
    }

    async fn pump_packet_mover2_pending_outbound_firsts(
        &mut self,
        firsts: PacketMover2LiveOutboundFirsts,
        endpoint_limit: usize,
        tun_limit: usize,
        crypto_limit: usize,
    ) -> PacketMover2LiveNodeTurn {
        let tun_tx = self.tun_tx.clone().unwrap_or_else(|| {
            let (tx, rx) = crate::upper::tun::write_channel();
            drop(rx);
            tx
        });
        let endpoint_tx = self.endpoint_events.sender().unwrap_or_else(|| {
            let (tx, rx) = EndpointEventSender::channel(1);
            drop(rx);
            tx
        });
        let sessions = &self.sessions;
        let identity_cache = &self.identity_cache;
        let endpoint_resolver = |source_addr: &NodeAddr| {
            Self::packet_mover2_endpoint_peer_from_stores(sessions, identity_cache, source_addr)
        };

        let turn = self
            .packet_mover2
            .pump_outbound_firsts(
                firsts,
                endpoint_limit,
                tun_limit,
                &tun_tx,
                &endpoint_tx,
                endpoint_resolver,
                &self.transports,
                crypto_limit,
            )
            .await;
        Self::observe_packet_mover2_turn(&turn);
        turn
    }

    async fn pump_packet_mover2_initial_outbound(
        &mut self,
        outbound: OutboundPacket,
        crypto_limit: usize,
        collect_transport_sent_outputs: bool,
    ) -> PacketMover2LiveNodeTurn {
        let firsts = PacketMover2LiveOutboundFirsts::default()
            .with_initial_outbound(Some(outbound))
            .with_transport_sent_output_collection(collect_transport_sent_outputs);
        let turn = self
            .pump_packet_mover2_pending_outbound_firsts(firsts, 0, 0, crypto_limit)
            .await;
        turn
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_packet_mover2_fsp_control_outbound(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        fsp_flags: u8,
        inner_flags: u8,
        payload: &[u8],
        coords_prefix: Option<Vec<u8>>,
        now_ms: u64,
        timestamp: u32,
        label: &str,
    ) -> Result<(), NodeError> {
        if !self.sync_packet_mover2_fsp_owner_preserving_coords_warmup(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP owner unavailable for {label}"),
            });
        }
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP wrap route unavailable for {label}"),
            });
        };
        let Some(generation) = self.packet_mover2_fsp_generation(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP generation unavailable for {label}"),
            });
        };
        let coords_prefix_len = coords_prefix.as_ref().map_or(0, Vec::len);

        let mut outbound = OutboundPacket::fsp(
            OwnerId::fsp_node(*dest_addr),
            generation,
            packet_mover2_fsp_control_class(msg_type),
            fsp_flags,
            payload.to_vec(),
        )
        .with_fsp_inner_header(msg_type, inner_flags)
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap))
        .with_activity_tick(ActivityTick::new(now_ms));
        if let Some(prefix) = coords_prefix {
            outbound = outbound.with_fsp_cleartext_prefix(prefix);
        } else {
            outbound = outbound.without_fsp_auto_coords_warmup();
        }

        let turn = self
            .pump_packet_mover2_initial_outbound(outbound, 2, false)
            .await;
        let mut turn = match self
            .finish_packet_mover2_pending_outbound_turn(dest_addr, label, turn)
            .await
        {
            Ok(turn) => turn,
            Err(error) => {
                self.record_route_failure(*dest_addr, next_hop);
                self.recover_direct_payload_send_failure(*dest_addr, next_hop, &error);
                return Err(error);
            }
        };
        let Some(counter) = Self::packet_mover2_wrapped_fsp_counter(&mut turn, *dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP receipt unavailable for {label}"),
            });
        };
        let frame_bytes = crate::node::session_wire::FSP_INNER_HEADER_SIZE
            .saturating_add(payload.len())
            .saturating_add(crate::noise::TAG_SIZE);
        let datagram_bytes = crate::protocol::SESSION_DATAGRAM_HEADER_SIZE
            .saturating_add(crate::node::session_wire::FSP_HEADER_SIZE)
            .saturating_add(coords_prefix_len)
            .saturating_add(frame_bytes);
        let _ = self.sessions.record_fsp_send_bookkeeping(
            dest_addr,
            FspSendBookkeepingInput::control(counter, timestamp, frame_bytes),
        );
        self.sessions
            .record_session_datagram_next_hop(dest_addr, next_hop);
        self.stats_mut()
            .forwarding
            .record_originated(datagram_bytes);
        Ok(())
    }

    async fn finish_packet_mover2_pending_outbound_turn(
        &mut self,
        dest_addr: &NodeAddr,
        label: &str,
        mut turn: PacketMover2LiveNodeTurn,
    ) -> Result<PacketMover2LiveNodeTurn, NodeError> {
        let mut wrapped_outbound_receipts = Vec::new();
        for continuation in 0..=PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS {
            wrapped_outbound_receipts.extend(turn.take_wrapped_outbound_receipts());
            let summary = turn.summary();
            let sent = Self::packet_mover2_pending_outbound_sent(&turn);
            let deferred = turn.endpoint_deferred_commands() > 0 || turn.tun_deferred_packets() > 0;
            let failed = turn.has_failures();
            let needs_continuation = Self::packet_mover2_pending_outbound_needs_continuation(&turn);

            self.process_packet_mover2_pending_outbound_bookkeeping(&mut turn)
                .await;

            if failed {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: Self::packet_mover2_pending_outbound_failure(label, &turn),
                });
            }
            if sent {
                turn.extend_wrapped_outbound_receipts(wrapped_outbound_receipts);
                return Ok(turn);
            }
            if deferred || !needs_continuation {
                let reason = if deferred {
                    "deferred without transport output"
                } else {
                    "made no transport output progress"
                };
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("packet_mover2 {label} {reason}: {:?}", summary),
                });
            }
            if continuation == PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!(
                        "packet_mover2 {label} exhausted pending outbound continuation turns: {:?}",
                        summary
                    ),
                });
            }

            if needs_continuation && summary.outputs() == 0 {
                self.wait_for_packet_mover2_completion().await;
            }
            turn = self
                .pump_packet_mover2_pending_outbound_firsts(
                    PacketMover2LiveOutboundFirsts::default(),
                    0,
                    0,
                    1,
                )
                .await;
        }

        unreachable!("bounded pending outbound continuation loop must return")
    }

    async fn wait_for_packet_mover2_completion(&self) {
        let notify = self.packet_mover2.completion_notify();
        let _ = tokio::time::timeout(
            PACKET_MOVER2_PENDING_OUTBOUND_COMPLETION_TIMEOUT,
            notify.notified(),
        )
        .await;
    }

    fn packet_mover2_wrapped_fsp_counter(
        turn: &mut PacketMover2LiveNodeTurn,
        dest_addr: NodeAddr,
    ) -> Option<u64> {
        let owner = OwnerId::fsp_node(dest_addr);
        let mut counter = None;
        for receipt in turn.take_wrapped_outbound_receipts() {
            if receipt.owner() == owner {
                counter = Some(receipt.counter());
            }
        }
        counter
    }

    fn packet_mover2_pending_outbound_sent(turn: &PacketMover2LiveNodeTurn) -> bool {
        turn.transport_sent() > 0 || turn.summary().outputs_sent() > 0
    }

    fn packet_mover2_pending_outbound_needs_continuation(turn: &PacketMover2LiveNodeTurn) -> bool {
        let summary = turn.summary();
        summary.outbound_admitted() > summary.dispatched()
            || (summary.outbound_admitted() > 0 && summary.outputs() == 0)
    }

    fn packet_mover2_pending_outbound_failure(
        label: &str,
        turn: &PacketMover2LiveNodeTurn,
    ) -> String {
        let summary = turn.summary();
        if let Some(drop) = turn.tun_outbound_drops().first() {
            return format!(
                "packet_mover2 {label} TUN route drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        if let Some(drop) = turn.endpoint_command_drops().first() {
            return format!(
                "packet_mover2 {label} endpoint route drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        if let Some(drop) = turn.output_drops().first() {
            return format!(
                "packet_mover2 {label} output drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        if let Some(drop) = turn.drops().first() {
            return format!(
                "packet_mover2 {label} packet drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        format!("packet_mover2 {label} failed: {summary:?}")
    }

    async fn process_packet_mover2_pending_outbound_bookkeeping(
        &mut self,
        turn: &mut PacketMover2LiveNodeTurn,
    ) -> usize {
        let mut processed = 0usize;
        for routed in turn.take_endpoint_routed_destinations() {
            if self.sessions.record_packet_mover2_endpoint_routed(routed) {
                processed += 1;
            }
        }
        // Pending flush callers already own the packet they are trying to send.
        // If PM2 defers it again, drain it here and let the caller queue/recover.
        for _packet in self.packet_mover2.take_deferred_tun_packets() {
            processed += 1;
        }
        for command in self.packet_mover2.take_deferred_endpoint_commands() {
            self.handle_packet_mover2_deferred_endpoint_command(command)
                .await;
            processed += 1;
        }
        processed
    }

    pub(in crate::node) fn sync_packet_mover2_fmp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        let Some(seed) = self.packet_mover2_fmp_owner_seed(node_addr) else {
            self.remove_packet_mover2_fmp_owner(node_addr);
            return false;
        };

        self.packet_mover2
            .register_owner_if_missing(seed.owner, seed.config.clone());
        self.packet_mover2
            .apply_owner_live_config(seed.owner, seed.config)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_crypto_keys(seed.owner, seed.keys)
                .is_ok()
            && self
                .packet_mover2
                .set_owner_active_path(seed.owner, seed.path)
                .is_ok()
            && self
                .packet_mover2
                .replace_owner_routes(seed.owner, seed.routes)
                .is_ok()
    }

    pub(in crate::node) fn remove_packet_mover2_fmp_owner(&mut self, node_addr: &NodeAddr) {
        self.packet_mover2
            .unregister_owner(OwnerId::fmp_node(*node_addr));
    }

    pub(in crate::node) fn sync_packet_mover2_fsp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        self.sync_packet_mover2_fsp_owner_with_coords_transfer(node_addr, true)
    }

    fn sync_packet_mover2_fsp_owner_preserving_coords_warmup(
        &mut self,
        node_addr: &NodeAddr,
    ) -> bool {
        self.sync_packet_mover2_fsp_owner_with_coords_transfer(node_addr, false)
    }

    fn sync_packet_mover2_fsp_owner_with_coords_transfer(
        &mut self,
        node_addr: &NodeAddr,
        transfer_coords_warmup: bool,
    ) -> bool {
        let Some(seed) = self.packet_mover2_fsp_owner_seed(node_addr, transfer_coords_warmup)
        else {
            self.remove_packet_mover2_fsp_owner(node_addr);
            return false;
        };

        self.packet_mover2
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let next_hop_ready = seed
            .next_hop
            .is_none_or(|next_hop| self.sync_packet_mover2_fmp_owner(&next_hop));
        self.packet_mover2
            .apply_owner_live_config(seed.owner, seed.config)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_crypto_keys(seed.owner, seed.keys)
                .is_ok()
            && self
                .packet_mover2
                .replace_owner_routes(seed.owner, seed.routes)
                .is_ok()
            && next_hop_ready
    }

    pub(in crate::node) fn remove_packet_mover2_fsp_owner(&mut self, node_addr: &NodeAddr) {
        self.packet_mover2
            .unregister_owner(OwnerId::fsp_node(*node_addr));
    }

    pub(in crate::node) fn sync_packet_mover2_established_fsp_owners(&mut self) {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2FspOwnerSync);
        crate::perf_profile::record_event(crate::perf_profile::Event::PacketMover2FspOwnerSyncCall);
        let established: Vec<NodeAddr> = self
            .sessions
            .iter()
            .filter_map(|(node_addr, session)| session.is_established().then_some(*node_addr))
            .collect();
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::PacketMover2FspOwnerSyncEstablished,
            established.len() as u64,
        );
        let mut applied = 0u64;
        for node_addr in established {
            if self.sync_packet_mover2_fsp_owner(&node_addr) {
                applied += 1;
            }
        }
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::PacketMover2FspOwnerSyncApplied,
            applied,
        );
    }

    fn packet_mover2_fmp_owner_seed(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FmpOwnerSeed> {
        let peer = self.peers.get(node_addr)?;
        let session = peer.noise_session()?;
        let transport_id = peer.transport_id()?;
        let remote_addr = peer.current_addr()?.clone();
        let receiver_idx = peer.our_index()?.as_u32();
        let generation = peer.session_generation();
        let session_start_ms = Self::now_ms().wrapping_sub(u64::from(peer.session_elapsed_ms()));
        let open = Arc::new(session.recv_cipher_clone()?);
        let seal = Arc::new(session.send_cipher_clone()?);
        let counter_authority = session.send_counter_authority();
        let mut routes = PacketMover2LiveOwnerRoutes::new();
        routes.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_id,
            receiver_idx,
            PacketMover2IngressRoute::new(
                OwnerId::fmp_node(*node_addr),
                generation,
                OutputTarget::SessionIngress {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));

        Some(PacketMover2FmpOwnerSeed {
            owner: OwnerId::fmp_node(*node_addr),
            config: self
                .packet_mover2_owner_config(generation)
                .with_send_counter_authority(counter_authority)
                .with_fmp_session_start_ms(session_start_ms),
            keys: OwnerCryptoKeys::new(open, seal),
            path: TransportPath::live(transport_id, remote_addr),
            routes,
        })
    }

    fn packet_mover2_fsp_owner_seed(
        &mut self,
        node_addr: &NodeAddr,
        transfer_coords_warmup: bool,
    ) -> Option<PacketMover2FspOwnerSeed> {
        let (
            open,
            seal,
            counter_authority,
            session_start_ms,
            fsp_flags,
            inner_flags,
            coords_warmup_remaining,
        ) = {
            let session = self.sessions.get(node_addr)?;
            let (open, seal) = session.fsp_crypto_keys()?;
            let counter_authority = session.send_counter_authority()?;
            let mut fsp_flags = 0;
            if session.current_k_bit() {
                fsp_flags |= crate::node::session_wire::FSP_FLAG_K;
            }
            let inner_flags = crate::protocol::FspInnerFlags {
                spin_bit: session.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()),
            }
            .to_byte();
            (
                open,
                seal,
                counter_authority,
                session.session_start_ms(),
                fsp_flags,
                inner_flags,
                session.coords_warmup_remaining(),
            )
        };
        let generation = Self::packet_mover2_generation_from_session_start_ms(session_start_ms);
        let coords_warmup_remaining = if transfer_coords_warmup {
            coords_warmup_remaining
        } else {
            0
        };
        let coords_prefix =
            self.packet_mover2_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        if transfer_coords_warmup
            && coords_warmup_remaining > 0
            && !coords_prefix.is_empty()
            && let Some(session) = self.sessions.get_mut(node_addr)
        {
            session.set_coords_warmup_remaining(0);
        }
        let (routes, next_hop) =
            self.packet_mover2_fsp_owner_routes(node_addr, generation, fsp_flags, inner_flags);

        let mut config = self
            .packet_mover2_owner_config(generation)
            .with_send_counter_authority(counter_authority)
            .with_fsp_session_start_ms(session_start_ms);
        if coords_warmup_remaining > 0 {
            config = config.with_fsp_coords_warmup(coords_warmup_remaining, coords_prefix);
        }
        Some(PacketMover2FspOwnerSeed {
            owner: OwnerId::fsp_node(*node_addr),
            config,
            keys: OwnerCryptoKeys::new(Arc::new(open), Arc::new(seal)),
            routes,
            next_hop,
        })
    }

    fn packet_mover2_fsp_coords_prefix(
        &self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> Vec<u8> {
        if coords_warmup_remaining == 0 {
            return Vec::new();
        }
        self.packet_mover2_fsp_coords_prefix_for_dest(node_addr)
    }

    fn packet_mover2_fsp_coords_prefix_for_dest(&self, node_addr: &NodeAddr) -> Vec<u8> {
        let src = self.tree_state.my_coords().clone();
        let dst = self.get_dest_coords(node_addr);
        let mut prefix = Vec::with_capacity(
            crate::protocol::coords_wire_size(&src) + crate::protocol::coords_wire_size(&dst),
        );
        crate::protocol::encode_coords(&src, &mut prefix);
        crate::protocol::encode_coords(&dst, &mut prefix);
        prefix
    }

    fn packet_mover2_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
        generation: u64,
        fsp_flags: u8,
        inner_flags: u8,
    ) -> (PacketMover2LiveOwnerRoutes, Option<NodeAddr>) {
        let owner = OwnerId::fsp_node(*node_addr);
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(node_addr) else {
            return (PacketMover2LiveOwnerRoutes::new(), None);
        };

        let mut routes = PacketMover2LiveOwnerRoutes::new();
        routes.push_fsp_ingress(PacketMover2LiveFspIngressRoute::new(
            *node_addr,
            PacketMover2IngressRoute::new(
                owner,
                generation,
                OutputTarget::SessionPayload {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));
        let tun = PacketMover2TunOutboundRoute::fsp_ipv6_shim(
            owner,
            generation,
            PacketClass::Bulk,
            fsp_flags,
            inner_flags,
        )
        .with_fmp_wrap(wrap);
        routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            *node_addr,
            PacketMover2TunDestinationRoute::new(tun)
                .with_max_packet_len(self.packet_mover2_tun_max_packet_len(node_addr)),
        ));

        let endpoint =
            PacketMover2EndpointCommandRoute::fsp(owner, generation, fsp_flags, inner_flags)
                .with_fmp_wrap(wrap);
        routes.push_endpoint_destination(PacketMover2LiveEndpointRoute::new(*node_addr, endpoint));

        (routes, Some(next_hop))
    }

    fn packet_mover2_fsp_wrap_route(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<(PacketMover2FspWrapRoute, NodeAddr)> {
        let (next_hop, generation, receiver_idx, transport_id, remote_addr, fmp_flags) = {
            let peer = self.find_next_hop(dest_addr)?;
            let mut fmp_flags = if peer.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()) {
                FLAG_SP
            } else {
                0
            };
            if peer.current_k_bit() {
                fmp_flags |= FLAG_KEY_EPOCH;
            }
            (
                *peer.node_addr(),
                peer.session_generation(),
                peer.their_index()?.as_u32(),
                peer.transport_id()?,
                peer.current_addr()?.clone(),
                fmp_flags,
            )
        };
        let path_mtu = self
            .transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu());
        let wrap = PacketMover2FspWrapRoute::new(
            OwnerId::fmp_node(next_hop),
            generation,
            receiver_idx,
            *self.node_addr(),
            *dest_addr,
        )
        .with_fmp_flags(fmp_flags)
        .with_ttl(self.config.node.session.default_ttl)
        .with_path_mtu(path_mtu);
        Some((wrap, next_hop))
    }

    fn packet_mover2_tun_max_packet_len(&self, dest_addr: &NodeAddr) -> usize {
        let effective_mtu = self.effective_ipv6_mtu() as usize;
        self.sessions
            .get(dest_addr)
            .and_then(|entry| entry.mmp())
            .map(|mmp| crate::upper::icmp::effective_ipv6_mtu(mmp.path_mtu.current_mtu()) as usize)
            .filter(|path_ipv6_mtu| *path_ipv6_mtu < effective_mtu)
            .unwrap_or(effective_mtu)
    }

    fn packet_mover2_owner_in_flight_limit(&self) -> usize {
        self.config.node.limits.max_pending_inbound.max(1)
    }

    fn packet_mover2_owner_config(&self, generation: u64) -> OwnerConfig {
        let in_flight_limit = self.packet_mover2_owner_in_flight_limit();
        let bulk_in_flight_limit = packet_mover2_owner_bulk_in_flight_limit(in_flight_limit);
        let reliable_bulk_in_flight_limit =
            packet_mover2_owner_reliable_bulk_in_flight_limit(in_flight_limit);
        OwnerConfig::new(generation, in_flight_limit)
            .with_bulk_in_flight_limit(bulk_in_flight_limit)
            .with_reliable_bulk_in_flight_limit(reliable_bulk_in_flight_limit)
    }

    fn packet_mover2_fsp_generation(&self, node_addr: &NodeAddr) -> Option<u64> {
        self.sessions.get(node_addr).map(|session| {
            Self::packet_mover2_generation_from_session_start_ms(session.session_start_ms())
        })
    }

    fn packet_mover2_generation_from_session_start_ms(session_start_ms: u64) -> u64 {
        session_start_ms.max(1)
    }

    fn packet_mover2_fmp_output_drop_error(
        &self,
        node_addr: NodeAddr,
        drop: &PacketMover2OutputDrop,
    ) -> NodeError {
        match drop.reason() {
            PacketMover2OutputError::MtuExceeded => NodeError::MtuExceeded {
                node_addr,
                packet_size: drop.payload_len(),
                mtu: self.packet_mover2_drop_path_mtu(drop),
            },
            PacketMover2OutputError::NoRoute => {
                NodeError::LocalRouteUnavailable("packet_mover2 transport route unavailable".into())
            }
            reason => NodeError::SendFailed {
                node_addr,
                reason: format!("packet_mover2 transport output failed: {:?}", reason),
            },
        }
    }

    fn packet_mover2_drop_path_mtu(&self, drop: &PacketMover2OutputDrop) -> u16 {
        let Some(TransportPath::Live {
            transport_id,
            remote_addr,
        }) = drop.path()
        else {
            return self.transport_mtu();
        };
        self.transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu())
    }
}

fn packet_mover2_fmp_link_class(plaintext: &[u8]) -> PacketClass {
    match plaintext
        .first()
        .and_then(|msg_type| LinkMessageType::from_byte(*msg_type))
    {
        Some(LinkMessageType::Heartbeat) => PacketClass::Liveness,
        Some(LinkMessageType::SenderReport | LinkMessageType::ReceiverReport) => PacketClass::Mmp,
        Some(LinkMessageType::SessionDatagram)
            if classify_fmp_plaintext_traffic(plaintext).bulk_endpoint_data =>
        {
            PacketClass::Bulk
        }
        _ => PacketClass::Control,
    }
}

fn packet_mover2_owner_bulk_in_flight_limit(in_flight_limit: usize) -> usize {
    let in_flight_limit = in_flight_limit.max(1);
    let priority_reserve = usize::from(in_flight_limit > 1);
    PACKET_MOVER2_DEFAULT_OWNER_BULK_IN_FLIGHT_LIMIT
        .min(in_flight_limit.saturating_sub(priority_reserve))
        .max(1)
}

fn packet_mover2_owner_reliable_bulk_in_flight_limit(in_flight_limit: usize) -> usize {
    let in_flight_limit = in_flight_limit.max(1);
    let priority_reserve = usize::from(in_flight_limit > 1);
    PACKET_MOVER2_DEFAULT_OWNER_RELIABLE_BULK_IN_FLIGHT_LIMIT
        .min(in_flight_limit.saturating_sub(priority_reserve))
        .max(1)
}

fn packet_mover2_fsp_control_class(msg_type: u8) -> PacketClass {
    match SessionMessageType::from_byte(msg_type) {
        Some(
            SessionMessageType::SenderReport
            | SessionMessageType::ReceiverReport
            | SessionMessageType::PathMtuNotification,
        ) => PacketClass::Mmp,
        _ => PacketClass::Control,
    }
}

#[cfg(test)]
mod packet_mover2_integration_tests {
    use super::*;

    #[test]
    fn owner_bulk_in_flight_limit_reserves_priority_slot() {
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(0), 1);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(1), 1);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(2), 1);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(64), 63);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(65), 64);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(128), 64);

        assert_eq!(packet_mover2_owner_reliable_bulk_in_flight_limit(0), 1);
        assert_eq!(packet_mover2_owner_reliable_bulk_in_flight_limit(1), 1);
        assert_eq!(packet_mover2_owner_reliable_bulk_in_flight_limit(2), 1);
        assert_eq!(packet_mover2_owner_reliable_bulk_in_flight_limit(64), 63);
        assert_eq!(packet_mover2_owner_reliable_bulk_in_flight_limit(65), 64);
        assert_eq!(packet_mover2_owner_reliable_bulk_in_flight_limit(128), 64);
    }
}
