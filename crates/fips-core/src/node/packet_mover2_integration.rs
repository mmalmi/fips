use super::endpoint_traffic::classify_fmp_plaintext_traffic;
use super::*;
use crate::packet_mover2::{
    ActivityTick, OutboundPacket, OutboundPostSeal, OutputTarget, OwnerConfig, OwnerCryptoKeys,
    OwnerId, PacketClass, PacketMover2EndpointCommandRoute, PacketMover2FspSendReceipt,
    PacketMover2FspWrapRoute, PacketMover2IngressRoute, PacketMover2LiveEndpointRoute,
    PacketMover2LiveFmpIngressRoute, PacketMover2LiveFspIngressRoute, PacketMover2LiveNodeTurn,
    PacketMover2LiveOutboundFirsts, PacketMover2LiveOwnerRoutes, PacketMover2LiveTunRoute,
    PacketMover2OutputDrop, PacketMover2OutputError, PacketMover2TunDestinationRoute,
    PacketMover2TunOutboundRoute, TransportPath,
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

pub(in crate::node) struct PacketMover2FspOwnerSessionSnapshot {
    open: ring::aead::LessSafeKey,
    seal: ring::aead::LessSafeKey,
    counter_authority: crate::noise::SendCounterAuthority,
    session_start_ms: u64,
    current_k_bit: bool,
    previous_draining_k_bit: Option<bool>,
    source_peer: PeerIdentity,
    is_initiator: bool,
}

impl Node {
    pub(in crate::node) async fn send_packet_mover2_fmp_link_plaintext(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        if !self.packet_mover2_has_fmp_owner(node_addr) {
            return if self.peers.get(node_addr).is_none() {
                Err(NodeError::PeerNotFound(*node_addr))
            } else {
                Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: "packet_mover2 FMP owner not registered".into(),
                })
            };
        }

        let Some(send_context) = self.packet_mover2.fmp_owner_send_context(node_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "packet_mover2 FMP send context unavailable".into(),
            });
        };

        let mut flags = send_context.flags();
        {
            let peer = self
                .peers
                .get(node_addr)
                .ok_or(NodeError::PeerNotFound(*node_addr))?;
            if peer.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()) {
                flags |= FLAG_SP;
            }
        };
        if ce_flag {
            flags |= FLAG_CE;
        }

        let outbound = OutboundPacket::fmp(
            OwnerId::fmp_node(*node_addr),
            send_context.generation(),
            packet_mover2_fmp_link_class(plaintext),
            send_context.receiver_idx(),
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

    pub(in crate::node) async fn send_packet_mover2_cached_tun_packet(
        &mut self,
        dest_addr: &NodeAddr,
        packet: Vec<u8>,
    ) -> Result<(), NodeError> {
        if !self.packet_mover2_has_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "packet_mover2 FSP owner not registered for queued TUN packet".into(),
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
        if let Some(error) = self.packet_mover2_cached_tun_drop_error(dest_addr, &turn) {
            return Err(error);
        }
        self.finish_packet_mover2_pending_outbound_turn(dest_addr, "queued TUN packet", turn, false)
            .await
            .map(|_| ())
    }

    fn packet_mover2_cached_tun_drop_error(
        &mut self,
        dest_addr: &NodeAddr,
        turn: &PacketMover2LiveNodeTurn,
    ) -> Option<NodeError> {
        let drop = turn.tun_outbound_drops().first()?;
        let packet = drop.packet().to_vec();
        let payload_len = drop.payload_len();
        match drop.reason() {
            crate::packet_mover2::PacketMover2TunOutboundDropReason::MtuExceeded { mtu } => {
                self.send_icmpv6_packet_too_big(&packet, mtu);
                Some(NodeError::MtuExceeded {
                    node_addr: *dest_addr,
                    packet_size: payload_len,
                    mtu: mtu.min(u32::from(u16::MAX)) as u16,
                })
            }
            crate::packet_mover2::PacketMover2TunOutboundDropReason::NoRoute => {
                self.send_icmpv6_dest_unreachable(&packet);
                Some(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "packet_mover2 TUN route unavailable".into(),
                })
            }
            crate::packet_mover2::PacketMover2TunOutboundDropReason::InvalidPacket => {
                Some(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "packet_mover2 TUN packet invalid".into(),
                })
            }
        }
    }

    pub(in crate::node) async fn send_packet_mover2_cached_endpoint_payloads(
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
        if !self.packet_mover2_has_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "packet_mover2 FSP owner not registered for queued endpoint data".into(),
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
        self.finish_packet_mover2_pending_outbound_turn(
            dest_addr,
            "queued endpoint data",
            turn,
            false,
        )
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
        self.send_packet_mover2_fsp_control_outbound(
            dest_addr,
            msg_type,
            None,
            payload,
            None,
            now_ms,
            "FSP control message",
        )
        .await
    }

    pub(in crate::node) async fn send_packet_mover2_fsp_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        let coords_prefix = self.packet_mover2_fsp_coords_prefix_for_dest(dest_addr);
        self.send_packet_mover2_fsp_control_outbound(
            dest_addr,
            SessionMessageType::CoordsWarmup.to_byte(),
            Some(crate::node::session_wire::FSP_FLAG_CP),
            &[],
            Some(coords_prefix),
            now_ms,
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
        let turn = self
            .packet_mover2
            .pump_outbound_firsts_with_transport_worker(
                firsts,
                endpoint_limit,
                tun_limit,
                &tun_tx,
                &endpoint_tx,
                &self.transports,
                crypto_limit,
                &mut self.packet_mover2_transport_send_worker,
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
        fsp_flags_override: Option<u8>,
        payload: &[u8],
        coords_prefix: Option<Vec<u8>>,
        now_ms: u64,
        label: &str,
    ) -> Result<(), NodeError> {
        if !self.packet_mover2_has_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP owner not registered for {label}"),
            });
        }
        if !self.refresh_packet_mover2_fsp_owner_routes(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP route unavailable for {label}"),
            });
        }
        let Some(send_context) = self.packet_mover2.fsp_owner_send_context(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP owner send context unavailable for {label}"),
            });
        };
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP wrap route unavailable for {label}"),
            });
        };
        let coords_prefix_len = coords_prefix.as_ref().map_or(0, Vec::len);
        let fsp_flags = fsp_flags_override.unwrap_or_else(|| send_context.fsp_flags());
        let inner_flags = send_context.inner_flags();

        let mut outbound = OutboundPacket::fsp(
            OwnerId::fsp_node(*dest_addr),
            send_context.generation(),
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
            .pump_packet_mover2_initial_outbound(outbound, 2, true)
            .await;
        let mut turn = match self
            .finish_packet_mover2_pending_outbound_turn(dest_addr, label, turn, true)
            .await
        {
            Ok(turn) => turn,
            Err(error) => {
                self.record_route_failure(*dest_addr, next_hop);
                self.recover_direct_payload_send_failure(*dest_addr, next_hop, &error);
                return Err(error);
            }
        };
        if Self::packet_mover2_sent_fsp_receipt(&mut turn, *dest_addr).is_none() {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP receipt unavailable for {label}"),
            });
        }
        let frame_bytes = crate::node::session_wire::FSP_INNER_HEADER_SIZE
            .saturating_add(payload.len())
            .saturating_add(crate::noise::TAG_SIZE);
        let datagram_bytes = crate::protocol::SESSION_DATAGRAM_HEADER_SIZE
            .saturating_add(crate::node::session_wire::FSP_HEADER_SIZE)
            .saturating_add(coords_prefix_len)
            .saturating_add(frame_bytes);
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
        collect_transport_sent_outputs: bool,
    ) -> Result<PacketMover2LiveNodeTurn, NodeError> {
        for continuation in 0..=PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS {
            let summary = turn.summary();
            let sent = Self::packet_mover2_pending_outbound_sent(&turn);
            let deferred = turn.endpoint_deferred_commands() > 0 || turn.tun_deferred_packets() > 0;
            let failed = turn.has_failures();
            let needs_continuation = Self::packet_mover2_pending_outbound_needs_continuation(&turn);

            self.process_packet_mover2_pending_outbound_bookkeeping()
                .await;

            if failed {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: Self::packet_mover2_pending_outbound_failure(label, &turn),
                });
            }
            if sent {
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
                    PacketMover2LiveOutboundFirsts::default()
                        .with_transport_sent_output_collection(collect_transport_sent_outputs),
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

    fn packet_mover2_sent_fsp_receipt(
        turn: &mut PacketMover2LiveNodeTurn,
        dest_addr: NodeAddr,
    ) -> Option<PacketMover2FspSendReceipt> {
        let owner = OwnerId::fsp_node(dest_addr);
        let mut sent_receipt = None;
        for output in turn.take_transport_sent_outputs() {
            if let Some(receipt) = output.fsp_send_receipt()
                && receipt.owner() == owner
            {
                sent_receipt = Some(receipt);
            }
        }
        sent_receipt
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

    async fn process_packet_mover2_pending_outbound_bookkeeping(&mut self) -> usize {
        let mut processed = 0usize;
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

    pub(in crate::node) fn packet_mover2_has_fmp_owner(&self, node_addr: &NodeAddr) -> bool {
        self.packet_mover2.has_owner(OwnerId::fmp_node(*node_addr))
    }

    pub(in crate::node) fn refresh_packet_mover2_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
    ) -> bool {
        let owner = OwnerId::fsp_node(*node_addr);
        let Some(send_context) = self.packet_mover2.fsp_owner_send_context(node_addr) else {
            return false;
        };
        let (routes, next_hop) = self.packet_mover2_fsp_owner_routes(
            node_addr,
            send_context.generation(),
            send_context.fsp_flags(),
            send_context.inner_flags(),
        );
        let next_hop_ready =
            next_hop.is_none_or(|next_hop| self.packet_mover2_has_fmp_owner(&next_hop));
        self.packet_mover2
            .replace_owner_routes(owner, routes)
            .is_ok()
            && next_hop_ready
    }

    pub(in crate::node) fn refresh_packet_mover2_fsp_owner_routes_with_coords_warmup(
        &mut self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> bool {
        let owner = OwnerId::fsp_node(*node_addr);
        let coords_prefix =
            self.packet_mover2_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        let warmup_applied = self
            .packet_mover2
            .set_owner_fsp_coords_warmup(owner, coords_warmup_remaining, coords_prefix)
            .is_ok();
        self.refresh_packet_mover2_fsp_owner_routes(node_addr) && warmup_applied
    }

    pub(in crate::node) fn set_packet_mover2_fsp_owner_epoch(
        &mut self,
        node_addr: &NodeAddr,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> bool {
        self.packet_mover2
            .set_owner_fsp_epoch(
                OwnerId::fsp_node(*node_addr),
                current_k_bit,
                previous_draining_k_bit,
            )
            .is_ok()
    }

    pub(in crate::node) fn packet_mover2_fsp_owner_epoch(
        session: &SessionEntry,
    ) -> (bool, Option<bool>) {
        let current_k_bit = session.current_k_bit();
        (
            current_k_bit,
            session.is_draining().then_some(!current_k_bit),
        )
    }

    pub(in crate::node) fn packet_mover2_has_fsp_owner(&self, node_addr: &NodeAddr) -> bool {
        self.packet_mover2.has_owner(OwnerId::fsp_node(*node_addr))
    }

    pub(in crate::node) fn sync_packet_mover2_fsp_owner_from_session_entry(
        &mut self,
        node_addr: &NodeAddr,
        session: &SessionEntry,
        coords_warmup_remaining: u8,
    ) -> bool {
        let Some(snapshot) = Self::packet_mover2_fsp_owner_session_snapshot(session) else {
            self.remove_packet_mover2_fsp_owner(node_addr);
            return false;
        };
        self.sync_packet_mover2_fsp_owner_from_session_snapshot(
            node_addr,
            snapshot,
            coords_warmup_remaining,
        )
    }

    pub(in crate::node) fn sync_packet_mover2_fsp_owner_from_session_snapshot(
        &mut self,
        node_addr: &NodeAddr,
        snapshot: PacketMover2FspOwnerSessionSnapshot,
        coords_warmup_remaining: u8,
    ) -> bool {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2FspOwnerSync);
        crate::perf_profile::record_event(crate::perf_profile::Event::PacketMover2FspOwnerSyncCall);

        let Some(seed) = self.packet_mover2_fsp_owner_seed_from_snapshot(
            node_addr,
            snapshot,
            coords_warmup_remaining,
        ) else {
            self.remove_packet_mover2_fsp_owner(node_addr);
            return false;
        };
        self.apply_packet_mover2_fsp_owner_seed(seed)
    }

    fn apply_packet_mover2_fsp_owner_seed(&mut self, seed: PacketMover2FspOwnerSeed) -> bool {
        self.packet_mover2
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let next_hop_ready = seed
            .next_hop
            .is_none_or(|next_hop| self.packet_mover2_has_fmp_owner(&next_hop));
        let synced = self
            .packet_mover2
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
            && next_hop_ready;
        if synced {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PacketMover2FspOwnerSyncApplied,
            );
        }
        synced
    }

    pub(in crate::node) fn remove_packet_mover2_fsp_owner(&mut self, node_addr: &NodeAddr) {
        self.packet_mover2
            .unregister_owner(OwnerId::fsp_node(*node_addr));
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
        let fmp_send_headers = peer.their_index().map(|their_index| {
            let mut flags = 0;
            if peer.current_k_bit() {
                flags |= FLAG_KEY_EPOCH;
            }
            (their_index.as_u32(), flags)
        });
        let generation = peer.session_generation();
        let session_start_ms = Self::now_ms().wrapping_sub(u64::from(peer.session_elapsed_ms()));
        let source_peer = *peer.identity();
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
        let mut config = self
            .packet_mover2_owner_config(generation)
            .with_send_counter_authority(counter_authority)
            .with_fmp_session_start_ms(session_start_ms)
            .with_source_peer(source_peer);
        if let Some((receiver_idx, flags)) = fmp_send_headers {
            config = config.with_fmp_send_headers(receiver_idx, flags);
        }

        Some(PacketMover2FmpOwnerSeed {
            owner: OwnerId::fmp_node(*node_addr),
            config,
            keys: OwnerCryptoKeys::new(open, seal),
            path: TransportPath::live(transport_id, remote_addr),
            routes,
        })
    }

    pub(in crate::node) fn packet_mover2_fsp_owner_session_snapshot(
        session: &SessionEntry,
    ) -> Option<PacketMover2FspOwnerSessionSnapshot> {
        let (open, seal) = session.fsp_crypto_keys()?;
        let counter_authority = session.send_counter_authority()?;
        let source_peer = session.remote_identity()?;
        let current_k_bit = session.current_k_bit();
        Some(PacketMover2FspOwnerSessionSnapshot {
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

    fn packet_mover2_fsp_owner_seed_from_snapshot(
        &mut self,
        node_addr: &NodeAddr,
        snapshot: PacketMover2FspOwnerSessionSnapshot,
        coords_warmup_remaining: u8,
    ) -> Option<PacketMover2FspOwnerSeed> {
        let mut fsp_flags = 0;
        if snapshot.current_k_bit {
            fsp_flags |= crate::node::session_wire::FSP_FLAG_K;
        }
        let generation =
            Self::packet_mover2_generation_from_session_start_ms(snapshot.session_start_ms);
        let inner_flags = crate::protocol::FspInnerFlags { spin_bit: false }.to_byte();
        let coords_prefix =
            self.packet_mover2_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        let (routes, next_hop) =
            self.packet_mover2_fsp_owner_routes(node_addr, generation, fsp_flags, inner_flags);

        let mut config = self
            .packet_mover2_owner_config(generation)
            .with_send_counter_authority(snapshot.counter_authority)
            .with_fsp_session_start_ms(snapshot.session_start_ms)
            .with_fsp_send_headers(fsp_flags, inner_flags)
            .with_fsp_epoch(snapshot.current_k_bit, snapshot.previous_draining_k_bit)
            .with_source_peer(snapshot.source_peer);
        config = config.with_fsp_mmp(self.config.node.session_mmp.clone(), snapshot.is_initiator);
        if coords_warmup_remaining > 0 {
            config = config.with_fsp_coords_warmup(coords_warmup_remaining, coords_prefix);
        }
        Some(PacketMover2FspOwnerSeed {
            owner: OwnerId::fsp_node(*node_addr),
            config,
            keys: OwnerCryptoKeys::new(Arc::new(snapshot.open), Arc::new(snapshot.seal)),
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
        let (next_hop, spin_bit) = {
            let peer = self.find_next_hop(dest_addr)?;
            (
                *peer.node_addr(),
                peer.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()),
            )
        };
        let send_context = self.packet_mover2.fmp_owner_send_context(&next_hop)?;
        let active_path = self
            .packet_mover2
            .owner_active_path(OwnerId::fmp_node(next_hop))
            .ok()??;
        let transport_id = active_path.transport_id()?;
        let remote_addr = active_path.remote_addr()?.clone();
        let mut fmp_flags = send_context.flags();
        if spin_bit {
            fmp_flags |= FLAG_SP;
        }
        let path_mtu = self
            .transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu());
        let wrap = PacketMover2FspWrapRoute::new(
            OwnerId::fmp_node(next_hop),
            send_context.generation(),
            send_context.receiver_idx(),
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
        self.packet_mover2
            .fsp_owner_activity(dest_addr)
            .and_then(|activity| activity.current_path_mtu())
            .map(crate::upper::icmp::effective_ipv6_mtu)
            .map(usize::from)
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
