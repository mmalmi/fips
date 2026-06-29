use super::endpoint_traffic::classify_fmp_plaintext_traffic;
use super::*;
use crate::packet_mover2::{
    ActivityTick, OutboundPacket, OutboundPostSeal, OwnerId, PacketClass, PacketMover2LiveNodeTurn,
    PacketMover2LiveOutboundFirsts,
};
use crate::protocol::SessionMessageType;

const PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS: usize = 2;
const PACKET_MOVER2_PENDING_OUTBOUND_COMPLETION_WAIT: std::time::Duration =
    std::time::Duration::from_millis(50);

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
            self.defer_packet_mover2_control_ingress_from_send(&mut turn);
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

            self.wait_packet_mover2_pending_crypto(&turn).await;
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

    pub(in crate::node) async fn send_packet_mover2_pending_endpoint_payload(
        &mut self,
        dest_addr: &NodeAddr,
        payload: EndpointDataPayload,
    ) -> Result<(), NodeError> {
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

        let lane = payload.lane();
        let command = NodeEndpointCommand::send_payload_oneway(remote, payload, None);
        let firsts = match lane {
            EndpointCommandLane::Priority => {
                PacketMover2LiveOutboundFirsts::default().with_endpoint_priority(Some(command))
            }
            EndpointCommandLane::Bulk => {
                PacketMover2LiveOutboundFirsts::default().with_endpoint_bulk(Some(command))
            }
        };
        let turn = self
            .pump_packet_mover2_pending_outbound_firsts(firsts, 1, 0, 1)
            .await;
        let result = self
            .finish_packet_mover2_pending_outbound_turn(dest_addr, "queued endpoint data", turn)
            .await;
        result.map(|_| ())
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

    #[cfg(test)]
    pub(in crate::node) async fn send_packet_mover2_fsp_data_plaintext(
        &mut self,
        dest_addr: &NodeAddr,
        mut fsp_flags: u8,
        inner_plaintext: &[u8],
        mut coords_prefix: Option<Vec<u8>>,
        now_ms: u64,
        timestamp: u32,
        payload_len: usize,
        label: &str,
    ) -> Result<(), NodeError> {
        if !self.sync_packet_mover2_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP owner unavailable for {label}"),
            });
        }
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no route to destination".into(),
            });
        };
        let Some(generation) = self.packet_mover2_fsp_generation(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP generation unavailable for {label}"),
            });
        };
        if coords_prefix.is_none() && next_hop != *dest_addr {
            coords_prefix = Some(self.packet_mover2_fsp_coords_prefix_for_dest(dest_addr));
            fsp_flags |= crate::node::session_wire::FSP_FLAG_CP;
        }
        let coords_prefix_len = coords_prefix.as_ref().map_or(0, Vec::len);

        let mut outbound = OutboundPacket::fsp(
            OwnerId::fsp_node(*dest_addr),
            generation,
            PacketClass::Bulk,
            fsp_flags,
            inner_plaintext.to_vec(),
        )
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap))
        .with_activity_tick(ActivityTick::new(now_ms));
        if let Some(prefix) = coords_prefix {
            outbound = outbound.with_fsp_cleartext_prefix(prefix);
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
        let frame_bytes = inner_plaintext.len().saturating_add(crate::noise::TAG_SIZE);
        let datagram_bytes = crate::protocol::SESSION_DATAGRAM_HEADER_SIZE
            .saturating_add(crate::node::session_wire::FSP_HEADER_SIZE)
            .saturating_add(coords_prefix_len)
            .saturating_add(frame_bytes);
        let _ = self.sessions.record_fsp_send_bookkeeping(
            dest_addr,
            FspSendBookkeepingInput::data(payload_len, counter, timestamp, frame_bytes, now_ms),
        );
        self.sessions
            .record_session_datagram_next_hop(dest_addr, next_hop);
        self.stats_mut()
            .forwarding
            .record_originated(datagram_bytes);
        if next_hop != *dest_addr {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        Ok(())
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
        if !self.sync_packet_mover2_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP owner unavailable for {label}"),
            });
        }
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no route to destination".into(),
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
            let summary = turn.summary();
            let sent = Self::packet_mover2_pending_outbound_sent(&turn);
            let deferred = turn.endpoint_deferred_commands() > 0;
            let failed = turn.has_failures();
            let needs_continuation = Self::packet_mover2_pending_outbound_needs_continuation(&turn);

            self.defer_packet_mover2_control_ingress_from_send(&mut turn);
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

            wrapped_outbound_receipts.extend(turn.take_wrapped_outbound_receipts());
            let _ = self.wait_packet_mover2_pending_crypto(&turn).await;
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

    fn defer_packet_mover2_control_ingress_from_send(
        &mut self,
        turn: &mut PacketMover2LiveNodeTurn,
    ) {
        if let Some(control_turn) = turn.take_control_ingress_turn() {
            self.pending_packet_mover2_control_turns
                .push_back(control_turn);
        }
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
        summary.pending_crypto() > 0
            || summary.outbound_admitted() > summary.dispatched()
            || (summary.outbound_admitted() > 0 && summary.outputs() == 0)
    }

    async fn wait_packet_mover2_pending_crypto(&self, turn: &PacketMover2LiveNodeTurn) -> bool {
        if turn.summary().pending_crypto() == 0 {
            return true;
        }

        self.packet_mover2
            .wait_for_aead_completion(PACKET_MOVER2_PENDING_OUTBOUND_COMPLETION_WAIT)
            .await
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
        for command in self.packet_mover2.take_deferred_endpoint_commands() {
            self.handle_packet_mover2_deferred_endpoint_command(command)
                .await;
            processed += 1;
        }
        processed
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
