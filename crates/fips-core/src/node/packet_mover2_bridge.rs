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

const INITIAL_FMP_GENERATION: u64 = 1;
const INITIAL_FSP_GENERATION: u64 = 1;
const PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS: usize = 2;
const PACKET_MOVER2_DEFAULT_OWNER_BULK_IN_FLIGHT_LIMIT: usize = 64;

struct PacketMover2FmpOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    counter_authority: crate::noise::SendCounterAuthority,
    session_start_ms: u64,
    path: TransportPath,
    routes: PacketMover2LiveOwnerRoutes,
}

struct PacketMover2FspOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    counter_authority: crate::noise::SendCounterAuthority,
    session_start_ms: u64,
    coords_warmup_remaining: u8,
    coords_prefix: Vec<u8>,
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

        let (receiver_idx, mut flags) = {
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
            (receiver_idx.as_u32(), flags)
        };
        if ce_flag {
            flags |= FLAG_CE;
        }

        let outbound = OutboundPacket::fmp(
            OwnerId::fmp_node(*node_addr),
            INITIAL_FMP_GENERATION,
            packet_mover2_fmp_link_class(plaintext),
            receiver_idx,
            flags,
            plaintext.to_vec(),
        )
        .with_activity_tick(ActivityTick::new(Self::now_ms()));
        let (turn, sent_output) = self
            .packet_mover2
            .send_outbound_transport(outbound, &self.transports, 1)
            .await;

        if let Some(output) = sent_output {
            let timestamp_ms = output
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

        if let Some(drop) = turn.output_drops().first() {
            return Err(self.packet_mover2_fmp_output_drop_error(*node_addr, drop));
        }
        if let Some(drop) = turn.drops().first() {
            return Err(NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!("packet_mover2 FMP send drop: {:?}", drop.reason()),
            });
        }
        Err(NodeError::SendFailed {
            node_addr: *node_addr,
            reason: format!(
                "packet_mover2 FMP send made no progress: {:?}",
                turn.summary()
            ),
        })
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
            )
            .await;
        self.finish_packet_mover2_pending_outbound_turn(dest_addr, "queued TUN packet", turn)
            .await
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
            .pump_packet_mover2_pending_outbound_firsts(firsts, 1, 0)
            .await;
        self.finish_packet_mover2_pending_outbound_turn(dest_addr, "queued endpoint data", turn)
            .await
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
                1,
            )
            .await;
        Self::observe_packet_mover2_scratch_turn(&turn);
        turn
    }

    async fn send_packet_mover2_live_outbound(
        &mut self,
        outbound: OutboundPacket,
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
            .send_live_outbound(
                outbound,
                &tun_tx,
                &endpoint_tx,
                endpoint_resolver,
                &self.transports,
                crypto_limit,
            )
            .await;
        Self::observe_packet_mover2_scratch_turn(&turn);
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
        let Some(counter) = self
            .sessions
            .get(dest_addr)
            .and_then(|entry| entry.send_counter_authority())
            .map(|authority| authority.current())
        else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP counter unavailable for {label}"),
            });
        };
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("packet_mover2 FSP wrap route unavailable for {label}"),
            });
        };
        let coords_prefix_len = coords_prefix.as_ref().map_or(0, Vec::len);

        let mut outbound = OutboundPacket::fsp(
            OwnerId::fsp_node(*dest_addr),
            INITIAL_FSP_GENERATION,
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

        let turn = self.send_packet_mover2_live_outbound(outbound, 2).await;
        if let Err(error) = self
            .finish_packet_mover2_pending_outbound_turn(dest_addr, label, turn)
            .await
        {
            self.record_route_failure(*dest_addr, next_hop);
            self.recover_direct_payload_send_failure(*dest_addr, next_hop, &error);
            return Err(error);
        }
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
    ) -> Result<(), NodeError> {
        for continuation in 0..=PACKET_MOVER2_PENDING_OUTBOUND_CONTINUATION_TURNS {
            let summary = turn.summary();
            let sent = Self::packet_mover2_pending_outbound_sent(&turn);
            let deferred = turn.endpoint_deferred_commands() > 0;
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
                return Ok(());
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

            turn = self
                .pump_packet_mover2_pending_outbound_firsts(
                    PacketMover2LiveOutboundFirsts::default(),
                    0,
                    0,
                )
                .await;
        }

        unreachable!("bounded pending outbound continuation loop must return")
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
        for command in self.packet_mover2.take_deferred_endpoint_commands() {
            if let NodeEndpointCommand::Send {
                command,
                response_tx,
            } = command
            {
                let _ = response_tx.send(Err(NodeError::SendFailed {
                    node_addr: command.data_send().dest_addr(),
                    reason: "packet_mover2 pending flush endpoint route unavailable".into(),
                }));
            }
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
            .register_owner_if_missing(seed.owner, seed.config);
        self.packet_mover2
            .set_owner_crypto_keys(seed.owner, seed.keys)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_send_counter_authority(seed.owner, seed.counter_authority)
                .is_ok()
            && self
                .packet_mover2
                .set_owner_fmp_session_start_ms(seed.owner, seed.session_start_ms)
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
        let Some(seed) = self.packet_mover2_fsp_owner_seed(node_addr) else {
            self.remove_packet_mover2_fsp_owner(node_addr);
            return false;
        };

        self.packet_mover2
            .register_owner_if_missing(seed.owner, seed.config);
        let next_hop_ready = seed
            .next_hop
            .is_none_or(|next_hop| self.sync_packet_mover2_fmp_owner(&next_hop));
        self.packet_mover2
            .set_owner_crypto_keys(seed.owner, seed.keys)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_send_counter_authority(seed.owner, seed.counter_authority)
                .is_ok()
            && self
                .packet_mover2
                .set_owner_fsp_session_start_ms(seed.owner, seed.session_start_ms)
                .is_ok()
            && self
                .packet_mover2
                .set_owner_fsp_coords_warmup(
                    seed.owner,
                    seed.coords_warmup_remaining,
                    seed.coords_prefix,
                )
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

    fn packet_mover2_fmp_owner_seed(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FmpOwnerSeed> {
        let peer = self.peers.get(node_addr)?;
        let session = peer.noise_session()?;
        let transport_id = peer.transport_id()?;
        let remote_addr = peer.current_addr()?.clone();
        let receiver_idx = peer.our_index()?.as_u32();
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
                INITIAL_FMP_GENERATION,
                OutputTarget::SessionIngress {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));

        Some(PacketMover2FmpOwnerSeed {
            owner: OwnerId::fmp_node(*node_addr),
            config: self
                .packet_mover2_owner_config(INITIAL_FMP_GENERATION)
                .with_send_counter_authority(counter_authority.clone())
                .with_fmp_session_start_ms(session_start_ms),
            keys: OwnerCryptoKeys::new(open, seal),
            counter_authority,
            session_start_ms,
            path: TransportPath::live(transport_id, remote_addr),
            routes,
        })
    }

    fn packet_mover2_fsp_owner_seed(
        &mut self,
        node_addr: &NodeAddr,
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
        let coords_prefix =
            self.packet_mover2_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        let (routes, next_hop) =
            self.packet_mover2_fsp_owner_routes(node_addr, fsp_flags, inner_flags);

        Some(PacketMover2FspOwnerSeed {
            owner: OwnerId::fsp_node(*node_addr),
            config: self
                .packet_mover2_owner_config(INITIAL_FSP_GENERATION)
                .with_send_counter_authority(counter_authority.clone())
                .with_fsp_session_start_ms(session_start_ms)
                .with_fsp_coords_warmup(coords_warmup_remaining, coords_prefix.clone()),
            keys: OwnerCryptoKeys::new(Arc::new(open), Arc::new(seal)),
            counter_authority,
            session_start_ms,
            coords_warmup_remaining,
            coords_prefix,
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
                INITIAL_FSP_GENERATION,
                OutputTarget::SessionPayload {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));
        let tun = PacketMover2TunOutboundRoute::fsp_ipv6_shim(
            owner,
            INITIAL_FSP_GENERATION,
            PacketClass::Bulk,
            fsp_flags,
            inner_flags,
        )
        .with_fmp_wrap(wrap);
        routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            *node_addr,
            PacketMover2TunDestinationRoute::new(tun),
        ));

        let endpoint = PacketMover2EndpointCommandRoute::fsp(
            owner,
            INITIAL_FSP_GENERATION,
            fsp_flags,
            inner_flags,
        )
        .with_fmp_wrap(wrap);
        routes.push_endpoint_destination(PacketMover2LiveEndpointRoute::new(*node_addr, endpoint));

        (routes, Some(next_hop))
    }

    fn packet_mover2_fsp_wrap_route(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<(PacketMover2FspWrapRoute, NodeAddr)> {
        let (next_hop, receiver_idx, transport_id, remote_addr, fmp_flags) = {
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
            INITIAL_FMP_GENERATION,
            receiver_idx,
            *self.node_addr(),
            *dest_addr,
        )
        .with_fmp_flags(fmp_flags)
        .with_ttl(self.config.node.session.default_ttl)
        .with_path_mtu(path_mtu);
        Some((wrap, next_hop))
    }

    fn packet_mover2_owner_in_flight_limit(&self) -> usize {
        self.config.node.limits.max_pending_inbound.max(1)
    }

    fn packet_mover2_owner_config(&self, generation: u64) -> OwnerConfig {
        let in_flight_limit = self.packet_mover2_owner_in_flight_limit();
        let bulk_in_flight_limit =
            PACKET_MOVER2_DEFAULT_OWNER_BULK_IN_FLIGHT_LIMIT.min(in_flight_limit.max(1));
        OwnerConfig::new(generation, in_flight_limit)
            .with_bulk_in_flight_limit(bulk_in_flight_limit)
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
