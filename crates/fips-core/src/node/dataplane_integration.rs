use super::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram;
use super::*;
use crate::dataplane::{
    ActivityTick, DataplaneDirectFspSource, DataplaneEndpointDataRoute, DataplaneFspSendReceipt,
    DataplaneFspWrapRoute, DataplaneIngressRoute, DataplaneLiveEndpointRoute,
    DataplaneLiveFmpIngressRoute, DataplaneLiveFspIngressRoute, DataplaneLiveNodeTurn,
    DataplaneLiveOutboundFirsts, DataplaneLiveOwnerRoutes, DataplaneLiveTunRoute,
    DataplaneOutputDrop, DataplaneOutputError, DataplaneTunDestinationRoute,
    DataplaneTunOutboundRoute, OutboundPacket, OutputTarget, OwnerConfig, OwnerCryptoKeys, OwnerId,
    PacketClass, TransportPath,
};
use crate::protocol::SessionMessageType;
use std::collections::HashMap;

const DATAPLANE_PENDING_OUTBOUND_CONTINUATION_TURNS: usize = 2;
const DATAPLANE_PENDING_OUTBOUND_COMPLETION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);
struct DataplaneFmpOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    path: TransportPath,
    routes: DataplaneLiveOwnerRoutes,
}

struct DataplaneFspOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    routes: DataplaneLiveOwnerRoutes,
    wrap: Option<DataplaneFspWrapRoute>,
    path: Option<TransportPath>,
    direct_path_mtu: Option<u16>,
}

struct DataplaneFspOwnerSessionSnapshot {
    open: ring::aead::LessSafeKey,
    seal: ring::aead::LessSafeKey,
    counter_authority: crate::noise::SendCounterAuthority,
    session_start_ms: u64,
    current_k_bit: bool,
    previous_draining_k_bit: Option<bool>,
    source_peer: PeerIdentity,
    is_initiator: bool,
}

struct DataplaneFspOwnerRouteUpdate {
    routes: DataplaneLiveOwnerRoutes,
    wrap: Option<DataplaneFspWrapRoute>,
    path: Option<TransportPath>,
    direct_path_mtu: Option<u16>,
    next_hop: Option<NodeAddr>,
}

impl DataplaneFspOwnerRouteUpdate {
    fn route_ready(&self) -> bool {
        self.wrap.is_some() || self.path.is_some()
    }

    fn next_hop(&self) -> Option<NodeAddr> {
        self.next_hop
    }
}

enum DataplanePendingOutboundFailure {
    TurnFailed(DataplaneLiveNodeTurn),
    Stopped {
        turn: DataplaneLiveNodeTurn,
        reason: &'static str,
    },
    Exhausted(DataplaneLiveNodeTurn),
}

impl Node {
    pub(in crate::node) async fn send_dataplane_fmp_link_plaintext(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        if !self.dataplane_has_fmp_owner(node_addr) {
            return if self.peers.get(node_addr).is_none() {
                Err(NodeError::PeerNotFound(*node_addr))
            } else {
                Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: "dataplane FMP owner not registered".into(),
                })
            };
        }

        let Some(send_context) = self.dataplane.fmp_owner_send_context(node_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "dataplane FMP send context unavailable".into(),
            });
        };

        if self.peers.get(node_addr).is_none() {
            return Err(NodeError::PeerNotFound(*node_addr));
        }

        let mut flags = send_context.flags();
        if ce_flag {
            flags |= FLAG_CE;
        }

        let outbound = OutboundPacket::fmp(
            OwnerId::fmp_node(*node_addr),
            send_context.generation(),
            dataplane_fmp_link_class(plaintext),
            send_context.receiver_idx(),
            flags,
            plaintext.to_vec(),
        )
        .with_activity_tick(ActivityTick::new(Self::now_ms()));
        let firsts = DataplaneLiveOutboundFirsts {
            initial_outbound: Some(outbound),
            collect_transport_sent_receipts: true,
            ..Default::default()
        };
        let mut turn = self
            .pump_dataplane_pending_outbound_firsts(firsts, 0, 0, 1)
            .await;
        turn = match self.drive_dataplane_pending_outbound_turn(turn, true).await {
            Ok(turn) => turn,
            Err(failure) => {
                let failure_turn = match &failure {
                    DataplanePendingOutboundFailure::TurnFailed(turn)
                    | DataplanePendingOutboundFailure::Exhausted(turn) => turn,
                    DataplanePendingOutboundFailure::Stopped { turn, .. } => turn,
                };
                if let Some(drop) = failure_turn.output_drops().first() {
                    return Err(self.dataplane_fmp_output_drop_error(*node_addr, drop));
                }
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: Self::dataplane_pending_outbound_failure_from_stop(
                        "FMP link send",
                        &failure,
                    ),
                });
            }
        };
        if turn.transport_sent() != 1
            || turn.transport_dropped() != 0
            || turn.summary().outputs_sent() != 1
        {
            return Err(NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!(
                    "dataplane FMP send unexpected output shape: {:?}",
                    turn.summary()
                ),
            });
        }
        let mut sent_receipts = turn.take_transport_sent_receipts();
        if sent_receipts.len() != 1 {
            return Err(NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!(
                    "dataplane FMP send transport receipt mismatch: {:?}",
                    turn.summary()
                ),
            });
        }
        let receipt = sent_receipts.pop().expect("checked one sent receipt");
        if receipt.owner != OwnerId::fmp_node(*node_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "dataplane FMP send receipt owner mismatch".into(),
            });
        }
        let timestamp_ms = receipt
            .fmp_timestamp_ms
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "dataplane FMP timestamp missing".into(),
            })?;
        let bytes_sent = receipt.payload_len;
        let _ = self.dataplane.record_fmp_mmp_send_result(
            node_addr,
            receipt.counter,
            timestamp_ms,
            bytes_sent,
        );
        let _ = self.peers.record_fmp_send_bookkeeping(
            node_addr,
            receipt.counter,
            timestamp_ms,
            bytes_sent,
        );
        let send_result: Result<usize, TransportError> = Ok(bytes_sent);
        self.note_local_send_outcome(node_addr, &send_result);
        Ok(())
    }

    pub(in crate::node) async fn send_dataplane_cached_tun_packet(
        &mut self,
        dest_addr: &NodeAddr,
        packet: Vec<u8>,
    ) -> Result<(), NodeError> {
        if !self.dataplane_has_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "dataplane FSP owner not registered for queued TUN packet".into(),
            });
        }

        let turn = self
            .pump_dataplane_pending_outbound_firsts(
                DataplaneLiveOutboundFirsts {
                    tun_packet: Some(packet),
                    ..Default::default()
                },
                0,
                1,
                1,
            )
            .await;
        if let Some(error) = self.dataplane_cached_tun_drop_error(dest_addr, &turn) {
            return Err(error);
        }
        self.finish_dataplane_pending_outbound_turn(dest_addr, "queued TUN packet", turn, false)
            .await
            .map(|_| ())
    }

    fn dataplane_cached_tun_drop_error(
        &mut self,
        dest_addr: &NodeAddr,
        turn: &DataplaneLiveNodeTurn,
    ) -> Option<NodeError> {
        let drop = turn.tun_outbound_drops().first()?;
        let packet = drop.packet().to_vec();
        let payload_len = drop.payload_len();
        match drop.reason() {
            crate::dataplane::DataplaneTunOutboundDropReason::MtuExceeded { mtu } => {
                self.send_icmpv6_packet_too_big(&packet, mtu);
                Some(NodeError::MtuExceeded {
                    node_addr: *dest_addr,
                    packet_size: payload_len,
                    mtu: mtu.min(u32::from(u16::MAX)) as u16,
                })
            }
            crate::dataplane::DataplaneTunOutboundDropReason::NoRoute => {
                self.send_icmpv6_dest_unreachable(&packet);
                Some(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "dataplane TUN route unavailable".into(),
                })
            }
            crate::dataplane::DataplaneTunOutboundDropReason::InvalidPacket => {
                Some(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "dataplane TUN packet invalid".into(),
                })
            }
        }
    }

    pub(in crate::node) async fn send_dataplane_cached_endpoint_payloads(
        &mut self,
        dest_addr: &NodeAddr,
        payloads: Vec<Vec<u8>>,
        _pending_enqueued_at_ms: u64,
    ) -> Result<(), NodeError> {
        if payloads.is_empty() {
            return Ok(());
        }
        if !self.dataplane_has_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "dataplane FSP owner not registered for queued endpoint data".into(),
            });
        }
        let Some(remote) = self.dataplane_peer_identity(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "dataplane endpoint identity unavailable for queued endpoint data".into(),
            });
        };

        let payload_count = payloads.len();
        // Pending session traffic waited outside dataplane while first-contact or
        // route recovery completed. Start the dataplane endpoint queue age when the
        // batch enters dataplane so session establishment latency does not trip the
        // live endpoint stale-bulk guard.
        let batch = NodeEndpointDataBatch::batch(remote, payloads, None)
            .expect("checked pending endpoint payload batch");
        let firsts = DataplaneLiveOutboundFirsts {
            endpoint_data_batch: Some(batch),
            ..Default::default()
        };
        let turn = self
            .pump_dataplane_pending_outbound_firsts(firsts, payload_count, 0, payload_count)
            .await;
        self.finish_dataplane_pending_outbound_turn(dest_addr, "queued endpoint data", turn, false)
            .await
            .map(|_| ())
    }

    pub(in crate::node) async fn send_dataplane_fsp_session_msg(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        self.send_dataplane_fsp_control_outbound(
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

    pub(in crate::node) async fn send_dataplane_fsp_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        let coords_prefix = self.dataplane_fsp_coords_prefix_for_dest(dest_addr);
        self.send_dataplane_fsp_control_outbound(
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

    async fn pump_dataplane_pending_outbound_firsts(
        &mut self,
        firsts: DataplaneLiveOutboundFirsts,
        endpoint_limit: usize,
        tun_limit: usize,
        crypto_limit: usize,
    ) -> DataplaneLiveNodeTurn {
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
        let mut empty_raw_ingress = std::collections::VecDeque::new();
        let (_, mut empty_endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_, mut empty_tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        let turn = self
            .dataplane
            .pump_turn_with_firsts_and_transport_worker(
                None,
                &mut empty_raw_ingress,
                0,
                firsts,
                &mut empty_endpoint_data_rx,
                endpoint_limit,
                &mut empty_tun_outbound_rx,
                tun_limit,
                &tun_tx,
                &endpoint_tx,
                &self.transports,
                crypto_limit,
                &mut self.dataplane_transport_send_worker,
            )
            .await;
        Self::observe_dataplane_turn(&turn);
        turn
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_dataplane_fsp_control_outbound(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        fsp_flags_override: Option<u8>,
        payload: &[u8],
        coords_prefix: Option<Vec<u8>>,
        now_ms: u64,
        label: &str,
    ) -> Result<(), NodeError> {
        if !self.dataplane_has_fsp_owner(dest_addr) {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("dataplane FSP owner not registered for {label}"),
            });
        }
        let Some(next_hop) = self.dataplane.fsp_owner_next_hop(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("dataplane FSP owner route unavailable for {label}"),
            });
        };
        let Some(send_context) = self.dataplane.fsp_owner_send_context(dest_addr) else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("dataplane FSP owner send context unavailable for {label}"),
            });
        };
        let coords_prefix_len = coords_prefix.as_ref().map_or(0, Vec::len);
        let fsp_flags = fsp_flags_override.unwrap_or_else(|| send_context.fsp_flags());
        let inner_flags = send_context.inner_flags();

        let mut outbound = OutboundPacket::fsp(
            OwnerId::fsp_node(*dest_addr),
            send_context.generation(),
            dataplane_fsp_control_class(msg_type),
            fsp_flags,
            payload.to_vec(),
        )
        .with_fsp_inner_header(msg_type, inner_flags)
        .with_activity_tick(ActivityTick::new(now_ms));
        if let Some(prefix) = coords_prefix {
            outbound = outbound.with_fsp_cleartext_prefix(prefix);
        } else {
            outbound = outbound.without_fsp_auto_coords_warmup();
        }

        let firsts = DataplaneLiveOutboundFirsts {
            initial_outbound: Some(outbound),
            collect_transport_sent_receipts: true,
            ..Default::default()
        };
        let turn = self
            .pump_dataplane_pending_outbound_firsts(firsts, 0, 0, 2)
            .await;
        let mut turn = match self
            .finish_dataplane_pending_outbound_turn(dest_addr, label, turn, true)
            .await
        {
            Ok(turn) => turn,
            Err(error) => {
                self.record_route_failure(*dest_addr, next_hop);
                self.recover_direct_payload_send_failure(*dest_addr, next_hop, &error);
                return Err(error);
            }
        };
        if Self::dataplane_sent_fsp_receipt(&mut turn, *dest_addr).is_none() {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("dataplane FSP receipt unavailable for {label}"),
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

    async fn finish_dataplane_pending_outbound_turn(
        &mut self,
        dest_addr: &NodeAddr,
        label: &str,
        turn: DataplaneLiveNodeTurn,
        collect_transport_sent_receipts: bool,
    ) -> Result<DataplaneLiveNodeTurn, NodeError> {
        let result = self
            .drive_dataplane_pending_outbound_turn(turn, collect_transport_sent_receipts)
            .await;
        self.process_dataplane_pending_outbound_bookkeeping().await;
        match result {
            Ok(turn) => Ok(turn),
            Err(failure) => Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: Self::dataplane_pending_outbound_failure_from_stop(label, &failure),
            }),
        }
    }

    async fn drive_dataplane_pending_outbound_turn(
        &mut self,
        mut turn: DataplaneLiveNodeTurn,
        collect_transport_sent_receipts: bool,
    ) -> Result<DataplaneLiveNodeTurn, DataplanePendingOutboundFailure> {
        for continuation in 0..=DATAPLANE_PENDING_OUTBOUND_CONTINUATION_TURNS {
            let summary = turn.summary();
            let sent = Self::dataplane_pending_outbound_sent(&turn);
            let deferred =
                turn.deferred_endpoint_data_batches_count() > 0 || turn.tun_deferred_packets() > 0;
            let failed = turn.has_failures();
            let needs_continuation = Self::dataplane_pending_outbound_needs_continuation(&turn);

            if failed {
                return Err(DataplanePendingOutboundFailure::TurnFailed(turn));
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
                return Err(DataplanePendingOutboundFailure::Stopped { turn, reason });
            }
            if continuation == DATAPLANE_PENDING_OUTBOUND_CONTINUATION_TURNS {
                return Err(DataplanePendingOutboundFailure::Exhausted(turn));
            }

            if needs_continuation && summary.outputs() == 0 {
                self.wait_for_dataplane_completion().await;
            }
            turn = self
                .pump_dataplane_pending_outbound_firsts(
                    DataplaneLiveOutboundFirsts {
                        collect_transport_sent_receipts,
                        ..Default::default()
                    },
                    0,
                    0,
                    1,
                )
                .await;
        }

        unreachable!("bounded pending outbound continuation loop must return")
    }

    async fn wait_for_dataplane_completion(&self) {
        let notify = self.dataplane.completion_notify();
        let _ = tokio::time::timeout(
            DATAPLANE_PENDING_OUTBOUND_COMPLETION_TIMEOUT,
            notify.notified(),
        )
        .await;
    }

    fn dataplane_sent_fsp_receipt(
        turn: &mut DataplaneLiveNodeTurn,
        dest_addr: NodeAddr,
    ) -> Option<DataplaneFspSendReceipt> {
        let owner = OwnerId::fsp_node(dest_addr);
        let mut sent_receipt = None;
        for transport_receipt in turn.take_transport_sent_receipts() {
            if let Some(receipt) = transport_receipt.fsp_send_receipt
                && receipt.owner() == owner
            {
                sent_receipt = Some(receipt);
            }
        }
        sent_receipt
    }

    fn dataplane_pending_outbound_sent(turn: &DataplaneLiveNodeTurn) -> bool {
        turn.transport_sent() > 0 || turn.summary().outputs_sent() > 0
    }

    fn dataplane_pending_outbound_needs_continuation(turn: &DataplaneLiveNodeTurn) -> bool {
        let summary = turn.summary();
        summary.outbound_admitted() > summary.dispatched()
            || (summary.outbound_admitted() > 0 && summary.outputs() == 0)
    }

    fn dataplane_pending_outbound_failure(label: &str, turn: &DataplaneLiveNodeTurn) -> String {
        let summary = turn.summary();
        if let Some(drop) = turn.tun_outbound_drops().first() {
            return format!(
                "dataplane {label} TUN route drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        if let Some(drop) = turn.endpoint_data_drops().first() {
            return format!(
                "dataplane {label} endpoint route drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        if let Some(drop) = turn.output_drops().first() {
            return format!(
                "dataplane {label} output drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        if let Some(drop) = turn.drops().first() {
            return format!(
                "dataplane {label} packet drop: {:?} ({summary:?})",
                drop.reason()
            );
        }
        format!("dataplane {label} failed: {summary:?}")
    }

    fn dataplane_pending_outbound_failure_from_stop(
        label: &str,
        failure: &DataplanePendingOutboundFailure,
    ) -> String {
        match failure {
            DataplanePendingOutboundFailure::TurnFailed(turn) => {
                Self::dataplane_pending_outbound_failure(label, turn)
            }
            DataplanePendingOutboundFailure::Stopped { turn, reason } => {
                format!("dataplane {label} {reason}: {:?}", turn.summary())
            }
            DataplanePendingOutboundFailure::Exhausted(turn) => {
                format!(
                    "dataplane {label} exhausted pending outbound continuation turns: {:?}",
                    turn.summary()
                )
            }
        }
    }

    async fn process_dataplane_pending_outbound_bookkeeping(&mut self) -> usize {
        let mut processed = 0usize;
        // Pending flush callers already own the packet they are trying to send.
        // If dataplane defers it again, drain it here and let the caller queue/recover.
        for _packet in self.dataplane.take_deferred_tun_packets() {
            processed += 1;
        }
        for batch in self.dataplane.take_deferred_endpoint_data_batches() {
            self.handle_endpoint_data_batch_no_established_flush(batch)
                .await;
            processed += 1;
        }
        processed
    }

    pub(in crate::node) fn sync_dataplane_fmp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        let Some(seed) = self.dataplane_fmp_owner_seed(node_addr) else {
            self.remove_dataplane_fmp_owner(node_addr);
            self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(node_addr);
            return false;
        };

        self.dataplane
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let synced = self
            .dataplane
            .apply_owner_live_config(seed.owner, seed.config)
            .is_ok()
            && self
                .dataplane
                .set_owner_crypto_keys(seed.owner, seed.keys)
                .is_ok()
            && self
                .dataplane
                .set_owner_active_path(seed.owner, seed.path)
                .is_ok()
            && self
                .dataplane
                .replace_owner_routes(seed.owner, seed.routes)
                .is_ok();
        if synced {
            self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(node_addr);
        }
        synced
    }

    pub(in crate::node) fn remove_dataplane_fmp_owner(&mut self, node_addr: &NodeAddr) {
        self.dataplane
            .unregister_owner(OwnerId::fmp_node(*node_addr));
    }

    pub(in crate::node) fn dataplane_has_fmp_owner(&self, node_addr: &NodeAddr) -> bool {
        self.dataplane.has_owner(OwnerId::fmp_node(*node_addr))
    }

    pub(in crate::node) fn refresh_dataplane_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
    ) -> bool {
        let owner = OwnerId::fsp_node(*node_addr);
        let Some(send_context) = self.dataplane.fsp_owner_send_context(node_addr) else {
            return false;
        };
        let update = self.dataplane_fsp_owner_routes(
            node_addr,
            send_context.generation(),
            send_context.fsp_flags(),
            send_context.inner_flags(),
        );
        let route_ready = update.route_ready();
        let next_hop_ready = update.path.is_some()
            || update
                .next_hop()
                .is_some_and(|next_hop| self.dataplane_has_fmp_owner(&next_hop));
        let direct_path_mtu = update.direct_path_mtu;
        let refreshed = self
            .dataplane
            .replace_owner_fsp_routes(owner, update.routes, update.wrap, update.path)
            .is_ok()
            && route_ready
            && next_hop_ready;
        if refreshed && let Some(path_mtu) = direct_path_mtu {
            let _ = self.dataplane.seed_fsp_path_mtu(*node_addr, path_mtu);
        }
        refreshed
    }

    pub(in crate::node) fn refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(
        &mut self,
        next_hop_addr: &NodeAddr,
    ) -> usize {
        let destinations = self.dataplane.fsp_owner_destinations();
        let mut refreshed = 0usize;
        for dest in destinations {
            let current_uses_next_hop =
                self.dataplane.fsp_owner_next_hop(&dest) == Some(*next_hop_addr);
            let would_use_next_hop = self
                .find_next_hop(&dest)
                .is_some_and(|peer| peer.node_addr() == next_hop_addr);
            if !(current_uses_next_hop || would_use_next_hop) {
                continue;
            }
            let route_ready = self.refresh_dataplane_fsp_owner_routes(&dest);
            if route_ready || current_uses_next_hop {
                refreshed = refreshed.saturating_add(1);
            }
        }
        refreshed
    }

    pub(in crate::node) fn refresh_dataplane_fsp_owner_routes_with_coords_warmup(
        &mut self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> bool {
        let owner = OwnerId::fsp_node(*node_addr);
        let coords_prefix = self.dataplane_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        let warmup_applied = self
            .dataplane
            .set_owner_fsp_coords_warmup(owner, coords_warmup_remaining, coords_prefix)
            .is_ok();
        self.refresh_dataplane_fsp_owner_routes(node_addr) && warmup_applied
    }

    pub(in crate::node) fn apply_dataplane_fsp_path_mtu_signal(
        &mut self,
        node_addr: &NodeAddr,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<
        crate::dataplane::DataplaneFspPathMtuApplyResult,
        crate::dataplane::DataplaneFspMmpSkip,
    > {
        let result = self
            .dataplane
            .apply_fsp_path_mtu_signal(*node_addr, path_mtu, now)?;
        if matches!(
            result,
            crate::dataplane::DataplaneFspPathMtuApplyResult::Changed(_)
        ) {
            let _ = self.refresh_dataplane_fsp_owner_routes(node_addr);
        }
        Ok(result)
    }

    pub(in crate::node) fn set_dataplane_fsp_owner_epoch(
        &mut self,
        node_addr: &NodeAddr,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> bool {
        self.dataplane
            .set_owner_fsp_epoch(
                OwnerId::fsp_node(*node_addr),
                current_k_bit,
                previous_draining_k_bit,
            )
            .is_ok()
    }

    pub(in crate::node) fn install_dataplane_fsp_pending_receive_epoch(
        &mut self,
        node_addr: &NodeAddr,
        pending_k_bit: bool,
        open: ring::aead::LessSafeKey,
    ) -> bool {
        self.dataplane
            .install_owner_fsp_pending_receive_epoch(
                OwnerId::fsp_node(*node_addr),
                pending_k_bit,
                std::sync::Arc::new(open),
            )
            .is_ok()
    }

    pub(in crate::node) fn promote_dataplane_authenticated_pending_fsp_epoch(
        &mut self,
        node_addr: &NodeAddr,
        received_k_bit: bool,
    ) -> bool {
        if !self
            .dataplane
            .fsp_owner_has_pending_receive_epoch(node_addr, received_k_bit)
        {
            return false;
        }
        let now_ms = Self::now_ms();
        let promoted = {
            let Some(session) = self.sessions.get_mut(node_addr) else {
                return false;
            };
            session.cutover_to_authenticated_pending_epoch(now_ms, received_k_bit)
        };
        if !promoted {
            return false;
        }

        self.sync_dataplane_fsp_owner_from_current_session(node_addr, 0)
    }

    pub(in crate::node) fn dataplane_fsp_owner_epoch(
        session: &SessionEntry,
    ) -> (bool, Option<bool>) {
        let current_k_bit = session.current_k_bit();
        (
            current_k_bit,
            session.is_draining().then_some(!current_k_bit),
        )
    }

    pub(in crate::node) fn dataplane_has_fsp_owner(&self, node_addr: &NodeAddr) -> bool {
        self.dataplane.has_owner(OwnerId::fsp_node(*node_addr))
    }

    pub(in crate::node) fn dataplane_direct_fsp_sources(
        &self,
    ) -> HashMap<
        (
            crate::transport::TransportId,
            crate::transport::TransportAddr,
        ),
        DataplaneDirectFspSource,
    > {
        let mut sources = HashMap::new();
        for (node_addr, peer) in &self.peers {
            let (Some(transport_id), Some(remote_addr)) =
                (peer.transport_id(), peer.current_addr().cloned())
            else {
                continue;
            };
            let path_mtu = self
                .transports
                .get(&transport_id)
                .map(|transport| transport.link_mtu(&remote_addr))
                .unwrap_or_else(|| self.transport_mtu());
            sources.insert(
                (transport_id, remote_addr),
                DataplaneDirectFspSource {
                    source_addr: *node_addr,
                    path_mtu,
                },
            );
        }
        sources
    }

    pub(in crate::node) fn sync_dataplane_fsp_owner_from_current_session(
        &mut self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> bool {
        let Some(snapshot) = self
            .sessions
            .get(node_addr)
            .and_then(Self::dataplane_fsp_owner_session_snapshot)
        else {
            self.remove_dataplane_fsp_owner(node_addr);
            return false;
        };
        self.sync_dataplane_fsp_owner_from_session_snapshot(
            node_addr,
            snapshot,
            coords_warmup_remaining,
        )
    }

    fn sync_dataplane_fsp_owner_from_session_snapshot(
        &mut self,
        node_addr: &NodeAddr,
        snapshot: DataplaneFspOwnerSessionSnapshot,
        coords_warmup_remaining: u8,
    ) -> bool {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneFspOwnerSync);
        crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneFspOwnerSyncCall);

        let Some(seed) = self.dataplane_fsp_owner_seed_from_snapshot(
            node_addr,
            snapshot,
            coords_warmup_remaining,
        ) else {
            self.remove_dataplane_fsp_owner(node_addr);
            return false;
        };
        self.apply_dataplane_fsp_owner_seed(seed)
    }

    fn apply_dataplane_fsp_owner_seed(&mut self, seed: DataplaneFspOwnerSeed) -> bool {
        self.dataplane
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let next_hop_ready = seed
            .wrap
            .map(DataplaneFspWrapRoute::next_hop_addr)
            .is_none_or(|next_hop| self.dataplane_has_fmp_owner(&next_hop));
        let synced = self
            .dataplane
            .install_owner_fsp_session_routes(
                seed.owner,
                seed.config,
                seed.keys,
                seed.routes,
                seed.wrap,
                seed.path,
            )
            .is_ok()
            && next_hop_ready;
        if synced && let Some(path_mtu) = seed.direct_path_mtu {
            let _ = self
                .dataplane
                .seed_fsp_path_mtu(seed.owner.node_addr(), path_mtu);
        }
        if synced {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DataplaneFspOwnerSyncApplied,
            );
        }
        synced
    }

    pub(in crate::node) fn remove_dataplane_fsp_owner(&mut self, node_addr: &NodeAddr) {
        self.dataplane
            .unregister_owner(OwnerId::fsp_node(*node_addr));
    }

    fn dataplane_fmp_owner_seed(&self, node_addr: &NodeAddr) -> Option<DataplaneFmpOwnerSeed> {
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
        let fmp_mmp_is_initiator = peer.fmp_mmp_is_initiator();
        let generation = peer.session_generation();
        let session_start_ms = Self::now_ms().wrapping_sub(u64::from(peer.session_elapsed_ms()));
        let source_peer = *peer.identity();
        let open = Arc::new(session.recv_cipher_clone()?);
        let seal = Arc::new(session.send_cipher_clone()?);
        let counter_authority = session.send_counter_authority();
        let mut routes = DataplaneLiveOwnerRoutes::new();
        routes.push_fmp_ingress(DataplaneLiveFmpIngressRoute::new(
            transport_id,
            receiver_idx,
            DataplaneIngressRoute::new(
                OwnerId::fmp_node(*node_addr),
                generation,
                OutputTarget::SessionIngress {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));
        let mut config = self
            .dataplane_owner_config(generation)
            .with_send_counter_authority(counter_authority)
            .with_fmp_session_start_ms(session_start_ms)
            .with_source_peer(source_peer);
        if let Some((receiver_idx, flags)) = fmp_send_headers {
            config = config.with_fmp_send_headers(receiver_idx, flags);
        }
        config = config.with_fmp_mmp(self.config.node.mmp.clone(), fmp_mmp_is_initiator);

        Some(DataplaneFmpOwnerSeed {
            owner: OwnerId::fmp_node(*node_addr),
            config,
            keys: OwnerCryptoKeys::new(open, seal),
            path: TransportPath::live(transport_id, remote_addr),
            routes,
        })
    }

    fn dataplane_fsp_owner_session_snapshot(
        session: &SessionEntry,
    ) -> Option<DataplaneFspOwnerSessionSnapshot> {
        let (open, seal) = session.fsp_crypto_keys()?;
        let counter_authority = session.send_counter_authority()?;
        let source_peer = session.remote_identity()?;
        let current_k_bit = session.current_k_bit();
        Some(DataplaneFspOwnerSessionSnapshot {
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

    fn dataplane_fsp_owner_seed_from_snapshot(
        &mut self,
        node_addr: &NodeAddr,
        snapshot: DataplaneFspOwnerSessionSnapshot,
        coords_warmup_remaining: u8,
    ) -> Option<DataplaneFspOwnerSeed> {
        let mut fsp_flags = 0;
        if snapshot.current_k_bit {
            fsp_flags |= crate::node::session_wire::FSP_FLAG_K;
        }
        let generation =
            Self::dataplane_generation_from_session_start_ms(snapshot.session_start_ms);
        let inner_flags = crate::protocol::FspInnerFlags { spin_bit: false }.to_byte();
        let coords_prefix = self.dataplane_fsp_coords_prefix(node_addr, coords_warmup_remaining);
        let route_update =
            self.dataplane_fsp_owner_routes(node_addr, generation, fsp_flags, inner_flags);

        let mut config = self
            .dataplane_owner_config(generation)
            .with_send_counter_authority(snapshot.counter_authority)
            .with_fsp_session_start_ms(snapshot.session_start_ms)
            .with_fsp_send_headers(fsp_flags, inner_flags)
            .with_fsp_epoch(snapshot.current_k_bit, snapshot.previous_draining_k_bit)
            .with_source_peer(snapshot.source_peer);
        config = config.with_fsp_mmp(self.config.node.session_mmp.clone(), snapshot.is_initiator);
        if coords_warmup_remaining > 0 {
            config = config.with_fsp_coords_warmup(coords_warmup_remaining, coords_prefix);
        }
        Some(DataplaneFspOwnerSeed {
            owner: OwnerId::fsp_node(*node_addr),
            config,
            keys: OwnerCryptoKeys::new(Arc::new(snapshot.open), Arc::new(snapshot.seal)),
            routes: route_update.routes,
            wrap: route_update.wrap,
            path: route_update.path,
            direct_path_mtu: route_update.direct_path_mtu,
        })
    }

    fn dataplane_fsp_coords_prefix(
        &self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> Vec<u8> {
        if coords_warmup_remaining == 0 {
            return Vec::new();
        }
        self.dataplane_fsp_coords_prefix_for_dest(node_addr)
    }

    fn dataplane_fsp_coords_prefix_for_dest(&self, node_addr: &NodeAddr) -> Vec<u8> {
        let src = self.tree_state.my_coords().clone();
        let dst = self.get_dest_coords(node_addr);
        let mut prefix = Vec::with_capacity(
            crate::protocol::coords_wire_size(&src) + crate::protocol::coords_wire_size(&dst),
        );
        crate::protocol::encode_coords(&src, &mut prefix);
        crate::protocol::encode_coords(&dst, &mut prefix);
        prefix
    }

    fn dataplane_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
        generation: u64,
        fsp_flags: u8,
        inner_flags: u8,
    ) -> DataplaneFspOwnerRouteUpdate {
        let owner = OwnerId::fsp_node(*node_addr);
        let Some(next_hop) = self.find_next_hop(node_addr).map(|peer| *peer.node_addr()) else {
            return DataplaneFspOwnerRouteUpdate {
                routes: DataplaneLiveOwnerRoutes::new(),
                wrap: None,
                path: None,
                direct_path_mtu: None,
                next_hop: None,
            };
        };
        let mut direct_path_mtu = None;
        let (wrap, path) = if next_hop == *node_addr {
            match self.dataplane_direct_fsp_path(node_addr) {
                Some((path, path_mtu)) => {
                    direct_path_mtu = Some(path_mtu);
                    (None, Some(path))
                }
                None => (self.dataplane_fsp_wrap_route_to(node_addr, next_hop), None),
            }
        } else {
            (self.dataplane_fsp_wrap_route_to(node_addr, next_hop), None)
        };
        if wrap.is_none() && path.is_none() {
            return DataplaneFspOwnerRouteUpdate {
                routes: DataplaneLiveOwnerRoutes::new(),
                wrap: None,
                path: None,
                direct_path_mtu: None,
                next_hop: Some(next_hop),
            };
        };
        let mut routes = DataplaneLiveOwnerRoutes::new();
        routes.push_fsp_ingress(DataplaneLiveFspIngressRoute::new(
            *node_addr,
            DataplaneIngressRoute::new(
                owner,
                generation,
                OutputTarget::SessionPayload {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));
        let tun = DataplaneTunOutboundRoute::fsp_ipv6_shim(
            owner,
            generation,
            PacketClass::Bulk,
            fsp_flags,
            inner_flags,
        );
        routes.push_tun_destination(DataplaneLiveTunRoute::new(
            *node_addr,
            DataplaneTunDestinationRoute::new(tun)
                .with_max_packet_len(self.dataplane_tun_max_packet_len(node_addr)),
        ));

        let mut endpoint =
            DataplaneEndpointDataRoute::fsp(owner, generation, fsp_flags, inner_flags);
        if direct_path_mtu.is_some() {
            endpoint = endpoint.with_direct_transport();
        }
        routes.push_endpoint_destination(DataplaneLiveEndpointRoute::new(*node_addr, endpoint));

        DataplaneFspOwnerRouteUpdate {
            routes,
            wrap,
            path,
            direct_path_mtu,
            next_hop: Some(next_hop),
        }
    }

    fn dataplane_direct_fsp_path(&self, dest_addr: &NodeAddr) -> Option<(TransportPath, u16)> {
        let peer = self.peers.get(dest_addr)?;
        let transport_id = peer.transport_id()?;
        let remote_addr = peer.current_addr()?.clone();
        let path_mtu = self
            .transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu());
        Some((TransportPath::live(transport_id, remote_addr), path_mtu))
    }

    fn dataplane_fsp_wrap_route_to(
        &mut self,
        dest_addr: &NodeAddr,
        next_hop: NodeAddr,
    ) -> Option<DataplaneFspWrapRoute> {
        let send_context = self.dataplane.fmp_owner_send_context(&next_hop)?;
        let active_path = self
            .dataplane
            .owner_active_path(OwnerId::fmp_node(next_hop))
            .ok()??;
        let transport_id = active_path.transport_id()?;
        let remote_addr = active_path.remote_addr()?.clone();
        let fmp_flags = send_context.flags();
        let path_mtu = self
            .transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu());
        let wrap = DataplaneFspWrapRoute::new(
            OwnerId::fmp_node(next_hop),
            send_context.generation(),
            send_context.receiver_idx(),
            *self.node_addr(),
            *dest_addr,
        )
        .with_fmp_flags(fmp_flags)
        .with_ttl(self.config.node.session.default_ttl)
        .with_path_mtu(path_mtu);
        Some(wrap)
    }

    fn dataplane_tun_max_packet_len(&self, dest_addr: &NodeAddr) -> usize {
        let effective_mtu = self.effective_ipv6_mtu() as usize;
        self.dataplane
            .fsp_owner_activity(dest_addr)
            .and_then(|activity| activity.current_path_mtu())
            .map(crate::upper::icmp::effective_ipv6_mtu)
            .map(usize::from)
            .filter(|path_ipv6_mtu| *path_ipv6_mtu < effective_mtu)
            .unwrap_or(effective_mtu)
    }

    fn dataplane_owner_in_flight_limit(&self) -> usize {
        self.config.node.limits.max_pending_inbound.max(1)
    }

    fn dataplane_owner_config(&self, generation: u64) -> OwnerConfig {
        let in_flight_limit = self.dataplane_owner_in_flight_limit();
        OwnerConfig::new(generation, in_flight_limit)
    }

    fn dataplane_generation_from_session_start_ms(session_start_ms: u64) -> u64 {
        session_start_ms.max(1)
    }

    fn dataplane_fmp_output_drop_error(
        &self,
        node_addr: NodeAddr,
        drop: &DataplaneOutputDrop,
    ) -> NodeError {
        match drop.reason() {
            DataplaneOutputError::MtuExceeded => NodeError::MtuExceeded {
                node_addr,
                packet_size: drop.payload_len(),
                mtu: self.dataplane_drop_path_mtu(drop),
            },
            DataplaneOutputError::NoRoute => {
                NodeError::LocalRouteUnavailable("dataplane transport route unavailable".into())
            }
            reason => NodeError::SendFailed {
                node_addr,
                reason: format!("dataplane transport output failed: {:?}", reason),
            },
        }
    }

    fn dataplane_drop_path_mtu(&self, drop: &DataplaneOutputDrop) -> u16 {
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

fn dataplane_fmp_link_class(plaintext: &[u8]) -> PacketClass {
    match plaintext
        .first()
        .and_then(|msg_type| LinkMessageType::from_byte(*msg_type))
    {
        Some(LinkMessageType::Heartbeat) => PacketClass::Liveness,
        Some(LinkMessageType::SenderReport | LinkMessageType::ReceiverReport) => PacketClass::Mmp,
        Some(LinkMessageType::SessionDatagram)
            if fmp_plaintext_is_bulk_session_datagram(plaintext) =>
        {
            PacketClass::Bulk
        }
        _ => PacketClass::Control,
    }
}

fn dataplane_fsp_control_class(msg_type: u8) -> PacketClass {
    match SessionMessageType::from_byte(msg_type) {
        Some(
            SessionMessageType::SenderReport
            | SessionMessageType::ReceiverReport
            | SessionMessageType::PathMtuNotification,
        ) => PacketClass::Mmp,
        _ => PacketClass::Control,
    }
}
