use super::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram;
use super::*;
use crate::dataplane::{
    ActivityTick, DataplaneDirectFspSource, DataplaneEndpointDataRoute, DataplaneFspSendReceipt,
    DataplaneFspWrapRoute, DataplaneIngressRoute, DataplaneLiveNodeTurn,
    DataplaneLiveOutboundFirsts, DataplaneLiveOwnerRoutes, DataplaneLiveTurnIo,
    DataplaneOutputDrop, DataplaneOutputError, DataplaneReceiveEpoch,
    DataplaneTransportSentReceipt, DataplaneTunOutboundRoute, OutboundPacket, OutputTarget,
    OwnerConfig, OwnerCryptoKeys, OwnerId, PacketClass, TransportPath,
};
use crate::node::session_wire::{FSP_PHASE_MSG2, FSP_PHASE_MSG3, FspCommonPrefix};
use crate::protocol::SessionMessageType;
use std::sync::atomic::{AtomicU64, Ordering};

const DATAPLANE_PENDING_OUTBOUND_FAST_CONTINUATION_TURNS: usize = 2;
const DATAPLANE_PENDING_OUTBOUND_CONTROL_CONTINUATION_TURNS: usize = 8;
const DATAPLANE_PENDING_OUTBOUND_COMPLETION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);
const DATAPLANE_DEFERRED_CONTROL_TURN_DRAIN_LIMIT: usize = 64;
static DATAPLANE_FMP_LINK_SEND_TOKEN: AtomicU64 = AtomicU64::new(1);

fn dataplane_static_udp_port_wildcard_addrs(
    addr: &str,
) -> Option<[crate::transport::TransportAddr; 2]> {
    if addr.parse::<std::net::SocketAddr>().is_ok() {
        return None;
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;

    Some([
        crate::transport::TransportAddr::from_string(&format!("0.0.0.0:{port}")),
        crate::transport::TransportAddr::from_string(&format!("[::]:{port}")),
    ])
}
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

enum DataplanePendingOutboundFailure {
    TurnFailed(DataplaneLiveNodeTurn),
    Stopped {
        turn: DataplaneLiveNodeTurn,
        reason: &'static str,
    },
    Exhausted(DataplaneLiveNodeTurn),
}

#[derive(Clone, Copy)]
struct DataplanePendingOutboundPolicy {
    continuation_turns: usize,
}

const DATAPLANE_PENDING_OUTBOUND_FAST_POLICY: DataplanePendingOutboundPolicy =
    DataplanePendingOutboundPolicy {
        continuation_turns: DATAPLANE_PENDING_OUTBOUND_FAST_CONTINUATION_TURNS,
    };
const DATAPLANE_PENDING_OUTBOUND_PATIENT_CONTROL_POLICY: DataplanePendingOutboundPolicy =
    DataplanePendingOutboundPolicy {
        continuation_turns: DATAPLANE_PENDING_OUTBOUND_CONTROL_CONTINUATION_TURNS,
    };

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
        let send_token = DATAPLANE_FMP_LINK_SEND_TOKEN.fetch_add(1, Ordering::Relaxed);

        let outbound = OutboundPacket::fmp(
            OwnerId::fmp_node(*node_addr),
            send_context.generation(),
            dataplane_fmp_link_class(plaintext),
            send_context.receiver_idx(),
            flags,
            crate::transport::PacketBuffer::new(plaintext.to_vec()),
        )
        .with_activity_tick(ActivityTick::new(Self::now_ms()))
        .with_send_token(send_token);
        let firsts = DataplaneLiveOutboundFirsts {
            initial_outbound: Some(outbound),
            collect_transport_sent_receipts: true,
            ..Default::default()
        };
        let pending_policy = dataplane_fmp_link_pending_policy(plaintext);
        let turn = self
            .pump_dataplane_pending_outbound_firsts(firsts, 0, 0, 1)
            .await;
        let (receipt, pending_turn) = match self
            .drive_dataplane_pending_outbound_owner_receipt(
                turn,
                OwnerId::fmp_node(*node_addr),
                send_token,
                pending_policy.continuation_turns,
            )
            .await
        {
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
        self.defer_dataplane_control_turn(pending_turn);
        let timestamp_ms = receipt
            .fmp_timestamp_ms
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "dataplane FMP timestamp missing".into(),
            })?;
        let bytes_sent = receipt.payload_len;
        self.dataplane.record_fmp_mmp_send_result(
            node_addr,
            receipt.counter,
            timestamp_ms,
            bytes_sent,
        );
        let _ = self
            .peers
            .record_fmp_send_bookkeeping(node_addr, bytes_sent);
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
        payloads: Vec<EndpointDataPayload>,
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
        let batch = NodeEndpointDataBatch::from_payloads(remote, payloads, None)
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
        self.send_dataplane_fsp_control_outbound(
            dest_addr,
            msg_type,
            None,
            payload,
            None,
            "FSP control message",
        )
        .await
    }

    pub(in crate::node) async fn send_dataplane_fsp_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let coords_prefix = self.dataplane_fsp_coords_prefix_for_dest(dest_addr);
        self.send_dataplane_fsp_control_outbound(
            dest_addr,
            SessionMessageType::CoordsWarmup.to_byte(),
            Some(crate::node::session_wire::FSP_FLAG_CP),
            &[],
            Some(coords_prefix),
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
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut empty_raw_ingress,
                0,
                firsts,
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut empty_endpoint_data_rx,
                    endpoint_limit,
                    tun_outbound_rx: &mut empty_tun_outbound_rx,
                    tun_limit,
                    endpoint_tx: &endpoint_tx,
                    transports: &self.transports,
                    crypto_limit,
                    transport_send_batch_packets: self.dataplane_transport_send_batch_packets,
                },
            )
            .await;
        Self::observe_dataplane_turn(&turn);
        turn
    }

    fn defer_dataplane_control_turn(&mut self, turn: DataplaneLiveNodeTurn) {
        if Self::dataplane_turn_has_control_side_effects(&turn) {
            self.deferred_dataplane_control_turns.push_back(turn);
        }
    }

    pub(in crate::node) async fn drain_deferred_dataplane_control_turns(&mut self) -> usize {
        let mut processed = 0usize;
        let mut turns = 0usize;
        while turns < DATAPLANE_DEFERRED_CONTROL_TURN_DRAIN_LIMIT {
            let Some(mut turn) = self.deferred_dataplane_control_turns.pop_front() else {
                break;
            };
            processed =
                processed.saturating_add(self.process_dataplane_control_ingress(&mut turn).await);
            turns = turns.saturating_add(1);
        }
        if !self.deferred_dataplane_control_turns.is_empty() {
            self.dataplane.readiness_notify().notify_one();
        }
        processed
    }

    fn dataplane_turn_has_control_side_effects(turn: &DataplaneLiveNodeTurn) -> bool {
        !turn.fmp_control_ingress().is_empty()
            || !turn.fmp_link_ingress().is_empty()
            || !turn.fsp_coord_warmups().is_empty()
            || !turn.fsp_local_session_ingress().is_empty()
            || turn.endpoint_data_packet_count() > 0
            || turn.fsp_session_ingress_count() > 0
            || !turn.raw_ingress_drops().is_empty()
            || !turn.tun_outbound_drops().is_empty()
            || !turn.endpoint_data_drops().is_empty()
            || !turn.output_drops().is_empty()
            || !turn.drops().is_empty()
    }

    async fn send_dataplane_fsp_control_outbound(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        fsp_flags_override: Option<u8>,
        payload: &[u8],
        coords_prefix: Option<Vec<u8>>,
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
        let activity_tick = ActivityTick::new(Self::now_ms());

        let mut outbound = OutboundPacket::fsp(
            OwnerId::fsp_node(*dest_addr),
            send_context.generation(),
            dataplane_fsp_control_class(msg_type),
            fsp_flags,
            crate::transport::PacketBuffer::new(payload.to_vec()),
        )
        .with_fsp_inner_header(msg_type, inner_flags)
        .with_activity_tick(activity_tick);
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
            .drive_dataplane_pending_outbound_turn(
                turn,
                collect_transport_sent_receipts,
                DATAPLANE_PENDING_OUTBOUND_FAST_POLICY.continuation_turns,
            )
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
        continuation_turns: usize,
    ) -> Result<DataplaneLiveNodeTurn, DataplanePendingOutboundFailure> {
        let mut awaiting_output = false;
        for continuation in 0..=continuation_turns {
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
            if needs_continuation {
                awaiting_output = true;
            }
            if deferred || (!needs_continuation && !awaiting_output) {
                let reason = if deferred {
                    "deferred without transport output"
                } else {
                    "made no transport output progress"
                };
                return Err(DataplanePendingOutboundFailure::Stopped { turn, reason });
            }
            if continuation == continuation_turns {
                return Err(DataplanePendingOutboundFailure::Exhausted(turn));
            }

            if summary.outputs() == 0 {
                self.wait_for_dataplane_completion().await;
            }
            self.defer_dataplane_control_turn(turn);
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

    async fn drive_dataplane_pending_outbound_owner_receipt(
        &mut self,
        mut turn: DataplaneLiveNodeTurn,
        owner: OwnerId,
        send_token: u64,
        continuation_turns: usize,
    ) -> Result<
        (DataplaneTransportSentReceipt, DataplaneLiveNodeTurn),
        DataplanePendingOutboundFailure,
    > {
        let mut awaiting_output = false;
        let mut idle_turns = 0usize;
        loop {
            if let Some(receipt) = Self::dataplane_sent_owner_receipt(&mut turn, owner, send_token)
            {
                return Ok((receipt, turn));
            }

            let summary = turn.summary();
            let deferred =
                turn.deferred_endpoint_data_batches_count() > 0 || turn.tun_deferred_packets() > 0;
            let failed = turn
                .drops()
                .iter()
                .any(|drop| drop.owner() == owner && drop.send_token() == Some(send_token))
                || turn
                    .output_drops()
                    .iter()
                    .any(|drop| drop.owner() == owner && drop.send_token() == Some(send_token));
            let needs_continuation = Self::dataplane_pending_outbound_needs_continuation(&turn);
            let made_progress =
                summary.has_activity() || turn.transport_sent() > 0 || turn.transport_dropped() > 0;

            if failed {
                return Err(DataplanePendingOutboundFailure::TurnFailed(turn));
            }
            if needs_continuation {
                awaiting_output = true;
            }
            if deferred {
                return Err(DataplanePendingOutboundFailure::Stopped {
                    turn,
                    reason: "deferred without transport output",
                });
            }
            if !needs_continuation && !awaiting_output && !made_progress {
                return Err(DataplanePendingOutboundFailure::Stopped {
                    turn,
                    reason: "made no transport output progress",
                });
            }
            if !made_progress {
                if idle_turns == continuation_turns {
                    return Err(DataplanePendingOutboundFailure::Exhausted(turn));
                }
                idle_turns = idle_turns.saturating_add(1);
            } else {
                idle_turns = 0;
            }

            if summary.outputs() == 0 {
                self.wait_for_dataplane_completion().await;
            }
            self.defer_dataplane_control_turn(turn);
            turn = self
                .pump_dataplane_pending_outbound_firsts(
                    DataplaneLiveOutboundFirsts {
                        collect_transport_sent_receipts: true,
                        ..Default::default()
                    },
                    0,
                    0,
                    1,
                )
                .await;
        }
    }

    async fn wait_for_dataplane_completion(&self) {
        let notify = self.dataplane.readiness_notify();
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
            if transport_receipt.owner == owner {
                sent_receipt = Some(DataplaneFspSendReceipt {
                    owner,
                    counter: transport_receipt.counter,
                });
            } else if let Some(receipt) = transport_receipt.fsp_send_receipt
                && receipt.owner == owner
            {
                sent_receipt = Some(receipt);
            }
        }
        sent_receipt
    }

    fn dataplane_sent_owner_receipt(
        turn: &mut DataplaneLiveNodeTurn,
        owner: OwnerId,
        send_token: u64,
    ) -> Option<DataplaneTransportSentReceipt> {
        turn.take_transport_sent_receipts()
            .into_iter()
            .find(|receipt| receipt.owner == owner && receipt.send_token == Some(send_token))
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
            self.requeue_deferred_endpoint_data_batch(batch);
            processed += 1;
        }
        processed
    }

    pub(in crate::node) fn sync_dataplane_fmp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        let Some(seed) = self.dataplane_fmp_owner_seed(node_addr) else {
            self.mark_dataplane_direct_fsp_sources_dirty();
            self.remove_dataplane_fmp_owner(node_addr);
            self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(node_addr);
            return false;
        };

        self.dataplane
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let synced = self
            .dataplane
            .install_owner_fmp_session_routes(
                seed.owner,
                seed.config,
                seed.keys,
                seed.path,
                seed.routes,
            )
            .is_ok();
        if synced {
            self.mark_dataplane_direct_fsp_sources_dirty();
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
        let route_ready = update.wrap.is_some() || update.path.is_some();
        let next_hop_ready = update.path.is_some()
            || update
                .next_hop
                .is_some_and(|next_hop| self.dataplane_has_fmp_owner(&next_hop));
        if !(route_ready && next_hop_ready)
            && self
                .dataplane
                .fsp_owner_next_hop(node_addr)
                .is_some_and(|next_hop| self.dataplane_has_fmp_owner(&next_hop))
        {
            return false;
        }
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

    pub(in crate::node) fn install_dataplane_fmp_pending_receive_epoch(
        &mut self,
        node_addr: &NodeAddr,
        pending_k_bit: bool,
        open: ring::aead::LessSafeKey,
    ) -> bool {
        self.dataplane
            .install_owner_fmp_pending_receive_epoch(
                OwnerId::fmp_node(*node_addr),
                pending_k_bit,
                std::sync::Arc::new(open),
            )
            .is_ok()
    }

    pub(in crate::node) fn promote_dataplane_authenticated_pending_fmp_epoch(
        &mut self,
        node_addr: &NodeAddr,
        received_k_bit: bool,
    ) -> bool {
        if !self
            .dataplane
            .fmp_owner_has_pending_receive_epoch(node_addr, received_k_bit)
        {
            return false;
        }
        let Some(previous_index) = self
            .peers
            .get_mut(node_addr)
            .and_then(|peer| peer.handle_peer_kbit_flip())
        else {
            return false;
        };
        let _ = previous_index;
        self.ensure_current_session_index_registered(
            node_addr,
            "responder authenticated FMP rekey cutover",
        );
        self.sync_dataplane_fmp_owner(node_addr)
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

    pub(in crate::node) fn mark_dataplane_direct_fsp_sources_dirty(&mut self) {
        self.dataplane_direct_fsp_sources_dirty = true;
    }

    pub(in crate::node) fn dataplane_direct_fsp_sources_for_rx_turn(
        &mut self,
    ) -> crate::dataplane::DataplaneDirectFspSources {
        if self.dataplane_direct_fsp_sources_dirty {
            let sources = self.dataplane_direct_fsp_sources();
            self.dataplane
                .set_established_fast_ingress_direct_fsp_sources(sources.clone());
            self.dataplane_direct_fsp_sources = sources;
            self.dataplane_direct_fsp_sources_dirty = false;
        }
        self.dataplane_direct_fsp_sources.clone()
    }

    pub(in crate::node) fn dataplane_direct_fsp_sources(
        &self,
    ) -> crate::dataplane::DataplaneDirectFspSources {
        let mut sources = Vec::new();
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
            sources.push((
                transport_id,
                remote_addr,
                DataplaneDirectFspSource {
                    source_addr: *node_addr,
                    path_mtu,
                },
            ));

            for static_addr in
                self.dataplane_configured_static_udp_source_addrs(node_addr, transport_id)
            {
                let path_mtu = self
                    .transports
                    .get(&transport_id)
                    .map(|transport| transport.link_mtu(&static_addr))
                    .unwrap_or(path_mtu);
                sources.push((
                    transport_id,
                    static_addr,
                    DataplaneDirectFspSource {
                        source_addr: *node_addr,
                        path_mtu,
                    },
                ));
            }
        }
        crate::dataplane::dataplane_direct_fsp_sources_from_exact(sources)
    }

    fn dataplane_configured_static_udp_source_addrs(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: crate::transport::TransportId,
    ) -> Vec<crate::transport::TransportAddr> {
        let Some(peer_config) = self.configured_peer(peer_node_addr) else {
            return Vec::new();
        };
        let Some(transport) = self.transports.get(&transport_id) else {
            return Vec::new();
        };
        if transport.transport_type().name != "udp" {
            return Vec::new();
        }

        let mut addrs = Vec::new();
        for candidate in &peer_config.addresses {
            if !candidate.is_configured()
                || !candidate.transport.eq_ignore_ascii_case("udp")
                || candidate.addr.eq_ignore_ascii_case("nat")
            {
                continue;
            }

            let candidate_addr = crate::transport::TransportAddr::from_string(&candidate.addr);
            let mut added_resolved_addr = false;
            if let Some(socket_addr) = transport.resolved_udp_socket_addr_if_cached(&candidate_addr)
                && let Some((candidate_transport_id, _)) =
                    self.find_udp_transport_for_remote_addr(socket_addr, candidate.provenance)
                && candidate_transport_id == transport_id
            {
                let resolved_addr = crate::transport::TransportAddr::from_socket_addr(socket_addr);
                if !addrs.iter().any(|existing| existing == &resolved_addr) {
                    addrs.push(resolved_addr);
                }
                added_resolved_addr = true;
            }
            if added_resolved_addr {
                continue;
            }

            if let Some(wildcard_addrs) = dataplane_static_udp_port_wildcard_addrs(&candidate.addr)
            {
                for wildcard_addr in wildcard_addrs {
                    if !addrs.iter().any(|existing| existing == &wildcard_addr) {
                        addrs.push(wildcard_addr);
                    }
                }
            }
        }
        addrs
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
        let mut receive_indices =
            vec![(transport_id, receiver_idx, DataplaneReceiveEpoch::Current)];
        for (route_transport_id, index, epoch) in [
            (
                peer.pending_our_index().map(|index| (transport_id, index)),
                DataplaneReceiveEpoch::Pending,
            ),
            (
                peer.previous_our_index()
                    .map(|index| (peer.previous_transport_id().unwrap_or(transport_id), index)),
                DataplaneReceiveEpoch::Previous,
            ),
        ]
        .into_iter()
        .filter_map(|(indexed_transport, epoch)| {
            indexed_transport
                .map(|(route_transport_id, index)| (route_transport_id, index.as_u32(), epoch))
        }) {
            if !receive_indices
                .iter()
                .any(|(existing_transport, existing_index, _)| {
                    *existing_transport == route_transport_id && *existing_index == index
                })
            {
                receive_indices.push((route_transport_id, index, epoch));
            }
        }
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
        let current_k_bit = peer.current_k_bit();
        let previous_draining_k_bit = peer.is_draining().then_some(!current_k_bit);
        let open = Arc::new(session.recv_cipher_clone()?);
        let seal = Arc::new(session.send_cipher_clone()?);
        let counter_authority = session.send_counter_authority();
        let mut routes = DataplaneLiveOwnerRoutes::new();
        for (route_transport_id, receiver_idx, receive_epoch) in receive_indices.iter().copied() {
            routes.push_fmp_ingress(
                route_transport_id,
                receiver_idx,
                DataplaneIngressRoute::new(
                    OwnerId::fmp_node(*node_addr),
                    generation,
                    OutputTarget::SessionIngress {
                        local_addr: *self.node_addr(),
                    },
                )
                .with_class(PacketClass::Bulk)
                .with_receive_epoch(receive_epoch),
            );
        }
        let mut config = self
            .dataplane_owner_config(generation)
            .with_send_counter_authority(counter_authority)
            .with_fmp_session_start_ms(session_start_ms)
            .with_fmp_epoch(current_k_bit, previous_draining_k_bit)
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
        let generation = snapshot.session_start_ms.max(1);
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
        routes.push_fsp_ingress(
            *node_addr,
            DataplaneIngressRoute::new(
                owner,
                generation,
                OutputTarget::SessionPayload {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        );
        let tun = DataplaneTunOutboundRoute::fsp_ipv6_shim(
            owner,
            generation,
            PacketClass::Bulk,
            fsp_flags,
            inner_flags,
        )
        .with_max_packet_len(self.dataplane_tun_max_packet_len(node_addr));
        routes.push_tun_destination(*node_addr, tun);

        let mut endpoint =
            DataplaneEndpointDataRoute::fsp(owner, generation, fsp_flags, inner_flags);
        if direct_path_mtu.is_some() {
            endpoint = endpoint.with_direct_transport();
        }
        routes.push_endpoint_destination(*node_addr, endpoint);

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
        let remote_addr = peer.send_addr()?.clone();
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
        let transport_id = active_path.transport_id;
        let remote_addr = active_path.remote_addr.clone();
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

    fn dataplane_owner_config(&self, generation: u64) -> OwnerConfig {
        let in_flight_limit = self.config.node.limits.max_pending_inbound.max(1);
        OwnerConfig::new(generation, in_flight_limit)
    }

    fn dataplane_fmp_output_drop_error(
        &self,
        node_addr: NodeAddr,
        drop: &DataplaneOutputDrop,
    ) -> NodeError {
        match drop.reason() {
            DataplaneOutputError::MtuExceeded { mtu } => NodeError::MtuExceeded {
                node_addr,
                packet_size: drop.payload_len(),
                mtu,
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

fn dataplane_fmp_link_pending_policy(plaintext: &[u8]) -> DataplanePendingOutboundPolicy {
    if fmp_plaintext_is_fsp_handshake_response_datagram(plaintext) {
        DATAPLANE_PENDING_OUTBOUND_PATIENT_CONTROL_POLICY
    } else {
        DATAPLANE_PENDING_OUTBOUND_FAST_POLICY
    }
}

fn fmp_plaintext_is_fsp_handshake_response_datagram(plaintext: &[u8]) -> bool {
    if plaintext
        .first()
        .is_none_or(|ty| *ty != LinkMessageType::SessionDatagram.to_byte())
    {
        return false;
    }
    let Some(fsp_payload) = plaintext.get(crate::protocol::SESSION_DATAGRAM_HEADER_SIZE..) else {
        return false;
    };
    FspCommonPrefix::parse(fsp_payload)
        .is_some_and(|prefix| matches!(prefix.phase, FSP_PHASE_MSG2 | FSP_PHASE_MSG3))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::{
        DataplaneLiveOutboundFirsts, DataplaneRawIngress, DataplaneRawIngressDropReason,
        PacketProtocol,
    };
    use crate::peer::{ActivePeer, ActivePeerSession};
    use crate::transport::{LinkStats, ReceivedPacket};
    use crate::utils::index::SessionIndex;
    use std::collections::VecDeque;

    fn test_fmp_session(
        local: &Identity,
        peer: &Identity,
        local_epoch: [u8; 8],
        peer_epoch: [u8; 8],
    ) -> crate::noise::NoiseSession {
        let mut initiator =
            crate::noise::HandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
        let mut responder = crate::noise::HandshakeState::new_responder(peer.keypair());
        initiator.set_local_epoch(local_epoch);
        responder.set_local_epoch(peer_epoch);
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();
        initiator.into_session().unwrap()
    }

    fn invalid_fmp_frame(receiver_idx: SessionIndex, counter: u64, flags: u8) -> Vec<u8> {
        let mut frame =
            Vec::with_capacity(crate::node::wire::ESTABLISHED_HEADER_SIZE + crate::noise::TAG_SIZE);
        frame.push(0);
        frame.push(flags);
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&receiver_idx.to_le_bytes());
        frame.extend_from_slice(&counter.to_le_bytes());
        frame.extend_from_slice(&[0; crate::noise::TAG_SIZE]);
        frame
    }

    fn session_datagram_plaintext_with_fsp_prefix(prefix: [u8; 4]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(crate::protocol::SESSION_DATAGRAM_HEADER_SIZE + 4);
        plaintext.push(LinkMessageType::SessionDatagram.to_byte());
        plaintext.push(64);
        plaintext.extend_from_slice(&1280u16.to_le_bytes());
        plaintext.extend_from_slice(&[0; 16]);
        plaintext.extend_from_slice(&[1; 16]);
        plaintext.extend_from_slice(&prefix);
        plaintext
    }

    async fn insert_started_udp_transport(node: &mut Node, transport_id: TransportId) {
        let (packet_tx, packet_rx) = crate::transport::packet_channel(64);
        node.packet_tx = Some(packet_tx.clone());
        node.packet_rx = Some(packet_rx);
        let mut udp = UdpTransport::new(
            transport_id,
            Some("test-udp".to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }

    fn insert_test_active_peer(
        node: &mut Node,
        peer_identity_full: &Identity,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        link_id: u64,
        index_base: u32,
        epoch_byte: u8,
    ) -> NodeAddr {
        let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
        let peer_addr = *peer_identity.node_addr();
        let session = test_fmp_session(
            &node.identity,
            peer_identity_full,
            node.startup_epoch,
            [epoch_byte; 8],
        );
        let peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(link_id),
            1_000,
            ActivePeerSession {
                session,
                our_index: SessionIndex::new(index_base),
                their_index: SessionIndex::new(index_base + 1),
                transport_id,
                current_addr: remote_addr,
                link_stats: LinkStats::new(),
                is_initiator: true,
                remote_epoch: Some([epoch_byte; 8]),
            },
        );
        node.peers.insert(peer_addr, peer);
        peer_addr
    }

    #[test]
    fn direct_fsp_send_path_uses_preferred_addr_but_source_map_stays_observed() {
        let mut node = Node::new(Config::new()).unwrap();
        let peer_identity_full = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
        let peer_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(7);
        let observed_addr = TransportAddr::from_string("127.0.0.1:7000");
        let preferred_send_addr = TransportAddr::from_string("127.0.0.1:7001");
        let session = test_fmp_session(
            &node.identity,
            &peer_identity_full,
            node.startup_epoch,
            [0x02; 8],
        );
        let mut peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(7),
            1_000,
            ActivePeerSession {
                session,
                our_index: SessionIndex::new(10),
                their_index: SessionIndex::new(11),
                transport_id,
                current_addr: observed_addr.clone(),
                link_stats: LinkStats::new(),
                is_initiator: true,
                remote_epoch: Some([0x02; 8]),
            },
        );
        peer.set_preferred_send_addr(preferred_send_addr.clone());
        node.peers.insert(peer_addr, peer);

        let (path, _) = node.dataplane_direct_fsp_path(&peer_addr).unwrap();
        assert_eq!(
            path,
            TransportPath::live(transport_id, preferred_send_addr.clone())
        );

        let sources = node.dataplane_direct_fsp_sources();
        assert!(
            sources
                .get(&transport_id)
                .is_some_and(|sources| sources.exact.contains_key(&observed_addr)),
            "direct FSP ingress classification should stay keyed by the authenticated observed source"
        );
        assert!(
            !sources
                .get(&transport_id)
                .is_some_and(|sources| sources.exact.contains_key(&preferred_send_addr)),
            "preferred outbound target must not replace the receive-source classifier"
        );
    }

    #[tokio::test]
    async fn direct_fsp_source_map_admits_unique_static_udp_and_rejects_ambiguity() {
        let mut node = Node::new(Config::new()).unwrap();
        let transport_id = TransportId::new(7);
        insert_started_udp_transport(&mut node, transport_id).await;

        let peer_one_full = Identity::generate();
        let peer_one = PeerIdentity::from_pubkey_full(peer_one_full.pubkey_full());
        let peer_two_full = Identity::generate();
        let peer_two = PeerIdentity::from_pubkey_full(peer_two_full.pubkey_full());
        let observed_one = TransportAddr::from_string("127.0.0.1:7100");
        let observed_two = TransportAddr::from_string("127.0.0.1:7200");
        let unique_static = TransportAddr::from_string("127.0.0.1:7001");
        let unique_hostname_wildcard = TransportAddr::from_string("0.0.0.0:7002");
        let shared_static = TransportAddr::from_string("127.0.0.1:7300");
        let shared_hostname_wildcard = TransportAddr::from_string("0.0.0.0:7301");
        let peer_one_addr = insert_test_active_peer(
            &mut node,
            &peer_one_full,
            transport_id,
            observed_one.clone(),
            8,
            30,
            0x04,
        );
        let peer_two_addr = insert_test_active_peer(
            &mut node,
            &peer_two_full,
            transport_id,
            observed_two.clone(),
            9,
            40,
            0x05,
        );
        node.config.peers = vec![
            crate::config::PeerConfig::new(peer_one.npub(), "udp", "127.0.0.1:7001")
                .with_address(crate::config::PeerAddress::new(
                    "udp",
                    "peer-one.local:7002",
                ))
                .with_address(crate::config::PeerAddress::new("udp", "127.0.0.1:7300"))
                .with_address(crate::config::PeerAddress::new(
                    "udp",
                    "peer-one.local:7301",
                )),
            crate::config::PeerConfig::new(peer_two.npub(), "udp", "127.0.0.1:7300").with_address(
                crate::config::PeerAddress::new("udp", "peer-two.local:7301"),
            ),
        ];
        node.configured_peer_send_weights = ConfiguredPeerSendWeights::from_config(&node.config);

        let sources = node.dataplane_direct_fsp_sources();
        let sources = sources.get(&transport_id).expect("UDP source map");
        assert_eq!(
            sources
                .exact
                .get(&observed_one)
                .map(|source| source.source_addr),
            Some(peer_one_addr)
        );
        assert_eq!(
            sources
                .exact
                .get(&observed_two)
                .map(|source| source.source_addr),
            Some(peer_two_addr)
        );
        assert_eq!(
            sources
                .exact
                .get(&unique_static)
                .map(|source| source.source_addr),
            Some(peer_one_addr),
            "configured numeric static source should be admitted"
        );
        assert_eq!(
            sources
                .exact
                .get(&unique_hostname_wildcard)
                .map(|source| source.source_addr),
            Some(peer_one_addr),
            "unresolved hostname source port should be admitted when unique"
        );
        assert!(
            !sources.exact.contains_key(&shared_static),
            "ambiguous configured static UDP tuples must not be assigned to an arbitrary peer"
        );
        assert!(
            !sources.exact.contains_key(&shared_hostname_wildcard),
            "ambiguous configured static UDP hostname ports must not be assigned to an arbitrary peer"
        );

        for transport in node.transports.values_mut() {
            transport.stop().await.ok();
        }
    }

    #[test]
    fn fmp_pending_policy_is_patient_only_for_fsp_handshake_responses() {
        let msg1 = session_datagram_plaintext_with_fsp_prefix(
            crate::node::session_wire::build_fsp_handshake_prefix(
                crate::node::session_wire::FSP_PHASE_MSG1,
                0,
            ),
        );
        let msg2 = session_datagram_plaintext_with_fsp_prefix(
            crate::node::session_wire::build_fsp_handshake_prefix(
                crate::node::session_wire::FSP_PHASE_MSG2,
                0,
            ),
        );
        let msg3 = session_datagram_plaintext_with_fsp_prefix(
            crate::node::session_wire::build_fsp_handshake_prefix(
                crate::node::session_wire::FSP_PHASE_MSG3,
                0,
            ),
        );
        let established = session_datagram_plaintext_with_fsp_prefix([
            crate::node::session_wire::FSP_VERSION << 4,
            0,
            0,
            0,
        ]);

        assert_eq!(
            dataplane_fmp_link_pending_policy(&msg1).continuation_turns,
            DATAPLANE_PENDING_OUTBOUND_FAST_CONTINUATION_TURNS
        );
        assert_eq!(
            dataplane_fmp_link_pending_policy(&msg2).continuation_turns,
            DATAPLANE_PENDING_OUTBOUND_CONTROL_CONTINUATION_TURNS
        );
        assert_eq!(
            dataplane_fmp_link_pending_policy(&msg3).continuation_turns,
            DATAPLANE_PENDING_OUTBOUND_CONTROL_CONTINUATION_TURNS
        );
        assert_eq!(
            dataplane_fmp_link_pending_policy(&established).continuation_turns,
            DATAPLANE_PENDING_OUTBOUND_FAST_CONTINUATION_TURNS
        );
    }

    #[tokio::test]
    async fn fmp_owner_sync_routes_current_pending_and_previous_receive_indices() {
        let mut node = Node::new(Config::new()).unwrap();
        let peer_identity_full = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
        let peer_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(77);
        let remote_addr = TransportAddr::from_string("127.0.0.1:7777");
        let preferred_send_addr = TransportAddr::from_string("127.0.0.1:8888");
        let previous_index = SessionIndex::new(10);
        let current_index = SessionIndex::new(11);
        let pending_index = SessionIndex::new(12);

        let current_session =
            test_fmp_session(&node.identity, &peer_identity_full, [0x01; 8], [0x02; 8]);
        let mut peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(77),
            1_000,
            ActivePeerSession {
                session: current_session,
                our_index: previous_index,
                their_index: SessionIndex::new(20),
                transport_id,
                current_addr: remote_addr.clone(),
                link_stats: LinkStats::new(),
                is_initiator: true,
                remote_epoch: Some([0x02; 8]),
            },
        );
        let first_pending =
            test_fmp_session(&node.identity, &peer_identity_full, [0x03; 8], [0x04; 8]);
        peer.set_pending_session(first_pending, current_index, SessionIndex::new(21), false);
        assert_eq!(peer.handle_peer_kbit_flip(), Some(previous_index));
        let second_pending =
            test_fmp_session(&node.identity, &peer_identity_full, [0x05; 8], [0x06; 8]);
        peer.set_pending_session(second_pending, pending_index, SessionIndex::new(22), false);
        peer.set_preferred_send_addr(preferred_send_addr.clone());
        assert_eq!(peer.our_index(), Some(current_index));
        assert_eq!(peer.previous_our_index(), Some(previous_index));
        assert_eq!(peer.pending_our_index(), Some(pending_index));
        node.peers.insert(peer_addr, peer);

        assert!(node.sync_dataplane_fmp_owner(&peer_addr));
        assert_eq!(
            node.dataplane
                .owner_active_path(OwnerId::fmp_node(peer_addr)),
            Ok(Some(TransportPath::live(transport_id, remote_addr.clone()))),
            "outbound FMP control stays on the authenticated observed path; preferred_send_addr is only for direct endpoint data"
        );

        let mut raw = VecDeque::from([
            DataplaneRawIngress::from_received(
                PacketProtocol::Fmp,
                TransportPath::live(transport_id, remote_addr.clone()),
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    crate::transport::PacketBuffer::new(invalid_fmp_frame(
                        current_index,
                        1,
                        crate::node::wire::FLAG_KEY_EPOCH,
                    )),
                    1,
                ),
            ),
            DataplaneRawIngress::from_received(
                PacketProtocol::Fmp,
                TransportPath::live(transport_id, remote_addr.clone()),
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    crate::transport::PacketBuffer::new(invalid_fmp_frame(previous_index, 2, 0)),
                    2,
                ),
            ),
            DataplaneRawIngress::from_received(
                PacketProtocol::Fmp,
                TransportPath::live(transport_id, remote_addr.clone()),
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr,
                    crate::transport::PacketBuffer::new(invalid_fmp_frame(pending_index, 3, 0)),
                    3,
                ),
            ),
        ]);
        let (endpoint_tx, endpoint_rx) = EndpointEventSender::channel(1);
        drop(endpoint_rx);
        let (_, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        let turn = node
            .dataplane
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut raw,
                3,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_tx,
                    transports: &node.transports,
                    crypto_limit: 3,
                    transport_send_batch_packets: node.dataplane_transport_send_batch_packets,
                },
            )
            .await;

        assert_eq!(turn.summary().inbound_admitted(), 3);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(
            !turn
                .raw_ingress_drops()
                .iter()
                .any(|drop| drop.reason() == DataplaneRawIngressDropReason::Unrouted)
        );
    }
}
