use super::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram;
use super::*;
use crate::dataplane::{
    ActivityTick, DataplaneDirectFspSource, DataplaneEndpointDataRoute, DataplaneFspWrapRoute,
    DataplaneIngressRoute, DataplaneLiveNodeTurn, DataplaneLiveOutboundFirsts,
    DataplaneLiveOwnerRoutes, DataplaneLiveTurnIo, DataplaneOutputDrop, DataplaneOutputError,
    DataplaneReceiveEpoch, DataplaneTransportSentReceipt, DataplaneTunOutboundRoute,
    OutboundPacket, OutputTarget, OwnerConfig, OwnerCryptoKeys, OwnerId, PacketClass,
    TransportPath,
};
use crate::protocol::SessionMessageType;
use std::sync::atomic::{AtomicU64, Ordering};

const DATAPLANE_PENDING_OUTBOUND_FAST_CONTINUATION_TURNS: usize = 2;
const DATAPLANE_PENDING_OUTBOUND_CONTROL_CONTINUATION_TURNS: usize = 8;
const DATAPLANE_PENDING_OUTBOUND_CONTROL_CRYPTO_LIMIT: usize = 64;
const DATAPLANE_PENDING_OUTBOUND_COMPLETION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);
const DATAPLANE_DEFERRED_CONTROL_TURN_DRAIN_LIMIT: usize = 64;
static DATAPLANE_SEND_TOKEN: AtomicU64 = AtomicU64::new(1);

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
    crypto_limit: usize,
}

struct DataplanePendingSendTokenReceipts {
    send_token: u64,
    remaining: usize,
}

impl DataplanePendingSendTokenReceipts {
    fn new(send_token: u64, expected: usize) -> Self {
        Self {
            send_token,
            remaining: expected,
        }
    }

    fn consume(
        &mut self,
        receipts: impl IntoIterator<Item = DataplaneTransportSentReceipt>,
    ) -> Option<DataplaneTransportSentReceipt> {
        // Receipt collection is enabled only for the synchronous caller's turns.
        // Non-matching receipts are observational bookkeeping for unrelated
        // background output, so consume them without acknowledging this batch.
        let mut completed_receipt = None;
        for receipt in receipts {
            if receipt.send_token == Some(self.send_token) {
                self.remaining = self.remaining.saturating_sub(1);
                completed_receipt = Some(receipt);
            }
        }
        (self.remaining == 0).then_some(completed_receipt).flatten()
    }
}

const DATAPLANE_PENDING_OUTBOUND_FAST_POLICY: DataplanePendingOutboundPolicy =
    DataplanePendingOutboundPolicy {
        continuation_turns: DATAPLANE_PENDING_OUTBOUND_FAST_CONTINUATION_TURNS,
        crypto_limit: 1,
    };
const DATAPLANE_PENDING_OUTBOUND_PATIENT_CONTROL_POLICY: DataplanePendingOutboundPolicy =
    DataplanePendingOutboundPolicy {
        continuation_turns: DATAPLANE_PENDING_OUTBOUND_CONTROL_CONTINUATION_TURNS,
        crypto_limit: DATAPLANE_PENDING_OUTBOUND_CONTROL_CRYPTO_LIMIT,
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
        let send_token = DATAPLANE_SEND_TOKEN.fetch_add(1, Ordering::Relaxed);

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
            .drive_dataplane_pending_outbound_token_receipts(
                turn,
                send_token,
                1,
                pending_policy.continuation_turns,
                pending_policy.crypto_limit,
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
                if let Some(drop) = failure_turn
                    .output_drops()
                    .iter()
                    .find(|drop| drop.send_token() == Some(send_token))
                {
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

    pub(in crate::node) fn prepare_dataplane_fmp_link_outbound(
        &self,
        node_addr: NodeAddr,
        plaintext: crate::transport::PacketBuffer,
        ce_flag: bool,
        activity_tick: ActivityTick,
    ) -> Result<(OutboundPacket, u64), NodeError> {
        if !self.dataplane_has_fmp_owner(&node_addr) {
            return if self.peers.get(&node_addr).is_none() {
                Err(NodeError::PeerNotFound(node_addr))
            } else {
                Err(NodeError::SendFailed {
                    node_addr,
                    reason: "dataplane FMP owner not registered".into(),
                })
            };
        }
        let Some(send_context) = self.dataplane.fmp_owner_send_context(&node_addr) else {
            return Err(NodeError::SendFailed {
                node_addr,
                reason: "dataplane FMP send context unavailable".into(),
            });
        };
        if self.peers.get(&node_addr).is_none() {
            return Err(NodeError::PeerNotFound(node_addr));
        }

        let mut flags = send_context.flags();
        if ce_flag {
            flags |= FLAG_CE;
        }
        let send_token = DATAPLANE_SEND_TOKEN.fetch_add(1, Ordering::Relaxed);
        let packet = OutboundPacket::fmp(
            OwnerId::fmp_node(node_addr),
            send_context.generation(),
            dataplane_fmp_link_class(plaintext.as_slice()),
            send_context.receiver_idx(),
            flags,
            plaintext,
        )
        .with_activity_tick(activity_tick)
        .with_send_token(send_token);
        Ok((packet, send_token))
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
        self.finish_dataplane_pending_outbound_turn(dest_addr, "queued TUN packet", turn)
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
        let send_token = DATAPLANE_SEND_TOKEN.fetch_add(1, Ordering::Relaxed);
        let batch = NodeEndpointDataBatch::from_payloads(remote, payloads, None)
            .expect("checked pending endpoint payload batch")
            .with_send_token(send_token);
        let firsts = DataplaneLiveOutboundFirsts {
            endpoint_data_batch: Some(batch),
            collect_transport_sent_receipts: true,
            ..Default::default()
        };
        let turn = self
            .pump_dataplane_pending_outbound_firsts(firsts, payload_count, 0, payload_count)
            .await;
        let result = self
            .drive_dataplane_pending_outbound_token_receipts(
                turn,
                send_token,
                payload_count,
                DATAPLANE_PENDING_OUTBOUND_FAST_POLICY.continuation_turns,
                DATAPLANE_PENDING_OUTBOUND_FAST_POLICY.crypto_limit,
            )
            .await;
        self.process_dataplane_pending_outbound_bookkeeping().await;
        result.map(|_| ()).map_err(|failure| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: Self::dataplane_pending_outbound_failure_from_stop(
                "queued endpoint data",
                &failure,
            ),
        })
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

    pub(in crate::node) async fn pump_dataplane_pending_outbound_firsts(
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
        let mut turn = self
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
        self.collect_deferred_session_forward_terminals(&mut turn);
        turn
    }

    pub(in crate::node) fn defer_dataplane_control_turn(&mut self, turn: DataplaneLiveNodeTurn) {
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
            processed = processed
                .saturating_add(Box::pin(self.process_dataplane_control_ingress(&mut turn)).await);
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

        let send_token = DATAPLANE_SEND_TOKEN.fetch_add(1, Ordering::Relaxed);
        let mut outbound = OutboundPacket::fsp(
            OwnerId::fsp_node(*dest_addr),
            send_context.generation(),
            dataplane_fsp_control_class(msg_type),
            fsp_flags,
            crate::transport::PacketBuffer::new(payload.to_vec()),
        )
        .with_fsp_inner_header(msg_type, inner_flags)
        .with_activity_tick(activity_tick)
        .with_send_token(send_token);
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
        let result = self
            .drive_dataplane_pending_outbound_token_receipts(
                turn,
                send_token,
                1,
                DATAPLANE_PENDING_OUTBOUND_PATIENT_CONTROL_POLICY.continuation_turns,
                DATAPLANE_PENDING_OUTBOUND_PATIENT_CONTROL_POLICY.crypto_limit,
            )
            .await;
        self.process_dataplane_pending_outbound_bookkeeping().await;
        let (_, turn) = match result {
            Ok(completed) => completed,
            Err(failure) => {
                let error = NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: Self::dataplane_pending_outbound_failure_from_stop(label, &failure),
                };
                self.record_route_failure(*dest_addr, next_hop);
                self.recover_direct_payload_send_failure(*dest_addr, next_hop, &error);
                return Err(error);
            }
        };
        self.defer_dataplane_control_turn(turn);
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
    ) -> Result<DataplaneLiveNodeTurn, NodeError> {
        let result = self
            .drive_dataplane_pending_outbound_turn(
                turn,
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
                    DataplaneLiveOutboundFirsts::default(),
                    0,
                    0,
                    1,
                )
                .await;
        }

        unreachable!("bounded pending outbound continuation loop must return")
    }

    async fn drive_dataplane_pending_outbound_token_receipts(
        &mut self,
        mut turn: DataplaneLiveNodeTurn,
        send_token: u64,
        expected_receipts: usize,
        continuation_turns: usize,
        continuation_crypto_limit: usize,
    ) -> Result<
        (DataplaneTransportSentReceipt, DataplaneLiveNodeTurn),
        DataplanePendingOutboundFailure,
    > {
        let mut pending = DataplanePendingSendTokenReceipts::new(send_token, expected_receipts);
        for continuation in 0..=continuation_turns {
            if let Some(receipt) = pending.consume(turn.take_transport_sent_receipts()) {
                return Ok((receipt, turn));
            }

            let summary = turn.summary();
            let deferred = turn.deferred_endpoint_data_batches_count() > 0;
            let failed = turn
                .drops()
                .iter()
                .any(|drop| drop.send_token() == Some(send_token))
                || turn
                    .output_drops()
                    .iter()
                    .any(|drop| drop.send_token() == Some(send_token));

            if failed {
                return Err(DataplanePendingOutboundFailure::TurnFailed(turn));
            }
            if deferred {
                return Err(DataplanePendingOutboundFailure::Stopped {
                    turn,
                    reason: "deferred without transport output",
                });
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
                        collect_transport_sent_receipts: true,
                        ..Default::default()
                    },
                    0,
                    0,
                    pending.remaining.max(continuation_crypto_limit),
                )
                .await;
        }

        unreachable!("bounded pending outbound token receipt loop must return")
    }

    pub(in crate::node) async fn wait_for_dataplane_completion(&self) {
        let notify = self.dataplane.readiness_notify();
        let _ = tokio::time::timeout(
            DATAPLANE_PENDING_OUTBOUND_COMPLETION_TIMEOUT,
            notify.notified(),
        )
        .await;
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
}

include!("dataplane_pending.rs");
include!("dataplane_owner_sync.rs");
include!("dataplane_helpers.rs");

#[cfg(test)]
mod pending_send_token_receipt_tests {
    use super::*;

    fn receipt(send_token: u64) -> DataplaneTransportSentReceipt {
        DataplaneTransportSentReceipt {
            owner: OwnerId::fmp_node(NodeAddr::from_bytes([7; 16])),
            counter: 0,
            fmp_timestamp_ms: None,
            payload_len: 1,
            fsp_send_receipt: None,
            send_token: Some(send_token),
        }
    }

    fn wrapped_receipt(send_token: u64) -> DataplaneTransportSentReceipt {
        DataplaneTransportSentReceipt {
            owner: OwnerId::fmp_node(NodeAddr::from_bytes([7; 16])),
            counter: 1,
            fmp_timestamp_ms: None,
            payload_len: 1,
            fsp_send_receipt: Some(crate::dataplane::DataplaneFspSendReceipt {
                owner: OwnerId::fsp_node(NodeAddr::from_bytes([8; 16])),
                counter: 2,
            }),
            send_token: Some(send_token),
        }
    }

    #[test]
    fn unrelated_receipt_does_not_acknowledge_endpoint_batch() {
        let mut pending = DataplanePendingSendTokenReceipts::new(41, 1);

        assert!(pending.consume([receipt(40)]).is_none());
        assert_eq!(pending.remaining, 1);
        assert_eq!(pending.consume([receipt(41)]).unwrap().send_token, Some(41));
    }

    #[test]
    fn endpoint_batch_requires_every_matching_receipt() {
        let mut pending = DataplanePendingSendTokenReceipts::new(41, 2);

        assert!(pending.consume([receipt(41), receipt(40)]).is_none());
        assert_eq!(pending.remaining, 1);
        assert_eq!(pending.consume([receipt(41)]).unwrap().send_token, Some(41));
    }

    #[test]
    fn wrapped_same_owner_receipt_requires_the_matching_send_token() {
        let mut pending = DataplanePendingSendTokenReceipts::new(41, 1);

        assert!(pending.consume([wrapped_receipt(40)]).is_none());
        assert_eq!(pending.remaining, 1);
        let matched = pending.consume([wrapped_receipt(41)]).unwrap();
        assert_eq!(matched.send_token, Some(41));
        assert_eq!(
            matched.fsp_send_receipt.unwrap().owner,
            OwnerId::fsp_node(NodeAddr::from_bytes([8; 16]))
        );
    }
}
