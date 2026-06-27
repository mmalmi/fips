use crate::node::decrypt_worker::DecryptFmpBookkeeping;
use crate::node::{
    AuthenticatedLinkMessage, EndpointEventSender, FLAG_CE, Node, NodeEndpointCommand,
};
use crate::transport::{PacketRx, ReceivedPacket};
use crate::upper::tun::TunOutboundRx;
use crate::{NodeAddr, PeerIdentity};
use std::collections::HashMap;
use tokio::sync::mpsc::Receiver;
use tracing::{debug, trace};

impl Node {
    pub(in crate::node) async fn drain_packet_mover2_scratch_turn(
        &mut self,
        packet_rx: &mut PacketRx,
        packet_limit: usize,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        crypto_limit: usize,
    ) -> crate::packet_mover2::PacketMover2LiveNodeTurn {
        self.drain_packet_mover2_scratch_turn_with_first(
            packet_rx,
            None,
            packet_limit,
            endpoint_priority_command_rx,
            endpoint_command_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            tun_tx,
            endpoint_tx,
            crypto_limit,
        )
        .await
    }

    pub(in crate::node) async fn drain_packet_mover2_scratch_turn_with_first(
        &mut self,
        packet_rx: &mut PacketRx,
        first_packet: Option<ReceivedPacket>,
        packet_limit: usize,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        crypto_limit: usize,
    ) -> crate::packet_mover2::PacketMover2LiveNodeTurn {
        self.drain_packet_mover2_scratch_turn_with_firsts(
            packet_rx,
            crate::packet_mover2::PacketMover2LiveTurnFirsts::default()
                .with_raw_packet(first_packet),
            packet_limit,
            endpoint_priority_command_rx,
            endpoint_command_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            tun_tx,
            endpoint_tx,
            crypto_limit,
        )
        .await
    }

    pub(in crate::node) async fn drain_packet_mover2_scratch_turn_with_firsts(
        &mut self,
        packet_rx: &mut PacketRx,
        firsts: crate::packet_mover2::PacketMover2LiveTurnFirsts,
        packet_limit: usize,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        crypto_limit: usize,
    ) -> crate::packet_mover2::PacketMover2LiveNodeTurn {
        let endpoint_identities = self.packet_mover2_endpoint_identity_snapshot();
        let endpoint_resolver =
            |source_addr: &NodeAddr| endpoint_identities.get(source_addr).copied();

        let turn = self
            .packet_mover2
            .pump_packet_rx_turn_with_firsts(
                packet_rx,
                firsts,
                packet_limit,
                endpoint_priority_command_rx,
                endpoint_command_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                tun_tx,
                endpoint_tx,
                endpoint_resolver,
                &self.transports,
                crypto_limit,
            )
            .await;
        Self::observe_packet_mover2_scratch_turn(&turn);
        turn
    }

    pub(super) async fn process_packet_mover2_scratch_control_ingress(
        &mut self,
        turn: &mut crate::packet_mover2::PacketMover2LiveNodeTurn,
    ) -> usize {
        let mut processed = 0usize;
        for receipt in turn.take_fmp_ingress_receipts() {
            if self.record_packet_mover2_fmp_ingress_receipt(&receipt) {
                processed += 1;
            }
        }
        for ingress in turn.take_fmp_link_ingress() {
            if self.process_packet_mover2_fmp_link_ingress(ingress).await {
                processed += 1;
            }
        }
        for ingress in turn.take_fsp_session_ingress() {
            if self
                .process_packet_mover2_authenticated_session(ingress)
                .await
            {
                processed += 1;
            }
        }
        for control in turn.take_fmp_control_ingress() {
            self.process_packet(control.into_packet()).await;
            processed += 1;
        }
        for command in self.packet_mover2.take_deferred_endpoint_commands() {
            self.handle_endpoint_data_command(command).await;
            processed += 1;
        }
        processed
    }

    fn record_packet_mover2_fmp_ingress_receipt(
        &mut self,
        receipt: &crate::packet_mover2::PacketMover2FmpIngressReceipt,
    ) -> bool {
        let Some(source_peer) = self
            .peers
            .get(receipt.source_addr())
            .map(|peer| *peer.identity())
        else {
            return false;
        };
        let fmp = DecryptFmpBookkeeping {
            source_peer,
            transport_id: receipt.transport_id(),
            remote_addr: receipt.remote_addr().clone(),
            packet_timestamp_ms: receipt.packet_timestamp_ms(),
            packet_len: receipt.packet_len(),
            fmp_counter: receipt.fmp_counter(),
            inner_timestamp_ms: receipt.inner_timestamp_ms(),
            fmp_flags: receipt.fmp_flags(),
        };
        self.record_worker_authenticated_fmp_receive(&fmp, Some(receipt.source_addr()));
        true
    }

    async fn process_packet_mover2_fmp_link_ingress(
        &mut self,
        ingress: crate::packet_mover2::PacketMover2FmpLinkIngress,
    ) -> bool {
        let receipt = ingress.receipt();
        let Some(source_peer) = self
            .peers
            .get(receipt.source_addr())
            .map(|peer| *peer.identity())
        else {
            return false;
        };
        let fmp = DecryptFmpBookkeeping {
            source_peer,
            transport_id: receipt.transport_id(),
            remote_addr: receipt.remote_addr().clone(),
            packet_timestamp_ms: receipt.packet_timestamp_ms(),
            packet_len: receipt.packet_len(),
            fmp_counter: receipt.fmp_counter(),
            inner_timestamp_ms: receipt.inner_timestamp_ms(),
            fmp_flags: receipt.fmp_flags(),
        };
        self.record_worker_authenticated_fmp_receive(&fmp, Some(receipt.source_addr()));
        let Some(msg_type) = ingress.msg_type() else {
            return true;
        };
        self.dispatch_link_message(AuthenticatedLinkMessage::new(
            source_peer,
            msg_type,
            ingress.payload(),
            receipt.fmp_flags() & FLAG_CE != 0,
        ))
        .await;
        true
    }

    pub(super) fn packet_mover2_scratch_packet_activity(
        turn: &crate::packet_mover2::PacketMover2LiveNodeTurn,
    ) -> usize {
        let summary = turn.summary();
        summary
            .raw_ingress_dropped()
            .saturating_add(summary.inbound_admitted())
            .saturating_add(summary.inbound_dropped())
            .saturating_add(turn.fmp_control_ingress().len())
            .saturating_add(turn.fmp_link_ingress().len())
            .saturating_add(turn.fsp_session_ingress().len())
            .saturating_add(turn.endpoint_deferred_commands())
    }

    fn packet_mover2_endpoint_identity_snapshot(&self) -> HashMap<NodeAddr, PeerIdentity> {
        let mut identities = HashMap::new();
        for (addr, entry) in self.sessions.iter() {
            if let Some(identity) = entry.remote_identity() {
                identities.insert(*addr, identity);
            }
        }
        for (addr, pubkey, _) in self.identity_cache.iter() {
            identities
                .entry(*addr)
                .or_insert_with(|| PeerIdentity::from_pubkey_full(*pubkey));
        }
        identities
    }

    fn observe_packet_mover2_scratch_turn(turn: &crate::packet_mover2::PacketMover2LiveNodeTurn) {
        if !turn.has_activity() {
            return;
        }

        let summary = turn.summary();
        if turn.has_failures() {
            debug!(
                raw_ingress_dropped = summary.raw_ingress_dropped(),
                inbound_dropped = summary.inbound_dropped(),
                outbound_dropped = summary.outbound_dropped(),
                output_drops = turn.output_drops().len(),
                fmp_control_ingress = turn.fmp_control_ingress().len(),
                fsp_session_ingress = turn.fsp_session_ingress().len(),
                raw_ingress_drops = turn.raw_ingress_drops().len(),
                tun_outbound_drops = turn.tun_outbound_drops().len(),
                endpoint_command_drops = turn.endpoint_command_drops().len(),
                packet_drops = turn.drops().len(),
                transport_dropped = turn.transport_dropped(),
                "packet mover2 scratch turn reported drops"
            );
            for drop in turn.raw_ingress_drops() {
                debug!(
                    protocol = ?drop.protocol(),
                    transport_id = ?drop.transport_id(),
                    remote_addr = ?drop.remote_addr(),
                    payload_len = drop.payload_len(),
                    reason = ?drop.reason(),
                    "packet mover2 raw ingress dropped"
                );
            }
            for drop in turn.endpoint_command_drops() {
                debug!(
                    dest_addr = ?drop.dest_addr(),
                    lane = ?drop.lane(),
                    payload_len = drop.payload_len(),
                    reason = ?drop.reason(),
                    "packet mover2 endpoint command dropped"
                );
            }
            return;
        }

        trace!(
            inbound_admitted = summary.inbound_admitted(),
            outbound_admitted = summary.outbound_admitted(),
            outputs_sent = summary.outputs_sent(),
            transport_sent = turn.transport_sent(),
            endpoint_deferred = turn.endpoint_deferred_commands(),
            fmp_control_ingress = turn.fmp_control_ingress().len(),
            fmp_link_ingress = turn.fmp_link_ingress().len(),
            fsp_session_ingress = turn.fsp_session_ingress().len(),
            "packet mover2 scratch turn completed"
        );
    }
}
