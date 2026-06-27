use crate::node::{EndpointEventSender, Node, NodeEndpointCommand};
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
        let endpoint_identities = self.packet_mover2_endpoint_identity_snapshot();
        let endpoint_resolver =
            |source_addr: &NodeAddr| endpoint_identities.get(source_addr).copied();

        let turn = self
            .packet_mover2
            .pump_packet_rx_turn_with_first(
                packet_rx,
                first_packet,
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
                raw_ingress_drops = turn.raw_ingress_drops().len(),
                tun_outbound_drops = turn.tun_outbound_drops().len(),
                endpoint_command_drops = turn.endpoint_command_drops().len(),
                packet_drops = turn.drops().len(),
                transport_dropped = turn.transport_dropped(),
                "packet mover2 scratch turn reported drops"
            );
            return;
        }

        trace!(
            inbound_admitted = summary.inbound_admitted(),
            outbound_admitted = summary.outbound_admitted(),
            outputs_sent = summary.outputs_sent(),
            transport_sent = turn.transport_sent(),
            endpoint_deferred = turn.endpoint_deferred_commands(),
            "packet mover2 scratch turn completed"
        );
    }
}
