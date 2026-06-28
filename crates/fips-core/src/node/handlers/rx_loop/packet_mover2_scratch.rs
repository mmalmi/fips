use crate::discovery::is_punch_packet;
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use crate::node::{
    AuthenticatedFmpReceiveFacts, AuthenticatedLinkMessage, EndpointEventSender, FLAG_CE,
    LocalSessionPayload, Node, NodeEndpointCommand,
};
use crate::transport::{PacketRx, ReceivedPacket};
use crate::upper::tun::TunOutboundRx;
use crate::{NodeAddr, PeerIdentity};
use std::collections::HashMap;
#[cfg(unix)]
use std::collections::HashSet;
use tokio::sync::mpsc::Receiver;
use tracing::{debug, trace, warn};

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
        let fmp_crypto_failures: Vec<_> = turn
            .drops()
            .iter()
            .filter_map(Self::packet_mover2_fmp_crypto_failure)
            .collect();
        for (source_addr, counter, authenticated_highest) in fmp_crypto_failures {
            if self
                .handle_packet_mover2_fmp_decrypt_failure(
                    &source_addr,
                    counter,
                    authenticated_highest,
                )
                .await
            {
                processed += 1;
            }
        }
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
        let fsp_crypto_failures: Vec<_> = turn
            .drops()
            .iter()
            .filter_map(Self::packet_mover2_fsp_crypto_failure)
            .collect();
        for (source_addr, counter, received_k_bit) in fsp_crypto_failures {
            if self
                .handle_packet_mover2_fsp_decrypt_failure(source_addr, counter, received_k_bit)
                .await
            {
                processed += 1;
            }
        }
        for ingress in turn.take_fsp_local_session_ingress() {
            if self
                .process_packet_mover2_local_session_ingress(ingress)
                .await
            {
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
            if self
                .process_packet_mover2_fmp_control_ingress(control)
                .await
            {
                processed += 1;
            }
        }
        #[cfg(unix)]
        let mut endpoint_bulk_lease_refreshes = HashSet::new();
        for routed in turn.take_endpoint_routed_destinations() {
            #[cfg(unix)]
            let dest_addr = routed.dest_addr();
            if self.sessions.record_packet_mover2_endpoint_routed(routed) {
                processed += 1;
            }
            #[cfg(unix)]
            {
                const MAX_ENDPOINT_BULK_LEASE_REFRESHES_PER_TURN: usize = 8;
                if endpoint_bulk_lease_refreshes.len() < MAX_ENDPOINT_BULK_LEASE_REFRESHES_PER_TURN
                    && endpoint_bulk_lease_refreshes.insert(dest_addr)
                    && self.refresh_endpoint_bulk_send_lease(dest_addr).await
                {
                    processed += 1;
                }
            }
        }
        for command in self.packet_mover2.take_deferred_endpoint_commands() {
            self.handle_packet_mover2_deferred_endpoint_command(command)
                .await;
            processed += 1;
        }
        processed
    }

    fn packet_mover2_fmp_crypto_failure(
        drop: &crate::packet_mover2::PacketDrop,
    ) -> Option<(NodeAddr, u64, u64)> {
        if drop.owner().protocol() != crate::packet_mover2::PacketProtocol::Fmp
            || drop.reason() != crate::packet_mover2::PacketDropReason::CryptoFailed
            || drop.crypto_failure() != Some(crate::packet_mover2::CryptoFailureKind::Open)
        {
            return None;
        }
        Some((
            drop.owner().node_addr()?,
            drop.counter()?,
            drop.authenticated_counter_highest().unwrap_or(0),
        ))
    }

    fn packet_mover2_fsp_crypto_failure(
        drop: &crate::packet_mover2::PacketDrop,
    ) -> Option<(NodeAddr, u64, bool)> {
        if drop.owner().protocol() != crate::packet_mover2::PacketProtocol::Fsp
            || drop.reason() != crate::packet_mover2::PacketDropReason::CryptoFailed
            || drop.crypto_failure() != Some(crate::packet_mover2::CryptoFailureKind::Open)
        {
            return None;
        }
        let received_k_bit =
            drop.wire_flags().unwrap_or(0) & crate::node::session_wire::FSP_FLAG_K != 0;
        Some((drop.owner().node_addr()?, drop.counter()?, received_k_bit))
    }

    async fn process_packet_mover2_local_session_ingress(
        &mut self,
        ingress: crate::packet_mover2::PacketMover2FspLocalSessionIngress,
    ) -> bool {
        let (source_addr, previous_hop_addr, ce_flag, path_mtu, payload) = ingress.into_parts();
        let Some(previous_hop_peer) = self.packet_mover2_peer_identity(&previous_hop_addr) else {
            debug!(
                src = %self.peer_display_name(&source_addr),
                previous_hop = %self.peer_display_name(&previous_hop_addr),
                payload_len = payload.len(),
                "Dropping packet-mover2 local session payload for unknown previous hop identity"
            );
            return false;
        };

        let delivery =
            LocalSessionPayload::new(source_addr, previous_hop_peer, &payload, path_mtu, ce_flag);
        self.handle_session_payload(delivery).await;
        true
    }

    async fn process_packet_mover2_fmp_control_ingress(
        &mut self,
        control: crate::packet_mover2::PacketMover2FmpControlIngress,
    ) -> bool {
        let packet = control.into_packet();
        if is_punch_packet(&packet.data) {
            trace!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                "Dropping stray punch probe/ack from packet mover2 control ingress"
            );
            return false;
        }
        if packet.data.len() < COMMON_PREFIX_SIZE {
            return false;
        }

        let Some(prefix) = CommonPrefix::parse(&packet.data) else {
            return false;
        };
        if prefix.version != FMP_VERSION {
            self.record_packet_mover2_fmp_protocol_mismatch(&packet, prefix.version, prefix.phase);
            return false;
        }

        match prefix.phase {
            PHASE_MSG1 => {
                self.handle_msg1(packet).await;
                true
            }
            PHASE_MSG2 => {
                self.handle_msg2(packet).await;
                true
            }
            _ => {
                debug!(
                    phase = prefix.phase,
                    transport_id = %packet.transport_id,
                    "Unknown packet mover2 FMP control phase, dropping"
                );
                false
            }
        }
    }

    fn record_packet_mover2_fmp_protocol_mismatch(
        &mut self,
        packet: &ReceivedPacket,
        version: u8,
        phase: u8,
    ) {
        debug!(
            version,
            transport_id = %packet.transport_id,
            "Unknown packet mover2 FMP version, dropping"
        );

        let looks_like_fmp_phase = matches!(phase, PHASE_ESTABLISHED | PHASE_MSG1 | PHASE_MSG2);
        if looks_like_fmp_phase
            && self.bootstrap_transports.contains(&packet.transport_id)
            && let Some(npub) = self.bootstrap_transports.peer_npub(&packet.transport_id)
            && let Some(handle) = self.nostr_discovery_handle()
        {
            let now_ms = Self::now_ms();
            let cooldown_secs = handle.protocol_mismatch_cooldown_secs();
            if handle.record_protocol_mismatch(npub, now_ms) {
                warn!(
                    peer_npub = %npub,
                    transport_id = %packet.transport_id,
                    peer_version = version,
                    our_version = FMP_VERSION,
                    cooldown_secs,
                    "Nostr-discovered peer speaks a different FMP version; suppressing retraversal"
                );
            }
        }
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
        let fmp = AuthenticatedFmpReceiveFacts::new(
            source_peer,
            receipt.transport_id(),
            receipt.remote_addr(),
            receipt.packet_timestamp_ms(),
            receipt.packet_len(),
            receipt.fmp_counter(),
            receipt.inner_timestamp_ms(),
            receipt.fmp_flags(),
        );
        self.record_authenticated_fmp_receive_facts(fmp, Some(receipt.source_addr()));
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
        let fmp = AuthenticatedFmpReceiveFacts::new(
            source_peer,
            receipt.transport_id(),
            receipt.remote_addr(),
            receipt.packet_timestamp_ms(),
            receipt.packet_len(),
            receipt.fmp_counter(),
            receipt.inner_timestamp_ms(),
            receipt.fmp_flags(),
        );
        self.record_authenticated_fmp_receive_facts(fmp, Some(receipt.source_addr()));
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

    fn packet_mover2_peer_identity(&self, addr: &NodeAddr) -> Option<PeerIdentity> {
        if let Some(identity) = self.peers.get(addr).map(|peer| *peer.identity()) {
            return Some(identity);
        }
        self.identity_cache
            .iter()
            .find_map(|(cached_addr, pubkey, _)| {
                (cached_addr == addr).then(|| PeerIdentity::from_pubkey_full(*pubkey))
            })
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
            .saturating_add(turn.fsp_local_session_ingress().len())
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
                fsp_local_session_ingress = turn.fsp_local_session_ingress().len(),
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
            fsp_local_session_ingress = turn.fsp_local_session_ingress().len(),
            fsp_session_ingress = turn.fsp_session_ingress().len(),
            "packet mover2 scratch turn completed"
        );
    }
}
