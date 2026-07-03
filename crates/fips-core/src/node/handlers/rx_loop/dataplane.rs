use crate::discovery::is_punch_packet;
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use crate::node::{
    AuthenticatedFmpReceiveFacts, AuthenticatedLinkMessage, EndpointDataBatchRx,
    EndpointEventSender, FLAG_CE, LocalSessionPayload, Node,
};
use crate::transport::{PacketRx, ReceivedPacket};
use crate::upper::tun::TunOutboundRx;
use crate::{NodeAddr, PeerIdentity};
use tracing::{debug, trace, warn};

impl Node {
    pub(in crate::node) async fn drain_dataplane_turn_with_firsts(
        &mut self,
        packet_rx: &mut PacketRx,
        firsts: crate::dataplane::DataplaneLiveTurnFirsts,
        packet_limit: usize,
        endpoint_data_rx: &mut EndpointDataBatchRx,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        crypto_limit: usize,
    ) -> crate::dataplane::DataplaneLiveNodeTurn {
        let direct_fsp_sources = std::sync::Arc::new(self.dataplane_direct_fsp_sources());
        self.dataplane
            .set_established_fast_ingress_direct_fsp_sources(direct_fsp_sources.clone());
        let turn = self
            .dataplane
            .pump_packet_rx_turn_with_firsts_direct_fsp_sources_and_transport_worker(
                packet_rx,
                firsts,
                packet_limit,
                direct_fsp_sources,
                endpoint_data_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                tun_tx,
                endpoint_tx,
                &self.transports,
                crypto_limit,
                &mut self.dataplane_transport_send_worker,
            )
            .await;
        Self::observe_dataplane_turn(&turn);
        turn
    }

    pub(in crate::node) async fn drain_dataplane_completion_turn(
        &mut self,
        endpoint_data_rx: &mut EndpointDataBatchRx,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        crypto_limit: usize,
    ) -> crate::dataplane::DataplaneLiveNodeTurn {
        let turn = self
            .dataplane
            .pump_completion_output_turn_with_transport_worker(
                endpoint_data_rx,
                tun_outbound_rx,
                tun_tx,
                endpoint_tx,
                &self.transports,
                crypto_limit,
                &mut self.dataplane_transport_send_worker,
            )
            .await;
        Self::observe_dataplane_turn(&turn);
        turn
    }

    pub(in crate::node) async fn process_dataplane_control_ingress(
        &mut self,
        turn: &mut crate::dataplane::DataplaneLiveNodeTurn,
    ) -> usize {
        let mut processed = 0usize;
        let fmp_crypto_failures: Vec<_> = turn
            .drops()
            .iter()
            .filter_map(Self::dataplane_fmp_crypto_failure)
            .collect();
        for (source_addr, counter, authenticated_highest) in fmp_crypto_failures {
            if self
                .handle_dataplane_fmp_decrypt_failure(&source_addr, counter, authenticated_highest)
                .await
            {
                processed += 1;
            }
        }
        for receipt in turn.take_fmp_ingress_receipts() {
            if self.record_dataplane_fmp_ingress_receipt(&receipt) {
                processed += 1;
            }
        }
        for ingress in turn.take_fmp_link_ingress() {
            if self.process_dataplane_fmp_link_ingress(ingress).await {
                processed += 1;
            }
        }
        for warmup in turn.take_fsp_coord_warmups() {
            warmup.apply_to(self.coord_cache_mut(), Self::now_ms());
            processed += 1;
        }
        let fsp_crypto_failures: Vec<_> = turn
            .drops()
            .iter()
            .filter_map(Self::dataplane_fsp_crypto_failure)
            .collect();
        for (source_addr, counter, received_k_bit) in fsp_crypto_failures {
            if self
                .handle_dataplane_fsp_decrypt_failure(source_addr, counter, received_k_bit)
                .await
            {
                processed += 1;
            }
        }
        for ingress in turn.take_fsp_local_session_ingress() {
            if self.process_dataplane_local_session_ingress(ingress).await {
                processed += 1;
            }
        }
        processed = processed.saturating_add(
            self.process_dataplane_compact_endpoint_data(turn.take_endpoint_data_bulk())
                .await,
        );
        processed = processed.saturating_add(
            self.process_dataplane_authenticated_sessions(turn.take_fsp_session_ingress())
                .await,
        );
        for control in turn.take_fmp_control_ingress() {
            if self.process_dataplane_fmp_control_ingress(control).await {
                processed += 1;
            }
        }
        for drop in turn.tun_outbound_drops() {
            if self.process_dataplane_tun_outbound_drop(drop) {
                processed += 1;
            }
        }
        for packet in self.dataplane.take_deferred_tun_packets() {
            self.handle_dataplane_deferred_tun_packet(packet.into_vec())
                .await;
            processed += 1;
        }
        for batch in self.dataplane.take_deferred_endpoint_data_batches() {
            self.handle_endpoint_data_batch_no_established_flush(batch)
                .await;
            processed += 1;
        }
        processed
    }

    fn dataplane_fmp_crypto_failure(
        drop: &crate::dataplane::PacketDrop,
    ) -> Option<(NodeAddr, u64, u64)> {
        if drop.owner().protocol() != crate::dataplane::PacketProtocol::Fmp
            || drop.reason() != crate::dataplane::PacketDropReason::CryptoFailed
            || drop.crypto_failure() != Some(crate::dataplane::CryptoFailureKind::Open)
        {
            return None;
        }
        Some((
            drop.owner().node_addr(),
            drop.counter()?,
            drop.authenticated_counter_highest().unwrap_or(0),
        ))
    }

    fn dataplane_fsp_crypto_failure(
        drop: &crate::dataplane::PacketDrop,
    ) -> Option<(NodeAddr, u64, bool)> {
        if drop.owner().protocol() != crate::dataplane::PacketProtocol::Fsp
            || drop.reason() != crate::dataplane::PacketDropReason::CryptoFailed
            || drop.crypto_failure() != Some(crate::dataplane::CryptoFailureKind::Open)
        {
            return None;
        }
        let received_k_bit =
            drop.wire_flags().unwrap_or(0) & crate::node::session_wire::FSP_FLAG_K != 0;
        Some((drop.owner().node_addr(), drop.counter()?, received_k_bit))
    }

    async fn process_dataplane_local_session_ingress(
        &mut self,
        ingress: crate::dataplane::DataplaneFspLocalSessionIngress,
    ) -> bool {
        let (source_addr, _previous_hop_addr, _ce_flag, _path_mtu, payload) = ingress.into_parts();
        let delivery = LocalSessionPayload::new(source_addr, &payload);
        self.handle_session_payload(delivery).await;
        true
    }

    async fn process_dataplane_fmp_control_ingress(
        &mut self,
        control: crate::dataplane::DataplaneFmpControlIngress,
    ) -> bool {
        let packet = control.into_packet();
        if is_punch_packet(&packet.data) {
            trace!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                "Dropping stray punch probe/ack from dataplane control ingress"
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
            self.record_dataplane_fmp_protocol_mismatch(&packet, prefix.version, prefix.phase);
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
                    "Unknown dataplane FMP control phase, dropping"
                );
                false
            }
        }
    }

    fn record_dataplane_fmp_protocol_mismatch(
        &mut self,
        packet: &ReceivedPacket,
        version: u8,
        phase: u8,
    ) {
        debug!(
            version,
            transport_id = %packet.transport_id,
            "Unknown dataplane FMP version, dropping"
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

    fn record_dataplane_fmp_ingress_receipt(
        &mut self,
        receipt: &crate::dataplane::DataplaneFmpIngressReceipt,
    ) -> bool {
        let source_peer = receipt.source_peer();
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

    fn process_dataplane_tun_outbound_drop(
        &mut self,
        drop: &crate::dataplane::DataplaneTunOutboundDrop,
    ) -> bool {
        if drop.packet().is_empty() {
            return false;
        }
        match drop.reason() {
            crate::dataplane::DataplaneTunOutboundDropReason::MtuExceeded { mtu } => {
                self.send_icmpv6_packet_too_big(drop.packet(), mtu);
                true
            }
            crate::dataplane::DataplaneTunOutboundDropReason::NoRoute => {
                self.send_icmpv6_dest_unreachable(drop.packet());
                true
            }
            crate::dataplane::DataplaneTunOutboundDropReason::InvalidPacket => false,
        }
    }

    async fn process_dataplane_fmp_link_ingress(
        &mut self,
        ingress: crate::dataplane::DataplaneFmpLinkIngress,
    ) -> bool {
        let receipt = ingress.receipt();
        let source_peer = receipt.source_peer();
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

    pub(in crate::node) fn dataplane_peer_identity(&self, addr: &NodeAddr) -> Option<PeerIdentity> {
        if let Some(identity) = self
            .sessions
            .get(addr)
            .and_then(|entry| entry.remote_identity())
        {
            return Some(identity);
        }
        if let Some(identity) = self.peers.get(addr).map(|peer| *peer.identity()) {
            return Some(identity);
        }
        self.identity_cache
            .iter()
            .find_map(|(cached_addr, pubkey, _)| {
                (cached_addr == addr).then(|| PeerIdentity::from_pubkey_full(*pubkey))
            })
    }

    pub(super) fn dataplane_packet_activity(
        turn: &crate::dataplane::DataplaneLiveNodeTurn,
    ) -> usize {
        let summary = turn.summary();
        summary
            .raw_ingress_dropped()
            .saturating_add(summary.inbound_admitted())
            .saturating_add(summary.inbound_dropped())
            .saturating_add(turn.fmp_control_ingress().len())
            .saturating_add(turn.fmp_link_ingress().len())
            .saturating_add(turn.fsp_coord_warmups().len())
            .saturating_add(turn.fsp_local_session_ingress().len())
            .saturating_add(turn.endpoint_data_bulk_count())
            .saturating_add(turn.fsp_session_ingress().len())
            .saturating_add(turn.deferred_endpoint_data_batches_count())
            .saturating_add(turn.tun_deferred_packets())
    }

    pub(super) fn dataplane_raw_ingress_activity(
        turn: &crate::dataplane::DataplaneLiveNodeTurn,
    ) -> usize {
        let summary = turn.summary();
        summary
            .raw_ingress_dropped()
            .saturating_add(summary.inbound_admitted())
            .saturating_add(summary.inbound_dropped())
            .saturating_add(turn.fmp_control_ingress().len())
    }

    pub(super) fn dataplane_control_activity(
        turn: &crate::dataplane::DataplaneLiveNodeTurn,
    ) -> usize {
        turn.fmp_control_ingress()
            .len()
            .saturating_add(turn.fmp_link_ingress().len())
            .saturating_add(turn.fsp_coord_warmups().len())
            .saturating_add(turn.fsp_local_session_ingress().len())
    }

    pub(in crate::node) fn observe_dataplane_turn(turn: &crate::dataplane::DataplaneLiveNodeTurn) {
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
                fsp_coord_warmups = turn.fsp_coord_warmups().len(),
                fsp_local_session_ingress = turn.fsp_local_session_ingress().len(),
                endpoint_data_bulk = turn.endpoint_data_bulk_count(),
                endpoint_data_bulk_batches = turn.endpoint_data_bulk().len(),
                fsp_session_ingress = turn.fsp_session_ingress().len(),
                raw_ingress_drops = turn.raw_ingress_drops().len(),
                tun_outbound_drops = turn.tun_outbound_drops().len(),
                endpoint_data_drops = turn.endpoint_data_drops().len(),
                tun_deferred_packets = turn.tun_deferred_packets(),
                packet_drops = turn.drops().len(),
                transport_dropped = turn.transport_dropped(),
                "dataplane turn reported drops"
            );
            for drop in turn.raw_ingress_drops() {
                debug!(
                    protocol = ?drop.protocol(),
                    transport_id = ?drop.transport_id(),
                    remote_addr = ?drop.remote_addr(),
                    payload_len = drop.payload_len(),
                    reason = ?drop.reason(),
                    "dataplane raw ingress dropped"
                );
            }
            for drop in turn.endpoint_data_drops() {
                debug!(
                    dest_addr = ?drop.dest_addr(),
                    payload_len = drop.payload_len(),
                    reason = ?drop.reason(),
                    "dataplane endpoint data batch dropped"
                );
            }
            return;
        }

        trace!(
            inbound_admitted = summary.inbound_admitted(),
            outbound_admitted = summary.outbound_admitted(),
            outputs_sent = summary.outputs_sent(),
            transport_sent = turn.transport_sent(),
            endpoint_deferred = turn.deferred_endpoint_data_batches_count(),
            tun_deferred = turn.tun_deferred_packets(),
            fmp_control_ingress = turn.fmp_control_ingress().len(),
            fmp_link_ingress = turn.fmp_link_ingress().len(),
            fsp_coord_warmups = turn.fsp_coord_warmups().len(),
            fsp_local_session_ingress = turn.fsp_local_session_ingress().len(),
            endpoint_data_bulk = turn.endpoint_data_bulk_count(),
            endpoint_data_bulk_batches = turn.endpoint_data_bulk().len(),
            fsp_session_ingress = turn.fsp_session_ingress().len(),
            "dataplane turn completed"
        );
    }
}
