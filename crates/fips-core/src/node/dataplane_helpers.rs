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
