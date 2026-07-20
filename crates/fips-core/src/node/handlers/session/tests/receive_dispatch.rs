    use crate::node::session_wire::fsp_prepend_inner_header;

    #[test]
    fn application_receive_refreshes_previous_hop_peer_without_direct_source_trust() {
        use crate::PeerIdentity;
        use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
        use crate::node::retry::RetryState;
        use crate::peer::{ActivePeer, ActivePeerSession};
        use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let source = Identity::generate();
        let previous_hop = Identity::generate();
        let previous_hop_identity = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let previous_hop_addr = *previous_hop_identity.node_addr();
        let source_addr = *source.node_addr();
        let previous_hop_config = PeerConfig {
            npub: previous_hop.npub(),
            alias: None,
            addresses: vec![PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)],
            connect_policy: ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        };

        let mut config = crate::config::Config::new();
        config.peers.push(previous_hop_config.clone());
        let mut node = Node::with_identity(local, config).expect("node");
        node.config.node.heartbeat_interval_secs = 10;

        let stale_seen_ms = Node::now_ms().saturating_sub(11_000);
        let mut active_peer = ActivePeer::with_session(
            previous_hop_identity,
            LinkId::new(9),
            1_000,
            ActivePeerSession {
                session: make_xk_session(&node.identity, &previous_hop),
                our_index: SessionIndex::new(0x1010),
                their_index: SessionIndex::new(0x2020),
                transport_id: TransportId::new(0x55),
                current_addr: TransportAddr::from_string("203.0.113.9:2121"),
                link_stats: LinkStats::new(),
                is_initiator: true,
                remote_epoch: None,
            },
        );
        active_peer.touch(stale_seen_ms);
        node.peers
            .insert_with_current_session_index(previous_hop_addr, active_peer);

        let session = SessionEntry::new(
            source_addr,
            source.pubkey_full(),
            EndToEndState::Established(make_xk_session(&node.identity, &source)),
            1_000,
            true,
        );
        node.sessions.insert(source_addr, session);

        let mut retry = RetryState::new(previous_hop_config);
        retry.reconnect = true;
        node.retry_pending.insert(previous_hop_addr, retry);

        SessionDispatchCommit {
            source_addr,
            receive_completion: Some(SessionReceiveCompletion {
                source_addr,
                previous_hop_addr,
                direct_path: false,
            }),
        }
        .finish_receive(&mut node);

        let previous_hop_peer = node
            .peers
            .get(&previous_hop_addr)
            .expect("previous hop should remain active");
        assert!(
            previous_hop_peer.idle_time(Node::now_ms()) <= 1_000,
            "accepted application data should refresh the direct previous-hop link"
        );
        assert!(
            !node.retry_pending.contains_key(&previous_hop_addr),
            "fresh authenticated data from the direct previous hop should stop link refresh churn"
        );
        assert!(node.sessions.get(&source_addr).is_some());
    }

    #[test]
    fn authenticated_fmp_receive_clears_direct_probe_retry_on_direct_path() {
        use crate::PeerIdentity;
        use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
        use crate::node::retry::RetryState;
        use crate::peer::{ActivePeer, ActivePeerSession};
        use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let peer_addr = *peer_identity.node_addr();
        let peer_config = PeerConfig {
            npub: peer.npub(),
            alias: None,
            addresses: vec![PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)],
            connect_policy: ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        };
        let transport_id = TransportId::new(0x56);
        let transport_addr = TransportAddr::from_string("198.51.100.20:61062");

        let mut config = crate::config::Config::new();
        config.peers.push(peer_config.clone());
        let mut node = Node::with_identity(local, config).expect("node");
        node.config.node.heartbeat_interval_secs = 10;

        let mut active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            ActivePeerSession {
                session: make_xk_session(&node.identity, &peer),
                our_index: SessionIndex::new(0x1011),
                their_index: SessionIndex::new(0x2021),
                transport_id,
                current_addr: transport_addr.clone(),
                link_stats: LinkStats::new(),
                is_initiator: true,
                remote_epoch: None,
            },
        );
        active_peer.touch(Node::now_ms().saturating_sub(11_000));
        node.peers
            .insert_with_current_session_index(peer_addr, active_peer);

        let mut retry = RetryState::new(peer_config);
        retry.reconnect = true;
        node.retry_pending.insert(peer_addr, retry);

        node.record_authenticated_fmp_receive_facts(
            crate::node::AuthenticatedFmpReceiveFacts {
                source_peer: peer_identity,
                transport_id,
                remote_addr: &transport_addr,
                packet_timestamp_ms: Node::now_ms(),
                packet_len: 256,
                fmp_counter: 11,
                inner_timestamp_ms: 22,
                fmp_flags: 0,
            },
            Some(&peer_addr),
        );

        assert!(
            !node.retry_pending.contains_key(&peer_addr),
            "fresh authenticated FMP return on the direct peer path should stop direct-probe churn"
        );
    }

    #[test]
    fn authenticated_fmp_receive_keeps_direct_probe_retry_for_forwarded_path() {
        use crate::PeerIdentity;
        use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
        use crate::node::retry::RetryState;
        use crate::peer::{ActivePeer, ActivePeerSession};
        use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let relay = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let peer_addr = *peer_identity.node_addr();
        let relay_addr = *relay.node_addr();
        let peer_config = PeerConfig {
            npub: peer.npub(),
            alias: None,
            addresses: vec![PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)],
            connect_policy: ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        };
        let transport_id = TransportId::new(0x57);
        let transport_addr = TransportAddr::from_string("198.51.100.20:61062");

        let mut config = crate::config::Config::new();
        config.peers.push(peer_config.clone());
        let mut node = Node::with_identity(local, config).expect("node");
        node.config.node.heartbeat_interval_secs = 10;

        let mut active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            ActivePeerSession {
                session: make_xk_session(&node.identity, &peer),
                our_index: SessionIndex::new(0x1012),
                their_index: SessionIndex::new(0x2022),
                transport_id,
                current_addr: transport_addr.clone(),
                link_stats: LinkStats::new(),
                is_initiator: true,
                remote_epoch: None,
            },
        );
        active_peer.touch(Node::now_ms().saturating_sub(11_000));
        node.peers
            .insert_with_current_session_index(peer_addr, active_peer);

        let mut retry = RetryState::new(peer_config);
        retry.reconnect = true;
        node.retry_pending.insert(peer_addr, retry);

        node.record_authenticated_fmp_receive_facts(
            crate::node::AuthenticatedFmpReceiveFacts {
                source_peer: peer_identity,
                transport_id,
                remote_addr: &transport_addr,
                packet_timestamp_ms: Node::now_ms(),
                packet_len: 256,
                fmp_counter: 11,
                inner_timestamp_ms: 22,
                fmp_flags: 0,
            },
            Some(&relay_addr),
        );

        assert!(
            node.retry_pending.contains_key(&peer_addr),
            "forwarded authenticated FMP traffic must not prove the direct peer path is healthy"
        );
    }

    #[test]
    fn authenticated_session_message_owns_endpoint_delivery_conversion() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let endpoint_payload = b"endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );

        let message = AuthenticatedSessionMessage::new(
            source_peer,
            crate::transport::PacketBuffer::new(plaintext),
            SessionMessageType::EndpointData.to_byte(),
        );

        assert_eq!(message.body(), endpoint_payload);
        let deliveries = message.into_endpoint_data_deliveries();
        assert_eq!(deliveries.len(), 1);
        let delivery = &deliveries[0];
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload.as_slice(), endpoint_payload.as_slice());
    }

    #[test]
    fn authenticated_session_dispatch_owns_route_ce_and_completion_facts() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"endpoint completion".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            true,
            AuthenticatedSessionMessage::new(
                source_peer,
                crate::transport::PacketBuffer::new(plaintext),
                SessionMessageType::EndpointData.to_byte(),
            ),
        );

        assert_eq!(dispatch.source_addr(), &source_addr);
        assert_eq!(&dispatch.previous_hop_addr, &previous_hop_addr);
        assert!(dispatch.ce_flag());
        assert_eq!(
            dispatch.msg_type(),
            SessionMessageType::EndpointData.to_byte()
        );
        assert_eq!(dispatch.body(), endpoint_payload);
        assert_eq!(
            dispatch.receive_completion(),
            Some(SessionReceiveCompletion {
                source_addr,
                previous_hop_addr,
                direct_path: false,
            })
        );
        let deliveries = dispatch.into_endpoint_data_deliveries();
        assert_eq!(deliveries.len(), 1);
        let delivery = &deliveries[0];
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload.as_slice(), endpoint_payload.as_slice());

        let report_plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::SenderReport.to_byte(),
            0,
            b"report",
        );
        let report_dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                crate::transport::PacketBuffer::new(report_plaintext),
                SessionMessageType::SenderReport.to_byte(),
            ),
        );
        assert_eq!(
            report_dispatch.receive_completion(),
            None,
            "MMP reports must not reset session idle"
        );
    }

    #[test]
    fn endpoint_data_batched_dispatch_finishes_receive_without_pending_flush() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"fast endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                crate::transport::PacketBuffer::new(plaintext),
                SessionMessageType::EndpointData.to_byte(),
            ),
        );

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let mut commit = SessionReceiveBatchCommit::default();
        let deliveries = dispatch.dispatch_endpoint_data_batched(&mut commit);
        let pending_flush = commit.finish(&mut node);
        node.deliver_endpoint_data_batch(deliveries);
        assert!(pending_flush.is_empty());
        let crate::node::NodeEndpointEvent { messages, .. } =
            endpoint_io.event_rx.try_recv().expect("endpoint event");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].source_peer, source_peer);
        assert_eq!(messages[0].payload.as_slice(), endpoint_payload.as_slice());
        assert!(node.sessions.get(&source_addr).is_some());
        assert!(
            !node.pending_session_traffic.has_traffic_for(&source_addr),
            "empty pending guard should keep the fast path synchronous"
        );
    }

    #[test]
    fn authenticated_transit_data_does_not_replace_proven_outbound_route() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let proven_outbound_hop = node_addr(0x54);
        let passive_ingress_hop = node_addr(0x55);
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            b"directional transit data",
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            passive_ingress_hop,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                crate::transport::PacketBuffer::new(plaintext),
                SessionMessageType::EndpointData.to_byte(),
            ),
        );

        let mut config = crate::config::Config::new();
        config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
        let mut node = Node::with_identity(local, config).expect("node");
        node.sessions
            .insert(source_addr, established_entry(node.identity(), &peer));
        node.learn_reverse_route(source_addr, proven_outbound_hop);

        let mut commit = SessionReceiveBatchCommit::default();
        let _deliveries = dispatch.dispatch_endpoint_data_batched(&mut commit);
        let _pending_flush = commit.finish(&mut node);

        let snapshot = node.learned_route_table_snapshot(Node::now_ms());
        assert_eq!(snapshot.destination_count, 1);
        assert_eq!(snapshot.route_count, 1);
        assert_eq!(
            snapshot.destinations[0].routes[0].next_hop,
            proven_outbound_hop.to_string(),
            "authenticated inbound transit must not enter outbound route rotation"
        );
    }

    #[test]
    fn endpoint_data_batched_dispatch_reports_pending_flush_owner() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"fast endpoint pending".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                crate::transport::PacketBuffer::new(plaintext),
                SessionMessageType::EndpointData.to_byte(),
            ),
        );

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let _endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));
        assert!(
            !node
                .pending_session_traffic
                .push_endpoint_data_batch_with_enqueued_at_ms(
                    source_addr,
                    vec![crate::node::EndpointDataPayload::from_packet_payload(vec![0xaa])
                        .expect("test endpoint payload")],
                    8,
                    8,
                    1_000,
                )
                .destination_dropped()
        );

        let mut commit = SessionReceiveBatchCommit::default();
        let _delivery = dispatch.dispatch_endpoint_data_batched(&mut commit);
        let pending_flush = commit.finish(&mut node);

        assert_eq!(pending_flush, vec![source_addr]);
        assert!(
            node.pending_session_traffic.has_traffic_for(&source_addr),
            "batched dispatch should report, not synchronously drain, pending traffic"
        );
    }

    #[tokio::test]
    async fn ipv6_shim_batched_dispatch_queues_tun_packets_and_reports_pending_flush() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let mut node = Node::with_identity(local, crate::config::Config::new()).expect("node");
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        node.tun_tx = Some(tun_tx);

        assert!(
            !node
                .pending_session_traffic
                .push_tun_packet(source_addr, vec![0xaa], 8, 8)
                .destination_dropped()
        );

        let mut ipv6 = Vec::new();
        ipv6.extend_from_slice(&[0x60, 0, 0, 0]);
        ipv6.extend_from_slice(&4u16.to_be_bytes());
        ipv6.push(59);
        ipv6.push(64);
        ipv6.extend_from_slice(
            &crate::FipsAddress::from_node_addr(&source_addr)
                .to_ipv6()
                .octets(),
        );
        ipv6.extend_from_slice(
            &crate::FipsAddress::from_node_addr(node.node_addr())
                .to_ipv6()
                .octets(),
        );
        ipv6.extend_from_slice(&[1, 2, 3, 4]);
        let expected_ipv6 = ipv6.clone();
        assert!(crate::upper::ipv6_shim::compress_ipv6_with_port_header_in_place(
            &mut ipv6,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
        ));

        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::DataPacket.to_byte(),
            0,
            &ipv6,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                crate::transport::PacketBuffer::new(plaintext),
                SessionMessageType::DataPacket.to_byte(),
            ),
        );

        assert!(dispatch.is_ipv6_shim_data_packet());
        let mut packets = Vec::new();
        let mut commit = SessionReceiveBatchCommit::default();
        dispatch.dispatch_ipv6_shim_batched(&mut node, &mut packets, &mut commit);
        assert_eq!(packets.len(), 1);
        assert!(!commit.is_empty());

        node.flush_dataplane_tun_session_batch(&mut packets, &mut commit)
            .await;

        assert!(packets.is_empty());
        assert!(commit.is_empty());
        let packet = tun_rx
            .try_recv_packet()
            .expect("batched shim packet should be queued to TUN");
        assert_eq!(packet.as_slice(), expected_ipv6.as_slice());
        assert!(
            node.pending_session_traffic.has_traffic_for(&source_addr),
            "batched TUN dispatch should report pending flush; without a dataplane owner the pending packet remains queued"
        );
    }
