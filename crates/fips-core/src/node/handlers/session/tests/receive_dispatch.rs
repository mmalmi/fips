    use crate::node::session_wire::fsp_prepend_inner_header;

    #[test]
    fn application_receive_refreshes_previous_hop_peer_without_direct_source_trust() {
        use crate::PeerIdentity;
        use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
        use crate::node::retry::RetryState;
        use crate::peer::ActivePeer;
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
            make_xk_session(&node.identity, &previous_hop),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            TransportId::new(0x55),
            TransportAddr::from_string("203.0.113.9:2121"),
            LinkStats::new(),
            true,
            &node.config.node.mmp,
            None,
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
                body_len: 512,
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
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("source session should remain");
        assert_eq!(
            entry.last_inbound_data_frame_ms(),
            1_000,
            "previous-hop liveness must not become direct-source payload trust"
        );
    }

    #[test]
    fn authenticated_fmp_receive_clears_direct_probe_retry_on_direct_path() {
        use crate::PeerIdentity;
        use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
        use crate::node::retry::RetryState;
        use crate::peer::ActivePeer;
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
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1011),
            SessionIndex::new(0x2021),
            transport_id,
            transport_addr.clone(),
            LinkStats::new(),
            true,
            &node.config.node.mmp,
            None,
        );
        active_peer.touch(Node::now_ms().saturating_sub(11_000));
        node.peers
            .insert_with_current_session_index(peer_addr, active_peer);

        let mut retry = RetryState::new(peer_config);
        retry.reconnect = true;
        node.retry_pending.insert(peer_addr, retry);

        node.record_authenticated_fmp_receive_facts(
            crate::node::AuthenticatedFmpReceiveFacts::new(
                peer_identity,
                transport_id,
                &transport_addr,
                Node::now_ms(),
                256,
                11,
                22,
                0,
            ),
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
        use crate::peer::ActivePeer;
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
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1012),
            SessionIndex::new(0x2022),
            transport_id,
            transport_addr.clone(),
            LinkStats::new(),
            true,
            &node.config.node.mmp,
            None,
        );
        active_peer.touch(Node::now_ms().saturating_sub(11_000));
        node.peers
            .insert_with_current_session_index(peer_addr, active_peer);

        let mut retry = RetryState::new(peer_config);
        retry.reconnect = true;
        node.retry_pending.insert(peer_addr, retry);

        node.record_authenticated_fmp_receive_facts(
            crate::node::AuthenticatedFmpReceiveFacts::new(
                peer_identity,
                transport_id,
                &transport_addr,
                Node::now_ms(),
                256,
                11,
                22,
                0,
            ),
            Some(&relay_addr),
        );

        assert!(
            node.retry_pending.contains_key(&peer_addr),
            "forwarded authenticated FMP traffic must not prove the direct peer path is healthy"
        );
    }

    #[test]
    fn fsp_receive_sync_requests_pm2_owner_refresh_only_on_epoch_promotion() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        let initial_k_bit = entry.current_k_bit();
        entry.set_pending_session(make_xk_session(&local, &peer));

        let promoted = entry.apply_fsp_receive_sync_result(
            crate::node::session::FspReceiveSync {
                counter: 7,
                slot: crate::node::session::EpochSlot::Pending,
                received_k_bit: !initial_k_bit,
                timestamp: 0x0102_0304,
                plaintext_len: FSP_INNER_HEADER_SIZE + 16,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            2_000,
            Instant::now(),
        );

        assert!(promoted.is_applied());
        assert!(
            promoted.refresh_packet_mover2_owner(),
            "pending promotion changes FSP epoch topology and must refresh the PM2 owner"
        );
        assert_eq!(entry.current_k_bit(), !initial_k_bit);
        assert!(entry.pending_new_session().is_none());
        assert!(entry.previous_highest_counter().is_some());

        let current = entry.apply_fsp_receive_sync_result(
            crate::node::session::FspReceiveSync {
                counter: 8,
                slot: crate::node::session::EpochSlot::Current,
                received_k_bit: entry.current_k_bit(),
                timestamp: 0x0102_0305,
                plaintext_len: FSP_INNER_HEADER_SIZE + 16,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            2_100,
            Instant::now(),
        );

        assert!(current.is_applied());
        assert!(
            !current.refresh_packet_mover2_owner(),
            "ordinary current-epoch replay mirroring must not refresh the PM2 owner"
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
            plaintext,
            SessionMessageType::EndpointData.to_byte(),
            0,
            0x0102_0304,
        );

        assert_eq!(message.body(), endpoint_payload);
        let delivery = message.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);
    }

    #[test]
    fn authenticated_session_message_can_own_plaintext_inside_wire_buffer() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let endpoint_payload = b"buffer endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let mut buffer = b"outer-fmp-prefix".to_vec();
        let plaintext_offset = buffer.len();
        buffer.extend_from_slice(&plaintext);
        buffer.extend_from_slice(b"outer-fmp-trailer");

        let message = AuthenticatedSessionMessage::from_buffer(
            source_peer,
            buffer,
            plaintext_offset,
            plaintext.len(),
            SessionMessageType::EndpointData.to_byte(),
            0,
            0x0102_0304,
        );

        assert_eq!(message.plaintext(), plaintext);
        assert_eq!(message.body(), endpoint_payload);
        let delivery = message.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);
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
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        assert_eq!(dispatch.source_addr(), &source_addr);
        assert_eq!(dispatch.previous_hop_addr(), &previous_hop_addr);
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
                body_len: endpoint_payload.len(),
                direct_path: false,
            })
        );
        let commit = dispatch.commit();
        assert_eq!(commit.source_addr(), &source_addr);
        assert_eq!(
            commit.receive_completion(),
            Some(SessionReceiveCompletion {
                source_addr,
                previous_hop_addr,
                body_len: endpoint_payload.len(),
                direct_path: false,
            })
        );
        let local = Identity::generate();
        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(source_addr, established_entry(&local, &peer));
        assert!(commit.record_receive(&mut sessions, 0x0bad_cafe));
        let entry = sessions.get(&source_addr).expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.last_activity(), 0x0bad_cafe);
        assert_eq!(
            entry.last_inbound_data_frame_ms(),
            1000,
            "relayed application data must not refresh direct-path trust"
        );

        let delivery = dispatch.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);

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
                report_plaintext,
                SessionMessageType::SenderReport.to_byte(),
                0,
                0x0102_0304,
            ),
        );
        assert_eq!(
            report_dispatch.receive_completion(),
            None,
            "MMP reports must not reset session idle/traffic counters"
        );
        let report_commit = report_dispatch.commit();
        assert_eq!(report_commit.source_addr(), &source_addr);
        assert_eq!(
            report_commit.receive_completion(),
            None,
            "MMP reports still flush pending packets without recording receive progress"
        );
        assert!(!report_commit.record_receive(&mut sessions, 0x0bad_f00d));
        let entry = sessions.get(&source_addr).expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.last_activity(), 0x0bad_cafe);
    }

    #[test]
    fn endpoint_data_fast_dispatch_finishes_receive_without_pending_flush() {
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
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let finish = dispatch.dispatch_endpoint_data_fast(&mut node);
        assert_eq!(finish.pending_flush_dest(), None);
        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, endpoint_payload);
            }
            event => panic!("expected single endpoint data event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(
            entry.last_inbound_data_frame_ms(),
            1000,
            "fast relayed endpoint data must not refresh direct-path trust"
        );
        assert!(
            !node.pending_session_traffic.has_traffic_for(&source_addr),
            "empty pending guard should keep the fast path synchronous"
        );
    }

    #[test]
    fn endpoint_data_fast_dispatch_reports_pending_flush_owner() {
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
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
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
                .push_endpoint_data_with_enqueued_at_ms(source_addr, vec![0xaa], 8, 8, 1_000)
                .destination_dropped()
        );

        let finish = dispatch.dispatch_endpoint_data_fast(&mut node);

        assert_eq!(finish.pending_flush_dest(), Some(source_addr));
        assert!(
            node.pending_session_traffic.has_traffic_for(&source_addr),
            "fast dispatch should report, not synchronously drain, pending traffic"
        );
    }
