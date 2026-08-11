    use crate::node::{
        SESSION_DIRECT_DEGRADED_HOLD_MS, session_wire::fsp_prepend_inner_header,
    };

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
    fn direct_inbound_data_does_not_clear_degradation_for_fallback_outbound_route() {
        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let source_addr = *Identity::generate().node_addr();
        let fallback_addr = *Identity::generate().node_addr();
        let now_ms = Node::now_ms();

        crate::node::tests::seed_dataplane_fsp_data_sent_for_test(
            &mut node,
            source_addr,
            fallback_addr,
            now_ms,
        );
        crate::node::tests::seed_dataplane_fsp_data_rx_for_test(
            &mut node,
            source_addr,
            source_addr,
            now_ms,
        );
        node.mark_session_direct_path_degraded(source_addr, now_ms);

        SessionDispatchCommit {
            source_addr,
            receive_completion: Some(SessionReceiveCompletion {
                source_addr,
                previous_hop_addr: source_addr,
                direct_path: true,
            }),
        }
        .finish_receive(&mut node);

        assert!(
            node.session_direct_path_degradation_active(&source_addr, now_ms),
            "a direct packet unrelated to the active fallback send must not restore direct payload routing"
        );
    }

    #[test]
    fn one_route_matched_direct_packet_does_not_clear_direct_degradation() {
        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let source_addr = *Identity::generate().node_addr();
        let now_ms = Node::now_ms();

        crate::node::tests::seed_dataplane_fsp_data_sent_for_test(
            &mut node,
            source_addr,
            source_addr,
            now_ms,
        );
        crate::node::tests::seed_dataplane_fsp_data_rx_for_test(
            &mut node,
            source_addr,
            source_addr,
            now_ms,
        );
        node.mark_session_direct_path_degraded(source_addr, now_ms);

        SessionDispatchCommit {
            source_addr,
            receive_completion: Some(SessionReceiveCompletion {
                source_addr,
                previous_hop_addr: source_addr,
                direct_path: true,
            }),
        }
        .finish_receive(&mut node);

        assert!(
            node.session_direct_path_degradation_active(&source_addr, now_ms),
            "one authenticated packet can be left in flight from the obsolete underlay"
        );
    }

    #[test]
    fn sustained_route_matched_direct_packets_clear_direct_degradation() {
        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let source_addr = *Identity::generate().node_addr();
        let now_ms = Node::now_ms();

        crate::node::tests::seed_dataplane_fsp_data_sent_for_test(
            &mut node,
            source_addr,
            source_addr,
            now_ms,
        );
        crate::node::tests::seed_dataplane_fsp_data_rx_for_test(
            &mut node,
            source_addr,
            source_addr,
            now_ms,
        );
        node.restart_session_direct_path_validation(source_addr, now_ms);

        for offset_ms in [100, 350, 600, 850] {
            assert!(
                !node.authenticated_direct_payload_validates_route(
                    &source_addr,
                    now_ms + offset_ms,
                ),
                "a short authenticated burst must keep route validation pending"
            );
        }
        assert!(
            node.authenticated_direct_payload_validates_route(&source_addr, now_ms + 1_100),
            "five fresh packets spanning one second prove sustained direct progress"
        );
        assert!(node.clear_session_direct_path_degraded(&source_addr));
        assert!(
            !node
                .session_direct_degradation
                .has_pending_validation(&source_addr)
        );
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
            addresses: vec![PeerAddress::with_priority(
                "udp",
                "198.51.100.20:61062",
                1,
            )],
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

        node.mark_session_direct_path_degraded(peer_addr, Node::now_ms());
        node.retry_pending
            .insert(peer_addr, RetryState::new(node.config.peers[0].clone()));
        assert!(node.session_direct_path_degradation_active(&peer_addr, Node::now_ms()));

        node.record_authenticated_fmp_receive_facts(
            crate::node::AuthenticatedFmpReceiveFacts {
                source_peer: peer_identity,
                transport_id,
                remote_addr: &transport_addr,
                packet_timestamp_ms: Node::now_ms(),
                packet_len: 256,
                fmp_counter: 12,
                inner_timestamp_ms: 23,
                fmp_flags: 0,
            },
            Some(&peer_addr),
        );

        assert!(
            node.session_direct_degradation
                .has_pending_validation(&peer_addr),
            "direct FMP control must not stand in for authenticated FSP payload"
        );
        assert!(
            !node.session_direct_path_degradation_active(&peer_addr, Node::now_ms()),
            "authenticated direct FMP recovery must immediately release the payload hold for a direct validation packet"
        );
        assert!(
            node.retry_pending.contains_key(&peer_addr),
            "the bounded direct retry remains until authenticated direct FSP payload validates recovery"
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
        assert_eq!(
            report_dispatch.direct_validation_source(),
            None,
            "routed MMP reports must not validate or move the fallback reply path"
        );

        let direct_report_plaintext = fsp_prepend_inner_header(
            0x0102_0305,
            SessionMessageType::SenderReport.to_byte(),
            0,
            b"direct report",
        );
        let direct_report_dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            source_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                crate::transport::PacketBuffer::new(direct_report_plaintext),
                SessionMessageType::SenderReport.to_byte(),
            ),
        );
        assert_eq!(direct_report_dispatch.receive_completion(), None);
        assert_eq!(
            direct_report_dispatch.direct_validation_source(),
            Some(source_addr),
            "authenticated direct FSP control should validate only the direct adjacency"
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
    fn authenticated_fallback_data_moves_stale_reply_owner_to_its_live_ingress() {
        let local = Identity::generate();
        let source = Identity::generate();
        let source_addr = *source.node_addr();
        let fallback = Identity::generate();
        let fallback_addr = *fallback.node_addr();

        let mut config = crate::config::Config::new();
        config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
        let mut node = Node::with_identity(local, config).expect("node");

        let direct_link = crate::transport::LinkId::new(1);
        let (direct_connection, direct_identity) =
            crate::node::tests::make_completed_connection_for_identity(
                &mut node,
                direct_link,
                crate::transport::TransportId::new(1),
                1_000,
                &source,
            );
        node.add_connection(direct_connection).unwrap();
        node.promote_connection(direct_link, direct_identity, 2_000)
            .unwrap();
        assert!(node.sync_dataplane_fmp_owner(&source_addr));

        let fallback_link = crate::transport::LinkId::new(2);
        let (fallback_connection, fallback_identity) =
            crate::node::tests::make_completed_connection_for_identity(
                &mut node,
                fallback_link,
                crate::transport::TransportId::new(2),
                1_000,
                &fallback,
            );
        node.add_connection(fallback_connection).unwrap();
        node.promote_connection(fallback_link, fallback_identity, 2_000)
            .unwrap();
        assert!(node.sync_dataplane_fmp_owner(&fallback_addr));

        node.sessions.insert(
            source_addr,
            established_entry(node.identity(), &source),
        );
        assert!(node.sync_dataplane_fsp_owner_from_current_session(&source_addr, 0));
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(source_addr),
            "fixture must start with replies pinned to the apparently healthy direct path"
        );

        let mut commit = SessionReceiveBatchCommit::default();
        commit.push_receive_completion(SessionReceiveCompletion {
            source_addr,
            previous_hop_addr: fallback_addr,
            direct_path: false,
        });
        let pending_flush = commit.finish(&mut node);

        assert!(pending_flush.is_empty());
        assert!(
            node.session_direct_path_degradation_active(&source_addr, Node::now_ms()),
            "authenticated application data on fallback is positive evidence that the direct session path cannot carry the reply"
        );
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(fallback_addr),
            "the reply owner must immediately follow the authenticated live ingress instead of waiting for direct-link liveness expiry"
        );
        assert_eq!(
            node.learned_route_table_snapshot(Node::now_ms()).route_count,
            0,
            "directional application ingress must remain reply affinity, not enter learned route rotation"
        );
        crate::node::tests::seed_dataplane_fsp_data_sent_for_test(
            &mut node,
            source_addr,
            fallback_addr,
            Node::now_ms(),
        );

        let direct_transport_id = node
            .get_peer(&source_addr)
            .and_then(|peer| peer.transport_id())
            .expect("direct transport");
        let direct_transport_addr = node
            .get_peer(&source_addr)
            .and_then(|peer| peer.current_addr())
            .cloned()
            .expect("direct address");
        node.config.peers.push(crate::config::PeerConfig::new(
            source.npub(),
            "udp",
            direct_transport_addr.to_string(),
        ));
        node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
        node.make_direct_payload_eligible_for_validation_after_fmp_recovery(&source_addr);
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(source_addr),
            "authenticated direct recovery must stage one prompt FSP validation route"
        );
        assert_eq!(
            node.dataplane
                .fsp_owner_activity(&source_addr)
                .and_then(|activity| activity.last_outbound_next_hop()),
            Some(fallback_addr),
            "staging direct validation must preserve the proven fallback until direct payload is sent"
        );
        node.record_authenticated_fmp_receive_facts(
            crate::node::AuthenticatedFmpReceiveFacts {
                source_peer: crate::PeerIdentity::from_pubkey_full(source.pubkey_full()),
                transport_id: direct_transport_id,
                remote_addr: &direct_transport_addr,
                packet_timestamp_ms: Node::now_ms(),
                packet_len: 128,
                fmp_counter: 1,
                inner_timestamp_ms: 1,
                fmp_flags: 0,
            },
            Some(&source_addr),
        );
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(source_addr),
            "fresh authenticated direct control must keep the bounded FSP validation staged"
        );

        let replacement_fallback = Identity::generate();
        let replacement_fallback_addr = *replacement_fallback.node_addr();
        let replacement_link = crate::transport::LinkId::new(3);
        let (replacement_connection, replacement_identity) =
            crate::node::tests::make_completed_connection_for_identity(
                &mut node,
                replacement_link,
                crate::transport::TransportId::new(3),
                1_000,
                &replacement_fallback,
            );
        node.add_connection(replacement_connection).unwrap();
        node.promote_connection(replacement_link, replacement_identity, 2_000)
            .unwrap();
        assert!(node.sync_dataplane_fmp_owner(&replacement_fallback_addr));

        let mut commit = SessionReceiveBatchCommit::default();
        commit.push_receive_completion(SessionReceiveCompletion {
            source_addr,
            previous_hop_addr: replacement_fallback_addr,
            direct_path: false,
        });
        let pending_flush = commit.finish(&mut node);

        assert!(pending_flush.is_empty());
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(replacement_fallback_addr),
            "alternate authenticated ingress must immediately replace a fallback without authenticated data return"
        );

        crate::node::tests::seed_dataplane_fsp_data_sent_for_test(
            &mut node,
            source_addr,
            replacement_fallback_addr,
            Node::now_ms(),
        );
        crate::node::tests::seed_dataplane_fsp_data_rx_for_test(
            &mut node,
            source_addr,
            replacement_fallback_addr,
            Node::now_ms(),
        );
        let mut commit = SessionReceiveBatchCommit::default();
        commit.push_receive_completion(SessionReceiveCompletion {
            source_addr,
            previous_hop_addr: fallback_addr,
            direct_path: false,
        });
        let pending_flush = commit.finish(&mut node);

        assert!(pending_flush.is_empty());
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(replacement_fallback_addr),
            "alternate authenticated ingress must not churn a fallback with recent authenticated data return"
        );

        node.record_active_route_failure(source_addr, replacement_fallback_addr);
        let route_after_failure = node.dataplane.fsp_owner_next_hop(&source_addr);
        assert_ne!(
            route_after_failure,
            Some(replacement_fallback_addr),
            "explicit route failure must remove the failed fallback"
        );
        let mut commit = SessionReceiveBatchCommit::default();
        commit.push_receive_completion(SessionReceiveCompletion {
            source_addr,
            previous_hop_addr: replacement_fallback_addr,
            direct_path: false,
        });
        let pending_flush = commit.finish(&mut node);

        assert!(pending_flush.is_empty());
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            route_after_failure,
            "in-flight ingress from a just-failed branch must not immediately reinstate it"
        );

        let mut commit = SessionReceiveBatchCommit::default();
        commit.push_receive_completion(SessionReceiveCompletion {
            source_addr,
            previous_hop_addr: fallback_addr,
            direct_path: false,
        });
        let pending_flush = commit.finish(&mut node);

        assert!(pending_flush.is_empty());
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(fallback_addr),
            "new authenticated fallback ingress must replace an explicitly failed fallback reply owner immediately"
        );

        // Keep exercising the production route-following function invoked by
        // post-authentication application receive completion. A live
        // asymmetric path can return every packet through the same fallback
        // for much longer than the initial direct-degradation hold; each
        // authenticated return must keep that proven reply owner stable
        // across every hold boundary.
        let mut ingress_ms = Node::now_ms().saturating_add(1_000);
        for cycle in 1..=4 {
            assert!(
                !node.follow_authenticated_fallback_ingress_for_session_reply(
                    source_addr,
                    fallback_addr,
                    ingress_ms,
                ),
                "cycle {cycle}: the existing authenticated fallback must not rewrite its owner"
            );
            assert_eq!(
                node.dataplane.fsp_owner_next_hop(&source_addr),
                Some(fallback_addr),
                "cycle {cycle}: the proven reply owner must remain stable"
            );
            assert!(
                node.session_direct_path_degradation_active(
                    &source_addr,
                    ingress_ms
                        .saturating_add(SESSION_DIRECT_DEGRADED_HOLD_MS)
                        .saturating_sub(1),
                ),
                "cycle {cycle}: authenticated fallback return must renew the hold"
            );
            ingress_ms = ingress_ms
                .saturating_add(SESSION_DIRECT_DEGRADED_HOLD_MS.saturating_sub(1_000));
        }
    }
