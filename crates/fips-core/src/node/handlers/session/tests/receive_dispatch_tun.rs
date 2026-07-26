    #[tokio::test]
    async fn traversal_offer_received_on_fallback_moves_answer_to_that_ingress() {
        use crate::discovery::nostr::{NostrDiscovery, TraversalOffer};

        let local = Identity::generate();
        let source = Identity::generate();
        let source_addr = *source.node_addr();
        let fallback = Identity::generate();
        let fallback_addr = *fallback.node_addr();

        let mut config = crate::config::Config::new();
        config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
        config.peers.push(crate::config::PeerConfig::new(
            source.npub(),
            "udp",
            "nat",
        ));
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
            "fixture must begin with traversal answers pinned to the stale-looking direct path"
        );

        let bootstrap = std::sync::Arc::new(NostrDiscovery::new_for_test());
        bootstrap.set_direct_refresh_admission(false);
        node.nostr_discovery = Some(bootstrap.clone());
        let now_ms = Node::now_ms();
        let offer = TraversalOffer {
            message_type: "offer".to_string(),
            session_id: "roaming-offer".to_string(),
            issued_at: now_ms,
            expires_at: now_ms.saturating_add(10_000),
            nonce: "roaming-nonce".to_string(),
            sender_npub: source.npub(),
            recipient_npub: node.identity().npub(),
            reflexive_address: None,
            local_addresses: Vec::new(),
            stun_server: None,
        };
        let payload = serde_json::to_vec(&offer).expect("offer JSON");
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::TraversalOffer.to_byte(),
            0,
            &payload,
        );
        AuthenticatedSessionDispatch::new(
            source_addr,
            fallback_addr,
            false,
            AuthenticatedSessionMessage::new(
                PeerIdentity::from_pubkey_full(source.pubkey_full()),
                crate::transport::PacketBuffer::new(plaintext),
                SessionMessageType::TraversalOffer.to_byte(),
            ),
        )
        .dispatch(&mut node)
        .await;

        assert!(
            node.session_direct_path_degradation_active(&source_addr, Node::now_ms()),
            "an authenticated traversal request on fallback proves the direct reply path needs replacement"
        );
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&source_addr),
            Some(fallback_addr),
            "the traversal answer must follow the live authenticated ingress instead of the dead direct path"
        );

        bootstrap.shutdown().await.expect("shutdown discovery");
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
