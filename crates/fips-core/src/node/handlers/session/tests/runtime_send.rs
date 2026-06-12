    #[cfg(unix)]
    #[test]
    fn session_datagram_runtime_route_owns_next_hop_path_mtu_and_bookkeeping() {
        use crate::PeerIdentity;
        use crate::config::RoutingMode;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportHandle, TransportId};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let dest = Identity::generate();
        let transit = Identity::generate();
        let transit_identity = PeerIdentity::from_pubkey_full(transit.pubkey_full());
        let dest_addr = *dest.node_addr();
        let transit_addr = *transit_identity.node_addr();
        let transport_id = TransportId::new(0x57);

        let mut config = crate::config::Config::new();
        config.node.routing.mode = RoutingMode::ReplyLearned;
        let mut node = Node::with_identity(local, config).expect("node");

        let mut session = established_entry(&node.identity, &dest);
        session.mark_established(0x1000);
        session.init_mmp(&node.config.node.session_mmp);
        assert_eq!(
            session.mmp().expect("session mmp").path_mtu.current_mtu(),
            u16::MAX
        );
        assert!(node.sessions.insert(dest_addr, session).is_none());

        let active_peer = ActivePeer::with_session(
            transit_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &transit),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string("127.0.0.1:9"),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(transit_addr, active_peer);
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
                .is_none()
        );
        node.learn_reverse_route(dest_addr, transit_addr);

        let mut datagram = SessionDatagram::new(
            *node.node_addr(),
            dest_addr,
            vec![SessionMessageType::DataPacket.to_byte(), 0, 0, 0],
        )
        .with_ttl(9);
        let route = node
            .resolve_session_datagram_runtime_route(&mut datagram)
            .expect("learned transit route should resolve");

        assert_eq!(route.dest_addr(), dest_addr);
        assert_eq!(route.next_hop_addr(), transit_addr);
        assert_eq!(route.path_mtu(), 1234);
        assert!(
            route.source_mmp_seeded(),
            "route owner should seed the session source-side MMP path MTU"
        );
        assert_eq!(
            datagram.path_mtu, 1234,
            "route owner should min-fold the outgoing transport MTU into the datagram"
        );
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .and_then(|entry| entry.mmp())
                .expect("session mmp")
                .path_mtu
                .current_mtu(),
            1234
        );

        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let encoded_len = datagram.encode().len();
        route.record_success(&mut node, encoded_len);
        let session = node.sessions.get(&dest_addr).expect("session exists");
        assert_eq!(
            session.last_outbound_next_hop(),
            Some(transit_addr),
            "route owner should record the successful outbound next hop"
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 1
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + encoded_len as u64
        );

        let route = node
            .resolve_session_datagram_runtime_route(&mut datagram)
            .expect("learned transit route should still resolve");
        route.record_failure(&mut node);
        let snapshot = node.learned_route_table_snapshot(Node::now_ms());
        let learned = snapshot
            .destinations
            .iter()
            .find(|dest| dest.destination == dest_addr.to_string())
            .and_then(|dest| {
                dest.routes
                    .iter()
                    .find(|route| route.next_hop == transit_addr.to_string())
            })
            .expect("learned transit route should remain visible");
        assert_eq!(
            learned.failures, 1,
            "route owner should record send failure against the selected learned next hop"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_peer_runtime_send_owns_transport_path_mtu_route_plan_and_runtime_dispatch()
     {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use std::collections::HashMap;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let source_addr = node_addr(0x10);
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(dest_addr, established_entry(&local, &peer))
                .is_none()
        );

        let mut peers = crate::node::PeerLifecycleRegistry::default();
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&local, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &crate::mmp::MmpConfig::default(),
            Some([0x02; 8]),
        );
        peers.insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");

        let mut transports = HashMap::new();
        assert!(
            transports
                .insert(transport_id, crate::transport::TransportHandle::Udp(udp))
                .is_none()
        );

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot");
        let runtime_route =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false);

        let fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointPeerRuntimeSend::new(runtime_route, send)
            .resolve_dispatch(&transports, &mut sessions, &mut peers)
            .await
            .expect("peer runtime send owner should build runtime plan and dispatch")
            .expect("established peer runtime send should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            dispatch.fsp_reservation_input().path_mtu,
            1234,
            "peer runtime send owner should derive path MTU from the selected transport"
        );
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "peer runtime send owner should consume exactly one FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "peer runtime send owner should consume exactly one FMP counter"
        );

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_before);
        assert_eq!(prepared.fmp_counter, fmp_before);

        let missing_transport_send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let missing_transport_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0x2020),
            TransportId::new(0x99),
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            0,
            true,
        );
        let missing_transport_route = PipelinedEndpointPeerRuntimeRoute::new(
            source_addr,
            missing_transport_snapshot,
            9,
            7,
            false,
        );

        assert!(matches!(
            PipelinedEndpointPeerRuntimeSend::new(
                missing_transport_route,
                missing_transport_send,
            )
            .resolve_dispatch(&transports, &mut sessions, &mut peers)
            .await,
            Err(PipelinedEndpointPeerRuntimeSendError::RuntimeSend(
                PipelinedEndpointRuntimeSendError::TransportNotFound(id),
            )) if id == TransportId::new(0x99)
        ));
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after missing transport")
                .send_counter(),
            fsp_before + 1,
            "missing transport must fail before consuming another FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after missing transport")
                .current_send_counter(),
            fmp_before + 1,
            "missing transport must fail before consuming another FMP counter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_runtime_send_owns_transport_target_and_reservation_handoff() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use std::collections::HashMap;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let source_addr = node_addr(0x10);
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(dest_addr, established_entry(&local, &peer))
                .is_none()
        );

        let mut peers = crate::node::PeerLifecycleRegistry::default();
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&local, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &crate::mmp::MmpConfig::default(),
            Some([0x02; 8]),
        );
        peers.insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");

        let mut transports = HashMap::new();
        assert!(
            transports
                .insert(transport_id, crate::transport::TransportHandle::Udp(udp))
                .is_none()
        );

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot");
        let transport = transports
            .get(&transport_id)
            .expect("transport should exist for runtime plan");
        let runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false)
                .into_runtime_send_plan(&send, transport)
                .expect("runtime route should build send plan");

        let fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointRuntimeSend::new(runtime)
            .resolve_dispatch(&transports, &mut sessions, &mut peers)
            .await
            .expect("runtime send owner should resolve transport and reserve")
            .expect("established runtime send should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "runtime send owner should consume exactly one FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "runtime send owner should consume exactly one FMP counter"
        );

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_before);
        assert_eq!(prepared.fmp_counter, fmp_before);

        let missing_transport_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0x2020),
            TransportId::new(0x99),
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            0,
            true,
        );
        let missing_transport_route =
            PipelinedEndpointRoutePlan::new(source_addr, dest_addr, 1234, 9, 7, false);
        let missing_transport_plan = missing_transport_route
            .build_send_plan(&send)
            .expect("missing-transport send plan should build");
        let missing_transport_runtime = PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
            missing_transport_route,
            missing_transport_plan,
            missing_transport_snapshot,
        )
        .expect("missing-transport runtime should still build send plan");

        assert!(matches!(
            PipelinedEndpointRuntimeSend::new(missing_transport_runtime)
                .resolve_dispatch(&transports, &mut sessions, &mut peers)
                .await,
            Err(PipelinedEndpointRuntimeSendError::TransportNotFound(id))
                if id == TransportId::new(0x99)
        ));
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after missing transport")
                .send_counter(),
            fsp_before + 1,
            "missing transport must fail before consuming another FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after missing transport")
                .current_send_counter(),
            fmp_before + 1,
            "missing transport must fail before consuming another FMP counter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_runtime_send_attempt_owns_target_and_reservations() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let source_addr = node_addr(0x10);
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(dest_addr, established_entry(&local, &peer))
                .is_none()
        );

        let mut peers = crate::node::PeerLifecycleRegistry::default();
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&local, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &crate::mmp::MmpConfig::default(),
            Some([0x02; 8]),
        );
        peers.insert_with_current_session_index(dest_addr, active_peer);

        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        let transport = TransportHandle::Udp(udp);
        let TransportHandle::Udp(udp) = &transport else {
            unreachable!("test transport is UDP");
        };

        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };

        let route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot");
        let runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false)
                .into_runtime_send_plan(&send, &transport)
                .expect("runtime route should build send plan");
        let send_target = runtime
            .resolve_send_target(udp)
            .await
            .expect("started UDP transport resolves send target");

        let fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointRuntimeSendAttempt::new(runtime, send_target)
            .reserve(&mut sessions, &mut peers)
            .expect("runtime send attempt should reserve from both registries")
            .expect("established runtime send attempt should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "attempt should consume exactly one FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "attempt should consume exactly one FMP counter"
        );

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_before);
        assert_eq!(prepared.fmp_counter, fmp_before);
        assert_eq!(prepared.worker_job.counter, fmp_before);

        let blocked_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            0,
            false,
        );
        let blocked_runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, blocked_snapshot, 9, 7, false)
                .into_runtime_send_plan(&send, &transport)
                .expect("blocked worker runtime should still build send plan");
        let blocked_target = blocked_runtime
            .resolve_send_target(udp)
            .await
            .expect("started UDP transport resolves blocked send target");

        assert!(
            PipelinedEndpointRuntimeSendAttempt::new(blocked_runtime, blocked_target)
                .reserve(&mut sessions, &mut peers)
                .expect("unavailable worker is a recoverable no-dispatch result")
                .is_none()
        );
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after blocked attempt")
                .send_counter(),
            fsp_before + 1,
            "blocked attempt must not consume another FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after blocked attempt")
                .current_send_counter(),
            fmp_before + 1,
            "blocked attempt must not consume another FMP counter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_runtime_dispatch_owns_target_reservations_and_prepared_send() {
        use crate::node::wire::{FLAG_SP, build_established_header};
        use crate::node::{PreparedFmpWorkerReservation, session::FspSendReservation};
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use ring::aead::{LessSafeKey, UnboundKey};

        fn test_cipher(byte: u8) -> LessSafeKey {
            let unbound =
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[byte; 32]).expect("test key");
            LessSafeKey::new(unbound)
        }

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let next_hop_addr = node_addr(0x30);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: &inner_plaintext,
            my_coords: None,
            dest_coords: None,
        };
        let route = PipelinedEndpointRoutePlan::new(source_addr, next_hop_addr, 1234, 9, 7, false);
        let plan = route
            .build_send_plan(&send)
            .expect("route plan should build send plan");
        let expected_originated_bytes = plan.link_plaintext_len() + crate::noise::TAG_SIZE;
        let expected_fsp_reservation = plan.fsp_reservation_input();

        let transport_id = TransportId::new(0x55);
        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fmp_prepared = crate::node::FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: plan.fmp_payload_len(),
        };
        let snapshot = crate::node::PeerRuntimeSendSnapshot::new(next_hop_addr, fmp_prepared, true);
        let runtime = PipelinedEndpointRuntimeSendPlan::from_parts(route, plan, snapshot)
            .expect("matching route/send/FMP preparation should form runtime plan");

        let send_target = runtime
            .resolve_send_target(&udp)
            .await
            .expect("started UDP transport resolves send target");
        let fmp_counter = 0x1112_1314_1516_1718;
        let fsp_counter = 0x0102_0304_0506_0708;
        let fmp_header = build_established_header(
            runtime.fmp_prepared().their_index,
            fmp_counter,
            runtime.fmp_prepared().flags,
            runtime.fmp_payload_len(),
        );
        let fsp_header = build_fsp_header(
            fsp_counter,
            send.fsp_flags,
            expected_fsp_reservation.payload_len,
        );
        let fmp_reservation = PreparedFmpWorkerReservation {
            counter: fmp_counter,
            header: fmp_header,
            cipher: test_cipher(7),
            predicted_bytes: ESTABLISHED_HEADER_SIZE
                + runtime.fmp_payload_len() as usize
                + crate::noise::TAG_SIZE,
        };
        let fsp_reservation = FspSendReservation {
            counter: fsp_counter,
            header: fsp_header,
            cipher: test_cipher(8),
        };

        let dispatch = PipelinedEndpointRuntimeSendDispatch::new(
            runtime,
            send_target,
            fmp_reservation,
            fsp_reservation,
        );
        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), next_hop_addr);
        assert_eq!(dispatch.fsp_reservation_input(), expected_fsp_reservation);

        let prepared = dispatch.into_prepared_send(None);
        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, next_hop_addr);
        assert_eq!(prepared.fmp_counter, fmp_counter);
        assert_eq!(prepared.fmp_timestamp_ms, 0x0102_0304);
        assert_eq!(prepared.originated_bytes, expected_originated_bytes);
        assert_eq!(prepared.fsp_bookkeeping.counter, fsp_counter);
        assert_eq!(prepared.fsp_bookkeeping.next_hop, Some(next_hop_addr));
        assert_eq!(prepared.worker_job.counter, fmp_counter);
        assert!(prepared.worker_job.bulk_endpoint_data);
        assert!(!prepared.worker_job.drop_on_backpressure);
        assert_eq!(prepared.worker_job.scheduling_weight, 7);
        assert!(prepared.worker_job.queued_at.is_none());
        assert_eq!(
            &prepared.worker_job.wire_buf[..ESTABLISHED_HEADER_SIZE],
            &fmp_header
        );
    }
