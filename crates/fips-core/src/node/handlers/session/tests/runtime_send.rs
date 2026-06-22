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
    async fn endpoint_bulk_send_lease_dispatches_feedback_before_worker_batch() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{LinkId, TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let dest = Identity::generate();
        let next_hop = Identity::generate();
        let dest_identity = PeerIdentity::from_pubkey_full(dest.pubkey_full());
        let next_hop_identity = PeerIdentity::from_pubkey_full(next_hop.pubkey_full());
        let dest_addr = *dest_identity.node_addr();
        let next_hop_addr = *next_hop_identity.node_addr();
        let transport_id = TransportId::new(0x5A);

        let mut node = Node::with_identity(local, crate::config::Config::new()).expect("node");
        let mut session = established_entry(&node.identity, &dest);
        session.mark_established(1_000);
        session.init_mmp(&node.config.node.session_mmp);
        assert!(node.sessions.insert(dest_addr, session).is_none());

        let active_peer = ActivePeer::with_session(
            next_hop_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &next_hop),
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
            .insert_with_current_session_index(next_hop_addr, active_peer);

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
        let prepared = crate::node::FmpSendPreparation {
            their_index: SessionIndex::new(0x2020),
            transport_id,
            remote_addr: TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0,
            flags: 0,
            payload_len: 0,
        };
        let send_target = PipelinedEndpointSendTarget::resolve(&udp, &prepared)
            .await
            .expect("started UDP transport resolves send target")
            .into_selected_send_target();
        let workers = crate::node::encrypt_worker::EncryptWorkerPool::spawn(1);
        let (runtime, mut feedback_rx) = crate::node::EndpointBulkSendRuntime::channel(8);
        let fsp = node
            .sessions
            .get(&dest_addr)
            .and_then(|entry| entry.endpoint_bulk_fsp_lease())
            .expect("established session should export FSP lease state");
        let fmp = node
            .peers
            .endpoint_bulk_fmp_lease(&next_hop_addr)
            .expect("active peer should export FMP lease state");
        runtime.publish(crate::node::EndpointBulkSendLease::new(
            *node.node_addr(),
            dest_addr,
            next_hop_addr,
            1234,
            9,
            3,
            false,
            fsp,
            fmp,
            send_target,
            workers,
            std::time::Duration::from_secs(1),
        ));

        let payloads = [
            EndpointDataPayload::new(vec![0xee; 96]),
            EndpointDataPayload::new(vec![0xdd; 128]),
        ];
        assert!(
            runtime.try_send_bulk_batch_to_peer(dest_identity, &payloads),
            "published lease should dispatch the bulk batch"
        );
        let feedback = feedback_rx
            .try_recv()
            .expect("endpoint mover must enqueue feedback before worker dispatch");
        assert_eq!(feedback.records.len(), payloads.len());
        for record in &feedback.records {
            assert_eq!(record.dest_addr, dest_addr);
            assert_eq!(record.next_hop_addr, next_hop_addr);
            let crate::node::EndpointBulkSendSessionBookkeeping::Fsp { path_mtu, .. } =
                record.session_bookkeeping;
            assert_eq!(path_mtu, 1234);
        }

        node.apply_endpoint_bulk_send_feedback(feedback);
        let session = node.sessions.get(&dest_addr).expect("session exists");
        let (packets_sent, _, bytes_sent, _) = session.traffic_counters();
        assert_eq!(packets_sent, payloads.len() as u64);
        assert_eq!(
            bytes_sent,
            payloads
                .iter()
                .map(|payload| payload.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(session.last_outbound_next_hop(), Some(next_hop_addr));
        assert_eq!(
            session
                .mmp()
                .expect("session MMP")
                .path_mtu
                .current_mtu(),
            1234
        );
        let peer = node.peers.get(&next_hop_addr).expect("peer exists");
        assert_eq!(peer.link_stats().packets_sent, payloads.len() as u64);
        assert_eq!(
            node.stats().forwarding.originated_packets,
            payloads.len() as u64
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
            body: PipelinedEndpointWireBody::InnerPlaintext(&inner_plaintext),
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
            body: PipelinedEndpointWireBody::InnerPlaintext(&inner_plaintext),
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

        let batched_route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot for batch target");
        let batched_route =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, batched_route_snapshot, 9, 7, false);
        let batch_target = batched_route
            .batch_target(&transports)
            .await
            .expect("batch target should resolve")
            .expect("UDP route should provide a reusable batch target");
        assert_eq!(
            batch_target.path_mtu, 1234,
            "batch target should cache the selected transport path MTU"
        );

        let batched_payload = EndpointDataPayload::new(vec![0xdd; 96]);
        let batched_inner_plaintext = vec![0xbb; 112];
        let batched_send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &batched_payload,
            now_ms: 0x2233_4455,
            timestamp: 0x6677_8899,
            fsp_flags: 0,
            body: PipelinedEndpointWireBody::InnerPlaintext(&batched_inner_plaintext),
            my_coords: None,
            dest_coords: None,
        };
        let fsp_before_batched = sessions
            .get(&dest_addr)
            .expect("session exists before batched send")
            .send_counter();
        let fmp_before_batched = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists before batched send")
            .current_send_counter();

        let batched_dispatch = PipelinedEndpointPeerRuntimeSend::resolve_dispatch_with_batch_target(
            &batched_route,
            batched_send,
            &batch_target,
            &mut sessions,
            &mut peers,
        )
        .expect("batch target dispatch should reserve")
        .expect("established batched peer runtime send should dispatch");

        assert_eq!(batched_dispatch.dest_addr(), dest_addr);
        assert_eq!(batched_dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            batched_dispatch.fsp_reservation_input().path_mtu,
            1234,
            "batched dispatch should reuse the cached transport path MTU"
        );
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after batched send")
                .send_counter(),
            fsp_before_batched + 1,
            "batch target path should still consume exactly one FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after batched send")
                .current_send_counter(),
            fmp_before_batched + 1,
            "batch target path should still consume exactly one FMP counter"
        );

        let batched_prepared = batched_dispatch.into_prepared_send(None);
        assert_eq!(batched_prepared.dest_addr, dest_addr);
        assert_eq!(batched_prepared.next_hop_addr, dest_addr);
        assert_eq!(
            batched_prepared.fsp_bookkeeping.counter,
            fsp_before_batched
        );
        assert_eq!(batched_prepared.fmp_counter, fmp_before_batched);
        assert_eq!(batched_prepared.worker_job.counter, fmp_before_batched);
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
            body: PipelinedEndpointWireBody::InnerPlaintext(&inner_plaintext),
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
            body: PipelinedEndpointWireBody::InnerPlaintext(&inner_plaintext),
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

        let send_target_for_batch = send_target.clone();
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

        let batch_payload_a = EndpointDataPayload::new(vec![0x11; 96]);
        let batch_payload_b = EndpointDataPayload::new(vec![0x22; 48]);
        let batch_inner_a = vec![0xa1; 112];
        let batch_inner_b = vec![0xb2; 64];
        let batch_send_a = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &batch_payload_a,
            now_ms: 0x1122_3345,
            timestamp: 0x5566_7789,
            fsp_flags: 0,
            body: PipelinedEndpointWireBody::InnerPlaintext(&batch_inner_a),
            my_coords: None,
            dest_coords: None,
        };
        let batch_send_b = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &batch_payload_b,
            now_ms: 0x1122_3346,
            timestamp: 0x5566_7790,
            fsp_flags: 0,
            body: PipelinedEndpointWireBody::InnerPlaintext(&batch_inner_b),
            my_coords: None,
            dest_coords: None,
        };
        let route_snapshot = peers
            .prepare_peer_runtime_route_snapshot(&dest_addr)
            .expect("active peer should prepare route snapshot for batch");
        let batch_target = PipelinedEndpointBatchTarget {
            send_target: send_target_for_batch,
            path_mtu: route_snapshot.path_mtu(&transport),
        };
        let batch_route =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false);
        let batch_fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists before batch")
            .send_counter();
        let batch_fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists before batch")
            .current_send_counter();

        let prepared_batch =
            PipelinedEndpointPeerRuntimeBatchSend::resolve_prepared_sends_with_batch_target(
                &batch_route,
                [batch_send_a, batch_send_b],
                &batch_target,
                &mut sessions,
                &mut peers,
            )
            .expect("batch send should reserve from both registries")
            .expect("available worker batch should dispatch");
        assert_eq!(prepared_batch.len(), 2);
        assert_eq!(prepared_batch[0].fsp_bookkeeping.counter, batch_fsp_before);
        assert_eq!(
            prepared_batch[1].fsp_bookkeeping.counter,
            batch_fsp_before + 1
        );
        assert_eq!(prepared_batch[0].fmp_counter, batch_fmp_before);
        assert_eq!(prepared_batch[1].fmp_counter, batch_fmp_before + 1);
        assert_eq!(prepared_batch[0].worker_job.counter, batch_fmp_before);
        assert_eq!(prepared_batch[1].worker_job.counter, batch_fmp_before + 1);
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after batch")
                .send_counter(),
            batch_fsp_before + 2,
            "batch should consume exactly one FSP counter per packet"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after batch")
                .current_send_counter(),
            batch_fmp_before + 2,
            "batch should consume exactly one FMP counter per packet"
        );

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
        let blocked_attempt_fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists before blocked attempt")
            .send_counter();
        let blocked_attempt_fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists before blocked attempt")
            .current_send_counter();

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
            blocked_attempt_fsp_before,
            "blocked attempt must not consume another FSP counter"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after blocked attempt")
                .current_send_counter(),
            blocked_attempt_fmp_before,
            "blocked attempt must not consume another FMP counter"
        );

        let blocked_batch_fsp_before = sessions
            .get(&dest_addr)
            .expect("session exists before blocked batch")
            .send_counter();
        let blocked_batch_fmp_before = peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists before blocked batch")
            .current_send_counter();
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
        let blocked_batch_route =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, blocked_snapshot, 9, 7, false);
        assert!(
            PipelinedEndpointPeerRuntimeBatchSend::resolve_prepared_sends_with_batch_target(
                &blocked_batch_route,
                [batch_send_a],
                &batch_target,
                &mut sessions,
                &mut peers,
            )
            .expect("unavailable worker batch is a recoverable no-dispatch result")
            .is_none()
        );
        assert_eq!(
            sessions
                .get(&dest_addr)
                .expect("session still exists after blocked batch")
                .send_counter(),
            blocked_batch_fsp_before,
            "blocked batch must not consume FSP counters"
        );
        assert_eq!(
            peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists after blocked batch")
                .current_send_counter(),
            blocked_batch_fmp_before,
            "blocked batch must not consume FMP counters"
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
            body: PipelinedEndpointWireBody::InnerPlaintext(&inner_plaintext),
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
