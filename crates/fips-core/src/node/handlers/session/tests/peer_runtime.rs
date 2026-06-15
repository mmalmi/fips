    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_peer_runtime_route_owns_snapshot_route_policy_and_send_plan() {
        use crate::node::wire::FLAG_SP;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
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

        let transport_id = TransportId::new(0x55);
        let route_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );
        let (packet_tx, _packet_rx) = packet_channel(4);
        let transport = TransportHandle::Udp(UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                mtu: Some(1234),
                ..Default::default()
            },
            packet_tx,
        ));
        let runtime_route =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, route_snapshot, 9, 7, false);
        assert_eq!(runtime_route.next_hop_addr(), dest_addr);
        assert_eq!(runtime_route.scheduling_weight(), 7);

        let runtime = runtime_route
            .into_runtime_send_plan(&send, &transport)
            .expect("peer runtime route owner should build the runtime send plan");

        assert_eq!(runtime.source_addr(), source_addr);
        assert_eq!(runtime.dest_addr(), dest_addr);
        assert_eq!(runtime.next_hop_addr(), dest_addr);
        assert_eq!(runtime.transport_id(), transport_id);
        assert_eq!(runtime.fmp_prepared().flags, FLAG_SP);
        assert!(runtime.fmp_worker_send_available());
        assert_eq!(
            runtime.fsp_reservation_input(),
            crate::node::FspWorkerSendReservationInput {
                flags: 0,
                payload_len: inner_plaintext.len() as u16,
                path_mtu: 1234,
            }
        );
        assert!(
            runtime.drop_on_backpressure(),
            "direct bulk endpoint traffic should keep explicit bulk-drop policy"
        );
        assert_eq!(runtime.scheduling_weight(), 7);

        let degraded_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            dest_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );
        let degraded_runtime =
            PipelinedEndpointPeerRuntimeRoute::new(source_addr, degraded_snapshot, 9, 7, true)
                .into_runtime_send_plan(&send, &transport)
                .expect("degraded direct route should still build runtime send plan");
        assert!(
            !degraded_runtime.drop_on_backpressure(),
            "blocked direct payload routes must not silently use bulk-drop policy"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_peer_runtime_route_request_owns_next_hop_snapshot_and_policy() {
        use crate::PeerIdentity;
        use crate::node::encrypt_worker;
        use crate::peer::ActivePeer;
        use crate::transport::{LinkId, TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x55);
        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
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
            .insert_with_current_session_index(dest_addr, active_peer);

        let request = PipelinedEndpointPeerRuntimeRouteRequest::new(
            *node.node_addr(),
            dest_addr,
            Node::now_ms(),
            node.config.node.session.default_ttl,
        );
        let runtime_route = request
            .resolve(&mut node)
            .expect("route request should resolve configured active peer");

        assert_eq!(runtime_route.next_hop_addr(), dest_addr);
        assert_eq!(runtime_route.transport_id(), transport_id);
        assert_eq!(
            runtime_route.scheduling_weight(),
            encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
            "route request should capture configured-peer scheduling weight"
        );
        assert_eq!(runtime_route.default_ttl(), 13);
        assert!(
            !runtime_route.direct_path_blocks_direct_payload(),
            "healthy direct route should keep the explicit bulk-drop policy available"
        );

        let missing_dest = node_addr(0x99);
        assert!(matches!(
            PipelinedEndpointPeerRuntimeRouteRequest::new(
                *node.node_addr(),
                missing_dest,
                Node::now_ms(),
                node.config.node.session.default_ttl,
            )
            .resolve(&mut node),
            Err(PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr })
                if dest_addr == missing_dest
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_peer_runtime_send_request_owns_route_request_and_dispatch() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

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
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
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
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();

        let dispatch = PipelinedEndpointPeerRuntimeSendRequest::new(
            *node.node_addr(),
            send,
            node.config.node.session.default_ttl,
        )
        .resolve_dispatch(&mut node)
        .await
        .expect("peer runtime send request should route and prepare dispatch")
        .expect("established direct peer should dispatch");

        assert_eq!(dispatch.dest_addr(), dest_addr);
        assert_eq!(dispatch.next_hop_addr(), dest_addr);
        assert_eq!(
            dispatch.fsp_reservation_input().path_mtu,
            1234,
            "send request should derive path MTU from the resolved peer transport"
        );
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "send request should reserve exactly one FSP counter"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "send request should reserve exactly one FMP counter"
        );

        let missing_dest = node_addr(0x99);
        let missing_send = PipelinedEndpointSend {
            dest_addr: &missing_dest,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            body: PipelinedEndpointWireBody::InnerPlaintext(&inner_plaintext),
            my_coords: None,
            dest_coords: None,
        };
        assert!(matches!(
            PipelinedEndpointPeerRuntimeSendRequest::new(
                *node.node_addr(),
                missing_send,
                node.config.node.session.default_ttl,
            )
            .resolve_dispatch(&mut node)
            .await,
            Err(PipelinedEndpointPeerRuntimeSendRequestError::Route(
                PipelinedEndpointPeerRuntimeRouteRequestError::NoRoute { dest_addr }
            )) if dest_addr == missing_dest
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_peer_runtime_send_request_owns_commit_bookkeeping() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x55);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

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
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
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
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();
        let session_traffic_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .traffic_counters();
        let link_stats_before = node
            .peers
            .get(&dest_addr)
            .expect("active peer exists")
            .link_stats()
            .clone();
        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + inner_plaintext.len();
        let expected_originated_bytes = link_plaintext_len + crate::noise::TAG_SIZE;
        let expected_fmp_wire_capacity =
            ESTABLISHED_HEADER_SIZE + 4 + link_plaintext_len + crate::noise::TAG_SIZE * 2;

        let workers = crate::node::encrypt_worker::EncryptWorkerPool::spawn(1);
        let sent = PipelinedEndpointPeerRuntimeSendRequest::new(
            *node.node_addr(),
            send,
            node.config.node.session.default_ttl,
        )
        .execute(&mut node, &workers)
        .await
        .expect("peer runtime send request should commit prepared dispatch");

        assert!(sent, "established direct peer should dispatch");
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "send request should reserve exactly one FSP counter"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "send request should reserve exactly one FMP counter"
        );
        let session = node.sessions.get(&dest_addr).expect("session still exists");
        assert_eq!(
            session.traffic_counters().0,
            session_traffic_before.0 + 1,
            "send request commit should record FSP data packet bookkeeping"
        );
        assert_eq!(
            session.traffic_counters().2,
            session_traffic_before.2 + payload.len() as u64,
            "send request commit should record endpoint payload bytes"
        );
        assert_eq!(
            session.last_outbound_next_hop(),
            Some(dest_addr),
            "send request commit should record outbound next hop"
        );
        let link_stats_after = node
            .peers
            .get(&dest_addr)
            .expect("active peer still exists")
            .link_stats();
        assert_eq!(
            link_stats_after.packets_sent,
            link_stats_before.packets_sent + 1
        );
        assert_eq!(
            link_stats_after.bytes_sent,
            link_stats_before.bytes_sent + expected_fmp_wire_capacity as u64,
            "send request commit should record FMP wire capacity against the peer link"
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 1
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + expected_originated_bytes as u64
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn peer_runtime_endpoint_send_facade_owns_route_dispatch_and_commit() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x56);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

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
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
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
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();
        let session_traffic_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .traffic_counters();
        let link_stats_before = node
            .peers
            .get(&dest_addr)
            .expect("active peer exists")
            .link_stats()
            .clone();
        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + inner_plaintext.len();
        let expected_originated_bytes = link_plaintext_len + crate::noise::TAG_SIZE;
        let expected_fmp_wire_capacity =
            ESTABLISHED_HEADER_SIZE + 4 + link_plaintext_len + crate::noise::TAG_SIZE * 2;

        let workers = crate::node::encrypt_worker::EncryptWorkerPool::spawn(1);
        let sent = node
            .execute_peer_runtime_endpoint_send(send, &workers)
            .await
            .expect("peer runtime endpoint facade should route, reserve, and commit");

        assert!(sent, "established direct peer should dispatch");
        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 1,
            "peer runtime facade should reserve exactly one FSP counter"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 1,
            "peer runtime facade should reserve exactly one FMP counter"
        );
        let session = node.sessions.get(&dest_addr).expect("session still exists");
        assert_eq!(
            session.traffic_counters().0,
            session_traffic_before.0 + 1,
            "peer runtime facade should record FSP data packet bookkeeping"
        );
        assert_eq!(
            session.traffic_counters().2,
            session_traffic_before.2 + payload.len() as u64,
            "peer runtime facade should record endpoint payload bytes"
        );
        assert_eq!(
            session.last_outbound_next_hop(),
            Some(dest_addr),
            "peer runtime facade should record outbound next hop"
        );
        let link_stats_after = node
            .peers
            .get(&dest_addr)
            .expect("active peer still exists")
            .link_stats();
        assert_eq!(
            link_stats_after.packets_sent,
            link_stats_before.packets_sent + 1
        );
        assert_eq!(
            link_stats_after.bytes_sent,
            link_stats_before.bytes_sent + expected_fmp_wire_capacity as u64,
            "peer runtime facade should record FMP wire capacity against the peer link"
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 1
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + expected_originated_bytes as u64
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn peer_runtime_endpoint_send_reuses_resolved_route_for_multiple_payloads() {
        use crate::PeerIdentity;
        use crate::peer::ActivePeer;
        use crate::transport::udp::UdpTransport;
        use crate::transport::{
            LinkId, TransportAddr, TransportHandle, TransportId, packet_channel,
        };
        use crate::utils::index::SessionIndex;

        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let dest_addr = *peer_identity.node_addr();
        let transport_id = TransportId::new(0x56);
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut config = crate::config::Config::new();
        config.node.session.default_ttl = 13;
        config.peers.push(crate::config::PeerConfig::new(
            peer.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        let mut node = Node::with_identity(local, config).expect("node");

        assert!(
            node.sessions
                .insert(dest_addr, established_entry(&node.identity, &peer))
                .is_none()
        );
        let active_peer = ActivePeer::with_session(
            peer_identity,
            LinkId::new(9),
            1_000,
            make_xk_session(&node.identity, &peer),
            SessionIndex::new(0x1010),
            SessionIndex::new(0x2020),
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            crate::transport::LinkStats::new(),
            true,
            &node.config.node.mmp,
            Some([0x02; 8]),
        );
        node.peers
            .insert_with_current_session_index(dest_addr, active_peer);

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
        assert!(
            node.transports
                .insert(transport_id, TransportHandle::Udp(udp))
                .is_none()
        );

        let route = node
            .resolve_peer_runtime_endpoint_route(dest_addr, Node::now_ms())
            .expect("established direct peer should resolve once for a batch");
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let fsp_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .send_counter();
        let fmp_before = node
            .peers
            .get(&dest_addr)
            .and_then(|peer| peer.noise_session())
            .expect("active peer session exists")
            .current_send_counter();
        let session_traffic_before = node
            .sessions
            .get(&dest_addr)
            .expect("session exists")
            .traffic_counters();
        let link_stats_before = node
            .peers
            .get(&dest_addr)
            .expect("active peer exists")
            .link_stats()
            .clone();
        let originated_before = node.stats().forwarding.originated_packets;
        let originated_bytes_before = node.stats().forwarding.originated_bytes;
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + inner_plaintext.len();
        let expected_originated_bytes = link_plaintext_len + crate::noise::TAG_SIZE;
        let expected_fmp_wire_capacity =
            ESTABLISHED_HEADER_SIZE + 4 + link_plaintext_len + crate::noise::TAG_SIZE * 2;

        let workers = crate::node::encrypt_worker::EncryptWorkerPool::spawn(1);
        let mut prepared_batch = Vec::new();
        for offset in 0..2 {
            let send = PipelinedEndpointSend {
                dest_addr: &dest_addr,
                payload: &payload,
                now_ms: 0x1122_3344 + offset,
                timestamp: 0x5566_7788 + offset as u32,
                fsp_flags: 0,
                body: PipelinedEndpointWireBody::InnerPlaintext(&inner_plaintext),
                my_coords: None,
                dest_coords: None,
            };
            let prepared = node
                .prepare_peer_runtime_endpoint_send_with_route(send, &route)
                .await
                .expect("reused endpoint route should prepare")
                .expect("reused route should prepare worker packet");
            assert!(
                prepared.worker_job.queued_at.is_none(),
                "batch commit owns the worker queue timestamp for packet {offset}"
            );
            prepared_batch.push(prepared);
        }
        PipelinedEndpointPreparedSend::commit_many(prepared_batch, &mut node, &workers);

        assert_eq!(
            node.sessions
                .get(&dest_addr)
                .expect("session still exists")
                .send_counter(),
            fsp_before + 2,
            "reused route should still reserve one FSP counter per payload"
        );
        assert_eq!(
            node.peers
                .get(&dest_addr)
                .and_then(|peer| peer.noise_session())
                .expect("active peer session still exists")
                .current_send_counter(),
            fmp_before + 2,
            "reused route should still reserve one FMP counter per payload"
        );
        let session = node.sessions.get(&dest_addr).expect("session still exists");
        assert_eq!(session.traffic_counters().0, session_traffic_before.0 + 2);
        assert_eq!(
            session.traffic_counters().2,
            session_traffic_before.2 + (payload.len() as u64 * 2)
        );
        assert_eq!(session.last_outbound_next_hop(), Some(dest_addr));
        let link_stats_after = node
            .peers
            .get(&dest_addr)
            .expect("active peer still exists")
            .link_stats();
        assert_eq!(
            link_stats_after.packets_sent,
            link_stats_before.packets_sent + 2
        );
        assert_eq!(
            link_stats_after.bytes_sent,
            link_stats_before.bytes_sent + expected_fmp_wire_capacity as u64 * 2
        );
        assert_eq!(
            node.stats().forwarding.originated_packets,
            originated_before + 2
        );
        assert_eq!(
            node.stats().forwarding.originated_bytes,
            originated_bytes_before + expected_originated_bytes as u64 * 2
        );
    }
