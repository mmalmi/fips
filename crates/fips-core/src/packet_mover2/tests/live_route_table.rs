    fn test_peer() -> PeerIdentity {
        PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full())
    }

    fn route_endpoint_payload(
        routes: &mut PacketMover2LiveRouteTable,
        remote: PeerIdentity,
        payload: &[u8],
    ) -> Result<OutboundPacket, PacketMover2EndpointDataDropReason> {
        let route = routes.route_endpoint_data_batch(remote, vec![payload.to_vec()]);
        let mut routed = Vec::new();
        let mut drops = Vec::new();
        let deferred = route.finish_batch(&mut drops, |packets| routed.extend(packets));
        if deferred.is_some() {
            return Err(PacketMover2EndpointDataDropReason::NoRoute);
        }
        if let Some(drop) = drops.first() {
            return Err(drop.reason());
        }
        Ok(routed
            .pop()
            .expect("one-payload endpoint route should produce one outbound packet"))
    }

    #[test]
    fn live_route_table_unregister_owner_prunes_output_routes() {
        let stale_peer = test_peer();
        let keep_peer = test_peer();
        let stale = *stale_peer.node_addr();
        let keep = *keep_peer.node_addr();
        let stale_fmp_owner = OwnerId::fmp_node(stale);
        let stale_fsp_owner = OwnerId::fsp_node(stale);
        let keep_fmp_owner = OwnerId::fmp_node(keep);
        let keep_fsp_owner = OwnerId::fsp_node(keep);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fmp(
            TransportId::new(63),
            630,
            PacketMover2IngressRoute::new(stale_fmp_owner, 1, OutputTarget::Tun),
        );
        routes.register_tun_destination(
            stale,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                stale_fmp_owner,
                1,
                PacketClass::Bulk,
                630,
                0,
            )),
        );
        routes.register_fsp(
            stale,
            PacketMover2IngressRoute::new(stale_fsp_owner, 2, OutputTarget::Endpoint),
        );
        routes.register_endpoint_destination(
            stale,
            PacketMover2EndpointDataRoute::fsp(stale_fsp_owner, 2, 0, 0),
        );
        routes.register_tun_destination(
            keep,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                keep_fmp_owner,
                3,
                PacketClass::Bulk,
                640,
                0,
            )),
        );
        routes.register_endpoint_destination(
            keep,
            PacketMover2EndpointDataRoute::fsp(keep_fsp_owner, 4, 0, 0),
        );

        assert_eq!(routes.unregister_owner(stale_fmp_owner), 2);
        assert_eq!(routes.unregister_owner(stale_fsp_owner), 2);
        assert_eq!(routes.unregister_owner(stale_fmp_owner), 0);

        assert_eq!(
            routes.route_tun_outbound(&tun_ipv6_packet(stale, 48)),
            Err(PacketMover2TunOutboundDropReason::NoRoute)
        );
        assert_eq!(
            route_endpoint_payload(&mut routes, stale_peer, b"stale"),
            Err(PacketMover2EndpointDataDropReason::NoRoute)
        );
        assert_eq!(
            routes
                .route_tun_outbound(&tun_ipv6_packet(keep, 48))
                .expect("keep TUN route")
                .owner(),
            keep_fmp_owner
        );
        assert_eq!(
            route_endpoint_payload(&mut routes, keep_peer, b"keep")
                .expect("keep endpoint route")
                .owner,
            keep_fsp_owner
        );
    }

    #[test]
    fn live_route_table_refresh_owner_generation_preserves_routes_across_rekey() {
        let fmp_source = NodeAddr::from_bytes([0x66; 16]);
        let fsp_peer = test_peer();
        let keep_peer = test_peer();
        let fsp_source = *fsp_peer.node_addr();
        let keep = *keep_peer.node_addr();
        let fmp_owner = OwnerId::fmp_node(fmp_source);
        let fsp_owner = OwnerId::fsp_node(fsp_source);
        let keep_fmp_owner = OwnerId::fmp_node(keep);
        let keep_fsp_owner = OwnerId::fsp_node(keep);
        let transport_id = TransportId::new(66);
        let keep_transport_id = TransportId::new(68);
        let remote_addr = TransportAddr::from_string("198.51.100.66:9000");
        let mut routes = PacketMover2LiveRouteTable::default();

        routes.register_fmp(
            transport_id,
            660,
            PacketMover2IngressRoute::new(fmp_owner, 1, OutputTarget::Endpoint)
                .with_class(PacketClass::Liveness),
        );
        routes.register_tun_destination(
            fmp_source,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                fmp_owner,
                1,
                PacketClass::Bulk,
                661,
                0,
            )),
        );
        routes.register_fsp(
            fsp_source,
            PacketMover2IngressRoute::new(fsp_owner, 2, OutputTarget::Tun)
                .with_class(PacketClass::Mmp),
        );
        routes.register_endpoint_destination(
            fsp_source,
            PacketMover2EndpointDataRoute::fsp(fsp_owner, 2, 0, 0),
        );
        routes.register_fmp(
            keep_transport_id,
            680,
            PacketMover2IngressRoute::new(keep_fmp_owner, 5, OutputTarget::Endpoint),
        );
        routes.register_endpoint_destination(
            keep,
            PacketMover2EndpointDataRoute::fsp(keep_fsp_owner, 6, 0, 0),
        );

        assert_eq!(routes.refresh_owner_generation(fmp_owner, 10), 2);
        assert_eq!(routes.refresh_owner_generation(fsp_owner, 11), 2);
        assert_eq!(
            routes.refresh_owner_generation(
                OwnerId::fmp_node(NodeAddr::from_bytes([0x69; 16])),
                12,
            ),
            0
        );

        let fmp_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fmp_wire(660, 1, 0),
                66_000,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&fmp_raw.payload).unwrap());
        let route = routes
            .route(&fmp_raw, header)
            .expect("FMP route survives refresh");
        assert_eq!(route.owner, fmp_owner);
        assert_eq!(route.generation, 10);
        assert_eq!(route.class, PacketClass::Liveness);

        let fsp_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fsp_wire(2, 0),
                67_000,
            ),
        )
        .with_fsp_source(fsp_source);
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&fsp_raw.payload).unwrap());
        let route = routes
            .route(&fsp_raw, header)
            .expect("FSP route survives refresh");
        assert_eq!(route.owner, fsp_owner);
        assert_eq!(route.generation, 11);
        assert_eq!(route.class, PacketClass::Mmp);

        let tun_route = routes
            .route_tun_outbound(&tun_ipv6_packet(fmp_source, 48))
            .expect("TUN route survives refresh");
        assert_eq!(tun_route.owner(), fmp_owner);
        assert_eq!(tun_route.generation, 10);

        let endpoint_packet = route_endpoint_payload(&mut routes, fsp_peer, b"after-rekey")
            .expect("endpoint route survives refresh");
        assert_eq!(endpoint_packet.owner, fsp_owner);
        assert_eq!(endpoint_packet.generation, 11);

        let keep_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                keep_transport_id,
                remote_addr,
                fmp_wire(680, 1, 0),
                68_000,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&keep_raw.payload).unwrap());
        assert_eq!(routes.route(&keep_raw, header).unwrap().generation, 5);
        assert_eq!(
            route_endpoint_payload(&mut routes, keep_peer, b"keep")
                .unwrap()
                .generation,
            6
        );
    }
