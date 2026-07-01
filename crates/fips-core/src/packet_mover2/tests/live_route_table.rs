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
