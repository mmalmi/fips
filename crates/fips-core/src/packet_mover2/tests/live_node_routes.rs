    #[test]
    fn live_node_replaces_and_unregisters_owner_routes() {
        let owner_addr = NodeAddr::from_bytes([0x91; 16]);
        let owner = OwnerId::fmp_node(owner_addr);
        let other_owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x92; 16]));
        let transport_a = TransportId::new(91);
        let transport_b = TransportId::new(92);
        let remote_addr = TransportAddr::from_string("198.51.100.91:9000");
        let mut live_node =
            PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));

        assert_eq!(
            live_node.replace_owner_routes(owner, PacketMover2LiveOwnerRoutes::new()),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );
        assert_eq!(
            live_node.set_owner_active_path(owner, live_path(91)),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );
        assert_eq!(
            live_node.set_owner_crypto_keys(
                owner,
                OwnerCryptoKeys::new(test_key(91), test_key(91)),
            ),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );
        assert_eq!(
            live_node.owner_active_path(owner),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );

        live_node.register_owner(owner, OwnerConfig::new(1, 8));
        let mut routes = PacketMover2LiveOwnerRoutes::new();
        routes.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_a,
            910,
            PacketMover2IngressRoute::new(owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness),
        ));
        routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            owner_addr,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                owner,
                1,
                PacketClass::Bulk,
                911,
                0,
            )),
        ));

        let summary = live_node
            .replace_owner_routes(owner, routes)
            .expect("owner routes should replace");
        assert!(!summary.owner_removed());
        assert_eq!(summary.routes_removed(), 0);
        assert_eq!(summary.routes_added(), 2);

        let old_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_a,
                remote_addr.clone(),
                fmp_wire(910, 1, 0),
                91_000,
            ),
        );
        let old_header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&old_raw.payload).unwrap());
        assert_eq!(
            live_node.routes.route(&old_raw, old_header).unwrap(),
            PacketMover2IngressRoute::new(owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness)
        );

        let mut mismatched = PacketMover2LiveOwnerRoutes::new();
        mismatched.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_b,
            920,
            PacketMover2IngressRoute::new(other_owner, 1, OutputTarget::Endpoint),
        ));
        assert_eq!(
            live_node.replace_owner_routes(owner, mismatched),
            Err(PacketMover2LiveOwnerError::OwnerMismatch)
        );

        let mut replacement = PacketMover2LiveOwnerRoutes::new();
        replacement.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_b,
            920,
            PacketMover2IngressRoute::new(owner, 2, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp),
        ));
        let summary = live_node
            .replace_owner_routes(owner, replacement)
            .expect("replacement routes should apply");
        assert_eq!(summary.routes_removed(), 2);
        assert_eq!(summary.routes_added(), 1);

        let old_header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&old_raw.payload).unwrap());
        assert_eq!(live_node.routes.route(&old_raw, old_header), None);

        let new_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_b,
                remote_addr,
                fmp_wire(920, 1, 0),
                92_000,
            ),
        );
        let new_header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&new_raw.payload).unwrap());
        assert_eq!(
            live_node.routes.route(&new_raw, new_header).unwrap(),
            PacketMover2IngressRoute::new(owner, 2, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp)
        );

        let summary = live_node.unregister_owner(owner);
        assert!(summary.owner_removed());
        assert_eq!(summary.routes_removed(), 1);
        assert_eq!(summary.routes_added(), 0);
    }

    #[test]
    fn live_node_register_owner_if_missing_preserves_existing_owner_state() {
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x93; 16]));
        let active_path = live_path(93);
        let mut live_node =
            PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));

        assert!(live_node.register_owner_if_missing(
            owner,
            OwnerConfig::new(1, 8).with_next_send_counter(93_000),
        ));
        assert_eq!(live_node.set_owner_active_path(owner, active_path.clone()), Ok(()));

        assert!(!live_node.register_owner_if_missing(
            owner,
            OwnerConfig::new(99, 1).with_next_send_counter(1),
        ));

        assert_eq!(live_node.owner_active_path(owner), Ok(Some(active_path)));
    }
