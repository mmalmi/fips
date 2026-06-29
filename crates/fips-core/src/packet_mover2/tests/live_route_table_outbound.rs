    #[test]
    fn live_route_table_outbound_source_defers_fresh_bulk_after_liveness_progress() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(owner, 7, 0x03, 0x09),
        );

        let priority_payload = priority_endpoint_payload();
        let fresh_bulk_payload = bulk_endpoint_payload();
        let fresh_bulk = EndpointSendBatchCommand::new(
            remote,
            vec![EndpointDataPayload::new(fresh_bulk_payload.clone())],
            None,
        )
        .expect("fresh bulk command");

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        priority_tx
            .try_send(NodeEndpointCommand::send_oneway(
                remote,
                priority_payload.clone(),
                None,
            ))
            .expect("enqueue priority endpoint command");
        bulk_tx
            .try_send(NodeEndpointCommand::SendBatchOneway {
                command: fresh_bulk,
                lane: EndpointCommandLane::Bulk,
            })
            .expect("enqueue fresh bulk command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        );
        source.endpoint_stale_bulk_drop_ms = 50;
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 1);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].class, PacketClass::Control);
        assert_eq!(outbound[0].payload.as_ref(), priority_payload);
        assert!(
            source.take_endpoint_command_drops().is_empty(),
            "fresh bulk should be deferred for the liveness turn, not dropped"
        );

        let mut next_outbound = Vec::new();
        assert_eq!(
            source.drain_outbound(8, |packet| next_outbound.push(packet)),
            1
        );
        assert_eq!(next_outbound.len(), 1);
        assert_eq!(next_outbound[0].class, PacketClass::Bulk);
        assert_eq!(next_outbound[0].payload.as_ref(), fresh_bulk_payload);
        assert!(source.take_endpoint_deferred_commands().is_empty());
    }
