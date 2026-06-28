    #[test]
    fn live_route_table_outbound_source_reserves_tun_liveness_after_large_stale_bulk_drop() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let endpoint_owner = OwnerId::fsp_node(*remote.node_addr());
        let tun_dest = NodeAddr::from_bytes([0x70; 16]);
        let tun_owner = OwnerId::fmp_node(tun_dest);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(endpoint_owner, 7, 0x03, 0x09),
        );
        routes.register_tun_destination(
            tun_dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                tun_owner,
                5,
                PacketClass::Liveness,
                610,
                0x02,
            )),
        );

        let stale_bulk_payload = bulk_endpoint_payload();
        let old_ms = crate::time::now_ms().saturating_sub(1_000);
        let stale_payloads = (0..64)
            .map(|_| EndpointDataPayload::new(stale_bulk_payload.clone()))
            .collect::<Vec<_>>();
        let stale_bulk =
            EndpointSendBatchCommand::new_with_enqueued_at_ms(remote, stale_payloads, None, old_ms)
                .expect("stale bulk command");

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        drop(priority_tx);
        bulk_tx
            .try_send(NodeEndpointCommand::SendBatchOneway {
                command: stale_bulk,
                lane: EndpointCommandLane::Bulk,
            })
            .expect("enqueue stale bulk command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_icmpv6_packet(tun_dest, 48);
        tun_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN liveness packet");

        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            1,
            &mut routes,
        )
        .with_endpoint_stale_bulk_drop_ms(50);
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 8);

        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].owner, tun_owner);
        assert_eq!(outbound[0].class, PacketClass::Liveness);
        assert_eq!(outbound[0].payload.as_ref(), tun_packet);
        let drops = source.take_endpoint_command_drops();
        assert_eq!(drops.len(), 64);
        assert!(drops.iter().all(|drop| {
            drop.dest_addr() == *remote.node_addr()
                && drop.lane() == EndpointCommandLane::Bulk
                && drop.payload_len() == stale_bulk_payload.len()
                && drop.reason() == PacketMover2EndpointCommandDropReason::StaleQueuedBulk
        }));
        drop(source);
        assert!(bulk_rx.try_recv().is_err());
        assert!(tun_rx.try_recv().is_err());
    }
