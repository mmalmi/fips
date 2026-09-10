use super::*;

#[test]
fn routine_rekey_rediscovers_coordinates_while_cached_routed_payload_still_flows() {
    run_large_stack_async_test("fips-rekey-coordinate-recovery", || async {
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);
        let local = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
        let remote = PeerIdentity::from_pubkey_full(nodes[2].node.identity().pubkey_full());
        let mut endpoint = nodes[2].node.attach_endpoint_data_io(8).unwrap();
        establish_routed_session(&mut nodes, local, remote, &mut endpoint.event_rx).await;

        // Parent ancestry changes clear this cache without discarding a working
        // dataplane route. Payload can therefore hide missing rekey coordinates.
        nodes[0].node.coord_cache.clear();
        assert_eq!(nodes[0].node.config.node.routing.mode, RoutingMode::Tree);
        assert!(nodes[0].node.find_next_hop(remote.node_addr()).is_none());
        assert_eq!(
            nodes[0]
                .node
                .dataplane
                .fsp_owner_next_hop(remote.node_addr()),
            Some(*nodes[1].node.node_addr())
        );
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        nodes[2].node.tun_tx = Some(tun_tx);
        let packet = build_ipv6_packet(
            &crate::FipsAddress::from_node_addr(local.node_addr()),
            &crate::FipsAddress::from_node_addr(remote.node_addr()),
            b"cached route after coordinate eviction",
        );
        send_tun_packet_via_dataplane(&mut nodes, 0, packet.clone()).await;
        let delivered = recv_tun_packet_while_draining(
            &mut nodes,
            &tun_rx,
            Duration::from_secs(5),
            "cached routed payload after coordinate eviction",
        )
        .await;
        assert_eq!(delivered, packet);
        assert!(nodes[0].node.find_next_hop(remote.node_addr()).is_none());
        assert!(
            nodes[0]
                .node
                .dataplane
                .fsp_owner_activity(remote.node_addr())
                .unwrap()
                .send_counter()
                > 0
        );

        nodes[0].node.config.node.rekey.after_secs = u64::MAX;
        nodes[0].node.config.node.rekey.after_messages = 1;
        let requests_before = nodes[0].node.stats().discovery.req_initiated;
        for _ in 0..10 {
            nodes[0].node.check_session_rekey().await;
        }
        let pending = nodes[0]
            .node
            .pending_lookups
            .contains_key(remote.node_addr());
        let requests = nodes[0].node.stats().discovery.req_initiated - requests_before;
        let unchanged_epoch = nodes[0]
            .node
            .get_session(remote.node_addr())
            .is_some_and(|entry| !entry.current_k_bit() && !entry.has_rekey_in_progress());
        if !pending || requests != 1 || !unchanged_epoch {
            cleanup_nodes(&mut nodes).await;
            assert!(
                pending,
                "a due rekey must rediscover coordinates missing from a live payload route"
            );
            assert_eq!(
                requests, 1,
                "repeated due checks must share one bounded lookup"
            );
            assert!(
                unchanged_epoch,
                "coordinate discovery must preserve the established epoch"
            );
            return;
        }

        let completed = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                process_available_packets(&mut nodes).await;
                run_session_retransmit_work(&mut nodes).await;
                for node in &mut nodes {
                    node.node.check_session_mmp_reports().await;
                    node.node.check_session_rekey().await;
                }
                if nodes[0]
                    .node
                    .get_session(remote.node_addr())
                    .unwrap()
                    .current_k_bit()
                    && nodes[2]
                        .node
                        .get_session(local.node_addr())
                        .unwrap()
                        .current_k_bit()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let verified_coords = nodes[0]
            .node
            .coord_cache
            .get_entry(remote.node_addr())
            .is_some_and(|entry| entry.is_verified(Node::now_ms()));
        let lookup_finished = !nodes[0]
            .node
            .pending_lookups
            .contains_key(remote.node_addr());
        let final_state = session_wait_snapshot(&nodes, 0, remote.node_addr());
        if completed.is_ok() {
            send_tun_packet_via_dataplane(&mut nodes, 0, packet.clone()).await;
            let delivered = recv_tun_packet_while_draining(
                &mut nodes,
                &tun_rx,
                Duration::from_secs(5),
                "routed payload after recovered rekey",
            )
            .await;
            assert_eq!(delivered, packet);
        }
        cleanup_nodes(&mut nodes).await;
        assert!(
            completed.is_ok(),
            "verified coordinate discovery must unblock an actual FSP cutover at both endpoints: {final_state}"
        );
        assert!(
            verified_coords,
            "rekey recovery must use proof-verified coordinates"
        );
        assert!(
            lookup_finished,
            "completed discovery must release its pending entry"
        );
    });
}

async fn establish_routed_session(
    nodes: &mut [TestNode],
    local: PeerIdentity,
    remote: PeerIdentity,
    remote_rx: &mut EndpointEventReceiver,
) {
    let mut local_endpoint = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    nodes[0]
        .node
        .initiate_session(*remote.node_addr(), remote.pubkey_full())
        .await
        .unwrap();
    for (index, peer) in [(0, remote.node_addr()), (2, local.node_addr())] {
        wait_for_session_established(
            nodes,
            index,
            peer,
            Duration::from_secs(5),
            "routed rekey fixture",
        )
        .await;
    }
    settle_session_handshake_retransmits(nodes, 0, remote.node_addr(), 2, local.node_addr());
    let warmup_packets = nodes[0]
        .node
        .config
        .node
        .session
        .coords_warmup_packets
        .max(nodes[2].node.config.node.session.coords_warmup_packets);
    for _ in 0..warmup_packets {
        for (source, destination, receiver) in [
            (0, remote, &mut *remote_rx),
            (2, local, &mut local_endpoint.event_rx),
        ] {
            send_endpoint_data_via_dataplane(&mut nodes[source].node, destination, vec![7])
                .await
                .unwrap();
            let event = recv_endpoint_event_while_draining(
                nodes,
                receiver,
                Duration::from_secs(5),
                "ordinary session coordinate warmup",
            )
            .await;
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                &[7]
            );
        }
    }
    drain_to_quiescence(nodes).await;
}
