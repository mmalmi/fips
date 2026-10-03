//! A routed FSP can recover before the obsolete direct FMP notices a restart.
use super::*;

#[test]
fn restart_msg1_preserves_fsp_recovered_over_transit() {
    run_large_stack_async_test("restart-msg1-recovered-fsp", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (0, 2), (1, 2)], false).await;
        let transit = (0..3).min_by_key(|i| *nodes[*i].node.node_addr()).unwrap();
        let mut endpoints = (0..3).filter(|i| *i != transit);
        let survivor = endpoints.next().unwrap();
        let restarted = endpoints.next().unwrap();
        for node in &mut nodes {
            node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
            node.node.config.node.rekey.enabled = false;
            node.node.config.node.session.idle_timeout_secs = 0;
        }
        let survivor_addr = *nodes[survivor].node.node_addr();
        let restarted_addr = *nodes[restarted].node.node_addr();
        let transit_addr = *nodes[transit].node.node_addr();
        let remote_key = nodes[restarted].node.identity().pubkey_full();
        nodes[survivor]
            .node
            .initiate_session(restarted_addr, remote_key)
            .await
            .unwrap();
        wait_for_session_established(
            &mut nodes,
            restarted,
            &survivor_addr,
            Duration::from_secs(5),
            "initial direct FSP",
        )
        .await;
        drain_to_quiescence(&mut nodes).await;
        let old_hash = nodes[survivor]
            .node
            .get_session(&restarted_addr)
            .unwrap()
            .handshake_hash()
            .copied()
            .unwrap();
        let old_epoch = nodes[restarted].node.startup_epoch;

        // Restart every protocol owner while retaining only the fixture's UDP
        // socket. The survivor keeps its dead direct peering; transit reconnects
        // first, exactly the order of a browser reload followed by WebRTC.
        let mut config = nodes[restarted].node.config.clone();
        config.node.identity.replace_nsec(Some(crate::encode_nsec(
            &nodes[restarted].node.identity().keypair().secret_key(),
        )));
        let mut fresh = Node::new(config).unwrap();
        fresh.transports = std::mem::take(&mut nodes[restarted].node.transports);
        fresh.tun_outbound_rx = nodes[restarted].node.tun_outbound_rx.take();
        nodes[restarted].node = fresh;
        nodes[transit].node.remove_active_peer(&restarted_addr);
        nodes[survivor].node.remove_link_dead_peer(&restarted_addr);
        connect(&mut nodes, restarted, transit).await;
        populate_all_coord_caches(&mut nodes);
        nodes[survivor]
            .node
            .learn_reverse_route(restarted_addr, transit_addr);
        nodes[restarted]
            .node
            .learn_reverse_route(survivor_addr, transit_addr);

        nodes[survivor].node.config.node.rekey.enabled = true;
        assert!(
            nodes[survivor]
                .node
                .initiate_session_rekey(&restarted_addr)
                .await
        );
        nodes[survivor].node.config.node.rekey.enabled = false;
        wait_for_session_established(
            &mut nodes,
            restarted,
            &survivor_addr,
            Duration::from_secs(5),
            "FSP recovery through transit",
        )
        .await;
        drain_to_quiescence(&mut nodes).await;
        let recovered_hash = nodes[survivor]
            .node
            .get_session(&restarted_addr)
            .unwrap()
            .handshake_hash()
            .copied()
            .unwrap();
        assert_ne!(recovered_hash, old_hash);
        assert_eq!(
            nodes[survivor]
                .node
                .get_peer(&restarted_addr)
                .unwrap()
                .remote_epoch(),
            Some(old_epoch)
        );
        assert_eq!(
            nodes[survivor]
                .node
                .dataplane
                .fsp_owner_next_hop(&restarted_addr),
            Some(transit_addr)
        );
        deliver_both_ways(&mut nodes, survivor, restarted).await;

        // Model the old carrier's elapsed dead time without sleeping. Fresh
        // traffic over transit must not refresh the obsolete adjacency's age.
        nodes[survivor]
            .node
            .peers
            .get_mut(&restarted_addr)
            .unwrap()
            .touch(Node::now_ms().saturating_sub(60_000));
        connect(&mut nodes, restarted, survivor).await;
        for (source, destination) in [(survivor, restarted), (restarted, survivor)] {
            let peer = nodes[destination].node.node_addr();
            let session = nodes[source]
                .node
                .get_session(peer)
                .expect("late FMP Msg1 must retain the FSP already recovered to this epoch");
            assert_eq!(session.handshake_hash(), Some(&recovered_hash));
            assert!(
                session
                    .established_remote_epoch_matches(Some(nodes[destination].node.startup_epoch))
            );
            assert!(nodes[source].node.dataplane_has_fsp_owner(peer));
        }
        deliver_both_ways(&mut nodes, survivor, restarted).await;
        cleanup_nodes(&mut nodes).await;
    });
}

async fn connect(nodes: &mut [TestNode], source: usize, destination: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[destination].node.identity().pubkey_full());
    let address = nodes[destination].addr.clone();
    let source_addr = *nodes[source].node.node_addr();
    let source_epoch = nodes[source].node.startup_epoch;
    let node = &mut nodes[source];
    node.node
        .initiate_connection(node.transport_id, address, identity)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            poll_available_packets(nodes).await;
            if nodes[source]
                .node
                .get_peer(identity.node_addr())
                .is_some_and(|peer| peer.can_send())
                && nodes[destination]
                    .node
                    .get_peer(&source_addr)
                    .is_some_and(|peer| {
                        peer.can_send() && peer.remote_epoch() == Some(source_epoch)
                    })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("real UDP Noise handshake must finish within its original deadline");
    drain_to_quiescence(nodes).await;
}

async fn deliver_both_ways(nodes: &mut [TestNode], first: usize, second: usize) {
    for (source, destination) in [(first, second), (second, first)] {
        let mut receiver = nodes[destination].node.attach_endpoint_data_io(8).unwrap();
        let identity =
            PeerIdentity::from_pubkey_full(nodes[destination].node.identity().pubkey_full());
        let payload = b"endpoint-data-across-delayed-direct-restart";
        send_endpoint_data_via_dataplane(&mut nodes[source].node, identity, payload.to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut receiver.event_rx,
            Duration::from_secs(3),
            "recovered FSP endpoint data",
        )
        .await;
        receiver.event_rx.release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            payload
        );
        drain_to_quiescence(nodes).await;
    }
}
