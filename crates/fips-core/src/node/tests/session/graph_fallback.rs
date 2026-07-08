use super::*;
use crate::peer::ActivePeerSession;

#[tokio::test]
async fn test_link_dead_fallback_warms_session_over_existing_graph() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let dest_addr = *nodes[2].node.node_addr();
    let dest_pubkey = nodes[2].node.identity().pubkey_full();
    let dest_npub = nodes[2].node.npub();
    nodes[0].node.register_identity(dest_addr, dest_pubkey);
    nodes[0].node.config.peers.push(crate::config::PeerConfig {
        npub: dest_npub,
        alias: Some("link-dead-fallback".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });

    assert!(
        nodes[0].node.find_next_hop(&dest_addr).is_some(),
        "fixture should have an existing graph route through the transit peer"
    );

    let baseline = nodes[0].node.stats().discovery.req_initiated;
    nodes[0]
        .node
        .schedule_link_dead_reprobe(dest_addr, crate::time::now_ms());
    nodes[0]
        .node
        .maybe_initiate_direct_path_fallback_lookup(&dest_addr)
        .await;

    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_initiating()),
        "link-dead should immediately warm a fresh FSP session over fallback"
    );
    assert!(
        !nodes[0].node.pending_lookups.contains_key(&dest_addr),
        "known fallback route should avoid waiting for a discovery round trip"
    );
    assert_eq!(
        nodes[0].node.stats().discovery.req_initiated,
        baseline,
        "warming over a known graph route should not initiate discovery"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_link_dead_preserves_session_and_sends_over_existing_graph() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let src_addr = *nodes[0].node.node_addr();
    let dest_addr = *nodes[2].node.node_addr();
    let dest_pubkey = nodes[2].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(dest_addr, dest_pubkey)
        .await
        .expect("session should initiate over graph route");
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_established()),
        "fixture should start with an established end-to-end session"
    );

    let direct_identity =
        crate::PeerIdentity::from_pubkey_full(nodes[2].node.identity().pubkey_full());
    let direct_session = make_noise_session(nodes[0].node.identity(), nodes[2].node.identity());
    let direct_peer = crate::peer::ActivePeer::with_session(
        direct_identity,
        LinkId::new(77),
        crate::time::now_ms(),
        ActivePeerSession {
            session: direct_session,
            our_index: crate::utils::index::SessionIndex::new(21),
            their_index: crate::utils::index::SessionIndex::new(22),
            transport_id: nodes[0].transport_id,
            current_addr: nodes[2].addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    nodes[0].node.peers.insert(dest_addr, direct_peer);

    nodes[0].node.remove_link_dead_peer(&dest_addr);

    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_established()),
        "link-dead direct path must not discard the end-to-end session"
    );
    assert!(
        nodes[0]
            .node
            .get_peer(&dest_addr)
            .expect("direct peer should remain tracked")
            .can_send(),
        "link-dead direct peer should remain probeable"
    );
    assert!(
        !nodes[0]
            .node
            .get_peer(&dest_addr)
            .expect("direct peer should remain tracked")
            .is_healthy(),
        "link-dead direct peer should not be treated as a healthy payload path"
    );
    let payload_next_hop = nodes[0]
        .node
        .find_next_hop(&dest_addr)
        .expect("graph fallback route");
    assert_ne!(
        payload_next_hop.node_addr(),
        &dest_addr,
        "link-dead direct peer should not hide graph fallback"
    );

    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[2].node.tun_tx = Some(tun_tx);

    let src_fips = crate::FipsAddress::from_node_addr(&src_addr);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dest_fips, b"link-dead-fallback-data");

    send_tun_packet_via_dataplane(&mut nodes, 0, ipv6_packet.clone()).await;
    drain_to_quiescence(&mut nodes).await;

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| {
        tun_rx
            .try_recv_packet()
            .ok()
            .map(|packet| packet.as_slice().to_vec())
    })
    .collect();
    assert_eq!(
        delivered,
        vec![ipv6_packet],
        "fallback graph route should carry traffic while direct is reconnecting"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_direct_established_endpoint_data_falls_back_after_link_dead() {
    run_large_stack_async_test("fips-graph-fallback-endpoint-data", || async {
        direct_established_endpoint_data_falls_back_after_link_dead().await;
    });
}

async fn direct_established_endpoint_data_falls_back_after_link_dead() {
    // A, B, C are all linked. A<->B should establish directly first. When
    // that direct path goes stale, endpoint data must keep using the
    // existing end-to-end session over C instead of sticking to the stale
    // direct link.
    let edges = vec![(0, 1), (0, 2), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    for node in &mut nodes {
        node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
    }

    let mut alice_endpoint = nodes[0]
        .node
        .attach_endpoint_data_io(8)
        .expect("alice endpoint data I/O should attach");
    let mut bob_endpoint = nodes[1]
        .node
        .attach_endpoint_data_io(8)
        .expect("bob endpoint data I/O should attach");

    let alice_addr = *nodes[0].node.node_addr();
    let bob_addr = *nodes[1].node.node_addr();
    let alice_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let bob_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());

    send_endpoint_data_via_dataplane(&mut nodes[0].node, bob_identity, b"direct-first".to_vec())
        .await
        .expect("initial endpoint data should send");
    drain_to_quiescence(&mut nodes).await;

    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut bob_endpoint.event_rx,
        Duration::from_secs(10),
        "initial direct endpoint data",
    )
    .await;
    let message = expect_single_endpoint_data_event(event);
    assert_eq!(*message.source_peer.node_addr(), alice_addr);
    assert_eq!(message.payload.as_slice(), &b"direct-first"[..]);

    assert!(
        nodes[0]
            .node
            .get_session(&bob_addr)
            .is_some_and(|entry| entry.is_established()),
        "alice should keep an established end-to-end session to bob"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&alice_addr)
            .is_some_and(|entry| entry.is_established()),
        "bob should keep an established end-to-end session to alice"
    );

    nodes[0].node.remove_link_dead_peer(&bob_addr);
    nodes[1].node.remove_link_dead_peer(&alice_addr);

    let charlie_addr = *nodes[2].node.node_addr();
    nodes[0].node.learn_reverse_route(bob_addr, charlie_addr);
    nodes[1].node.learn_reverse_route(alice_addr, charlie_addr);

    let alice_next_hop = *nodes[0]
        .node
        .find_next_hop(&bob_addr)
        .expect("alice should have fallback next hop")
        .node_addr();
    let bob_next_hop = *nodes[1]
        .node
        .find_next_hop(&alice_addr)
        .expect("bob should have fallback next hop")
        .node_addr();
    assert_ne!(alice_next_hop, bob_addr);
    assert_ne!(bob_next_hop, alice_addr);

    send_endpoint_data_via_dataplane(&mut nodes[0].node, bob_identity, b"alice-fallback".to_vec())
        .await
        .expect("alice fallback endpoint data should send");
    send_endpoint_data_via_dataplane(&mut nodes[1].node, alice_identity, b"bob-fallback".to_vec())
        .await
        .expect("bob fallback endpoint data should send");
    drain_to_quiescence(&mut nodes).await;

    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut bob_endpoint.event_rx,
        Duration::from_secs(10),
        "alice fallback endpoint data",
    )
    .await;
    let message = expect_single_endpoint_data_event(event);
    assert_eq!(*message.source_peer.node_addr(), alice_addr);
    assert_eq!(message.payload.as_slice(), &b"alice-fallback"[..]);

    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut alice_endpoint.event_rx,
        Duration::from_secs(10),
        "bob fallback endpoint data",
    )
    .await;
    let message = expect_single_endpoint_data_event(event);
    assert_eq!(*message.source_peer.node_addr(), bob_addr);
    assert_eq!(message.payload.as_slice(), &b"bob-fallback"[..]);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_update_peers_races_direct_address_with_existing_graph() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let dest_addr = *nodes[2].node.node_addr();
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("graph-before-direct".to_string()),
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            nodes[2].addr.to_string(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = nodes[0].node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_initiating()),
        "configured peer should warm over the existing FIPS graph"
    );
    assert!(
        has_outbound_handshake_to(&nodes[0].node, &dest_addr),
        "a usable graph route should not suppress direct outgoing auto-connect"
    );

    cleanup_nodes(&mut nodes).await;
}
