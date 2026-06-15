use super::*;

#[cfg(unix)]
#[test]
fn peer_runtime_send_snapshot_owns_fmp_metadata_and_worker_availability() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(7);
    let link_id = LinkId::new(9);
    let remote_addr = TransportAddr::from_string("peer-runtime-send-snapshot");
    let our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let sender = make_test_fmp_session(&node.identity, &peer_full, [0x01; 8], [0x02; 8]);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        sender,
        our_index,
        their_index,
        transport_id,
        remote_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let payload_len = 96;
    let snapshot = registry
        .prepare_peer_runtime_send_snapshot(&peer_addr, true, payload_len)
        .expect("peer runtime owner should prepare one send snapshot");

    assert_eq!(snapshot.node_addr(), peer_addr);
    assert_eq!(snapshot.fmp_prepared().transport_id, transport_id);
    assert_eq!(snapshot.fmp_prepared().remote_addr, remote_addr);
    assert_eq!(snapshot.fmp_prepared().their_index, their_index);
    assert_eq!(snapshot.fmp_prepared().payload_len, payload_len);
    assert_eq!(snapshot.fmp_prepared().flags & FLAG_CE, FLAG_CE);
    assert!(
        snapshot.fmp_worker_send_available(),
        "snapshot should carry worker-send availability from the same peer read"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "snapshot preparation must not consume a Noise send counter"
    );

    let reservation = registry
        .reserve_peer_runtime_fmp_worker_send(&snapshot)
        .expect("peer runtime snapshot should reserve the FMP worker send")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(reservation.counter, 0);
    assert_eq!(
        reservation.header,
        build_established_header(
            their_index,
            reservation.counter,
            snapshot.fmp_prepared().flags,
            payload_len,
        )
    );
    assert_eq!(
        reservation.predicted_bytes,
        ESTABLISHED_HEADER_SIZE + payload_len as usize + crate::noise::TAG_SIZE,
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        1,
        "snapshot reservation should consume exactly one FMP counter"
    );
}

#[cfg(unix)]
#[test]
fn peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(11);
    let link_id = LinkId::new(12);
    let remote_addr = TransportAddr::from_string("127.0.0.1:19191");
    let our_index = SessionIndex::new(13);
    let their_index = SessionIndex::new(14);
    let sender = make_test_fmp_session(&node.identity, &peer_full, [0x03; 8], [0x04; 8]);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        sender,
        our_index,
        their_index,
        transport_id,
        remote_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x04; 8]),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let route_snapshot = registry
        .prepare_peer_runtime_route_snapshot(&peer_addr)
        .expect("peer runtime owner should prepare route snapshot");
    assert_eq!(route_snapshot.node_addr(), peer_addr);
    assert_eq!(route_snapshot.transport_id(), transport_id);
    assert_eq!(route_snapshot.remote_addr(), &remote_addr);

    let (packet_tx, _packet_rx) = packet_channel(4);
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
    let transport = TransportHandle::Udp(udp);
    assert_eq!(
        route_snapshot.path_mtu(&transport),
        1234,
        "route snapshot should seed path MTU from its own transport/current-address pair"
    );

    let payload_len = 104;
    let send_snapshot = route_snapshot.prepare_send_snapshot(true, payload_len);
    assert_eq!(send_snapshot.node_addr(), peer_addr);
    assert_eq!(send_snapshot.fmp_prepared().transport_id, transport_id);
    assert_eq!(send_snapshot.fmp_prepared().remote_addr, remote_addr);
    assert_eq!(send_snapshot.fmp_prepared().their_index, their_index);
    assert_eq!(send_snapshot.fmp_prepared().payload_len, payload_len);
    assert_eq!(send_snapshot.fmp_prepared().flags & FLAG_CE, FLAG_CE);
    assert!(
        send_snapshot.fmp_worker_send_available(),
        "route snapshot should carry worker-send availability into send snapshots"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "route/send snapshot preparation must not consume a Noise send counter"
    );

    let reservation = registry
        .reserve_peer_runtime_fmp_worker_send(&send_snapshot)
        .expect("peer runtime send snapshot should reserve the FMP worker send")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(reservation.counter, 0);
    assert_eq!(
        reservation.header,
        build_established_header(
            their_index,
            reservation.counter,
            send_snapshot.fmp_prepared().flags,
            payload_len,
        )
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        1,
        "route-owned send snapshot should reserve exactly one FMP counter"
    );
}

#[test]
fn peer_lifecycle_registry_owns_batched_fmp_send_bookkeeping() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(17);
    let link_id = LinkId::new(18);
    let remote_addr = TransportAddr::from_string("peer-runtime-batch-bookkeeping");
    let sender = make_test_fmp_session(&node.identity, &peer_full, [0x05; 8], [0x06; 8]);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        sender,
        SessionIndex::new(19),
        SessionIndex::new(20),
        transport_id,
        remote_addr,
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x06; 8]),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let recorded = registry
        .record_fmp_send_bookkeeping_batch(&peer_addr, [(7, 2_000, 64), (8, 2_100, 128)])
        .expect("batched FMP send bookkeeping should find active peer");
    assert_eq!(recorded, 2);

    let peer = registry
        .get(&peer_addr)
        .expect("batched FMP bookkeeping must keep peer storage");
    assert_eq!(peer.link_stats().packets_sent, 2);
    assert_eq!(peer.link_stats().bytes_sent, 192);
    let mmp = peer.mmp().expect("active peer should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 2);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 192);

    assert!(
        registry
            .record_fmp_send_bookkeeping_batch(&make_node_addr(99), [(9, 2_200, 256)])
            .is_none(),
        "missing peers should not record batched FMP send bookkeeping"
    );
}

#[cfg(unix)]
#[test]
fn peer_runtime_route_decision_owns_next_hop_snapshot_weight_and_policy() {
    let local = Identity::generate();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(21);
    let remote_addr = TransportAddr::from_string("127.0.0.1:20202");
    let mut config = crate::config::Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_full.npub(),
        "udp",
        "127.0.0.1:20202",
    ));
    let mut node = Node::with_identity(local, config).expect("node");
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        LinkId::new(22),
        remote_addr.clone(),
        SessionIndex::new(23),
        SessionIndex::new(24),
    );
    node.peers
        .insert_with_current_session_index(peer_addr, active_peer);

    let decision = node
        .resolve_peer_runtime_route_decision(&peer_addr, 0x0102_0304)
        .expect("peer runtime route decision should resolve configured active peer");

    assert_eq!(decision.next_hop_addr(), peer_addr);
    assert_eq!(
        decision.scheduling_weight(),
        crate::node::encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
        "route decision should carry configured-peer send weight"
    );
    assert!(
        !decision.direct_path_blocks_direct_payload(),
        "configured static UDP direct peer should keep direct payload eligible"
    );
    let snapshot = decision.peer_snapshot();
    assert_eq!(snapshot.node_addr(), peer_addr);
    assert_eq!(snapshot.transport_id(), transport_id);
    assert_eq!(snapshot.remote_addr(), &remote_addr);

    let missing_dest = make_node_addr(0xE1);
    assert!(matches!(
        node.resolve_peer_runtime_route_decision(&missing_dest, 0x0102_0304),
        Err(PeerRuntimeRouteDecisionError::NoRoute { dest_addr })
            if dest_addr == missing_dest
    ));
}
