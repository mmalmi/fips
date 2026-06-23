use super::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn peer_lifecycle_registry_owns_connected_udp_activation_plan() {
    let node = make_node();
    let transport_id = TransportId::new(1);

    let configured_full = Identity::generate();
    let configured_identity = PeerIdentity::from_pubkey_full(configured_full.pubkey_full());
    let configured_addr = *configured_identity.node_addr();

    let discovered_full = Identity::generate();
    let discovered_identity = PeerIdentity::from_pubkey_full(discovered_full.pubkey_full());
    let discovered_addr = *discovered_identity.node_addr();

    let stale_full = Identity::generate();
    let stale_identity = PeerIdentity::from_pubkey_full(stale_full.pubkey_full());
    let stale_addr = *stale_identity.node_addr();

    let installed_full = Identity::generate();
    let installed_identity = PeerIdentity::from_pubkey_full(installed_full.pubkey_full());
    let installed_addr = *installed_identity.node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        configured_full.npub(),
        "udp",
        "127.0.0.1:1",
    ));
    let configured_peers = ConfiguredPeerCache::from_config(&config);

    let mut registry = PeerLifecycleRegistry::default();
    registry.insert_with_current_session_index(
        discovered_addr,
        make_active_test_peer(
            &node,
            &discovered_full,
            discovered_identity,
            transport_id,
            LinkId::new(20),
            TransportAddr::from_string("connected-udp-discovered"),
            SessionIndex::new(20),
            SessionIndex::new(30),
        ),
    );
    registry.insert_with_current_session_index(
        configured_addr,
        make_active_test_peer(
            &node,
            &configured_full,
            configured_identity,
            transport_id,
            LinkId::new(10),
            TransportAddr::from_string("connected-udp-configured"),
            SessionIndex::new(10),
            SessionIndex::new(11),
        ),
    );

    let mut stale_peer = make_active_test_peer(
        &node,
        &stale_full,
        stale_identity,
        transport_id,
        LinkId::new(30),
        TransportAddr::from_string("connected-udp-stale"),
        SessionIndex::new(40),
        SessionIndex::new(41),
    );
    stale_peer.mark_stale();
    registry.insert_with_current_session_index(stale_addr, stale_peer);

    let mut installed_peer = make_active_test_peer(
        &node,
        &installed_full,
        installed_identity,
        transport_id,
        LinkId::new(40),
        TransportAddr::from_string("connected-udp-installed"),
        SessionIndex::new(50),
        SessionIndex::new(51),
    );
    let (socket, drain) = make_test_connected_udp_pair(transport_id);
    installed_peer.set_connected_udp(socket, drain);
    registry.insert_with_current_session_index(installed_addr, installed_peer);

    let plan = registry.connected_udp_activation_plan(&configured_peers);

    assert_eq!(
        plan.installed_count, 1,
        "lifecycle owner should count already-installed connected UDP peers"
    );
    assert_eq!(
        plan.candidates,
        vec![configured_addr, discovered_addr],
        "configured peers should be activated before discovered peers, while stale and already-connected peers are skipped"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn connected_udp_decrypt_fast_path_prepares_matching_current_epoch_established_packets() {
    let transport_id = TransportId::new(7);
    let receiver_idx = SessionIndex::new(0x0a0b_0c0d);
    let session_key =
        crate::node::decrypt_worker::DecryptSessionKey::new(transport_id, receiver_idx.as_u32());
    let workers = crate::node::decrypt_worker::DecryptWorkerPool::spawn(1);
    let (_fallback_tx, _fallback_rx) =
        crate::node::decrypt_worker::decrypt_worker_fallback_channels();
    let fast_path =
        ConnectedUdpDecryptFastPath::new(session_key, 0, false, make_node_addr(0x77), workers);
    let remote_addr = TransportAddr::from_string("127.0.0.1:2121");

    let header = build_established_header(receiver_idx, 99, FLAG_CE | FLAG_SP, 0);
    let packet = build_encrypted(&header, &[0u8; 16]);
    let job = fast_path
        .prepare_job(transport_id, remote_addr.clone(), packet.clone(), 1_234)
        .expect("matching established packet should prepare a decrypt job");
    assert_eq!(job.packet_data, packet);
    assert_eq!(job.session_key, session_key);
    assert_eq!(job.fmp_counter, 99);
    assert_eq!(job.fmp_flags, FLAG_CE | FLAG_SP);
    assert_eq!(job.fmp_header, header);
    assert_eq!(job.fmp_ciphertext_offset, ESTABLISHED_HEADER_SIZE);

    let bulk_packet = build_encrypted(
        &header,
        &vec![0u8; crate::transport::udp::peer_drain::CONNECTED_UDP_PRIORITY_MAX_LEN],
    );
    let bulk_job = fast_path
        .prepare_job(
            transport_id,
            remote_addr.clone(),
            bulk_packet.clone(),
            1_235,
        )
        .expect("matching established bulk packet should prepare a decrypt job");
    assert_eq!(bulk_job.packet_data, bulk_packet);
    assert_eq!(bulk_job.session_key, session_key);
    assert_eq!(bulk_job.fmp_counter, 99);
    assert_eq!(bulk_job.fmp_ciphertext_offset, ESTABLISHED_HEADER_SIZE);

    let wrong_epoch_header =
        build_established_header(receiver_idx, 100, FLAG_CE | FLAG_KEY_EPOCH, 0);
    let wrong_epoch_packet = build_encrypted(&wrong_epoch_header, &[0u8; 16]);
    match fast_path.prepare_job(
        transport_id,
        remote_addr.clone(),
        wrong_epoch_packet.clone(),
        1_235,
    ) {
        Ok(_) => panic!("wrong FMP epoch must stay on rx_loop for rekey handling"),
        Err(returned) => assert_eq!(returned, wrong_epoch_packet),
    }

    let wrong_header = build_established_header(SessionIndex::new(0x0102_0304), 100, 0, 0);
    let wrong_packet = build_encrypted(&wrong_header, &[0u8; 16]);
    match fast_path.prepare_job(
        transport_id,
        remote_addr.clone(),
        wrong_packet.clone(),
        1_235,
    ) {
        Ok(_) => panic!("wrong receiver index must not bypass rx_loop"),
        Err(returned) => assert_eq!(returned, wrong_packet),
    }

    let mut non_established = vec![0u8; ESTABLISHED_HEADER_SIZE + 16];
    non_established[0] = 0x01;
    match fast_path.prepare_job(transport_id, remote_addr, non_established.clone(), 1_236) {
        Ok(_) => panic!("non-established packets must stay on the packet channel"),
        Err(returned) => assert_eq!(returned, non_established),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn peer_lifecycle_registry_owns_connected_udp_install_and_clear() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        LinkId::new(10),
        TransportAddr::from_string("connected-udp-install"),
        SessionIndex::new(10),
        SessionIndex::new(11),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let (socket, drain) = make_test_connected_udp_pair(transport_id);
    let installed = registry.install_connected_udp_if_eligible(&peer_addr, socket, drain);

    assert_eq!(
        installed,
        ConnectedUdpInstallResult::Installed,
        "lifecycle owner should install connected UDP only after eligibility recheck"
    );
    assert!(
        registry
            .get(&peer_addr)
            .expect("active peer")
            .connected_udp()
            .is_some(),
        "connected UDP socket should be visible through the active peer after lifecycle install"
    );

    let (second_socket, second_drain) = make_test_connected_udp_pair(transport_id);
    assert_eq!(
        registry.install_connected_udp_if_eligible(&peer_addr, second_socket, second_drain),
        ConnectedUdpInstallResult::NotEligible,
        "already-installed connected UDP peers must not get a replacement from the activation race path"
    );

    assert_eq!(
        registry.clear_connected_udp_for_peer(&peer_addr),
        ConnectedUdpClearResult::Cleared,
        "lifecycle owner should clear an installed connected UDP socket/drain pair"
    );
    assert!(
        registry
            .get(&peer_addr)
            .expect("active peer")
            .connected_udp()
            .is_none(),
        "connected UDP socket should be gone after lifecycle clear"
    );
    assert_eq!(
        registry.clear_connected_udp_for_peer(&peer_addr),
        ConnectedUdpClearResult::AlreadyClear,
        "clearing an already-clear peer should be idempotent"
    );
    assert_eq!(
        registry.clear_connected_udp_for_peer(&NodeAddr::from_bytes([0x42; 16])),
        ConnectedUdpClearResult::MissingPeer,
        "clear should report when the peer lifecycle owner has no active peer"
    );
}

#[test]
fn peer_lifecycle_registry_owns_link_dead_direct_path_degradation() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("link-dead-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let (socket, drain) = make_test_connected_udp_pair(transport_id);
        active_peer.set_connected_udp(socket, drain);
        assert!(
            active_peer.connected_udp().is_some(),
            "fixture should start with connected UDP installed"
        );
    }

    registry.insert_with_current_session_index(peer_addr, active_peer);

    let degraded = registry
        .mark_link_dead_direct_path(&peer_addr)
        .expect("link-dead degradation should find active peer");

    assert_eq!(
        degraded.link_id, link_id,
        "lifecycle owner should return the degraded link for logging and cleanup"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(
        degraded.connected_udp_cleared,
        "link-dead degradation should clear connected UDP through the lifecycle owner"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("link-dead degradation must keep active peer storage");
    assert!(
        peer.can_send(),
        "stale direct paths remain probeable instead of becoming disconnected"
    );
    assert!(
        !peer.is_healthy(),
        "link-dead direct paths should no longer be healthy for payload routing"
    );
    assert_eq!(
        peer.link_id(),
        link_id,
        "link-dead degradation should not swap peer link identity"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(
        peer.connected_udp().is_none(),
        "connected UDP socket/drain pair must not outlive stale direct-path evidence"
    );
}

#[test]
fn peer_lifecycle_registry_owns_active_peer_teardown_session_indices() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("teardown-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let rekey_our_index = SessionIndex::new(11);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );
    arm_test_fmp_rekey(&mut active_peer, rekey_our_index);

    assert!(registry.insert(peer_addr, active_peer).is_none());
    assert_eq!(
        registry.insert_session_index((transport_id, current_our_index.as_u32()), peer_addr),
        None
    );
    assert_eq!(
        registry.insert_session_index((transport_id, rekey_our_index.as_u32()), peer_addr),
        None
    );

    let removed = registry
        .remove_with_session_indices(&peer_addr)
        .expect("active peer teardown should return the removed peer plus session indices");
    assert_eq!(removed.peer.node_addr(), &peer_addr);
    assert_eq!(
        removed.session_indices,
        vec![
            PeerSessionIndex {
                kind: PeerSessionIndexKind::Current,
                key: (transport_id, current_our_index.as_u32()),
                index: current_our_index,
            },
            PeerSessionIndex {
                kind: PeerSessionIndexKind::Rekey,
                key: (transport_id, rekey_our_index.as_u32()),
                index: rekey_our_index,
            },
        ],
        "peer lifecycle teardown must own which active-peer session indices need deregister/free"
    );
    assert!(
        registry.get(&peer_addr).is_none(),
        "teardown removal must remove active peer storage"
    );
}

#[test]
fn peer_lifecycle_registry_owns_connection_and_active_peer_storage() {
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(77);
    let session_key = (transport_id, 10);

    let mut registry = PeerLifecycleRegistry::default();
    let connection = PeerConnection::outbound(link_id, peer_identity, 1_000);

    assert!(registry.insert_connection(link_id, connection).is_none());
    assert_eq!(registry.connection_len(), 1);
    assert!(registry.contains_connection(&link_id));
    assert_eq!(
        registry
            .get_connection(&link_id)
            .and_then(|conn: &PeerConnection| conn.expected_identity())
            .map(|identity: &PeerIdentity| identity.node_addr()),
        Some(&peer_addr)
    );

    assert!(
        registry
            .insert(peer_addr, ActivePeer::new(peer_identity, link_id, 2_000))
            .is_none()
    );
    assert_eq!(registry.len(), 1);
    assert!(registry.contains_key(&peer_addr));
    assert_eq!(registry.insert_session_index(session_key, peer_addr), None);
    assert_eq!(registry.lookup_session_index(session_key), Some(peer_addr));

    let removed_connection = registry
        .remove_connection(&link_id)
        .expect("pending connection storage should live in the lifecycle owner");
    assert_eq!(removed_connection.link_id(), link_id);
    assert!(
        registry.get(&peer_addr).is_some(),
        "active peer storage must survive pending-connection teardown"
    );
    assert_eq!(registry.lookup_session_index(session_key), Some(peer_addr));

    let removed_peer = registry
        .remove(&peer_addr)
        .expect("active peer storage should live in the lifecycle owner");
    assert_eq!(removed_peer.node_addr(), &peer_addr);
    assert!(registry.connection_is_empty());
    assert!(registry.is_empty());
}
