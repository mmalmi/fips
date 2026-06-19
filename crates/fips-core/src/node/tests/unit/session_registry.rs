use super::*;

#[test]
fn session_registry_owns_endpoint_session_storage_and_worker_registration_mirror() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let session_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(1), 10);
    let other_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(2), 10);

    let mut registry = SessionRegistry::default();
    let first = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x01; 8], [0x02; 8])),
        1_000,
        true,
    );
    assert!(registry.insert(peer_addr, first).is_none());
    assert_eq!(registry.len(), 1);
    assert!(registry.contains_key(&peer_addr));
    assert_eq!(
        registry.get(&peer_addr).map(SessionEntry::remote_pubkey),
        Some(&peer.pubkey_full())
    );
    assert!(
        !registry.record_worker_registration(session_key, false),
        "a rejected worker registration must not mark the session worker-owned"
    );
    assert!(!registry.is_worker_registered(&session_key));
    assert!(!registry.unregister_worker_session_if_registered(&session_key));

    assert!(registry.record_worker_registration(session_key, true));
    assert!(registry.is_worker_registered(&session_key));
    assert!(!registry.is_worker_registered(&other_key));

    let replacement = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x03; 8], [0x04; 8])),
        2_000,
        true,
    );
    let replaced = registry
        .insert(peer_addr, replacement)
        .expect("session replacement should return the previous entry");
    assert_eq!(replaced.remote_pubkey(), &peer.pubkey_full());
    registry
        .get_mut(&peer_addr)
        .expect("mutable access should stay behind the same owner")
        .record_sent(123);

    assert_eq!(
        registry
            .iter()
            .map(|(addr, entry)| (*addr, entry.remote_pubkey()))
            .collect::<Vec<_>>(),
        vec![(peer_addr, &peer.pubkey_full())]
    );

    let removed = registry
        .remove(&peer_addr)
        .expect("session storage should live in the session owner");
    assert_eq!(removed.remote_pubkey(), &peer.pubkey_full());
    assert!(
        registry.unregister_worker_session_if_registered(&session_key),
        "worker registration mirror should be cleaned through the session owner"
    );
    assert!(!registry.is_worker_registered(&session_key));
    assert!(!registry.contains_key(&peer_addr));
    assert!(registry.is_empty());
    assert!(registry.worker_registration_is_empty());
}

#[test]
fn session_registry_owns_fsp_send_bookkeeping() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let next_hop = make_node_addr(77);

    let mut registry = SessionRegistry::default();
    let mut entry = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x01; 8], [0x02; 8])),
        1_000,
        true,
    );
    entry.init_mmp(&crate::config::SessionMmpConfig::default());
    assert!(registry.insert(peer_addr, entry).is_none());

    let data_update =
        FspSendBookkeepingInput::data(123, 7, 1_234, 256, 2_000).with_next_hop(next_hop);
    let data_result = registry
        .record_fsp_send_bookkeeping(&peer_addr, data_update)
        .expect("FSP data send bookkeeping should find session entry");
    assert!(data_result.data_recorded);
    assert!(data_result.mmp_recorded);
    assert!(data_result.touched);
    assert!(data_result.next_hop_recorded);

    let entry = registry
        .get(&peer_addr)
        .expect("send bookkeeping must keep session storage");
    assert_eq!(entry.traffic_counters(), (1, 0, 123, 0));
    assert_eq!(entry.last_activity(), 2_000);
    assert_eq!(entry.last_outbound_frame_ms(), 2_000);
    assert_eq!(entry.last_outbound_next_hop(), Some(next_hop));
    let mmp = entry.mmp().expect("session should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 1);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 256);

    let control_result = registry
        .record_fsp_send_bookkeeping(&peer_addr, FspSendBookkeepingInput::control(8, 1_300, 64))
        .expect("FSP control send bookkeeping should find session entry");
    assert!(!control_result.data_recorded);
    assert!(control_result.mmp_recorded);
    assert!(!control_result.touched);
    assert!(!control_result.next_hop_recorded);
    let entry = registry
        .get(&peer_addr)
        .expect("control bookkeeping must keep session storage");
    assert_eq!(
        entry.traffic_counters(),
        (1, 0, 123, 0),
        "control/MMP bookkeeping must not inflate data counters"
    );
    assert_eq!(
        entry.last_activity(),
        2_000,
        "control/MMP bookkeeping must not reset idle activity"
    );
    assert_eq!(
        entry.last_outbound_frame_ms(),
        2_000,
        "control/MMP bookkeeping must not refresh outbound data activity"
    );
    let mmp = entry.mmp().expect("session should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 2);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 320);

    let legacy_full = Identity::generate();
    let legacy_identity = PeerIdentity::from_pubkey_full(legacy_full.pubkey_full());
    let legacy_addr = *legacy_identity.node_addr();
    let legacy_entry = SessionEntry::new(
        legacy_addr,
        legacy_full.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(
            &local,
            &legacy_full,
            [0x03; 8],
            [0x04; 8],
        )),
        3_000,
        true,
    );
    assert!(registry.insert(legacy_addr, legacy_entry).is_none());
    let legacy_result = registry
        .record_fsp_send_bookkeeping(
            &legacy_addr,
            FspSendBookkeepingInput::data(10, 9, 1_400, 32, 4_000),
        )
        .expect("legacy session without MMP should still record data bookkeeping");
    assert!(legacy_result.data_recorded);
    assert!(!legacy_result.mmp_recorded);
    assert!(legacy_result.touched);
    let entry = registry
        .get(&legacy_addr)
        .expect("legacy bookkeeping must keep session storage");
    assert_eq!(entry.traffic_counters(), (1, 0, 10, 0));
    assert_eq!(entry.last_activity(), 4_000);
    assert_eq!(entry.last_outbound_frame_ms(), 4_000);

    assert!(
        registry
            .record_fsp_send_bookkeeping(
                &make_node_addr(99),
                FspSendBookkeepingInput::control(10, 1_500, 48),
            )
            .is_none(),
        "missing sessions should not record FSP send bookkeeping"
    );
}

#[test]
fn session_registry_owns_batched_fsp_send_bookkeeping() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let first_next_hop = make_node_addr(77);
    let second_next_hop = make_node_addr(88);

    let mut registry = SessionRegistry::default();
    let mut entry = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x01; 8], [0x02; 8])),
        1_000,
        true,
    );
    entry.init_mmp(&crate::config::SessionMmpConfig::default());
    assert!(registry.insert(peer_addr, entry).is_none());

    let recorded = registry
        .record_fsp_send_bookkeeping_batch(
            &peer_addr,
            [
                FspSendBookkeepingInput::data(10, 9, 3_000, 40, 4_000)
                    .with_next_hop(first_next_hop),
                FspSendBookkeepingInput::control(11, 3_100, 24),
                FspSendBookkeepingInput::data(20, 12, 3_200, 60, 5_000)
                    .with_next_hop(second_next_hop),
            ],
        )
        .expect("batched FSP send bookkeeping should find session entry");
    assert_eq!(
        recorded, 2,
        "only data frames should contribute to data counter batch size"
    );

    let entry = registry
        .get(&peer_addr)
        .expect("batched bookkeeping must keep session storage");
    assert_eq!(entry.traffic_counters(), (2, 0, 30, 0));
    assert_eq!(entry.last_activity(), 5_000);
    assert_eq!(entry.last_outbound_frame_ms(), 5_000);
    assert_eq!(entry.last_outbound_next_hop(), Some(second_next_hop));
    let mmp = entry.mmp().expect("session should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 3);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 124);

    assert!(
        registry
            .record_fsp_send_bookkeeping_batch(
                &make_node_addr(99),
                [FspSendBookkeepingInput::data(10, 1, 3_300, 32, 6_000)],
            )
            .is_none(),
        "missing sessions should not record batched FSP send bookkeeping"
    );
}

#[cfg(unix)]
#[test]
fn session_registry_owns_endpoint_fsp_worker_reservation_and_path_mtu_seed() {
    use crate::node::session::{EndToEndState, SessionEntry};
    use ring::aead::Aad;

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let (send_session, mut recv_session) =
        make_test_fmp_session_pair(&local, &peer, [0x01; 8], [0x02; 8]);

    let mut registry = SessionRegistry::default();
    let mut entry = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(send_session),
        1_000,
        true,
    );
    entry.init_mmp(&crate::config::SessionMmpConfig::default());
    assert_eq!(
        entry.mmp().expect("MMP initialized").path_mtu.current_mtu(),
        u16::MAX
    );
    assert!(registry.insert(peer_addr, entry).is_none());

    let plaintext = b"endpoint-fsp-worker-frame";
    let input = FspWorkerSendReservationInput {
        flags: crate::node::session_wire::FSP_FLAG_K,
        payload_len: plaintext.len() as u16,
        path_mtu: 1_280,
    };
    let reservation = registry
        .reserve_endpoint_data_fsp_worker_send(&peer_addr, input)
        .expect("session registry should own established FSP worker reservation")
        .expect("established session should expose a worker cipher");

    assert_eq!(reservation.counter, 0);
    assert_eq!(
        reservation.header,
        crate::node::session_wire::build_fsp_header(
            reservation.counter,
            input.flags,
            input.payload_len,
        )
    );
    let entry = registry
        .get(&peer_addr)
        .expect("reservation must keep session storage");
    assert_eq!(
        entry.send_counter(),
        1,
        "reservation should consume exactly one FSP counter"
    );
    assert_eq!(
        entry
            .mmp()
            .expect("MMP should remain initialized")
            .path_mtu
            .current_mtu(),
        input.path_mtu,
        "endpoint-data FSP reservation should seed source path MTU"
    );

    let mut ciphertext = plaintext.to_vec();
    reservation
        .cipher
        .seal_in_place_append_tag(
            crate::noise::CipherState::counter_to_nonce(reservation.counter),
            Aad::from(&reservation.header),
            &mut ciphertext,
        )
        .expect("worker-style FSP seal should succeed");
    assert_eq!(
        recv_session
            .decrypt_with_replay_check_and_aad(
                &ciphertext,
                reservation.counter,
                &reservation.header,
            )
            .expect("receiver should accept worker-sealed FSP frame"),
        plaintext
    );

    assert!(
        matches!(
            registry.reserve_endpoint_data_fsp_worker_send(&make_node_addr(99), input),
            Err(FspWorkerSendReservationError::MissingSession)
        ),
        "missing sessions should fail before reservation"
    );

    let pending_peer = Identity::generate();
    let pending_identity = PeerIdentity::from_pubkey_full(pending_peer.pubkey_full());
    let pending_addr = *pending_identity.node_addr();
    let pending_entry = SessionEntry::new(
        pending_addr,
        pending_peer.pubkey_full(),
        EndToEndState::Initiating(crate::noise::HandshakeState::new_initiator(
            local.keypair(),
            pending_peer.pubkey_full(),
        )),
        2_000,
        true,
    );
    assert!(registry.insert(pending_addr, pending_entry).is_none());
    assert!(
        matches!(
            registry.reserve_endpoint_data_fsp_worker_send(&pending_addr, input),
            Err(FspWorkerSendReservationError::NotEstablished)
        ),
        "non-established sessions should fail before counter reservation"
    );
    assert_eq!(
        registry
            .get(&pending_addr)
            .expect("pending session remains stored")
            .send_counter(),
        0,
        "non-established reservation failure must not consume a counter"
    );
}

#[test]
fn decrypt_session_registrations_own_worker_acceptance_and_unregister_gate() {
    let session_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(1), 10);
    let other_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(2), 10);
    let mut registrations = DecryptSessionRegistrations::default();

    assert!(!registrations.record_worker_registration(session_key, false));
    assert!(
        !registrations.is_registered(&session_key),
        "a full worker queue must not make rx-loop dispatch to an unregistered shard"
    );
    assert!(
        !registrations.unregister_if_registered(&session_key),
        "worker unregister should be skipped when local registration never succeeded"
    );

    assert!(registrations.record_worker_registration(session_key, true));
    assert!(registrations.is_registered(&session_key));
    assert!(!registrations.is_registered(&other_key));

    assert!(registrations.unregister_if_registered(&session_key));
    assert!(!registrations.is_registered(&session_key));
    assert!(registrations.is_empty());
}

#[test]
fn configured_peer_send_weights_own_identity_parse_and_default_policy() {
    let configured = Identity::generate();
    let configured_npub = configured.npub();
    let configured_addr = *PeerIdentity::from_npub(&configured_npub)
        .expect("configured peer identity")
        .node_addr();
    let on_demand = Identity::generate();
    let on_demand_npub = on_demand.npub();
    let on_demand_addr = *PeerIdentity::from_npub(&on_demand_npub)
        .expect("on-demand peer identity")
        .node_addr();
    let unknown_addr =
        *PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full()).node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        configured_npub.clone(),
        "udp",
        "127.0.0.1:1",
    ));
    let mut on_demand_peer =
        crate::config::PeerConfig::new(on_demand_npub.clone(), "udp", "127.0.0.1:3");
    on_demand_peer.connect_policy = crate::config::ConnectPolicy::OnDemand;
    config.peers.push(on_demand_peer);
    config.peers.push(crate::config::PeerConfig::new(
        "not-a-valid-peer-id",
        "udp",
        "127.0.0.1:2",
    ));

    let weights = ConfiguredPeerSendWeights::from_config(&config);

    assert_eq!(
        weights.weight_for(&configured_addr),
        encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
        "configured peers reserve the explicit send-scheduling lane"
    );
    assert_eq!(
        weights.weight_for(&unknown_addr),
        encrypt_worker::DEFAULT_SEND_WEIGHT,
        "unconfigured peers must stay on the default send-scheduling lane"
    );
    assert_eq!(
        weights.len(),
        2,
        "invalid peer identities must not create phantom scheduling policy"
    );
    assert_eq!(
        weights.peer_addr_for_npub(&configured_npub),
        Some(configured_addr),
        "configured peer npubs are parsed once into a reverse address lookup"
    );
    assert_eq!(
        weights.peer_addr_for_npub(&on_demand_npub),
        Some(on_demand_addr),
        "non-auto configured peers should still be addressable by npub"
    );
    assert_eq!(
        weights
            .peer_config(&configured_addr)
            .expect("configured peer metadata")
            .addresses[0]
            .addr,
        "127.0.0.1:1",
        "configured peer metadata is parsed once into the runtime lookup cache"
    );
    let auto_connect_addrs = weights
        .auto_connect_peer_configs()
        .map(|(addr, _)| *addr)
        .collect::<Vec<_>>();
    assert_eq!(
        auto_connect_addrs,
        vec![configured_addr],
        "runtime auto-connect iteration must preserve Config::auto_connect_peers semantics"
    );
    assert!(
        weights.peer_config(&unknown_addr).is_none(),
        "unconfigured peers must not have cached peer metadata"
    );
}
