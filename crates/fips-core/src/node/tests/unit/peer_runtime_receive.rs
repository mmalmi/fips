use super::*;

#[test]
fn peer_runtime_receive_rejects_short_authenticated_fmp_plaintext() {
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let remote_addr = TransportAddr::from_string("short-authenticated-fmp");

    let result =
        PeerRuntimeReceive::from_authenticated_fmp_plaintext(AuthenticatedFmpPlaintext::new(
            peer_identity,
            TransportId::new(1),
            &remote_addr,
            1_000,
            32,
            1,
            0,
            &[1, 2, 3],
        ));

    assert!(matches!(
        result,
        Err(PeerRuntimeReceiveError::MissingInnerTimestamp)
    ));
}

#[test]
fn peer_runtime_receive_owns_bookkeeping_and_dispatch_metadata() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let new_transport_id = TransportId::new(2);
    let link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("runtime-recv-old-path");
    let new_addr = TransportAddr::from_string("runtime-recv-new-path");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        old_transport_id,
        link_id,
        old_addr,
        current_our_index,
        current_their_index,
    );
    active_peer.increment_decrypt_failures();
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let fmp_plaintext = [
        0xd2,
        0x04,
        0x00,
        0x00,
        LinkMessageType::SessionDatagram.to_byte(),
        0xbb,
        0xcc,
    ];
    let receive =
        PeerRuntimeReceive::from_authenticated_fmp_plaintext(AuthenticatedFmpPlaintext::new(
            peer_identity,
            new_transport_id,
            &new_addr,
            2_000,
            128,
            7,
            FLAG_CE,
            &fmp_plaintext,
        ))
        .expect("valid authenticated FMP plaintext should build a receive runtime");

    let dispatch = receive.record_bookkeeping(&mut registry, std::time::Instant::now(), true);

    assert_eq!(dispatch.source_peer(), peer_identity);
    assert!(dispatch.ce_flag());
    assert_eq!(
        dispatch.link_message(),
        &[LinkMessageType::SessionDatagram.to_byte(), 0xbb, 0xcc]
    );
    let bookkeeping = dispatch
        .bookkeeping()
        .expect("authenticated receive should find the active peer");
    assert!(bookkeeping.path_bookkeeping_recorded);
    assert!(bookkeeping.mmp_recorded);

    let action = dispatch.into_action();
    assert_eq!(action.node_addr(), &peer_addr);
    assert!(action.address_changed());
    let link_message = action
        .link_message()
        .expect("non-empty FMP link message should parse");
    assert_eq!(link_message.source_node_addr(), &peer_addr);
    assert_eq!(
        link_message.msg_type(),
        LinkMessageType::SessionDatagram.to_byte()
    );
    assert_eq!(link_message.payload(), &[0xbb, 0xcc]);
    assert!(link_message.ce_flag());
    let link_message = action
        .into_link_message()
        .expect("non-empty FMP link message should parse");
    assert_eq!(link_message.source_node_addr(), &peer_addr);
    assert_eq!(
        link_message.msg_type(),
        LinkMessageType::SessionDatagram.to_byte()
    );
    assert_eq!(link_message.payload(), &[0xbb, 0xcc]);
    assert!(link_message.ce_flag());
    let session_datagram = link_message.into_session_datagram();
    assert_eq!(session_datagram.previous_hop_addr(), &peer_addr);
    assert_eq!(session_datagram.payload(), &[0xbb, 0xcc]);
    assert!(session_datagram.ce_flag());
    let session_source = make_node_addr(0x44);
    let local_payload =
        session_datagram.local_session_payload(session_source, &[0xdd, 0xee], 1_280);
    assert_eq!(local_payload.source_addr(), &session_source);
    assert_eq!(local_payload.previous_hop_addr(), &peer_addr);
    assert_eq!(local_payload.payload(), &[0xdd, 0xee]);
    let encrypted_payload = local_payload.into_encrypted();
    assert_eq!(encrypted_payload.source_addr(), &session_source);
    assert_eq!(encrypted_payload.previous_hop_addr(), &peer_addr);
    assert_eq!(encrypted_payload.payload(), &[0xdd, 0xee]);
    assert_eq!(encrypted_payload.path_mtu(), 1_280);
    assert!(encrypted_payload.ce_flag());

    let empty_receive =
        PeerRuntimeReceive::from_authenticated_fmp_plaintext(AuthenticatedFmpPlaintext::new(
            peer_identity,
            new_transport_id,
            &new_addr,
            2_100,
            64,
            8,
            0,
            &[0, 0, 0, 0],
        ))
        .expect("timestamp-only authenticated FMP plaintext should parse");
    let mut empty_registry = PeerLifecycleRegistry::default();
    let empty_action = empty_receive
        .record_bookkeeping(&mut empty_registry, std::time::Instant::now(), true)
        .into_action();
    assert_eq!(empty_action.node_addr(), &peer_addr);
    assert!(
        empty_action.link_message().is_none(),
        "timestamp-only authenticated FMP plaintext should not leave Node to split dispatch bytes"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("receive runtime must keep active peer storage");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(peer.transport_id(), Some(new_transport_id));
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.link_stats().packets_recv, 1);
    assert_eq!(peer.link_stats().bytes_recv, 128);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.receiver.highest_counter(), 7);
    assert_eq!(mmp.receiver.ecn_ce_count(), 1);
}

#[test]
fn peer_lifecycle_registry_owns_fmp_send_bookkeeping() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("fmp-send-bookkeeping-peer");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        current_their_index,
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let update = registry
        .record_fmp_send_bookkeeping(&peer_addr, 7, 1_234, 256)
        .expect("FMP send bookkeeping should find active peer");
    assert!(
        update.mmp_recorded,
        "active FMP peers should update MMP sender state with link send stats"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("send bookkeeping must keep active peer storage");
    assert_eq!(peer.link_stats().packets_sent, 1);
    assert_eq!(peer.link_stats().bytes_sent, 256);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 1);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 256);

    let second_update = registry
        .record_fmp_send_bookkeeping(&peer_addr, 8, 1_300, 128)
        .expect("second FMP send bookkeeping should find active peer");
    assert!(second_update.mmp_recorded);
    let peer = registry
        .get(&peer_addr)
        .expect("second send bookkeeping must keep active peer storage");
    assert_eq!(peer.link_stats().packets_sent, 2);
    assert_eq!(peer.link_stats().bytes_sent, 384);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 2);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 384);

    let no_mmp_full = Identity::generate();
    let no_mmp_identity = PeerIdentity::from_pubkey_full(no_mmp_full.pubkey_full());
    let no_mmp_addr = *no_mmp_identity.node_addr();
    assert!(
        registry
            .insert(
                no_mmp_addr,
                ActivePeer::new(no_mmp_identity, LinkId::new(77), 3_000),
            )
            .is_none()
    );
    let legacy_update = registry
        .record_fmp_send_bookkeeping(&no_mmp_addr, 9, 1_400, 64)
        .expect("legacy active peer should still record link send stats");
    assert!(
        !legacy_update.mmp_recorded,
        "legacy peers without MMP state should not claim MMP sender updates"
    );
    let peer = registry
        .get(&no_mmp_addr)
        .expect("legacy send bookkeeping must keep active peer storage");
    assert_eq!(peer.link_stats().packets_sent, 1);
    assert_eq!(peer.link_stats().bytes_sent, 64);

    assert!(
        registry
            .record_fmp_send_bookkeeping(&make_node_addr(99), 10, 1_500, 32)
            .is_none(),
        "missing active peers should not record send bookkeeping"
    );
}

#[cfg(unix)]
#[test]
fn peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(7);
    let link_id = LinkId::new(9);
    let remote_addr = TransportAddr::from_string("fmp-send-prepare-peer");
    let our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let (sender, mut receiver) =
        make_test_fmp_session_pair(&node.identity, &peer_full, [0x01; 8], [0x02; 8]);

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

    let plaintext = b"owner-prepared-fmp";
    let payload_len = (4 + plaintext.len()) as u16;
    let prepared = registry
        .prepare_fmp_send(&peer_addr, true, payload_len)
        .expect("lifecycle owner should prepare FMP send metadata");

    assert_eq!(prepared.transport_id, transport_id);
    assert_eq!(prepared.remote_addr, remote_addr);
    assert_eq!(prepared.their_index, their_index);
    assert_eq!(prepared.payload_len, payload_len);
    assert_eq!(prepared.flags & FLAG_CE, FLAG_CE);
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "preparation must not consume a Noise send counter"
    );

    let mismatched_prepared = registry
        .prepare_fmp_send(&peer_addr, true, payload_len + 1)
        .expect("lifecycle owner should prepare mismatched metadata for guard");
    assert!(
        matches!(
            registry.prepare_fmp_worker_send(&peer_addr, &mismatched_prepared, plaintext),
            Err(FmpSendPreparationError::PayloadLengthMismatch)
        ),
        "payload mismatch should be rejected before counter reservation"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "payload mismatch must not consume a Noise send counter"
    );

    let worker = registry
        .prepare_fmp_worker_send(&peer_addr, &prepared, plaintext)
        .expect("worker packet preparation should be owner-managed")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(worker.counter, 0);
    assert_eq!(
        worker.header,
        build_established_header(their_index, worker.counter, prepared.flags, payload_len)
    );
    assert_eq!(
        worker.predicted_bytes,
        ESTABLISHED_HEADER_SIZE + payload_len as usize + 16
    );
    assert_eq!(
        worker.wire_buf.len(),
        ESTABLISHED_HEADER_SIZE + payload_len as usize
    );
    assert!(
        worker.wire_buf.capacity() >= worker.predicted_bytes,
        "worker wire buffer should reserve room for the FMP AEAD tag"
    );
    assert_eq!(&worker.wire_buf[..ESTABLISHED_HEADER_SIZE], &worker.header);
    assert_eq!(
        &worker.wire_buf[ESTABLISHED_HEADER_SIZE..ESTABLISHED_HEADER_SIZE + 4],
        &prepared.timestamp_ms.to_le_bytes()
    );
    assert_eq!(&worker.wire_buf[ESTABLISHED_HEADER_SIZE + 4..], plaintext);
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        1,
        "worker reservation should consume exactly one counter"
    );

    let worker_inner_plaintext = prepend_inner_header(prepared.timestamp_ms, plaintext);
    let mut worker_wire = worker.wire_buf.clone();
    let worker_tag = {
        let (header, plaintext) = worker_wire.split_at_mut(ESTABLISHED_HEADER_SIZE);
        worker
            .cipher
            .seal_in_place_separate_tag(
                crate::noise::CipherState::counter_to_nonce(worker.counter),
                ring::aead::Aad::from(header),
                plaintext,
            )
            .expect("worker-style FMP seal should succeed")
    };
    worker_wire.extend_from_slice(worker_tag.as_ref());
    let worker_parsed = EncryptedHeader::parse(&worker_wire).expect("worker wire packet parses");
    assert_eq!(worker_parsed.counter, worker.counter);
    assert_eq!(worker_parsed.receiver_idx, their_index);
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                worker_parsed.ciphertext(&worker_wire),
                worker_parsed.counter,
                &worker.header,
            )
            .expect("receiver should accept worker-sealed packet"),
        worker_inner_plaintext
    );

    let inline_prepared = registry
        .prepare_fmp_send(&peer_addr, false, payload_len)
        .expect("lifecycle owner should prepare inline FMP send metadata");
    let inline_inner_plaintext = prepend_inner_header(inline_prepared.timestamp_ms, plaintext);
    let inline = registry
        .seal_prepared_fmp_inline_send(&peer_addr, &inline_prepared, &inline_inner_plaintext)
        .expect("inline seal should be owner-managed");
    assert_eq!(inline.counter, 1);
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        2,
        "inline seal should consume exactly one counter"
    );
    let parsed = EncryptedHeader::parse(&inline.wire_packet).expect("inline wire packet parses");
    assert_eq!(parsed.counter, inline.counter);
    assert_eq!(parsed.receiver_idx, their_index);
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                parsed.ciphertext(&inline.wire_packet),
                parsed.counter,
                &inline.header,
            )
            .expect("receiver should accept inline-sealed packet"),
        inline_inner_plaintext
    );

    let pipelined_link_plaintext_len = crate::protocol::SESSION_DATAGRAM_HEADER_SIZE
        + crate::node::session_wire::FSP_HEADER_SIZE
        + 32;
    let pipelined_payload_len = (4 + pipelined_link_plaintext_len + crate::noise::TAG_SIZE) as u16;
    let pipelined_prepared = registry
        .prepare_fmp_send(&peer_addr, false, pipelined_payload_len)
        .expect("lifecycle owner should prepare pipelined FMP metadata");
    let pipelined_snapshot = registry
        .prepare_peer_runtime_send_snapshot(&peer_addr, false, pipelined_payload_len)
        .expect("peer runtime owner should prepare pipelined FMP metadata with availability");
    assert!(
        pipelined_snapshot.fmp_worker_send_available(),
        "pipelined path should check FMP worker-cipher availability before reserving FSP"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        2,
        "worker availability check must not consume an FMP counter"
    );
    let pipelined_reservation = registry
        .reserve_prepared_fmp_worker_send(&peer_addr, &pipelined_prepared)
        .expect("pipelined FMP reservation should be owner-managed")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(pipelined_reservation.counter, 2);
    assert_eq!(
        pipelined_reservation.header,
        build_established_header(
            their_index,
            pipelined_reservation.counter,
            pipelined_prepared.flags,
            pipelined_payload_len,
        )
    );
    assert_eq!(
        pipelined_reservation.predicted_bytes,
        ESTABLISHED_HEADER_SIZE + pipelined_payload_len as usize + crate::noise::TAG_SIZE,
        "predicted bytes should include the outer FMP AEAD tag"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        3,
        "pipelined worker reservation should consume exactly one FMP counter"
    );

    let mut pipelined_link_ciphertext = vec![0xA5; pipelined_link_plaintext_len];
    pipelined_link_ciphertext.extend_from_slice(&[0x5A; crate::noise::TAG_SIZE]);
    let pipelined_inner =
        prepend_inner_header(pipelined_prepared.timestamp_ms, &pipelined_link_ciphertext);
    let mut pipelined_wire = Vec::with_capacity(pipelined_reservation.predicted_bytes);
    pipelined_wire.extend_from_slice(&pipelined_reservation.header);
    pipelined_wire.extend_from_slice(&pipelined_inner);
    assert_eq!(
        pipelined_wire.len(),
        ESTABLISHED_HEADER_SIZE + pipelined_payload_len as usize
    );
    let pipelined_tag = {
        let (header, plaintext) = pipelined_wire.split_at_mut(ESTABLISHED_HEADER_SIZE);
        pipelined_reservation
            .cipher
            .seal_in_place_separate_tag(
                crate::noise::CipherState::counter_to_nonce(pipelined_reservation.counter),
                ring::aead::Aad::from(header),
                plaintext,
            )
            .expect("pipelined worker-style FMP seal should succeed")
    };
    pipelined_wire.extend_from_slice(pipelined_tag.as_ref());
    let pipelined_parsed =
        EncryptedHeader::parse(&pipelined_wire).expect("pipelined wire packet parses");
    assert_eq!(pipelined_parsed.counter, pipelined_reservation.counter);
    assert_eq!(pipelined_parsed.receiver_idx, their_index);
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                pipelined_parsed.ciphertext(&pipelined_wire),
                pipelined_parsed.counter,
                &pipelined_reservation.header,
            )
            .expect("receiver should accept pipelined worker-sealed packet"),
        pipelined_inner
    );
}
