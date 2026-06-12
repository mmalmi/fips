use super::*;

#[cfg(unix)]
#[test]
fn fmp_worker_send_reservation_owns_counter_header_and_cipher() {
    let local = Identity::generate();
    let peer = Identity::generate();
    let (mut sender, mut receiver) =
        make_test_fmp_session_pair(&local, &peer, [0x01; 8], [0x02; 8]);
    let their_index = SessionIndex::new(0xA0B0_C0D0);
    let flags = FLAG_SP | FLAG_CE;
    let payload_len = 32;

    let reservation = reserve_fmp_worker_send(&mut sender, their_index, flags, payload_len)
        .expect("counter reservation should succeed")
        .expect("established session should expose a send cipher");

    assert_eq!(reservation.counter, 0);
    assert_eq!(
        sender.current_send_counter(),
        1,
        "reservation is the only session mutation before worker dispatch"
    );
    assert_eq!(
        reservation.header,
        build_established_header(their_index, reservation.counter, flags, payload_len)
    );

    let plaintext = vec![0x5A; payload_len as usize];
    let mut ciphertext = plaintext.clone();
    reservation
        .cipher
        .seal_in_place_append_tag(
            crate::noise::CipherState::counter_to_nonce(reservation.counter),
            ring::aead::Aad::from(&reservation.header),
            &mut ciphertext,
        )
        .expect("worker-style FMP seal should succeed");
    assert_eq!(
        sender.current_send_counter(),
        1,
        "worker cipher use must not mutate the owning session"
    );
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                &ciphertext,
                reservation.counter,
                &reservation.header,
            )
            .expect("receiver should accept worker-sealed packet"),
        plaintext
    );
}

#[cfg(unix)]
#[tokio::test]
async fn fmp_worker_target_fallback_consumes_one_inline_counter() {
    let mut node = make_node();
    node.encrypt_workers = Some(crate::node::encrypt_worker::EncryptWorkerPool::spawn(1));

    let transport_id = TransportId::new(77);
    let link_id = LinkId::new(88);
    let (packet_tx, _packet_rx) = packet_channel(8);
    let udp = UdpTransport::new(
        transport_id,
        None,
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let remote_addr = TransportAddr::from_string("127.0.0.1:9");
    let peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        SessionIndex::new(11),
        SessionIndex::new(12),
    );
    node.peers.insert(peer_addr, peer);

    node.send_encrypted_link_message_with_ce(&peer_addr, b"fallback-inline", false)
        .await
        .expect_err("unstarted UDP transport should fail after inline encryption");

    let session = node
        .peers
        .get(&peer_addr)
        .and_then(|peer| peer.noise_session())
        .expect("peer should keep its session");
    assert_eq!(
        session.current_send_counter(),
        1,
        "worker-target fallback must not consume a worker counter before inline encryption"
    );
}
