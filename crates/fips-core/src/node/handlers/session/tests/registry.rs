    use super::*;
    use crate::Identity;
    use crate::noise::{NoiseError, NoiseSession};

    fn node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_xk_session_pair(
        initiator: &Identity,
        responder: &Identity,
    ) -> (NoiseSession, NoiseSession) {
        let mut initiator_hs =
            HandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
        let mut responder_hs = HandshakeState::new_xk_responder(responder.keypair());
        initiator_hs.set_local_epoch([1u8; 8]);
        responder_hs.set_local_epoch([2u8; 8]);

        let msg1 = initiator_hs.write_xk_message_1().unwrap();
        responder_hs.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder_hs.write_xk_message_2().unwrap();
        initiator_hs.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator_hs.write_xk_message_3().unwrap();
        responder_hs.read_xk_message_3(&msg3).unwrap();

        (
            initiator_hs.into_session().unwrap(),
            responder_hs.into_session().unwrap(),
        )
    }

    fn make_xk_session(initiator: &Identity, responder: &Identity) -> NoiseSession {
        make_xk_session_pair(initiator, responder).0
    }

    fn encrypt_frame(session: &mut NoiseSession, plaintext: &[u8], aad: &[u8]) -> (u64, Vec<u8>) {
        let counter = session.current_send_counter();
        let ciphertext = session.encrypt_with_aad(plaintext, aad).unwrap();
        (counter, ciphertext)
    }

    fn decrypt_current(
        entry: &mut SessionEntry,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        match entry.state_mut() {
            EndToEndState::Established(session) => {
                session.decrypt_with_replay_check_and_aad(ciphertext, counter, aad)
            }
            _ => unreachable!("test entry is established"),
        }
    }

    fn established_entry(local: &Identity, peer: &Identity) -> SessionEntry {
        let session = make_xk_session(local, peer);
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(session),
            1000,
            true,
        )
    }

    fn initiating_entry(local: &Identity, peer: &Identity) -> SessionEntry {
        let mut handshake = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        handshake.set_local_epoch([1u8; 8]);
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
        )
    }

    fn receiver_report(
        highest_counter: u64,
        cumulative_packets_recv: u64,
        cumulative_bytes_recv: u64,
        timestamp_echo: u32,
    ) -> ReceiverReport {
        ReceiverReport {
            highest_counter,
            cumulative_packets_recv,
            cumulative_bytes_recv,
            timestamp_echo,
            dwell_time: 0,
            max_burst_loss: 0,
            mean_burst_loss: 0,
            jitter: 0,
            ecn_ce_count: 0,
            owd_trend: 0,
            burst_loss_count: 0,
            cumulative_reorder_count: 0,
            interval_packets_recv: 0,
            interval_bytes_recv: 0,
        }
    }

    #[test]
    fn session_registry_owns_session_receiver_report_processing() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());
        entry.record_outbound_next_hop(peer_addr);
        entry.mmp_mut().expect("session mmp").receiver.record_recv(
            40,
            10,
            1200,
            false,
            std::time::Instant::now(),
        );

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let now = std::time::Instant::now();
        let baseline = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(100, 100, 10_000, 50),
                1_100,
                now,
            )
            .expect("baseline report should process");

        assert_eq!(baseline.sample, None);
        assert!(baseline.used_direct_next_hop);
        assert_eq!(baseline.srtt_ms, Some(50.0));
        assert!(baseline.route_quality_sample);

        let lossy = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(300, 290, 29_000, 100),
                1_200,
                now + std::time::Duration::from_secs(1),
            )
            .expect("lossy report should process");
        let (span, loss) = lossy.sample.expect("second report should sample loss");
        assert_eq!(span, 200);
        assert!(
            (loss - 0.05).abs() < 0.01,
            "loss={loss}, expected roughly 5%"
        );

        let mmp = sessions
            .get(&peer_addr)
            .and_then(|entry| entry.mmp())
            .expect("session mmp");
        assert!(mmp.metrics.srtt_ms().is_some());
        assert_eq!(
            mmp.sender.report_interval(),
            std::time::Duration::from_millis(MIN_SESSION_REPORT_INTERVAL_MS)
        );
        assert_eq!(
            mmp.receiver.report_interval(),
            std::time::Duration::from_millis(MIN_SESSION_REPORT_INTERVAL_MS)
        );
    }

    #[test]
    fn session_receiver_report_loss_accumulates_for_low_rate_route_quality() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());
        entry.record_outbound_next_hop(peer_addr);

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let now = std::time::Instant::now();
        let baseline = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(100, 100, 10_000, 50),
                1_100,
                now,
            )
            .expect("baseline report should process");
        assert_eq!(baseline.sample, None);

        for (i, (highest, received)) in [(104, 103), (108, 106), (112, 109)]
            .into_iter()
            .enumerate()
        {
            let sample = sessions
                .process_session_receiver_report(
                    &peer_addr,
                    &receiver_report(highest, received, received * 100, 100),
                    1_200 + i as u64,
                    now + std::time::Duration::from_millis(500 + i as u64),
                )
                .expect("low-rate report should process")
                .sample;
            assert_eq!(sample, None, "tiny report {i} should accumulate only");
        }

        let accumulated = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(116, 112, 11_200, 100),
                1_300,
                now + std::time::Duration::from_secs(2),
            )
            .expect("fourth low-rate report should process");

        let (span, loss) = accumulated
            .sample
            .expect("low-rate samples should accumulate into route evidence");
        assert_eq!(span, SESSION_DIRECT_DEGRADED_MIN_SAMPLE);
        assert!(
            (loss - 0.25).abs() < 0.01,
            "loss={loss}, expected roughly 25%"
        );
        assert!(accumulated.used_direct_next_hop);
        assert!(accumulated.route_quality_sample);
    }

    #[test]
    fn session_receiver_report_missing_route_metadata_still_flags_direct_quality() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let now = std::time::Instant::now();
        let baseline = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(100, 100, 10_000, 50),
                1_100,
                now,
            )
            .expect("baseline report should process");

        assert!(
            baseline.used_direct_next_hop,
            "missing route metadata must not hide direct-path samples"
        );
        assert!(baseline.route_quality_sample);

        let lossy = sessions
            .process_session_receiver_report(
                &peer_addr,
                &receiver_report(300, 260, 26_000, 100),
                1_200,
                now + std::time::Duration::from_secs(1),
            )
            .expect("lossy report should process");

        assert!(lossy.used_direct_next_hop);
        let (span, loss) = lossy.sample.expect("loss sample");
        assert_eq!(span, 200);
        assert!(
            (loss - 0.20).abs() < 0.01,
            "loss={loss}, expected roughly 20%"
        );
    }

    #[test]
    fn session_registry_session_receiver_report_processing_reports_skip_reasons() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();
        let rr = receiver_report(100, 100, 10_000, 50);

        assert_eq!(
            sessions.process_session_receiver_report(
                &peer_addr,
                &rr,
                1_100,
                std::time::Instant::now()
            ),
            Err(SessionReceiverReportSkip::UnknownSession)
        );

        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        assert!(sessions.insert(peer_addr, entry).is_none());

        assert_eq!(
            sessions.process_session_receiver_report(
                &peer_addr,
                &rr,
                1_100,
                std::time::Instant::now()
            ),
            Err(SessionReceiverReportSkip::MmpDisabled)
        );
    }

    #[test]
    fn session_registry_owns_session_path_mtu_signal_application() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut entry = established_entry(&local, &peer);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let now = std::time::Instant::now();
        assert_eq!(
            sessions.apply_session_path_mtu_signal(&peer_addr, 1280, now),
            Ok(SessionPathMtuApplyResult::Changed(SessionPathMtuChange {
                old_mtu: u16::MAX,
                new_mtu: 1280
            }))
        );
        assert_eq!(
            sessions
                .get(&peer_addr)
                .and_then(|entry| entry.mmp())
                .expect("session mmp")
                .path_mtu
                .current_mtu(),
            1280
        );

        assert_eq!(
            sessions.apply_session_path_mtu_signal(
                &peer_addr,
                1400,
                now + std::time::Duration::from_secs(1)
            ),
            Ok(SessionPathMtuApplyResult::Unchanged),
            "a single larger PMTU signal must not loosen the source-side MTU"
        );
    }

    #[test]
    fn session_registry_session_path_mtu_signal_reports_skip_reasons() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();
        let now = std::time::Instant::now();

        assert_eq!(
            sessions.apply_session_path_mtu_signal(&peer_addr, 1280, now),
            Err(SessionPathMtuApplySkip::UnknownSession)
        );

        assert!(
            sessions
                .insert(peer_addr, established_entry(&local, &peer))
                .is_none()
        );
        assert_eq!(
            sessions.apply_session_path_mtu_signal(&peer_addr, 1280, now),
            Err(SessionPathMtuApplySkip::MmpDisabled)
        );
    }

    #[test]
    fn session_registry_owns_route_error_coords_warmup_policy() {
        let local = Identity::generate();
        let established_peer = Identity::generate();
        let initiating_peer = Identity::generate();
        let established_addr = *established_peer.node_addr();
        let initiating_addr = *initiating_peer.node_addr();
        let missing_addr = node_addr(0x99);
        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(
                    established_addr,
                    established_entry(&local, &established_peer)
                )
                .is_none()
        );
        assert!(
            sessions
                .insert(initiating_addr, initiating_entry(&local, &initiating_peer))
                .is_none()
        );

        assert!(sessions.route_error_can_send_coords_warmup(&established_addr));
        assert!(!sessions.route_error_can_send_coords_warmup(&initiating_addr));
        assert!(!sessions.route_error_can_send_coords_warmup(&missing_addr));

        assert!(sessions.reset_route_error_coords_warmup(&established_addr, 3));
        assert!(sessions.reset_route_error_coords_warmup(&initiating_addr, 2));
        assert!(!sessions.reset_route_error_coords_warmup(&missing_addr, 1));
        assert_eq!(
            sessions
                .get(&established_addr)
                .expect("established session")
                .coords_warmup_remaining(),
            3
        );
        assert_eq!(
            sessions
                .get(&initiating_addr)
                .expect("initiating session")
                .coords_warmup_remaining(),
            2
        );
    }

    #[test]
    fn session_registry_owns_fsp_send_context_and_coords_warmup_consumption() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let now_ms = 0x0102_0304_0506_0708;
        let mut entry = established_entry(&local, &peer);
        let expected_timestamp = entry.session_timestamp(now_ms);
        entry.set_coords_warmup_remaining(2);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let context = sessions
            .session_fsp_send_context(&peer_addr, now_ms)
            .expect("established context");
        assert_eq!(context.timestamp, expected_timestamp);
        assert!(context.wants_coords());
        assert_eq!(
            context.inner_flags_byte(),
            FspInnerFlags { spin_bit: false }.to_byte()
        );
        assert_eq!(context.fsp_flags(false), 0);
        assert_eq!(context.fsp_flags(true), FSP_FLAG_CP);

        assert!(sessions.consume_coords_warmup_packet(&peer_addr));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .expect("session")
                .coords_warmup_remaining(),
            1
        );
        assert!(sessions.consume_coords_warmup_packet(&peer_addr));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .expect("session")
                .coords_warmup_remaining(),
            0
        );
        assert!(!sessions.consume_coords_warmup_packet(&peer_addr));
    }

    #[test]
    fn session_registry_fsp_send_context_reports_skip_reasons() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();

        assert_eq!(
            sessions.session_fsp_send_context(&peer_addr, 123),
            Err(SessionFspSendContextError::NoSession)
        );

        assert!(
            sessions
                .insert(peer_addr, initiating_entry(&local, &peer))
                .is_none()
        );
        assert_eq!(
            sessions.session_fsp_send_context(&peer_addr, 123),
            Err(SessionFspSendContextError::NotEstablished)
        );

        let inner_plaintext =
            fsp_prepend_inner_header(123, SessionMessageType::EndpointData.to_byte(), 0, b"hello");
        let plan = SessionFspSendPlan::new(
            peer_addr,
            123,
            0,
            &inner_plaintext,
            None,
            SessionFspSendBookkeeping::Control,
        );
        let error = match sessions.seal_session_fsp_send(plan) {
            Ok(_) => panic!("initiating session must not seal established FSP data"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                NodeError::SendFailed { node_addr, ref reason }
                    if node_addr == peer_addr && reason == "session not established"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn session_registry_owns_fsp_sealing_and_datagram_bookkeeping() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let next_hop = node_addr(0x55);
        let mut entry = established_entry(&local, &peer);
        entry.init_mmp(&crate::config::SessionMmpConfig::default());
        let counter_before = entry.send_counter();

        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(peer_addr, entry).is_none());

        let inner_plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            b"hello",
        );
        let plan = SessionFspSendPlan::new(
            peer_addr,
            0x0102_0304,
            FSP_FLAG_K,
            &inner_plaintext,
            None,
            SessionFspSendBookkeeping::Data {
                payload_len: 5,
                now_ms: 0x5566_7788,
            },
        );

        let sealed = sessions
            .seal_session_fsp_send(plan)
            .expect("established session should seal");
        assert_eq!(sealed.dest_addr(), peer_addr);
        assert_eq!(sealed.counter(), counter_before);
        assert_eq!(
            sessions.get(&peer_addr).expect("session").send_counter(),
            counter_before + 1
        );

        let (_datagram, bookkeeping) = sealed.into_datagram(node_addr(0xaa), 7);
        assert_eq!(
            bookkeeping,
            FspSendBookkeepingInput::data(
                5,
                counter_before,
                0x0102_0304,
                inner_plaintext.len() + crate::noise::TAG_SIZE,
                0x5566_7788,
            )
        );

        assert!(sessions.seed_session_datagram_path_mtu(&peer_addr, 1280));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .and_then(|entry| entry.mmp())
                .expect("session mmp")
                .path_mtu
                .current_mtu(),
            1280
        );
        assert!(sessions.record_session_datagram_next_hop(&peer_addr, next_hop));
        assert_eq!(
            sessions
                .get(&peer_addr)
                .expect("session")
                .last_outbound_next_hop(),
            Some(next_hop)
        );
        assert!(!sessions.seed_session_datagram_path_mtu(&node_addr(0x77), 1280));
        assert!(!sessions.record_session_datagram_next_hop(&node_addr(0x77), next_hop));
    }

    #[test]
    fn session_registry_owns_outbound_session_state_and_tun_pmtu_guard() {
        let local = Identity::generate();
        let established_peer = Identity::generate();
        let initiating_peer = Identity::generate();
        let established_addr = *established_peer.node_addr();
        let initiating_addr = *initiating_peer.node_addr();
        let missing_addr = node_addr(0x99);
        let mut established = established_entry(&local, &established_peer);
        established.init_mmp(&crate::config::SessionMmpConfig::default());
        let mut sessions = crate::node::SessionRegistry::default();
        assert!(sessions.insert(established_addr, established).is_none());
        assert!(
            sessions
                .insert(initiating_addr, initiating_entry(&local, &initiating_peer))
                .is_none()
        );

        assert_eq!(
            sessions.outbound_session_state(&established_addr),
            OutboundSessionState::Established
        );
        assert_eq!(
            sessions.outbound_session_state(&initiating_addr),
            OutboundSessionState::Pending
        );
        assert_eq!(
            sessions.outbound_session_state(&missing_addr),
            OutboundSessionState::Missing
        );
        assert!(sessions.should_skip_session_initiation(&established_addr));
        assert!(sessions.should_skip_session_initiation(&initiating_addr));
        assert!(!sessions.should_skip_session_initiation(&missing_addr));

        assert_eq!(
            sessions.tun_outbound_session_decision(&established_addr, 1500, 1280),
            TunOutboundSessionDecision::Established
        );

        let path_mtu = 1280;
        assert!(sessions.seed_session_datagram_path_mtu(&established_addr, path_mtu));
        let path_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as usize;
        assert_eq!(
            sessions.tun_outbound_session_decision(&established_addr, 1500, path_ipv6_mtu + 1),
            TunOutboundSessionDecision::EstablishedPathMtuExceeded {
                path_ipv6_mtu: path_ipv6_mtu as u32
            }
        );
        assert_eq!(
            sessions.tun_outbound_session_decision(&established_addr, 1500, path_ipv6_mtu),
            TunOutboundSessionDecision::Established
        );
        assert_eq!(
            sessions.tun_outbound_session_decision(&initiating_addr, 1500, 1280),
            TunOutboundSessionDecision::Pending
        );
        assert_eq!(
            sessions.tun_outbound_session_decision(&missing_addr, 1500, 1280),
            TunOutboundSessionDecision::Missing
        );
    }

    #[test]
    fn session_registry_owns_discovery_retry_restart_policy() {
        let local = Identity::generate();
        let established_peer = Identity::generate();
        let initiating_peer = Identity::generate();
        let established_addr = *established_peer.node_addr();
        let initiating_addr = *initiating_peer.node_addr();
        let missing_addr = node_addr(0x88);
        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(
                    established_addr,
                    established_entry(&local, &established_peer)
                )
                .is_none()
        );
        assert!(
            sessions
                .insert(initiating_addr, initiating_entry(&local, &initiating_peer))
                .is_none()
        );

        assert_eq!(
            sessions.prepare_retry_session_after_discovery(&established_addr),
            DiscoveryRetrySessionDecision::Established
        );
        assert!(
            sessions.get(&established_addr).is_some(),
            "established sessions must remain intact"
        );
        assert_eq!(
            sessions.prepare_retry_session_after_discovery(&initiating_addr),
            DiscoveryRetrySessionDecision::RestartedPending
        );
        assert!(
            sessions.get(&initiating_addr).is_none(),
            "pending setup should be removed so it can be rebuilt with fresh coords"
        );
        assert_eq!(
            sessions.prepare_retry_session_after_discovery(&missing_addr),
            DiscoveryRetrySessionDecision::Missing
        );
    }

    #[test]
    fn session_registry_owns_handshake_session_installation() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();
        let mmp_config = crate::config::SessionMmpConfig::default();

        let mut initiating_handshake =
            HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        initiating_handshake.set_local_epoch([1u8; 8]);
        assert!(
            sessions
                .install_initiating_session(
                    peer_addr,
                    peer.pubkey_full(),
                    initiating_handshake,
                    vec![0x11, 0x22],
                    1_000,
                    250,
                )
                .is_none()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("initiating session should be installed");
        assert!(entry.is_initiating());
        assert!(entry.is_initiator());
        assert_eq!(entry.handshake_payload(), Some([0x11, 0x22].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 1_250);

        let mut awaiting_handshake = HandshakeState::new_xk_responder(local.keypair());
        awaiting_handshake.set_local_epoch([2u8; 8]);
        assert!(
            sessions
                .install_awaiting_msg3_session(
                    peer_addr,
                    local.pubkey_full(),
                    awaiting_handshake,
                    vec![0x33],
                    2_000,
                    500,
                )
                .is_some(),
            "awaiting-msg3 install replaces the old initiating entry"
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("awaiting-msg3 session should be installed");
        assert!(entry.is_awaiting_msg3());
        assert!(!entry.is_initiator());
        assert_eq!(entry.handshake_payload(), Some([0x33].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 2_500);

        let (initiator_session, _) = make_xk_session_pair(&local, &peer);
        let mut entry = initiating_entry(&local, &peer);
        let _ = entry.take_state();
        assert!(
            sessions
                .install_established_initiator_session(
                    peer_addr,
                    entry,
                    initiator_session,
                    vec![0x44, 0x55],
                    3_000,
                    750,
                    3,
                    &mmp_config,
                )
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("established initiator session should be installed");
        assert!(entry.is_established());
        assert!(entry.is_initiator());
        assert_eq!(entry.coords_warmup_remaining(), 3);
        assert_eq!(entry.session_start_ms(), 3_000);
        assert_eq!(entry.last_activity(), 3_000);
        assert!(entry.mmp().is_some());
        assert_eq!(entry.handshake_payload(), Some([0x44, 0x55].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 3_750);

        let (_, responder_session) = make_xk_session_pair(&peer, &local);
        assert!(
            sessions
                .install_established_responder_session(
                    peer_addr,
                    peer.pubkey_full(),
                    responder_session,
                    4_000,
                    2,
                    &mmp_config,
                )
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("established responder session should be installed");
        assert!(entry.is_established());
        assert!(!entry.is_initiator());
        assert_eq!(entry.coords_warmup_remaining(), 2);
        assert_eq!(entry.session_start_ms(), 4_000);
        assert_eq!(entry.last_activity(), 4_000);
        assert!(entry.mmp().is_some());
        assert_eq!(*entry.remote_pubkey(), peer.pubkey_full());
        assert_eq!(entry.handshake_payload(), None);
    }

    #[test]
    fn session_registry_owns_rekey_session_installation_and_abandon() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();

        assert!(
            sessions
                .insert(peer_addr, established_entry(&local, &peer))
                .is_none()
        );
        let mut rekey_handshake = HandshakeState::new_xk_responder(local.keypair());
        rekey_handshake.set_local_epoch([3u8; 8]);
        assert!(sessions.install_rekey_responder_awaiting_msg3(
            &peer_addr,
            rekey_handshake,
            vec![0xaa],
            5_000,
            125,
        ));
        let entry = sessions
            .get(&peer_addr)
            .expect("rekey awaiting-msg3 state should remain installed");
        assert!(entry.has_rekey_in_progress());
        assert!(!entry.is_rekey_initiator());
        assert_eq!(entry.handshake_payload(), Some([0xaa].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 5_125);
        assert!(entry.is_rekey_dampened(5_100, 500));

        assert!(sessions.abandon_rekey(&peer_addr));
        let entry = sessions
            .get(&peer_addr)
            .expect("session should remain after abandon");
        assert!(!entry.has_rekey_in_progress());
        assert!(entry.pending_new_session().is_none());
        assert_eq!(entry.handshake_payload(), None);

        let (pending_session, _) = make_xk_session_pair(&local, &peer);
        let mut entry = established_entry(&local, &peer);
        entry.set_handshake_payload(vec![0xbb], 6_050);
        assert!(
            sessions
                .install_rekey_initiator_pending_session(
                    peer_addr,
                    entry,
                    pending_session,
                    vec![0xcc, 0xdd],
                    6_000,
                    250,
                )
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("initiator pending rekey should be installed");
        assert!(entry.pending_new_session().is_some());
        assert_eq!(entry.rekey_completed_ms(), 6_000);
        assert_eq!(entry.handshake_payload(), None);
        assert_eq!(entry.rekey_msg3_payload(), Some([0xcc, 0xdd].as_slice()));
        assert_eq!(entry.rekey_msg3_next_resend_ms(), 6_250);

        let (_, pending_session) = make_xk_session_pair(&peer, &local);
        let mut entry = established_entry(&local, &peer);
        entry.set_handshake_payload(vec![0xee], 7_050);
        assert!(
            sessions
                .install_rekey_responder_pending_session(peer_addr, entry, pending_session)
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("responder pending rekey should be installed");
        assert!(entry.pending_new_session().is_some());
        assert_eq!(entry.handshake_payload(), None);
        assert_eq!(entry.rekey_msg3_payload(), None);
    }
