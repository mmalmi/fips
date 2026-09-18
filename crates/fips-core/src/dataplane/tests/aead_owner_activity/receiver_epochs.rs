mod receiver_epochs {
    use super::*;
    use std::time::{Duration, Instant};

    fn owner() -> OwnerState {
        OwnerState::new(
            fsp_owner(131),
            OwnerConfig::new(1, 8)
                .with_fsp_session_start_ms(1_000)
                .with_fsp_epoch(false, None)
                .with_fsp_mmp(crate::config::SessionMmpConfig::default(), false),
        )
    }

    fn receive(state: &mut OwnerState, key: bool, counter: u64, now: Instant) {
        let sync = FspReceiveSync {
            counter,
            received_k_bit: key,
            timestamp: counter as u32 + 1,
            plaintext_len: 32,
            ce_flag: false,
            path_mtu: 1280,
            spin_bit: false,
        };
        assert!(
            state
                .record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
                    state.owner.node_addr(),
                    state.owner.node_addr(),
                    crate::protocol::SessionMessageType::EndpointData.to_byte(),
                    26,
                    sync,
                    Some(ActivityTick::new(2_000 + counter)),
                    now,
                ),)
                .is_some()
        );
    }

    fn pending(state: &mut OwnerState, key: u8) -> crate::noise::SendCounterAuthority {
        let authority = crate::noise::SendCounterAuthority::for_test();
        assert!(state.install_fsp_pending_epoch(
            true,
            test_key(key),
            test_key(key),
            authority.clone(),
        ));
        authority
    }

    fn report(
        state: &mut OwnerState,
        now: Instant,
    ) -> Option<crate::protocol::SessionReceiverReport> {
        let mut batch = DataplaneFspMmpReportBatch::default();
        state.collect_fsp_mmp_reports(now, &mut batch);
        batch
            .reports
            .into_iter()
            .find(|report| {
                report.msg_type == crate::protocol::SessionMessageType::ReceiverReport.to_byte()
            })
            .map(|report| crate::protocol::SessionReceiverReport::decode(&report.encoded).unwrap())
    }

    #[test]
    fn fsp_receiver_metrics_follow_pending_promotion_without_old_epoch_contamination() {
        let mut state = owner();
        let now = Instant::now();
        receive(&mut state, false, 89, now);
        assert_eq!(
            report(&mut state, now + Duration::from_secs(2))
                .unwrap()
                .highest_counter,
            89
        );

        let authority = pending(&mut state, 132);
        receive(&mut state, true, 0, now + Duration::from_secs(3));
        receive(&mut state, false, 90, now + Duration::from_secs(3));
        receive(&mut state, true, 1, now + Duration::from_secs(3));
        assert!(
            report(&mut state, now + Duration::from_secs(4)).is_none(),
            "pending-key counters cannot be reported under the old sending key"
        );
        assert!(
            state.install_fsp_session(
                OwnerConfig::new(2, 8)
                    .with_send_counter_authority(authority)
                    .with_fsp_session_start_ms(4_000)
                    .with_fsp_epoch(true, Some(false)),
                OwnerCryptoKeys::new(test_key(132), test_key(132)),
            )
        );
        let first = report(&mut state, now + Duration::from_secs(5)).unwrap();
        assert_eq!((first.highest_counter, first.timestamp_echo), (1, 2));
        assert_eq!(
            (first.cumulative_packets_recv, first.interval_packets_recv),
            (3, 2)
        );
        assert_eq!(
            (first.cumulative_reorder_count, first.burst_loss_count),
            (0, 0)
        );

        receive(&mut state, false, 91, now + Duration::from_secs(6));
        assert!(
            report(&mut state, now + Duration::from_secs(7)).is_none(),
            "draining application delivery must not schedule a current-epoch report"
        );
        receive(&mut state, true, 2, now + Duration::from_secs(8));
        let next = report(&mut state, now + Duration::from_secs(9)).unwrap();
        assert_eq!((next.highest_counter, next.timestamp_echo), (2, 3));
        assert_eq!(
            (next.cumulative_packets_recv, next.interval_packets_recv),
            (4, 1)
        );
        assert_eq!(
            (next.cumulative_reorder_count, next.burst_loss_count),
            (0, 0)
        );
        assert_eq!(
            state.data_packets_recv, 6,
            "old and pending authenticated application packets remain delivered/accounted"
        );
        let mut quality = crate::mmp::MmpMetrics::new();
        quality.process_receiver_report(&crate::mmp::ReceiverReport::from(&first), 100, now);
        quality.process_receiver_report(
            &crate::mmp::ReceiverReport::from(&next),
            200,
            now + Duration::from_secs(1),
        );
        assert_eq!(
            quality.last_forward_loss_sample(),
            Some((1, 0.0)),
            "new-key progress must not wait to overtake the old key's high counter"
        );
    }

    #[test]
    fn fsp_receiver_pending_replacement_and_cancellation_reset_selected_metrics() {
        for cancel in [false, true] {
            let mut state = owner();
            let now = Instant::now();
            receive(&mut state, false, 89, now);
            pending(&mut state, 132);
            receive(&mut state, true, 50, now);
            if cancel {
                assert!(state.clear_fsp_pending_receive_epoch());
                receive(&mut state, false, 90, now);
                let current = report(&mut state, now + Duration::from_secs(2)).unwrap();
                assert_eq!((current.highest_counter, current.timestamp_echo), (90, 91));
                assert_eq!(
                    (
                        current.interval_packets_recv,
                        current.cumulative_reorder_count
                    ),
                    (1, 0)
                );
            }
            let authority = pending(&mut state, 133);
            receive(&mut state, true, 0, now + Duration::from_secs(3));
            assert!(
                state.install_fsp_session(
                    OwnerConfig::new(2, 8)
                        .with_send_counter_authority(authority)
                        .with_fsp_session_start_ms(4_000)
                        .with_fsp_epoch(true, Some(false)),
                    OwnerCryptoKeys::new(test_key(133), test_key(133)),
                )
            );
            let replaced = report(&mut state, now + Duration::from_secs(4)).unwrap();
            assert_eq!((replaced.highest_counter, replaced.timestamp_echo), (0, 1));
            assert_eq!(
                (
                    replaced.interval_packets_recv,
                    replaced.cumulative_reorder_count
                ),
                (1, 0)
            );
        }
    }

    #[test]
    fn fsp_receiver_current_epoch_metrics_keep_ordinary_reordering() {
        let mut state = owner();
        let now = Instant::now();
        for counter in [0, 2, 1] {
            receive(&mut state, false, counter, now);
        }
        let current = report(&mut state, now + Duration::from_secs(2)).unwrap();
        assert_eq!(
            (current.highest_counter, current.cumulative_packets_recv),
            (2, 3)
        );
        assert_eq!(
            (
                current.interval_packets_recv,
                current.cumulative_reorder_count
            ),
            (3, 1)
        );
        assert_eq!(state.data_packets_recv, 3);
    }
}
