use super::*;
use crate::node::{ForwardingOutcome, OriginatedSessionAdmission};
use std::sync::{
    Mutex,
    atomic::{AtomicU8, Ordering},
};

#[derive(Debug, Default)]
struct Policy {
    mode: AtomicU8,
    intents: Mutex<Vec<(NodeAddr, usize)>>,
    completions: Mutex<Vec<(u64, ForwardingOutcome)>>,
}
impl OriginatedSessionObserver for Policy {
    fn prepare(&self, intent: &OriginatedSessionIntent) -> OriginatedSessionAdmission {
        self.intents
            .lock()
            .unwrap()
            .push((intent.next_hop, intent.session_bytes));
        match self.mode.load(Ordering::Relaxed) {
            0 => OriginatedSessionAdmission::Reject,
            1 => OriginatedSessionAdmission::Track(77),
            2 => OriginatedSessionAdmission::Untracked,
            4 => OriginatedSessionAdmission::Retry,
            _ => OriginatedSessionAdmission::Defer,
        }
    }
    fn observe(&self, _: &OriginatedSessionRequest<'_>) -> Option<u64> {
        Some(88)
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.completions.lock().unwrap().push((token, outcome));
    }
}

fn packet(owner: OwnerId) -> OutboundPacket {
    OutboundPacket::fsp(
        owner,
        1,
        PacketClass::Bulk,
        0,
        PacketBuffer::new(vec![7; 100]),
    )
    .with_fsp_inner_header(
        crate::protocol::SessionMessageType::EndpointData.to_byte(),
        0,
    )
    .with_activity_tick(ActivityTick::new(100))
}

#[test]
fn denial_precedes_sequence_metrics_and_coords_for_scalar_and_batch() {
    let owner = fsp_owner(960);
    let next = fmp_owner(961);
    let source = test_node_addr(959);
    let policy = Arc::new(Policy::default());
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.originated_session_observer = Some(policy.clone());
    driver.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_next_send_counter(7)
            .with_fsp_session_start_ms(0)
            .with_fsp_coords_warmup(2, empty_fsp_coords_prefix()),
    );
    driver
        .owner_mut(owner)
        .unwrap()
        .set_fsp_wrap_route(Some(DataplaneFspWrapRoute::new(
            next,
            1,
            961,
            source,
            owner.node_addr(),
        )));
    let mut summary = DataplaneRuntimeSummary::default();
    driver.admit_outbound_packet(packet(owner), &mut summary);
    driver.admit_outbound_packet_batch(vec![packet(owner), packet(owner)], &mut summary);
    assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
    let drops = driver.mover.drain_drops();
    assert_eq!(drops.len(), 3);
    assert!(
        drops
            .iter()
            .all(|d| d.reason() == PacketDropReason::SourcePolicy && d.counter.is_none())
    );
    let state = driver.owner_mut(owner).unwrap();
    assert_eq!(state.fsp_activity().unwrap().traffic_counters().0, 0);
    assert_eq!(state.last_tx_activity(), None);
    assert_eq!(state.fsp_coords_warmup_remaining(), 2);

    policy.mode.store(1, Ordering::Relaxed);
    driver.admit_outbound_packet(packet(owner), &mut summary);
    let work = dispatch_outbound_available(&mut driver.mover, 8)
        .pop()
        .unwrap();
    assert_eq!(
        work.reservation.counter, 7,
        "denied sends leave no sequence gaps"
    );
    assert_eq!(
        driver
            .owner_mut(owner)
            .unwrap()
            .fsp_coords_warmup_remaining(),
        1
    );
    let CryptoResult::Outbound(mut wrapped) =
        execute_seal_crypto_work(work.packet, &work.reservation, &test_cipher(7))
    else {
        panic!("established session record must seal and wrap");
    };
    let envelope =
        crate::protocol::SessionDatagramRef::decode(&wrapped.payload.as_slice()[1..]).unwrap();
    assert!(
        policy
            .intents
            .lock()
            .unwrap()
            .iter()
            .all(|(hop, bytes)| *hop == next.node_addr() && *bytes == envelope.payload.len())
    );
    // The FMP stage cannot reserve/observe the same envelope a second time.
    driver.observe_originated_outbound(&mut wrapped);
    let observation = wrapped.originated_observation.clone().unwrap();
    observation.submitted();
    observation.submitted();
    drop(observation);
    drop(wrapped);
    assert_eq!(
        *policy.completions.lock().unwrap(),
        vec![(77, ForwardingOutcome::Submitted)]
    );
}

#[test]
fn accepted_cancellation_is_uncertain_and_free_or_deferred_modes_are_distinct() {
    let owner = fsp_owner(970);
    let next = fmp_owner(971);
    let policy = Arc::new(Policy::default());
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.originated_session_observer = Some(policy.clone());
    driver.register_owner(owner, OwnerConfig::new(1, 8).with_fsp_session_start_ms(0));
    driver
        .owner_mut(owner)
        .unwrap()
        .set_fsp_wrap_route(Some(DataplaneFspWrapRoute::new(
            next,
            1,
            971,
            test_node_addr(969),
            owner.node_addr(),
        )));
    let mut summary = DataplaneRuntimeSummary::default();
    policy.mode.store(1, Ordering::Relaxed);
    driver.admit_outbound_packet(packet(owner), &mut summary);
    drop(dispatch_outbound_available(&mut driver.mover, 8));
    assert_eq!(
        *policy.completions.lock().unwrap(),
        vec![(77, ForwardingOutcome::Unconfirmed)]
    );

    for mode in [2, 3] {
        policy.mode.store(mode, Ordering::Relaxed);
        driver.admit_outbound_packet(packet(owner), &mut summary);
        let work = dispatch_outbound_available(&mut driver.mover, 8)
            .pop()
            .unwrap();
        let CryptoResult::Outbound(mut wrapped) =
            execute_seal_crypto_work(work.packet, &work.reservation, &test_cipher(7))
        else {
            panic!("established session record must seal and wrap");
        };
        driver.observe_originated_outbound(&mut wrapped);
        assert_eq!(wrapped.originated_observation.is_some(), mode == 3);
        if let Some(observation) = &wrapped.originated_observation {
            observation.submitted();
        }
    }
    assert_eq!(
        *policy.completions.lock().unwrap(),
        vec![
            (77, ForwardingOutcome::Unconfirmed),
            (88, ForwardingOutcome::Submitted)
        ]
    );
}

fn waiting_driver(config: AdmissionConfig) -> (DataplaneTurnDriver, Arc<Policy>, OwnerId) {
    let owner = fsp_owner(980);
    let policy = Arc::new(Policy::default());
    policy.mode.store(4, Ordering::Relaxed);
    let mut driver = DataplaneTurnDriver::new(config);
    driver.originated_session_observer = Some(policy.clone());
    driver.register_owner(
        owner,
        OwnerConfig::new(1, config.total_capacity().max(8))
            .with_next_send_counter(7)
            .with_fsp_session_start_ms(0)
            .with_fsp_coords_warmup(2, empty_fsp_coords_prefix()),
    );
    driver
        .owner_mut(owner)
        .unwrap()
        .set_fsp_wrap_route(Some(DataplaneFspWrapRoute::new(
            fmp_owner(981),
            1,
            981,
            test_node_addr(979),
            owner.node_addr(),
        )));
    (driver, policy, owner)
}

#[tokio::test(start_paused = true)]
async fn source_retry_keeps_original_without_sequence_or_accounting_until_resumed() {
    let (mut driver, policy, owner) = waiting_driver(AdmissionConfig::new(4, 2));
    let mut summary = DataplaneRuntimeSummary::default();
    let original = packet(owner);
    let payload_pointer = original.payload.as_slice().as_ptr();
    driver.admit_outbound_packet(original, &mut summary);
    assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
    assert_eq!(driver.mover.outbound_admission_lens.bulk, 1);
    assert!(!driver.mover.has_runnable_work());
    assert_eq!(
        driver.mover.source_wait.delay(),
        Some(SOURCE_ADMISSION_RETRY_DELAY)
    );
    assert!(policy.completions.lock().unwrap().is_empty());
    assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
    assert_eq!(policy.intents.lock().unwrap().len(), 1, "no busy recheck");
    let state = driver.owner_mut(owner).unwrap();
    assert_eq!(state.fsp_activity().unwrap().traffic_counters().0, 0);
    assert_eq!(state.last_tx_activity(), None);
    assert_eq!(state.fsp_coords_warmup_remaining(), 2);

    // Other owners and untracked control work can still reserve crypto.
    let healthy = fsp_owner(982);
    driver.register_owner(healthy, OwnerConfig::new(1, 8));
    let mut healthy_packet = packet(healthy);
    healthy_packet.class = PacketClass::Control;
    driver.admit_outbound_packet(healthy_packet, &mut summary);
    let mut control = packet(owner);
    control.class = PacketClass::Control;
    control.originated_preparation = None;
    driver.mover.submit_outbound_packet(control).unwrap();
    let healthy_work = dispatch_outbound_available(&mut driver.mover, 8);
    assert_eq!(healthy_work.len(), 2);
    assert_eq!(policy.intents.lock().unwrap().len(), 1);
    drop(healthy_work);

    policy.mode.store(1, Ordering::Relaxed);
    tokio::time::advance(SOURCE_ADMISSION_RETRY_DELAY).await;
    let mut works = dispatch_outbound_available(&mut driver.mover, 8);
    assert_eq!(works.len(), 1);
    let work = works.pop().unwrap();
    assert_eq!(work.packet.payload.as_slice().as_ptr(), payload_pointer);
    assert_eq!(
        work.reservation.counter, 8,
        "only admitted control consumed counter 7"
    );
    assert_eq!(
        driver
            .owner_mut(owner)
            .unwrap()
            .fsp_coords_warmup_remaining(),
        0
    );
    assert_eq!(driver.mover.outbound_admission_lens.bulk, 0);
    assert!(driver.mover.source_wait.tracked.is_empty());
    assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
    let observation = work.packet.originated_observation.as_ref().unwrap();
    observation.submitted();
    observation.submitted();
    drop(work);
    assert_eq!(
        *policy.completions.lock().unwrap(),
        vec![(77, ForwardingOutcome::Submitted)]
    );
}

#[tokio::test(start_paused = true)]
async fn source_retry_expires_from_original_queue_age_and_releases_capacity() {
    let (mut driver, policy, owner) = waiting_driver(AdmissionConfig::new(4, 2));
    let healthy = fsp_owner(982);
    driver.register_owner(healthy, OwnerConfig::new(1, 8));
    let mut summary = DataplaneRuntimeSummary::default();
    driver.admit_outbound_packet(packet(owner), &mut summary);
    tokio::time::advance(SOURCE_ADMISSION_MAX_AGE / 2).await;
    assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
    driver
        .mover
        .submit_outbound_packet(packet(healthy))
        .unwrap();
    assert!(driver.mover.submit_outbound_packet(packet(owner)).is_err());
    assert_eq!(
        driver.mover.drain_drops().len(),
        1,
        "ordinary queue capacity still applies"
    );
    tokio::time::advance(SOURCE_ADMISSION_RETRY_DELAY).await;
    let work = dispatch_outbound_available(&mut driver.mover, 8);
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].packet.owner, healthy);
    drop(work);
    assert_eq!(policy.intents.lock().unwrap().len(), 2);
    tokio::time::advance(SOURCE_ADMISSION_MAX_AGE / 2).await;
    assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
    assert_eq!(driver.mover.drain_drops().len(), 1);
    assert!(driver.mover.source_wait.tracked.is_empty());
    assert_eq!(driver.mover.outbound_admission_lens.bulk, 0);
    assert!(driver.mover.source_wait.delay().is_none());
    assert!(policy.completions.lock().unwrap().is_empty());
    policy.mode.store(1, Ordering::Relaxed);
    driver.admit_outbound_packet(packet(owner), &mut summary);
    let work = dispatch_outbound_available(&mut driver.mover, 8)
        .pop()
        .unwrap();
    assert_eq!(work.reservation.counter, 7);
}

#[tokio::test(start_paused = true)]
async fn source_retry_rejection_and_replacement_cancel_parked_or_woken_originals() {
    for action in 0..5 {
        let (mut driver, policy, owner) = waiting_driver(AdmissionConfig::new(4, 2));
        let mut summary = DataplaneRuntimeSummary::default();
        driver.admit_outbound_packet(packet(owner), &mut summary);
        assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
        tokio::time::advance(SOURCE_ADMISSION_RETRY_DELAY).await;
        if action != 0 {
            driver.mover.service_source_admissions();
            assert!(driver.mover.source_wait.packets.is_empty());
            assert_eq!(driver.mover.source_wait.tracked.len(), 1);
        }
        match action {
            0 => {
                policy.mode.store(0, Ordering::Relaxed);
            }
            1 => driver.register_owner(owner, OwnerConfig::new(1, 8)),
            2 => driver.unregister_owner(owner),
            3 => driver.mover.cancel_source_admissions(None),
            _ => tokio::time::advance(SOURCE_ADMISSION_MAX_AGE).await,
        }
        assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
        let drops = driver.mover.drain_drops();
        assert_eq!(drops.len(), 1, "action {action}");
        assert!(drops[0].counter.is_none());
        assert!(driver.mover.source_wait.tracked.is_empty());
        assert_eq!(driver.mover.outbound_admission_lens.bulk, 0);
        assert!(policy.completions.lock().unwrap().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn source_retry_wait_bounds_packets_bytes_and_next_hop_share() {
    let production = AdmissionConfig::new(1024, 4096);
    let mut cases: Vec<(AdmissionConfig, PacketClass, usize, usize)> = vec![
        (production, PacketClass::Control, 512, 256),
        (production, PacketClass::Bulk, 2048, 1024),
        (production, PacketClass::Background, 32, 16),
    ];
    for (capacity, total, peer) in [(0, 0, 0), (1, 0, 0), (2, 1, 1), (3, 1, 1), (8, 4, 2)] {
        for class in [
            PacketClass::Control,
            PacketClass::Bulk,
            PacketClass::Background,
        ] {
            cases.push((AdmissionConfig::new(capacity, capacity), class, total, peer));
        }
    }
    for (config, class, total_packets, peer_packets) in cases {
        for payload_bytes in [100, 4096] {
            let (mut driver, policy, owner) = waiting_driver(config);
            let mut summary = DataplaneRuntimeSummary::default();
            let per_peer = peer_packets.min(SOURCE_ADMISSION_PEER_BYTES / payload_bytes);
            for offset in 0..3 {
                let owner = if offset == 0 {
                    owner
                } else {
                    fsp_owner(990 + offset)
                };
                if offset != 0 {
                    driver.register_owner(owner, OwnerConfig::new(1, 4096));
                    driver.owner_mut(owner).unwrap().set_fsp_wrap_route(Some(
                        DataplaneFspWrapRoute::new(
                            fmp_owner(995 + offset),
                            1,
                            1,
                            test_node_addr(979),
                            owner.node_addr(),
                        ),
                    ));
                }
                let packets = (0..=per_peer)
                    .map(|_| {
                        let mut packet = packet(owner);
                        packet.class = class;
                        packet.payload = PacketBuffer::new(vec![7; payload_bytes]);
                        packet
                    })
                    .collect();
                driver.admit_outbound_packet_batch(packets, &mut summary);
                assert!(dispatch_outbound_available(&mut driver.mover, 4096).is_empty());
                let retained = (per_peer * (offset as usize + 1))
                    .min(total_packets.min(SOURCE_ADMISSION_MAX_BYTES / payload_bytes));
                assert_eq!(
                    driver.mover.source_wait.tracked.len(),
                    retained,
                    "{config:?} {class:?}, payload {payload_bytes}, peer {offset}"
                );
                assert_eq!(
                    driver.mover.outbound_admission_lens.lane(class.lane()),
                    retained
                );
                assert_eq!(driver.mover.source_wait.bytes, retained * payload_bytes);
            }
            // A healthy owner in the same lane still reaches crypto with waits full.
            if config.lane_capacity(class.lane()) > 0 {
                let healthy = fsp_owner(999);
                driver.register_owner(healthy, OwnerConfig::new(1, 8));
                let mut healthy_packet = packet(healthy);
                healthy_packet.class = class;
                driver.admit_outbound_packet(healthy_packet, &mut summary);
                let work = dispatch_outbound_available(&mut driver.mover, 4096);
                assert_eq!(work.len(), 1);
                assert_eq!(work[0].packet.owner, healthy);
                drop(work);
            }
            assert!(policy.completions.lock().unwrap().is_empty());
            driver.mover.cancel_source_admissions(None);
            assert_eq!(driver.mover.source_wait.bytes, 0);
            assert!(driver.mover.source_wait.peers.is_empty());
            assert_eq!(driver.mover.outbound_admission_lens, LaneLens::default());
            // Cancellation returns the wait allowance for a later renewal too.
            let mut next = packet(owner);
            next.class = class;
            driver.admit_outbound_packet(next, &mut summary);
            assert!(dispatch_outbound_available(&mut driver.mover, 4096).is_empty());
            assert_eq!(
                driver.mover.source_wait.tracked.len(),
                usize::from(total_packets > 0)
            );
            driver.mover.cancel_source_admissions(None);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn source_retry_shares_a_peer_without_sharing_lane_allowances() {
    let (mut driver, policy, owner) = waiting_driver(AdmissionConfig::new(8, 8));
    let mut summary = DataplaneRuntimeSummary::default();
    for class in [
        PacketClass::Control,
        PacketClass::Bulk,
        PacketClass::Background,
    ] {
        for _ in 0..3 {
            let mut original = packet(owner);
            original.class = class;
            driver.admit_outbound_packet(original, &mut summary);
        }
        assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
        assert_eq!(driver.mover.outbound_admission_lens.lane(class.lane()), 2);
    }
    assert_eq!(driver.mover.source_wait.tracked.len(), 6);
    assert_eq!(driver.mover.source_wait.peers.len(), 1);
    assert_eq!(driver.mover.drain_drops().len(), 3);
    policy.mode.store(1, Ordering::Relaxed);
    tokio::time::advance(SOURCE_ADMISSION_RETRY_DELAY).await;
    let mut counters = Vec::new();
    // Background admits one in-flight packet per owner. Complete each batch
    // before the next dispatch so all lanes release their peer charges.
    for _ in 0..2 {
        let work = dispatch_outbound_available(&mut driver.mover, 8);
        for work in work {
            counters.push(work.reservation.counter);
            driver
                .mover
                .stage_retire_slot(CryptoReadySlot::completed(complete_test_seal_work(work, 7)));
        }
        driver.retire_ready_aead_outputs(8, false);
    }
    counters.sort_unstable();
    assert_eq!(counters, (7..13).collect::<Vec<_>>());
    assert!(driver.mover.source_wait.tracked.is_empty());
    assert!(driver.mover.source_wait.peers.is_empty());
    assert_eq!(driver.mover.source_wait.bytes, 0);
    assert_eq!(driver.mover.source_wait.counts, LaneLens::default());
    assert_eq!(driver.mover.outbound_admission_lens, LaneLens::default());
}

#[tokio::test(start_paused = true)]
async fn source_retry_policy_replacement_and_shutdown_drop_without_accounting() {
    for replace_policy in [false, true] {
        let (mut driver, policy, owner) = waiting_driver(AdmissionConfig::new(4, 2));
        let mut summary = DataplaneRuntimeSummary::default();
        driver.admit_outbound_packet(packet(owner), &mut summary);
        assert!(dispatch_outbound_available(&mut driver.mover, 8).is_empty());
        let mut live = DataplaneLiveNode::new(AdmissionConfig::new(4, 2));
        live.driver = driver;
        if replace_policy {
            live.set_originated_session_observer(None);
            assert!(live.driver.mover.source_wait.tracked.is_empty());
            assert_eq!(live.driver.mover.outbound_admission_lens.bulk, 0);
            assert_eq!(live.driver.mover.drain_drops().len(), 1);
        }
        drop(live);
        assert!(policy.completions.lock().unwrap().is_empty());
    }
}
