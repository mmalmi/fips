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
