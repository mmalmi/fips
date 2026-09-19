use super::*;

pub(super) fn peer(n: u8) -> NodeAddr {
    *fips_core::Identity::from_secret_bytes(&[n; 32])
        .unwrap()
        .node_addr()
}

#[test]
fn admission_burst_refills_to_its_fixed_cap() {
    let now = Instant::now();
    let mut budget = AdmissionBudget::new(now);
    for _ in 0..ADMISSION_BURST {
        assert!(budget.allow(now));
    }
    assert!(!budget.allow(now));
    assert!(budget.allow(now + ADMISSION_INTERVAL));
    assert!(!budget.allow(now + ADMISSION_INTERVAL));
    assert!(budget.allow(now + Duration::from_secs(10)));
    assert_eq!(budget.tokens, ADMISSION_BURST - 1);
}

#[test]
fn payment_epochs_fit_without_identity_or_direction_bypassing_the_aggregate() {
    let now = Instant::now();
    let mut state = AdmissionState::new(now);
    for epoch in 0..40 {
        let at = now + Duration::from_millis(epoch * 250);
        for n in 1..=16 {
            let id = peer(n);
            for outbound in [false, true] {
                for _ in 0..2 {
                    assert!(state.aggregate.allow(at));
                    assert!(state.admit_peer(id, outbound, at, false));
                    state.release_peer(id);
                }
            }
            assert!(state.aggregate.allow(at));
            assert!(state.admit_peer(id, epoch % 2 == 0, at, false));
            state.release_peer(id);
        }
        // Rotating identities or direction cannot exceed the node budget.
        assert!(!state.aggregate.allow(at));
    }
    assert_eq!(state.peers.len(), 16);
}

#[test]
fn fractional_refill_time_is_retained_for_both_budget_profiles() {
    let now = Instant::now();
    for (burst, interval) in [
        (ADMISSION_BURST, ADMISSION_INTERVAL),
        (AGGREGATE_BURST, AGGREGATE_INTERVAL),
    ] {
        let mut budget = AdmissionBudget::with_limits(now, burst, interval);
        for _ in 0..burst {
            assert!(budget.allow(now));
        }
        assert!(!budget.allow(now + interval / 2));
        assert!(budget.allow(now + interval + interval / 2));
        assert!(!budget.allow(now + interval + interval / 2));
        assert!(budget.allow(now + interval * 2));
        assert!(!budget.allow(now + interval * 2));
    }
}

#[test]
fn a_peer_has_four_shared_slots_and_returning_one_keeps_its_budget() {
    let now = Instant::now();
    let mut state = AdmissionState::new(now);
    let id = peer(1);
    for outbound in [false, true, false, true] {
        assert!(state.admit_peer(id, outbound, now, false));
    }
    for outbound in [false, true] {
        assert!(!state.admit_peer(id, outbound, now, false));
    }
    assert!(state.admit_peer(peer(2), false, now, false));
    state.release_peer(id);
    assert!(state.admit_peer(id, false, now, false));
    assert_eq!(state.peers[&id].active, 4);
    assert_eq!(state.peers[&id].incoming.tokens, ADMISSION_BURST - 3);
    assert_eq!(state.peers[&id].outgoing.tokens, ADMISSION_BURST - 2);
}

#[test]
fn idle_identity_eviction_waits_for_both_budgets_to_fully_refill() {
    let now = Instant::now();
    let mut state = AdmissionState::new(now);
    for n in 1..=UNCONFIGURED_IDENTITIES as u8 {
        for _ in 0..ADMISSION_BURST {
            for outbound in [false, true] {
                assert!(state.admit_peer(peer(n), outbound, now, false));
                state.release_peer(peer(n));
            }
        }
    }
    let extra = peer(65);
    assert!(!state.admit_peer(extra, false, now, false));
    assert!(!state.admit_peer(extra, true, now + ADMISSION_INTERVAL, false));
    assert_eq!(state.peers.len(), UNCONFIGURED_IDENTITIES);
    let refilled = now + ADMISSION_INTERVAL * ADMISSION_BURST;
    assert!(state.admit_peer(extra, false, refilled, false));
    assert_eq!(state.peers.len(), UNCONFIGURED_IDENTITIES);
}

#[test]
fn active_identity_cannot_be_evicted_even_after_its_budget_refills() {
    let now = Instant::now();
    let mut state = AdmissionState::new(now);
    for n in 1..=UNCONFIGURED_IDENTITIES as u8 {
        assert!(state.admit_peer(peer(n), false, now, false));
    }
    let later = now + Duration::from_secs(10);
    assert!(!state.admit_peer(peer(65), false, later, false));
    state.release_peer(peer(1));
    assert!(state.admit_peer(peer(65), false, later, false));
    assert!(!state.peers.contains_key(&peer(1)));
    for n in 2..=UNCONFIGURED_IDENTITIES as u8 {
        assert_eq!(state.peers[&peer(n)].active, 1);
    }
}

#[test]
fn finishing_an_exchange_does_not_reset_its_identity_budget() {
    let now = Instant::now();
    let mut state = AdmissionState::new(now);
    for _ in 0..ADMISSION_BURST {
        assert!(state.admit_peer(peer(1), false, now, false));
        state.release_peer(peer(1));
    }
    assert!(!state.admit_peer(peer(1), false, now, false));
    assert!(state.admit_peer(peer(1), true, now, false));
    assert!(state.admit_peer(peer(1), false, now + ADMISSION_INTERVAL, false));
    assert_eq!(state.peers.len(), 1);
}

#[test]
fn neighbor_admission_mode_is_explicit_and_defaults_to_configured() {
    assert_eq!(
        NeighborAdmission::default(),
        NeighborAdmission::ConfiguredOnly
    );
    assert_eq!(
        serde_json::to_string(&NeighborAdmission::AuthenticatedAdjacent).unwrap(),
        "\"authenticated_adjacent\""
    );
    assert!(serde_json::from_str::<NeighborAdmission>("\"all\"").is_err());
}

#[test]
fn financial_identity_storage_survives_a_full_newcomer_table_and_stays_bounded() {
    let now = Instant::now();
    let mut state = AdmissionState::new(now);
    for n in 1..=128u8 {
        let reserved = n > UNCONFIGURED_IDENTITIES as u8;
        assert!(state.admit_peer(peer(n), false, now, reserved));
    }
    assert_eq!(
        state.peers.len(),
        UNCONFIGURED_IDENTITIES + OBLIGATION_IDENTITIES
    );
    assert!(!state.admit_peer(peer(129), false, now, false));
    assert!(!state.admit_peer(peer(129), false, now, true));
    // Only an idle, fully refilled member of the requested pool may be evicted.
    state.release_peer(peer(65));
    assert!(!state.admit_peer(peer(129), false, now, true));
    assert!(state.admit_peer(peer(129), false, now + ADMISSION_INTERVAL, true));
    assert!(!state.peers.contains_key(&peer(65)));
    assert!(state.peers.contains_key(&peer(1)));
}

#[test]
fn gaining_and_losing_financial_eligibility_never_resets_identity_limits() {
    let now = Instant::now();
    let mut state = AdmissionState::new(now);
    let id = peer(1);
    for reserved in [false, true, false, true] {
        assert!(state.admit_peer(id, false, now, reserved));
    }
    assert!(!state.admit_peer(id, true, now, false));
    assert_eq!(state.peers[&id].active, 4);
    assert_eq!(state.peers[&id].incoming.tokens, ADMISSION_BURST - 4);
    for _ in 0..4 {
        state.release_peer(id);
    }
    for n in 4..ADMISSION_BURST {
        assert!(state.admit_peer(id, false, now, n % 2 == 0));
        state.release_peer(id);
    }
    assert!(!state.admit_peer(id, false, now, true));
    assert!(!state.admit_peer(id, false, now, false));
    assert!(state.admit_peer(id, true, now, true));
    assert_eq!(state.peers.len(), 1);
}
