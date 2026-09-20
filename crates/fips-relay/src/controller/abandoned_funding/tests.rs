use super::super::transition_tests::{fixture, reload};
use super::*;

pub(super) fn abandoned(directory: &Path) -> (Store, Outgoing) {
    let (mut store, old) = fixture(directory);
    store
        .change(|j| {
            j.outgoing.clear();
            j.funding.get_mut("test-1").unwrap().funded = None;
            j.version |= journal::RECOVERY_ONLY_VERSION;
            j.recovery_only.insert(old.offer.id.clone());
            Ok(())
        })
        .unwrap();
    (store, old)
}

pub(super) fn receipt() -> ReclaimedFunding {
    ReclaimedFunding {
        wallet_operation_id: "original-send".into(),
        wallet_cost: cashu_service::CashuSendCost {
            token_amount_sat: 32,
            swap_fee_sat: 0,
            wallet_debit_sat: 32,
        },
        recovered_amount_sat: 30,
    }
}

pub(super) fn prepare(store: &mut Store) -> FundingIntent {
    let intent = store.journal.funding["test-1"].clone();
    store
        .change(|j| Controller::prepare_funding_reclaim(j, &intent))
        .unwrap()
}

#[test]
fn reclaim_reservation_and_terminal_cost_survive_reload_without_route_authority() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = abandoned(&root.path().join("controller"));
    let pending = prepare(&mut store);
    store = reload(store);
    let reserved = Controller::capital(&store.journal).unwrap();
    assert_eq!(reserved.pending_reserved_sat, 32);
    assert_eq!(reserved.locked_sat, 32);
    assert!(!Controller::funding_released(&store.journal, &pending));
    assert!(Controller::check_purchase(&store.journal, &old.offer, None).is_err());
    let mut fresh = old.offer.clone();
    fresh.id = "new-authorized-offer".into();
    assert!(Controller::check_purchase(&store.journal, &fresh, None).is_err());
    // An unrelated provider is not fenced; its normal capital limits still apply.
    fresh.provider = NodeAddr::from_bytes([3; 16]);
    fresh.path[0] = fresh.provider;
    store
        .change(|j| Controller::reserve_purchase(j, fresh.clone()))
        .unwrap();
    for _ in 0..2 {
        store
            .change(|j| Controller::record_funding_reclaim(j, &pending, receipt()))
            .unwrap();
        store = reload(store);
        let budget = Controller::capital(&store.journal).unwrap();
        assert_eq!(budget.pending_reserved_sat, 0);
        assert_eq!(budget.locked_sat, 0);
        assert_eq!(budget.wallet_debited_sat, 32);
        assert_eq!(budget.wallet_refunded_sat, 30);
        assert_eq!(budget.exposure_sat, 2);
        assert!(store.journal.outgoing.is_empty());
        assert!(Controller::funding_released(
            &store.journal,
            &store.journal.funding["test-1"]
        ));
        assert!(Controller::check_purchase(&store.journal, &old.offer, None).is_err());
    }
    fresh.provider = old.offer.provider;
    fresh.path[0] = fresh.provider;
    fresh.id = "authorized-after-reclaim".into();
    assert!(Controller::check_purchase(&store.journal, &fresh, None).is_ok());
    let before = serde_json::to_value(&store.journal).unwrap();
    for mutation in 0..4 {
        let mut result = receipt();
        match mutation {
            0 => result.recovered_amount_sat += 1,
            1 => result.wallet_operation_id = "replacement".into(),
            2 => result.recovered_amount_sat = 33,
            _ => result.wallet_cost.wallet_debit_sat = 33,
        }
        assert!(
            store
                .change(|j| Controller::record_funding_reclaim(j, &pending, result))
                .is_err()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
    }
    let mut invalid = store.journal.clone();
    invalid.version &= !journal::FUNDING_RECLAIM_VERSION;
    assert!(Controller::validate_journal(&invalid, &invalid.policy, invalid.local).is_err());
    let mut duplicate = store.journal.clone();
    let mut second = duplicate.funding["test-1"].clone();
    second.id = "test-2".into();
    second.provider = NodeAddr::from_bytes([4; 16]);
    duplicate.funding.insert(second.id.clone(), second);
    duplicate.next_funding = 3;
    assert!(
        Controller::validate_capital(&duplicate).is_err(),
        "one send cannot fund two intents"
    );
}

#[test]
fn reclaim_refuses_unwithdrawn_or_shared_route_owners() {
    let root = tempfile::tempdir().unwrap();
    let (store, old) = abandoned(&root.path().join("controller"));
    for owner in 0..8 {
        let mut j = store.journal.clone();
        match owner {
            0 => {
                j.recovery_only.clear();
            }
            1 => {
                let mut fresh = old.offer.clone();
                fresh.id = "other-destination-owner".into();
                j.requested.insert(fresh.id.clone(), fresh);
            }
            2 => {
                j.outgoing
                    .insert(old.purchase.contract.id.clone(), old.clone());
            }
            3 => {
                j.incoming.insert(
                    "incoming".into(),
                    Incoming {
                        offer: old.offer.clone(),
                        downstream: Some(old.offer.clone()),
                        channel: old.purchase.channel.clone(),
                        contract: old.purchase.contract.clone(),
                        verified_paid_msat: 0,
                        phase: Phase::Stopped,
                        replaces: None,
                        replacement_retired: false,
                    },
                );
            }
            4 => {
                j.route_changes.insert(
                    "change".into(),
                    super::super::transition_tests::change(&old),
                );
            }
            5 => {
                j.renewals.insert(
                    "renewal".into(),
                    serde_json::from_value(serde_json::json!({
                        "previous":[old], "replacements":null, "completed":false,
                    }))
                    .unwrap(),
                );
            }
            6 => {
                let watch = WatchedRoute {
                    billing: old.offer.billing,
                    destination: old.offer.destination.npub(),
                    max_rate_msat_per_kib: 1024,
                    paused: false,
                    pending: Some(old.offer.clone()),
                    selected_trial: None,
                };
                j.watched_routes.insert(watch.destination.clone(), watch);
            }
            _ => {
                // An actually funded opening is never a pre-opening reclaim.
                j.funding.get_mut("test-1").unwrap().funded = Some(Funded {
                    wallet_operation_id: "original".into(),
                    wallet_cost: receipt().wallet_cost,
                    terms: old.purchase.channel.clone(),
                    opening: CashuSpilmanPayment {
                        channel_id: old.purchase.channel.id.clone(),
                        balance: 0,
                        signature: "fixture".into(),
                        params: None,
                        funding_proofs: None,
                    },
                });
            }
        }
        let expected = j.funding["test-1"].clone();
        let before = serde_json::to_value(&j).unwrap();
        assert!(
            Controller::prepare_funding_reclaim(&mut j, &expected).is_err(),
            "owner {owner}"
        );
        assert_eq!(serde_json::to_value(&j).unwrap(), before);
    }
}

#[test]
fn pending_without_restore_evidence_can_later_record_only_verified_original_opening() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, _) = fixture(&root.path().join("controller"));
    let funded = store.journal.funding["test-1"].funded.clone().unwrap();
    store
        .change(|j| {
            j.outgoing.clear();
            j.funding.get_mut("test-1").unwrap().funded = None;
            j.version |= journal::RECOVERY_ONLY_VERSION;
            j.recovery_only.insert("old-offer".into());
            Ok(())
        })
        .unwrap();
    let unfenced = store.journal.funding["test-1"].clone();
    let pending = prepare(&mut store);
    // Empty restore/NoPlan/error carries no funded evidence and releases nothing.
    store = reload(store);
    assert_eq!(
        Controller::capital(&store.journal)
            .unwrap()
            .pending_reserved_sat,
        32
    );
    for expected in [unfenced, pending.clone()] {
        assert!(
            store
                .change(|j| Controller::record_funding(j, expected, funded.clone()))
                .is_err()
        );
    }
    store
        .change(|j| Controller::record_restored_funding(j, pending, funded.clone()))
        .unwrap();
    store = reload(store);
    let intent = &store.journal.funding["test-1"];
    assert!(intent.reclaim.is_none());
    assert!(intent.funded.as_ref() == Some(&funded));
    assert!(store.journal.recovery_only.contains("old-offer"));
    assert!(store.journal.outgoing.is_empty());
    assert_eq!(Controller::capital(&store.journal).unwrap().locked_sat, 32);
}

#[test]
fn completed_reclaim_cannot_become_funded_and_pending_fence_is_validated_on_load() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = abandoned(&root.path().join("controller"));
    let pending = prepare(&mut store);
    let mut j = store.journal.clone();
    j.recovery_only.clear();
    assert!(Controller::validate_journal(&j, &j.policy, j.local).is_err());
    store
        .change(|j| Controller::record_funding_reclaim(j, &pending, receipt()))
        .unwrap();
    let terminal = store.journal.funding["test-1"].clone();
    let funded = Funded {
        wallet_operation_id: receipt().wallet_operation_id,
        wallet_cost: receipt().wallet_cost,
        terms: old.purchase.channel,
        opening: CashuSpilmanPayment {
            channel_id: "channel".into(),
            balance: 0,
            signature: "fixture".into(),
            params: None,
            funding_proofs: None,
        },
    };
    for expected in [pending, terminal] {
        assert!(
            store
                .change(|j| Controller::record_restored_funding(j, expected, funded.clone()))
                .is_err()
        );
    }
    reload(store);
}
