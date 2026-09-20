use super::super::transition_tests::reload;
use super::tests::{abandoned, prepare, receipt};
use super::*;
use cashu_service::CashuSpilmanFundingReclaim as Wallet;

#[test]
fn only_exact_cancelled_admission_releases_its_reservation_after_reload() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = abandoned(&root.path().join("controller"));
    let pending = prepare(&mut store);
    // Another provider's uncertain intent must retain its separate reservation.
    store
        .change(|j| {
            j.policy.max_locked_sat = 64;
            let mut other = pending.clone();
            other.id = "test-2".into();
            other.provider = NodeAddr::from_bytes([3; 16]);
            other.reclaim = None;
            j.funding.insert(other.id.clone(), other);
            j.next_funding = 3;
            Ok(())
        })
        .unwrap();
    let before = serde_json::to_value(&store.journal).unwrap();
    let budget = Controller::capital(&store.journal).unwrap();
    assert_eq!(budget.pending_reserved_sat, 64);
    for uncertain in [Wallet::Missing, Wallet::NoPlan] {
        store
            .change(|j| Controller::record_wallet_reclaim(j, &pending, uncertain))
            .unwrap();
        store = reload(store);
        assert!(serde_json::to_value(&store.journal).unwrap() == before);
        assert_eq!(Controller::capital(&store.journal).unwrap(), budget);
        assert!(Controller::provider_reclaiming(
            &store.journal,
            pending.provider
        ));
    }
    for _ in 0..2 {
        store
            .change(|j| Controller::record_wallet_reclaim(j, &pending, Wallet::Cancelled))
            .unwrap();
        store = reload(store);
        let current = &store.journal.funding[&pending.id];
        assert!(current.cancelled() && current.reclaim_terminal() && current.reclaimed().is_none());
        assert!(current.funded.is_none());
        assert!(!Controller::abandoned_funding(&store.journal, current));
        assert!(Controller::funding_released(&store.journal, current));
        assert!(!Controller::provider_reclaiming(
            &store.journal,
            current.provider
        ));
        assert_eq!(
            Controller::capital(&store.journal).unwrap(),
            FundingBudget {
                pending_reserved_sat: 32,
                locked_sat: 32,
                exposure_sat: 32,
                ..FundingBudget::default()
            }
        );
        let after = serde_json::to_value(&store.journal).unwrap();
        for field in [
            "policy",
            "next_funding",
            "requested",
            "recovery_only",
            "watched_routes",
        ] {
            assert!(
                after[field] == before[field],
                "cancellation changed retained authority"
            );
        }
        assert!(after["funding"]["test-2"] == before["funding"]["test-2"]);
        assert!(store.journal.outgoing.is_empty() && store.journal.buyer_settlements.is_empty());
        assert!(Controller::check_purchase(&store.journal, &old.offer, None).is_err());
    }
    let mut fresh = old.offer;
    fresh.id = "new-authorized-request".into();
    assert!(Controller::check_purchase(&store.journal, &fresh, None).is_ok());
}

#[test]
fn cancellation_rejects_changed_or_unfenced_authority_and_late_funding() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = abandoned(&root.path().join("controller"));
    let unprepared = store.journal.funding["test-1"].clone();
    assert!(
        store
            .change(|j| Controller::record_wallet_reclaim(j, &unprepared, Wallet::Cancelled))
            .is_err()
    );
    let pending = prepare(&mut store);
    let original = serde_json::to_value(&store.journal).unwrap();
    for mutation in 0..5 {
        let mut changed = pending.clone();
        match mutation {
            0 => changed.id = "missing".into(),
            1 => changed.provider = NodeAddr::from_bytes([3; 16]),
            2 => changed.expires_unix += 1,
            3 => changed.max_wallet_debit_sat += 1,
            _ => changed.receiver_pubkey_hex = format!("02{}", "22".repeat(32)),
        }
        assert!(
            store
                .change(|j| Controller::record_wallet_reclaim(j, &changed, Wallet::Cancelled))
                .is_err()
        );
        assert!(serde_json::to_value(&store.journal).unwrap() == original);
    }
    let mut unwithdrawn = store.journal.clone();
    unwithdrawn.recovery_only.clear();
    assert!(
        Controller::record_wallet_reclaim(&mut unwithdrawn, &pending, Wallet::Cancelled).is_err()
    );
    store
        .change(|j| Controller::record_wallet_reclaim(j, &pending, Wallet::Cancelled))
        .unwrap();
    let terminal = store.journal.funding[&pending.id].clone();
    let saved = serde_json::to_value(&store.journal).unwrap();
    assert!(
        store
            .change(|j| Controller::record_funding_reclaim(j, &pending, receipt()))
            .is_err()
    );
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
                .change(|j| Controller::record_restored_funding(
                    j,
                    expected.clone(),
                    funded.clone()
                ))
                .is_err()
        );
        assert!(
            store
                .change(|j| Controller::record_funding(j, expected, funded.clone()))
                .is_err()
        );
        assert!(serde_json::to_value(&store.journal).unwrap() == saved);
    }
    for flag in [
        journal::FUNDING_CANCELLED_VERSION,
        journal::FUNDING_RECLAIM_VERSION,
    ] {
        let mut unsupported = store.journal.clone();
        unsupported.version &= !flag;
        assert!(
            Controller::validate_journal(&unsupported, &unsupported.policy, unsupported.local)
                .is_err()
        );
    }
    reload(store);
}

#[test]
fn cancellation_cannot_replace_a_verified_reclaimed_send() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, _) = abandoned(&root.path().join("controller"));
    let pending = prepare(&mut store);
    let result = receipt();
    store
        .change(|j| {
            Controller::record_wallet_reclaim(
                j,
                &pending,
                Wallet::Reclaimed {
                    wallet_operation_id: result.wallet_operation_id,
                    wallet_cost: result.wallet_cost,
                    recovered_amount_sat: result.recovered_amount_sat,
                },
            )
        })
        .unwrap();
    let before = serde_json::to_value(&store.journal).unwrap();
    for expected in [pending, store.journal.funding["test-1"].clone()] {
        assert!(
            store
                .change(|j| Controller::record_wallet_reclaim(j, &expected, Wallet::Cancelled))
                .is_err()
        );
        assert!(serde_json::to_value(&store.journal).unwrap() == before);
    }
    reload(store);
}
