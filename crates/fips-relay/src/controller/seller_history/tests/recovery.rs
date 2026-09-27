use super::*;
use std::cell::{Cell, RefCell};

fn no_prepare(_: &[String]) -> Result<ReceiverPlan, String> {
    panic!("a saved SDK intent must be retried without preparing another")
}

fn apply_sdk(
    state: &RefCell<(ReceiverHistory, usize)>,
    p: &ReceiverPlan,
) -> Result<ReceiverHistory, String> {
    p.validate()?;
    let mut state = state.borrow_mut();
    if state.0 != p.accounting.after {
        assert_eq!(state.0, p.accounting.before);
        state.0 = p.accounting.after.clone();
        state.1 += 1;
    }
    Ok(state.0.clone())
}

fn legacy(j: &mut Journal) {
    j.version = 5;
    let h = j.history.as_mut().unwrap().seller.as_mut().unwrap();
    h.totals.receiver = None;
    if let Some(p) = &mut h.pending {
        p.receiver = None;
        p.before.receiver = None;
        p.after.receiver = None;
    }
}

#[test]
fn receiver_commit_failures_and_lost_replies_resume_the_original_financial_intent() {
    for boundary in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, seller, t) = fixture(root.path());
        let t = append(&mut store, &seller, &t, 1, true);
        prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
        let p = pending(&store).receiver.unwrap();
        let sdk = RefCell::new((p.accounting.before.clone(), 0));
        let path = store.directory.join("controller.json");
        let saved = root.path().join("before-final-write.json");
        let failed = store.resume_sales(&seller, no_prepare, |p| {
            if boundary == 0 {
                return Err("receiver write failed".into());
            }
            let after = apply_sdk(&sdk, p)?;
            match boundary {
                1 => Err("receiver reply lost".into()),
                2 => {
                    std::fs::rename(&path, &saved).unwrap();
                    std::fs::create_dir(&path).unwrap();
                    Ok(after)
                }
                _ => Ok(ReceiverHistory::default()),
            }
        });
        assert!(failed.is_err());
        assert!(store.change(|_| Ok(())).is_err());
        assert!(seller.channel_terms(&t.id).is_none());
        if boundary == 2 {
            std::fs::remove_dir(&path).unwrap();
            std::fs::rename(&saved, &path).unwrap();
        }
        store = reload(store);
        assert!(store.journal.seller_settlements[&t.id].released);
        drop(seller);
        let seller = DurableRelay::load(&root.path().join("seller")).unwrap();
        assert_eq!(
            store
                .resume_sales(&seller, no_prepare, |p| apply_sdk(&sdk, p))
                .unwrap(),
            1
        );
        assert_eq!(
            sdk.borrow().1,
            1,
            "recovery cannot apply the receiver history twice"
        );
        assert_eq!(
            store
                .journal
                .history
                .as_ref()
                .unwrap()
                .seller
                .as_ref()
                .unwrap()
                .totals
                .receiver
                .as_ref(),
            Some(&p.accounting.after)
        );
        assert_eq!(
            store
                .resume_sales(&seller, no_prepare, |_| panic!("no pending intent"))
                .unwrap(),
            0
        );
    }
}

#[test]
fn receiver_proof_queue_backpressure_retains_the_exact_plan_across_reload() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, t) = fixture(root.path());
    let t = append(&mut store, &seller, &t, 1, true);
    seller.apply_verified_balance(&t.id, 3_000).unwrap();
    let sale = store.journal.seller_settlements.get_mut(&t.id).unwrap();
    sale.payment.as_mut().unwrap().balance = 3;
    sale.usage.as_mut().unwrap().paid_msat = 3_000;
    let report = sale.report.as_mut().unwrap();
    report.signed_sat = 3;
    report.paid_sat = 3;
    report.receiver_fee_reserve_sat = 1;
    report.refunded_sat -= 4;
    store.persist().unwrap();
    prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
    let original = pending(&store);
    let exact_plan = serde_json::to_value(original.receiver.as_ref().unwrap()).unwrap();
    assert_eq!(exact_plan["payouts"][0], support::payout(&t.id, 4));
    assert_eq!(exact_plan["binding"], "00".repeat(32));
    let saved_journal = serde_json::to_value(&store.journal).unwrap();
    let sdk = RefCell::new((
        original
            .receiver
            .as_ref()
            .unwrap()
            .accounting
            .before
            .clone(),
        0,
    ));

    // The real SDK owns proof deletion. This closure models its durable receiver
    // commit followed by release-queue backpressure, without minting fixture money.
    for _ in 0..2 {
        let error = store.resume_sales(&seller, no_prepare, |p| {
            assert_eq!(serde_json::to_value(p).unwrap(), exact_plan);
            apply_sdk(&sdk, p)?;
            Err("proof release queue is full".into())
        });
        assert_eq!(error, Err("proof release queue is full".into()));
        assert_eq!(
            sdk.borrow().0,
            original.receiver.as_ref().unwrap().accounting.after
        );
        assert!(seller.channel_terms(&t.id).is_none());
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), saved_journal);
        assert!(store.change(|_| Ok(())).is_err());
        store = reload(store);
        assert_eq!(
            serde_json::to_value(pending(&store).receiver.unwrap()).unwrap(),
            exact_plan
        );
    }

    let admitted = RefCell::new(None);
    let queue_handoffs = Cell::new(0);
    let mut admit = |p: &ReceiverPlan| -> Result<ReceiverHistory, String> {
        assert_eq!(serde_json::to_value(p).unwrap(), exact_plan);
        let after = apply_sdk(&sdk, p)?;
        let mut admitted = admitted.borrow_mut();
        if admitted.is_none() {
            *admitted = Some(exact_plan["payouts"].clone());
            queue_handoffs.set(queue_handoffs.get() + 1);
        }
        Ok(after)
    };
    assert_eq!(
        store.resume_sales(&seller, no_prepare, |p| {
            admit(p)?;
            Err("proof release reply lost".into())
        }),
        Err("proof release reply lost".into())
    );
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), saved_journal);
    store = reload(store);
    assert_eq!(
        store.resume_sales(&seller, no_prepare, &mut admit).unwrap(),
        1
    );
    assert_eq!(sdk.borrow().1, 1);
    assert_eq!(queue_handoffs.get(), 1);
    assert_eq!(admitted.borrow().as_ref(), Some(&exact_plan["payouts"]));
    let history = store
        .journal
        .history
        .as_ref()
        .unwrap()
        .seller
        .as_ref()
        .unwrap();
    assert!(history.totals == original.after);
    assert_eq!(history.totals.paid_sat, 3);
    assert_eq!(history.totals.receiver_fee_reserve_sat, 1);
    assert_eq!(history.totals.fee_sat, 1);
    assert!(history.pending.is_none());
    assert!(!store.journal.seller_settlements.contains_key(&t.id));
    assert_ne!(
        store.journal.version & journal::RECEIVER_PROOF_RELEASE_VERSION,
        0
    );
    store = reload(store);
    assert_eq!(
        store
            .resume_sales(&seller, no_prepare, |_| panic!("no pending handoff"))
            .unwrap(),
        0
    );
}

#[test]
fn legacy_pending_sales_acquire_receiver_evidence_before_losing_original_ids() {
    for ledger_already_removed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, seller, t) = fixture(root.path());
        let t = append(&mut store, &seller, &t, 1, true);
        prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
        legacy(&mut store.journal);
        let ledger = pending(&store).ledger;
        store.persist().unwrap();
        if ledger_already_removed {
            seller.retire_channels(&ledger).unwrap();
        }
        store = reload(store);
        let original = store.journal.clone();
        let prepared = Cell::new(0);
        store
            .resume_sales(
                &seller,
                |ids| {
                    assert_eq!(ids, std::slice::from_ref(&t.id));
                    prepared.set(prepared.get() + 1);
                    support::receiver_plan(&original, ids)
                },
                |p| Ok(p.accounting.after.clone()),
            )
            .unwrap();
        assert_eq!(prepared.get(), 1);
        assert_eq!(store.journal.history_version(), 6);
        assert_ne!(
            store.journal.version & journal::RECEIVER_PROOF_RELEASE_VERSION,
            0
        );
        let total = &store
            .journal
            .history
            .as_ref()
            .unwrap()
            .seller
            .as_ref()
            .unwrap()
            .totals;
        assert_eq!(total.accounting.channels, 1);
        assert_eq!(total.receiver.as_ref().unwrap().totals[0].channels, 1);
        assert_eq!(total.fee_sat, 1);
    }
}

#[test]
fn receiver_history_can_cover_a_subset_of_old_application_rollups() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, t) = fixture(root.path());
    let t = append(&mut store, &seller, &t, 1, true);
    retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
    // Model an old application-only rollup; the SDK never retired that old ID.
    legacy(&mut store.journal);
    store.persist().unwrap();
    store = reload(store);
    let t = append(&mut store, &seller, &t, 2, true);
    retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
    let total = &store
        .journal
        .history
        .as_ref()
        .unwrap()
        .seller
        .as_ref()
        .unwrap()
        .totals;
    assert_eq!(total.accounting.channels, 2);
    assert_eq!(total.receiver.as_ref().unwrap().totals[0].channels, 1);
    assert_eq!(total.fee_sat, 2);
}

#[test]
fn ineligible_or_changed_receiver_evidence_never_saves_a_new_cleanup_intent() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, t) = fixture(root.path());
    let t = append(&mut store, &seller, &t, 1, true);
    let original = store.journal.clone();
    let snapshot = serde_json::to_value(&original).unwrap();
    let failed = store.prepare_sales(&seller, t.expires_unix + 61, |_| {
        Err("payout missing".into())
    });
    assert!(failed.is_err());
    for field in [
        "capacity",
        "signed_amount",
        "closed_amount",
        "receiver_sum",
        "sender_sum",
        "mint",
        "unit",
        "expiry",
        "history",
    ] {
        let mut p = support::receiver_plan(&original, std::slice::from_ref(&t.id)).unwrap();
        if field == "history" {
            let mut other = original.clone();
            other
                .history
                .as_mut()
                .unwrap()
                .seller
                .get_or_insert_with(SellerHistory::default)
                .totals
                .receiver = Some(p.accounting.after);
            p = support::receiver_plan(&other, std::slice::from_ref(&t.id)).unwrap();
        } else {
            let mut encoded = serde_json::to_value(p).unwrap();
            let value = match field {
                "mint" => serde_json::json!("https://other.invalid"),
                "unit" => serde_json::json!("usd"),
                "expiry" => serde_json::json!(t.expires_unix + 61),
                "sender_sum" => serde_json::json!(t.capacity_sat - 2),
                _ => {
                    serde_json::json!(
                        encoded["accounting"]["channels"][0]["totals"][field]
                            .as_u64()
                            .unwrap()
                            + 1
                    )
                }
            };
            if field == "expiry" {
                encoded["accounting"]["channels"][0]["expires_unix"] = value.clone();
                encoded["accounting"]["after"]["expires_through_unix"] = value;
            } else {
                encoded["accounting"]["channels"][0]["totals"][field] = value.clone();
                encoded["accounting"]["after"]["totals"][0][field] = value;
            }
            if field == "receiver_sum" {
                encoded["payouts"][0] = support::payout(
                    &t.id,
                    encoded["accounting"]["channels"][0]["totals"][field]
                        .as_u64()
                        .unwrap(),
                );
            }
            p = serde_json::from_value(encoded).unwrap();
        }
        if matches!(field, "unit" | "closed_amount") {
            assert!(
                p.validate().is_err(),
                "SDK release checks currency and the signed bound"
            );
        } else {
            // Internally sound SDK values still need the FIPS channel binding.
            p.validate().unwrap();
        }
        assert!(
            store
                .prepare_sales(&seller, t.expires_unix + 61, |_| Ok(p.clone()))
                .is_err(),
            "{field}"
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), snapshot);
        assert!(seller.channel_terms(&t.id).is_some());
    }
    assert!(store.change(|_| Ok(())).is_ok());
}

#[test]
fn modern_cleanup_requires_complete_receiver_history_and_intent() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, t) = fixture(root.path());
    let t = append(&mut store, &seller, &t, 1, true);
    prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
    for field in [
        "history",
        "plan",
        "before",
        "after",
        "version",
        "proof_format",
    ] {
        let mut j = store.journal.clone();
        let h = j.history.as_mut().unwrap().seller.as_mut().unwrap();
        match field {
            "history" => h.totals.receiver = None,
            "plan" => h.pending.as_mut().unwrap().receiver = None,
            "before" => h.pending.as_mut().unwrap().before.receiver = None,
            "after" => h.pending.as_mut().unwrap().after.receiver = None,
            "proof_format" => j.version &= !journal::RECEIVER_PROOF_RELEASE_VERSION,
            _ => j.version = 5,
        }
        assert!(
            Controller::validate_journal(&j, &j.policy, j.local).is_err(),
            "{field}"
        );
    }
}
