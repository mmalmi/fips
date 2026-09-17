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
    if state.0 != p.after {
        assert_eq!(state.0, p.before);
        state.0 = p.after.clone();
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
        let sdk = RefCell::new((p.before.clone(), 0));
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
            Some(&p.after)
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
                |p| Ok(p.after.clone()),
            )
            .unwrap();
        assert_eq!(prepared.get(), 1);
        assert_eq!(store.journal.version, 6);
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
                .receiver = Some(p.after);
            p = support::receiver_plan(&other, std::slice::from_ref(&t.id)).unwrap();
        } else {
            let mut encoded = serde_json::to_value(p).unwrap();
            let value = match field {
                "mint" => serde_json::json!("https://other.invalid"),
                "unit" => serde_json::json!("usd"),
                "expiry" => serde_json::json!(t.expires_unix + 61),
                "sender_sum" => serde_json::json!(t.capacity_sat - 2),
                _ => {
                    serde_json::json!(encoded["channels"][0]["totals"][field].as_u64().unwrap() + 1)
                }
            };
            if field == "expiry" {
                encoded["channels"][0]["expires_unix"] = value.clone();
                encoded["after"]["expires_through_unix"] = value;
            } else {
                encoded["channels"][0]["totals"][field] = value.clone();
                encoded["after"]["totals"][0][field] = value;
            }
            p = serde_json::from_value(encoded).unwrap();
        }
        p.validate().unwrap(); // Internally sound SDK values still need the FIPS binding.
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
    for field in ["history", "plan", "before", "after", "version"] {
        let mut j = store.journal.clone();
        let h = j.history.as_mut().unwrap().seller.as_mut().unwrap();
        match field {
            "history" => h.totals.receiver = None,
            "plan" => h.pending.as_mut().unwrap().receiver = None,
            "before" => h.pending.as_mut().unwrap().before.receiver = None,
            "after" => h.pending.as_mut().unwrap().after.receiver = None,
            _ => j.version = 5,
        }
        assert!(
            Controller::validate_journal(&j, &j.policy, j.local).is_err(),
            "{field}"
        );
    }
}
