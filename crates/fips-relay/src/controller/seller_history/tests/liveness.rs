use super::*;

fn fragmented_plan(j: &Journal, ids: &[String]) -> Result<ReceiverPlan, String> {
    let mut encoded = serde_json::to_value(support::receiver_plan(j, ids)?).unwrap();
    for payout in encoded["payouts"].as_array_mut().unwrap() {
        let id = payout["channel_id"].as_str().unwrap().to_owned();
        let coin = support::payout(&id, 1)["proofs"][0].clone();
        payout["proofs"] = serde_json::json!(
            (0..400)
                .map(|n| {
                    let mut proof = coin.clone();
                    proof["secret"] = format!("receiver-retirement-{id}-{n}").into();
                    proof
                })
                .collect::<Vec<_>>()
        );
    }
    let plan: ReceiverPlan = serde_json::from_value(encoded).unwrap();
    plan.validate()?;
    Ok(plan)
}

#[test]
fn large_receiver_payouts_retire_oldest_first_without_combining_handoffs() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, mut template) = fixture_with_channels(root.path(), 3);
    template.capacity_sat = 512;
    // With denominations [512, 1], each admitted 512-sat channel can close
    // into 400 receiver proofs and 112 refund proofs. These are storage-only
    // identities; the real SDK validates their handoff bounds and accounting.
    let mut channels = Vec::new();
    for (n, delay) in [(1, 30), (2, 10), (3, 20)] {
        let mut terms = template.clone();
        terms.expires_unix += delay;
        if let Some(refund) = &mut terms.refund_after_unix {
            *refund += delay;
        }
        let terms = append(&mut store, &seller, &terms, n, true);
        seller.apply_verified_balance(&terms.id, 400_000).unwrap();
        let sale = store.journal.seller_settlements.get_mut(&terms.id).unwrap();
        sale.payment.as_mut().unwrap().balance = 400;
        sale.usage.as_mut().unwrap().paid_msat = 400_000;
        let report = sale.report.as_mut().unwrap();
        report.signed_sat = 400;
        report.paid_sat = 400;
        report.refunded_sat = 112;
        report.fee_sat = 0;
        channels.push(terms);
    }
    store.persist().unwrap();
    let ids: Vec<_> = channels.iter().map(|c| c.id.clone()).collect();
    for id in &ids {
        fragmented_plan(&store.journal, std::slice::from_ref(id)).unwrap();
    }
    assert_eq!(
        fragmented_plan(&store.journal, &ids).unwrap_err(),
        "receiver payout handoff exceeds 1024 coins"
    );
    channels.sort_by_key(ChannelTerms::refund_deadline);
    assert_eq!(
        channels[0].id, "sale-2",
        "expiry order differs from ID order"
    );
    let timestamp = channels.last().unwrap().refund_deadline().unwrap() + 1;
    let authority = |j: &Journal| {
        let mut value = serde_json::to_value(j).unwrap();
        for field in ["version", "history", "seller_settlements"] {
            value.as_object_mut().unwrap().remove(field);
        }
        value
    };
    let original = authority(&store.journal);
    for (index, channel) in channels.iter().enumerate() {
        let journal = store.journal.clone();
        assert_eq!(
            Store::retire_sales(
                &Mutex::new(&mut store),
                &seller,
                timestamp,
                |ids| fragmented_plan(&journal, ids),
                |plan| {
                    plan.validate()?;
                    assert_eq!(plan.accounting.channels.len(), 1);
                    assert_eq!(plan.accounting.channels[0].id, channel.id);
                    Ok(plan.accounting.after.clone())
                },
            ),
            Ok(1),
            "individually admitted payouts must keep making retirement progress"
        );
        store = reload(store);
        assert_eq!(authority(&store.journal), original);
        let history = store
            .journal
            .history
            .as_ref()
            .unwrap()
            .seller
            .as_ref()
            .unwrap();
        assert!(history.pending.is_none());
        let count = index as u64 + 1;
        assert_eq!(history.totals.accounting.channels, count);
        assert_eq!(history.totals.value_sat, count * 512);
        assert_eq!(history.totals.signed_sat, count * 400);
        assert_eq!(history.totals.paid_sat, count * 400);
        assert_eq!(history.totals.returned_sat, count * 112);
        assert_eq!(history.totals.fee_sat, 0);
        for other in &channels {
            if other.refund_deadline() > channel.refund_deadline() {
                assert!(seller.channel_terms(&other.id).is_some());
                assert_eq!(
                    serde_json::to_value(&store.journal.seller_settlements[&other.id]).unwrap(),
                    serde_json::to_value(&journal.seller_settlements[&other.id]).unwrap()
                );
            } else {
                assert!(seller.channel_terms(&other.id).is_none());
                assert!(!store.journal.seller_settlements.contains_key(&other.id));
            }
        }
    }
}

#[test]
fn receiver_planning_keeps_controller_reads_available() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, template) = fixture(root.path());
    let t = append(&mut store, &seller, &template, 1, true);
    let shared = Mutex::new(store);
    let prepared = Store::prepare_sales(&shared, &seller, t.expires_unix + 61, |ids| {
        let mut store = shared
            .try_lock()
            .map_err(|_| "receiver planning blocks controller reads")?;
        // Planning has not persisted an intent yet. An unrelated change must
        // survive when the selected receiver evidence is attached.
        store.change(|j| {
            j.next_funding += 1;
            Ok(())
        })?;
        support::receiver_plan(&store.journal, ids)
    });
    assert_eq!(prepared, Ok(()));
    let store = shared.into_inner().unwrap();
    assert_eq!(store.journal.next_funding, 3);
    assert!(store.journal.history.as_ref().unwrap().pending());
}

#[test]
fn receiver_retirement_keeps_controller_reads_available() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, template) = fixture(root.path());
    let t = append(&mut store, &seller, &template, 1, true);
    prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
    let shared = Mutex::new(store);
    let retired = Store::resume_sales(
        &shared,
        &seller,
        |_| panic!("saved intent"),
        |p| {
            let mut store = shared
                .try_lock()
                .map_err(|_| "receiver retirement blocks controller reads")?;
            assert!(store.journal.seller_settlements.contains_key(&t.id));
            assert!(
                store.change(|_| Ok(())).is_err(),
                "pending handoff must fence writes"
            );
            Ok(p.accounting.after.clone())
        },
    );
    assert_eq!(retired, Ok(1));
    let mut store = shared.into_inner().unwrap();
    store.change(|_| Ok(())).unwrap();
    assert!(!store.journal.seller_settlements.contains_key(&t.id));
}

#[test]
fn receiver_planning_revalidates_reports_before_saving_its_intent() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, template) = fixture(root.path());
    let t = append(&mut store, &seller, &template, 1, true);
    let shared = Mutex::new(store);
    let result = Store::prepare_sales(&shared, &seller, t.expires_unix + 61, |ids| {
        let mut store = shared.lock().unwrap();
        let original = support::receiver_plan(&store.journal, ids)?;
        store.change(|j| {
            let report = j
                .seller_settlements
                .get_mut(&t.id)
                .unwrap()
                .report
                .as_mut()
                .unwrap();
            report.fee_sat -= 1;
            report.refunded_sat += 1;
            Ok(())
        })?;
        Ok(original)
    });
    assert!(
        result
            .unwrap_err()
            .contains("differs from original settlement")
    );
    let mut store = shared.into_inner().unwrap();
    assert!(!store.journal.history.as_ref().unwrap().pending());
    assert!(seller.channel_terms(&t.id).is_some());
    assert_eq!(
        store.journal.seller_settlements[&t.id]
            .report
            .as_ref()
            .unwrap()
            .fee_sat,
        0
    );
    assert_eq!(
        retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap(),
        1
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
            .fee_sat,
        0
    );
}
