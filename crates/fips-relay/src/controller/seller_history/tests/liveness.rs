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

#[tokio::test]
async fn receiver_retirement_keeps_reads_live_and_retries_settlement() {
    let root = tempfile::tempdir().unwrap();
    let controller =
        Arc::new(super::super::super::refresh::tests::disconnected_controller(root.path()).await);
    let (_, old) = super::super::super::transition_tests::fixture(&root.path().join("fixture"));
    let peer = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let stranger = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let mut template = old.purchase.channel;
    template.buyer = *peer.node_addr();
    let (retiring, retained) = {
        let mut store = controller.store.lock().unwrap();
        let retiring = append(&mut store, &controller.services.seller, &template, 1, true);
        template.expires_unix += 3600;
        let retained = append(&mut store, &controller.services.seller, &template, 2, false);
        prepare_sales(
            &mut store,
            &controller.services.seller,
            retiring.expires_unix + 61,
        )
        .unwrap();
        (retiring, retained)
    };
    let seal = serde_json::to_vec(&ControllerRequest::Seal {
        channel_id: retained.id.clone(),
    })
    .unwrap();
    let journal = root.path().join("controller/controller.json");
    let saved = std::fs::read(&journal).unwrap();
    let worker = controller.clone();
    let request = seal.clone();
    let rt = tokio::runtime::Handle::current();
    let retired = tokio::task::spawn_blocking(move || {
        Store::resume_sales(
            &worker.store,
            &worker.services.seller,
            |_| panic!("saved intent"),
            |p| {
                {
                    let mut store = worker
                        .store
                        .try_lock()
                        .map_err(|_| "receiver retirement blocks controller reads")?;
                    assert!(store.journal.seller_settlements.contains_key(&retiring.id));
                    assert!(
                        store.change(|_| Ok(())).is_err(),
                        "handoff must fence writes"
                    );
                    store.ready = false;
                    assert_eq!(
                        store.ensure_ready().unwrap_err(),
                        "controller journal suspended"
                    );
                    store.ready = true;
                }
                rt.block_on(async {
                    assert!(worker.snapshot().await.unwrap().history.unwrap().pending());
                    assert!(matches!(
                        worker.handle(peer, &request).await,
                        ControllerResponse::Pending
                    ));
                    assert!(worker.last_error.lock().unwrap().is_none());
                    assert!(matches!(
                        worker.handle(stranger, &request).await,
                        ControllerResponse::Rejected
                    ));
                    let mut payment = worker.snapshot().await.unwrap().seller_settlements
                        [&retained.id]
                        .payment
                        .clone()
                        .unwrap();
                    payment.balance += 1;
                    let invalid_payment = serde_json::to_vec(&ControllerRequest::Settle {
                        channel_id: retained.id.clone(),
                        payment: Box::new(payment),
                    })
                    .unwrap();
                    assert!(matches!(
                        worker.handle(peer, &invalid_payment).await,
                        ControllerResponse::Rejected
                    ));
                    assert!(matches!(
                        worker.handle(peer, b"invalid").await,
                        ControllerResponse::Rejected
                    ));
                    worker.store.lock().unwrap().ready = false;
                    assert!(matches!(
                        worker.handle(peer, &request).await,
                        ControllerResponse::Rejected
                    ));
                    worker.store.lock().unwrap().ready = true;
                    assert_eq!(std::fs::read(&journal).unwrap(), saved);
                });
                Ok(p.accounting.after.clone())
            },
        )
    })
    .await
    .unwrap();
    assert_eq!(retired, Ok(1));
    assert!(matches!(
        controller.handle(peer, &seal).await,
        ControllerResponse::Sealed { .. }
    ));
    let state = controller.snapshot().await.unwrap();
    assert!(!state.history.unwrap().pending());
    assert_eq!(state.seller_settlements.len(), 1);
    controller.services.endpoint.shutdown().await.unwrap();
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
