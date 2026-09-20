//! Expiry must withdraw transit purchases which have no local source Watch.
use super::*;
use crate::controller::refresh::tests::disconnected_controller;
use crate::ledger::BillingBasis;

async fn fixture(root: &Path, phase: Phase, expiry: u64) -> (Controller, Incoming) {
    let controller = disconnected_controller(root).await;
    let (_, old) = crate::controller::transition_tests::fixture(&root.join("fixture"));
    let local = *controller.services.endpoint.node_addr();
    let mut downstream = old.offer;
    downstream.buyer = local;
    downstream.expires_unix = expiry;
    downstream.billing = BillingBasis::ForwardingAttempt;
    let mut channel = old.purchase.channel;
    channel.id = "upstream".into();
    channel.buyer = NodeAddr::from_bytes([9; 16]);
    let mut offered = downstream.clone();
    offered.id = "unfinished-transit".into();
    offered.buyer = channel.buyer;
    offered.provider = local;
    offered.next_hop = downstream.provider;
    offered.path.insert(0, local);
    let incoming = Incoming {
        contract: contract_from_offer(&offered, &channel).unwrap(),
        offer: offered,
        channel,
        downstream: Some(downstream.clone()),
        verified_paid_msat: 0,
        phase,
        replaces: None,
        replacement_retired: false,
    };
    let saved = incoming.clone();
    controller
        .change(move |j| {
            j.requested.insert(downstream.id.clone(), downstream);
            j.incoming.insert(saved.contract.id.clone(), saved);
            Controller::validate_journal(j, &j.policy, j.local)
        })
        .await
        .unwrap();
    (controller, incoming)
}

#[tokio::test]
async fn upkeep_fences_expired_transit_without_a_local_watch() {
    for phase in [Phase::Prepared, Phase::Stopped] {
        let root = tempfile::tempdir().unwrap();
        let (controller, incoming) = fixture(root.path(), phase, now().unwrap() - 1).await;
        let offer = incoming.downstream.as_ref().unwrap();
        let before = controller.snapshot().await.unwrap();
        let capital = controller.funding_budget().await.unwrap();
        assert!(before.watched_routes.is_empty());
        // The old implementation rejects an expired purchase but never withdraws
        // it. Inspect durable authority even when unrelated recovery returns Err.
        let _ = controller.resume_pending().await;
        let after = controller.snapshot().await.unwrap();
        assert!(
            after.recovery_only.contains(&offer.id),
            "an expired transit purchase must not depend on a local source Watch"
        );
        assert!(after.incoming[&incoming.contract.id].phase == Phase::Stopped);
        assert_eq!(after.requested.get(&offer.id), Some(offer));
        assert_eq!(after.next_funding, before.next_funding);
        assert_eq!(controller.funding_budget().await.unwrap(), capital);
        assert!(after.outgoing.is_empty());
        assert!(!root.path().join("wallet").exists());
        let services = controller.services.clone();
        let policy = controller.policy.clone();
        drop(controller);
        let loaded = Controller::load(&root.path().join("controller"), policy, services).unwrap();
        assert!(
            loaded
                .snapshot()
                .await
                .unwrap()
                .recovery_only
                .contains(&offer.id)
        );
        loaded.services.endpoint.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn live_shared_transit_and_source_watch_keep_their_purchase() {
    for source_watch in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (controller, incoming) = fixture(root.path(), Phase::Stopped, now().unwrap() - 1).await;
        let mut live = incoming.clone();
        live.offer.id = "live-shared-sale".into();
        live.offer.expires_unix = now().unwrap() + 30;
        live.contract = contract_from_offer(&live.offer, &live.channel).unwrap();
        live.phase = Phase::Prepared;
        let offer = incoming.downstream.clone().unwrap();
        controller
            .change(move |j| {
                if source_watch {
                    let watch = WatchedRoute {
                        destination: offer.destination.npub(),
                        max_rate_msat_per_kib: offer.price.msat,
                        billing: offer.billing,
                        paused: false,
                        pending: Some(offer),
                        selected_trial: None,
                    };
                    j.watched_routes.insert(watch.destination.clone(), watch);
                } else {
                    j.incoming.insert(live.contract.id.clone(), live);
                }
                Controller::validate_journal(j, &j.policy, j.local)
            })
            .await
            .unwrap();
        let before = serde_json::to_value(controller.snapshot().await.unwrap()).unwrap();
        controller.withdraw_expired_purchases().await.unwrap();
        assert_eq!(
            serde_json::to_value(controller.snapshot().await.unwrap()).unwrap(),
            before
        );
        controller.services.endpoint.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn fresh_incoming_can_replace_an_expired_unowned_request() {
    let root = tempfile::tempdir().unwrap();
    let (controller, stopped) = fixture(root.path(), Phase::Stopped, now().unwrap() - 1).await;
    let old = stopped.downstream.clone().unwrap();
    let mut fresh = stopped.clone();
    fresh.offer.id = "fresh-upstream".into();
    fresh.offer.expires_unix = now().unwrap() + 30;
    fresh.contract = contract_from_offer(&fresh.offer, &fresh.channel).unwrap();
    fresh.phase = Phase::Prepared;
    let downstream = fresh.downstream.as_mut().unwrap();
    downstream.id = "fresh-downstream".into();
    downstream.expires_unix = fresh.offer.expires_unix;
    let wanted = downstream.clone();
    let fresh_id = fresh.contract.id.clone();
    controller
        .change(move |j| {
            j.incoming.insert(fresh.contract.id.clone(), fresh);
            Controller::validate_journal(j, &j.policy, j.local)
        })
        .await
        .unwrap();
    let financial = controller.funding_budget().await.unwrap();
    controller.withdraw_expired_purchases().await.unwrap();
    let after = controller.snapshot().await.unwrap();
    assert!(
        after.recovery_only.contains(&old.id),
        "a new offer for the same destination must not pin the expired request"
    );
    assert!(after.incoming[&fresh_id].phase == Phase::Prepared);
    let expected = wanted.clone();
    let reserved = controller
        .change(move |j| Controller::reserve_purchase(j, wanted))
        .await
        .unwrap();
    assert_eq!(
        reserved, expected,
        "fresh purchase must not normalize back to expired authority"
    );
    assert_eq!(controller.funding_budget().await.unwrap(), financial);
    controller.services.endpoint.shutdown().await.unwrap();
}

#[tokio::test]
async fn retained_watch_identity_keeps_the_expiry_checkpoint_loadable() {
    let root = tempfile::tempdir().unwrap();
    let (controller, incoming) = fixture(root.path(), Phase::Stopped, now().unwrap() - 1).await;
    let mut pending = incoming.downstream.clone().unwrap();
    // Journal validation permits a same-id pending offer with differing fields.
    // A withdrawal fence is keyed by id, so protect that owner
    // until its normal worker reconciles the terms as well as its identity.
    pending.max_units += 1;
    controller
        .change(move |j| {
            let watch = WatchedRoute {
                destination: pending.destination.npub(),
                max_rate_msat_per_kib: pending.price.msat,
                billing: pending.billing,
                paused: false,
                pending: Some(pending),
                selected_trial: None,
            };
            j.watched_routes.insert(watch.destination.clone(), watch);
            Controller::validate_journal(j, &j.policy, j.local)
        })
        .await
        .unwrap();
    let before = serde_json::to_value(controller.snapshot().await.unwrap()).unwrap();
    controller.withdraw_expired_purchases().await.unwrap();
    let after = controller.snapshot().await.unwrap();
    assert!(
        Controller::validate_journal(&after, &after.policy, after.local).is_ok(),
        "expiry must not create a checkpoint that its own loader rejects"
    );
    assert_eq!(serde_json::to_value(after).unwrap(), before);
    let services = controller.services.clone();
    let policy = controller.policy.clone();
    drop(controller);
    let loaded = Controller::load(&root.path().join("controller"), policy, services).unwrap();
    assert_eq!(
        serde_json::to_value(loaded.snapshot().await.unwrap()).unwrap(),
        before
    );
    loaded.services.endpoint.shutdown().await.unwrap();
}

#[test]
fn expiry_preserves_financial_evidence_and_incomplete_transition_owners() {
    use crate::controller::transition_tests::{change, fixture, reload};
    for owner in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        match owner {
            1 => store
                .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
                .unwrap(),
            2 => store
                .change(|j| Controller::reserve_route_change(j, change(&old)))
                .unwrap(),
            _ => (),
        }
        let before = serde_json::to_value(&store.journal).unwrap();
        let capital = Controller::capital(&store.journal).unwrap();
        let financial = serde_json::to_value(&store.journal.funding).unwrap();
        let changed = store
            .withdraw_expired_purchases(old.offer.expires_unix, |j| {
                assert!(j.recovery_only.contains(&old.offer.id));
                Ok(())
            })
            .unwrap();
        assert_eq!(changed, owner == 0);
        assert_eq!(Controller::capital(&store.journal).unwrap(), capital);
        assert_eq!(
            serde_json::to_value(&store.journal.funding).unwrap(),
            financial
        );
        if owner == 0 {
            assert!(
                !Controller::finish_acceptance(&mut store.journal, &old.purchase.contract.id)
                    .unwrap(),
                "a late accepted reply cannot reactivate the expired purchase"
            );
            assert!(Controller::record_purchase(&mut store.journal, old.clone()).is_err());
        } else {
            assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        }
        reload(store);
    }
}

#[tokio::test]
async fn expiry_fence_survives_local_close_failure_and_reload() {
    let root = tempfile::tempdir().unwrap();
    let (controller, incoming) = fixture(root.path(), Phase::Prepared, now().unwrap() - 1).await;
    let offer = incoming.downstream.as_ref().unwrap();
    let capital = controller.funding_budget().await.unwrap();
    {
        let mut store = controller.store.lock().unwrap();
        assert_eq!(
            store.withdraw_expired_purchases(now().unwrap(), |_| {
                Err("injected local closure failure".into())
            }),
            Err("injected local closure failure".into())
        );
        assert!(!store.ready);
    }
    let services = controller.services.clone();
    let policy = controller.policy.clone();
    drop(controller);
    let loaded = Controller::load(&root.path().join("controller"), policy, services).unwrap();
    let snapshot = loaded.snapshot().await.unwrap();
    assert!(snapshot.recovery_only.contains(&offer.id));
    assert!(snapshot.incoming[&incoming.contract.id].phase == Phase::Stopped);
    assert_eq!(loaded.funding_budget().await.unwrap(), capital);
    loaded.services.endpoint.shutdown().await.unwrap();
}
