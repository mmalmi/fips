//! Expired reservations with no wallet intent can release only their metadata slots.
use super::*;
use crate::controller::refresh::tests::disconnected_controller;

async fn reservation(root: &Path, expires: u64) -> (Controller, RouteOffer) {
    let controller = disconnected_controller(root).await;
    let (_, old) = crate::controller::transition_tests::fixture(&root.join("fixture"));
    let mut offer = old.offer;
    offer.buyer = *controller.services.endpoint.node_addr();
    offer.expires_unix = expires;
    let saved = offer.clone();
    controller
        .change(move |j| {
            j.requested.insert(saved.id.clone(), saved);
            Ok(())
        })
        .await
        .unwrap();
    (controller, offer)
}

async fn withdraw(controller: &Controller, offer: &RouteOffer) {
    let offer = offer.clone();
    controller
        .change(move |j| {
            let watch = WatchedRoute {
                billing: offer.billing,
                destination: offer.destination.npub(),
                max_rate_msat_per_kib: offer.price.msat,
                paused: false,
                pending: Some(offer),
            };
            j.watched_routes
                .insert(watch.destination.clone(), watch.clone());
            assert!(Controller::withdraw_watched_purchase(j, &watch)?);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn upkeep_retires_expired_unfunded_reservation_and_preserves_newer_watch() {
    let root = tempfile::tempdir().unwrap();
    let (controller, offer) = reservation(root.path(), now().unwrap() - 1).await;
    withdraw(&controller, &offer).await;
    let mut next = offer.clone();
    next.id = "newer-independent-authorization".into();
    next.provider = NodeAddr::from_bytes([9; 16]);
    next.path[0] = next.provider;
    next.expires_unix = now().unwrap() + 300;
    let saved = next.clone();
    controller
        .change(move |j| {
            j.requested.insert(saved.id.clone(), saved.clone());
            let watch = j.watched_routes.get_mut(&saved.destination.npub()).unwrap();
            watch.pending = Some(saved);
            watch.paused = true;
            Ok(())
        })
        .await
        .unwrap();
    let before = controller.snapshot().await.unwrap();
    let budget = controller.funding_budget().await.unwrap();
    controller.resume_pending().await.unwrap();
    let after = controller.snapshot().await.unwrap();
    assert!(
        !after.requested.contains_key(&offer.id),
        "expired never-funded reservation must release its bounded slot"
    );
    assert!(!after.recovery_only.contains(&offer.id));
    assert_eq!(after.requested.get(&next.id), Some(&next));
    assert!(after.watched_routes == before.watched_routes);
    assert_eq!(after.next_funding, before.next_funding);
    assert_eq!(controller.funding_budget().await.unwrap(), budget);
    assert!(
        Controller::retired_offer(&after, &offer),
        "retained expiry fence must reject stale replay even after a clock rollback"
    );
    assert_ne!(after.version & journal::RECOVERY_ONLY_VERSION, 0);
    let services = controller.services.clone();
    let policy = controller.policy.clone();
    drop(controller);
    let loaded = Controller::load(&root.path().join("controller"), policy, services).unwrap();
    loaded.resume_pending().await.unwrap();
    assert!(
        serde_json::to_value(loaded.snapshot().await.unwrap()).unwrap()
            == serde_json::to_value(after).unwrap()
    );
    assert!(!root.path().join("wallet").exists());
    loaded.services.endpoint.shutdown().await.unwrap();
}

fn unstarted_store(root: &Path, expiry: u64) -> (Store, RouteOffer) {
    let (mut store, old) = crate::controller::transition_tests::fixture(&root.join("controller"));
    store.journal.funding.clear();
    store.journal.outgoing.clear();
    let mut offer = old.offer;
    offer.expires_unix = expiry;
    store.journal.requested = [(offer.id.clone(), offer.clone())].into();
    store.journal.recovery_only.insert(offer.id.clone());
    store.journal.version |= journal::RECOVERY_ONLY_VERSION;
    store.persist().unwrap();
    (store, offer)
}

#[test]
fn expiry_floor_fences_a_delayed_worker_and_clock_rollback_without_new_funding() {
    let root = tempfile::tempdir().unwrap();
    let expiry = now().unwrap() + 60;
    let (mut store, offer) = unstarted_store(root.path(), expiry);
    let before_sequence = store.journal.next_funding;
    assert_eq!(store.retire_unfunded_reservations(expiry - 1).unwrap(), 0);
    assert_eq!(store.retire_unfunded_reservations(expiry).unwrap(), 1);
    let mut store = crate::controller::transition_tests::reload(store);
    assert!(
        offer.expires_unix > now().unwrap(),
        "wall clock is behind the retirement observation"
    );
    let before = serde_json::to_value(&store.journal).unwrap();
    assert!(
        store
            .change(|j| Controller::reserve_purchase(j, offer.clone()))
            .is_err()
    );
    assert!(Controller::check_purchase(&store.journal, &offer, None).is_err());
    assert_eq!(store.journal.next_funding, before_sequence);
    assert!(store.journal.funding.is_empty());
    assert_eq!(store.retire_unfunded_reservations(expiry).unwrap(), 0);
    assert!(serde_json::to_value(&store.journal).unwrap() == before);
    let mut fresh = offer;
    fresh.id = "fresh-permission".into();
    fresh.expires_unix = expiry + 1;
    store
        .change(|j| Controller::reserve_purchase(j, fresh))
        .unwrap();
    crate::controller::transition_tests::reload(store);
}

#[tokio::test]
async fn paused_worker_cannot_fund_after_expiry_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let (controller, offer) = reservation(root.path(), now().unwrap() + 60).await;
    Controller::check_purchase(&controller.snapshot().await.unwrap(), &offer, None).unwrap();
    let controller = Arc::new(controller);
    let worker = controller.clone();
    let captured = offer.clone();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        waiting.await.unwrap();
        worker.fund(&captured).await
    });
    withdraw(&controller, &offer).await;
    // Advance the cleanup observation only: the resumed production worker must
    // reject the retained fence even though its own wall clock is still earlier.
    assert_eq!(
        controller
            .store
            .lock()
            .unwrap()
            .retire_unfunded_reservations(offer.expires_unix)
            .unwrap(),
        1
    );
    let before = serde_json::to_value(controller.snapshot().await.unwrap()).unwrap();
    release.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(serde_json::to_value(controller.snapshot().await.unwrap()).unwrap() == before);
    assert!(!root.path().join("wallet").exists());
    controller.services.endpoint.shutdown().await.unwrap();
}

#[test]
fn a_funding_intent_appearing_before_cleanup_retains_the_whole_reservation() {
    for funded in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) =
            crate::controller::transition_tests::fixture(&root.path().join("controller"));
        store.journal.outgoing.clear();
        store
            .journal
            .requested
            .get_mut(&old.offer.id)
            .unwrap()
            .expires_unix = 1;
        store.journal.recovery_only.insert(old.offer.id.clone());
        store.journal.version |= journal::RECOVERY_ONLY_VERSION;
        if !funded {
            store
                .journal
                .funding
                .get_mut(&old.funding_id)
                .unwrap()
                .funded = None;
        }
        store.persist().unwrap();
        let before = serde_json::to_value(&store.journal).unwrap();
        let disk = std::fs::read(store.directory.join("controller.json")).unwrap();
        assert_eq!(
            store.retire_unfunded_reservations(now().unwrap()).unwrap(),
            0
        );
        assert!(serde_json::to_value(&store.journal).unwrap() == before);
        assert_eq!(
            std::fs::read(store.directory.join("controller.json")).unwrap(),
            disk
        );
        crate::controller::transition_tests::reload(store);
    }
}

#[test]
fn cleanup_preserves_older_uncertain_finances_and_their_completion_paths() {
    for funded in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, mut old) =
            crate::controller::transition_tests::fixture(&root.path().join("controller"));
        old.offer.expires_unix = 1;
        old.purchase.contract = contract_from_offer(&old.offer, &old.purchase.channel).unwrap();
        old.accepted = false;
        store
            .journal
            .requested
            .insert(old.offer.id.clone(), old.offer.clone());
        store.journal.outgoing = if funded {
            [(old.purchase.contract.id.clone(), old.clone())].into()
        } else {
            BTreeMap::new()
        };
        let intent = store.journal.funding.get_mut(&old.funding_id).unwrap();
        let committed = intent.funded.clone().unwrap();
        if !funded {
            intent.funded = None;
        }
        let captured_intent = intent.clone();
        store.journal.recovery_only.insert(old.offer.id.clone());
        let mut expired = old.offer.clone();
        expired.id = "never-funded-independent-offer".into();
        expired.provider = NodeAddr::from_bytes([9; 16]);
        expired.path[0] = expired.provider;
        expired.expires_unix = now().unwrap() - 1;
        store
            .journal
            .requested
            .insert(expired.id.clone(), expired.clone());
        store.journal.recovery_only.insert(expired.id.clone());
        store.journal.version = journal::RECOVERY_ONLY_VERSION | 5;
        let mut history = History::default();
        history.through_unix = 1;
        let mut channels = crate::controller::channel_history::ChannelHistory::default();
        channels.totals.through = 1;
        channels.totals.channels = 1;
        channels.totals.capacity_sat = 8;
        channels.totals.signed_sat = 2;
        channels.totals.refund_sat = 6;
        channels.totals.cost = cashu_service::CashuSendCost {
            token_amount_sat: 8,
            swap_fee_sat: 0,
            wallet_debit_sat: 8,
        };
        channels.totals.expires_through_unix = 1;
        history.channels = Some(channels);
        history.seller = Some(crate::controller::seller_history::SellerHistory::default());
        store.journal.history = Some(history);
        Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
            .unwrap();
        store.persist().unwrap();
        let mut expected = serde_json::to_value(&store.journal).unwrap();
        let budget = Controller::capital(&store.journal).unwrap();
        let id = expired.id.clone();
        expected["requested"].as_object_mut().unwrap().remove(&id);
        expected["recovery_only"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v != &id);
        expected["history"]["through_unix"] = expired.expires_unix.into();
        assert_eq!(
            store.retire_unfunded_reservations(now().unwrap()).unwrap(),
            1
        );
        assert!(
            serde_json::to_value(&store.journal).unwrap() == expected,
            "only exact metadata and expiry floor may change"
        );
        assert_eq!(Controller::capital(&store.journal).unwrap(), budget);
        let mut store = crate::controller::transition_tests::reload(store);
        store
            .change(|j| Controller::record_funding(j, captured_intent, committed))
            .unwrap();
        if funded {
            assert!(
                !store
                    .change(|j| Controller::finish_acceptance(j, &old.purchase.contract.id))
                    .unwrap()
            );
            assert!(store.journal.outgoing[&old.purchase.contract.id].accepted);
            assert!(Controller::settlement_terms(&store.journal, &old.purchase.channel.id).is_ok());
        }
        assert!(store.journal.buyer_settlements.is_empty());
        crate::controller::transition_tests::reload(store);
    }
}

#[test]
fn a_pending_real_retirement_blocks_cleanup_without_changing_evidence() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = crate::controller::retirement_tests::fixture(root.path());
    crate::controller::retirement_tests::replace(&mut store, &old, &buyer);
    let mut expired = old.offer.clone();
    expired.id = "independent-never-funded".into();
    expired.provider = NodeAddr::from_bytes([9; 16]);
    expired.path[0] = expired.provider;
    expired.expires_unix = 1;
    store
        .journal
        .requested
        .insert(expired.id.clone(), expired.clone());
    store.journal.recovery_only.insert(expired.id.clone());
    store.journal.version |= journal::RECOVERY_ONLY_VERSION;
    store
        .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
        .unwrap();
    let before = serde_json::to_value(&store.journal).unwrap();
    let disk = std::fs::read(store.directory.join("controller.json")).unwrap();
    assert!(store.retire_unfunded_reservations(now().unwrap()).is_err());
    assert!(serde_json::to_value(&store.journal).unwrap() == before);
    assert_eq!(
        std::fs::read(store.directory.join("controller.json")).unwrap(),
        disk
    );
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    let mut store = crate::controller::transition_tests::reload(store);
    let previous_floor = store.journal.history.as_ref().unwrap().through_unix;
    assert_eq!(
        store.retire_unfunded_reservations(now().unwrap()).unwrap(),
        1
    );
    assert_eq!(
        store.journal.history.as_ref().unwrap().through_unix,
        previous_floor
    );
    crate::controller::transition_tests::reload(store);
}

#[test]
fn live_shared_work_and_unmarked_requests_do_not_expire() {
    for kind in ["unmarked", "incoming", "change", "watch", "request"] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, offer) = unstarted_store(root.path(), 1);
        match kind {
            "unmarked" => {
                store.journal.recovery_only.clear();
            }
            "incoming" => {
                // A retained upstream contract must never lose its onward evidence,
                // including a stopped contract still awaiting settlement.
                let (_, mut old) =
                    crate::controller::transition_tests::fixture(&root.path().join("upstream"));
                let customer = NodeAddr::from_bytes([3; 16]);
                old.offer.buyer = customer;
                old.offer.provider = store.journal.local;
                old.offer.path[0] = store.journal.local;
                old.purchase.channel.buyer = customer;
                old.purchase.contract =
                    contract_from_offer(&old.offer, &old.purchase.channel).unwrap();
                let incoming: Incoming = serde_json::from_value(serde_json::json!({
                    "offer":old.offer,"channel":old.purchase.channel,
                    "contract":old.purchase.contract,"downstream":offer,
                    "phase":"Stopped","verified_paid_msat":0,
                    "replaces":null,"replacement_retired":false
                }))
                .unwrap();
                store
                    .journal
                    .incoming
                    .insert("retained-upstream".into(), incoming);
            }
            "change" => {
                let (_, old) =
                    crate::controller::transition_tests::fixture(&root.path().join("change"));
                let mut change = crate::controller::transition_tests::change(&old);
                change.offer = offer.clone();
                store.journal.route_changes.insert(offer.id.clone(), change);
            }
            "watch" => {
                let watch = WatchedRoute {
                    billing: offer.billing,
                    destination: offer.destination.npub(),
                    max_rate_msat_per_kib: offer.price.msat,
                    paused: true,
                    pending: Some(offer.clone()),
                };
                store
                    .journal
                    .watched_routes
                    .insert(watch.destination.clone(), watch);
            }
            "request" => {
                let mut shared = offer.clone();
                shared.id = "another-user-of-provider".into();
                shared.expires_unix = now().unwrap() + 60;
                store.journal.requested.insert(shared.id.clone(), shared);
            }
            _ => unreachable!(),
        }
        // These defensive reference checks are unit-level: production journal
        // validation additionally rejects contradictory or incomplete bindings.
        store.persist().unwrap();
        let before = serde_json::to_value(&store.journal).unwrap();
        assert_eq!(
            store.retire_unfunded_reservations(now().unwrap()).unwrap(),
            0,
            "{kind}"
        );
        assert!(serde_json::to_value(&store.journal).unwrap() == before);
    }
}

#[test]
fn a_full_book_of_never_funded_reservations_releases_capacity_as_one_batch() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, offer) = unstarted_store(root.path(), 1);
    for n in 1..MAX_ROUTES {
        let mut old = offer.clone();
        old.id = format!("abandoned-{n}");
        store.journal.recovery_only.insert(old.id.clone());
        store.journal.requested.insert(old.id.clone(), old);
    }
    store.persist().unwrap();
    let sequence = store.journal.next_funding;
    assert_eq!(store.journal.requested.len(), MAX_ROUTES);
    assert_eq!(
        store.retire_unfunded_reservations(now().unwrap()).unwrap(),
        MAX_ROUTES
    );
    let mut store = crate::controller::transition_tests::reload(store);
    assert!(store.journal.recovery_only.is_empty());
    assert!(store.journal.requested.is_empty());
    assert_eq!(store.journal.next_funding, sequence);
    let mut fresh = offer;
    fresh.id = "fresh-after-full-book".into();
    fresh.expires_unix = now().unwrap() + 60;
    store
        .change(|j| Controller::reserve_purchase(j, fresh))
        .unwrap();
    assert_eq!(
        Controller::capital(&store.journal).unwrap(),
        FundingBudget::default()
    );
    crate::controller::transition_tests::reload(store);
}
