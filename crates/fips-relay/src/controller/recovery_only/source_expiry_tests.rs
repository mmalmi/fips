//! A source quote expires independently of the provider's connection state.
use super::*;
use crate::controller::transition_tests::{change, fixture, reload};

fn watch(store: &mut Store, old: &Outgoing, paused: bool, selected: bool) -> WatchedRoute {
    let mut offer = old.offer.clone();
    if selected {
        offer.trial = true;
    }
    let watch = WatchedRoute {
        destination: offer.destination.npub(),
        max_rate_msat_per_kib: offer.price.msat,
        billing: offer.billing,
        paused,
        pending: Some(offer.clone()),
        selected_trial: selected.then(|| old.purchase.contract.id.clone()),
    };
    store
        .change(|j| {
            if selected {
                j.version |= journal::SELECTED_TRIAL_VERSION;
                j.requested.insert(offer.id.clone(), offer.clone());
                j.outgoing.get_mut(&old.purchase.contract.id).unwrap().offer = offer;
            }
            j.watched_routes
                .insert(watch.destination.clone(), watch.clone());
            Controller::validate_journal(j, &j.policy, j.local)
        })
        .unwrap();
    watch
}

#[test]
fn expiry_detaches_exact_pending_watches_without_erasing_financial_history() {
    for (paused, selected) in [(false, false), (true, false), (false, true), (true, true)] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let expected = watch(&mut store, &old, paused, selected);
        let offer = expected.pending.as_ref().unwrap();
        let funding = serde_json::to_value(&store.journal.funding).unwrap();
        let outgoing = serde_json::to_value(&store.journal.outgoing).unwrap();
        let capital = Controller::capital(&store.journal).unwrap();
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            !store
                .withdraw_expired_purchases(offer.expires_unix - 1, |_| Ok(()))
                .unwrap()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);

        assert!(
            store
                .withdraw_expired_purchases(offer.expires_unix, |j| {
                    assert!(j.watched_routes[&expected.destination].pending.is_none());
                    assert!(j.recovery_only.contains(&offer.id));
                    Ok(())
                })
                .unwrap(),
            "the expired pending Watch must not require native peer eviction"
        );
        let mut detached = expected.clone();
        detached.pending = None;
        assert!(store.journal.watched_routes[&expected.destination] == detached);
        assert_eq!(
            serde_json::to_value(&store.journal.funding).unwrap(),
            funding
        );
        assert_eq!(
            serde_json::to_value(&store.journal.outgoing).unwrap(),
            outgoing
        );
        assert_eq!(Controller::capital(&store.journal).unwrap(), capital);
        assert!(
            !Controller::finish_acceptance(&mut store.journal, &old.purchase.contract.id).unwrap()
        );
        let mut late = old.clone();
        late.offer = offer.clone();
        assert!(Controller::record_purchase(&mut store.journal, late).is_err());
        assert!(
            Controller::complete_watched_purchase(
                &mut store.journal,
                &expected.destination,
                expected.clone(),
                &old.purchase,
            )
            .is_err()
        );
        let mut store = reload(store);
        assert!(store.journal.watched_routes[&expected.destination] == detached);
        let persisted = serde_json::to_value(&store.journal).unwrap();
        assert!(
            !store
                .withdraw_expired_purchases(offer.expires_unix - 1, |_| Ok(()))
                .unwrap()
        );
        assert!(
            !store
                .withdraw_expired_purchases(offer.expires_unix, |_| Ok(()))
                .unwrap()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), persisted);
    }
}

#[test]
fn expired_source_watch_releases_only_the_routing_owner_of_unopened_funding() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let expected = watch(&mut store, &old, false, false);
    store
        .change(|j| {
            j.outgoing.clear();
            j.funding.get_mut(&old.funding_id).unwrap().funded = None;
            Ok(())
        })
        .unwrap();
    let original = store.journal.funding[&old.funding_id].clone();
    let funding = serde_json::to_value(&store.journal.funding).unwrap();
    let capital = Controller::capital(&store.journal).unwrap();
    assert!(!Controller::abandoned_funding(&store.journal, &original));
    assert!(
        store
            .withdraw_expired_purchases(old.offer.expires_unix, |_| Ok(()))
            .unwrap()
    );
    assert!(Controller::abandoned_funding(&store.journal, &original));
    assert!(
        store.journal.watched_routes[&expected.destination]
            .pending
            .is_none()
    );
    assert_eq!(
        serde_json::to_value(&store.journal.funding).unwrap(),
        funding
    );
    assert_eq!(Controller::capital(&store.journal).unwrap(), capital);
    assert!(!root.path().join("wallet").exists());
    reload(store);
}

#[test]
fn expired_source_watch_does_not_override_live_transition_ownership() {
    for renewal in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        if renewal {
            store
                .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
                .unwrap();
        } else {
            store
                .change(|j| Controller::reserve_route_change(j, change(&old)))
                .unwrap();
        }
        watch(&mut store, &old, false, false);
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            !store
                .withdraw_expired_purchases(old.offer.expires_unix, |_| Ok(()))
                .unwrap()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        reload(store);
    }
}

#[test]
fn source_expiry_checkpoint_survives_failed_local_close() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let expected = watch(&mut store, &old, true, true);
    let capital = Controller::capital(&store.journal).unwrap();
    assert_eq!(
        store.withdraw_expired_purchases(old.offer.expires_unix, |j| {
            assert!(j.watched_routes[&expected.destination].pending.is_none());
            assert!(j.recovery_only.contains(&old.offer.id));
            Err("injected source close failure".into())
        }),
        Err("injected source close failure".into())
    );
    assert!(!store.ready);
    assert!(store.ensure_ready().is_err());
    assert_eq!(Controller::capital(&store.journal).unwrap(), capital);
    let store = reload(store);
    let saved = &store.journal.watched_routes[&expected.destination];
    assert!(saved.paused && saved.pending.is_none());
    assert_eq!(saved.selected_trial, expected.selected_trial);
    assert!(store.journal.recovery_only.contains(&old.offer.id));
}
