use super::*;
use crate::controller::{retirement_tests, transition_tests};
use fips_core::node::{
    ForwardingOutcome, OriginatedSessionAdmission, OriginatedSessionIntent,
    OriginatedSessionObserver,
};

fn fixture(root: &Path) -> (Store, Outgoing, BuyerAuthorizer, DurableRelay) {
    let (mut store, mut old, buyer, seller) = retirement_tests::fixture(root);
    old.offer.trial = true;
    store
        .journal
        .outgoing
        .insert(old.purchase.contract.id.clone(), old.clone());
    store
        .journal
        .requested
        .insert(old.offer.id.clone(), old.offer.clone());
    let watch = WatchedRoute {
        billing: old.offer.billing,
        destination: old.offer.destination.npub(),
        max_rate_msat_per_kib: 8192,
        paused: false,
        pending: Some(old.offer.clone()),
        selected_trial: None,
    };
    store
        .journal
        .watched_routes
        .insert(watch.destination.clone(), watch.clone());
    Controller::complete_watched_purchase(
        &mut store.journal,
        &watch.destination,
        watch.clone(),
        &old.purchase,
    )
    .unwrap();
    store.persist().unwrap();
    (transition_tests::reload(store), old, buyer, seller)
}

fn consume(buyer: &BuyerAuthorizer, old: &Outgoing, bytes: usize) {
    let OriginatedSessionAdmission::Track(token) = buyer.prepare(&OriginatedSessionIntent {
        source: old.offer.buyer,
        destination: *old.offer.destination.node_addr(),
        next_hop: old.offer.provider,
        session_bytes: bytes,
    }) else {
        panic!("real buyer admission");
    };
    buyer.complete(token, ForwardingOutcome::Submitted);
}

fn replacement(
    store: &mut Store,
    old: &Outgoing,
    buyer: &BuyerAuthorizer,
    max_units: u64,
    trial: bool,
) -> Outgoing {
    let mut next = old.clone();
    next.offer.id = format!("replacement-{}", old.offer.id);
    next.offer.expires_unix += 1;
    next.offer.max_units = max_units;
    next.offer.trial = trial;
    next.purchase.contract = contract_from_offer(&next.offer, &next.purchase.channel).unwrap();
    let change: RouteChange = serde_json::from_value(serde_json::json!({
        "offer": next.offer, "previous": [old.purchase], "prepared": true,
        "paused": false, "stopped_remotes": []
    }))
    .unwrap();
    store
        .journal
        .route_changes
        .insert(next.offer.id.clone(), change);
    store
        .journal
        .outgoing
        .get_mut(&old.purchase.contract.id)
        .unwrap()
        .retired = true;
    store.journal.requested.remove(&old.offer.id);
    store
        .journal
        .requested
        .insert(next.offer.id.clone(), next.offer.clone());
    store
        .journal
        .outgoing
        .insert(next.purchase.contract.id.clone(), next.clone());
    store
        .journal
        .watched_routes
        .get_mut(&old.offer.destination.npub())
        .unwrap()
        .pending = Some(next.offer.clone());
    buyer.close_quote(&old.purchase.contract.id).unwrap();
    buyer.accept_quote(next.purchase.contract.clone()).unwrap();
    next
}

#[test]
fn repeated_same_channel_trial_replacement_and_reload_preserve_exact_remainder() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, mut old, mut buyer, _) = fixture(root.path());
    let mut used = 0;
    for bytes in [1234, 789, 456] {
        consume(&buyer, &old, bytes);
        used += bytes as u64;
        let remaining = old.offer.max_units - bytes as u64;
        let next = replacement(&mut store, &old, &buyer, remaining, true);
        let id = old.offer.destination.npub();
        let pending = store.journal.watched_routes[&id].clone();
        assert_eq!(
            pending.selected_trial.as_ref(),
            Some(&old.purchase.contract.id)
        );
        assert!(
            Controller::interrupted_trial_hint(&store.journal, &pending)
                .unwrap()
                .is_none()
        );
        Controller::complete_watched_purchase(&mut store.journal, &id, pending, &next.purchase)
            .unwrap();
        store.persist().unwrap();
        store = transition_tests::reload(store);
        drop(buyer);
        buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
        let watch = &store.journal.watched_routes[&id];
        assert_eq!(
            watch.selected_trial.as_ref(),
            Some(&next.purchase.contract.id)
        );
        let hint = Controller::interrupted_trial_hint(&store.journal, watch)
            .unwrap()
            .unwrap();
        assert_eq!(hint, next.offer);
        assert_eq!(buyer.retained_quota(&hint), Ok(Some((true, 30_000 - used))));
        assert_eq!(
            buyer.retained_quota(&old.offer),
            Ok(Some((false, remaining)))
        );
        assert_eq!(buyer.remaining_budget_sat(), Some(1024));
        assert_eq!(store.journal.funding.len(), 1);
        old = next;
    }
    let remaining = old.offer.max_units;
    consume(&buyer, &old, remaining as usize);
    buyer.close_quote(&old.purchase.contract.id).unwrap();
    drop(buyer);
    let buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
    let watch = &store.journal.watched_routes[&old.offer.destination.npub()];
    let hint = Controller::interrupted_trial_hint(&store.journal, watch)
        .unwrap()
        .unwrap();
    assert_eq!(buyer.retained_quota(&hint), Ok(Some((false, 0))));
}

#[test]
fn selected_trial_is_pinned_until_a_current_full_acceptance_clears_it() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = fixture(root.path());
    consume(&buyer, &old, 1234);
    let full = replacement(&mut store, &old, &buyer, 30_000, false);
    store.persist().unwrap();
    store = transition_tests::reload(store);
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        0
    );
    assert_eq!(buyer.retained_quota(&old.offer), Ok(Some((false, 28_766))));
    let id = old.offer.destination.npub();
    let expected = store.journal.watched_routes[&id].clone();
    store.journal.watched_routes.get_mut(&id).unwrap().paused = true;
    assert!(
        Controller::complete_watched_purchase(
            &mut store.journal,
            &id,
            expected.clone(),
            &full.purchase
        )
        .is_err()
    );
    let paused = &store.journal.watched_routes[&id];
    assert_eq!(
        paused.selected_trial.as_ref(),
        Some(&old.purchase.contract.id)
    );
    assert!(
        Controller::interrupted_trial_hint(&store.journal, paused)
            .unwrap()
            .is_none()
    );
    store.journal.watched_routes.get_mut(&id).unwrap().paused = false;
    Controller::complete_watched_purchase(&mut store.journal, &id, expected, &full.purchase)
        .unwrap();
    store.persist().unwrap();
    store = transition_tests::reload(store);
    assert!(store.journal.watched_routes[&id].selected_trial.is_none());
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    assert!(
        !store
            .journal
            .outgoing
            .contains_key(&old.purchase.contract.id)
    );
    assert!(store.journal.version & journal::SELECTED_TRIAL_VERSION != 0);
    transition_tests::reload(store);
}

#[test]
fn trial_pointer_requires_exact_accepted_accounting_and_format_fence() {
    let root = tempfile::tempdir().unwrap();
    let (store, old, _, _) = fixture(root.path());
    for changed in 0..6 {
        let mut j = store.journal.clone();
        let id = old.offer.destination.npub();
        match changed {
            0 => {
                j.version &= !journal::SELECTED_TRIAL_VERSION;
            }
            1 => {
                j.outgoing.remove(&old.purchase.contract.id);
            }
            2 => {
                j.outgoing
                    .get_mut(&old.purchase.contract.id)
                    .unwrap()
                    .accepted = false;
            }
            3 => {
                j.outgoing
                    .get_mut(&old.purchase.contract.id)
                    .unwrap()
                    .offer
                    .trial = false;
            }
            4 => {
                j.outgoing
                    .get_mut(&old.purchase.contract.id)
                    .unwrap()
                    .offer
                    .buyer = old.offer.provider;
            }
            _ => {
                j.watched_routes.get_mut(&id).unwrap().selected_trial = Some("missing".into());
            }
        }
        let watch = &j.watched_routes[&id];
        assert!(Controller::interrupted_trial_hint(&j, watch).is_err());
        assert!(Controller::validate_journal(&j, &j.policy, j.local).is_err());
    }
}
