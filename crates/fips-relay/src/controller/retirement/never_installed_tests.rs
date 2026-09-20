use super::*;
use crate::controller::{retirement_tests, transition_tests};

use super::never_installed_regression::{incoming, stop};

#[test]
fn uninstalled_stopped_acceptance_retires_without_forwarding_or_losing_credit() {
    for boundary in 0..=1 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old, buyer, seller) = retirement_tests::fixture(root.path());
        let prepared = incoming(&mut store, &old, &seller);
        let usage = seller.channel_usage(&prepared.channel.id).unwrap();
        let capital = Controller::capital(&store.journal).unwrap();
        assert!(seller.contract(&prepared.contract.id).is_none());
        stop(&mut store, &prepared);
        assert!(
            store
                .install_incoming_contract(&seller, &prepared, old.offer.expires_unix - 1)
                .is_err()
        );
        assert!(seller.contract(&prepared.contract.id).is_none());
        store
            .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
            .unwrap();
        let plan = store
            .journal
            .history
            .as_ref()
            .unwrap()
            .pending
            .clone()
            .unwrap();
        assert_eq!(plan.never_installed, vec![prepared.contract.clone()]);
        assert_eq!(plan.count(), 1);
        assert_eq!(plan.seller[0].after.units, crate::ledger::Usage::default());
        let mut unsupported = store.journal.clone();
        unsupported.version &= !journal::UNINSTALLED_RETIREMENT_VERSION;
        assert!(
            Controller::validate_journal(&unsupported, &unsupported.policy, unsupported.local)
                .is_err()
        );
        assert!(
            store
                .install_incoming_contract(&seller, &prepared, old.offer.expires_unix - 1)
                .is_err()
        );
        if boundary == 1 {
            let p = &plan.seller[0];
            seller
                .retire_closed_routes_with_uninstalled(
                    &p.channel,
                    p.through_unix,
                    &plan.never_installed,
                )
                .unwrap();
        }
        store = transition_tests::reload(store);
        drop(seller);
        let seller = DurableRelay::load(&root.path().join("seller")).unwrap();
        assert_eq!(store.resume_retirement(&buyer, &seller).unwrap(), 1);
        assert!(store.journal.incoming.is_empty());
        assert_eq!(
            store.journal.history.as_ref().unwrap().sellers[&prepared.channel.id],
            prepared.channel
        );
        assert_eq!(
            seller.channel_terms(&prepared.channel.id),
            Some(prepared.channel.clone())
        );
        assert_eq!(seller.channel_usage(&prepared.channel.id), Some(usage));
        assert!(seller.contract(&prepared.contract.id).is_none());
        assert_eq!(Controller::capital(&store.journal).unwrap(), capital);
        assert_eq!(buyer.remaining_budget_sat(), Some(1024));
        assert!(
            store
                .install_incoming_contract(&seller, &prepared, old.offer.expires_unix - 1)
                .is_err()
        );
        assert!(
            seller.add_contract(prepared.contract.clone()).is_err(),
            "durable replay floor rejects a delayed install"
        );
        assert_eq!(
            store
                .retire_routes(&buyer, &seller, old.offer.expires_unix)
                .unwrap(),
            0
        );
        // The upstream channel remains available for the ordinary settlement
        // handler via History.sellers, with the exact verified credit intact.
        assert_eq!(
            seller.seal_channel(&prepared.channel.id).unwrap().paid_msat,
            3_000
        );
        transition_tests::reload(store);
    }
}

#[test]
fn prepared_or_live_shared_prefix_blocks_uninstalled_retirement() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = retirement_tests::fixture(root.path());
    let pending = incoming(&mut store, &old, &seller);
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        0
    );
    // Ordinary activation still installs the exact current prepared agreement.
    store
        .install_incoming_contract(&seller, &pending, old.offer.expires_unix - 1)
        .unwrap();
    assert!(store.journal.incoming[&pending.contract.id].phase == Phase::Active);
    let mut next = pending.clone();
    next.offer.id = "uninstalled-later-sale".into();
    next.offer.expires_unix += 1;
    next.contract = contract_from_offer(&next.offer, &next.channel).unwrap();
    next.phase = Phase::Stopped;
    store
        .journal
        .incoming
        .insert(next.contract.id.clone(), next.clone());
    store.persist().unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, next.offer.expires_unix)
            .unwrap(),
        0,
        "an older live agreement on the shared channel blocks the complete expiry prefix"
    );
    assert!(seller.contract(&next.contract.id).is_none());
    stop(&mut store, &pending);
    seller.close_contract(&pending.contract.id).unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, next.offer.expires_unix)
            .unwrap(),
        2
    );
    assert_eq!(
        seller.channel_usage(&pending.channel.id).unwrap().paid_msat,
        3_000
    );
    transition_tests::reload(store);
}

#[test]
fn seller_rejects_changed_or_existing_uninstalled_evidence() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, _, seller) = retirement_tests::fixture(root.path());
    let pending = incoming(&mut store, &old, &seller);
    let before = seller.retired_route_evidence(&pending.channel.id).unwrap();
    for mutation in 0..3 {
        let mut contract = pending.contract.clone();
        match mutation {
            0 => contract.channel_id = "foreign".into(),
            1 => contract.expires_unix = pending.channel.expires_unix + 1,
            _ => contract.max_units = 0,
        }
        assert!(
            seller
                .retire_closed_routes_with_uninstalled(
                    &pending.channel.id,
                    old.offer.expires_unix,
                    &[contract]
                )
                .is_err()
        );
        assert_eq!(
            seller.retired_route_evidence(&pending.channel.id),
            Some(before)
        );
    }
    seller.add_contract(pending.contract.clone()).unwrap();
    seller.close_contract(&pending.contract.id).unwrap();
    assert!(
        seller
            .retire_closed_routes_with_uninstalled(
                &pending.channel.id,
                old.offer.expires_unix,
                std::slice::from_ref(&pending.contract)
            )
            .is_err()
    );
    assert!(
        seller.contract(&pending.contract.id).is_some(),
        "uninstalled input cannot replace existing accounting"
    );
}
