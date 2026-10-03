//! Deterministic worker interleavings at the durable reservation boundary.
use super::*;

pub(super) fn fixture(directory: &Path) -> (Store, Outgoing) {
    let mut j = tests::unresolved_journal();
    let funding = j.funding.get_mut("test-1").unwrap();
    funding.created_unix = now().unwrap();
    funding.expires_unix = funding.created_unix + j.policy.channel_lifetime_secs;
    let channel = ChannelTerms {
        id: "channel".into(),
        buyer: j.local,
        mint_url: j.policy.mint_url.clone(),
        capacity_sat: funding.capacity_sat,
        grace_msat: funding.grace_msat,
        expires_unix: funding.expires_unix,
    };
    funding.funded = Some(Funded {
        wallet_operation_id: "fixture-operation-1".into(),
        wallet_cost: cashu_service::CashuSendCost {
            token_amount_sat: 32,
            swap_fee_sat: 0,
            wallet_debit_sat: 32,
        },
        terms: channel.clone(),
        // This fixture tests journal transitions, not signature verification.
        opening: CashuSpilmanPayment {
            channel_id: channel.id.clone(),
            balance: 0,
            signature: "fixture".into(),
            params: None,
            funding_proofs: None,
        },
    });
    let destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let offer = RouteOffer {
        id: "old-offer".into(),
        buyer: j.local,
        provider: funding.provider,
        destination,
        next_hop: *destination.node_addr(),
        path: vec![funding.provider, *destination.node_addr()],
        price: crate::ledger::BytePrice {
            msat: 1024,
            per_bytes: 1024,
        },
        billing: Default::default(),
        trial: false,
        expires_unix: channel.expires_unix,
        max_units: 30_000,
        mint_url: channel.mint_url.clone(),
        receiver_pubkey_hex: funding.receiver_pubkey_hex.clone(),
        capacity_sat: channel.capacity_sat,
        grace_msat: channel.grace_msat,
    };
    let old = Outgoing {
        purchase: Purchase {
            provider: offer.provider,
            contract: contract_from_offer(&offer, &channel).unwrap(),
            channel,
        },
        offer: offer.clone(),
        funding_id: funding.id.clone(),
        accepted: true,
        retired: false,
    };
    j.requested.insert(offer.id.clone(), offer);
    j.outgoing
        .insert(old.purchase.contract.id.clone(), old.clone());
    Controller::validate_journal(&j, &j.policy, j.local).unwrap();
    let mut store = Store {
        _owner: acquire_owner(directory).unwrap(),
        directory: directory.into(),
        control_obligations: ControlObligations::from_journal(&j).unwrap(),
        journal: j,
        ready: true,
    };
    store.persist().unwrap();
    (store, old)
}

pub(super) fn change(old: &Outgoing) -> RouteChange {
    let mut offer = old.offer.clone();
    offer.id = "replacement".into();
    offer.price.msat += 1;
    serde_json::from_value(serde_json::json!({
        "offer":offer, "previous":[old.purchase], "prepared":false,
        "paused":false, "stopped_remotes":[]
    }))
    .unwrap()
}

pub(super) fn reload(store: Store) -> Store {
    let directory = store.directory.clone();
    let before = serde_json::to_value(&store.journal).unwrap();
    drop(store);
    let journal: Journal =
        serde_json::from_slice(&std::fs::read(directory.join("controller.json")).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&journal).unwrap(), before);
    Controller::validate_journal(&journal, &journal.policy, journal.local).unwrap();
    Store {
        _owner: acquire_owner(&directory).unwrap(),
        directory,
        control_obligations: ControlObligations::from_journal(&journal).unwrap(),
        journal,
        ready: true,
    }
}

#[test]
fn renewal_wins_before_a_route_worker_saves_its_old_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let stale = change(&old);
    store
        .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
        .unwrap();
    let mut store = reload(store);
    let before = serde_json::to_value(&store.journal).unwrap();
    assert!(
        store
            .change(|j| Controller::reserve_route_change(j, stale))
            .is_err(),
        "a route worker cannot also reserve the channel that renewal owns"
    );
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
    reload(store);
}

#[test]
fn route_change_wins_before_renewal_saves_its_due_channel() {
    for paused in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let mut intent = change(&old);
        intent.paused = paused;
        store
            .change(|j| Controller::reserve_route_change(j, intent))
            .unwrap();
        let mut store = reload(store);
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            store
                .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
                .is_err(),
            "renewal cannot settle a channel reserved by an unfinished route change"
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        reload(store);
    }
}

#[test]
fn route_reservation_rechecks_acceptance_instead_of_trusting_a_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let stale = change(&old);
    store
        .change(|j| {
            j.outgoing
                .get_mut(&old.purchase.contract.id)
                .unwrap()
                .accepted = false;
            Ok(())
        })
        .unwrap();
    assert!(
        store
            .change(|j| Controller::reserve_route_change(j, stale))
            .is_err()
    );
    assert!(store.journal.route_changes.is_empty());
    reload(store);
}

#[test]
fn a_new_settlement_invalidates_the_route_workers_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let stale = change(&old);
    store
        .change(|j| {
            let purchase = serde_json::to_value(&old.purchase).unwrap();
            j.buyer_settlements.insert(
                old.purchase.channel.id.clone(),
                serde_json::from_value(serde_json::json!({
                    "provider": purchase["provider"], "channel": old.purchase.channel,
                    "usage":null, "payment":null, "report":null, "refunded":false
                }))
                .unwrap(),
            );
            Ok(())
        })
        .unwrap();
    let mut store = reload(store);
    assert!(
        store
            .change(|j| Controller::reserve_route_change(j, stale))
            .is_err()
    );
    assert!(store.journal.route_changes.is_empty());
    reload(store);
}

#[test]
fn a_new_trial_agreement_cannot_be_renewed_from_an_old_due_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    store
        .change(|j| {
            let outgoing = j.outgoing.get_mut(&old.purchase.contract.id).unwrap();
            outgoing.offer.trial = true;
            j.requested
                .insert(outgoing.offer.id.clone(), outgoing.offer.clone());
            Ok(())
        })
        .unwrap();
    let mut store = reload(store);
    assert!(
        store
            .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
            .is_err()
    );
    assert!(store.journal.renewals.is_empty());
    reload(store);
}

#[test]
fn route_reservation_rejects_a_replaced_predecessor() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let stale = change(&old);
    store
        .change(|j| {
            let current = j.outgoing.get_mut(&old.purchase.contract.id).unwrap();
            current.purchase.contract.expires_unix -= 1;
            current.offer.expires_unix -= 1;
            j.requested
                .insert(current.offer.id.clone(), current.offer.clone());
            Ok(())
        })
        .unwrap();
    let mut store = reload(store);
    assert!(
        store
            .change(|j| Controller::reserve_route_change(j, stale))
            .is_err()
    );
    assert!(store.journal.route_changes.is_empty());
    reload(store);
}

pub(super) fn prepare_replacement(j: &mut Journal, old: &Outgoing, accepted: bool) {
    // Model the real journal boundary after predecessor retirement and before
    // (or after) the provider's Accept reply. The channel is intentionally reused.
    let mut value = serde_json::to_value(&j.route_changes["replacement"]).unwrap();
    value["prepared"] = true.into();
    let intent: RouteChange = serde_json::from_value(value).unwrap();
    let replacement = Outgoing {
        offer: intent.offer.clone(),
        purchase: Purchase {
            contract: contract_from_offer(&intent.offer, &old.purchase.channel).unwrap(),
            ..old.purchase.clone()
        },
        accepted,
        ..old.clone()
    };
    j.outgoing
        .get_mut(&old.purchase.contract.id)
        .unwrap()
        .retired = true;
    j.requested.remove(&old.offer.id);
    j.requested
        .insert(intent.offer.id.clone(), intent.offer.clone());
    j.outgoing
        .insert(replacement.purchase.contract.id.clone(), replacement);
    j.route_changes.insert(intent.offer.id.clone(), intent);
}

#[test]
fn renewal_waits_for_replacement_acceptance_then_reuses_the_channel() {
    for accepted in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        store
            .change(|j| {
                Controller::reserve_route_change(j, change(&old))?;
                prepare_replacement(j, &old, accepted);
                Ok(())
            })
            .unwrap();
        let mut store = reload(store);
        assert_eq!(
            store
                .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
                .is_ok(),
            accepted
        );
        assert_eq!(store.journal.funding.len(), 1);
        assert_eq!(
            store.journal.outgoing.len(),
            2,
            "retain both agreements' evidence"
        );
        reload(store);
    }
}

fn add_other_channel(j: &mut Journal, old: &Outgoing) -> Outgoing {
    let mut other = old.clone();
    other.purchase.provider = NodeAddr::from_bytes([3; 16]);
    other.purchase.channel.id = "other-channel".into();
    other.offer.id = "other-offer".into();
    other.offer.provider = other.purchase.provider;
    let destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    other.offer.destination = destination;
    other.offer.next_hop = *destination.node_addr();
    other.offer.path = vec![other.purchase.provider, *destination.node_addr()];
    other.purchase.contract = contract_from_offer(&other.offer, &other.purchase.channel).unwrap();
    other.funding_id = "test-2".into();
    let mut funding = j.funding[&old.funding_id].clone();
    funding.id = other.funding_id.clone();
    funding.provider = other.purchase.provider;
    let funded = funding.funded.as_mut().unwrap();
    funded.wallet_operation_id = "fixture-operation-2".into();
    funded.terms = other.purchase.channel.clone();
    funded.opening.channel_id = other.purchase.channel.id.clone();
    j.policy.max_locked_sat *= 2;
    j.next_funding += 1;
    j.funding.insert(funding.id.clone(), funding);
    j.requested
        .insert(other.offer.id.clone(), other.offer.clone());
    j.outgoing
        .insert(other.purchase.contract.id.clone(), other.clone());
    other
}

#[test]
fn a_route_transition_does_not_reserve_an_unrelated_channel() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    store
        .change(|j| {
            let other = add_other_channel(j, &old);
            Controller::reserve_route_change(j, change(&old))?;
            Controller::reserve_renewal(j, other.purchase.channel.id)
        })
        .unwrap();
    reload(store);
}

#[test]
fn route_change_and_reclaim_cannot_acquire_the_same_provider_in_either_order() {
    for reclaim_first in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let other = store
            .change(|j| {
                let other = add_other_channel(j, &old);
                j.outgoing.remove(&other.purchase.contract.id);
                j.funding.get_mut(&other.funding_id).unwrap().funded = None;
                j.version |= journal::RECOVERY_ONLY_VERSION;
                j.recovery_only.insert(other.offer.id.clone());
                Ok(other)
            })
            .unwrap();
        let funding = store.journal.funding[&other.funding_id].clone();
        let mut replacement = change(&old);
        replacement.offer.provider = other.purchase.provider;
        replacement.offer.path[0] = other.purchase.provider;
        if reclaim_first {
            store
                .change(|j| Controller::prepare_funding_reclaim(j, &funding))
                .unwrap();
            store = reload(store);
            let before = serde_json::to_value(&store.journal).unwrap();
            assert!(
                store
                    .change(|j| Controller::reserve_route_change(j, replacement))
                    .is_err(),
                "a route change cannot acquire a provider being reclaimed"
            );
            assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        } else {
            store
                .change(|j| Controller::reserve_route_change(j, replacement))
                .unwrap();
            store = reload(store);
            let before = serde_json::to_value(&store.journal).unwrap();
            assert!(
                store
                    .change(|j| Controller::prepare_funding_reclaim(j, &funding))
                    .is_err(),
                "a selected provider cannot be reclaimed before withdrawal"
            );
            assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        }
        assert!(Controller::routing_eligible(
            &store.journal,
            &store.journal.outgoing[&old.purchase.contract.id]
        ));
        reload(store);
    }
}

#[test]
fn reload_rejects_overlapping_unfinished_route_and_renewal_intents() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    store
        .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
        .unwrap();
    // A journal from the previous race must fail closed, retaining all records.
    store
        .change(|j| {
            j.route_changes.insert("replacement".into(), change(&old));
            Ok(())
        })
        .unwrap();
    let bytes = std::fs::read(store.directory.join("controller.json")).unwrap();
    let saved: Journal = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        Controller::validate_journal(&saved, &saved.policy, saved.local),
        Err("conflicting route and renewal intents".into())
    );
    assert_eq!(
        std::fs::read(store.directory.join("controller.json")).unwrap(),
        bytes
    );
}

#[test]
fn changing_provider_and_renewing_its_shared_channel_exclude_each_other() {
    for renewal_first in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let other = store.change(|j| Ok(add_other_channel(j, &old))).unwrap();
        let mut intent = change(&old);
        intent.offer.provider = other.purchase.provider;
        intent.offer.path[0] = other.purchase.provider;
        if renewal_first {
            store
                .change(|j| Controller::reserve_renewal(j, other.purchase.channel.id.clone()))
                .unwrap();
            let mut store = reload(store);
            assert!(
                store
                    .change(|j| Controller::reserve_route_change(j, intent))
                    .is_err(),
                "replacement cannot reuse a target provider channel while it renews"
            );
            reload(store);
        } else {
            store
                .change(|j| Controller::reserve_route_change(j, intent))
                .unwrap();
            let mut store = reload(store);
            assert!(
                store
                    .change(|j| Controller::reserve_renewal(j, other.purchase.channel.id.clone()))
                    .is_err(),
                "renewal cannot close the channel a replacement is about to reuse"
            );
            reload(store);
        }
    }
}
