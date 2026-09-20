//! Expiry authority stays under the controller lock through local custody checks.
use super::*;
use crate::controller::transition_tests::{fixture, reload};
use crate::ledger::Limits;

fn withdrawn(root: &Path) -> (Store, Outgoing, BuyerAuthorizer, FundingIntent, u64) {
    let (mut store, old) = fixture(&root.join("controller"));
    store.journal.outgoing.clear();
    let watch = WatchedRoute {
        billing: old.offer.billing,
        destination: old.offer.destination.npub(),
        max_rate_msat_per_kib: old.offer.price.msat,
        paused: false,
        pending: Some(old.offer.clone()),
        selected_trial: None,
    };
    store
        .journal
        .watched_routes
        .insert(watch.destination.clone(), watch.clone());
    store
        .change(|j| Controller::withdraw_watched_purchase(j, &watch))
        .unwrap();
    let buyer = BuyerAuthorizer::create(
        &root.join("buyer"),
        store.journal.local,
        64,
        Limits::default(),
    )
    .unwrap();
    let intent = store.journal.funding[&old.funding_id].clone();
    let timestamp = intent.expires_unix + 61;
    (store, old, buyer, intent, timestamp)
}

#[test]
fn expiry_intent_is_durable_before_refund_and_rejects_delayed_installation() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, intent, timestamp) = withdrawn(root.path());
    let budget = Controller::capital(&store.journal).unwrap();
    let funding = serde_json::to_value(&store.journal.funding).unwrap();
    let history = serde_json::to_value(&store.journal.history).unwrap();
    assert!(
        store
            .prepare_expiry_refund(&buyer, &intent, timestamp - 1)
            .is_err()
    );
    assert!(store.journal.buyer_settlements.is_empty());
    store
        .prepare_expiry_refund(&buyer, &intent, timestamp)
        .unwrap();
    let mut store = reload(store);
    let saved = &store.journal.buyer_settlements[&old.purchase.channel.id];
    assert!(saved.kind == SettlementKind::Expiry);
    assert!(!saved.refunded && !saved.released && !saved.terminal());
    assert!(saved.usage.is_none() && saved.payment.is_none() && saved.report.is_none());
    assert!(saved.wallet_refund_sat.is_none());
    assert_eq!(Controller::capital(&store.journal).unwrap(), budget);
    assert_eq!(
        serde_json::to_value(&store.journal.funding).unwrap(),
        funding
    );
    assert_eq!(
        serde_json::to_value(&store.journal.history).unwrap(),
        history
    );
    // The preceding format masks only 0x100 and rejects this newer history value.
    assert!(!matches!(
        store.journal.version & !journal::RECOVERY_ONLY_VERSION,
        2..=6
    ));
    assert!(
        Controller::install_funded_channel(
            &store.journal,
            &buyer,
            &old.offer,
            &intent.id,
            intent.funded.as_ref().unwrap()
        )
        .is_err()
    );
    assert_eq!(buyer.authorized_sat(&old.purchase.channel.id), None);
    let before = serde_json::to_value(&store.journal).unwrap();
    store
        .prepare_expiry_refund(&buyer, &intent, timestamp)
        .unwrap();
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
    store.journal.version &= !journal::EXPIRY_RECOVERY_VERSION;
    assert!(
        Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
            .is_err()
    );
}

#[test]
fn expiry_refund_rechecks_shared_authority_and_local_usage_before_writing() {
    for case in [
        "outgoing",
        "new request",
        "pending watch",
        "accepted history",
        "quote",
        "retired quote",
        "advance",
        "uncertain",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old, buyer, intent, timestamp) = withdrawn(root.path());
        match case {
            "outgoing" => {
                store
                    .journal
                    .outgoing
                    .insert(old.purchase.contract.id.clone(), old.clone());
            }
            "new request" => {
                let mut next = old.offer.clone();
                next.id = "new-authority".into();
                store.journal.requested.insert(next.id.clone(), next);
            }
            "pending watch" => {
                store
                    .journal
                    .watched_routes
                    .values_mut()
                    .next()
                    .unwrap()
                    .pending = Some(old.offer.clone());
            }
            "accepted history" => {
                store
                    .journal
                    .history
                    .get_or_insert_with(History::default)
                    .buyers
                    .insert(old.purchase.channel.id.clone());
            }
            "quote" | "retired quote" => {
                buyer
                    .accept_channel(old.offer.provider, old.purchase.channel.clone(), 0)
                    .unwrap();
                let mut contract = old.purchase.contract.clone();
                contract.billing = crate::ledger::BillingBasis::ForwardingData;
                buyer.accept_quote(contract.clone()).unwrap();
                if case == "retired quote" {
                    buyer.close_quote(&contract.id).unwrap();
                    assert_eq!(
                        buyer
                            .retire_closed_routes(&contract.channel_id, timestamp)
                            .unwrap(),
                        1
                    );
                }
            }
            "advance" => {
                buyer
                    .accept_channel(old.offer.provider, old.purchase.channel.clone(), 1)
                    .unwrap();
            }
            "uncertain" => {
                store.journal.funding.get_mut(&intent.id).unwrap().funded = None;
            }
            _ => unreachable!(),
        }
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            store
                .prepare_expiry_refund(&buyer, &intent, timestamp)
                .is_err(),
            "{case}"
        );
        assert_eq!(
            serde_json::to_value(&store.journal).unwrap(),
            before,
            "{case}"
        );
        assert!(store.journal.buyer_settlements.is_empty());
    }
}

#[test]
fn absent_channel_retirement_rechecks_membership_and_fences_late_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let (_store, old, buyer, _intent, timestamp) = withdrawn(root.path());
    let terms = old.purchase.channel.clone();
    let plan = buyer
        .channel_retirement_plan(&[], std::slice::from_ref(&terms), timestamp)
        .unwrap();
    assert_eq!(plan.after.channels, 1);
    assert_eq!(plan.after.capacity_sat, terms.capacity_sat);
    assert_eq!(plan.after.authorized_sat, 0);
    assert_eq!(plan.after.advance_msat, 0);
    assert_eq!(plan.after.routes, Default::default());
    assert_eq!(plan.never_installed().collect::<Vec<_>>(), vec![&terms]);
    // A delayed install between plan and commit makes that exact plan invalid.
    buyer
        .accept_channel(old.offer.provider, terms.clone(), 0)
        .unwrap();
    assert!(buyer.retire_channels(&plan).is_err());
    assert!(
        buyer
            .channel_retirement_plan(&[], std::slice::from_ref(&terms), timestamp)
            .is_err()
    );
    let other = BuyerAuthorizer::create(
        &root.path().join("absent"),
        terms.buyer,
        64,
        Limits::default(),
    )
    .unwrap();
    other.retire_channels(&plan).unwrap();
    other.retire_channels(&plan).unwrap();
    assert_eq!(other.authorized_sat(&terms.id), None);
    assert!(
        other
            .accept_channel(old.offer.provider, terms.clone(), 0)
            .is_err()
    );
    drop(other);
    let other = BuyerAuthorizer::load(&root.path().join("absent")).unwrap();
    other.retire_channels(&plan).unwrap();
    assert!(other.accept_channel(old.offer.provider, terms, 0).is_err());
}

#[test]
fn retained_expiry_intent_can_finish_after_new_unfunded_onward_selection() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, intent, timestamp) = withdrawn(root.path());
    store
        .prepare_expiry_refund(&buyer, &intent, timestamp)
        .unwrap();
    // Acceptance journals upstream funding before trying the onward purchase.
    // That purchase is fenced by Expiry, but the unrelated selection can remain.
    let mut offer = old.offer.clone();
    offer.id = "later-upstream".into();
    offer.provider = store.journal.local;
    offer.buyer = NodeAddr::from_bytes([7; 16]);
    offer.next_hop = old.offer.provider;
    offer.path.insert(0, offer.provider);
    let mut terms = old.purchase.channel.clone();
    terms.id = "upstream-funding".into();
    terms.buyer = offer.buyer;
    let incoming = Incoming {
        contract: contract_from_offer(&offer, &terms).unwrap(),
        offer,
        downstream: Some(old.offer.clone()),
        channel: terms,
        verified_paid_msat: 0,
        phase: Phase::Prepared,
        replaces: None,
        replacement_retired: false,
    };
    store
        .change(|j| {
            j.incoming.insert(incoming.contract.id.clone(), incoming);
            Ok(())
        })
        .unwrap();
    let mut store = reload(store);
    let before = serde_json::to_value(&store.journal).unwrap();
    assert_eq!(
        store
            .prepare_expiry_refund(&buyer, &intent, timestamp)
            .unwrap(),
        old.purchase.channel
    );
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
    assert!(
        Controller::check_purchase(&store.journal, &old.offer, Some(&old.purchase.channel.id))
            .is_err()
    );
    // Model the SDK-verified terminal result; the monetary amount is actual
    // recovered value, not the original channel capacity.
    store
        .change(|j| Controller::finish_expiry_refund(j, &intent, &old.purchase.channel, 29))
        .unwrap();
    let mut store = reload(store);
    let saved = &store.journal.buyer_settlements[&old.purchase.channel.id];
    assert!(saved.terminal() && !saved.released);
    assert_eq!(saved.wallet_refund_sat, Some(29));
    assert!(saved.report.is_none() && saved.payment.is_none());
    assert_eq!(store.journal.incoming.len(), 1);
    assert!(store.journal.outgoing.is_empty());
    let completed = serde_json::to_value(&store.journal).unwrap();
    store
        .change(|j| Controller::finish_expiry_refund(j, &intent, &old.purchase.channel, 29))
        .unwrap();
    assert!(
        store
            .change(|j| Controller::finish_expiry_refund(j, &intent, &old.purchase.channel, 30))
            .is_err()
    );
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), completed);
}
