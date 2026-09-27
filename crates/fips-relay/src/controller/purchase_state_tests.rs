use super::transition_tests::{fixture, reload};
use super::*;

#[test]
fn paused_free_source_authorization_keeps_its_zero_ceiling_after_reload() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let destination = old.offer.destination.npub();
    let funding = serde_json::to_value(&store.journal.funding).unwrap();
    store
        .change(|j| {
            j.watched_routes.insert(
                destination.clone(),
                WatchedRoute {
                    billing: crate::ledger::BillingBasis::ForwardingData,
                    destination: destination.clone(),
                    max_rate_msat_per_kib: 0,
                    paused: true,
                    pending: None,
                    selected_trial: None,
                },
            );
            Ok(())
        })
        .unwrap();
    let store = reload(store);
    let watch = &store.journal.watched_routes[&destination];
    assert!(watch.paused);
    assert_eq!(watch.max_rate_msat_per_kib, 0);
    assert_eq!(
        serde_json::to_value(&store.journal.funding).unwrap(),
        funding
    );
    let mut candidate = store.journal.clone();
    let mut paid = old.offer;
    paid.billing = crate::ledger::BillingBasis::ForwardingData;
    candidate
        .watched_routes
        .get_mut(&destination)
        .unwrap()
        .pending = Some(paid);
    assert_eq!(
        Controller::validate_journal(&candidate, &candidate.policy, candidate.local),
        Err("invalid watched route authorization".into()),
        "a free-only authorization cannot resume a paid purchase"
    );
    let mut candidate = store.journal.clone();
    candidate
        .watched_routes
        .get_mut(&destination)
        .unwrap()
        .billing = Default::default();
    assert_eq!(
        Controller::validate_journal(&candidate, &candidate.policy, candidate.local),
        Err("invalid watched route authorization".into()),
        "zero-price authority still requires forwarding-data billing"
    );
}

fn additional(old: &Outgoing) -> Outgoing {
    let mut pending = old.clone();
    let destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    pending.offer.id = "another-destination".into();
    pending.offer.destination = destination;
    pending.offer.next_hop = *destination.node_addr();
    pending.offer.path = vec![old.purchase.provider, *destination.node_addr()];
    pending.purchase.contract =
        contract_from_offer(&pending.offer, &pending.purchase.channel).unwrap();
    pending.accepted = false;
    pending
}

fn start_close(j: &mut Journal, old: &Outgoing) {
    let purchase = serde_json::to_value(&old.purchase).unwrap();
    j.buyer_settlements.insert(
        old.purchase.channel.id.clone(),
        serde_json::from_value(serde_json::json!({
            "provider":purchase["provider"], "channel":old.purchase.channel,
            "usage":null, "payment":null, "report":null, "refunded":false
        }))
        .unwrap(),
    );
}

#[test]
fn closing_channel_rejects_new_destination_authorization() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let pending = additional(&old);
    store
        .change(|j| {
            start_close(j, &old);
            Ok(())
        })
        .unwrap();
    let mut store = reload(store);
    let before = serde_json::to_value(&store.journal).unwrap();
    assert!(
        store
            .change(|j| Controller::reserve_purchase(j, pending.offer))
            .is_err()
    );
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
    reload(store);
}

#[test]
fn settlement_between_funding_selection_and_purchase_record_is_rechecked() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let pending = additional(&old);
    store
        .change(|j| Controller::reserve_purchase(j, pending.offer.clone()))
        .unwrap();
    store
        .change(|j| {
            start_close(j, &old);
            Ok(())
        })
        .unwrap();
    let mut store = reload(store);
    assert!(
        store
            .change(|j| Controller::record_purchase(j, pending))
            .is_err()
    );
    assert_eq!(store.journal.outgoing.len(), 1);
    assert_eq!(store.journal.funding.len(), 1);
    reload(store);
}

#[test]
fn renewal_cannot_seal_a_shared_channel_with_unfinished_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let pending = additional(&old);
    store
        .change(|j| {
            Controller::reserve_purchase(j, pending.offer.clone())?;
            Controller::record_purchase(j, pending)?;
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
fn renewal_reservation_rejects_new_destination_purchases() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let pending = additional(&old);
    store
        .change(|j| Controller::reserve_renewal(j, old.purchase.channel.id.clone()))
        .unwrap();
    let mut store = reload(store);
    assert!(
        store
            .change(|j| Controller::reserve_purchase(j, pending.offer))
            .is_err()
    );
    assert_eq!(store.journal.requested.len(), 1);
    reload(store);
}

#[test]
fn acceptance_and_settlement_have_one_durable_order_without_a_network_lock() {
    for close_first in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let pending = additional(&old);
        store
            .change(|j| {
                Controller::reserve_purchase(j, pending.offer.clone())?;
                Controller::record_purchase(j, pending.clone())?;
                if close_first {
                    start_close(j, &old);
                }
                Ok(())
            })
            .unwrap();
        let mut store = reload(store);
        let accepted = store
            .change(|j| Controller::finish_acceptance(j, &pending.purchase.contract.id))
            .unwrap();
        assert_eq!(accepted, !close_first);
        assert_eq!(
            store.journal.outgoing[&pending.purchase.contract.id].accepted,
            !close_first
        );
        store
            .change(|j| {
                start_close(j, &old);
                Ok(())
            })
            .unwrap();
        assert!(
            !store
                .change(|j| Controller::finish_acceptance(j, &pending.purchase.contract.id))
                .unwrap()
        );
        assert_eq!(
            store.journal.outgoing[&pending.purchase.contract.id].accepted,
            !close_first
        );
        reload(store);
    }
}

#[test]
fn refund_retires_interrupted_acceptance_without_erasing_evidence_or_replaying_it() {
    for replacement in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let pending = store
            .change(|j| {
                let pending = if replacement {
                    Controller::reserve_route_change(j, transition_tests::change(&old))?;
                    transition_tests::prepare_replacement(j, &old, false);
                    j.outgoing.values().find(|o| !o.accepted).unwrap().clone()
                } else {
                    let pending = additional(&old);
                    Controller::reserve_purchase(j, pending.offer.clone())?;
                    Controller::record_purchase(j, pending)?
                };
                j.watched_routes.insert(
                    pending.offer.destination.npub(),
                    WatchedRoute {
                        billing: pending.offer.billing,
                        destination: pending.offer.destination.npub(),
                        max_rate_msat_per_kib: 8192,
                        paused: true,
                        pending: Some(pending.offer.clone()),
                        selected_trial: None,
                    },
                );
                start_close(j, &old);
                Ok(pending)
            })
            .unwrap();
        assert!(
            store
                .change(|j| Controller::retire_refunded_purchases(j, &old.purchase.channel.id))
                .is_err()
        );
        assert!(!store.journal.outgoing[&pending.purchase.contract.id].retired);
        let mut store = reload(store);
        let funding = serde_json::to_value(&store.journal.funding).unwrap();
        store
            .change(|j| {
                let channel = &old.purchase.channel;
                let mut completed =
                    serde_json::to_value(&j.buyer_settlements[&channel.id]).unwrap();
                completed["usage"] =
                    serde_json::to_value(crate::ledger::ChannelUsage::default()).unwrap();
                completed["payment"] = serde_json::to_value(
                    &j.funding[&old.funding_id].funded.as_ref().unwrap().opening,
                )
                .unwrap();
                completed["report"] = serde_json::to_value(SettlementReport {
                    channel_id: channel.id.clone(),
                    value_after_stage1_sat: channel.capacity_sat,
                    signed_sat: 0,
                    paid_sat: 0,
                    receiver_fee_reserve_sat: 0,
                    refunded_sat: channel.capacity_sat,
                    fee_sat: 0,
                })
                .unwrap();
                completed["refunded"] = true.into();
                completed["wallet_refund_sat"] = channel.capacity_sat.into();
                j.buyer_settlements.insert(
                    channel.id.clone(),
                    serde_json::from_value(completed).unwrap(),
                );
                Controller::retire_refunded_purchases(j, &channel.id)
            })
            .unwrap();
        let mut store = reload(store);
        let retired = &store.journal.outgoing[&pending.purchase.contract.id];
        assert!(retired.retired);
        assert!(!retired.accepted);
        assert_eq!(retired.purchase, pending.purchase);
        assert_eq!(retired.funding_id, pending.funding_id);
        assert_eq!(
            serde_json::to_value(&store.journal.funding).unwrap(),
            funding
        );
        assert!(!store.journal.requested.contains_key(&pending.offer.id));
        let watch = &store.journal.watched_routes[&pending.offer.destination.npub()];
        assert!(watch.paused && watch.pending.is_none());
        assert!(!Controller::route_change_pending_on(
            &store.journal,
            &old.purchase.channel.id
        ));
        // A worker holding an earlier recovery snapshot cannot resurrect it.
        assert!(
            store
                .change(|j| Controller::reserve_purchase(j, pending.offer.clone()))
                .is_err()
        );
        assert!(
            store
                .change(|j| Controller::record_purchase(j, pending.clone()))
                .is_err()
        );
        assert!(
            !store
                .change(|j| Controller::finish_acceptance(j, &pending.purchase.contract.id))
                .unwrap()
        );
        let mut fresh = pending.offer.clone();
        fresh.id = "new-explicit-authorization".into();
        assert!(Controller::check_purchase(&store.journal, &fresh, None).is_ok());
        reload(store);
    }
}

#[test]
fn purchase_rechecks_expiry_after_waiting_for_wallet_ownership() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let mut pending = additional(&old);
    pending.offer.expires_unix = 1;
    assert!(
        store
            .change(|j| Controller::reserve_purchase(j, pending.offer.clone()))
            .is_err()
    );
    assert!(Controller::check_purchase(&store.journal, &pending.offer, None).is_err());
    assert_eq!(store.journal.requested.len(), 1);
    reload(store);
}
