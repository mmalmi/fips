//! Baseline-compatible regression through the ordinary retirement entry point.
use super::*;
use crate::controller::retirement_tests;

pub(super) fn incoming(store: &mut Store, old: &Outgoing, seller: &DurableRelay) -> Incoming {
    let mut channel = old.purchase.channel.clone();
    channel.id = "upstream".into();
    channel.buyer = NodeAddr::from_bytes([9; 16]);
    let mut offer = old.offer.clone();
    offer.id = "unfinished-sale".into();
    offer.buyer = channel.buyer;
    offer.provider = store.journal.local;
    offer.next_hop = old.offer.provider;
    offer.path.insert(0, store.journal.local);
    let contract = contract_from_offer(&offer, &channel).unwrap();
    let incoming = Incoming {
        offer,
        channel: channel.clone(),
        contract,
        downstream: Some(old.offer.clone()),
        verified_paid_msat: 3_000,
        phase: Phase::Prepared,
        replaces: None,
        replacement_retired: false,
    };
    // The real activation path verifies upstream funding and opens its channel
    // before it waits for downstream funding. No seller contract exists yet.
    seller
        .open_channel_verified(channel, incoming.verified_paid_msat)
        .unwrap();
    store
        .journal
        .incoming
        .insert(incoming.contract.id.clone(), incoming.clone());
    Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
        .unwrap();
    store.persist().unwrap();
    incoming
}

pub(super) fn stop(store: &mut Store, saved: &Incoming) {
    store
        .change(|j| {
            j.incoming.get_mut(&saved.contract.id).unwrap().phase = Phase::Stopped;
            Ok(())
        })
        .unwrap();
}

#[test]
fn stopped_uninstalled_sale_retires_through_existing_routes_api() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = retirement_tests::fixture(root.path());
    let prepared = incoming(&mut store, &old, &seller);
    let credit = seller.channel_usage(&prepared.channel.id).unwrap();
    stop(&mut store, &prepared);
    assert!(seller.contract(&prepared.contract.id).is_none());
    let retired = store
        .retire_routes(&buyer, &seller, prepared.offer.expires_unix)
        .unwrap();
    assert_eq!(
        retired, 1,
        "stopped verified-channel acceptance must retire even without an installed seller contract"
    );
    assert!(store.journal.incoming.is_empty());
    assert!(seller.contract(&prepared.contract.id).is_none());
    assert_eq!(seller.channel_usage(&prepared.channel.id), Some(credit));
    assert_eq!(
        store.journal.history.as_ref().unwrap().sellers[&prepared.channel.id],
        prepared.channel
    );
}
