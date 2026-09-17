use super::*;

#[test]
fn release_requires_the_original_buyer_and_complete_report_and_has_no_future_effect() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = super::super::transition_tests::fixture(&root.path().join("controller"));
    let peer = old.purchase.provider;
    let mut channel = old.purchase.channel;
    channel.buyer = peer;
    assert!(!release_needed(&store.journal, peer, &channel.id).unwrap());
    store.journal.version = 3;
    let history = store.journal.history.get_or_insert_with(History::default);
    history.through_unix = 1;
    history.sellers.insert(channel.id.clone(), channel.clone());
    assert!(release_needed(&store.journal, peer, &channel.id).is_err());
    let mut sale: SellerSettlement = serde_json::from_value(serde_json::json!({
        "channel":channel, "usage":null, "payment":null, "report":null
    }))
    .unwrap();
    store
        .journal
        .seller_settlements
        .insert(channel.id.clone(), sale.clone());
    assert!(release_needed(&store.journal, peer, &channel.id).is_err());
    sale.report = Some(SettlementReport {
        channel_id: channel.id.clone(),
        value_after_stage1_sat: 32,
        paid_sat: 0,
        receiver_fee_reserve_sat: 0,
        refunded_sat: 32,
        fee_sat: 0,
    });
    store
        .journal
        .seller_settlements
        .insert(channel.id.clone(), sale.clone());
    assert!(release_needed(&store.journal, store.journal.local, &channel.id).is_err());
    assert!(
        release_needed(&store.journal, peer, &channel.id).unwrap(),
        "early unknown release never authorizes future removal"
    );
    sale.released = true;
    store
        .journal
        .seller_settlements
        .insert(channel.id.clone(), sale);
    assert!(!release_needed(&store.journal, peer, &channel.id).unwrap());
    store.journal.seller_settlements.remove(&channel.id);
    store
        .journal
        .history
        .as_mut()
        .unwrap()
        .sellers
        .remove(&channel.id);
    let before = serde_json::to_vec(&store.journal).unwrap();
    for _ in 0..128 {
        assert!(!release_needed(&store.journal, peer, &channel.id).unwrap());
    }
    assert_eq!(serde_json::to_vec(&store.journal).unwrap(), before);
}
