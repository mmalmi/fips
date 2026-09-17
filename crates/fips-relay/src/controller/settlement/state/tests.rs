use super::*;

fn close(id: &str, capacity: u64) -> cashu_service::CashuSpilmanReceiverCloseResult {
    cashu_service::CashuSpilmanReceiverCloseResult {
        channel_id: id.into(),
        mint_url: "https://mint.invalid".into(),
        unit: "sat".into(),
        closed_amount: 3,
        total_value: capacity + 4,
        receiver_sum: 4,
        sender_sum: capacity,
        receiver_proofs_json: "[]".into(),
        sender_proofs_json: "[]".into(),
        already_closed: true,
    }
}

#[test]
fn settlement_keeps_signed_amounts_proof_reserves_and_reported_fees_distinct() {
    let root = tempfile::tempdir().unwrap();
    let (_, purchase) =
        crate::controller::transition_tests::fixture(&root.path().join("controller"));
    let t = purchase.purchase.channel;
    let closed = close(&t.id, t.capacity_sat);
    let report = SettlementReport::from_close(&closed).unwrap();
    assert!(valid_report(&t, &report, 3));
    assert_eq!(report.paid_sat, 3);
    assert_eq!(report.receiver_fee_reserve_sat, 1);
    assert_eq!(report.receiver_value_sat(), Some(4));
    assert_eq!(report.fee_sat, 0, "a reserve is not an already-paid fee");
    assert!(!valid_report(&t, &report, 4));
    let mut changed = report.clone();
    changed.receiver_fee_reserve_sat = 0;
    assert!(!valid_report(&t, &changed, 3));
    changed.receiver_fee_reserve_sat = u64::MAX;
    assert!(!valid_report(&t, &changed, 3));
    for invalid in [
        cashu_service::CashuSpilmanReceiverCloseResult {
            receiver_sum: 2,
            ..closed.clone()
        },
        cashu_service::CashuSpilmanReceiverCloseResult {
            receiver_sum: u64::MAX,
            ..closed.clone()
        },
        cashu_service::CashuSpilmanReceiverCloseResult {
            total_value: 1,
            ..closed
        },
    ] {
        assert!(SettlementReport::from_close(&invalid).is_err());
    }
}

#[test]
fn legacy_reports_load_without_fabricating_reserves_and_missing_nonzero_reserves_reject() {
    let root = tempfile::tempdir().unwrap();
    let (_, purchase) =
        crate::controller::transition_tests::fixture(&root.path().join("controller"));
    let t = purchase.purchase.channel;
    let mut old = serde_json::json!({"channel_id":t.id, "value_after_stage1_sat":t.capacity_sat,
        "paid_sat":3, "refunded_sat":t.capacity_sat - 3, "fee_sat":0});
    let report: SettlementReport = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(report.receiver_fee_reserve_sat, 0);
    assert!(valid_report(&t, &report, 3));
    old["value_after_stage1_sat"] = (t.capacity_sat + 1).into();
    let missing: SettlementReport = serde_json::from_value(old.clone()).unwrap();
    assert!(!valid_report(&t, &missing, 3));
    old["receiver_fee_reserve_sat"] = 1.into();
    let report: SettlementReport = serde_json::from_value(old).unwrap();
    assert!(valid_report(&t, &report, 3));
}
