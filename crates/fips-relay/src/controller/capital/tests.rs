use super::*;
use crate::controller::transition_tests::{fixture, reload};

#[test]
fn reservations_actual_costs_and_refunds_preserve_lifetime_spending() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let mut funded = store.journal.funding["test-1"].funded.clone().unwrap();
    funded.wallet_cost = cashu_service::CashuSendCost {
        token_amount_sat: 35,
        swap_fee_sat: 2,
        wallet_debit_sat: 37,
    };
    store
        .change(|j| {
            j.outgoing.clear();
            j.requested.clear();
            j.policy.max_funding_overhead_sat = 8;
            j.policy.max_locked_sat = 40;
            j.policy.max_wallet_spend_sat = 40;
            let f = j.funding.get_mut("test-1").unwrap();
            f.max_wallet_debit_sat = 40;
            f.funded = None;
            Ok(())
        })
        .unwrap();
    store = reload(store);
    let reserved = Controller::capital(&store.journal).unwrap();
    assert_eq!(reserved.pending_reserved_sat, 40);
    assert_eq!(reserved.locked_sat, 40);
    assert_eq!(reserved.exposure_sat, 40);
    let intent = store.journal.funding["test-1"].clone();
    for _ in 0..2 {
        store
            .change(|j| Controller::record_funding(j, intent.clone(), funded.clone()))
            .unwrap();
        store = reload(store);
        let actual = Controller::capital(&store.journal).unwrap();
        assert_eq!(actual.pending_reserved_sat, 0);
        assert_eq!(actual.wallet_debited_sat, 37);
        assert_eq!(actual.locked_sat, 37);
    }
    let mut payment = funded.opening.clone();
    payment.balance = 7;
    let settlement = serde_json::json!({
        "provider": serde_json::to_value(&old.purchase).unwrap()["provider"],
        "channel": funded.terms, "usage": {"reserved_msat":7000,"submitted_msat":7000,"lost_msat":0,"paid_msat":7000},
        "payment":payment, "report":{"channel_id": funded.terms.id,"value_after_stage1_sat":32,"signed_sat":7,"paid_sat":7,"refunded_sat":25,"fee_sat":0},
        "refunded":true,"wallet_refund_sat":25
    });
    store
        .change(|j| {
            j.buyer_settlements.insert(
                funded.terms.id.clone(),
                serde_json::from_value(settlement).unwrap(),
            );
            Ok(())
        })
        .unwrap();
    store = reload(store);
    let settled = Controller::capital(&store.journal).unwrap();
    assert_eq!(settled.wallet_debited_sat, 37);
    assert_eq!(settled.wallet_refunded_sat, 25);
    assert_eq!(settled.locked_sat, 0);
    assert_eq!(
        settled.exposure_sat, 12,
        "payment plus all unrecovered funding costs remain spent"
    );
    let before = serde_json::to_value(&store.journal).unwrap();
    let error = store
        .change(|j| {
            let mut another = intent.clone();
            another.id = "test-2".into();
            j.next_funding = 3;
            j.funding.insert(another.id.clone(), another);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error, "lifetime wallet spending budget exhausted");
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
    reload(store);
}

#[test]
fn changed_over_budget_or_duplicate_funding_evidence_cannot_release_reservations() {
    let root = tempfile::tempdir().unwrap();
    let (store, _) = fixture(&root.path().join("controller"));
    for fault in 0..5 {
        let mut j = store.journal.clone();
        let f = j.funding.get_mut("test-1").unwrap();
        match fault {
            0 => f.max_wallet_debit_sat += 1,
            1 => f.funded.as_mut().unwrap().wallet_cost.wallet_debit_sat += 1,
            2 => {
                f.funded.as_mut().unwrap().wallet_cost.swap_fee_sat = 1;
                f.funded.as_mut().unwrap().wallet_cost.wallet_debit_sat += 1;
            }
            3 => f.funded.as_mut().unwrap().wallet_operation_id.clear(),
            _ => {
                let mut duplicate = f.clone();
                duplicate.id = "test-2".into();
                j.funding.insert(duplicate.id.clone(), duplicate);
                j.policy.max_locked_sat = 64;
            }
        }
        assert!(Controller::validate_capital(&j).is_err());
    }
    let mut legacy = store.journal.clone();
    legacy.version = 1;
    assert!(Controller::validate_journal(&legacy, &legacy.policy, legacy.local).is_err());
}
