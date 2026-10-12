use super::*;

fn close(id: &str, capacity: u64) -> cashu_service::CashuSpilmanReceiverCloseResult {
    cashu_service::CashuSpilmanReceiverCloseResult {
        channel_id: id.into(),
        mint_url: "https://mint.invalid".into(),
        unit: "sat".into(),
        signed_amount: 3,
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
    assert_eq!(report.signed_sat, 3);
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
            signed_amount: 2,
            ..closed.clone()
        },
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
fn reports_require_signed_history_and_account_for_fee_reserves() {
    let root = tempfile::tempdir().unwrap();
    let (_, purchase) =
        crate::controller::transition_tests::fixture(&root.path().join("controller"));
    let t = purchase.purchase.channel;
    let mut old = serde_json::json!({"channel_id":t.id, "value_after_stage1_sat":t.capacity_sat,
        "signed_sat":3,"paid_sat":3, "refunded_sat":t.capacity_sat - 3, "fee_sat":0});
    let mut missing_signed = old.clone();
    missing_signed.as_object_mut().unwrap().remove("signed_sat");
    assert!(serde_json::from_value::<SettlementReport>(missing_signed).is_err());
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

#[tokio::test]
async fn completed_expiry_report_replays_only_for_its_buyer_and_original_balance() {
    let root = tempfile::tempdir().unwrap();
    let controller = crate::controller::refresh::tests::disconnected_controller(root.path()).await;
    let (_, old) = crate::controller::transition_tests::fixture(&root.path().join("fixture"));
    let payer = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let stranger = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let mut channel = old.purchase.channel;
    channel.buyer = *payer.node_addr();
    channel.expires_unix = now().unwrap() - 1;
    let report = SettlementReport::from_close(&close(&channel.id, channel.capacity_sat)).unwrap();
    let sale = SellerSettlement {
        channel: channel.clone(),
        usage: Some(ChannelUsage {
            paid_msat: 3_000,
            ..Default::default()
        }),
        payment: None,
        report: Some(report.clone()),
        released: false,
    };
    controller
        .change(move |j| {
            j.advance_history_version(3);
            let history = j.history.get_or_insert_with(History::default);
            history.through_unix = sale.channel.expires_unix;
            history
                .sellers
                .insert(sale.channel.id.clone(), sale.channel.clone());
            j.seller_settlements.insert(sale.channel.id.clone(), sale);
            Ok(())
        })
        .await
        .unwrap();
    let payment = CashuSpilmanPayment {
        channel_id: channel.id.clone(),
        balance: report.signed_sat,
        signature: "no new payment is applied for a saved report".into(),
        params: None,
        funding_proofs: None,
    };
    let path = root.path().join("controller/controller.json");
    let before = std::fs::read(&path).unwrap();
    for id in [String::new(), "missing".into(), "x".repeat(129)] {
        assert!(
            controller
                .handle_settle(payer, &id, payment.clone())
                .await
                .is_err()
        );
    }
    for balance in [2, 4] {
        let changed = CashuSpilmanPayment {
            balance,
            ..payment.clone()
        };
        assert!(
            controller
                .handle_settle(payer, &channel.id, changed)
                .await
                .is_err()
        );
    }
    assert!(
        controller
            .handle_settle(stranger, &channel.id, payment.clone())
            .await
            .is_err()
    );
    let wrong_channel = CashuSpilmanPayment {
        channel_id: "other".into(),
        ..payment.clone()
    };
    assert!(
        controller
            .handle_settle(payer, &channel.id, wrong_channel)
            .await
            .is_err()
    );
    for _ in 0..2 {
        let response = controller
            .handle_settle(payer, &channel.id, payment.clone())
            .await
            .unwrap();
        assert!(
            matches!(response, ControllerResponse::Settled { report: saved } if saved == report)
        );
    }
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(
        !root.path().join("wallet").exists(),
        "report replay must not open a wallet"
    );
    controller.services.endpoint.shutdown().await.unwrap();
}
