//! Small real channels stay fragmented while grants and collection stay bounded.
use super::*;
use cashu::nuts::{Proof, State, Token};
use cashu_service::{
    CashuSpilmanPaymentReceiver, CashuSpilmanPaymentSigner, CashuWalletService,
    FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig, FileSpilmanPaymentSigner,
    StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    restore_streaming_route_cashu_spilman_refund,
};
use cdk_common::database::WalletDatabase;
use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fragmented_channels_preserve_original_grant_refunds_and_final_collection() {
    let root = tempfile::tempdir().unwrap().keep();
    eprintln!("fragmented channel fixture: {}", root.display());
    tokio::time::timeout(Duration::from_secs(180), exercise(&root, false))
        .await
        .expect("bounded grant/channel/refund/collection test");
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receiver_history_keyset_preserves_959_original_payouts_and_collection() {
    let root = tempfile::tempdir().unwrap().keep();
    eprintln!("receiver keyset fixture: {}", root.display());
    tokio::time::timeout(Duration::from_secs(180), exercise(&root, true))
        .await
        .expect("bounded receiver grant/payout/collection test");
    std::fs::remove_dir_all(root).unwrap();
}

async fn exercise(root: &Path, receiver_history: bool) {
    let grant_sat = if receiver_history { 3072 } else { 128 };
    let capacity = if receiver_history { 960 } else { 32 };
    let denominations = if receiver_history {
        [1, 960, 1024]
    } else {
        [1, 64, 128]
    };
    let mut config: BenchConfig = serde_json::from_value(json!({
        "state_directory": root.join("mint"),
        "bind": "127.0.0.1:0", "max_issued_sat": if receiver_history {3073} else {513}
    }))
    .unwrap();
    assert!(!config.fragmented_channel_keyset);
    assert!(!config.receiver_history_keyset);
    config.fragmented_channel_keyset = !receiver_history;
    config.receiver_history_keyset = receiver_history;
    assert!(BenchMint::start(config.clone()).await.is_err());
    assert!(!config.state_directory.exists());
    config.max_issued_sat = grant_sat;
    if receiver_history {
        config.fragmented_channel_keyset = true;
        assert!(BenchMint::start(config.clone()).await.is_err());
        assert!(!config.state_directory.exists());
        config.fragmented_channel_keyset = false;
    }
    let mut mint = BenchMint::start(config).await.unwrap();
    let cfg = super::config(root, mint.url());
    RelayService::initialize(cfg.clone()).await.unwrap();
    let grant = mint
        .handle(BenchRequest::Issue {
            id: "original".into(),
            amount_sat: grant_sat,
        })
        .await
        .unwrap();
    let payment: Value =
        serde_json::from_slice(&std::fs::read(grant["path"].as_str().unwrap()).unwrap()).unwrap();
    let token = payment["token"].as_str().unwrap();
    let parsed = Token::from_str(token).unwrap();
    let Token::TokenV4(value) = &parsed else {
        panic!("fixture exports use the current token encoding");
    };
    let amounts: Vec<_> = value
        .token
        .iter()
        .flat_map(|group| &group.proofs)
        .map(|proof| proof.amount.to_u64())
        .collect();
    let issuer = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(
        &root.join("mint/wallet"),
    ))
    .await
    .unwrap();
    let history: Value = serde_json::from_slice(
        &issuer
            .kv_read("cashu_service", "send_requests", "journal")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    drop(issuer);
    let bounded = parsed.value().unwrap().to_u64() == grant_sat
        && amounts.len() <= 65
        && amounts.iter().all(|amount| denominations.contains(amount))
        && serde_json::to_vec(&history["entries"]["fips-export:original"])
            .unwrap()
            .len()
            <= 64 * 1024;
    if !bounded {
        // An unused grant can still be collected before a failing assertion
        // drops this in-process mint. Keep the failure and original evidence.
        mint.handle(BenchRequest::Collect {
            token: token.into(),
        })
        .await
        .unwrap();
        mint.shutdown().await;
        panic!("original grant must fit the ordinary recovery-record bound");
    }
    offline_wallet(
        &cfg,
        WalletRequest::Import {
            token: token.into(),
        },
    )
    .await
    .unwrap();
    let buyer = cfg.state_directory.join("wallet");
    let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
        &root.join("receiver"),
        FileSpilmanPaymentReceiverConfig::new([mint.url().to_owned()]),
    )
    .await
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payments: Vec<u64> = if receiver_history {
        vec![959]
    } else {
        std::iter::repeat_n(0, 15).chain([19]).collect()
    };
    for (index, paid) in payments.iter().copied().enumerate() {
        let wallet = CashuWalletService::open_file_backed(&buyer).await.unwrap();
        wallet.set_request_budget(128, 60_000).unwrap();
        let opened = wallet
            .open_streaming_route_cashu_spilman_channel(
                StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                    mint_url: mint.url().into(),
                    receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
                    capacity_sat: capacity,
                    max_total_amount_sat: Some(capacity),
                    expiry_unix: now + 300 + index as u64,
                    max_amount_per_output: 0,
                    unit: "sat".into(),
                    opening_paid_msat: 0,
                    keyset_id: None,
                    keyset_info_json: None,
                    client_request_id: Some(format!("fragmented-{index}")),
                    route_created_at_unix: Some(now),
                },
            )
            .await
            .unwrap();
        drop(wallet);
        assert_eq!(opened.channel.funding_token_amount, capacity);
        let funding: Vec<Proof> =
            serde_json::from_value(opened.channel.payment.funding_proofs.clone().unwrap()).unwrap();
        if receiver_history {
            assert_eq!(funding.len(), 1);
            assert_eq!(funding[0].amount.to_u64(), capacity);
        } else {
            assert_eq!(funding.len(), 32);
            assert!(funding.iter().all(|proof| proof.amount.to_u64() == 1));
        }
        let id = &opened.channel.channel_id;
        let signer = FileSpilmanPaymentSigner::load(&buyer).unwrap();
        let payment = signer.sign_cashu_spilman_payment(id, paid, true).unwrap();
        drop(signer);
        receiver
            .process_cashu_spilman_payment(&payment, &"fragmented-test".into())
            .unwrap();
        let settled = receiver.close_cashu_spilman_channel(id).await.unwrap();
        assert_eq!(settled.receiver_sum, paid);
        assert_eq!(settled.sender_sum, capacity - paid);
        let refund: Vec<Proof> = serde_json::from_str(&settled.sender_proofs_json).unwrap();
        assert_eq!(refund.len() as u64, capacity - paid);
        assert!(refund.iter().all(|proof| proof.amount.to_u64() == 1));
        let restored = restore_streaming_route_cashu_spilman_refund(&buyer, id)
            .await
            .unwrap();
        assert!(restored.complete);
        assert_eq!(restored.imported_amount_sat, capacity - paid);
        if paid > 0 {
            let proofs: Vec<Proof> = serde_json::from_str(&settled.receiver_proofs_json).unwrap();
            if receiver_history {
                assert_eq!(proofs.len(), 959);
                assert!(proofs.iter().all(|proof| proof.amount.to_u64() == 1));
            }
            // P2PK payout witnesses must also fit the ordinary token-size bound.
            for batch in proofs.chunks(32) {
                let amount: u64 = batch.iter().map(|proof| proof.amount.to_u64()).sum();
                let token = Token::new(
                    mint.url().parse().unwrap(),
                    batch.to_vec(),
                    None,
                    "sat".parse().unwrap(),
                );
                assert_eq!(
                    mint.handle(BenchRequest::Collect {
                        token: token.to_string()
                    })
                    .await
                    .unwrap()["amount_sat"],
                    amount
                );
            }
        }
    }
    let db = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(&buyer))
        .await
        .unwrap();
    let coins = db
        .get_proofs(None, None, Some(vec![State::Unspent]), None)
        .await
        .unwrap();
    assert_eq!(
        coins
            .iter()
            .map(|coin| coin.proof.amount.to_u64())
            .sum::<u64>(),
        grant_sat - payments.iter().sum::<u64>()
    );
    assert!(
        coins
            .iter()
            .any(|coin| coin.proof.amount.to_u64() == denominations[1]
                || coin.proof.amount.to_u64() == denominations[2])
    );
    drop(db);
    let remaining = grant_sat - payments.iter().sum::<u64>();
    // Preserve the larger grant denominations during final collection instead
    // of repeatedly splitting them into unrelated small outgoing payments.
    let chunk = if receiver_history { 1024 } else { 32 };
    let chunks = (0..remaining.div_ceil(chunk)).map(|index| (remaining - index * chunk).min(chunk));
    for (index, amount_sat) in chunks.enumerate() {
        let exported = offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: index as u64 + 1,
                amount_sat,
            },
        )
        .await
        .unwrap();
        let payment: Value =
            serde_json::from_slice(&std::fs::read(exported["path"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(payment["amount_sat"], amount_sat);
        assert_eq!(payment["send_fee_sat"], 0);
        assert_eq!(
            mint.handle(BenchRequest::Collect {
                token: payment["token"].as_str().unwrap().into()
            })
            .await
            .unwrap()["amount_sat"],
            amount_sat
        );
    }
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        0
    );
    let report = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(report["issued_sat"], grant_sat);
    assert_eq!(report["collected_sat"], grant_sat);
    assert_eq!(report["conserved"], true);
    mint.shutdown().await;
}
