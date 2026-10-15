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
    tokio::time::timeout(Duration::from_secs(180), exercise(&root))
        .await
        .expect("bounded grant/channel/refund/collection test");
    std::fs::remove_dir_all(root).unwrap();
}

async fn exercise(root: &Path) {
    let mut config: BenchConfig = serde_json::from_value(json!({
        "state_directory": root.join("mint"),
        "bind": "127.0.0.1:0", "max_issued_sat": 513
    }))
    .unwrap();
    assert!(!config.fragmented_channel_keyset);
    config.fragmented_channel_keyset = true;
    assert!(BenchMint::start(config.clone()).await.is_err());
    assert!(!config.state_directory.exists());
    config.max_issued_sat = 128;
    let mut mint = BenchMint::start(config).await.unwrap();
    let cfg = super::config(root, mint.url());
    RelayService::initialize(cfg.clone()).await.unwrap();
    let grant = mint
        .handle(BenchRequest::Issue {
            id: "original".into(),
            amount_sat: 128,
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
    let bounded = parsed.value().unwrap().to_u64() == 128
        && amounts.len() <= 65
        && amounts.iter().all(|amount| [1, 64, 128].contains(amount))
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
        panic!("128-sat grant must fit the ordinary recovery-record bound");
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
    for (index, paid) in [0, 19].into_iter().enumerate() {
        let wallet = CashuWalletService::open_file_backed(&buyer).await.unwrap();
        wallet.set_request_budget(128, 60_000).unwrap();
        let opened = wallet
            .open_streaming_route_cashu_spilman_channel(
                StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                    mint_url: mint.url().into(),
                    receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
                    capacity_sat: 32,
                    max_total_amount_sat: Some(32),
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
        assert_eq!(opened.channel.funding_token_amount, 32);
        let funding: Vec<Proof> =
            serde_json::from_value(opened.channel.payment.funding_proofs.clone().unwrap()).unwrap();
        assert_eq!(funding.len(), 32);
        assert!(funding.iter().all(|proof| proof.amount.to_u64() == 1));
        let id = &opened.channel.channel_id;
        let signer = FileSpilmanPaymentSigner::load(&buyer).unwrap();
        let payment = signer.sign_cashu_spilman_payment(id, paid, true).unwrap();
        drop(signer);
        receiver
            .process_cashu_spilman_payment(&payment, &"fragmented-test".into())
            .unwrap();
        let settled = receiver.close_cashu_spilman_channel(id).await.unwrap();
        assert_eq!(settled.receiver_sum, paid);
        assert_eq!(settled.sender_sum, 32 - paid);
        let refund: Vec<Proof> = serde_json::from_str(&settled.sender_proofs_json).unwrap();
        assert_eq!(refund.len() as u64, 32 - paid);
        assert!(refund.iter().all(|proof| proof.amount.to_u64() == 1));
        let restored = restore_streaming_route_cashu_spilman_refund(&buyer, id)
            .await
            .unwrap();
        assert!(restored.complete);
        assert_eq!(restored.imported_amount_sat, 32 - paid);
        if paid > 0 {
            let proofs: Vec<Proof> = serde_json::from_str(&settled.receiver_proofs_json).unwrap();
            let token = Token::new(
                mint.url().parse().unwrap(),
                proofs,
                None,
                "sat".parse().unwrap(),
            );
            assert_eq!(
                mint.handle(BenchRequest::Collect {
                    token: token.to_string()
                })
                .await
                .unwrap()["amount_sat"],
                paid
            );
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
        109
    );
    assert!(coins.iter().any(|coin| coin.proof.amount.to_u64() == 64));
    drop(db);
    let exported = offline_wallet(
        &cfg,
        WalletRequest::Export {
            id: 1,
            amount_sat: 109,
        },
    )
    .await
    .unwrap();
    let payment: Value =
        serde_json::from_slice(&std::fs::read(exported["path"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(
        mint.handle(BenchRequest::Collect {
            token: payment["token"].as_str().unwrap().into()
        })
        .await
        .unwrap()["amount_sat"],
        109
    );
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        0
    );
    let report = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(report["issued_sat"], 128);
    assert_eq!(report["collected_sat"], 128);
    assert_eq!(report["conserved"], true);
    mint.shutdown().await;
}
