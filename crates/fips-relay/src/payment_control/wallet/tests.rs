use super::*;
use crate::ledger::{BytePrice, Limits};
use cashu_service::{
    CashuSpilmanPaymentSigner, FileSpilmanPaymentReceiverConfig, FileSpilmanPaymentSigner,
    StreamingRouteOpenCashuSpilmanChannelFromWalletRequest, create_topup_quote, load_mint_balance,
    load_wallet_overview, open_streaming_route_cashu_spilman_channel_from_wallet,
    restore_streaming_route_cashu_spilman_refund,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use cdk_sqlite::WalletSqliteDatabase;
use fips_core::Identity;
use std::time::{SystemTime, UNIX_EPOCH};

async fn handle(
    control: &Arc<PaymentControl>,
    peer: PeerIdentity,
    request: PaymentRequest,
) -> PaymentResponse {
    let control = control.clone();
    tokio::task::spawn_blocking(move || {
        control.handle(peer, &serde_json::to_vec(&request).unwrap())
    })
    .await
    .unwrap()
}

async fn open(
    control: &Arc<PaymentControl>,
    channel: &ChannelTerms,
    peer: PeerIdentity,
    payment: &CashuSpilmanPayment,
    automatic: bool,
) -> bool {
    if automatic {
        let control = control.clone();
        let channel = channel.clone();
        let payment = payment.clone();
        tokio::task::spawn_blocking(move || {
            let _wallet = control.wallet.blocking_lock();
            control.verify_funding(&channel, peer, &payment).is_ok()
        })
        .await
        .unwrap()
    } else {
        matches!(
            handle(
                control,
                peer,
                PaymentRequest::Open {
                    channel_id: channel.id.clone(),
                    payment: payment.clone(),
                },
            )
            .await,
            PaymentResponse::Status { .. }
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_opening_paths_reserve_payout_before_accepting_funding() {
    for automatic in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(916, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "receiver-admission",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let buyer = root.path().join("buyer");
        let seller = root.path().join("seller");
        let quote = create_topup_quote(&buyer, mint.url(), 64).await.unwrap();
        network
            .orchestrator_funding()
            .settle_external(&quote.payment_request)
            .unwrap();
        assert!(
            load_wallet_overview(&buyer, true)
                .await
                .unwrap()
                .warnings
                .is_empty()
        );
        let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
            &root.path().join("receiver"),
            FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
        )
        .await
        .unwrap();
        let opened = open_streaming_route_cashu_spilman_channel_from_wallet(
            &buyer,
            StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                mint_url: mint.url().into(),
                receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
                capacity_sat: 32,
                max_total_amount_sat: Some(32),
                expiry_unix: now + 600,
                max_amount_per_output: 0,
                unit: "sat".into(),
                opening_paid_msat: 0,
                keyset_id: None,
                keyset_info_json: None,
                client_request_id: Some("receiver-admission".into()),
                route_created_at_unix: Some(now),
            },
        )
        .await
        .unwrap();
        let identity = Identity::generate();
        let peer = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        let channel = ChannelTerms {
            id: opened.channel.channel_id,
            buyer: *peer.node_addr(),
            mint_url: mint.url().into(),
            expires_unix: now + 600,
            capacity_sat: 32,
            grace_msat: 0,
        };
        let ledger = Arc::new(
            DurableRelay::create(&root.path().join("ledger"), Limits::default(), 10_000).unwrap(),
        );
        let quote = Contract {
            billing: Default::default(),
            id: "approved-route".into(),
            channel_id: channel.id.clone(),
            destination: *Identity::generate().node_addr(),
            next_hop: *Identity::generate().node_addr(),
            expires_unix: now + 300,
            price: BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            max_units: 1000,
        };
        let control = Arc::new(
            PaymentControl::new(
                receiver,
                seller.clone(),
                ledger.clone(),
                vec![ApprovedAgreement {
                    channel: channel.clone(),
                    quotes: vec![quote],
                }],
            )
            .unwrap(),
        );
        let wallet = CashuWalletService::open_file_backed(&seller).await.unwrap();
        let db = WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(&seller))
            .await
            .unwrap();
        db.configure_storage_capacity(16 * 1024 * 1024)
            .await
            .unwrap();
        let charged = db.storage_capacity().await.unwrap().unwrap().charged_bytes;
        db.configure_storage_capacity(charged.max(1)).await.unwrap();
        drop(wallet);

        assert!(!open(&control, &channel, peer, &opened.channel.payment, automatic).await);
        assert!(!control.receiver.has_funding(&channel.id));
        assert!(ledger.channel_usage(&channel.id).is_none());

        // A retained ledger and a signed update cannot recreate missing funding.
        ledger.open_channel_verified(channel.clone(), 0).unwrap();
        assert!(matches!(
            handle(
                &control,
                peer,
                PaymentRequest::Update {
                    channel_id: channel.id.clone(),
                    payment: opened.channel.payment.clone(),
                }
            )
            .await,
            PaymentResponse::Rejected
        ));
        assert!(!control.receiver.has_funding(&channel.id));
        db.configure_storage_capacity(16 * 1024 * 1024)
            .await
            .unwrap();
        assert!(open(&control, &channel, peer, &opened.channel.payment, automatic).await);
        assert!(control.receiver.has_funding(&channel.id));
        let charged = db.storage_capacity().await.unwrap().unwrap().charged_bytes;
        db.configure_storage_capacity(charged).await.unwrap();

        // Updates need only existing receiver evidence, even while the wallet is
        // owned by another local operation and has no unreserved capacity.
        let wallet = CashuWalletService::open_file_backed(&seller).await.unwrap();
        let payment = FileSpilmanPaymentSigner::load(&buyer)
            .unwrap()
            .sign_cashu_spilman_payment(&channel.id, 3, false)
            .unwrap();
        let response = handle(
            &control,
            peer,
            PaymentRequest::Update {
                channel_id: channel.id.clone(),
                payment,
            },
        )
        .await;
        let PaymentResponse::Status { usage, .. } = response else {
            panic!("funded update rejected")
        };
        assert_eq!(usage.paid_msat, 3000);
        drop(wallet);
        let _owner = control.wallet.lock().await;
        control.close_at_mint(&channel.id).await.unwrap();
        control.import_wallet_payout(&channel.id).await.unwrap();
        control.import_wallet_payout(&channel.id).await.unwrap();
        assert_eq!(
            load_mint_balance(&seller, mint.url())
                .await
                .unwrap()
                .balance_sat,
            3
        );
        assert_eq!(
            db.storage_capacity().await.unwrap().unwrap().maximum_bytes,
            charged
        );
        restore_streaming_route_cashu_spilman_refund(&buyer, &channel.id)
            .await
            .unwrap();
        assert_eq!(
            load_mint_balance(&buyer, mint.url())
                .await
                .unwrap()
                .balance_sat,
            61
        );
    }
}
