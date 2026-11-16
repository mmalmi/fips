//! Real service-credit issuance through the existing authenticated FIPS bridge.
use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview, receive_payment_token,
    send_lightning_payment, send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::{
    Config, FipsEndpoint, Identity, PeerIdentity, SimNetwork,
    config::{SimTransportConfig, TransportInstances},
};
use fips_relay::mint_mesh::MeshMintBridge;
use std::{sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn insert_only_credits_issue_and_transfer_over_authenticated_fips() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let root = tempfile::tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payments = PaymentNetwork::new(17, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            payments.clone(),
            "exit",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let name = format!("insert-only-{}", Identity::generate().node_addr());
        fips_core::register_sim_network(name.clone(), SimNetwork::new(17));
        let mut endpoints = Vec::new();
        for n in 1..=2 {
            let mut config = Config::new();
            config.node.identity.nsec = Some(format!("{n:02x}").repeat(32));
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.local.enabled = false;
            config.transports.sim = TransportInstances::Single(SimTransportConfig {
                network: Some(name.clone()),
                addr: Some(n.to_string()),
                mtu: Some(1280),
                auto_connect: Some(true),
                accept_connections: Some(true),
            });
            endpoints.push(Arc::new(
                FipsEndpoint::builder()
                    .config(config)
                    .without_system_tun()
                    .bind()
                    .await
                    .unwrap(),
            ));
        }
        let port = 44_745;
        let export = MeshMintBridge::serve(
            endpoints[1].clone(),
            port,
            mint.url().strip_prefix("http://").unwrap().parse().unwrap(),
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bridge = MeshMintBridge::connect(
            endpoints[0].clone(),
            port,
            PeerIdentity::from_npub(endpoints[1].npub()).unwrap(),
            listener,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !endpoints[0]
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected)
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("FIPS neighbor ready");

        // Every wallet request uses the mesh listener, never the mint backend.
        let buyer = root.path().join("buyer");
        let seller = root.path().join("seller");
        let replay = root.path().join("replay");
        let quote = create_topup_quote(&buyer, &url, 16).await.unwrap();
        payments
            .orchestrator_funding()
            .settle_external(&quote.payment_request)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let overview = load_wallet_overview(&buyer, true).await.unwrap();
                assert!(overview.warnings.is_empty(), "{:?}", overview.warnings);
                if load_mint_balance(&buyer, &url).await.unwrap().balance_sat == 16 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("paid deposit issued through FIPS");
        let token = send_payment_token(&buyer, &url, 8).await.unwrap();
        assert_eq!(
            receive_payment_token(&seller, &token.token)
                .await
                .unwrap()
                .amount_sat,
            8
        );
        assert!(receive_payment_token(&replay, &token.token).await.is_err());
        let cashout = create_topup_quote(&replay, &url, 4).await.unwrap();
        assert!(
            send_lightning_payment(&seller, &url, &cashout.payment_request)
                .await
                .is_err()
        );
        assert_eq!(
            load_mint_balance(&seller, &url).await.unwrap().balance_sat,
            8
        );
        assert_eq!(
            payments.accounting().unwrap().mint_reserve("exit"),
            Some(16)
        );
        bridge.shutdown().await.unwrap();
        export.shutdown().await.unwrap();
        mint.mint().stop().await.unwrap();
        drop(endpoints);
        fips_core::unregister_sim_network(&name);
    })
    .await
    .expect("insert-only FIPS integration deadline");
}
