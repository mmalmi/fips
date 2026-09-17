//! Startup must reject partial native transport deployment before wallet work.

use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::{TcpConfig, TransportInstances, UdpConfig};
use fips_relay::service::{RelayService, native_request};
use serde_json::json;
use std::{
    collections::HashMap,
    net::{TcpListener, UdpSocket},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::process_support;

fn network() -> PaymentNetwork {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    PaymentNetwork::new(110, 0, Arc::new(VirtualClock::new(now)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn named_udp_tcp_and_outbound_only_tcp_all_start() {
    healthy_transports_start().await;
}

#[tokio::test(flavor = "current_thread")]
async fn startup_waits_for_the_native_control_task_on_a_single_thread() {
    healthy_transports_start().await;
}

async fn healthy_transports_start() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let root = tempfile::tempdir().unwrap();
        let mint = LocalMint::start(
            root.path(),
            network(),
            "transport-startup",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut config = process_support::config(root.path(), mint.url());
        config.transports.udp = TransportInstances::Named(HashMap::from([(
            "local".into(),
            UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                ..Default::default()
            },
        )]));
        config.transports.tcp = TransportInstances::Named(HashMap::from([
            (
                "listener".into(),
                TcpConfig {
                    bind_addr: Some("127.0.0.1:0".into()),
                    ..Default::default()
                },
            ),
            ("outbound".into(), TcpConfig::default()),
        ]));
        RelayService::initialize(config.clone()).await.unwrap();
        for _ in 0..2 {
            let service = RelayService::load(config.clone()).await.unwrap();
            let report = native_request(&config, &json!({"command": "show_transports"}))
                .await
                .unwrap();
            let rows = report["data"]["transports"].as_array().unwrap();
            assert_eq!(rows.len(), 3);
            assert!(rows.iter().all(|row| row["state"] == "up"));
            let outbound = rows.iter().find(|row| row["name"] == "outbound").unwrap();
            assert_eq!(outbound["type"], "tcp");
            assert!(
                outbound.get("local_addr").is_none(),
                "outbound-only TCP needs no listener"
            );
            service.shutdown().await.unwrap();
            assert!(!config.state_directory.join("native.sock").exists());
        }
        assert_eq!(
            load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            0
        );
    })
    .await
    .expect("healthy transport startup deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_tcp_bind_rejects_service_and_releases_started_udp_without_spending() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let root = tempfile::tempdir().unwrap();
        let network = network();
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "transport-bind-failure",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_address = udp.local_addr().unwrap();
        let mut config = process_support::config(root.path(), mint.url());
        config.transports.udp = TransportInstances::Named(HashMap::from([(
            "healthy".into(),
            UdpConfig {
                bind_addr: Some(udp_address.to_string()),
                ..Default::default()
            },
        )]));
        config.transports.tcp = TransportInstances::Named(HashMap::from([(
            "occupied".into(),
            TcpConfig {
                bind_addr: Some(occupied.local_addr().unwrap().to_string()),
                ..Default::default()
            },
        )]));
        // Initialization intentionally uses only its private loopback adapter;
        // deployment checks must happen when the real transports are started.
        RelayService::initialize(config.clone()).await.unwrap();
        let wallet = config.state_directory.join("wallet");
        let quote = create_topup_quote(&wallet, mint.url(), 32).await.unwrap();
        network
            .orchestrator_funding()
            .settle_external(&quote.payment_request)
            .unwrap();
        assert!(
            load_wallet_overview(&wallet, true)
                .await
                .unwrap()
                .warnings
                .is_empty()
        );
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            32
        );
        let journal_paths = [
            "buyer/buyer.json",
            "seller/ledger.json",
            "controller/controller.json",
        ];
        let before: Vec<_> = journal_paths
            .iter()
            .map(|path| std::fs::read(config.state_directory.join(path)).unwrap())
            .collect();
        drop(udp);
        let error = match RelayService::load(config.clone()).await {
            Err(error) => error,
            Ok(service) => {
                service.shutdown().await.unwrap();
                panic!("a healthy UDP adapter must not mask an occupied TCP listener");
            }
        };
        assert!(
            error.contains("transport"),
            "unexpected startup rejection: {error}"
        );
        let released = UdpSocket::bind(udp_address)
            .expect("failed startup releases its healthy sibling UDP socket");
        assert_eq!(released.local_addr().unwrap(), udp_address);
        for (path, previous) in journal_paths.iter().zip(before) {
            assert_eq!(
                std::fs::read(config.state_directory.join(path)).unwrap(),
                previous,
                "startup failure changed financial journal {path}"
            );
        }
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            32
        );
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("partial transport startup rejection deadline");
}
