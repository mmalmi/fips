#![cfg(unix)]
#[path = "process_support/idle.rs"]
mod idle;
#[path = "process_support/transports.rs"]
mod transports;
use transports::{udp_bind, udp_transports};

use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview, receive_payment_token,
    send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::{Identity, config::PeerConfig};
use fips_relay::{
    customer::{CustomerClient, CustomerCommand as Action, CustomerProfile},
    service::{AdminRequest, RelayService, ServiceConfig, request},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn profile(entry: &str, address: String, destination: &str, mint: &str) -> CustomerProfile {
    serde_json::from_value(json!({
        "version":1, "test_only":true, "entry_npub":entry, "entry_address":address,
        "destination_npub":destination, "mint_url":mint,
        "budget_sat":128, "channel_capacity_sat":32, "max_rate_msat_per_kib":8192
    }))
    .unwrap()
}

fn config(root: &Path, mint: &str) -> ServiceConfig {
    let mut value: Value = serde_json::from_str(include_str!("../service.example.json")).unwrap();
    value["state_directory"] = json!(root.join("state"));
    value["transports"] = json!({"udp": {"bind_addr": "127.0.0.1:0", "advertise_on_nostr": false}});
    value["terms"]["controller"]["mint_url"] = json!(mint);
    value["terms"]["controller"]["channel_capacity_sat"] = json!(32);
    value["terms"]["controller"]["renewal"] = Value::Null;
    serde_json::from_value(value).unwrap()
}

async fn fund(root: &Path, mint: &str, network: &PaymentNetwork, sats: u64) {
    let quote = create_topup_quote(root, mint, sats).await.unwrap();
    network
        .orchestrator_funding()
        .settle_external(&quote.payment_request)
        .unwrap();
    assert!(
        load_wallet_overview(root, true)
            .await
            .unwrap()
            .warnings
            .is_empty()
    );
}

async fn deliver(client: &mut CustomerClient, destination: &ServiceConfig, epoch: u64) {
    let payload = format!("customer-{epoch}-{}", "x".repeat(950));
    let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    // FIPS datagrams are best effort. As in the process recovery test, allow
    // endpoint retries across the native discovery/backoff cycle after restart.
    for attempt in 1..=6 {
        client
            .execute(Action::Send {
                payload: payload.clone(),
            })
            .await
            .unwrap();
        if tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let state = request(destination, &AdminRequest::Status).await.unwrap();
                if state["received"]["last_sha256"] == digest {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
        {
            eprintln!("customer delivery epoch={epoch} attempts={attempt}");
            return;
        }
    }
    let state = client.execute(Action::Status).await.unwrap();
    panic!(
        "customer delivery epoch={epoch}; last_error={:?}",
        state["relay"]["last_error"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn customer_app_uses_real_accounts_and_preserves_them_across_reopen() {
    tokio::time::timeout(Duration::from_secs(160), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(98, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "customer-app",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut configs = vec![
            config(&root.path().join("entry"), mint.url()),
            config(&root.path().join("destination"), mint.url()),
        ];
        let mut sockets = Vec::new();
        let mut npubs = Vec::new();
        for cfg in &mut configs {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            cfg.transports = udp_transports(socket.local_addr().unwrap());
            sockets.push(socket);
            std::fs::create_dir_all(cfg.state_directory.parent().unwrap()).unwrap();
            npubs.push(RelayService::initialize(cfg.clone()).await.unwrap());
            fund(
                &cfg.state_directory.join("wallet"),
                mint.url(),
                &network,
                128,
            )
            .await;
        }
        for i in 0..2 {
            configs[i].neighbors = vec![PeerConfig::new(
                &npubs[1 - i],
                "udp",
                udp_bind(&configs[1 - i]).to_string(),
            )];
        }
        configs[0].customer_network = Some("127.0.0.1/32".parse().unwrap());
        drop(sockets);
        let mut servers = Vec::new();
        for cfg in &configs {
            let service = RelayService::load(cfg.clone()).await.unwrap();
            let (send, recv) = tokio::sync::oneshot::channel::<()>();
            servers.push((
                send,
                tokio::spawn(service.serve(async {
                    let _ = recv.await;
                })),
            ));
        }
        let directory = root.path().join("customer");
        let profile = profile(
            &npubs[0],
            udp_bind(&configs[0]).to_string(),
            &npubs[1],
            mint.url(),
        );
        let mut client = CustomerClient::open(&directory).unwrap();
        assert!(
            CustomerClient::open(&directory).is_err(),
            "one owner per customer account"
        );
        let setup = client
            .execute(Action::Setup {
                profile: profile.clone(),
            })
            .await
            .unwrap();
        let customer_npub = setup["npub"].as_str().unwrap().to_string();
        assert_eq!(
            client
                .execute(Action::Setup {
                    profile: profile.clone()
                })
                .await
                .unwrap()["npub"],
            customer_npub
        );
        let mut changed = profile.clone();
        changed.budget_sat += 1;
        assert!(
            client
                .execute(Action::Setup { profile: changed })
                .await
                .is_err()
        );
        let grant_wallet = root.path().join("grant");
        fund(&grant_wallet, mint.url(), &network, 128).await;
        let grant = send_payment_token(&grant_wallet, mint.url(), 128)
            .await
            .unwrap();
        client
            .execute(Action::Import { token: grant.token })
            .await
            .unwrap();
        assert_eq!(
            client.execute(Action::Balance).await.unwrap()["balance_sat"],
            128
        );
        client.execute(Action::Start).await.unwrap();
        assert!(
            client.execute(Action::Balance).await.is_err(),
            "wallet operations must not race the running service"
        );
        client.execute(Action::Buy).await.unwrap();
        // The destination explicitly funds its own return direction, including
        // FIPS session replies. A customer's purchase cannot authorize spending
        // by another endpoint or grant that endpoint free transit.
        request(
            &configs[1],
            &AdminRequest::Watch {
                destination: customer_npub,
                max_rate_msat_per_kib: 8192,
            },
        )
        .await
        .unwrap();
        for epoch in 0..2 {
            deliver(&mut client, &configs[1], epoch).await;
            if epoch == 0 {
                let before = client.execute(Action::Status).await.unwrap();
                client.execute(Action::Stop).await.unwrap();
                drop(client);
                client = CustomerClient::open(&directory).unwrap();
                client.execute(Action::Start).await.unwrap();
                let after = client.execute(Action::Status).await.unwrap();
                assert_eq!(before["npub"], after["npub"]);
                assert_eq!(before["relay"]["history"], after["relay"]["history"]);
            }
        }
        idle::assert_idle(&configs[..1]).await;
        let final_wallet = client.execute(Action::Finish).await.unwrap();
        let amount = final_wallet["balance_sat"].as_u64().unwrap();
        let export = client
            .execute(Action::Export {
                id: "return-test".into(),
                amount_sat: amount,
            })
            .await
            .unwrap();
        assert!(
            export.get("token").is_none(),
            "never return bearer funds through UI status"
        );
        assert_eq!(
            export,
            client
                .execute(Action::Export {
                    id: "return-test".into(),
                    amount_sat: amount
                })
                .await
                .unwrap()
        );
        let token: Value =
            serde_json::from_slice(&std::fs::read(export["path"].as_str().unwrap()).unwrap())
                .unwrap();
        let collector = root.path().join("collector");
        receive_payment_token(&collector, token["token"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            client.execute(Action::Balance).await.unwrap()["balance_sat"],
            0
        );
        for cfg in &configs {
            request(cfg, &AdminRequest::Settle).await.unwrap();
        }
        for (send, task) in servers {
            send.send(()).unwrap();
            task.await.unwrap().unwrap();
        }
        for (i, cfg) in configs.iter().enumerate() {
            let wallet = cfg.state_directory.join("wallet");
            let balance = load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat;
            if i == 0 {
                assert!(balance > 128);
            }
            let payment = send_payment_token(&wallet, mint.url(), balance)
                .await
                .unwrap();
            receive_payment_token(&collector, &payment.token)
                .await
                .unwrap();
        }
        assert_eq!(
            load_mint_balance(&collector, mint.url())
                .await
                .unwrap()
                .balance_sat,
            384
        );
        assert!(network.accounting().unwrap().is_conserved());
        drop(client);
    })
    .await
    .expect("customer app account flow deadline");
}

#[test]
fn customer_profiles_reject_unbounded_or_non_test_configuration() {
    let a = Identity::generate();
    let b = Identity::generate();
    let good = profile(
        &a.npub(),
        "127.0.0.1:2121".into(),
        &b.npub(),
        "http://127.0.0.1:3338",
    );
    good.validate().unwrap();
    for (field, value) in [
        ("test_only", json!(false)),
        ("budget_sat", json!(513)),
        ("channel_capacity_sat", json!(0)),
        ("max_rate_msat_per_kib", json!(0)),
        ("mint_url", json!("https://mint.example.com")),
        ("entry_address", json!("0.0.0.0:0")),
        ("destination_npub", json!(a.npub())),
    ] {
        let mut value_json = serde_json::to_value(&good).unwrap();
        value_json[field] = value;
        let invalid: CustomerProfile = serde_json::from_value(value_json).unwrap();
        assert!(
            invalid.validate().is_err(),
            "invalid profile field: {field}"
        );
    }
}
