//! Real wallet HTTP through a paid relay's bounded, explicitly free route.
use super::*;
use crate::{
    controller::RouteAccess,
    customer::{CustomerClient, CustomerCommand, CustomerProfile},
    free_routes::FreeBandwidthPolicy,
    mint_mesh::MeshMintBridge,
    wallet_tools::{WalletRequest, offline_wallet},
};
use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview, receive_payment_token,
    send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::{TransportInstances, TransportsConfig, UdpConfig};
use std::{
    net::UdpSocket,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};

const PORT: u16 = 44_745;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_wallet_funds_and_settles_over_mesh_without_a_direct_mint_url() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_timer(tracing_subscriber::fmt::time::Uptime::default())
        .with_test_writer()
        .try_init();
    let started = std::time::Instant::now();
    let checkpoint =
        |phase| eprintln!("mesh mint {:.2}s: {phase}", started.elapsed().as_secs_f64());
    // The complete financial lifecycle shares the unchanged 1 KiB/s reply tier.
    tokio::time::timeout(Duration::from_secs(300), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(317, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "mesh-mint",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let backend = mint.url().strip_prefix("http://").unwrap().parse().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}");
        assert_ne!(url, mint.url());
        let reservations: Vec<_> = (0..3)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let mut configs = Vec::new();
        let mut identities = Vec::new();
        for (i, socket) in reservations.iter().enumerate() {
            let mut config: ServiceConfig =
                serde_json::from_str(include_str!("../../service.example.json")).unwrap();
            config.state_directory = root.path().join(format!("node-{i}"));
            config.terms.billing = BillingBasis::ForwardingData;
            config.terms.controller.mint_url = url.clone();
            if i == 2 {
                config.mint_export = Some(crate::mint_mesh::MintExport {
                    backend,
                    service_port: PORT,
                });
            }
            config.terms.quote_max_units = 2 * 1024 * 1024;
            config.transports = TransportsConfig {
                udp: TransportInstances::Single(UdpConfig {
                    bind_addr: Some(socket.local_addr().unwrap().to_string()),
                    advertise_on_nostr: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let npub = RelayService::initialize(config.clone()).await.unwrap();
            identities.push(PeerIdentity::from_npub(&npub).unwrap());
            configs.push(config);
        }
        // The customer identity has no bootstrap entry in any relay's tariff.
        let customer_root = root.path().join("phone");
        let mut phone = CustomerClient::open(&customer_root).unwrap();
        let profile: CustomerProfile = serde_json::from_value(json!({
            "version": 1, "test_only": true,
            "entry_npub": identities[0].npub(),
            "entry_address": reservations[0].local_addr().unwrap().to_string(),
            "destination_npub": identities[1].npub(), "mint_url": url,
            "mint_mesh": {"npub": identities[2].npub(), "service_port": PORT},
            "budget_sat": 16, "channel_capacity_sat": 8,
            "max_rate_msat_per_kib": 8_192, "billing": "forwarding_data"
        }))
        .unwrap();
        let setup = phone
            .execute(CustomerCommand::Setup {
                profile: profile.clone(),
            })
            .await
            .unwrap();
        let mut changed = profile.clone();
        changed.mint_mesh.as_mut().unwrap().npub = identities[1].npub();
        assert!(
            phone
                .execute(CustomerCommand::Setup { profile: changed })
                .await
                .is_err()
        );
        // Only the mint has a free tariff. Replies must use the existing bounded
        // allowance earned by forwarded requests, with no client return watch.
        configs[1].destination_fees = serde_json::from_value(json!({
            identities[2].npub(): 0
        }))
        .unwrap();
        configs[1].free_bandwidth = Some(FreeBandwidthPolicy {
            global_bytes_per_second: 65_536,
            global_burst_bytes: 131_072,
            peer_bytes_per_second: 32_768,
            peer_burst_bytes: 65_536,
        });
        configs[0].destination_fees = serde_json::from_value(json!({
            identities[2].npub(): 0
        }))
        .unwrap();
        configs[0].free_bandwidth = configs[1].free_bandwidth.clone();
        configs[0].neighbor_admission =
            crate::control_transport::NeighborAdmission::AuthenticatedAdjacent;
        configs[0].return_allowance = true;
        configs[1].return_allowance = true;
        for (i, config) in configs.iter_mut().enumerate() {
            config.neighbors = identities
                .iter()
                .enumerate()
                .filter(|(j, _)| i.abs_diff(*j) == 1)
                .map(|(j, id)| {
                    PeerConfig::new(
                        id.npub(),
                        "udp",
                        reservations[j].local_addr().unwrap().to_string(),
                    )
                })
                .collect();
        }
        drop(reservations);
        let mut nodes = Vec::new();
        for config in &configs {
            nodes.push(RelayService::load(config.clone()).await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut ready = true;
                for (i, node) in nodes.iter().enumerate() {
                    ready &= node
                        .endpoint
                        .peers()
                        .await
                        .unwrap()
                        .iter()
                        .filter(|p| p.connected)
                        .count()
                        == if i == 1 { 2 } else { 1 };
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let wallet = root.path().join("customer-wallet");
        assert_eq!(
            load_mint_balance(&wallet, &url).await.unwrap().balance_sat,
            0
        );
        let mut untouched = Vec::new();
        for config in &configs {
            for relative in ["buyer/buyer.json", "seller/ledger.json"] {
                let path = config.state_directory.join(relative);
                untouched.push((path.clone(), std::fs::read(path).unwrap()));
            }
        }
        assert!(matches!(
            nodes[0].controller.open_route(identities[2]).await.unwrap(),
            RouteAccess::Free(_)
        ));
        let client =
            MeshMintBridge::connect(nodes[0].endpoint.clone(), PORT, identities[2], listener)
                .await
                .unwrap();
        // Hold the original request across a relay outage. The mint's HTTP
        // listener stays alive, so any direct fallback would violate this check.
        nodes[1].forwarding.ready.store(false, Ordering::Release);
        let mut request = TcpStream::connect(address).await.unwrap();
        request
            .write_all(b"GET /v1/info HTTP/1.1\r\nHost: mint\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        request.shutdown().await.unwrap();
        let mut response = Vec::new();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(600),
                request.read_to_end(&mut response)
            )
            .await
            .is_err()
        );
        assert!(
            response.is_empty(),
            "mint HTTP bypassed the unavailable relay"
        );
        nodes[1].forwarding.ready.store(true, Ordering::Release);
        let reply =
            tokio::time::timeout(Duration::from_secs(10), request.read_to_end(&mut response)).await;
        if !matches!(reply, Ok(Ok(_))) || !response.starts_with(b"HTTP/1.1 200") {
            let server = nodes[2].mint.take().unwrap().shutdown().await;
            panic!(
                "mint reply {reply:?}, bytes {}, server {server:?}, returns {:?}",
                response.len(),
                nodes[1].forwarding.relay.return_stats()
            );
        }
        let body = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
        let info: Value =
            serde_json::from_slice(&response[body..]).expect("complete mint JSON after recovery");
        assert!(info["nuts"].is_object());
        checkpoint("original HTTP response recovered");
        let quote = create_topup_quote(&wallet, &url, 16).await.unwrap();
        network
            .orchestrator_funding()
            .settle_external(&quote.payment_request)
            .unwrap();
        let overview = load_wallet_overview(&wallet, true).await.unwrap();
        assert!(overview.warnings.is_empty(), "{:?}", overview.warnings);
        assert_eq!(
            load_mint_balance(&wallet, &url).await.unwrap().balance_sat,
            16
        );
        let payment = send_payment_token(&wallet, &url, 16).await.unwrap();
        assert_eq!(payment.mint_url, url);
        checkpoint("source wallet funded and exported");
        for (path, bytes) in &untouched {
            assert_eq!(std::fs::read(path).unwrap(), *bytes);
        }

        // The fixture releases the URL; the customer now owns its adapter.
        assert!(
            phone.execute(CustomerCommand::Start).await.is_err(),
            "an occupied mint listener must not be adopted"
        );
        assert_eq!(
            phone.execute(CustomerCommand::Status).await.unwrap()["running"],
            false
        );
        client.shutdown().await.unwrap();
        phone.execute(CustomerCommand::Start).await.unwrap();
        let guarded = phone
            .execute(CustomerCommand::Import {
                token: payment.token.clone(),
            })
            .await
            .unwrap_err();
        assert!(guarded.contains("stop the customer service"));
        phone.execute(CustomerCommand::Stop).await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
        phone
            .execute(CustomerCommand::Import {
                token: payment.token,
            })
            .await
            .unwrap();
        assert!(TcpStream::connect(address).await.is_err());
        assert_eq!(
            phone.execute(CustomerCommand::Balance).await.unwrap()["balance_sat"],
            16
        );
        checkpoint("customer offline import complete");
        phone.execute(CustomerCommand::Start).await.unwrap();
        // Payment, provider redemption and buyer refund all use the mesh mint.
        let purchase = phone.execute(CustomerCommand::Buy).await;
        assert!(
            purchase.is_ok(),
            "purchase {purchase:?}; provider {:?}",
            nodes[0].controller.last_error()
        );
        let funded = phone.execute(CustomerCommand::Status).await.unwrap();
        assert_eq!(funded["relay"]["locked_sat"], 8);
        assert_eq!(funded["relay"]["funding_budget"]["wallet_debited_sat"], 8);
        checkpoint("customer channel funded");
        let channel = funded["relay"]["history"][0]["channel"]["id"]
            .as_str()
            .unwrap();
        let payload = "paid delivery with a mesh-only mint";
        let expected = format!("{:x}", Sha256::digest(payload.as_bytes()));
        phone
            .execute(CustomerCommand::Send {
                payload: payload.into(),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let delivered =
                    nodes[1].received.lock().unwrap().last_sha256.as_ref() == Some(&expected);
                if delivered && nodes[0].seller.channel_usage(channel).unwrap().paid_msat > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("payload delivery and automatic provider credit");
        checkpoint("paid payload delivered and provider credited");
        let finished = phone.execute(CustomerCommand::Finish).await;
        assert!(
            finished.is_ok(),
            "finish {finished:?}; provider {:?}; returns {:?}",
            nodes[0].controller.last_error(),
            nodes
                .iter()
                .map(|n| n.forwarding.relay.return_stats())
                .collect::<Vec<_>>()
        );
        let remaining = finished.unwrap()["balance_sat"].as_u64().unwrap();
        let journal: Value =
            read_json(&customer_root.join("state/controller/controller.json")).unwrap();
        let settlements = journal["buyer_settlements"].as_object().unwrap();
        assert_eq!(settlements.len(), 1);
        let settlement = settlements.values().next().unwrap();
        assert_eq!(settlement["released"], true);
        assert_eq!(settlement["refunded"], true);
        let paid = settlement["report"]["paid_sat"].as_u64().unwrap();
        assert!(paid > 0 && paid <= 8);
        assert_eq!(remaining + paid, 16);
        assert_eq!(settlement["report"]["refunded_sat"], 8 - paid);
        assert_eq!(settlement["wallet_refund_sat"], 8 - paid);
        checkpoint("provider settlement and customer refund complete");
        drop(phone);
        let mut phone = CustomerClient::open(&customer_root).unwrap();
        let reopened = phone.execute(CustomerCommand::Status).await.unwrap();
        assert_eq!(reopened["npub"], setup["npub"]);
        assert_eq!(reopened["profile"], serde_json::to_value(profile).unwrap());
        let exported = phone
            .execute(CustomerCommand::Export {
                id: 1,
                amount_sat: remaining,
            })
            .await
            .unwrap();
        let retained = phone
            .execute(CustomerCommand::Export {
                id: 1,
                amount_sat: remaining,
            })
            .await
            .unwrap();
        assert_eq!(
            exported, retained,
            "export recovery must retain the original operation"
        );
        checkpoint("customer export retained across reopen");
        let payment: cashu_service::CashuSentPayment =
            read_json(Path::new(exported["path"].as_str().unwrap())).unwrap();
        let collected = root.path().join("collected");
        phone.execute(CustomerCommand::Start).await.unwrap();
        receive_payment_token(&collected, &payment.token)
            .await
            .unwrap();
        phone.execute(CustomerCommand::Stop).await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
        assert_eq!(
            load_mint_balance(&wallet, &url).await.unwrap().balance_sat,
            0
        );
        assert_eq!(
            phone.execute(CustomerCommand::Balance).await.unwrap()["balance_sat"],
            0
        );
        assert_eq!(
            load_mint_balance(&collected, &url)
                .await
                .unwrap()
                .balance_sat,
            remaining
        );
        checkpoint("customer token collected");
        let stats = nodes[1].free.stats();
        assert!(stats.admitted_packets > 0 && stats.admitted_session_bytes > 0);
        assert!(stats.bandwidth.unwrap().admitted_packets > 0);
        for node in &nodes {
            assert!(node.controller.purchases().await.unwrap().is_empty());
            assert!(node.controller.watched_routes().await.unwrap().is_empty());
        }
        for node in &nodes[..2] {
            assert!(
                node.forwarding
                    .relay
                    .return_stats()
                    .unwrap()
                    .traffic
                    .admitted_packets
                    > 0
            );
        }
        for (path, bytes) in untouched {
            if !path.starts_with(&configs[0].state_directory) {
                assert_eq!(std::fs::read(path).unwrap(), bytes);
            }
        }
        // Stop the provider before accessing its wallet. The remaining fixture
        // endpoint carries collection HTTP over FIPS under the same mint URL.
        nodes.remove(0).shutdown().await.unwrap();
        let collection_proxy = MeshMintBridge::connect(
            nodes[0].endpoint.clone(),
            PORT,
            identities[2],
            TcpListener::bind(address).await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            offline_wallet(&configs[0], WalletRequest::Balance)
                .await
                .unwrap()["balance_sat"],
            paid
        );
        let exported = offline_wallet(
            &configs[0],
            WalletRequest::Export {
                id: 1,
                amount_sat: paid,
            },
        )
        .await
        .unwrap();
        let earnings: cashu_service::CashuSentPayment =
            read_json(Path::new(exported["path"].as_str().unwrap())).unwrap();
        receive_payment_token(&collected, &earnings.token)
            .await
            .unwrap();
        assert_eq!(
            offline_wallet(&configs[0], WalletRequest::Balance)
                .await
                .unwrap()["balance_sat"],
            0
        );
        assert_eq!(
            load_mint_balance(&collected, &url)
                .await
                .unwrap()
                .balance_sat,
            16
        );
        checkpoint("all sixteen test sats collected");
        collection_proxy.shutdown().await.unwrap();
        for node in nodes {
            node.shutdown().await.unwrap();
        }
    })
    .await
    .expect("mesh mint acceptance deadline");
}
