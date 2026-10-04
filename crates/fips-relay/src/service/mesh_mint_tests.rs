//! Real wallet HTTP through a paid relay's bounded, explicitly free route.
use super::*;
use crate::{
    controller::RouteAccess, free_routes::FreeBandwidthPolicy, testbench::mesh::MeshMintBridge,
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
async fn empty_wallet_funds_over_two_hops_without_a_paid_channel_or_direct_mint_url() {
    tokio::time::timeout(Duration::from_secs(90), async {
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
        // Only this mint/client pair has a free tariff. Other destinations keep
        // the configured positive fee; both directions share the relay's cap.
        configs[1].destination_fees = serde_json::from_value(json!({
            identities[0].npub(): 0, identities[2].npub(): 0
        }))
        .unwrap();
        configs[1].free_bandwidth = Some(FreeBandwidthPolicy {
            global_bytes_per_second: 65_536,
            global_burst_bytes: 131_072,
            peer_bytes_per_second: 32_768,
            peer_burst_bytes: 65_536,
        });
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
        for (source, destination) in [(0, 2), (2, 0)] {
            assert!(matches!(
                nodes[source]
                    .controller
                    .open_route(identities[destination])
                    .await
                    .unwrap(),
                RouteAccess::Free(_)
            ));
        }
        let server = MeshMintBridge::serve(nodes[2].endpoint.clone(), PORT, backend)
            .await
            .unwrap();
        let client =
            MeshMintBridge::connect(nodes[0].endpoint.clone(), PORT, identities[2], listener)
                .await
                .unwrap();
        // Exercise request EOF and complete response delivery before wallet
        // operations. Neither HTTP bytes nor funding commands go over the LAN.
        let mut request = TcpStream::connect(address).await.unwrap();
        request
            .write_all(b"GET /v1/info HTTP/1.1\r\nHost: mint\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        request.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), request.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "mint response: {}",
            String::from_utf8_lossy(&response)
        );
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
        let collected = root.path().join("collected");
        receive_payment_token(&collected, &payment.token)
            .await
            .unwrap();
        assert_eq!(
            load_mint_balance(&wallet, &url).await.unwrap().balance_sat,
            0
        );
        assert_eq!(
            load_mint_balance(&collected, &url)
                .await
                .unwrap()
                .balance_sat,
            16
        );
        let stats = nodes[1].free.stats();
        assert!(stats.admitted_packets > 0 && stats.admitted_session_bytes > 0);
        assert!(stats.bandwidth.unwrap().admitted_packets > 0);
        for node in &nodes {
            assert!(node.controller.purchases().await.unwrap().is_empty());
        }
        for (path, bytes) in untouched {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        for node in nodes {
            node.shutdown().await.unwrap();
        }
    })
    .await
    .expect("mesh mint acceptance deadline");
}
