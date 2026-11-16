//! Keep both former neighbors alive while mint forwarding changes direction.
use super::*;
use fips_core::{SimLink, SimNetwork, config::SimTransportConfig};
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Clone, Copy, Debug)]
enum Failure {
    Disconnected,
    ForwardLoss,
    ReturnLoss,
}

impl Failure {
    fn apply(self, network: &SimNetwork, proxy: &MintProxy) {
        let (source, destination) = match self {
            Self::Disconnected => {
                network.set_link_up("1", "2", false);
                return;
            }
            Self::ForwardLoss => ("1", "2"),
            Self::ReturnLoss => ("2", "1"),
        };
        // The link remains enabled, but packets and discovery advertisements
        // disappear in one direction. Never repair it to obtain settlement.
        network.set_directed_link(
            source,
            destination,
            Some(SimLink {
                loss_probability: 1.0,
                ..Default::default()
            }),
        );
        // A forward-only loss can still deliver the already committed reply.
        // Discard that response so both directed cases exercise restoration.
        proxy.state.lose_swap_reply.store(true, Ordering::SeqCst);
    }
}

async fn info(address: SocketAddr) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut socket = TcpStream::connect(address)
            .await
            .map_err(|e| e.to_string())?;
        socket
            .write_all(b"GET /v1/info HTTP/1.1\r\nHost: mint\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        socket
            .take(128 * 1024)
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        if response.starts_with(b"HTTP/1.1 200") && response.windows(6).any(|w| w == b"\"nuts\"") {
            Ok(())
        } else {
            Err(format!("incomplete mint info: {} bytes", response.len()))
        }
    })
    .await
    .map_err(|_| "mint info deadline".to_owned())?
}

async fn topology(nodes: &[RelayService], identities: &[PeerIdentity], changed: bool) {
    let wanted: [&[usize]; 4] = if changed {
        [&[1, 2], &[0], &[0, 3], &[2]]
    } else {
        [&[1], &[0, 2], &[1, 3], &[2]]
    };
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let mut ready = true;
            for (i, node) in nodes.iter().enumerate() {
                let connected: BTreeSet<_> = node
                    .endpoint
                    .peers()
                    .await
                    .unwrap()
                    .into_iter()
                    .filter(|p| p.connected)
                    .map(|p| p.node_addr)
                    .collect();
                ready &= connected
                    == wanted[i]
                        .iter()
                        .map(|j| *identities[*j].node_addr())
                        .collect();
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("exact mesh edges must be observed");
}

async fn settle_through_customer(
    nodes: &[RelayService],
    configs: &[ServiceConfig],
    identities: &[PeerIdentity],
    network: &SimNetwork,
    proxy: &MintProxy,
    channel: &str,
    failure: Failure,
) -> u64 {
    let buyer_path = configs[0]
        .state_directory
        .join("controller/controller.json");
    let seller_path = configs[1]
        .state_directory
        .join("controller/controller.json");
    let original: Value = read_json(&buyer_path).unwrap();
    let saved: Value = read_json(&cashu_service::spilman_client_store_path(
        &configs[0].state_directory.join("wallet"),
    ))
    .unwrap();
    let proofs: Vec<cashu::nuts::Proof> = serde_json::from_str(
        saved["funding"][channel]["funding_proofs_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let inputs: BTreeSet<_> = proofs.iter().map(|p| p.y().unwrap().to_string()).collect();
    assert!(!inputs.is_empty());
    let (committed, release) = proxy.state.pause_matching_swap_reply(move |swap| {
        swap.inputs().len() == inputs.len()
            && swap
                .inputs()
                .iter()
                .all(|p| p.y().is_ok_and(|y| inputs.contains(&y.to_string())))
    });
    let controller = nodes[0].controller.clone();
    let id = channel.to_owned();
    let mut close = tokio::spawn(async move { controller.settle_channel(&id).await });
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = committed => result.unwrap(),
            result = &mut close => panic!("close ended before its committed mint reply: {result:?}"),
        }
    }).await.unwrap();
    let swaps = proxy.state.swaps.load(Ordering::SeqCst);
    let attempts = proxy.state.swap_attempts.load(Ordering::SeqCst);
    let restores = proxy.state.restores.load(Ordering::SeqCst);
    proxy.state.reject_swap_replay.store(true, Ordering::SeqCst);
    let before = network.stats();
    failure.apply(network, proxy);
    release.send(()).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let interrupted: Value = read_json(&seller_path).unwrap();
    assert!(interrupted["seller_settlements"][channel]["report"].is_null());
    network.set_link("0", "2", SimLink::default());
    topology(nodes, identities, true).await;
    eprintln!(
        "mint handover: replacement edges observed; waiting only for normal settlement workers"
    );
    // Read journals only. No fresh HTTP probe, quote, admin retry or service
    // restart may prepare the provider's replacement mint route for it.
    let recovered = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let buyer: Value = read_json(&buyer_path).unwrap();
            let seller: Value = read_json(&seller_path).unwrap();
            for key in ["funding", "next_funding", "policy"] {
                assert_eq!(buyer[key], original[key]);
            }
            assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), swaps);
            assert_eq!(proxy.state.swap_attempts.load(Ordering::SeqCst), attempts);
            let purchase = &buyer["buyer_settlements"][channel];
            let sale = &seller["seller_settlements"][channel];
            if purchase["released"] == true
                && purchase["refunded"] == true
                && sale["released"] == true
            {
                assert_eq!(purchase["report"], sale["report"]);
                assert_eq!(purchase["payment"], sale["payment"]);
                let paid = purchase["report"]["paid_sat"].as_u64().unwrap();
                assert!(paid > 0 && paid <= 8);
                assert_eq!(purchase["report"]["refunded_sat"], 8 - paid);
                return paid;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if recovered.is_err() {
        for (i, node) in nodes.iter().enumerate() {
            for command in ["show_tree", "show_routing", "show_sessions"] {
                let snapshot = native_request(&node.config, &json!({"command": command})).await;
                eprintln!("mint handover node {i} {command}: {snapshot:?}");
            }
        }
    }
    assert!(
        recovered.is_ok(),
        "mint handover settlement: provider {:?}; transit {:?}",
        nodes[1].controller.last_error(),
        nodes[0].free.stats()
    );
    let original_result = tokio::time::timeout(Duration::from_secs(5), close)
        .await
        .unwrap()
        .unwrap();
    eprintln!("mint handover: original close result {original_result:?}");
    assert!(proxy.state.restores.load(Ordering::SeqCst) > restores);
    if !matches!(failure, Failure::Disconnected) {
        assert!(network.stats().delta_since(&before).packets_dropped_loss > 0);
        assert!(!proxy.state.lose_swap_reply.load(Ordering::SeqCst));
    }
    proxy
        .state
        .reject_swap_replay
        .store(false, Ordering::SeqCst);
    recovered.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settlement_requotes_after_its_customer_becomes_the_mint_transit_peer() {
    exercise(Failure::Disconnected).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settlement_recovers_after_forward_only_link_loss() {
    exercise(Failure::ForwardLoss).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settlement_recovers_after_return_only_link_loss() {
    exercise(Failure::ReturnLoss).await;
}

async fn exercise(failure: Failure) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    tokio::time::timeout(Duration::from_secs(240), async {
        eprintln!("mint handover: {failure:?}");
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payments = PaymentNetwork::new(318, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            payments.clone(),
            "handover-mint",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let proxy = MintProxy::start(mint.url()).await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        let url = format!("http://{address}");
        let name = format!("mint-handover-{}", Identity::generate().node_addr());
        let network = SimNetwork::new(318);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        for (a, b) in [(0, 1), (1, 2), (2, 3)] {
            network.set_link(a.to_string(), b.to_string(), SimLink::default());
        }
        fips_core::register_sim_network(name.clone(), network.clone());
        // Hold routing identities fixed as well as link randomness. Keep the
        // customer as tree root, matching the failed physical return-loss case.
        let mut keys: Vec<_> = [11, 23, 47, 83]
            .into_iter()
            .map(|seed| Identity::from_secret_bytes(&[seed; 32]).unwrap())
            .collect();
        keys.sort_by_key(|identity| *identity.node_addr());
        keys.swap(1, 3);
        let mut configs = Vec::new();
        for i in 0..4 {
            let mut config: ServiceConfig =
                serde_json::from_str(include_str!("../../../service.example.json")).unwrap();
            config.state_directory = root.path().join(format!("node-{i}"));
            config.terms.billing = BillingBasis::ForwardingData;
            config.terms.controller.mint_url = url.clone();
            config.terms.controller.channel_capacity_sat = 8;
            config.terms.controller.max_locked_sat = 8;
            config.terms.controller.max_wallet_spend_sat = 16;
            config.terms.buyer_budget_sat = 16;
            config.terms.quote_max_units = 2 * 1024 * 1024;
            config.neighbor_admission =
                crate::control_transport::NeighborAdmission::AuthenticatedAdjacent;
            config.return_allowance = true;
            config.free_bandwidth = Some(FreeBandwidthPolicy {
                global_bytes_per_second: 65_536,
                global_burst_bytes: 131_072,
                peer_bytes_per_second: 32_768,
                peer_burst_bytes: 65_536,
            });
            config.return_bandwidth = Some(FreeBandwidthPolicy {
                global_bytes_per_second: 32_768,
                global_burst_bytes: 65_536,
                peer_bytes_per_second: 8_192,
                peer_burst_bytes: 16_384,
            });
            config.transports = TransportsConfig {
                sim: TransportInstances::Single(SimTransportConfig {
                    network: Some(name.clone()),
                    addr: Some(i.to_string()),
                    auto_connect: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            };
            configs.push(config);
        }
        configs[3].mint_export = Some(crate::mint_mesh::MintExport {
            backend: proxy.url.strip_prefix("http://").unwrap().parse().unwrap(),
            service_port: PORT,
        });
        let gateway =
            RelayService::initialize_with_identity(configs[3].clone(), keys.pop().unwrap())
                .await
                .unwrap();
        configs[1].terms.mint_mesh = Some(crate::mint_mesh::MintMesh {
            npub: gateway.clone(),
            service_port: PORT,
        });
        let mut identities = Vec::new();
        for (config, key) in configs[..3].iter_mut().zip(keys) {
            config.destination_fees = serde_json::from_value(json!({gateway.clone(): 0})).unwrap();
            let npub = RelayService::initialize_with_identity(config.clone(), key)
                .await
                .unwrap();
            identities.push(PeerIdentity::from_npub(&npub).unwrap());
        }
        identities.push(PeerIdentity::from_npub(&gateway).unwrap());
        drop(reserved);
        let mut nodes = Vec::new();
        for config in &configs[1..] {
            nodes.push(RelayService::load(config.clone()).await.unwrap());
        }
        // All wallets share the provider's canonical loopback URL in this
        // process. Its adapter must negotiate the changed path itself; fresh
        // diagnostic HTTP requests must not prepare that path during recovery.
        let wallet = configs[0].state_directory.join("wallet");
        let quote = create_topup_quote(&wallet, &url, 16).await.unwrap();
        payments
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
            load_mint_balance(&wallet, &url).await.unwrap().balance_sat,
            16
        );
        nodes.insert(0, RelayService::load(configs[0].clone()).await.unwrap());
        topology(&nodes, &identities, false).await;
        // Warm the original customer's quoted path and native session. This
        // node stays alive when the provider later needs it in reverse.
        assert!(matches!(
            nodes[0].controller.open_route(identities[3]).await.unwrap(),
            RouteAccess::Free(_)
        ));
        let initial = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let initial_address = initial.local_addr().unwrap();
        let customer =
            MeshMintBridge::connect(nodes[0].endpoint.clone(), PORT, identities[3], initial)
                .await
                .unwrap();
        info(initial_address).await.unwrap();
        info(address).await.unwrap();
        for node in &nodes {
            let tree = native_request(&node.config, &json!({"command": "show_tree"}))
                .await
                .unwrap();
            assert_eq!(tree["data"]["root"], identities[0].node_addr().to_string());
        }
        let RouteAccess::Paid(purchase) =
            nodes[0].controller.open_route(identities[2]).await.unwrap()
        else {
            panic!("non-mint transit must remain paid");
        };
        let channel = &purchase.channel.id;
        let payload = b"paid payload before the provider needs its customer for mint transit";
        nodes[0]
            .endpoint
            .send_datagram(identities[2], DATA_PORT, DATA_PORT, payload.to_vec())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while nodes[2].received.lock().unwrap().packets == 0
                || nodes[1].seller.channel_usage(channel).unwrap().paid_msat == 0
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let paid = settle_through_customer(
            &nodes,
            &configs,
            &identities,
            &network,
            &proxy,
            channel,
            failure,
        )
        .await;
        assert!(nodes[0].free.stats().admitted_session_bytes > 0);
        assert!(
            nodes[0]
                .forwarding
                .relay
                .return_stats()
                .unwrap()
                .traffic
                .admitted_packets
                > 0
        );
        customer.shutdown().await.unwrap();
        nodes.remove(1).shutdown().await.unwrap();
        nodes.remove(0).shutdown().await.unwrap();
        // Both account owners are stopped. Collect through the remaining
        // mint-side FIPS endpoint to verify the recovered proofs are spendable.
        let collection = MeshMintBridge::connect(
            nodes[0].endpoint.clone(),
            PORT,
            identities[3],
            TcpListener::bind(address).await.unwrap(),
        )
        .await
        .unwrap();
        let collected = root.path().join("collected");
        for (config, balance) in [(&configs[0], 16 - paid), (&configs[1], paid)] {
            let wallet = config.state_directory.join("wallet");
            assert_eq!(
                load_mint_balance(&wallet, &url).await.unwrap().balance_sat,
                balance
            );
            let payment = send_payment_token(&wallet, &url, balance).await.unwrap();
            receive_payment_token(&collected, &payment.token)
                .await
                .unwrap();
            assert_eq!(
                load_mint_balance(&wallet, &url).await.unwrap().balance_sat,
                0
            );
        }
        assert_eq!(
            load_mint_balance(&collected, &url)
                .await
                .unwrap()
                .balance_sat,
            16
        );
        eprintln!("mint handover: {failure:?} collected all sixteen test sats");
        collection.shutdown().await.unwrap();
        for node in nodes {
            node.shutdown().await.unwrap();
        }
        fips_core::unregister_sim_network(&name);
    })
    .await
    .expect("mint handover test deadline");
}
