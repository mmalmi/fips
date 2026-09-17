//! Real controllers, test-money channels, native FIPS/MMP and SimNetwork.
#[path = "priced_paths/impairments.rs"]
mod impairments;
use cashu_service::{
    FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig, create_topup_quote,
    load_mint_balance, load_wallet_overview,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::{
    Config, FipsEndpoint, Identity, PeerIdentity, SimLink, SimNetwork,
    config::{PeerConfig, SimTransportConfig, TransportInstances},
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use fips_relay::{
    buyer::{BuyerAuthorizer, PaidForwarder},
    control_transport::ControlTransport,
    controller::{
        Controller, ControllerPolicy, ControllerServices, ControllerTasks, RenewalPolicy,
        RouteAccess,
    },
    durable::DurableRelay,
    ledger::{BillingBasis, Limits},
    payment_control::{PaymentControl, PaymentServer},
    route_quotes::{PriceSelectionPolicy, QuotePolicy, QuoteServer, RouteQuotes},
};
use impairments::Scenario;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
struct Gate {
    paid: PaidForwarder,
    blackhole: AtomicBool,
    dropped: AtomicU64,
    refused: AtomicU64,
}
impl ForwardingPolicy for Gate {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        if self.blackhole.load(Ordering::Relaxed) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            None
        } else {
            let result = self.paid.admit(request);
            if result.is_none() {
                self.refused.fetch_add(1, Ordering::Relaxed);
            }
            result
        }
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.paid.complete(token, outcome);
    }
}

fn policy(mint: &str) -> ControllerPolicy {
    ControllerPolicy {
        mint_url: mint.into(),
        channel_capacity_sat: 64,
        max_locked_sat: 128,
        max_funding_overhead_sat: 0,
        max_wallet_spend_sat: 1024,
        channel_lifetime_secs: 600,
        renewal: Some(RenewalPolicy {
            at_capacity_percent: 90,
            before_expiry_secs: 30,
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priced_paths_follow_quality_upgrade_trials_and_keep_channel_evidence() {
    for root_index in 0..4 {
        eprintln!("priced diamond root placement {root_index}");
        tokio::time::timeout(
            Duration::from_secs(180),
            run(root_index, Scenario::Blackhole, 114),
        )
        .await
        .expect("priced path scenario deadline");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exhausted_trial_does_not_renew_and_survives_controller_reload() {
    for iteration in 0..3 {
        eprintln!("quota trial repetition {iteration}");
        tokio::time::timeout(Duration::from_secs(90), run(0, Scenario::Exhaustion, 114))
            .await
            .expect("trial cap scenario deadline");
    }
}

fn selection_policy() -> PriceSelectionPolicy {
    PriceSelectionPolicy {
        feedback_timeout_ms: 2_000,
        retry_after_ms: 60_000,
        trial_max_units: 8192,
        ..Default::default()
    }
}

fn errors(controllers: &[Arc<Controller>]) -> Vec<(usize, String)> {
    controllers
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.last_error().map(|e| (i, e)))
        .collect()
}

async fn run(root_index: usize, scenario: Scenario, seed: u64) {
    let exhaust_trial = matches!(scenario, Scenario::Exhaustion);
    let selection = scenario.selection_policy();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let root = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payments = PaymentNetwork::new(114, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(
        root.path(),
        payments.clone(),
        "priced-paths",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    let network_name = format!("priced-{}", Identity::generate().node_addr());
    let network = SimNetwork::new(seed);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    let edges = [(0, 1), (0, 2), (1, 3), (2, 3)];
    for (a, b) in edges {
        network.set_link(
            a.to_string(),
            b.to_string(),
            SimLink {
                latency_ms: 2,
                ..Default::default()
            },
        );
    }
    fips_core::register_sim_network(network_name.clone(), network.clone());
    let mut nodes = Vec::new();
    let mut peers = Vec::new();
    let mut buyers = Vec::new();
    let mut sellers = Vec::new();
    let mut gates = Vec::new();
    let mut wallets = Vec::new();
    let mut receivers = Vec::new();
    let mut keys: Vec<_> = (1..=4)
        .map(|n| Identity::from_secret_bytes(&[n; 32]).unwrap())
        .collect();
    keys.sort_by_key(|k| *k.node_addr());
    keys.swap(0, root_index);
    for (i, key) in keys.into_iter().enumerate() {
        let peer = PeerIdentity::from_pubkey_full(key.pubkey_full());
        let seller = Arc::new(
            DurableRelay::create(
                &root.path().join(format!("seller-{i}")),
                Limits::default(),
                8_000,
            )
            .unwrap(),
        );
        let buyer = Arc::new(
            BuyerAuthorizer::create(
                &root.path().join(format!("buyer-{i}")),
                *peer.node_addr(),
                128,
                Limits::default(),
            )
            .unwrap(),
        );
        let gate = Arc::new(Gate {
            paid: PaidForwarder::for_billing(
                seller.clone(),
                buyer.clone(),
                BillingBasis::ForwardingData,
            )
            .with_return_allowance()
            .unwrap(),
            blackhole: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        });
        let mut config = Config::new();
        config.node.identity.nsec = Some(fips_core::encode_nsec(&key.keypair().secret_key()));
        config.node.control.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(network_name.clone()),
            addr: Some(i.to_string()),
            mtu: Some(1280),
            auto_connect: Some(false),
            accept_connections: Some(true),
        });
        let node = Arc::new(
            FipsEndpoint::builder()
                .config(config)
                .without_system_tun()
                .forwarding_policy(gate.clone())
                .originated_session_observer(buyer.clone())
                .bind()
                .await
                .unwrap(),
        );
        receivers.push(node.register_service_receiver(44_740).await.unwrap());
        let wallet = root.path().join(format!("wallet-{i}"));
        // Initialize isolated wallets; only the source opens forwarding channels.
        let amount = if i == 0 { 256 } else { 1 };
        let topup = create_topup_quote(&wallet, mint.url(), amount)
            .await
            .unwrap();
        payments
            .orchestrator_funding()
            .settle_external(&topup.payment_request)
            .unwrap();
        assert!(
            load_wallet_overview(&wallet, true)
                .await
                .unwrap()
                .warnings
                .is_empty()
        );
        nodes.push(node);
        peers.push(peer);
        sellers.push(seller);
        buyers.push(buyer);
        gates.push(gate);
        wallets.push(wallet);
    }
    for (i, node) in nodes.iter().enumerate() {
        node.update_peers(
            (0..4)
                .filter(|&j| edges.contains(&(i, j)) || edges.contains(&(j, i)))
                .map(|j| PeerConfig::new(peers[j].npub(), "sim", j.to_string()))
                .collect(),
        )
        .await
        .unwrap();
    }
    let mut controllers = Vec::new();
    let mut services = Vec::new();
    let mut tasks = Vec::new();
    let mut quote_servers = Vec::new();
    let mut quote_inputs = Vec::new();
    let mut payment_servers = Vec::new();
    for i in 0..4 {
        let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
            &root.path().join(format!("receiver-{i}")),
            FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
        )
        .await
        .unwrap();
        let neighbors: Vec<_> = (0..4)
            .filter(|&j| edges.contains(&(i, j)) || edges.contains(&(j, i)))
            .map(|j| peers[j])
            .collect();
        let (transport, incoming) =
            ControlTransport::start(nodes[i].clone(), 44_741, neighbors.clone(), i as u64 + 1)
                .await
                .unwrap();
        let transport = Arc::new(transport);
        let quote_policy = QuotePolicy {
            destination_fees: Default::default(),
            billing: BillingBasis::ForwardingData,
            mint_url: mint.url().into(),
            receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
            fee_msat_per_kib: if i == 2 {
                scenario.alternative_price()
            } else {
                1024
            },
            max_rate_msat_per_kib: 8192,
            lifetime_secs: 300,
            max_units: 1_000_000,
            capacity_sat: 64,
            grace_msat: 8_000,
        };
        quote_inputs.push((transport.clone(), quote_policy.clone()));
        let quotes = RouteQuotes::new(nodes[i].clone(), transport, quote_policy).unwrap();
        let quotes = Arc::new(if i == 0 {
            quotes.with_price_selection(selection.clone()).unwrap()
        } else {
            quotes
        });
        quote_servers.push(QuoteServer::start(quotes.clone(), incoming));
        let (acceptance, incoming) =
            ControlTransport::start(nodes[i].clone(), 44_742, neighbors.clone(), i as u64 + 10)
                .await
                .unwrap();
        let (payment, requests) =
            ControlTransport::start(nodes[i].clone(), 44_743, neighbors, i as u64 + 20)
                .await
                .unwrap();
        let payment_control =
            Arc::new(PaymentControl::new(receiver, sellers[i].clone(), vec![]).unwrap());
        payment_servers.push(PaymentServer::start_shared(
            payment_control.clone(),
            requests,
        ));
        let service = ControllerServices {
            endpoint: nodes[i].clone(),
            quotes,
            acceptance: Arc::new(acceptance),
            payments: Arc::new(payment),
            payment_control,
            seller: sellers[i].clone(),
            buyer: buyers[i].clone(),
            wallet_directory: wallets[i].clone(),
        };
        let controller = Arc::new(
            Controller::create(
                &root.path().join(format!("controller-{i}")),
                policy(mint.url()),
                service.clone(),
            )
            .unwrap(),
        );
        tasks.push(ControllerTasks::start(controller.clone(), incoming));
        controllers.push(controller);
        services.push(service);
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let mut n = 0;
            for node in &nodes {
                n += node
                    .peers()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|p| p.connected)
                    .count();
            }
            if n == 8 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let RouteAccess::Paid(first) = controllers[0]
        .watch_route(peers[3], 4096)
        .await
        .unwrap_or_else(|e| panic!("first purchase: {e}; {:?}", errors(&controllers)))
    else {
        panic!("priced path requires a paid purchase");
    };
    assert_eq!(
        first.provider,
        *peers[1].node_addr(),
        "cheapest initial quote"
    );
    assert_eq!(
        first.contract.max_units, 8192,
        "unknown path is quota limited"
    );
    let polled = services[0].quotes.refresh_route(peers[3]).await.unwrap();
    let fresh = services[0].quotes.request_route(peers[3]).await.unwrap();
    assert_ne!(
        fresh.id, polled.id,
        "explicit fresh requests cannot recycle a trial"
    );
    assert!(fresh.trial && polled.trial);
    assert_eq!(fresh.max_units, polled.max_units);
    assert_eq!(
        controllers[0].purchase_history().await.unwrap(),
        vec![first.clone()],
        "discovery alone does not buy the new quote"
    );
    if exhaust_trial {
        controllers[0].pause_route_refresh().await.unwrap();
        // Establish actual delivery before the saturation phase so setup timing
        // is not mistaken for an allowance result.
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                nodes[0]
                    .send_datagram(peers[3], 44_740, 44_740, vec![6; 200])
                    .await
                    .unwrap();
                if let Ok(Some(_)) = tokio::time::timeout(
                    Duration::from_millis(250),
                    receivers[3].recv_batch_into(&mut received, 32),
                )
                .await
                    && received.iter().any(|m| {
                        m.source_peer.node_addr() == peers[0].node_addr()
                            && m.data.as_slice() == [6; 200]
                    })
                {
                    break;
                }
            }
        })
        .await
        .expect("healthy trial must first deliver its application payload");
        // Renewal stays enabled. The configured 90% threshold would renew a
        // normal agreement; a trial must retain its original cumulative cap.
        for _ in 0..160 {
            nodes[0]
                .send_datagram(peers[3], 44_740, 44_740, vec![6; 200])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_secs(6)).await;
        let observed = buyers[0].observed_units(&first.contract.id).unwrap();
        let usage = sellers[1].usage(&first.contract.id).unwrap();
        let mut delivered = received.len();
        while let Ok(Some(_)) = tokio::time::timeout(
            Duration::from_millis(20),
            receivers[3].recv_batch_into(&mut received, 64),
        )
        .await
        {
            delivered += received.len();
        }
        let quality = nodes[0]
            .source_route_quality(peers[3], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            delivered as u64, quality.sent_packets,
            "all admitted application packets must reach the receiver"
        );
        assert!(
            quality.sent_packets < 160,
            "local allowance denials must not become native sent packets: {quality:?}"
        );
        assert!(
            !quality.delivery_feedback_timed_out,
            "exhausting a healthy trial is not a failed carrier: {quality:?} observed={observed} usage={usage:?} returns={:?} errors={:?}",
            gates
                .iter()
                .map(|g| (g.paid.return_stats(), g.refused.load(Ordering::Relaxed)))
                .collect::<Vec<_>>(),
            errors(&controllers)
        );
        let after_exhaustion = services[0].quotes.refresh_route(peers[3]).await.unwrap();
        assert_eq!(
            after_exhaustion.provider, first.provider,
            "exhaustion cannot quarantine the healthy cheap provider"
        );
        assert!(
            observed >= first.contract.max_units * 90 / 100,
            "trial must really reach its cap: observed={observed} usage={usage:?} quality={quality:?} errors={:?}",
            errors(&controllers)
        );
        assert!(observed <= first.contract.max_units);
        assert!(usage.submitted_units > 0 && usage.reserved_units <= first.contract.max_units);
        assert_eq!(
            controllers[0].purchase_history().await.unwrap(),
            vec![first.clone()]
        );
        assert_eq!(controllers[0].locked_capital_sat().await.unwrap(), 64);
    } else {
        let mut batch = Vec::new();
        // The sender's return reports must traverse the corresponding earned return
        // allowance; the receiver neither purchases a route nor sends app ACKs.
        let mut delivered = 0;
        let upgraded = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                nodes[0]
                    .send_datagram(peers[3], 44_740, 44_740, vec![7; 200])
                    .await
                    .unwrap();
                if let Ok(Some(_)) = tokio::time::timeout(
                    Duration::from_millis(200),
                    receivers[3].recv_batch_into(&mut batch, 32),
                )
                .await
                {
                    delivered += batch
                        .iter()
                        .filter(|m| {
                            m.source_peer.node_addr() == peers[0].node_addr()
                                && m.data.as_slice() == [7; 200]
                        })
                        .count();
                }
                if let Some(p) = controllers[0]
                    .purchases()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|p| p.contract.max_units > 8192)
                {
                    break p;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        if upgraded.is_err() {
            eprintln!(
                "trial diagnostics: delivered={delivered} quality={:?} observed={:?} usage={:?} watches={} returns={}",
                nodes[0]
                    .source_route_quality(peers[3], Duration::from_secs(2))
                    .await
                    .unwrap(),
                buyers[0].observed_units(&first.contract.id),
                sellers[1].usage(&first.contract.id),
                serde_json::to_string(&controllers[0].watched_routes().await.unwrap()).unwrap(),
                serde_json::to_string(&gates[1].paid.return_stats()).unwrap()
            );
        }
        let upgraded = upgraded
            .unwrap_or_else(|_| panic!("healthy trial upgrade: {:?}", errors(&controllers)));
        assert_eq!(upgraded.provider, first.provider);
        assert_eq!(
            upgraded.channel.id, first.channel.id,
            "quota upgrade reuses channel and financial history"
        );
        assert_ne!(upgraded.contract.id, first.contract.id);
        assert!(delivered > 0, "trial payload reached its intended endpoint");
        let quality = nodes[0]
            .source_route_quality(peers[3], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(quality.next_hop, Some(first.provider));
        assert!(quality.has_recent_delivery_feedback);
        // Quotes/payment control are still local to the bad provider and continue
        // working. Only native end-to-end evidence can identify its blackhole.
        if matches!(scenario, Scenario::Blackhole) {
            gates[1].blackhole.store(true, Ordering::Relaxed);
        } else {
            impairments::observe_then_select(
                scenario,
                &network,
                &nodes,
                &peers,
                &controllers[0],
                &mut receivers[3],
            )
            .await;
        }
        let replacement = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                nodes[0]
                    .send_datagram(peers[3], 44_740, 44_740, vec![8; 200])
                    .await
                    .unwrap();
                if let Some(p) = controllers[0]
                    .purchases()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|p| p.provider == *peers[2].node_addr())
                {
                    break p;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("impaired path replacement: {:?}", errors(&controllers)));
        assert_eq!(
            replacement.contract.price.msat,
            scenario.alternative_price()
        );
        assert_eq!(replacement.contract.max_units, 8192);
        if matches!(scenario, Scenario::Blackhole) {
            assert!(gates[1].dropped.load(Ordering::Relaxed) > 0);
        }
        assert_eq!(
            nodes[0]
                .peers()
                .await
                .unwrap()
                .iter()
                .filter(|p| p.connected)
                .count(),
            2
        );
        let mut replacement_delivered = false;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                nodes[0]
                    .send_datagram(peers[3], 44_740, 44_740, vec![9; 200])
                    .await
                    .unwrap();
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    receivers[3].recv_batch_into(&mut batch, 32),
                )
                .await;
                replacement_delivered |= batch.iter().any(|m| {
                    m.source_peer.node_addr() == peers[0].node_addr()
                        && m.data.as_slice() == [9; 200]
                });
                let q = nodes[0]
                    .source_route_quality(peers[3], Duration::from_secs(2))
                    .await
                    .unwrap();
                if replacement_delivered
                    && q.next_hop == Some(replacement.provider)
                    && q.has_recent_delivery_feedback
                {
                    assert!(
                        q.rtt_ms
                            .is_some_and(|rtt| rtt <= selection.max_rtt_ms as f64),
                        "replacement must meet the latency limit: {q:?}"
                    );
                    assert!(
                        gates[2]
                            .paid
                            .return_stats()
                            .unwrap()
                            .traffic
                            .admitted_packets
                            > 0,
                        "native feedback must use the replacement's earned return allowance"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("working alternative carries payload and native feedback");
        assert!(controllers[0].locked_capital_sat().await.unwrap() <= 128);
        // Re-polling cheaper advertisements retains the working alternative through
        // measured cost, switching margin or failed-provider cooldown.
        let current = controllers[0].buy_route(peers[3]).await.unwrap();
        assert_eq!(current.provider, replacement.provider);
        controllers[0].pause_route_refresh().await.unwrap();
        controllers[0].pause_renewals().await.unwrap();
    }
    let remaining = buyers[0].remaining_budget_sat().unwrap();
    assert!(remaining < 128 && remaining > 0);
    controllers[0].pause_route_refresh().await.unwrap();
    // Keep renewals enabled for the exhausted trial through reload.
    if !exhaust_trial {
        controllers[0].pause_renewals().await.unwrap();
    }
    let current = controllers[0].purchases().await.unwrap().pop().unwrap();
    let history = controllers[0].purchase_history().await.unwrap();
    let locked = controllers[0].locked_capital_sat().await.unwrap();
    let incoming = tasks.remove(0).stop().await.unwrap();
    drop(controllers.remove(0));
    nodes[0].set_source_route(peers[3], None).await.unwrap();
    let (transport, quote_policy) = &quote_inputs[0];
    services[0].quotes = Arc::new(
        RouteQuotes::new(nodes[0].clone(), transport.clone(), quote_policy.clone())
            .unwrap()
            .with_price_selection(selection.clone())
            .unwrap(),
    );
    let restored = Arc::new(
        Controller::load(
            &root.path().join("controller-0"),
            policy(mint.url()),
            services[0].clone(),
        )
        .unwrap(),
    );
    // A controller + selector reload, retaining the live native/control plane.
    restored.resume_pending().await.unwrap();
    assert_eq!(restored.purchase_history().await.unwrap(), history);
    assert_eq!(restored.locked_capital_sat().await.unwrap(), locked);
    tasks.insert(0, ControllerTasks::start(restored.clone(), incoming));
    controllers.insert(0, restored);
    let mut restored_payload = false;
    let mut batch = Vec::new();
    for _ in 0..20 {
        nodes[0]
            .send_datagram(peers[3], 44_740, 44_740, vec![10; 200])
            .await
            .unwrap();
        if let Ok(Some(_)) = tokio::time::timeout(
            Duration::from_millis(200),
            receivers[3].recv_batch_into(&mut batch, 32),
        )
        .await
        {
            restored_payload |= batch.iter().any(|m| {
                m.source_peer.node_addr() == peers[0].node_addr() && m.data.as_slice() == [10; 200]
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let q = nodes[0]
        .source_route_quality(peers[3], Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        q.next_hop,
        if exhaust_trial {
            None
        } else {
            Some(current.provider)
        },
        "a denied post-reload send cannot invent an observed carrier"
    );
    assert_eq!(
        restored_payload, !exhaust_trial,
        "reload cannot reset an exhausted trial"
    );
    assert_eq!(controllers[0].purchase_history().await.unwrap(), history);
    assert_eq!(controllers[0].locked_capital_sat().await.unwrap(), locked);
    controllers[0].pause_renewals().await.unwrap();
    // Settle both used neighbor channels, including the retired path. Their
    // accounting is retained across replacement; no source budget is reset.
    let channels: std::collections::BTreeSet<_> = history.iter().map(|p| &p.channel.id).collect();
    for channel in channels {
        controllers[0].settle_channel(channel).await.unwrap();
    }
    assert!(buyers[0].remaining_budget_sat().unwrap() <= remaining);
    assert_eq!(controllers[0].locked_capital_sat().await.unwrap(), 0);
    let mut total = 0;
    for wallet in &wallets {
        total += load_mint_balance(wallet, mint.url())
            .await
            .unwrap()
            .balance_sat;
    }
    assert_eq!(
        total, 259,
        "all isolated test money is conserved after settlement"
    );
    for task in tasks.drain(..) {
        task.stop().await;
    }
    drop(controllers);
    drop(services);
    for server in quote_servers {
        server.stop().await;
    }
    for server in payment_servers {
        server.stop().await;
    }
    for node in nodes {
        node.shutdown().await.unwrap();
    }
    fips_core::unregister_sim_network(&network_name);
}
