//! Each router independently accepts, funds onward channels and pays usage.
use cashu_service::{
    FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig, create_topup_quote,
    load_mint_balance, load_wallet_overview, receive_payment_token, send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::{
    Config, FipsEndpoint, PeerIdentity,
    config::{PeerConfig, TransportInstances, UdpConfig},
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use fips_relay::{
    buyer::{BuyerAuthorizer, PaidForwarder},
    control_transport::ControlTransport,
    controller::{
        Controller, ControllerPolicy, ControllerRequest, ControllerResponse, ControllerServices,
        ControllerTasks, RenewalPolicy,
    },
    durable::DurableRelay,
    ledger::Limits,
    payment_control::{PaymentControl, PaymentServer},
    route_quotes::{QuotePolicy, QuoteServer, RouteQuotes},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routers_independently_fund_accept_and_pay_both_directions() {
    controller_scenario(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exhausted_channels_renew_automatically_without_resetting_capital_or_spending() {
    controller_scenario(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_buyer_pays_supported_usage_despite_a_provider_evidence_gap() {
    controller_scenario(false, true).await;
}

async fn controller_scenario(automatic_renewal: bool, evidence_gap: bool) {
    tokio::time::timeout(Duration::from_secs(240), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(93, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "autonomous-relay-test",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut nodes = Vec::new();
        let mut peers = Vec::new();
        let mut addresses = Vec::new();
        let mut ledgers = Vec::new();
        let mut buyers = Vec::new();
        let mut data = Vec::new();
        let seed_sat = if automatic_renewal { 256 } else { 128 };
        let capacity = if automatic_renewal { 16 } else { 32 };
        let wallets: Vec<_> = (0..5)
            .map(|i| root.path().join(format!("wallet-{i}")))
            .collect();
        for (i, wallet) in wallets.iter().enumerate() {
            let identity = fips_core::Identity::generate();
            let peer = PeerIdentity::from_pubkey_full(identity.pubkey_full());
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
                    if automatic_renewal { 256 } else { 64 },
                    Limits::default(),
                )
                .unwrap(),
            );
            let mut config = Config::new();
            config.node.identity.nsec =
                Some(fips_core::encode_nsec(&identity.keypair().secret_key()));
            config.node.control.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.local.enabled = false;
            config.transports.udp = TransportInstances::Single(UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                advertise_on_nostr: Some(false),
                ..UdpConfig::default()
            });
            let node = Arc::new(
                FipsEndpoint::builder()
                    .config(config)
                    .forwarding_policy(Arc::new(PaidForwarder::new(seller.clone(), buyer.clone())))
                    .originated_session_observer(buyer.clone())
                    .without_system_tun()
                    .bind()
                    .await
                    .unwrap(),
            );
            addresses.push(node.bound_udp_listen_addrs().await.unwrap()[0]);
            data.push(node.register_service_receiver(44_740).await.unwrap());
            peers.push(peer);
            nodes.push(node);
            ledgers.push(seller);
            buyers.push(buyer);
            let quote = create_topup_quote(wallet, mint.url(), seed_sat).await.unwrap();
            network
                .orchestrator_funding()
                .settle_external(&quote.payment_request)
                .unwrap();
            assert!(
                load_wallet_overview(wallet, true)
                    .await
                    .unwrap()
                    .warnings
                    .is_empty()
            );
        }
        for (i, node) in nodes.iter().enumerate() {
            node.update_peers(
                peers
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| i.abs_diff(*j) == 1)
                    .map(|(j, _)| PeerConfig::new(nodes[j].npub(), "udp", addresses[j].to_string()))
                    .collect(),
            )
            .await
            .unwrap();
        }
        let mut controllers = Vec::new();
        let mut tasks = Vec::new();
        let mut quote_servers = Vec::new();
        let mut payment_servers = Vec::new();
        let mut services = Vec::new();
        for i in 0usize..5 {
            let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                &root.path().join(format!("receiver-{i}")),
                FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
            )
            .await
            .unwrap();
            let neighbors: Vec<_> = peers
                .iter()
                .enumerate()
                .filter(|(j, _)| i.abs_diff(*j) == 1)
                .map(|(_, p)| *p)
                .collect();
            let (quote_transport, quote_incoming) =
                ControlTransport::start(nodes[i].clone(), 44_741, neighbors.clone(), i as u64 + 1)
                    .await
                    .unwrap();
            let quotes = Arc::new(
                RouteQuotes::new(
                    nodes[i].clone(),
                    Arc::new(quote_transport),
                    QuotePolicy {
                        mint_url: mint.url().to_string(),
                        receiver_pubkey_hex: receiver.receiver_pubkey_hex().to_string(),
                        fee_msat_per_kib: 1_024,
                        max_rate_msat_per_kib: 8_192,
                        lifetime_secs: 300,
                        max_units: 30_000,
                        capacity_sat: capacity,
                        grace_msat: 8_000,
                    },
                )
                .unwrap(),
            );
            quote_servers.push(QuoteServer::start(quotes.clone(), quote_incoming));
            let (acceptance, incoming) =
                ControlTransport::start(nodes[i].clone(), 44_742, neighbors.clone(), i as u64 + 10)
                    .await
                    .unwrap();
            let (payments, payment_incoming) =
                ControlTransport::start(nodes[i].clone(), 44_743, neighbors, i as u64 + 20)
                    .await
                    .unwrap();
            let payment_control =
                Arc::new(PaymentControl::new(receiver, ledgers[i].clone(), vec![]).unwrap());
            payment_servers.push(PaymentServer::start_shared(
                payment_control.clone(),
                payment_incoming,
            ));
            services.push(ControllerServices {
                        endpoint: nodes[i].clone(),
                        quotes,
                        acceptance: Arc::new(acceptance),
                        payments: Arc::new(payments),
                        payment_control,
                        seller: ledgers[i].clone(),
                        buyer: buyers[i].clone(),
                        wallet_directory: wallets[i].clone(),
                    });
            let controller = Arc::new(
                Controller::create(
                    &root.path().join(format!("controller-{i}")),
                    policy(mint.url(), automatic_renewal),
                    services[i].clone(),
                )
                .unwrap(),
            );
            tasks.push(ControllerTasks::start(controller.clone(), incoming));
            controllers.push(controller);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut count = 0;
                for n in &nodes {
                    count += n
                        .peers()
                        .await
                        .unwrap()
                        .iter()
                        .filter(|p| p.connected)
                        .count();
                }
                if count == 8 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let (a, b) = tokio::join!(
            controllers[0].buy_route(peers[4]),
            controllers[4].buy_route(peers[0])
        );
        fn errors(controllers: &[Arc<Controller>]) -> Vec<(usize, String)> {
            controllers
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.last_error().map(|e| (i, e)))
                .collect::<Vec<_>>()
        }
        fn recovery_stages(root: &std::path::Path) -> Vec<serde_json::Value> {
            (0..5).map(|i| {
                let path = root.join(format!("controller-{i}/controller.json"));
                let j: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                let rows = |name: &str, fields: &[&str]| j[name].as_object().unwrap().values().map(|row| {
                    fields.iter().map(|field| match &row[*field] {
                        serde_json::Value::Null => "none".to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        serde_json::Value::Array(a) => format!("{} entries", a.len()),
                        _ => "saved".to_string(),
                    }).collect::<Vec<_>>()
                }).collect::<Vec<_>>();
                serde_json::json!({"node": i, "funding": j["funding"].as_object().unwrap().len(),
                    "outgoing": rows("outgoing", &["accepted", "retired"]),
                    "renewals": rows("renewals", &["replacements", "completed"]),
                    "buyer_settlements": rows("buyer_settlements", &["usage", "payment", "report", "refunded"]),
                    "seller_settlements": rows("seller_settlements", &["usage", "payment", "report"])})
            }).collect()
        }
        let (a, b) = (
            a.unwrap_or_else(|e| panic!("forward acceptance: {e}; errors={:?}", errors(&controllers))),
            b.unwrap_or_else(|e| panic!("reverse acceptance: {e}; errors={:?}", errors(&controllers))),
        );
        assert_eq!(a.contract.price.msat, 3_072);
        assert_eq!(b.contract.price.msat, 3_072);
        assert_eq!(
            controllers[0].buy_route(peers[4]).await.unwrap().channel.id,
            a.channel.id,
            "reuse persistent channel on repeated purchase"
        );
        let mut links = Vec::new();
        for (i, controller) in controllers.iter().enumerate() {
            for purchase in controller.purchases().await.unwrap() {
                links.push((
                    i,
                    peers
                        .iter()
                        .position(|p| p.node_addr() == &purchase.provider)
                        .unwrap(),
                    purchase,
                ));
            }
        }
        assert_eq!(links.len(), 6);
        let unauthorized = serde_json::to_vec(&ControllerRequest::Seal { channel_id: a.channel.id.clone() }).unwrap();
        assert!(matches!(controllers[1].handle(peers[2], &unauthorized).await, ControllerResponse::Rejected));
        let mut incoming = Vec::new();
        for task in tasks.drain(..) {
            incoming.push(task.stop().await.unwrap());
        }
        drop(controllers);
        // Model two durable crash boundaries. The provider accepted but the
        // source lost its reply; the other source funded but lost its outgoing
        // contract record. Its earlier authorized offer must recover the same
        // funding identity. Network, seller and buyer services remain running.
        for source in [0, 4] {
            let path = root.path().join(format!("controller-{source}/controller.json"));
            let mut journal: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let outgoing = journal["outgoing"].as_object_mut().unwrap();
            if source == 0 {
                for record in outgoing.values_mut() {
                    record["accepted"] = false.into();
                }
            } else {
                outgoing.clear();
            }
            std::fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
        }
        let mut controllers = Vec::new();
        for (i, receiver) in incoming.into_iter().enumerate() {
            let controller = Arc::new(
                Controller::load(
                    &root.path().join(format!("controller-{i}")),
                    policy(mint.url(), automatic_renewal),
                    services[i].clone(),
                )
                .unwrap(),
            );
            if i == 0 || i == 4 {
                assert!(controller.purchases().await.unwrap().is_empty());
            }
            tasks.push(ControllerTasks::start(controller.clone(), receiver));
            controllers.push(controller);
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if controllers[0].purchases().await.unwrap() == vec![a.clone()]
                    && controllers[4].purchases().await.unwrap() == vec![b.clone()]
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("durable purchase recovery: {:?}", errors(&controllers)));
        for (i, controller) in controllers.iter().enumerate() {
            let expected: Vec<_> = links.iter().filter(|(buyer, _, _)| *buyer == i)
                .map(|(_, _, p)| p.clone()).collect();
            assert_eq!(controller.purchases().await.unwrap(), expected);
            assert_eq!(load_mint_balance(&wallets[i], mint.url()).await.unwrap().balance_sat,
                seed_sat - capacity * expected.len() as u64,
                "controller reload must not fund another channel");
        }
        if evidence_gap {
            // Model one local submission lost from the buyer's last checkpoint:
            // the provider retained it, but the restored buyer has no evidence.
            let (_, _, p) = links.iter().find(|(b,s,_)| *b==2 && *s==3).unwrap();
            let request = ForwardingRequest {
                ingress: peers[2], next_hop: p.contract.next_hop,
                source: *peers[0].node_addr(), destination: p.contract.destination,
                session_payload: &[219; 1_000],
            };
            let token = ledgers[3].admit(&request).unwrap();
            ledgers[3].complete(token, ForwardingOutcome::Submitted);
            ledgers[3].checkpoint().unwrap();
            controllers[2].flush_payments().await.expect("unsupported remainder must not block supported payments");
            assert_eq!(buyers[2].authorized_sat(&p.channel.id), Some(0),
                "provider-only evidence cannot create a payment obligation");
        }
        for round in 0..if automatic_renewal { 18 } else { 8 } {
            for (source, destination) in [(0, 4), (4, 0)] {
                let mut payload = vec![round; 1_000];
                payload[0] = source as u8;
                tokio::time::timeout(Duration::from_secs(30), async {
                    loop {
                        nodes[source].send_datagram(peers[destination], 44_740, 44_740, payload.clone()).await.unwrap();
                        let mut received = Vec::new();
                        if let Ok(result) = tokio::time::timeout(
                            Duration::from_millis(if automatic_renewal { 750 } else { 10_000 }),
                            data[destination].recv_batch_into(&mut received, 8),
                        ).await {
                            result.unwrap();
                            if received.iter().any(|m| m.data.as_slice() == payload) { break; }
                        }
                        assert!(automatic_renewal, "ordinary delivery unexpectedly needed a retry");
                    }
                })
                .await
                .unwrap_or_else(|_| panic!("autonomously paid delivery round={round} direction={source}->{destination}; errors={:?}; usage={:?}; evidence={:?}; stages={:?}", errors(&controllers), links.iter().map(|(b,s,p)|(*b,*s,ledgers[*s].channel_usage(&p.channel.id))).collect::<Vec<_>>(), links.iter().map(|(b,s,p)|(*b,*s,buyers[*b].evidence_msat(&p.channel.id))).collect::<Vec<_>>(), recovery_stages(root.path())));
            }
            for controller in &controllers {
                assert!(controller.locked_capital_sat().await.unwrap() <= capacity * 2);
            }
            // Payments are driven only by each controller's periodic task.
            tokio::time::sleep(Duration::from_millis(600)).await;
        }
        for (_, seller, purchase) in &links {
            assert!(
                ledgers[*seller]
                    .channel_usage(&purchase.channel.id)
                    .unwrap()
                    .paid_msat
                    > 8_000,
                "automatic payments replenished the initial allowance"
            );
        }
        // Freeze a quiescent replacement for the lost-acceptance-reply check.
        // A last in-flight datagram can exhaust a channel after its delivery
        // was observed. Resuming that already-due channel legitimately opens
        // another replacement, which is a different event from reply recovery.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                for controller in &controllers {
                    controller.pause_renewals().await.unwrap();
                }
                let mut stable = true;
                if automatic_renewal {
                    for (i, controller) in controllers.iter().enumerate() {
                        let active = controller.purchases().await.unwrap();
                        stable &= active.len() == if i == 2 { 2 } else { 1 };
                        for p in active {
                            stable &= buyers[i].evidence_msat(&p.channel.id).unwrap()
                                < p.channel.capacity_sat * 1000;
                            stable &= buyers[i].observed_units(&p.contract.id).unwrap()
                                < p.contract.max_units;
                        }
                    }
                }
                if stable { break; }
                for controller in &controllers { controller.resume_renewals().await.unwrap(); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.expect("renewal fixture reaches a funded, non-exhausted checkpoint");
        if !automatic_renewal {
            // An explicit close ends this purchase, not the saved account.
            // Background recovery cannot interpret it as another purchase.
            for controller in &controllers {
                controller.settle_all().await.unwrap();
                assert_eq!(controller.locked_capital_sat().await.unwrap(), 0);
                controller.resume_pending().await.unwrap();
                assert!(controller.purchases().await.unwrap().is_empty());
            }
            if evidence_gap {
                let (_, _, p) = links.iter().find(|(b,s,_)| *b==2 && *s==3).unwrap();
                let usage = ledgers[3].channel_usage(&p.channel.id).unwrap();
                assert!(usage.submitted_msat > usage.paid_msat,
                    "the unsupported remainder stays unpaid after settlement");
                assert_eq!(usage.paid_msat, buyers[2].authorized_sat(&p.channel.id).unwrap()*1000);
            }
            let remaining: Vec<_> = buyers.iter().map(|b| b.remaining_budget_sat().unwrap()).collect();
            let (forward, reverse) = tokio::join!(
                controllers[0].buy_route(peers[4]),
                controllers[4].buy_route(peers[0])
            );
            let forward = forward.expect("explicit repurchase after confirmed refund");
            let reverse = reverse.expect("explicit reverse repurchase after confirmed refund");
            assert_ne!(forward.channel.id, a.channel.id);
            assert_ne!(reverse.channel.id, b.channel.id);
            assert_eq!(controllers[0].buy_route(peers[4]).await.unwrap(), forward);
            for (buyer, left) in buyers.iter().zip(remaining) {
                assert_eq!(buyer.remaining_budget_sat().unwrap(), left,
                    "repurchase cannot reset lifetime authorization");
            }
            for (source, destination) in [(0, 4), (4, 0)] {
                let mut payload = vec![117; 1_000];
                payload[0] = source as u8;
                nodes[source].send_datagram(peers[destination], 44_740, 44_740, payload.clone()).await.unwrap();
                let mut received = Vec::new();
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        data[destination].recv_batch_into(&mut received, 8).await.unwrap();
                        if received.iter().any(|m| m.data.as_slice() == payload) { break; }
                    }
                }).await.expect("same account forwards after repurchase");
            }
            links.clear();
            for (i, controller) in controllers.iter().enumerate() {
                let history = controller.purchase_history().await.unwrap();
                for purchase in history {
                    let seller = peers.iter().position(|p| p.node_addr() == &purchase.provider).unwrap();
                    links.push((i, seller, purchase));
                }
            }
            assert_eq!(links.len(), 12, "retain the six closed channels and six new channels");
        }
        if automatic_renewal {
            for (buyer, _, old) in &links {
                let current = controllers[*buyer].purchases().await.unwrap();
                assert!(current.iter().any(|p| p.provider == old.provider && p.channel.id != old.channel.id), "each original direction needs a replacement channel");
                assert!(buyers[*buyer].evidence_msat(&old.channel.id).unwrap() >= capacity * 1_000,
                    "original channels were replaced because of local capacity evidence");
            }
            let mut active_before = Vec::new();
            let mut funding_before = Vec::new();
            for (i, controller) in controllers.iter().enumerate() {
                active_before.push(controller.purchases().await.unwrap());
                let j: serde_json::Value = serde_json::from_slice(&std::fs::read(root.path().join(format!("controller-{i}/controller.json"))).unwrap()).unwrap();
                funding_before.push(j["funding"].as_object().unwrap().len());
            }
            let mut receiver_streams = Vec::new();
            for task in tasks.drain(..) { receiver_streams.push(task.stop().await.unwrap()); }
            drop(controllers);
            let path = root.path().join("controller-0/controller.json");
            let mut journal: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let current = &mut journal["outgoing"][&active_before[0][0].contract.id];
            current["accepted"] = false.into();
            let offer_id = current["offer"]["id"].clone();
            let mut interrupted = false;
            for renewal in journal["renewals"].as_object_mut().unwrap().values_mut() {
                if renewal["replacements"].as_array().is_some_and(|offers| offers.iter().any(|o| o["id"] == offer_id)) {
                    renewal["completed"] = false.into();
                    interrupted = true;
                }
            }
            assert!(interrupted);
            std::fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
            controllers = Vec::new();
            for (i, incoming) in receiver_streams.into_iter().enumerate() {
                let controller = Arc::new(Controller::load(&root.path().join(format!("controller-{i}")), policy(mint.url(), true), services[i].clone()).unwrap());
                tasks.push(ControllerTasks::start(controller.clone(), incoming));
                controllers.push(controller);
            }
            controllers[0].resume_pending().await.unwrap();
            assert!(controllers[0].purchases().await.unwrap().is_empty(), "paused replacement cannot resend acceptance or fund another channel");
            controllers[0].resume_renewals().await.unwrap();
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let journal: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    if controllers[0].purchases().await.unwrap() == active_before[0]
                        && journal["renewals"].as_object().unwrap().values().all(|r| r["completed"] == true) { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.unwrap_or_else(|_| panic!("interrupted renewal recovery: {:?}; stages={:?}", errors(&controllers), recovery_stages(root.path())));
            controllers[0].pause_renewals().await.unwrap();
            for (i, controller) in controllers.iter().enumerate() {
                assert_eq!(controller.purchases().await.unwrap(), active_before[i]);
                let j: serde_json::Value = serde_json::from_slice(&std::fs::read(root.path().join(format!("controller-{i}/controller.json"))).unwrap()).unwrap();
                assert_eq!(j["funding"].as_object().unwrap().len(), funding_before[i], "renewal recovery cannot fund another channel");
            }
            links.clear();
            for (i, controller) in controllers.iter().enumerate() {
                for purchase in controller.purchase_history().await.unwrap() {
                    let seller = peers.iter().position(|p| p.node_addr() == &purchase.provider).unwrap();
                    links.push((i, seller, purchase));
                }
            }
            assert!(links.len() >= 12);
        }
        for controller in &controllers {
            controller.stop_selling().await.unwrap();
        }
        for controller in &controllers {
            controller.flush_payments().await.unwrap();
        }
        let mut settlement_count = 0;
        for controller in &controllers {
            let reports = controller.settle_all().await
                .unwrap_or_else(|e| panic!("automatic mint settlement: {e}; errors={:?}", errors(&controllers)));
            settlement_count += reports.len();
            assert!(reports.iter().all(|r| r.fee_sat == 0));
            assert_eq!(controller.locked_capital_sat().await.unwrap(), 0);
            assert!(controller.purchases().await.unwrap().is_empty());
        }
        assert_eq!(settlement_count, links.len());
        for (i, buyer) in buyers.iter().enumerate() {
            let authorized: u64 = links.iter().filter(|(b, _, _)| *b == i)
                .map(|(_, _, p)| buyer.authorized_sat(&p.channel.id).unwrap()).sum();
            assert_eq!(buyer.remaining_budget_sat().unwrap() + authorized,
                if automatic_renewal { 256 } else { 64 }, "renewal must preserve the lifetime signing cap");
        }
        let mut expected = [seed_sat as i64; 5];
        for (buyer, seller, purchase) in &links {
            let paid = ledgers[*seller]
                .channel_usage(&purchase.channel.id)
                .unwrap()
                .paid_msat
                / 1_000;
            expected[*buyer] -= paid as i64;
            expected[*seller] += paid as i64;
        }
        assert!(expected[1..4].iter().all(|n| *n > seed_sat as i64));
        for (i, node) in nodes.iter().enumerate() {
            let neighbors = node.peers().await.unwrap();
            assert_eq!(neighbors.len(), if i == 0 || i == 4 { 1 } else { 2 });
            for neighbor in neighbors {
                let j = peers.iter().position(|p| p.node_addr() == &neighbor.node_addr).unwrap();
                assert_eq!(i.abs_diff(j), 1, "native topology cannot acquire a shortcut");
            }
        }
        for task in tasks {
            task.stop().await;
        }
        for server in quote_servers {
            server.stop().await;
        }
        for server in payment_servers {
            server.stop().await;
        }
        for node in &nodes {
            node.shutdown().await.unwrap();
        }
        for (wallet, balance) in wallets.iter().zip(expected) {
            assert_eq!(
                load_mint_balance(wallet, mint.url())
                    .await
                    .unwrap()
                    .balance_sat,
                balance as u64
            );
            let token = send_payment_token(wallet, mint.url(), balance as u64)
                .await
                .unwrap();
            receive_payment_token(&root.path().join("collector"), &token.token)
                .await
                .unwrap();
        }
        for controller in &controllers {
            controller.settle_all().await.unwrap();
        }
        drop(controllers);
        // A crash can lose our completion report after the mint closed and the
        // payout was imported. Even if that payout has since been spent, retry
        // must not reintroduce its old proofs as spendable wallet balance.
        for (i, service) in services.iter().enumerate() {
            let directory = root.path().join(format!("controller-{i}"));
            let path = directory.join("controller.json");
            let mut journal: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            for settlement in journal["seller_settlements"].as_object_mut().unwrap().values_mut() {
                settlement["report"] = serde_json::Value::Null;
            }
            std::fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
            let controller = Controller::load(&directory, policy(mint.url(), automatic_renewal), service.clone()).unwrap();
            controller.resume_pending().await.unwrap();
            assert_eq!(load_mint_balance(&wallets[i], mint.url()).await.unwrap().balance_sat, 0);
        }
        drop(services);
        assert_eq!(
            load_mint_balance(&root.path().join("collector"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            seed_sat * 5
        );
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("autonomous controller test deadline");
}

fn policy(mint_url: &str, automatic_renewal: bool) -> ControllerPolicy {
    ControllerPolicy {
        mint_url: mint_url.to_string(),
        channel_capacity_sat: if automatic_renewal { 16 } else { 32 },
        max_locked_sat: if automatic_renewal { 32 } else { 64 },
        channel_lifetime_secs: 600,
        renewal: automatic_renewal.then_some(RenewalPolicy {
            at_capacity_percent: 100,
            before_expiry_secs: 30,
        }),
    }
}
