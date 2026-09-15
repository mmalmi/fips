//! Each router independently accepts, funds onward channels and pays usage.
use cashu_service::{
    FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig, create_topup_quote,
    load_mint_balance, load_wallet_overview, receive_payment_token, send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::{
    Config, FipsEndpoint, PeerIdentity,
    config::{PeerConfig, TransportInstances, UdpConfig},
};
use fips_relay::{
    buyer::{BuyerAuthorizer, PaidForwarder},
    control_transport::ControlTransport,
    controller::{
        Controller, ControllerPolicy, ControllerRequest, ControllerResponse, ControllerServices,
        ControllerTasks,
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
    tokio::time::timeout(Duration::from_secs(180), async {
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
                    64,
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
            let quote = create_topup_quote(wallet, mint.url(), 128).await.unwrap();
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
                        capacity_sat: 32,
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
                    policy(mint.url()),
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
                    policy(mint.url()),
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
                128 - 32 * expected.len() as u64,
                "controller reload must not fund another channel");
        }
        for round in 0..8 {
            for (source, destination) in [(0, 4), (4, 0)] {
                let mut payload = vec![round; 1_000];
                payload[0] = source as u8;
                nodes[source]
                    .send_datagram(peers[destination], 44_740, 44_740, payload.clone())
                    .await
                    .unwrap();
                let mut received = Vec::new();
                tokio::time::timeout(
                    Duration::from_secs(10),
                    data[destination].recv_batch_into(&mut received, 8),
                )
                .await
                .unwrap_or_else(|_| panic!("autonomously paid delivery round={round} direction={source}->{destination}; errors={:?}; usage={:?}", errors(&controllers), links.iter().map(|(b,s,p)|(*b,*s,ledgers[*s].channel_usage(&p.channel.id))).collect::<Vec<_>>()))
                .unwrap();
                assert!(received.iter().any(|m| m.data.as_slice() == payload));
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
        assert_eq!(settlement_count, 6);
        let mut expected = [128i64; 5];
        for (buyer, seller, purchase) in &links {
            let paid = ledgers[*seller]
                .channel_usage(&purchase.channel.id)
                .unwrap()
                .paid_msat
                / 1_000;
            expected[*buyer] -= paid as i64;
            expected[*seller] += paid as i64;
        }
        assert!(expected[1..4].iter().all(|n| *n > 128));
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
            let controller = Controller::load(&directory, policy(mint.url()), service.clone()).unwrap();
            controller.resume_pending().await.unwrap();
            assert_eq!(load_mint_balance(&wallets[i], mint.url()).await.unwrap().balance_sat, 0);
        }
        drop(services);
        assert_eq!(
            load_mint_balance(&root.path().join("collector"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            640
        );
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("autonomous controller test deadline");
}

fn policy(mint_url: &str) -> ControllerPolicy {
    ControllerPolicy {
        mint_url: mint_url.to_string(),
        channel_capacity_sat: 32,
        max_locked_sat: 64,
        channel_lifetime_secs: 600,
    }
}
