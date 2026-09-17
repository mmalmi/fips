//! Each router independently accepts, funds onward channels and pays usage.
#[path = "controller_support/admission.rs"]
mod admission;
mod controller_support;
#[path = "controller_support/funding_recovery.rs"]
mod funding_recovery;
#[path = "controller_support/payment_mobility.rs"]
mod payment_mobility;
#[path = "controller_support/purchase_closure.rs"]
mod purchase_closure;
#[path = "controller_support/quote_traffic.rs"]
mod quote_traffic;
use controller_support::{errors, native_control, policy, recovery_stages};

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
async fn authenticated_adjacent_routers_fund_accept_and_pay_without_a_control_roster() {
    controller_scenario(false, false, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exhausted_channels_renew_automatically_without_resetting_capital_or_spending() {
    controller_scenario(true, false, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_buyer_pays_supported_usage_despite_a_provider_evidence_gap() {
    controller_scenario(false, true, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(unix)]
async fn changed_native_paths_reprice_routes_and_reuse_unchanged_neighbor_channels() {
    controller_scenario(false, false, true, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(unix)]
async fn source_authorized_routes_refresh_automatically_within_price_and_spending_caps() {
    controller_scenario(false, false, true, true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_neighbor_payment_and_settlement_do_not_stall_healthy_channels() {
    controller_scenario(false, false, false, false, true).await;
}

// Each scenario owns five live nodes and several signing workers. Keep the
// independent scenarios apart so machine contention cannot masquerade as
// packet-delivery or payment-timing failures; nodes within each remain concurrent.
static NETWORK_SCENARIO: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn controller_scenario(
    automatic_renewal: bool,
    evidence_gap: bool,
    route_change: bool,
    automatic_routes: bool,
    slow_neighbor: bool,
) {
    let _network = NETWORK_SCENARIO.lock().await;
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
        let paid_quote_traffic = !automatic_renewal && !evidence_gap && !route_change && !slow_neighbor;
        // Keep route-change and slow-neighbor scenarios below exhaustion, which the
        // separate renewal scenario deliberately exercises with small channels.
        // The baseline also needs room for its paid quote request/reply and data.
        let capacity = if automatic_renewal { 16 } else if route_change || slow_neighbor || paid_quote_traffic { 64 } else { 32 };
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
            if route_change && (1..=3).contains(&i) {
                config.node.control.enabled = true;
                config.node.control.socket_path = root.path().join(format!("native-{i}.sock")).to_str().unwrap().into();
            }
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
        let mut payment_gates = Vec::new();
        let mut settlement_gates = Vec::new();
        for i in 0usize..5 {
            let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                &root.path().join(format!("receiver-{i}")),
                FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
            )
            .await
            .unwrap();
            let admission = admission::for_router(nodes[i].clone(), &peers, i, route_change, paid_quote_traffic);
            let (quote_transport, quote_incoming) =
                ControlTransport::start_with_admission(nodes[i].clone(), 44_741, admission.clone(), i as u64 + 1)
                    .await
                    .unwrap();
            let quotes = Arc::new(
                RouteQuotes::new(
                    nodes[i].clone(),
                    Arc::new(quote_transport),
                    QuotePolicy {
                        destination_fees: Default::default(),
                        billing: Default::default(),
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
                ControlTransport::start_with_admission(nodes[i].clone(), 44_742, admission.clone(), i as u64 + 10)
                    .await
                    .unwrap();
            let (payments, payment_incoming) =
                ControlTransport::start_with_admission(nodes[i].clone(), 44_743, admission, i as u64 + 20)
                    .await
                    .unwrap();
            let gate_buyer = if paid_quote_traffic { peers[0] } else { peers[2] };
            let (incoming, gate) = payment_mobility::gate(incoming, gate_buyer, slow_neighbor || paid_quote_traffic);
            settlement_gates.push(gate);
            let (payment_incoming, gate) = payment_mobility::gate(payment_incoming, peers[2], slow_neighbor);
            payment_gates.push(gate);
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
                    policy(mint.url(), automatic_renewal, capacity),
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
        if paid_quote_traffic {
            admission::quotes_preserve_financial_authority(&controllers, &services, &peers, mint.url()).await;
        }
        if automatic_routes {
            assert!(controllers[0].watch_route(peers[4], 1024).await.is_err());
            assert_eq!(controllers[0].locked_capital_sat().await.unwrap(), 0);
            assert_eq!(buyers[0].remaining_budget_sat(), Some(64));
            controllers[0].pause_route_refresh().await.unwrap();
        }
        let (a, b) = tokio::join!(
            async { if automatic_routes { controllers[0].watch_route(peers[4], 3072).await }
                else { controllers[0].buy_route(peers[4]).await } },
            async { if automatic_routes { controllers[4].watch_route(peers[0], 3072).await }
                else { controllers[4].buy_route(peers[0]).await } }
        );
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
        if paid_quote_traffic {
            funding_recovery::exercise(root.path(), policy(mint.url(), false, capacity), services[4].clone()).await;
        }
        let mut controllers = Vec::new();
        for (i, receiver) in incoming.into_iter().enumerate() {
            let controller = Arc::new(
                Controller::load(
                    &root.path().join(format!("controller-{i}")),
                    policy(mint.url(), automatic_renewal, capacity),
                    services[i].clone(),
                )
                .unwrap(),
            );
            if i == 0 || i == 4 {
                assert!(controller.purchases().await.unwrap().is_empty());
            }
            let watches = controller.watched_routes().await.unwrap();
            if automatic_routes && (i == 0 || i == 4) {
                assert_eq!(watches.len(), 1);
                assert_eq!(watches[0].destination, peers[4 - i].npub());
                assert_eq!(watches[0].max_rate_msat_per_kib, 3072);
                assert!(!watches[0].paused, "source authorization survives reload");
            } else {
                assert!(watches.is_empty(), "transit cannot create source watches");
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
        // Wallet-only funding recovery is checked before any paid payload.
        if paid_quote_traffic {
            quote_traffic::exercise(&nodes, &peers, &services, &ledgers, &links).await;
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
                        assert!(automatic_renewal,
                            "ordinary delivery needed a retry: round={round} direction={source}->{destination}; errors={:?}; usage={:?}",
                            errors(&controllers), links.iter().map(|(b,s,p)|(*b,*s,ledgers[*s].channel_usage(&p.channel.id))).collect::<Vec<_>>());
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
        // Delivery and the periodic payment worker are independent. Observe
        // the verified balance transition instead of assuming the final 600ms
        // sleep has also completed every neighbor's signature and response.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if links.iter().all(|(_, seller, purchase)| {
                    ledgers[*seller].channel_usage(&purchase.channel.id).unwrap().paid_msat > 8_000
                }) { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.unwrap_or_else(|_| panic!("automatic payments did not replenish the initial allowance; errors={:?}; paid/evidence={:?}",
            errors(&controllers), links.iter().map(|(buyer,seller,p)| (
                *buyer,*seller,ledgers[*seller].channel_usage(&p.channel.id),
                buyers[*buyer].evidence_msat(&p.channel.id))).collect::<Vec<_>>()));
        if slow_neighbor {
            payment_mobility::exercise(root.path(), &nodes, &peers, &mut data, &controllers, &ledgers,
                &buyers, &payment_gates, &settlement_gates).await;
        }
        if route_change {
            // Replace the middle path with 0--1--3--4. Removing config hints
            // alone preserves live links, so use the real local control API to
            // disconnect the old links after suppressing their retry hints.
            for (i, node) in nodes.iter().enumerate() {
                let edges = [(0usize, 1usize), (1, 3), (3, 4)];
                node.update_peers(
                    peers
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| {
                            edges
                                .iter()
                                .any(|(a, b)| (i == *a && *j == *b) || (i == *b && *j == *a))
                        })
                        .map(|(j, _)| {
                            let mut peer =
                                PeerConfig::new(nodes[j].npub(), "udp", addresses[j].to_string());
                            if (i == 1 && j == 3) || (i == 3 && j == 1) {
                                peer.connect_policy = fips_core::config::ConnectPolicy::Manual;
                            }
                            peer
                        })
                        .collect(),
                )
                .await
                .unwrap();
            }
            #[cfg(unix)]
            for peer in [peers[1], peers[3]] {
                native_control(
                    root.path(),
                    2,
                    serde_json::json!({
                        "command": "disconnect", "params": {"npub": peer.npub()}
                    }),
                )
                .await;
            }
            // Explicitly establish the new carrier. Auto-connect may first warm
            // an end-to-end session over the old graph instead of a direct link.
            #[cfg(unix)]
            native_control(
                root.path(),
                1,
                serde_json::json!({
                    "command": "connect", "params": {
                        "npub": peers[3].npub(), "address": addresses[3].to_string(), "transport": "udp"
                    }
                }),
            )
            .await;
            let mut last_topology = Vec::new();
            let mut last_hops = [None, None];
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    last_topology.clear();
                    let mut count = 0;
                    for node in &nodes {
                        let connected: Vec<_> = node.peers().await.unwrap().into_iter().filter(|p| p.connected)
                            .map(|n| peers.iter().position(|p| p.node_addr() == &n.node_addr).unwrap()).collect();
                        count += connected.len();
                        last_topology.push(connected);
                    }
                    for (index, source, destination, previous) in [(0, 1, 4, 0), (1, 3, 0, 4)] {
                        last_hops[index] = nodes[source].resolve_next_hop(peers[destination], Some(*peers[previous].node_addr()))
                            .await.unwrap().and_then(|n| peers.iter().position(|p| p.pubkey() == n.pubkey()));
                    }
                    if count == 6 && last_hops == [Some(3), Some(1)]
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("changed native topology: {last_topology:?}; next hops: {last_hops:?}"));
            let (forward, reverse) = if automatic_routes {
                tokio::time::timeout(Duration::from_secs(60), async {
                    loop {
                        let forward = controllers[0].purchases().await.unwrap().into_iter().find(|p| p.contract.price.msat == 2048);
                        let reverse = controllers[4].purchases().await.unwrap().into_iter().find(|p| p.contract.price.msat == 2048);
                        if let (Some(forward), Some(reverse)) = (forward, reverse) { break (Ok(forward), Ok(reverse)); }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }).await.unwrap_or_else(|_| panic!("automatic route refresh deadline; errors={:?}", errors(&controllers)))
            } else { tokio::join!(
                controllers[0].buy_route(peers[4]), controllers[4].buy_route(peers[0])
            ) };
            let forward = forward.unwrap_or_else(|e| {
                panic!(
                    "changed forward route: {e}; errors={:?}",
                    errors(&controllers)
                )
            });
            let reverse = reverse.unwrap_or_else(|e| {
                panic!(
                    "changed reverse route: {e}; errors={:?}",
                    errors(&controllers)
                )
            });
            assert_eq!(
                forward.channel.id, a.channel.id,
                "same source neighbour keeps its channel"
            );
            assert_eq!(
                reverse.channel.id, b.channel.id,
                "same reverse neighbour keeps its channel"
            );
            assert_eq!(forward.contract.price.msat, 2048);
            assert_eq!(reverse.contract.price.msat, 2048);
            assert_ne!(forward.contract.id, a.contract.id);
            assert_ne!(reverse.contract.id, b.contract.id);
            assert_eq!(forward.contract.next_hop, *peers[3].node_addr());
            assert_eq!(reverse.contract.next_hop, *peers[1].node_addr());
            let unauthorized = serde_json::to_vec(&ControllerRequest::StopRoute {
                contract_id: forward.contract.id.clone(),
            })
            .unwrap();
            assert!(matches!(
                controllers[1].handle(peers[3], &unauthorized).await,
                ControllerResponse::Rejected
            ));
            let before = [forward.clone(), reverse.clone()];
            let mut streams = Vec::new();
            for task in tasks.drain(..) {
                streams.push(task.stop().await.unwrap());
            }
            controllers.clear();
            // Recover a lost replacement reply and a lost outgoing record.
            // The old quote history and earlier funding intent are untouched.
            for (source, purchase) in [(0, &forward), (4, &reverse)] {
                let path = root
                    .path()
                    .join(format!("controller-{source}/controller.json"));
                let mut journal: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                if automatic_routes {
                    // Crash after acceptance but before clearing the watched
                    // offer: recovery must retain its exact funding identity.
                    journal["watched_routes"][peers[4 - source].npub()]["pending"] =
                        journal["outgoing"][&purchase.contract.id]["offer"].clone();
                }
                if source == 0 {
                    journal["outgoing"][&purchase.contract.id]["accepted"] = false.into();
                } else {
                    journal["outgoing"]
                        .as_object_mut()
                        .unwrap()
                        .remove(&purchase.contract.id);
                }
                std::fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
            }
            for (i, stream) in streams.into_iter().enumerate() {
                let controller = Arc::new(
                    Controller::load(
                        &root.path().join(format!("controller-{i}")),
                        policy(mint.url(), false, capacity),
                        services[i].clone(),
                    )
                    .unwrap(),
                );
                tasks.push(ControllerTasks::start(controller.clone(), stream));
                controllers.push(controller);
            }
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if controllers[0].purchases().await.unwrap() == vec![before[0].clone()]
                        && controllers[4].purchases().await.unwrap() == vec![before[1].clone()]
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("replacement recovery retains the same channels and contracts");
            for (source, destination) in [(0, 4), (4, 0)] {
                let payload = vec![source as u8 + 99; 500];
                // FIPS delivery is best effort across a topology transition.
                // Bound application retries; every new envelope still counts
                // against the same channel and lifetime spending allowance.
                let mut delivered = false;
                for _ in 0..3 {
                    nodes[source].send_datagram(peers[destination], 44_740, 44_740, payload.clone()).await.unwrap();
                    if tokio::time::timeout(Duration::from_secs(3), async {
                        let mut received = Vec::new();
                        loop {
                            data[destination].recv_batch_into(&mut received, 8).await.unwrap();
                            if received.iter().any(|m| m.data.as_slice() == payload) { break; }
                        }
                    }).await.is_ok() { delivered = true; break; }
                }
                if !delivered {
                    let mut usage = Vec::new();
                    for (buyer, controller) in controllers.iter().enumerate() {
                        for purchase in controller.purchase_history().await.unwrap() {
                            let seller = peers.iter().position(|p| p.node_addr() == &purchase.provider).unwrap();
                            usage.push((buyer, seller, purchase.contract.price.msat,
                                ledgers[seller].channel_usage(&purchase.channel.id), buyers[buyer].evidence_msat(&purchase.channel.id)));
                        }
                    }
                    panic!("changed-path delivery {source}->{destination}; usage={usage:?}; errors={:?}", errors(&controllers));
                }
            }
            // Reconnect the old neighbours for final bilateral settlement,
            // retaining the new link too. No further application traffic runs.
            for (i, node) in nodes.iter().enumerate() {
                node.update_peers(
                    peers
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| {
                            i.abs_diff(*j) == 1 || (i == 1 && *j == 3) || (i == 3 && *j == 1)
                        })
                        .map(|(j, _)| PeerConfig::new(nodes[j].npub(), "udp", addresses[j].to_string()))
                        .collect(),
                )
                .await
                .unwrap();
            }
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let mut count = 0;
                    for node in &nodes {
                        count += node
                            .peers()
                            .await
                            .unwrap()
                            .iter()
                            .filter(|p| p.connected)
                            .count();
                    }
                    if count == 10 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
            links.clear();
            for (i, controller) in controllers.iter().enumerate() {
                let mut seen = std::collections::HashSet::new();
                for p in controller.purchase_history().await.unwrap() {
                    if seen.insert(p.channel.id.clone()) {
                        let seller = peers
                            .iter()
                            .position(|peer| peer.node_addr() == &p.provider)
                            .unwrap();
                        links.push((i, seller, p));
                    }
                }
            }
            assert_eq!(
                links.len(),
                8,
                "only the two new neighbour pairs need additional funding"
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
        if paid_quote_traffic {
            let incoming = tasks.remove(0).stop().await.unwrap();
            purchase_closure::exercise(&controllers, &services, &peers, &settlement_gates, root.path()).await;
            tasks.insert(0, ControllerTasks::start(controllers[0].clone(), incoming));
        }
        if !automatic_renewal && !route_change {
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
                let controller = Arc::new(Controller::load(&root.path().join(format!("controller-{i}")), policy(mint.url(), true, capacity), services[i].clone()).unwrap());
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
            assert!(controller.watched_routes().await.unwrap().iter().all(|w| w.paused));
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
            assert_eq!(neighbors.len(), if i == 0 || i == 4 { 1 } else if route_change && i!=2 {3} else { 2 });
            for neighbor in neighbors {
                let j = peers.iter().position(|p| p.node_addr() == &neighbor.node_addr).unwrap();
                assert!(i.abs_diff(j)==1 || (route_change && ((i==1 && j==3)||(i==3 && j==1))), "native topology cannot acquire an unconfigured shortcut");
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
                // Losing the report also loses its later release acknowledgment.
                settlement["released"] = serde_json::Value::Bool(false);
            }
            std::fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
            let controller = Controller::load(&directory, policy(mint.url(), automatic_renewal, capacity), service.clone()).unwrap();
            assert!(controller.watched_routes().await.unwrap().iter().all(|w| w.paused),
                "settlement's watch pause must survive reload");
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
