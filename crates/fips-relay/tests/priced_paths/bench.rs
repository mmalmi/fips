//! Shared real controller and test-money assembly for simulated carrier scenarios.
use super::*;
use cashu_service::{receive_payment_token, send_payment_token, simulation::MintProxy};
use fips_core::{FipsEndpointServiceReceiver, config::NeighborRotationConfig};
use std::path::{Path, PathBuf};

pub(super) async fn collect_wallets(
    root: &Path,
    wallets: &[PathBuf],
    mint: &str,
    expected: &[u64],
) {
    assert_eq!(wallets.len(), expected.len());
    let collector = root.join("collector");
    for (wallet, expected) in wallets.iter().zip(expected) {
        let balance = load_mint_balance(wallet, mint).await.unwrap().balance_sat;
        assert_eq!(balance, *expected);
        if balance != 0 {
            let token = send_payment_token(wallet, mint, balance).await.unwrap();
            receive_payment_token(&collector, &token.token)
                .await
                .unwrap();
        }
        assert_eq!(
            load_mint_balance(wallet, mint).await.unwrap().balance_sat,
            0
        );
    }
    assert_eq!(
        load_mint_balance(&collector, mint)
            .await
            .unwrap()
            .balance_sat,
        expected.iter().sum::<u64>()
    );
}

pub(super) struct Bench {
    pub root: tempfile::TempDir,
    pub mint: LocalMint,
    pub controller_policy: ControllerPolicy,
    pub network_name: String,
    pub network: SimNetwork,
    pub nodes: Vec<Arc<FipsEndpoint>>,
    pub peers: Vec<PeerIdentity>,
    pub buyers: Vec<Arc<BuyerAuthorizer>>,
    pub sellers: Vec<Arc<DurableRelay>>,
    pub gates: Vec<Arc<Gate>>,
    pub wallets: Vec<PathBuf>,
    pub receivers: Vec<FipsEndpointServiceReceiver>,
    pub controllers: Vec<Arc<Controller>>,
    pub services: Vec<ControllerServices>,
    pub tasks: Vec<ControllerTasks>,
    pub quote_servers: Vec<QuoteServer>,
    pub quote_inputs: Vec<(Arc<ControlTransport>, QuotePolicy)>,
    pub payment_servers: Vec<PaymentServer>,
    pub admissions: Vec<Arc<ControlAdmission>>,
    pub interrupted_acceptance: Option<mobility::pending::ResponseGate>,
}

pub(super) async fn start(root_index: usize, scenario: Scenario, seed: u64) -> Bench {
    start_inner(root_index, scenario, seed, false, false, None)
        .await
        .0
}

pub(super) async fn start_with_promotion_gate(root_index: usize, seed: u64) -> Bench {
    start_inner(
        root_index,
        Scenario::RecoveryTiming,
        seed,
        false,
        true,
        None,
    )
    .await
    .0
}

#[cfg(unix)]
pub(super) async fn start_with_mint_proxy(root_index: usize, seed: u64) -> (Bench, MintProxy) {
    let (bench, proxy) =
        start_inner(root_index, Scenario::MergeSplit, seed, true, false, None).await;
    (bench, proxy.unwrap())
}

pub(super) async fn start_with_neighbor_rotation(
    root_index: usize,
    seed: u64,
    rotation: NeighborRotationConfig,
) -> Bench {
    Box::pin(start_inner(
        root_index,
        Scenario::MergeSplit,
        seed,
        false,
        false,
        Some(rotation),
    ))
    .await
    .0
}

async fn start_inner(
    root_index: usize,
    scenario: Scenario,
    seed: u64,
    intercept_mint: bool,
    hold_promotion: bool,
    rotation: Option<NeighborRotationConfig>,
) -> (Bench, Option<MintProxy>) {
    let handshakes = matches!(scenario, Scenario::HandshakeSaturation);
    let saturation = matches!(
        scenario,
        Scenario::ControlSaturation | Scenario::HandshakeSaturation
    );
    let mesh = saturation || matches!(scenario, Scenario::MergeSplit);
    let recovery_timing = matches!(scenario, Scenario::RecoveryTiming);
    let interrupted = matches!(scenario, Scenario::InterruptedMobility { .. });
    let mobile = matches!(
        scenario,
        Scenario::Mobility | Scenario::InterruptedMobility { .. }
    );
    let changing_neighbors = mobile || matches!(scenario, Scenario::QualityChurn);
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
    let mint_proxy = if intercept_mint {
        Some(MintProxy::start(mint.url()).await)
    } else {
        None
    };
    // Wallet proofs, quotes and receiver validation must all name the same mint.
    let mint_url = mint_proxy.as_ref().map_or(mint.url(), |proxy| &proxy.url);
    let mut controller_policy = policy(mint_url);
    if recovery_timing || mesh {
        controller_policy.max_wallet_spend_sat = 128;
        controller_policy.renewal = None;
    }
    let network_name = format!("priced-{}", Identity::generate().node_addr());
    let network = SimNetwork::new(seed);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    let count = if saturation {
        3
    } else if mesh {
        6
    } else {
        4
    };
    let edges = if saturation {
        vec![(0, 1), (1, 2)]
    } else if mesh {
        vec![(0, 1), (1, 2), (3, 4), (4, 5)]
    } else {
        vec![(0, 1), (0, 2), (1, 3), (2, 3)]
    };
    for &(a, b) in &edges {
        network.set_link(
            a.to_string(),
            b.to_string(),
            SimLink {
                latency_ms: 2,
                ..Default::default()
            },
        );
    }
    if mobile || hold_promotion {
        network.set_link_up("0", "2", false);
    }
    fips_core::register_sim_network(network_name.clone(), network.clone());
    let mut nodes = Vec::new();
    let mut peers = Vec::new();
    let mut buyers = Vec::new();
    let mut sellers = Vec::new();
    let mut gates = Vec::new();
    let mut wallets = Vec::new();
    let mut receivers = Vec::new();
    let mut keys: Vec<_> = (1..=count as u8)
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
        config.node.control.enabled = mesh;
        config.node.neighbor_rotation = rotation.as_ref().map(|r| NeighborRotationConfig {
            idle_secs: r.idle_secs,
            interval_secs: r.interval_secs,
        });
        if mesh {
            config.node.control.socket_path = root
                .path()
                .join(format!("native-{i}.sock"))
                .to_str()
                .unwrap()
                .into();
            config.node.limits.max_peers = if handshakes {
                10
            } else if saturation {
                4
            } else {
                2
            };
            config.node.limits.max_connections = if handshakes { 10 } else { 4 };
            config.node.limits.max_links = if handshakes { 10 } else { 4 };
            config.node.limits.max_pending_inbound = if handshakes { 10 } else { 4 };
            config.node.limits.max_sessions = 128;
        }
        if matches!(scenario, Scenario::AdmissionExhaustion) && i == 3 {
            // Source keeps Full mode and its real feedback grace period; the
            // receiver omits reports so delivery cannot qualify a trial.
            config.node.session_mmp.mode = fips_core::mmp::MmpMode::Minimal;
        }
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(network_name.clone()),
            addr: Some(i.to_string()),
            mtu: Some(1280),
            auto_connect: Some(mesh),
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
        // The diamond funds its source; both mesh components have onward capital.
        let amount = if mesh || i == 0 { 256 } else { 1 };
        let topup = create_topup_quote(&wallet, mint_url, amount).await.unwrap();
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
    // Discovery supplies mesh neighbors; the diamond retains its configured links.
    for (i, node) in nodes.iter().enumerate().filter(|_| !mesh) {
        node.update_peers(
            (0..count)
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
    let mut admissions = Vec::new();
    let mut interrupted_acceptance = None;
    for i in 0..count {
        let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
            &root.path().join(format!("receiver-{i}")),
            FileSpilmanPaymentReceiverConfig::new([mint_url.to_string()]),
        )
        .await
        .unwrap();
        let neighbors: Vec<_> = (0..count)
            .filter(|&j| edges.contains(&(i, j)) || edges.contains(&(j, i)))
            .map(|j| peers[j])
            .collect();
        let admission = ControlAdmission::new(
            nodes[i].clone(),
            if changing_neighbors || mesh {
                vec![]
            } else {
                neighbors
            },
            None,
            if changing_neighbors || mesh {
                NeighborAdmission::AuthenticatedAdjacent
            } else {
                NeighborAdmission::ConfiguredOnly
            },
        )
        .unwrap();
        admissions.push(admission.clone());
        let (transport, incoming) = ControlTransport::start_with_admission(
            nodes[i].clone(),
            44_741,
            admission.clone(),
            i as u64 + 1,
        )
        .await
        .unwrap();
        let transport = Arc::new(transport);
        let quote_policy = QuotePolicy {
            destination_fees: Default::default(),
            billing: BillingBasis::ForwardingData,
            mint_url: mint_url.into(),
            receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
            fee_msat_per_kib: if mesh {
                128
            } else if i == 2 {
                scenario.alternative_price()
            } else if recovery_timing {
                128
            } else {
                1024
            },
            max_rate_msat_per_kib: 8192,
            lifetime_secs: 300,
            max_units: if rotation.is_some() {
                // The continuous local pump plus finite paid bursts exceed
                // 128 KiB. At 128 msat/KiB this still fits the 64-sat channel.
                384 * 1024
            } else if recovery_timing || mesh {
                128 * 1024
            } else {
                1_000_000
            },
            capacity_sat: 64,
            grace_msat: 8_000,
        };
        quote_inputs.push((transport.clone(), quote_policy.clone()));
        let quotes = RouteQuotes::new(nodes[i].clone(), transport, quote_policy).unwrap();
        let quotes = Arc::new(if i == 0 && !mesh {
            quotes
                .with_price_selection(selection.clone(), buyers[0].clone())
                .unwrap()
        } else {
            quotes
        });
        quote_servers.push(QuoteServer::start(quotes.clone(), incoming));
        let (acceptance, incoming) = ControlTransport::start_with_admission(
            nodes[i].clone(),
            44_742,
            admission.clone(),
            i as u64 + 10,
        )
        .await
        .unwrap();
        let (payment, requests) = ControlTransport::start_with_admission(
            nodes[i].clone(),
            44_743,
            admission,
            i as u64 + 20,
        )
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
                controller_policy.clone(),
                service.clone(),
            )
            .unwrap(),
        );
        let incoming = if hold_promotion && i == 1 {
            let (incoming, gate) = mobility::pending::interpose_promotion(
                incoming,
                peers[0],
                selection.trial_max_units,
            );
            interrupted_acceptance = Some(gate);
            incoming
        } else if interrupted && i == 2 {
            let (incoming, gate) = mobility::pending::interpose(
                incoming,
                peers[0],
                matches!(
                    scenario,
                    Scenario::InterruptedMobility {
                        lose_settlement: true
                    }
                ),
            );
            interrupted_acceptance = Some(gate);
            incoming
        } else {
            incoming
        };
        tasks.push(ControllerTasks::start(controller.clone(), incoming));
        controllers.push(controller);
        services.push(service);
    }
    let bench = Bench {
        root,
        mint,
        controller_policy,
        network_name,
        network,
        nodes,
        peers,
        buyers,
        sellers,
        gates,
        wallets,
        receivers,
        controllers,
        services,
        tasks,
        quote_servers,
        quote_inputs,
        payment_servers,
        admissions,
        interrupted_acceptance,
    };
    (bench, mint_proxy)
}
