use super::*;
use fips_relay::service::ServiceConfig;
use std::path::{Path, PathBuf};
use tokio::process::Child;

pub(super) struct Bench {
    pub mint: LocalMint,
    pub configs: Vec<ServiceConfig>,
    pub paths: Vec<PathBuf>,
    pub npubs: Vec<String>,
    pub children: Vec<Child>,
}

pub(super) async fn start_bench(root: &Path, seed: u64, lifetime: u64) -> Bench {
    let (mint, network) = start_mint(root, seed).await;
    let url = mint.url().to_owned();
    start_nodes(root, mint, network, &url, lifetime, lifetime / 2).await
}

pub(super) async fn start_mint(root: &Path, seed: u64) -> (LocalMint, PaymentNetwork) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(seed, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(
        root,
        network.clone(),
        "funding-costs",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    mint.mint()
        .rotate_keyset(
            "sat".parse().unwrap(),
            (0..=10).map(|b| 1u64 << b).collect(),
            500,
            false,
            None,
        )
        .await
        .unwrap();
    (mint, network)
}

pub(super) async fn start_nodes(
    root: &Path,
    mint: LocalMint,
    network: PaymentNetwork,
    mint_url: &str,
    lifetime: u64,
    quote_lifetime: u64,
) -> Bench {
    let mut configs = Vec::new();
    let mut paths = Vec::new();
    let mut npubs = Vec::new();
    let mut sockets = Vec::new();
    for i in 0..3 {
        let directory = root.join(format!("n{i}"));
        std::fs::create_dir(&directory).unwrap();
        let mut cfg = config(&directory, mint_url);
        cfg.terms.controller.max_funding_overhead_sat = 8;
        cfg.terms.controller.max_locked_sat = 40;
        cfg.terms.controller.max_wallet_spend_sat = 40;
        cfg.terms.controller.channel_lifetime_secs = lifetime;
        cfg.terms.quote_lifetime_secs = quote_lifetime;
        cfg.terms.billing = fips_relay::ledger::BillingBasis::ForwardingAttempt;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        cfg.transports = udp_transports(socket.local_addr().unwrap());
        sockets.push(socket);
        npubs.push(RelayService::initialize(cfg.clone()).await.unwrap());
        let wallet = cfg.state_directory.join("wallet");
        let quote = create_topup_quote(&wallet, mint_url, 128).await.unwrap();
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
        paths.push(directory.join("config.json"));
        configs.push(cfg);
    }
    let addresses: Vec<_> = configs.iter().map(udp_bind).collect();
    for (i, cfg) in configs.iter_mut().enumerate() {
        cfg.neighbors = npubs
            .iter()
            .enumerate()
            .filter(|(j, _)| i.abs_diff(*j) == 1)
            .map(|(j, p)| PeerConfig::new(p, "udp", addresses[j].to_string()))
            .collect();
        std::fs::write(&paths[i], serde_json::to_vec(cfg).unwrap()).unwrap();
    }
    drop(sockets);
    let mut children = Vec::new();
    for path in &paths {
        children.push(start(path).await);
    }
    ready(&configs, &paths, &npubs, &mut children).await;
    Bench {
        mint,
        configs,
        paths,
        npubs,
        children,
    }
}
