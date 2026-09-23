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

// Observe the small fixture's stored balance without competing with the running
// service for exclusive SDK wallet ownership or invoking recovery on its behalf.
pub(super) async fn load_mint_balance(
    directory: &Path,
    mint_url: &str,
) -> Result<cashu_service::CashuMintBalance, String> {
    let coins = load_mint_proofs(directory, mint_url).await?;
    Ok(cashu_service::CashuMintBalance {
        mint_url: mint_url.to_owned(),
        unit: cashu::nuts::CurrencyUnit::Sat.to_string(),
        balance_sat: coins.iter().map(|coin| coin.proof.amount.to_u64()).sum(),
    })
}

pub(super) async fn load_mint_proofs(
    directory: &Path,
    mint_url: &str,
) -> Result<Vec<cdk_common::wallet::ProofInfo>, String> {
    use cashu::nuts::{CurrencyUnit, State};
    use cdk_common::database::WalletDatabase;
    let db = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(directory))
        .await
        .map_err(|error| error.to_string())?;
    db.get_proofs(
        Some(mint_url.parse().map_err(|error| format!("{error}"))?),
        Some(CurrencyUnit::Sat),
        Some(vec![State::Unspent]),
        None,
    )
    .await
    .map_err(|error| error.to_string())
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
    start_nodes_with_funding_limit(root, mint, network, mint_url, lifetime, quote_lifetime, 40)
        .await
}

pub(super) async fn start_nodes_with_funding_limit(
    root: &Path,
    mint: LocalMint,
    network: PaymentNetwork,
    mint_url: &str,
    lifetime: u64,
    quote_lifetime: u64,
    buyer_funding_limit: u64,
) -> Bench {
    start_line(
        root,
        mint,
        network,
        mint_url,
        lifetime,
        quote_lifetime,
        &[buyer_funding_limit, 40, 40],
    )
    .await
}

pub(super) async fn start_line(
    root: &Path,
    mint: LocalMint,
    network: PaymentNetwork,
    mint_url: &str,
    lifetime: u64,
    quote_lifetime: u64,
    funding_limits: &[u64],
) -> Bench {
    start_configured_line(
        root,
        mint,
        network,
        mint_url,
        LineConfig {
            lifetime,
            quote_lifetime,
            funding_limits,
        },
        |_, _| {},
    )
    .await
}

pub(super) struct LineConfig<'a> {
    pub lifetime: u64,
    pub quote_lifetime: u64,
    pub funding_limits: &'a [u64],
}

/// Apply scenario terms before initialization creates immutable money policy.
pub(super) async fn start_configured_line(
    root: &Path,
    mint: LocalMint,
    network: PaymentNetwork,
    mint_url: &str,
    line: LineConfig<'_>,
    configure: impl Fn(usize, &mut ServiceConfig),
) -> Bench {
    let LineConfig {
        lifetime,
        quote_lifetime,
        funding_limits,
    } = line;
    assert!((3..=4).contains(&funding_limits.len()));
    let mut configs = Vec::new();
    let mut paths = Vec::new();
    let mut npubs = Vec::new();
    let mut sockets = Vec::new();
    for (i, &limit) in funding_limits.iter().enumerate() {
        let directory = root.join(format!("n{i}"));
        std::fs::create_dir(&directory).unwrap();
        let mut cfg = config(&directory, mint_url);
        cfg.terms.controller.max_funding_overhead_sat = limit
            .checked_sub(cfg.terms.controller.channel_capacity_sat)
            .expect("fixture funding allowance covers channel capacity");
        cfg.terms.controller.max_locked_sat = limit;
        cfg.terms.controller.max_wallet_spend_sat = limit;
        cfg.terms.controller.channel_lifetime_secs = lifetime;
        cfg.terms.quote_lifetime_secs = quote_lifetime;
        cfg.terms.billing = fips_relay::ledger::BillingBasis::ForwardingAttempt;
        configure(i, &mut cfg);
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
