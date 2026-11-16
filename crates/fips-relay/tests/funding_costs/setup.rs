use super::*;
use fips_relay::service::ServiceConfig;
use std::path::{Path, PathBuf};
use tokio::process::Child;

pub(super) async fn reject_invalid_financial_state(configs: &[ServiceConfig], paths: &[PathBuf]) {
    for (name, error, replacement) in [
        ("wallet/cashu/seed.json", "seed does not match"),
        (
            "receiver/spilman-receiver-key.json",
            "stored payment receiver identity changed",
        ),
        (
            "wallet/spilman-sender-key.json",
            "stored payment sender identity changed",
        ),
    ]
    .map(|(name, error)| {
        (
            name,
            error,
            std::fs::read(configs[0].state_directory.join(name)).unwrap(),
        )
    })
    .into_iter()
    .chain([b" \n".as_slice(), b"{".as_slice()].map(|content| {
        (
            "wallet/spilman-client.json",
            "failed to decode Spilman client store:",
            content.to_vec(),
        )
    })) {
        reject_damaged_state(&configs[1], &paths[1], name, Some(&replacement), error).await;
    }
    let name = "buyer/buyer.json";
    let mut buyer: serde_json::Value =
        serde_json::from_slice(&std::fs::read(configs[1].state_directory.join(name)).unwrap())
            .unwrap();
    buyer["total_budget_sat"] = (configs[1].terms.buyer_budget_sat + 1).into();
    reject_damaged_state(
        &configs[1],
        &paths[1],
        name,
        Some(&serde_json::to_vec(&buyer).unwrap()),
        "buyer identity or budget differs from saved service terms",
    )
    .await;
}

pub(super) async fn reject_damaged_state(
    config: &ServiceConfig,
    config_path: &Path,
    name: &str,
    replacement: Option<&[u8]>,
    error: &str,
) {
    let root = &config.state_directory;
    let journals = [
        "seller/ledger.json",
        "buyer/buyer.json",
        "controller/controller.json",
    ]
    .map(|name| (name, std::fs::read(root.join(name)).unwrap()));
    let path = root.join(name);
    let retained = path.with_extension("retained-test");
    assert!(!retained.exists());
    let original = std::fs::read(&path).unwrap();
    if let Some(replacement) = replacement {
        assert!(
            original != replacement,
            "fixture must change the original financial state"
        );
        std::fs::write(&path, replacement).unwrap();
    } else {
        std::fs::rename(&path, &retained).unwrap();
    }
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(relay_program())
            .arg("run")
            .arg(config_path)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let recreated = replacement.is_none() && path.exists();
    let unchanged =
        replacement.is_none_or(|bytes| std::fs::read(&path).is_ok_and(|saved| saved == bytes));
    if replacement.is_some() {
        std::fs::write(path, original).unwrap();
    } else {
        std::fs::rename(retained, path).unwrap();
    }
    assert!(!recreated, "startup recreated missing financial state");
    let result = result
        .expect("invalid financial state startup must terminate")
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains(error),
        "startup must reject invalid financial state: {name}"
    );
    assert!(
        unchanged,
        "rejected startup rewrote invalid financial state"
    );
    for (name, original) in &journals {
        assert!(
            std::fs::read(root.join(name)).unwrap() == *original,
            "rejected startup mutated {name}"
        );
    }
}

pub(super) struct Bench {
    pub mint: LocalMint,
    pub configs: Vec<ServiceConfig>,
    pub paths: Vec<PathBuf>,
    pub npubs: Vec<String>,
    pub children: Vec<Child>,
}

#[path = "../process_support/mint.rs"]
mod mint;
pub(super) use mint::pause_channel_close;

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

pub(super) async fn verify_settled_wallets(bench: &Bench, mint: &str, expected_sat: u64) {
    use cashu::nuts::{CheckStateRequest, State};
    use cdk_common::database::WalletDatabase;
    let mut live = std::collections::BTreeSet::new();
    let mut total = 0;
    for config in &bench.configs {
        let db = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(
            &config.state_directory.join("wallet"),
        ))
        .await
        .unwrap();
        assert!(db.get_incomplete_sagas().await.unwrap().is_empty());
        let coins = db
            .get_proofs(
                Some(mint.parse().unwrap()),
                Some("sat".parse().unwrap()),
                None,
                None,
            )
            .await
            .unwrap();
        // A retained-receipt workload can contain thousands of spent originals.
        // Audit every identity without exceeding the mint's request bound.
        for page in coins.chunks(128) {
            let states = bench
                .mint
                .mint()
                .check_state(&CheckStateRequest {
                    ys: page.iter().map(|coin| coin.y).collect(),
                })
                .await
                .unwrap()
                .states;
            assert_eq!(states.len(), page.len());
            for (coin, state) in page.iter().zip(states) {
                assert_eq!(coin.y, state.y);
                if coin.state == State::Unspent {
                    assert_eq!(state.state, State::Unspent);
                    assert!(live.insert(coin.y), "duplicate live original coin");
                    total += coin.proof.amount.to_u64();
                } else {
                    // A retained sent-token record can still mark its already-spent
                    // inputs PendingSpent. It is not an additional outstanding balance.
                    assert!(matches!(coin.state, State::Spent | State::PendingSpent));
                    assert_eq!(state.state, State::Spent);
                }
            }
        }
    }
    assert_eq!(total, expected_sat);
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
    start_configured_topology(
        root, mint, network, mint_url, line, configure, false, None, None,
    )
    .await
}

#[cfg(all(feature = "measurements", target_os = "linux"))]
#[allow(clippy::too_many_arguments)] // Reuse initialization with explicit grants and edges.
pub(super) async fn start_funded_topology(
    root: &Path,
    mint: LocalMint,
    network: PaymentNetwork,
    mint_url: &str,
    line: LineConfig<'_>,
    grants: &[u64],
    edges: &[(usize, usize)],
    configure: impl Fn(usize, &mut ServiceConfig),
) -> Bench {
    assert_eq!(grants.len(), line.funding_limits.len());
    start_configured_topology(
        root,
        mint,
        network,
        mint_url,
        line,
        configure,
        false,
        Some(grants),
        Some(edges),
    )
    .await
}

/// Add an unfunded provider and destination without changing the original grants.
pub(super) async fn start_configured_fork(
    root: &Path,
    mint: LocalMint,
    network: PaymentNetwork,
    mint_url: &str,
    line: LineConfig<'_>,
    configure: impl Fn(usize, &mut ServiceConfig),
) -> Bench {
    assert_eq!(line.funding_limits.len(), 5);
    start_configured_topology(
        root, mint, network, mint_url, line, configure, true, None, None,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // One existing topology initializer owns all setup paths.
async fn start_configured_topology(
    root: &Path,
    mint: LocalMint,
    network: PaymentNetwork,
    mint_url: &str,
    line: LineConfig<'_>,
    configure: impl Fn(usize, &mut ServiceConfig),
    fork: bool,
    grants: Option<&[u64]>,
    edges: Option<&[(usize, usize)]>,
) -> Bench {
    let LineConfig {
        lifetime,
        quote_lifetime,
        funding_limits,
    } = line;
    assert!((3..=if fork || edges.is_some() { 5 } else { 4 }).contains(&funding_limits.len()));
    if let Some(edges) = edges {
        assert!(!fork && !edges.is_empty());
        assert!(
            edges
                .iter()
                .all(|&(a, b)| a < funding_limits.len() && b < funding_limits.len() && a != b)
        );
    }
    let mut configs = Vec::new();
    let mut paths = Vec::new();
    let mut npubs = Vec::new();
    let mut sockets = Vec::new();
    for i in 0..funding_limits.len() {
        // The fork is a line with the original source in its middle. Keep
        // directory/term identities stable while using ordinary line readiness.
        let index = if fork && i < 3 { 2 - i } else { i };
        let limit = funding_limits[index];
        let directory = root.join(format!("n{index}"));
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
        configure(index, &mut cfg);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        cfg.transports = udp_transports(socket.local_addr().unwrap());
        sockets.push(socket);
        npubs.push(RelayService::initialize(cfg.clone()).await.unwrap());
        let wallet = cfg.state_directory.join("wallet");
        let grant = grants.map_or(if !fork || index < 3 { 128 } else { 0 }, |g| g[index]);
        if grant > 0 {
            let quote = create_topup_quote(&wallet, mint_url, grant).await.unwrap();
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
        }
        paths.push(directory.join("config.json"));
        configs.push(cfg);
    }
    let addresses: Vec<_> = configs.iter().map(udp_bind).collect();
    for (i, cfg) in configs.iter_mut().enumerate() {
        cfg.neighbors = npubs
            .iter()
            .enumerate()
            .filter(|(j, _)| {
                edges.map_or(i.abs_diff(*j) == 1, |edges| {
                    edges
                        .iter()
                        .any(|&(a, b)| (a == i && b == *j) || (b == i && a == *j))
                })
            })
            .map(|(j, p)| PeerConfig::new(p, "udp", addresses[j].to_string()))
            .collect();
        std::fs::write(&paths[i], serde_json::to_vec(cfg).unwrap()).unwrap();
    }
    drop(sockets);
    let mut children = Vec::new();
    for path in &paths {
        children.push(start(path).await);
    }
    ready_configured(&configs, &paths, &mut children).await;
    if fork {
        configs.swap(0, 2);
        paths.swap(0, 2);
        npubs.swap(0, 2);
        children.swap(0, 2);
    }
    Bench {
        mint,
        configs,
        paths,
        npubs,
        children,
    }
}

#[path = "../process_support/wallet_capacity.rs"]
mod wallet_capacity;
pub(super) use wallet_capacity::{MIXED_ROLE_CAPACITY, fill_wallet_capacity};
