//! A new authenticated buyer must not inherit a disconnected buyer's money.
use super::*;
use cashu_service::{create_topup_quote, load_wallet_overview};
use cdk_common::database::WalletDatabase;
use fips_core::config::NeighborRotationConfig;
use fips_relay::service::ServiceConfig;
use std::path::{Path, PathBuf};

fn journal(config: &ServiceConfig, name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(config.state_directory.join(name)).unwrap()).unwrap()
}

async fn buy(bench: &MixedBench, source: usize, destination: usize) -> Value {
    request(
        &bench.configs[source],
        &AdminRequest::Buy {
            destination: bench.npubs[destination].clone(),
        },
    )
    .await
    .unwrap()["purchase"]
        .clone()
}

fn channel(purchase: &Value) -> &str {
    purchase["channel"]["id"].as_str().unwrap()
}

#[path = "../../process_support/wallet_capacity.rs"]
mod wallet_capacity;

async fn buy_after_capacity_recovers(bench: &MixedBench, incumbent: &Value) -> Value {
    let db = wallet_capacity::fill_wallet_capacity(&bench.configs[1]).await;
    let full = db.storage_capacity().await.unwrap().unwrap();
    let error = request(
        &bench.configs[2],
        &AdminRequest::Buy {
            destination: bench.npubs[0].clone(),
        },
    )
    .await
    .unwrap_err();
    assert!(error.contains("provider rejected purchase"), "{error}");
    let pending = journal(&bench.configs[2], "controller/controller.json");
    assert_eq!(pending["funding"].as_object().unwrap().len(), 1);
    let funded = &pending["funding"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()["funded"];
    assert!(
        funded.is_object(),
        "refusal must follow the original funding"
    );
    let status = request(&bench.configs[2], &AdminRequest::Status)
        .await
        .unwrap();
    assert_eq!(status["funding_budget"]["wallet_debited_sat"], 32);
    assert_eq!(status["funding_budget"]["locked_sat"], 32);
    assert!(status["purchases"].as_array().unwrap().is_empty());
    bench.expect_denied(2, 0).await;

    let previous = bench.relay_usage_msat(channel(incumbent)).1;
    bench.deliver_sized(0, 2, 512).await;
    bench.wait_paid_beyond(channel(incumbent), previous).await;
    assert_eq!(
        journal(&bench.configs[1], "seller/ledger.json")["ledger"]["channels"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "a full wallet cannot admit another payout obligation"
    );
    assert_eq!(db.storage_capacity().await.unwrap().unwrap(), full);
    assert_eq!(
        journal(&bench.configs[2], "controller/controller.json")["funding"],
        pending["funding"]
    );

    db.kv_remove("capacity-test", "", "ballast").await.unwrap();
    let purchase = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = request(&bench.configs[2], &AdminRequest::Status)
                .await
                .unwrap();
            if let Some(purchase) = status["purchases"].as_array().unwrap().first() {
                assert_eq!(status["funding_budget"]["wallet_debited_sat"], 32);
                assert_eq!(status["funding_budget"]["locked_sat"], 32);
                break purchase.clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("original purchase must recover without another buy request");
    assert_eq!(purchase["channel"], funded["terms"]);
    let recovered = journal(&bench.configs[2], "controller/controller.json");
    assert_eq!(recovered["funding"], pending["funding"]);
    assert_eq!(recovered["next_funding"], pending["next_funding"]);
    let capacity = db.storage_capacity().await.unwrap().unwrap();
    assert_eq!(capacity.maximum_bytes, full.maximum_bytes);
    assert!(capacity.charged_bytes < capacity.maximum_bytes);
    eprintln!(
        "new paying identity: full wallet refused admission while incumbent paid; original funding recovered after freeing only test ballast"
    );
    purchase
}

struct Retired {
    config: ServiceConfig,
    path: PathBuf,
    npub: String,
    buyer: Value,
    controller: Value,
}

impl Retired {
    async fn replace(bench: &mut MixedBench, root: &Path, network: &PaymentNetwork) -> Self {
        process_support::stop(&mut bench.children[2]).await;
        let config = bench.configs[2].clone();
        let retired = Self {
            buyer: journal(&config, "buyer/buyer.json"),
            controller: journal(&config, "controller/controller.json"),
            config,
            path: bench.paths[2].clone(),
            npub: bench.npubs[2].clone(),
        };
        let directory = root.join("newcomer");
        std::fs::create_dir(&directory).unwrap();
        let mut config = retired.config.clone();
        config.state_directory = directory.join("state");
        assert!(config.neighbors.is_empty());
        let path = directory.join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let initialized = process_support::command(&path, "init").await;
        assert!(initialized.status.success());
        let npub = String::from_utf8(initialized.stdout)
            .unwrap()
            .trim()
            .to_owned();
        assert!(!bench.npubs.contains(&npub));
        let wallet = config.state_directory.join("wallet");
        let quote = create_topup_quote(&wallet, &config.terms.controller.mint_url, 128)
            .await
            .unwrap();
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
        bench.children[2] = process_support::start(&path).await;
        bench.configs[2] = config;
        bench.paths[2] = path;
        bench.npubs[2] = npub;
        process_support::ready(
            &bench.configs,
            &bench.paths,
            &bench.npubs,
            &mut bench.children,
        )
        .await;
        retired
    }

    fn unchanged(&self) {
        assert!(journal(&self.config, "buyer/buyer.json") == self.buyer);
        assert!(journal(&self.config, "controller/controller.json") == self.controller);
    }
}

async fn exercise(bench: &mut MixedBench, root: &Path, network: &PaymentNetwork) -> Retired {
    bench.set_stage("old-paying-neighbor");
    let original = [buy(bench, 0, 2).await, buy(bench, 2, 0).await];
    for (source, destination, purchase) in [(0, 2, &original[0]), (2, 0, &original[1])] {
        bench.deliver(source, destination).await;
        bench.wait_paid(channel(purchase)).await;
    }
    let before = bench.states().await;
    assert_eq!(before[2]["funding_budget"]["locked_sat"], 32);
    let useful_link = before[1]["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|peer| peer["npub"] == bench.npubs[0])
        .unwrap()["link_id"]
        .clone();
    let retained_pids = [bench.children[0].id(), bench.children[1].id()];

    bench.set_stage("new-identity-unfunded");
    let retired = Retired::replace(bench, root, network).await;
    let joined = bench.states().await;
    assert!(joined[2]["history"].as_array().unwrap().is_empty());
    assert_eq!(joined[2]["funding_budget"]["wallet_debited_sat"], 0);
    assert_eq!(joined[2]["remaining_budget_sat"], 64);
    assert_eq!(joined[0]["funding_budget"], before[0]["funding_budget"]);
    // The new FIPS identity has its own wallet, but authentication alone grants
    // neither the retired buyer's allowance nor authority to buy a route.
    bench.expect_denied(2, 0).await;
    retired.unchanged();
    let old_channel = channel(&original[1]);
    assert!(
        journal(&retired.config, "controller/controller.json")["buyer_settlements"]
            .get(old_channel)
            .is_none()
    );
    assert!(
        journal(&bench.configs[1], "controller/controller.json")["seller_settlements"]
            .get(old_channel)
            .is_none()
    );

    bench.set_stage("new-identity-paid");
    let incumbent = buy(bench, 0, 2).await;
    bench.set_stage("new-identity-wallet-capacity");
    let newcomer = buy_after_capacity_recovers(bench, &incumbent).await;
    let newcomers = [incumbent, newcomer];
    assert_eq!(channel(&newcomers[0]), channel(&original[0]));
    assert_ne!(channel(&newcomers[1]), old_channel);
    for (source, destination, purchase) in [(0, 2, &newcomers[0]), (2, 0, &newcomers[1])] {
        let previous = bench.relay_usage_msat(channel(purchase)).1;
        bench.deliver_sized(source, destination, 512).await;
        bench.wait_paid_beyond(channel(purchase), previous).await;
    }
    let after = bench.states().await;
    assert_eq!(after[1]["peers"].as_array().unwrap().len(), 2);
    let useful = after[1]["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|peer| peer["npub"] == bench.npubs[0])
        .unwrap();
    assert_eq!(useful["link_id"], useful_link);
    assert_eq!(
        [bench.children[0].id(), bench.children[1].id()],
        retained_pids
    );
    for state in &after {
        let budget: FundingBudget =
            serde_json::from_value(state["funding_budget"].clone()).unwrap();
        assert!(budget.locked_sat <= 64 && budget.wallet_debited_sat <= 128);
        assert_eq!(budget.pending_reserved_sat, 0);
        assert!(state["remaining_budget_sat"].as_u64().unwrap() <= 64);
    }
    assert!(
        after[0]["history"]
            .as_array()
            .unwrap()
            .contains(&original[0])
    );
    assert_eq!(after[0]["funding_budget"], before[0]["funding_budget"]);
    assert_eq!(after[2]["funding_budget"]["locked_sat"], 32);
    assert_eq!(after[2]["funding_budget"]["wallet_debited_sat"], 32);
    assert!(
        after[0]["remaining_budget_sat"].as_u64().unwrap()
            <= before[0]["remaining_budget_sat"].as_u64().unwrap()
    );
    retired.unchanged();
    assert!(
        journal(&bench.configs[1], "controller/controller.json")["seller_settlements"]
            .get(old_channel)
            .is_none()
    );
    let seller = journal(&bench.configs[1], "seller/ledger.json");
    assert_eq!(seller["ledger"]["channels"].as_array().unwrap().len(), 3);
    assert!(
        seller["ledger"]["channels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["terms"]["id"] == old_channel
                && row["usage"]["paid_msat"].as_u64().unwrap() > 0)
    );
    eprintln!(
        "new paying identity: fresh channel and bidirectional delivery; retired buyer unchanged; useful link retained; capital and spending bounded"
    );
    retired
}

async fn settle(bench: &mut MixedBench, retired: Retired, mint: &str) {
    let newcomer = bench.configs[2].clone();
    request(&newcomer, &AdminRequest::Settle).await.unwrap();
    let newcomer_status = request(&newcomer, &AdminRequest::Status).await.unwrap();
    process_support::stop(&mut bench.children[2]).await;
    retired.unchanged();
    bench.configs[2] = retired.config;
    bench.paths[2] = retired.path;
    bench.npubs[2] = retired.npub;
    bench.children[2] = process_support::start(&bench.paths[2]).await;
    process_support::ready(
        &bench.configs,
        &bench.paths,
        &bench.npubs,
        &mut bench.children,
    )
    .await;
    for config in &bench.configs {
        request(config, &AdminRequest::Settle).await.unwrap();
    }
    let settled = bench.states().await;
    for state in settled.iter().chain([&newcomer_status]) {
        assert_eq!(state["funding_budget"]["locked_sat"], 0);
        assert_eq!(state["funding_budget"]["pending_reserved_sat"], 0);
    }
    for child in &mut bench.children {
        process_support::stop(child).await;
    }
    let mut total = 0;
    for (index, (config, status)) in bench
        .configs
        .iter()
        .chain([&newcomer])
        .zip(settled.iter().chain([&newcomer_status]))
        .enumerate()
    {
        let balance = load_mint_balance(&config.state_directory.join("wallet"), mint)
            .await
            .unwrap()
            .balance_sat;
        if index == 1 {
            assert!(balance > 128, "the provider earned real test funds");
        } else {
            assert_eq!(
                balance + status["funding_budget"]["exposure_sat"].as_u64().unwrap(),
                128
            );
        }
        total += balance;
    }
    assert_eq!(total, 512);
    eprintln!(
        "new paying identity: original and newcomer accounts settled; all 512 test sats conserved"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_paying_identity_joins_while_disconnected_buyer_retains_unsettled_funds() {
    let mut root = retained_tempdir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(193, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(
        root.path(),
        network.clone(),
        "paying-newcomer",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    let bench =
        MixedBench::start_configured(mint.url(), &network, SecondHop::WebSocketSeed, |_, cfg| {
            cfg.max_peers = Some(2);
            cfg.neighbor_rotation = Some(NeighborRotationConfig {
                idle_secs: 2,
                interval_secs: 2,
            });
            cfg.terms.controller.channel_capacity_sat = 32;
            cfg.terms.controller.max_locked_sat = 64;
            cfg.terms.controller.max_wallet_spend_sat = 128;
            cfg.terms.controller.renewal = None;
            cfg.terms.wallet_capacity_bytes = Some(16 * 1024 * 1024);
        })
        .await;
    let bench = Arc::new(tokio::sync::Mutex::new(bench));
    let running = bench.clone();
    let directory = root.path().to_owned();
    let mint_url = mint.url().to_owned();
    let accounting = network.clone();
    let result = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(180), async {
            let mut bench = running.lock().await;
            let retired = exercise(&mut bench, &directory, &network).await;
            settle(&mut bench, retired, &mint_url).await;
            assert!(accounting.accounting().unwrap().is_conserved());
        })
        .await
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        bench.lock().await.failure_snapshot().await;
        Arc::try_unwrap(bench).ok().unwrap().into_inner().preserve();
        eprintln!("retained failed mint/newcomer at {}", root.keep().display());
    } else {
        root.disable_cleanup(false);
    }
    assert!(
        matches!(result, Ok(Ok(()))),
        "new paying identity acceptance failed"
    );
}
