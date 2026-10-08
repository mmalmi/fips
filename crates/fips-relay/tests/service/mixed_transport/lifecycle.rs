//! Shared funding, settlement and failure preservation for carrier lifecycle tests.
use super::*;
use fips_relay::controller::RenewalPolicy;

pub(super) enum Workload {
    SustainedLoss,
    #[cfg(target_os = "linux")]
    SuspendedProvider,
}

pub(super) async fn run(second_hop: SecondHop, workload: Workload) {
    let root = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(175, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(
        root.path(),
        network.clone(),
        "sustained-carrier",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    let bench = MixedBench::start_configured(mint.url(), &network, second_hop, |_, cfg| {
        cfg.terms.fee_msat_per_kib = 1;
        cfg.terms.quote_max_units = 32 * 1024 * 1024;
        cfg.terms.quote_lifetime_secs = 90;
        cfg.terms.controller.channel_capacity_sat = 32;
        cfg.terms.controller.max_locked_sat = 64;
        cfg.terms.controller.max_wallet_spend_sat = 128;
        cfg.terms.controller.channel_lifetime_secs = 1800;
        cfg.terms.controller.renewal = Some(RenewalPolicy {
            at_capacity_percent: 100,
            before_expiry_secs: 8,
        });
    })
    .await;
    let bench = Arc::new(tokio::sync::Mutex::new(bench));
    let running = bench.clone();
    let exercise = tokio::spawn(async move {
        let mut bench = running.lock().await;
        // Topology setup has its own bounds. Keep the traffic/renewal deadline
        // unchanged, and preserve funded profiles if setup fails too.
        bench.form_ethernet_line().await;
        tokio::time::timeout(Duration::from_secs(380), async {
            match workload {
                Workload::SustainedLoss => super::sustained_loss::exercise(&mut bench).await,
                #[cfg(target_os = "linux")]
                Workload::SuspendedProvider => super::suspension::exercise(&mut bench).await,
            }
        })
        .await
    })
    .await;
    let settling = bench.clone();
    let mint_url = mint.url().to_owned();
    let accounting = network.clone();
    let cleanup = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(120), async {
            let mut bench = settling.lock().await;
            bench.enable_loss(false);
            bench.set_renewals_paused(true).await;
            for cfg in &bench.configs {
                request(cfg, &AdminRequest::Settle).await.unwrap();
            }
            let settled = bench.states().await;
            for child in &mut bench.children {
                process_support::stop(child).await;
            }
            let mut total = 0;
            for (node, cfg) in bench.configs.iter().enumerate() {
                let balance = load_mint_balance(&cfg.state_directory.join("wallet"), &mint_url)
                    .await
                    .unwrap()
                    .balance_sat;
                let budget: FundingBudget =
                    serde_json::from_value(settled[node]["funding_budget"].clone()).unwrap();
                assert_eq!(budget.pending_reserved_sat, 0);
                assert_eq!(budget.locked_sat, 0);
                if node == 1 {
                    assert!(balance > 128);
                } else {
                    assert_eq!(balance + budget.exposure_sat, 128);
                }
                total += balance;
            }
            assert_eq!(total, 384);
            assert!(accounting.accounting().unwrap().is_conserved());
            eprintln!("carrier lifecycle: all 384 test sats conserved");
        })
        .await
    })
    .await;
    let passed = matches!(exercise, Ok(Ok(()))) && matches!(cleanup, Ok(Ok(())));
    if !passed {
        Arc::try_unwrap(bench).ok().unwrap().into_inner().preserve();
        eprintln!("retained failed mint at {}", root.keep().display());
    }
    assert!(
        passed,
        "carrier lifecycle acceptance failed; original accounts retained"
    );
}
