use fips_relay::{
    controller::ControllerPolicy,
    service::{AdminRequest, ServiceConfig, ServiceTerms, request},
};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};

pub fn config(root: &Path, mint: &str) -> ServiceConfig {
    ServiceConfig {
        state_directory: root.join("state"),
        udp_bind: Some("127.0.0.1:0".parse().unwrap()),
        customer_network: None,
        neighbor_admission: Default::default(),
        destination_fees: Default::default(),
        return_allowance: false,
        price_selection: None,
        payment_cadence: Default::default(),
        ethernet_interfaces: vec![],
        neighbors: vec![],
        terms: ServiceTerms {
            billing: Default::default(),
            controller: ControllerPolicy {
                mint_url: mint.into(),
                channel_capacity_sat: 32,
                max_locked_sat: 64,
                max_funding_overhead_sat: 0,
                max_wallet_spend_sat: 1024,
                channel_lifetime_secs: 600,
                renewal: None,
            },
            buyer_budget_sat: 64,
            window_msat: 4_000,
            grace_msat: 8_000,
            fee_msat_per_kib: 1_024,
            max_rate_msat_per_kib: 8_192,
            quote_lifetime_secs: 300,
            quote_max_units: 30_000,
        },
    }
}

pub async fn start(path: &Path) -> Child {
    let log = std::fs::File::create(path.with_extension("log")).unwrap();
    Command::new(env!("CARGO_BIN_EXE_fips-relay"))
        .arg("run")
        .arg(path)
        .stdout(Stdio::null())
        .env(
            "RUST_LOG",
            std::env::var("FIPS_RELAY_TEST_LOG").unwrap_or_else(|_| "warn".into()),
        )
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

pub async fn stop(child: &mut Child) {
    let pid = child.id().expect("owned test child");
    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .await
            .unwrap()
            .success()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(40), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

pub fn has_line_peers(status: &serde_json::Value, npubs: &[String], index: usize) -> bool {
    let actual = status["peers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["connected"] == true)
        .map(|p| p["npub"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let expected = npubs
        .iter()
        .enumerate()
        .filter(|(j, _)| index.abs_diff(*j) == 1)
        .map(|(_, p)| p.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    actual == expected
}

pub async fn ready(
    configs: &[ServiceConfig],
    paths: &[PathBuf],
    npubs: &[String],
    children: &mut [Child],
) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let mut ready_nodes = 0;
            for (i, cfg) in configs.iter().enumerate() {
                if let Some(status) = children[i].try_wait().unwrap() {
                    panic!(
                        "node {i} exited {status}: {}",
                        std::fs::read_to_string(paths[i].with_extension("log")).unwrap()
                    );
                }
                if let Ok(status) = request(cfg, &AdminRequest::Status).await
                    && has_line_peers(&status, npubs, i)
                {
                    ready_nodes += 1;
                }
            }
            if ready_nodes == configs.len() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("all processes should establish exactly the intended line peers");
}

pub async fn command(path: &Path, action: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fips-relay"))
        .arg(action)
        .arg(path)
        .output()
        .await
        .unwrap()
}
