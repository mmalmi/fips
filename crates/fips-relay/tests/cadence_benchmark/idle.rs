//! Diagnostic only: identify billed native upkeep without changing its timers.
use super::*;

pub(super) async fn observe(configs: &[ServiceConfig], output: &mut std::fs::File) {
    let started = Instant::now();
    loop {
        let nodes = sample(configs).await;
        writeln!(
            output,
            "{}",
            json!({"idle_control": {"elapsed_ms": started.elapsed().as_millis(),
                "unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                "nodes": nodes}})
        )
        .unwrap();
        output.flush().unwrap();
        if started.elapsed() >= Duration::from_secs(16) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "idle trace, not a cadence comparison; set FIPS_CADENCE_REPORT and FIPS_CADENCE_DIAGNOSTIC_DIR"]
async fn observe_native_session_upkeep_accounting() {
    let directory = PathBuf::from(
        std::env::var_os("FIPS_CADENCE_DIAGNOSTIC_DIR").expect("set a new log directory"),
    );
    std::fs::create_dir(&directory).unwrap();
    let mut output = new_report();
    writeln!(
        output,
        "{}",
        json!({"diagnostic":"idle-session-control",
        "comparison_complete":false, "max_delay_ms":500,
        "sample_interval_ms":100, "idle_observation_secs":16})
    )
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(180),
        trial(500, 0, &mut output, TrialMode::IdleControl),
    )
    .await
    .expect("idle diagnostic deadline");
}
