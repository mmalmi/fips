//! Diagnostic only: reuse native drop counters without changing admission.
use super::*;
use fips_relay::service::native_request;

pub(super) const LOG_FILTER: &str = "warn,fips_core::forwarding_error=debug";

pub(super) async fn snapshot(configs: &[ServiceConfig]) -> Vec<Value> {
    let mut nodes = Vec::new();
    for config in configs {
        let response = native_request(config, &json!({"command": "show_status"}))
            .await
            .unwrap();
        assert_eq!(response["status"], "ok");
        let data = &response["data"];
        assert!(data["pid"].is_u64());
        assert!(data["forwarding"]["drop_policy_denied_packets"].is_u64());
        nodes.push(json!({"process_id": data["pid"], "counters": data["forwarding"]}));
    }
    nodes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "forwarding-drop diagnostic; set FIPS_CADENCE_REPORT and FIPS_CADENCE_DIAGNOSTIC_DIR"]
async fn observe_forwarding_drops() {
    let directory = PathBuf::from(
        std::env::var_os("FIPS_CADENCE_DIAGNOSTIC_DIR").expect("set a new log directory"),
    );
    std::fs::create_dir(&directory).unwrap();
    let mut output = new_report();
    writeln!(
        output,
        "{}",
        json!({"diagnostic": "native-forwarding-drops", "comparison_complete": false,
            "max_delay_ms": 500, "repeats": 2,
            "log_filter": LOG_FILTER, "retained_log_tail_bytes_per_node": 65_536,
            "scope": "native forwarding counters around unchanged workload and service snapshots"})
    )
    .unwrap();
    for trial_id in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(180),
            trial(500, trial_id, &mut output, TrialMode::ForwardingDrops),
        )
        .await
        .expect("forwarding diagnostic deadline");
    }
}
