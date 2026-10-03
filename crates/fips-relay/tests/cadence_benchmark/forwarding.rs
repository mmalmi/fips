//! Diagnostic only: reuse native drop counters without changing admission.
use super::*;
use fips_relay::service::native_request;

pub(super) fn trace_admission() -> bool {
    let enabled = benchmark_amount("FIPS_CADENCE_ADMISSION_TRACE", 0);
    assert!(enabled <= 1);
    enabled == 1
}

pub(super) fn log_filter() -> &'static str {
    if trace_admission() {
        "warn,fips_admission=trace"
    } else {
        "warn,fips_core::forwarding_error=debug"
    }
}

pub(super) fn log_limit() -> u64 {
    if trace_admission() {
        4 * 1024 * 1024
    } else {
        65_536
    }
}

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
    let (grace_msat, unpaid_percent, window_msat) = allowance_settings();
    writeln!(
        output,
        "{}",
        json!({"diagnostic": "native-forwarding-drops", "comparison_complete": false,
            "max_delay_ms": 500, "repeats": 2,
            "grace_msat": grace_msat, "unpaid_percent": unpaid_percent, "window_msat": window_msat,
            "log_filter": log_filter(), "retained_log_tail_bytes_per_node": log_limit(),
            "admission_timing": trace_admission(),
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
