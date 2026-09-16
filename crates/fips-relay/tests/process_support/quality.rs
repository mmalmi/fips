//! Check production end-to-end MMP feedback across multiple report intervals.
use fips_relay::service::{AdminRequest, ServiceConfig, native_request, request};
use serde_json::Value;
use std::time::Duration;

async fn quality(config: &ServiceConfig, remote: &str) -> Value {
    let peer = fips_core::PeerIdentity::from_npub(remote).unwrap();
    let remote: String = peer
        .node_addr()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let result = native_request(config, &serde_json::json!({"command":"show_mmp"}))
        .await
        .unwrap();
    result["data"]["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["remote"] == remote)
        .map(|row| row["session_layer"].clone())
        .unwrap_or(Value::Null)
}

pub async fn assert_quality(source: &ServiceConfig, destination: &str) {
    // Multiple native report intervals must update delivery metrics, not just
    // produce one timestamp from initial session establishment.
    for sequence in 0..4 {
        request(
            source,
            &AdminRequest::Send {
                destination: destination.to_owned(),
                payload: format!("quality-{sequence}:{}", "q".repeat(128)),
            },
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let metrics = quality(source, destination).await;
            if metrics["srtt_ms"].as_f64().is_some_and(|rtt| rtt >= 0.0)
                && metrics["goodput_bps"]
                    .as_f64()
                    .is_some_and(|rate| rate > 0.0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("unfunded recipient must return native end-to-end quality reports"));
}
