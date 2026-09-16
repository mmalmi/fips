//! Observe real payment quiescence before measuring idle suppression.
use fips_relay::service::{AdminRequest, ServiceConfig, request};
use std::time::Duration;

pub async fn counts(configs: &[ServiceConfig]) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    for config in configs {
        let status = request(config, &AdminRequest::Status).await.unwrap();
        let row = status["control_traffic"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["service_port"] == 44_743)
            .unwrap();
        result.push((
            row["counters"]["requests_started"].as_u64().unwrap(),
            row["counters"]["requests_received"].as_u64().unwrap(),
        ));
    }
    result
}

pub async fn assert_idle(configs: &[ServiceConfig]) {
    // Delivery and receiver feedback may precede the final payment exchange.
    // The old perpetual 500-ms poll can never satisfy this bounded quiet wait.
    let before = tokio::time::timeout(Duration::from_secs(10), async {
        let mut previous = counts(configs).await;
        let mut unchanged_since = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let current = counts(configs).await;
            if current != previous {
                previous = current;
                unchanged_since = tokio::time::Instant::now();
            } else if unchanged_since.elapsed() >= Duration::from_millis(1_500) {
                break current;
            }
        }
    })
    .await
    .expect("completed traffic must reach payment quiescence");
    assert!(
        before.iter().any(|(sent, received)| sent + received > 0),
        "the real payment path must have been exercised"
    );
    tokio::time::sleep(Duration::from_millis(1_250)).await;
    assert_eq!(
        counts(configs).await,
        before,
        "confirmed idle channels must generate no payment-control requests"
    );
}
