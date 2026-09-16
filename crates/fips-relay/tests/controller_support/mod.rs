use super::*;

pub(super) fn policy(mint_url: &str, automatic_renewal: bool, capacity: u64) -> ControllerPolicy {
    ControllerPolicy {
        mint_url: mint_url.to_string(),
        channel_capacity_sat: capacity,
        max_locked_sat: capacity * 2,
        max_funding_overhead_sat: 0,
        max_wallet_spend_sat: 1024,
        channel_lifetime_secs: 600,
        renewal: automatic_renewal.then_some(RenewalPolicy {
            at_capacity_percent: 100,
            before_expiry_secs: 30,
        }),
    }
}

#[cfg(unix)]
pub(super) async fn native_control(
    root: &std::path::Path,
    node: usize,
    request: serde_json::Value,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut socket = tokio::net::UnixStream::connect(root.join(format!("native-{node}.sock")))
            .await
            .unwrap();
        let mut bytes = serde_json::to_vec(&request).unwrap();
        bytes.push(b'\n');
        socket.write_all(&bytes).await.unwrap();
        let mut reply = String::new();
        BufReader::new(socket).read_line(&mut reply).await.unwrap();
        let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["status"], "ok", "native control failed: {reply}");
    })
    .await
    .expect("native management deadline");
}

pub(super) fn errors(controllers: &[Arc<Controller>]) -> Vec<(usize, String)> {
    controllers
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.last_error().map(|e| (i, e)))
        .collect::<Vec<_>>()
}
pub(super) fn recovery_stages(root: &std::path::Path) -> Vec<serde_json::Value> {
    (0..5).map(|i| {
        let path = root.join(format!("controller-{i}/controller.json"));
        let j: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let rows = |name: &str, fields: &[&str]| j[name].as_object().unwrap().values().map(|row| {
            fields.iter().map(|field| match &row[*field] {
                serde_json::Value::Null => "none".to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Array(a) => format!("{} entries", a.len()),
                _ => "saved".to_string(),
            }).collect::<Vec<_>>()
        }).collect::<Vec<_>>();
        serde_json::json!({"node": i, "funding": j["funding"].as_object().unwrap().len(),
            "outgoing": rows("outgoing", &["accepted", "retired"]),
            "renewals": rows("renewals", &["replacements", "completed"]),
            "buyer_settlements": rows("buyer_settlements", &["usage", "payment", "report", "refunded"]),
            "seller_settlements": rows("seller_settlements", &["usage", "payment", "report"])})
    }).collect()
}
