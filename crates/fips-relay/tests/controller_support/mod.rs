use super::*;
use fips_relay::controller::{Purchase, RouteAccess};

pub(super) fn require_paid(access: RouteAccess) -> Purchase {
    let RouteAccess::Paid(purchase) = access else {
        panic!("paid scenario returned a free route");
    };
    purchase
}

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
    let reply = tokio::time::timeout(Duration::from_secs(10), native_query(root, node, request))
        .await
        .expect("native management deadline")
        .expect("native management response");
    assert_eq!(reply["status"], "ok", "native control failed: {reply}");
}

#[cfg(unix)]
async fn native_query(
    root: &std::path::Path,
    node: usize,
    request: serde_json::Value,
) -> Option<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let mut socket = tokio::net::UnixStream::connect(root.join(format!("native-{node}.sock")))
        .await
        .ok()?;
    let mut bytes = serde_json::to_vec(&request).ok()?;
    bytes.push(b'\n');
    socket.write_all(&bytes).await.ok()?;
    let mut reply = Vec::new();
    BufReader::new(socket.take(65_537))
        .read_until(b'\n', &mut reply)
        .await
        .ok()?;
    if reply.len() > 65_536 || !reply.ends_with(b"\n") {
        return None;
    }
    serde_json::from_slice(&reply).ok()
}

#[cfg(unix)]
pub(super) async fn delivery_snapshot(root: &std::path::Path, peers: &[PeerIdentity]) {
    // Query only generated test nodes after failure. Never read wallet journals
    // or extend the delivery deadline while gathering routing/session evidence.
    let captured = tokio::time::timeout(Duration::from_secs(4), async {
        for (node, peer) in peers.iter().enumerate() {
            eprintln!(
                "controller delivery node={node} address={}",
                peer.node_addr()
            );
            for command in ["show_routing", "show_sessions", "show_tree"] {
                let reply = tokio::time::timeout(
                    Duration::from_millis(250),
                    native_query(root, node, serde_json::json!({"command": command})),
                )
                .await;
                let value = match reply {
                    Ok(Some(reply)) if reply["status"] == "ok" => reply["data"].clone(),
                    _ => serde_json::json!({"unavailable": true}),
                };
                let text = value.to_string();
                let bounded: String = text.chars().take(12_000).collect();
                eprintln!(
                    "controller delivery node={node} query={command} truncated={} {bounded}",
                    bounded.len() < text.len()
                );
            }
        }
    })
    .await;
    if captured.is_err() {
        eprintln!("controller delivery diagnostics reached their four-second budget");
    }
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
            "unfinished_funding": j["funding"].as_object().unwrap().iter()
                .filter(|(_, row)| row["funded"].is_null()).take(16)
                .map(|(id, row)| serde_json::json!({"id": id, "created_unix": row["created_unix"],
                    "expires_unix": row["expires_unix"], "reclaim_present": !row["reclaim"].is_null()}))
                .collect::<Vec<_>>(),
            "pending_offers": j["requested"].as_object().unwrap().keys()
                .filter(|id| !j["outgoing"].as_object().unwrap().values()
                    .any(|row| row["offer"]["id"] == **id && row["accepted"] == true))
                .take(16).collect::<Vec<_>>(),
            "active_outgoing": j["outgoing"].as_object().unwrap().iter()
                .filter(|(_, row)| row["retired"] == false).take(16)
                .map(|(id, row)| serde_json::json!({"id": id, "accepted": row["accepted"],
                    "channel": row["purchase"]["channel"]["id"], "funding_id": row["funding_id"]}))
                .collect::<Vec<_>>(),
            "outgoing": rows("outgoing", &["accepted", "retired"]),
            "renewals": rows("renewals", &["replacements", "completed"]),
            "buyer_settlements": rows("buyer_settlements", &["usage", "payment", "report", "refunded"]),
            "seller_settlements": rows("seller_settlements", &["usage", "payment", "report"])})
    }).collect()
}
