use super::*;
use fips_relay::controller::{Purchase, RouteAccess};
mod delivery_trace;
pub(super) use delivery_trace::DeliveryTrace;
#[cfg(unix)]
mod rekey;
#[cfg(unix)]
pub(super) use rekey::RekeyObservation;

pub(super) fn controller(result: Result<Controller, String>, renewal: bool) -> Arc<Controller> {
    // The small-channel renewal workload owns its disposable mint. Its request
    // allowance is independent of channel capital, payment and delivery limits.
    let budget = renewal.then_some(fips_relay::controller::FundingRequestBudget {
        burst: 128.try_into().unwrap(),
        requests_per_minute: 60_000.try_into().unwrap(),
    });
    Arc::new(result.unwrap().with_funding_request_budget(budget))
}

pub(super) fn require_paid(access: RouteAccess) -> Purchase {
    let RouteAccess::Paid(purchase) = access else {
        panic!("paid scenario returned a free route");
    };
    purchase
}

pub(super) async fn accepted_routes(
    root: &std::path::Path,
    peers: &[PeerIdentity],
    controllers: &[Arc<Controller>],
    forward: Result<Purchase, String>,
    reverse: Result<Purchase, String>,
) -> (Purchase, Purchase) {
    if forward.is_err() || reverse.is_err() {
        #[cfg(unix)]
        delivery_snapshot(root, peers).await;
        eprintln!(
            "route acceptance recovery stages={}",
            serde_json::json!(recovery_stages(root))
        );
    }
    (
        forward.unwrap_or_else(|e| {
            panic!("forward acceptance: {e}; errors={:?}", errors(controllers))
        }),
        reverse.unwrap_or_else(|e| {
            panic!("reverse acceptance: {e}; errors={:?}", errors(controllers))
        }),
    )
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

pub(super) async fn delivery_evidence(
    root: &std::path::Path,
    peers: &[PeerIdentity],
    traces: &[Arc<DeliveryTrace>],
    ledgers: &[Arc<DurableRelay>],
    buyers: &[Arc<BuyerAuthorizer>],
) {
    for (node, trace) in traces.iter().enumerate() {
        trace.dump(node);
    }
    #[cfg(unix)]
    delivery_snapshot(root, peers).await;
    // Inspect only fixture terms and counters, never wallet proofs or payment tokens.
    let journals: Vec<_> = (0..peers.len())
        .map(|i| controller_journal(root, i))
        .collect();
    for (buyer, journal) in journals.iter().enumerate() {
        for row in journal["outgoing"].as_object().unwrap().values().take(32) {
            let purchase: Purchase = serde_json::from_value(row["purchase"].clone()).unwrap();
            let seller = peers
                .iter()
                .position(|p| *p.node_addr() == purchase.provider)
                .unwrap();
            let channel = &purchase.channel.id;
            let contract = &purchase.contract.id;
            let incoming = &journals[seller]["incoming"][contract];
            let terms_match =
                ledgers[seller].channel_terms(channel).as_ref() == Some(&purchase.channel);
            eprintln!(
                "controller delivery credit {}",
                serde_json::json!({
                    "buyer": buyer, "seller": seller, "channel": channel, "contract": contract,
                    "destination": peers.iter().position(|p| *p.node_addr() == purchase.contract.destination),
                    "accepted": row["accepted"], "retired": row["retired"],
                    "provider_phase": incoming["phase"], "terms_match": terms_match,
                    "capacity_sat": purchase.channel.capacity_sat, "max_units": purchase.contract.max_units,
                    "observed_units": buyers[buyer].observed_units(contract),
                    "evidence_msat": buyers[buyer].evidence_msat(channel),
                    "authorized_sat": buyers[buyer].authorized_sat(channel),
                    "seller_usage": ledgers[seller].usage(contract),
                    "seller_channel_usage": ledgers[seller].channel_usage(channel)
                })
            );
        }
    }
}

fn controller_journal(root: &std::path::Path, node: usize) -> serde_json::Value {
    let path = root.join(format!("controller-{node}/controller.json"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

pub(super) fn recovery_stages(root: &std::path::Path) -> Vec<serde_json::Value> {
    (0..5).map(|i| {
        let j = controller_journal(root, i);
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

// Offline wallet reads require exclusive ownership. Drain the live controller
// workers first, then resume the same controllers and request streams.
pub(super) async fn verify_reloaded_wallets(
    tasks: &mut Vec<ControllerTasks>,
    controllers: &[Arc<Controller>],
    wallets: &[std::path::PathBuf],
    links: &[(usize, usize, Purchase)],
    mint_url: &str,
    seed_sat: u64,
    capacity: u64,
) {
    let mut streams = Vec::new();
    for task in tasks.drain(..) {
        streams.push(
            task.stop()
                .await
                .expect("controller drained before wallet inspection"),
        );
    }
    for (i, controller) in controllers.iter().enumerate() {
        let expected: Vec<_> = links
            .iter()
            .filter(|(buyer, _, _)| *buyer == i)
            .map(|(_, _, purchase)| purchase.clone())
            .collect();
        assert_eq!(controller.purchases().await.unwrap(), expected);
        assert_eq!(
            load_mint_balance(&wallets[i], mint_url)
                .await
                .unwrap()
                .balance_sat,
            seed_sat - capacity * expected.len() as u64,
            "controller reload must not fund another channel"
        );
    }
    for (controller, incoming) in controllers.iter().zip(streams) {
        tasks.push(ControllerTasks::start(controller.clone(), incoming));
    }
}

pub(super) async fn collect_wallets(
    root: &std::path::Path,
    wallets: &[std::path::PathBuf],
    mint_url: &str,
    expected: [i64; 5],
) {
    for (wallet, balance) in wallets.iter().zip(expected) {
        assert_eq!(
            load_mint_balance(wallet, mint_url)
                .await
                .unwrap()
                .balance_sat,
            balance as u64
        );
        let token = send_payment_token(wallet, mint_url, balance as u64)
            .await
            .unwrap();
        receive_payment_token(&root.join("collector"), &token.token)
            .await
            .unwrap();
    }
}
