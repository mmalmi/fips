use crate::control::protocol::Response;
use crate::identity::{NodeAddr, PeerIdentity};
use crate::node::Node;
use crate::node::stats_history::{ALL_METRICS, ALL_PEER_METRICS, Granularity, Metric, PeerMetric};
use serde_json::{Value, json};
use std::str::FromStr;
use std::time::Duration;

/// Resolve an `npub1...` string to the corresponding `NodeAddr`.
fn parse_peer_npub(s: &str) -> Result<NodeAddr, String> {
    PeerIdentity::from_npub(s)
        .map(|p| *p.node_addr())
        .map_err(|e| format!("invalid peer npub: {e}"))
}

/// `show_stats_list` — Enumerate available history metrics and their units.
pub fn show_stats_list() -> Value {
    let metrics: Vec<Value> = ALL_METRICS
        .iter()
        .map(|m| {
            json!({
                "name": m.name(),
                "unit": m.unit(),
                "scope": "node",
            })
        })
        .chain(ALL_PEER_METRICS.iter().map(|m| {
            json!({
                "name": m.name(),
                "unit": m.unit(),
                "scope": "peer",
            })
        }))
        .collect();
    json!({
        "metrics": metrics,
        "fast_ring_seconds": crate::node::stats_history::FAST_RING_CAPACITY,
        "slow_ring_minutes": crate::node::stats_history::SLOW_RING_CAPACITY,
        "peer_retention_seconds": crate::node::stats_history::PEER_EVICTION_SECS,
        "inactive_peer_history_limit": crate::node::stats_history::MAX_INACTIVE_PEER_HISTORIES,
    })
}

/// `show_stats_history` — Time-series samples for one metric.
///
/// Params:
/// - `metric` (required): metric name. Node-level metrics (e.g.
///   `mesh_size`) are resolved against `Metric`; per-peer metrics (e.g.
///   `srtt_ms`, `ecn_ce`) require the `peer` param and resolve against
///   `PeerMetric`.
/// - `peer` (optional): `npub1...` of the peer; required for per-peer
///   metrics.
/// - `window` (default `10m`): duration `<N>s`, `<N>m`, or `<N>h`.
/// - `granularity` (default `1s`): `1s` or `1m`.
pub fn show_stats_history(node: &Node, params: Option<&Value>) -> Response {
    use Response;
    let Some(params) = params else {
        return Response::error("missing params for show_stats_history");
    };

    let metric_name = match params.get("metric").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'metric' parameter"),
    };

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let peer_npub = params.get("peer").and_then(|v| v.as_str());
    let hist = node.stats_history();

    if let Some(npub) = peer_npub {
        let addr = match parse_peer_npub(npub) {
            Ok(a) => a,
            Err(e) => return Response::error(e),
        };
        let peer_metric = match PeerMetric::from_str(metric_name) {
            Ok(m) => m,
            Err(e) => return Response::error(e),
        };
        match hist.peer_query(&addr, peer_metric, window, granularity) {
            Some(series) => Response::ok(serde_json::to_value(&series).unwrap_or(Value::Null)),
            None => Response::error(format!(
                "peer not tracked in stats history: {}",
                node.peer_display_name(&addr)
            )),
        }
    } else {
        let metric = match Metric::from_str(metric_name) {
            Ok(m) => m,
            Err(e) => return Response::error(e),
        };
        let series = hist.query(metric, window, granularity);
        Response::ok(serde_json::to_value(&series).unwrap_or(Value::Null))
    }
}

/// Parse a duration of the form `<N>s`, `<N>m`, or `<N>h` into a `Duration`.
fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num_part, unit) = s.split_at(s.len() - 1);
    let n: u64 = num_part
        .parse()
        .map_err(|_| format!("invalid duration: {s}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("unknown duration unit: {unit} (expected s, m, h)")),
    };
    Ok(Duration::from_secs(secs))
}

/// `show_stats_all_history` — Return a series for every tracked metric
/// in one round trip. Intended for the fipstop Graphs tab.
///
/// Without `peer`: returns the 10 node-level metrics.
/// With `peer` (npub): returns the 7 per-peer metrics for that peer.
///
/// Params: `{"peer": "<npub>"?, "window": "<dur>", "granularity": "<1s|1m>"}`.
pub fn show_stats_all_history(node: &Node, params: Option<&Value>) -> Response {
    use Response;
    let params = params.cloned().unwrap_or_else(|| json!({}));

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let peer_npub = params.get("peer").and_then(|v| v.as_str());
    let hist = node.stats_history();

    let series: Vec<Value> = if let Some(npub) = peer_npub {
        let addr = match parse_peer_npub(npub) {
            Ok(a) => a,
            Err(e) => return Response::error(e),
        };
        if !hist.has_peer(&addr) {
            return Response::error(format!(
                "peer not tracked in stats history: {}",
                node.peer_display_name(&addr)
            ));
        }
        ALL_PEER_METRICS
            .iter()
            .map(|m| {
                let s = hist
                    .peer_query(&addr, *m, window, granularity)
                    .unwrap_or_else(|| {
                        // Unreachable: has_peer checked above, but degrade
                        // gracefully rather than panic.
                        crate::node::stats_history::Series {
                            metric: m.name(),
                            unit: m.unit(),
                            granularity_seconds: granularity.seconds(),
                            values: Vec::new(),
                        }
                    });
                serde_json::to_value(&s).unwrap_or(Value::Null)
            })
            .collect()
    } else {
        ALL_METRICS
            .iter()
            .map(|m| {
                let s = hist.query(*m, window, granularity);
                serde_json::to_value(&s).unwrap_or(Value::Null)
            })
            .collect()
    };

    Response::ok(json!({
        "granularity_seconds": granularity.seconds(),
        "window_seconds": window.as_secs(),
        "peer": peer_npub,
        "series": series,
    }))
}

/// `show_stats_peers` — Enumerate peers tracked in the stats history
/// with their lifecycle metadata. Used by operator tools to populate
/// peer selectors and to confirm a peer is in the retention window.
pub fn show_stats_peers(node: &Node) -> Value {
    let hist = node.stats_history();
    let now = std::time::Instant::now();

    let mut peers: Vec<Value> = hist
        .peers()
        .map(|(addr, rings)| {
            let last_contact_secs = now.duration_since(rings.last_contact()).as_secs();
            let first_seen_secs = now.duration_since(rings.first_seen()).as_secs();
            let is_active = node.peers().any(|p| p.node_addr() == addr);
            let npub = node
                .peers()
                .find(|p| p.node_addr() == addr)
                .map(|p| p.npub())
                .unwrap_or_else(|| hex::encode(addr.as_bytes()));
            json!({
                "npub": npub,
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "is_active": is_active,
                "first_seen_secs_ago": first_seen_secs,
                "last_contact_secs_ago": last_contact_secs,
            })
        })
        .collect();

    // Stable display order: active peers first, then by display name.
    peers.sort_by(|a, b| {
        let a_active = a
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let b_active = b
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match (b_active, a_active) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => a
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("display_name").and_then(|v| v.as_str()).unwrap_or("")),
        }
    });

    json!({ "peers": peers, "count": peers.len() })
}

/// `show_stats_history_all_peers` — One metric across every tracked
/// peer in one round trip. Backs the fipstop MetricByPeer grid view.
///
/// Params: `{"metric": "<name>", "window": "<dur>", "granularity": "<1s|1m>"}`.
/// `metric` must be a per-peer metric name (see `PeerMetric`).
pub fn show_stats_history_all_peers(node: &Node, params: Option<&Value>) -> Response {
    use Response;
    let Some(params) = params else {
        return Response::error("missing params for show_stats_history_all_peers");
    };

    let metric_name = match params.get("metric").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'metric' parameter"),
    };
    let metric = match PeerMetric::from_str(metric_name) {
        Ok(m) => m,
        Err(e) => return Response::error(e),
    };

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let hist = node.stats_history();
    let peer_addrs: Vec<NodeAddr> = hist.peer_addrs().copied().collect();

    let mut peers: Vec<Value> = peer_addrs
        .iter()
        .filter_map(|addr| {
            let s = hist.peer_query(addr, metric, window, granularity)?;
            let is_active = node.peers().any(|p| p.node_addr() == addr);
            Some(json!({
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "is_active": is_active,
                "values": serde_json::to_value(&s.values).unwrap_or(Value::Null),
            }))
        })
        .collect();

    // Active peers first, then by display name.
    peers.sort_by(|a, b| {
        let a_active = a
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let b_active = b
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match (b_active, a_active) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => a
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("display_name").and_then(|v| v.as_str()).unwrap_or("")),
        }
    });

    Response::ok(json!({
        "metric": metric.name(),
        "unit": metric.unit(),
        "granularity_seconds": granularity.seconds(),
        "window_seconds": window.as_secs(),
        "peers": peers,
    }))
}
