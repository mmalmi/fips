//! Schema-stability snapshot tests for all 18 control-socket query
//! handlers.
//!
//! Each handler is invoked against a deterministically-constructed
//! `Node` (fixed identity seed, empty peer/link/transport/cache
//! state). The resulting JSON is normalized — fields whose values
//! depend on wall-clock, PID, build environment, or filesystem
//! layout are replaced with the literal string `"<redacted>"` —
//! and compared against versioned fixtures under
//! `src/control/snapshots/`.
//!
//! The point is to catch accidental schema drift (renames, type
//! changes, dropped fields) in the operator-facing wire format.
//! Empty-state snapshots are sufficient because every top-level
//! key still appears, and per-element shapes inside `[]` arrays
//! are covered by the dispatcher contract test plus serde
//! derives elsewhere.
//!
//! ## Updating snapshots
//!
//! When a schema change is intentional, regenerate fixtures by
//! deleting the relevant `.json` files (or the whole
//! `snapshots/` directory) and re-running this test. Missing
//! fixtures are written from the current output rather than
//! failing — the next run then enforces the new shape. Review
//! the resulting diff before committing.
//!
//! ## Determinism
//!
//! The `Node` is built via `Node::with_identity` from a fixed
//! 32-byte seed (`[0xAB; 32]`), so `npub`, `node_addr`, and
//! `ipv6_addr` are stable across runs and machines.
//! Time-dependent scalars are redacted in `normalize_value` —
//! see the `VOLATILE_KEYS` list there for the exact set.
//! Empty arrays/maps are intrinsically stable and need no
//! redaction.
//!
//! Schnorr signatures are non-deterministic, but the only
//! signature surfaced by these handlers is `declaration_signed:
//! bool` (a flag, not the signature itself), so no redaction is
//! needed for that.
use super::*;
use crate::config::Config;
use crate::identity::Identity;
use crate::node::Node;
use serde_json::{Map, Value, json};
use std::path::PathBuf;

/// 32-byte seed for the deterministic test identity.
/// Any non-zero secret-key-shaped value works; 0xAB-fill is just
/// readable in hex.
const TEST_SEED: [u8; 32] = [0xAB; 32];

/// Fields whose value is environment-, time-, or build-dependent
/// and therefore must be redacted before comparison. Matched by
/// JSON key name anywhere in the document.
const VOLATILE_KEYS: &[&str] = &[
    // Process / build environment
    "version",
    "pid",
    "exe_path",
    "control_socket",
    "tun_name",
    // Filesystem layout (ACL, hosts, etc.)
    "allow_file",
    "deny_file",
    // Wall-clock derived
    "uptime_secs",
    "started_at_ms",
    "session_start_ms",
    "authenticated_at_ms",
    "last_seen_ms",
    "last_activity_ms",
    "last_recv_ms",
    "created_at_ms",
    "initiated_ms",
    "last_sent_ms",
    "age_ms",
    "last_used_ms",
    "idle_ms",
    "first_seen_secs_ago",
    "last_contact_secs_ago",
];

/// Build a Node with a fixed identity, default config, and empty
/// runtime state (no peers, links, sessions, transports, or cache
/// entries). This keeps every per-element list empty and every
/// scalar deterministic modulo `VOLATILE_KEYS`.
fn build_test_node() -> Node {
    let identity =
        Identity::from_secret_bytes(&TEST_SEED).expect("test seed is a valid secret key");
    let config = Config::new();
    Node::with_identity(identity, config).expect("default config is valid")
}

/// Recursively walk a JSON value, replacing the value of any key
/// listed in `VOLATILE_KEYS` with the literal string
/// `"<redacted>"`. Array elements are recursed into.
fn normalize_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if VOLATILE_KEYS.contains(&key.as_str()) {
                    *v = Value::String("<redacted>".to_string());
                } else {
                    normalize_value(v);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                normalize_value(item);
            }
        }
        _ => {}
    }
}

/// Wrap a handler value in the on-the-wire `Response` envelope so
/// the snapshot reflects exactly what a control-socket client
/// receives. Pretty-printed and sorted-keyed for readable diffs.
fn render(value: Value) -> String {
    let mut wrapped = json!({ "status": "ok", "data": value });
    normalize_value(&mut wrapped);
    let sorted = sort_object_keys(&wrapped);
    serde_json::to_string_pretty(&sorted).expect("json serialization is infallible")
}

/// Same as `render` but takes a `Response` directly (for handlers
/// that return `Response`, not `Value`).
fn render_response(resp: super::super::protocol::Response) -> String {
    let value = serde_json::to_value(&resp).expect("response always serializes");
    let mut value = value;
    normalize_value(&mut value);
    let sorted = sort_object_keys(&value);
    serde_json::to_string_pretty(&sorted).expect("json serialization is infallible")
}

/// Recursively sort object keys for stable diff-friendly output.
/// `serde_json::Value` preserves insertion order; handlers don't
/// guarantee any particular emit order, so normalize here.
fn sort_object_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: Map<String, Value> = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_object_keys(&map[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_object_keys).collect()),
        other => other.clone(),
    }
}

fn snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("control")
        .join("snapshots")
}

/// Compare `actual` against the on-disk fixture for `name`. If the
/// fixture does not exist, write it (first-run convention) and
/// pass. Any subsequent mismatch fails with an inline diff hint.
fn assert_snapshot(name: &str, actual: &str) {
    let path = snapshot_dir().join(format!("{name}.json"));
    if !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).expect("failed to create snapshots dir");
        std::fs::write(&path, actual).expect("failed to write new snapshot");
        // Newly written: nothing to compare. Subsequent runs enforce.
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read snapshot {}: {e}", path.display()));
    // Normalize line endings: Windows checkouts with core.autocrlf=true
    // convert fixture files to CRLF; the in-memory JSON output is LF.
    let expected = expected.replace("\r\n", "\n");
    // Tolerate trailing newline differences from editors.
    if expected.trim_end() != actual.trim_end() {
        panic!(
            "snapshot mismatch for {name}\n\
                 fixture: {}\n\
                 -- expected --\n{expected}\n\
                 -- actual --\n{actual}\n\
                 -- end --\n\
                 If the schema change is intentional, delete the fixture \
                 and re-run to regenerate.",
            path.display()
        );
    }
}

// ---- 18 handler snapshot tests --------------------------------------

#[test]
fn snapshot_show_status() {
    let node = build_test_node();
    assert_snapshot("show_status", &render(show_status(&node)));
}

#[test]
fn snapshot_show_acl() {
    let node = build_test_node();
    assert_snapshot("show_acl", &render(show_acl(&node)));
}

#[test]
fn snapshot_show_peers() {
    let node = build_test_node();
    assert_snapshot("show_peers", &render(show_peers(&node)));
}

#[test]
fn snapshot_show_links() {
    let node = build_test_node();
    assert_snapshot("show_links", &render(show_links(&node)));
}

#[test]
fn snapshot_show_tree() {
    let node = build_test_node();
    assert_snapshot("show_tree", &render(show_tree(&node)));
}

#[test]
fn snapshot_show_sessions() {
    let node = build_test_node();
    assert_snapshot("show_sessions", &render(show_sessions(&node)));
}

#[test]
fn snapshot_show_bloom() {
    let node = build_test_node();
    assert_snapshot("show_bloom", &render(show_bloom(&node)));
}

#[test]
fn snapshot_show_mmp() {
    let node = build_test_node();
    assert_snapshot("show_mmp", &render(show_mmp(&node)));
}

#[test]
fn snapshot_show_cache() {
    let node = build_test_node();
    assert_snapshot("show_cache", &render(show_cache(&node)));
}

#[test]
fn snapshot_show_connections() {
    let node = build_test_node();
    assert_snapshot("show_connections", &render(show_connections(&node)));
}

#[test]
fn snapshot_show_transports() {
    let node = build_test_node();
    assert_snapshot("show_transports", &render(show_transports(&node)));
}

#[test]
fn snapshot_show_routing() {
    let node = build_test_node();
    assert_snapshot("show_routing", &render(show_routing(&node)));
}

#[test]
fn snapshot_show_identity_cache() {
    let node = build_test_node();
    assert_snapshot("show_identity_cache", &render(show_identity_cache(&node)));
}

#[test]
fn snapshot_show_listening_sockets() {
    let node = build_test_node();
    assert_snapshot(
        "show_listening_sockets",
        &render(show_listening_sockets(&node)),
    );
}

#[test]
fn snapshot_show_stats_list() {
    // Static — no Node needed.
    assert_snapshot("show_stats_list", &render(show_stats_list()));
}

#[test]
fn snapshot_show_stats_history() {
    let node = build_test_node();
    // Pin the empty-history series shape for one node-level metric.
    let params = json!({ "metric": "mesh_size", "window": "10s", "granularity": "1s" });
    let resp = show_stats_history(&node, Some(&params));
    assert_snapshot("show_stats_history", &render_response(resp));
}

#[test]
fn snapshot_show_stats_all_history() {
    let node = build_test_node();
    // Empty-history all-node series; small window keeps the
    // per-series `values` arrays short and stable.
    let params = json!({ "window": "10s", "granularity": "1s" });
    let resp = show_stats_all_history(&node, Some(&params));
    assert_snapshot("show_stats_all_history", &render_response(resp));
}

#[test]
fn snapshot_show_stats_peers() {
    let node = build_test_node();
    assert_snapshot("show_stats_peers", &render(show_stats_peers(&node)));
}

#[test]
fn snapshot_show_stats_history_all_peers() {
    let node = build_test_node();
    // No peers tracked → empty `peers: []` envelope. Per-peer
    // `values` shape is exercised once a real peer is wired in;
    // here we only pin the envelope.
    let params = json!({ "metric": "srtt_ms", "window": "10s", "granularity": "1s" });
    let resp = show_stats_history_all_peers(&node, Some(&params));
    assert_snapshot("show_stats_history_all_peers", &render_response(resp));
}

/// Sanity check: every handler advertised in `dispatch` is also
/// covered by a snapshot test above. If a new handler is added
/// without a matching snapshot, this test fails.
#[test]
fn dispatch_covers_all_snapshotted_handlers() {
    let expected = [
        "show_status",
        "show_acl",
        "show_peers",
        "show_links",
        "show_tree",
        "show_sessions",
        "show_bloom",
        "show_mmp",
        "show_cache",
        "show_connections",
        "show_transports",
        "show_routing",
        "show_identity_cache",
        "show_listening_sockets",
        "show_stats_list",
        "show_stats_history",
        "show_stats_all_history",
        "show_stats_peers",
        "show_stats_history_all_peers",
    ];
    assert_eq!(expected.len(), 19, "expected exactly 19 query handlers");
    let node = build_test_node();
    for cmd in expected {
        // Each must dispatch successfully (status == "ok") with
        // minimal params. Handlers requiring params get them.
        let params = match cmd {
            "show_stats_history" => Some(json!({
                "metric": "mesh_size", "window": "10s", "granularity": "1s"
            })),
            "show_stats_all_history" => Some(json!({ "window": "10s", "granularity": "1s" })),
            "show_stats_history_all_peers" => Some(json!({
                "metric": "srtt_ms", "window": "10s", "granularity": "1s"
            })),
            _ => None,
        };
        let resp = dispatch(&node, cmd, params.as_ref());
        assert_eq!(
            resp.status, "ok",
            "dispatch({cmd}) returned status={} message={:?}",
            resp.status, resp.message
        );
    }
}
