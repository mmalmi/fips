use nostr::prelude::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::node::Node;

const DEFAULT_RATING_SCOPE: &str = "fips.peer";
const FACT_OP_KIND: u16 = 7368;
const FACT_SCHEMA_VERSION: &str = "1";
const FACT_TYPE_RATING: &str = "rating";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerRatingExportFormat {
    Records,
    Events,
}

impl PeerRatingExportFormat {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("records").trim() {
            "" | "records" | "json" => Ok(Self::Records),
            "events" | "fact-events" | "nostr-events" => Ok(Self::Events),
            other => Err(format!(
                "unsupported peer rating export format {other}; expected records or events"
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Records => "records",
            Self::Events => "events",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerRatingQuery {
    scope: String,
    format: PeerRatingExportFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PeerRatingRecord {
    id: String,
    rater: String,
    subject: String,
    scope: String,
    rating: i64,
    min_rating: i64,
    max_rating: i64,
    sample_count: u64,
    window_end: u64,
    reason: String,
    tags: Vec<String>,
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerRatingHealth {
    score: i64,
    sample_count: u64,
    reason: String,
}

pub fn show_peer_ratings(node: &Node, params: Option<&Value>) -> super::super::protocol::Response {
    let query = match PeerRatingQuery::parse(params) {
        Ok(query) => query,
        Err(error) => return super::super::protocol::Response::error(error),
    };

    match build_peer_rating_export(node, &query.scope, query.format, now_unix_secs()) {
        Ok(export) => super::super::protocol::Response::ok(export),
        Err(error) => super::super::protocol::Response::error(error),
    }
}

impl PeerRatingQuery {
    fn parse(params: Option<&Value>) -> Result<Self, String> {
        let scope = params
            .and_then(|params| params.get("scope"))
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_RATING_SCOPE)
            .trim()
            .to_owned();
        if scope.is_empty() {
            return Err("rating scope cannot be empty".to_string());
        }

        let format = PeerRatingExportFormat::parse(
            params
                .and_then(|params| params.get("format"))
                .and_then(Value::as_str),
        )?;
        Ok(Self { scope, format })
    }
}

fn build_peer_rating_export(
    node: &Node,
    scope: &str,
    format: PeerRatingExportFormat,
    now: u64,
) -> Result<Value, String> {
    let peers_value = super::show_peers(node);
    let peers = peers_value
        .get("peers")
        .and_then(Value::as_array)
        .ok_or_else(|| "show_peers response did not include peers array".to_string())?;
    let rater = node.npub();
    let ratings = peers
        .iter()
        .filter_map(|peer| peer_rating_record(&rater, peer, scope, now))
        .collect::<Vec<_>>();

    match format {
        PeerRatingExportFormat::Records => Ok(json!({
            "schema": 1,
            "type": "fips_peer_rating_export",
            "format": format.as_str(),
            "scope": scope,
            "rater": rater,
            "generated_at": now,
            "ratings": ratings,
        })),
        PeerRatingExportFormat::Events => {
            let keys = nostr_keys_for_node(node)?;
            let events = ratings
                .iter()
                .map(|rating| rating.to_fact_event(&keys))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({
                "schema": 1,
                "type": "fips_peer_rating_fact_event_export",
                "format": format.as_str(),
                "kind": FACT_OP_KIND,
                "scope": scope,
                "rater": rater,
                "generated_at": now,
                "events": events,
            }))
        }
    }
}

fn nostr_keys_for_node(node: &Node) -> Result<Keys, String> {
    Keys::parse(&hex::encode(node.identity().keypair().secret_bytes()))
        .map_err(|error| format!("failed to derive Nostr signing keys: {error}"))
}

fn peer_rating_record(
    rater: &str,
    peer: &Value,
    scope: &str,
    now: u64,
) -> Option<PeerRatingRecord> {
    let subject = peer_rating_subject(peer)?;
    let health = compute_peer_rating(peer)?;
    Some(PeerRatingRecord {
        id: Uuid::new_v4().to_string(),
        rater: rater.to_owned(),
        subject,
        scope: scope.to_owned(),
        rating: health.score,
        min_rating: 0,
        max_rating: 100,
        sample_count: health.sample_count,
        window_end: now,
        reason: health.reason,
        tags: vec!["fips".to_string(), "peer".to_string()],
        created_at: now,
    })
}

impl PeerRatingRecord {
    fn to_fact_event(&self, keys: &Keys) -> Result<Event, String> {
        let subject = Uuid::parse_str(&self.id)
            .map_err(|error| format!("rating id must be a UUID: {}: {error}", self.id))?;
        let mut tags = vec![
            raw_tag(["i", &subject.to_string(), "subject"])?,
            raw_tag(["i", &self.rater.to_lowercase()])?,
            raw_tag(["i", &self.subject.to_lowercase()])?,
            raw_tag(["i", &self.scope.to_lowercase()])?,
            raw_tag(["type", FACT_TYPE_RATING])?,
            raw_tag(["schema", FACT_SCHEMA_VERSION])?,
            raw_tag(["created_at", &self.created_at.to_string()])?,
            raw_tag(["rater", &self.rater])?,
            raw_tag(["subject", &self.subject])?,
            raw_tag(["rating", &self.rating.to_string()])?,
            raw_tag(["min_rating", &self.min_rating.to_string()])?,
            raw_tag(["max_rating", &self.max_rating.to_string()])?,
            raw_tag(["scope", &self.scope])?,
            raw_tag(["sample_count", &self.sample_count.to_string()])?,
            raw_tag(["window_end", &self.window_end.to_string()])?,
            raw_tag(["reason", &self.reason])?,
        ];
        for tag in &self.tags {
            tags.push(raw_tag(["i", &tag.to_lowercase()])?);
            tags.push(raw_tag(["tag", tag])?);
        }

        EventBuilder::new(Kind::from(FACT_OP_KIND), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(self.created_at.max(1)))
            .sign_with_keys(keys)
            .map_err(|error| format!("failed to sign peer rating fact event: {error}"))
    }
}

fn raw_tag<const N: usize>(parts: [&str; N]) -> Result<Tag, String> {
    Tag::parse(parts).map_err(|error| format!("failed to build Nostr tag: {error}"))
}

fn peer_rating_subject(peer: &Value) -> Option<String> {
    json_string_field(peer, "npub")
        .filter(|npub| !npub.trim().is_empty())
        .or_else(|| json_string_field(peer, "node_addr").map(|addr| format!("fips-node:{addr}")))
}

fn compute_peer_rating(peer: &Value) -> Option<PeerRatingHealth> {
    let mut score = 50_i64;
    let mut signals = 0_usize;
    let mut reasons = Vec::new();

    if let Some(mmp) = peer.get("mmp").and_then(Value::as_object) {
        if let Some(loss) = json_f64_prefer(mmp, &["smoothed_loss", "loss_rate"]) {
            let loss = loss.clamp(0.0, 1.0);
            signals += 1;
            if loss <= 0.005 {
                score += 10;
            } else if loss <= 0.02 {
                score += 4;
            } else {
                score -= ((loss * 100.0).round() as i64).clamp(4, 45);
            }
            reasons.push(format!("loss={loss:.3}"));
        }

        if let Some(delivery) = average_delivery_ratio(mmp) {
            let delivery = delivery.clamp(0.0, 1.0);
            signals += 1;
            if delivery >= 0.995 {
                score += 15;
            } else if delivery >= 0.98 {
                score += 8;
            } else if delivery < 0.80 {
                score -= 35;
            } else if delivery < 0.90 {
                score -= 25;
            } else if delivery < 0.97 {
                score -= 12;
            }
            reasons.push(format!("delivery={delivery:.3}"));
        }

        if let Some(etx) = json_f64_prefer(mmp, &["smoothed_etx", "etx"]) {
            let etx = etx.max(1.0);
            signals += 1;
            if etx <= 1.05 {
                score += 12;
            } else if etx <= 1.20 {
                score += 6;
            } else if etx >= 3.0 {
                score -= 35;
            } else if etx >= 2.0 {
                score -= 25;
            } else if etx >= 1.5 {
                score -= 15;
            }
            reasons.push(format!("etx={etx:.2}"));
        }

        if let Some(srtt_ms) = json_f64_prefer(mmp, &["srtt_ms"]) {
            signals += 1;
            if srtt_ms <= 50.0 {
                score += 8;
            } else if srtt_ms <= 150.0 {
                score += 3;
            } else if srtt_ms >= 1_000.0 {
                score -= 25;
            } else if srtt_ms >= 300.0 {
                score -= 15;
            }
            reasons.push(format!("srtt_ms={srtt_ms:.0}"));
        }

        if let Some(goodput_bps) = json_f64_prefer(mmp, &["goodput_bps"]) {
            signals += 1;
            if goodput_bps >= 5_000_000.0 {
                score += 8;
            } else if goodput_bps >= 1_000_000.0 {
                score += 4;
            }
            reasons.push(format!("goodput_bps={goodput_bps:.0}"));
        }
    }

    let decrypt_failures = json_u64_field(peer, "consecutive_decrypt_failures").unwrap_or(0);
    if decrypt_failures > 0 {
        signals += 1;
        score -= i64::try_from(decrypt_failures.saturating_mul(20).min(70)).unwrap_or(70);
        reasons.push(format!("decrypt_failures={decrypt_failures}"));
    }

    let replay_suppressed = json_u64_field(peer, "replay_suppressed").unwrap_or(0);
    if replay_suppressed > 0 {
        signals += 1;
        score -= i64::try_from(replay_suppressed.saturating_mul(5).min(30)).unwrap_or(30);
        reasons.push(format!("replay_suppressed={replay_suppressed}"));
    }

    if signals == 0 {
        return None;
    }

    let sample_count = peer_sample_count(peer).max(signals as u64);
    Some(PeerRatingHealth {
        score: score.clamp(0, 100),
        sample_count,
        reason: reasons.join(" "),
    })
}

fn average_delivery_ratio(map: &serde_json::Map<String, Value>) -> Option<f64> {
    let forward = json_f64_prefer(map, &["delivery_ratio_forward"]);
    let reverse = json_f64_prefer(map, &["delivery_ratio_reverse"]);
    match (forward, reverse) {
        (Some(forward), Some(reverse)) => Some((forward + reverse) / 2.0),
        (Some(forward), None) => Some(forward),
        (None, Some(reverse)) => Some(reverse),
        (None, None) => None,
    }
}

fn peer_sample_count(peer: &Value) -> u64 {
    ["packets_sent", "packets_recv"]
        .into_iter()
        .filter_map(|key| nested_u64_field(peer, "stats", key))
        .fold(0_u64, u64::saturating_add)
}

fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn json_u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn nested_u64_field(value: &Value, object_key: &str, key: &str) -> Option<u64> {
    value
        .get(object_key)
        .and_then(|object| object.get(key))
        .and_then(Value::as_u64)
}

fn json_f64_prefer(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .filter_map(|key| object.get(*key).and_then(Value::as_f64))
        .find(|value| value.is_finite())
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::identity::Identity;

    const TEST_SEED: [u8; 32] = [0xAB; 32];

    fn build_test_node() -> Node {
        let identity =
            Identity::from_secret_bytes(&TEST_SEED).expect("test seed is a valid secret key");
        Node::with_identity(identity, Config::new()).expect("default config is valid")
    }

    #[test]
    fn healthy_peer_rating_promotes() {
        let peer = json!({
            "npub": "npub1good",
            "stats": {"packets_sent": 100, "packets_recv": 120},
            "mmp": {
                "smoothed_loss": 0.001,
                "smoothed_etx": 1.01,
                "delivery_ratio_forward": 0.999,
                "delivery_ratio_reverse": 0.998,
                "srtt_ms": 20.0,
                "goodput_bps": 8_000_000.0
            },
            "replay_suppressed": 0,
            "consecutive_decrypt_failures": 0
        });

        let health = compute_peer_rating(&peer).expect("health rating");

        assert!(health.score > 50, "{health:?}");
        assert_eq!(health.sample_count, 220);
    }

    #[test]
    fn degraded_peer_rating_downranks() {
        let peer = json!({
            "npub": "npub1bad",
            "stats": {"packets_sent": 100, "packets_recv": 120},
            "mmp": {
                "smoothed_loss": 0.25,
                "smoothed_etx": 3.2,
                "delivery_ratio_forward": 0.73,
                "delivery_ratio_reverse": 0.81,
                "srtt_ms": 1200.0,
                "goodput_bps": 50_000.0
            },
            "replay_suppressed": 2,
            "consecutive_decrypt_failures": 2
        });

        let health = compute_peer_rating(&peer).expect("health rating");

        assert!(health.score < 50, "{health:?}");
    }

    #[test]
    fn peer_without_health_signal_is_skipped() {
        let peer = json!({
            "npub": "npub1unknown",
            "stats": {"packets_sent": 0, "packets_recv": 0},
            "replay_suppressed": 0,
            "consecutive_decrypt_failures": 0
        });

        assert!(compute_peer_rating(&peer).is_none());
    }

    #[test]
    fn rating_fact_event_is_signed_and_parseable() {
        let node = build_test_node();
        let rating = PeerRatingRecord {
            id: Uuid::new_v4().to_string(),
            rater: node.npub(),
            subject: "npub1peer".to_string(),
            scope: "fips.peer".to_string(),
            rating: 80,
            min_rating: 0,
            max_rating: 100,
            sample_count: 3,
            window_end: 1234,
            reason: "healthy".to_string(),
            tags: vec!["fips".to_string(), "peer".to_string()],
            created_at: 1234,
        };

        let event = rating
            .to_fact_event(&nostr_keys_for_node(&node).unwrap())
            .unwrap();

        event.verify().unwrap();
        assert_eq!(event.kind, Kind::from(FACT_OP_KIND));
        let value = serde_json::to_value(&event).unwrap();
        let tags = value["tags"].as_array().unwrap();
        assert!(tags.iter().any(|tag| tag == &json!(["type", "rating"])));
        assert!(tags.iter().any(|tag| tag == &json!(["scope", "fips.peer"])));
        assert!(
            tags.iter()
                .any(|tag| tag == &json!(["subject", "npub1peer"]))
        );
    }

    #[test]
    fn query_params_accept_scope_and_event_format() {
        let params = json!({"scope": "fips.peer", "format": "events"});

        let query = PeerRatingQuery::parse(Some(&params)).unwrap();

        assert_eq!(query.scope, "fips.peer");
        assert_eq!(query.format, PeerRatingExportFormat::Events);
    }
}
