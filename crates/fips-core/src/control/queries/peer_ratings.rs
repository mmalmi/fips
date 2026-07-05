use nostr::prelude::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::node::Node;
use crate::peer_rating::compute_peer_rating;

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

fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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
    use nostr::ToBech32;

    const TEST_SEED: [u8; 32] = [0xAB; 32];

    fn build_test_node() -> Node {
        let identity =
            Identity::from_secret_bytes(&TEST_SEED).expect("test seed is a valid secret key");
        Node::with_identity(identity, Config::new()).expect("default config is valid")
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

    #[tokio::test]
    async fn machine_rating_fact_event_updates_discovery_trust_and_downgrades() {
        let node = build_test_node();
        let subject = nostr::Keys::generate()
            .public_key()
            .to_bech32()
            .expect("subject npub");
        let discovery = crate::discovery::nostr::NostrDiscovery::new_for_test_with_config(
            crate::config::NostrDiscoveryConfig {
                open_discovery_trust_ratings_enabled: true,
                open_discovery_trusted_rating_authors: vec![node.npub()],
                ..Default::default()
            },
        );
        let healthy_peer = json!({
            "npub": subject,
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
        let degraded_peer = json!({
            "npub": subject,
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
        let keys = nostr_keys_for_node(&node).expect("node nostr keys");
        let healthy = peer_rating_record(&node.npub(), &healthy_peer, "fips.peer", 1_000)
            .expect("healthy machine rating")
            .to_fact_event(&keys)
            .expect("healthy rating event");
        let degraded = peer_rating_record(&node.npub(), &degraded_peer, "fips.peer", 1_001)
            .expect("degraded machine rating")
            .to_fact_event(&keys)
            .expect("degraded rating event");

        healthy.verify().expect("healthy event verifies");
        assert!(discovery.process_rating_fact_event(&healthy).await);
        let scores = discovery
            .trust_scores_for_npubs(std::slice::from_ref(&subject))
            .await;
        assert_eq!(scores.get(&subject), Some(&100));

        degraded.verify().expect("degraded event verifies");
        assert!(discovery.process_rating_fact_event(&degraded).await);
        let scores = discovery
            .trust_scores_for_npubs(std::slice::from_ref(&subject))
            .await;
        assert_eq!(scores.get(&subject), Some(&-100));
    }

    #[test]
    fn query_params_accept_scope_and_event_format() {
        let params = json!({"scope": "fips.peer", "format": "events"});

        let query = PeerRatingQuery::parse(Some(&params)).unwrap();

        assert_eq!(query.scope, "fips.peer");
        assert_eq!(query.format, PeerRatingExportFormat::Events);
    }
}
