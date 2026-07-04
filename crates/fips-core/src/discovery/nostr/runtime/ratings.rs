use super::*;

pub(in crate::discovery::nostr) const RATING_FACT_KIND: u16 = 7368;

const RATING_FACT_TYPE: &str = "rating";
const RATING_FACT_SCHEMA: &str = "1";
const RATING_FACT_LOOKUP_LIMIT: usize = 500;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RatingFactFileLoadReport {
    pub(crate) files: usize,
    pub(crate) events: usize,
    pub(crate) accepted: usize,
}

impl NostrDiscovery {
    pub(super) fn should_subscribe_rating_facts(&self) -> bool {
        self.config.open_discovery_trust_ratings_enabled
    }

    pub(crate) async fn load_rating_fact_events_from_files(&self) -> RatingFactFileLoadReport {
        let mut report = RatingFactFileLoadReport::default();
        if !self.config.open_discovery_trust_ratings_enabled {
            return report;
        }

        for path in &self.config.open_discovery_rating_event_files {
            report.files += 1;
            let bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    warn!(
                        path = %path.display(),
                        error = %error,
                        "failed to read local Nostr rating fact event file"
                    );
                    continue;
                }
            };
            let value: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    warn!(
                        path = %path.display(),
                        error = %error,
                        "failed to parse local Nostr rating fact event file"
                    );
                    continue;
                }
            };
            let events = match rating_fact_events_from_json(&value) {
                Ok(events) => events,
                Err(error) => {
                    warn!(
                        path = %path.display(),
                        error = %error,
                        "local Nostr rating fact event file has unsupported shape"
                    );
                    continue;
                }
            };

            for event in events {
                report.events += 1;
                if self.process_rating_fact_event(&event).await {
                    report.accepted += 1;
                }
            }
        }

        if report.files > 0 {
            info!(
                files = report.files,
                events = report.events,
                accepted = report.accepted,
                "loaded local Nostr rating fact events"
            );
        }
        report
    }

    pub(super) fn rating_fact_filter(&self) -> Filter {
        let mut filter = Filter::new()
            .kind(Kind::Custom(RATING_FACT_KIND))
            .limit(RATING_FACT_LOOKUP_LIMIT);
        let scope = self.config.open_discovery_rating_scope.trim();
        if !scope.is_empty() {
            filter = filter.custom_tag(
                SingleLetterTag::lowercase(Alphabet::I),
                scope.to_lowercase(),
            );
        }
        let lookback_secs = self.config.open_discovery_rating_lookback_secs;
        if lookback_secs > 0 {
            let since = now_ms().saturating_div(1_000).saturating_sub(lookback_secs);
            filter = filter.since(Timestamp::from(since));
        }
        filter
    }

    pub(crate) async fn process_rating_fact_event(&self, event: &Event) -> bool {
        if !self.config.open_discovery_trust_ratings_enabled
            || event.kind != Kind::Custom(RATING_FACT_KIND)
        {
            return false;
        }

        let Ok(verified_event) = VerifiedEvent::try_from(event) else {
            return false;
        };
        if !self.rating_fact_author_is_trusted(verified_event.pubkey()) {
            return false;
        }

        let Some(record) = self.rating_record_from_event(verified_event.as_event()) else {
            return false;
        };
        self.record_peer_trust_score(&record.subject, record.score, record.created_at)
            .await
            .is_ok()
    }

    fn rating_fact_author_is_trusted(&self, author: &PublicKey) -> bool {
        let author_key = NostrPeerKey::from_public_key_ref(author);
        if author_key == self.self_peer_key() {
            return true;
        }
        self.config
            .open_discovery_trusted_rating_authors
            .iter()
            .filter_map(|author| NostrPeerKey::parse(author).ok())
            .any(|trusted| trusted == author_key)
    }

    fn rating_record_from_event(&self, event: &Event) -> Option<RatingFactRecord> {
        let value = serde_json::to_value(event).ok()?;
        if rating_fact_scalar(&value, "type").as_deref() != Some(RATING_FACT_TYPE) {
            return None;
        }
        if rating_fact_scalar(&value, "schema").as_deref() != Some(RATING_FACT_SCHEMA) {
            return None;
        }
        let expected_scope = self.config.open_discovery_rating_scope.trim();
        if expected_scope.is_empty()
            || rating_fact_scalar(&value, "scope")
                .as_deref()
                .is_none_or(|scope| scope.trim() != expected_scope)
        {
            return None;
        }

        let subject = rating_fact_scalar(&value, "subject")?;
        let rating = rating_fact_scalar(&value, "rating")?.parse::<i64>().ok()?;
        let min_rating = rating_fact_scalar(&value, "min_rating")?
            .parse::<i64>()
            .ok()?;
        let max_rating = rating_fact_scalar(&value, "max_rating")?
            .parse::<i64>()
            .ok()?;
        let score = normalize_rating_score(rating, min_rating, max_rating)?;
        let created_at = rating_fact_scalar(&value, "created_at")
            .and_then(|created_at| created_at.parse::<u64>().ok())
            .or_else(|| value.get("created_at").and_then(serde_json::Value::as_u64))
            .unwrap_or_else(|| event.created_at.as_secs());
        Some(RatingFactRecord {
            subject,
            score,
            created_at,
        })
    }
}

struct RatingFactRecord {
    subject: String,
    score: i64,
    created_at: u64,
}

fn normalize_rating_score(rating: i64, min_rating: i64, max_rating: i64) -> Option<i64> {
    if min_rating >= max_rating || rating < min_rating || rating > max_rating {
        return None;
    }
    let rating = i128::from(rating);
    let min = i128::from(min_rating);
    let max = i128::from(max_rating);
    let centered = rating.saturating_mul(2) - min - max;
    Some(((centered.saturating_mul(100)) / (max - min)) as i64)
}

fn rating_fact_scalar(event_value: &serde_json::Value, key: &str) -> Option<String> {
    rating_fact_values(event_value, key).into_iter().next()
}

fn rating_fact_values(event_value: &serde_json::Value, key: &str) -> Vec<String> {
    event_value
        .get("tags")
        .and_then(|tags| tags.as_array())
        .into_iter()
        .flatten()
        .filter_map(|tag| {
            let parts = tag.as_array()?;
            if parts.first().and_then(|value| value.as_str()) != Some(key) {
                return None;
            }
            parts.get(1).and_then(|value| value.as_str()).map(str::trim)
        })
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn rating_fact_events_from_json(value: &serde_json::Value) -> Result<Vec<Event>, String> {
    let events = if let Some(events) = value.get("events").and_then(serde_json::Value::as_array) {
        events
    } else if let Some(data) = value.get("data") {
        data.get("events")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "expected an events array".to_string())?
    } else {
        value
            .as_array()
            .ok_or_else(|| "expected an event array or object with events array".to_string())?
    };

    events
        .iter()
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| format!("failed to decode Nostr event: {error}"))
        })
        .collect()
}
