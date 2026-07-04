use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const DEFAULT_SCOPE: &str = "fips.peer";
const LOCAL_RATER: &str = "fips-sim:local";
const RATING_FACT_KIND: u16 = 7368;

/// Configuration for the deterministic open-discovery WoT admission scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotAdmissionSimConfig {
    /// Maximum peer adverts the admission pass can enqueue.
    pub max_pending: usize,
    /// Capacity reserved for unknown peers so newcomers can earn trust.
    pub newcomer_probe_slots: usize,
    /// Rating fact scope accepted by the simulated FIPS open-discovery policy.
    pub rating_scope: String,
    /// Maximum historic rating events returned by each simulated index lookup.
    pub history_lookup_limit: usize,
}

impl Default for WotAdmissionSimConfig {
    fn default() -> Self {
        Self {
            max_pending: 3,
            newcomer_probe_slots: 1,
            rating_scope: DEFAULT_SCOPE.to_string(),
            history_lookup_limit: 64,
        }
    }
}

/// Peer shape used by the default WoT admission simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WotPeerProfile {
    Reliable,
    BackupReliable,
    Newcomer,
    Degrading,
    Bad,
}

/// Advertised peer in the WoT admission simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotPeerSpec {
    pub id: String,
    pub profile: WotPeerProfile,
    pub advertised_at: u64,
}

/// Source of a rating fact event in the simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WotRatingEventSource {
    HistoricIndex,
    LocalProbe,
    LocalDegradation,
}

/// Fact-like rating event shared by pubsub and historic lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotRatingFactEvent {
    pub id: String,
    pub kind: u16,
    pub rater: String,
    pub subject: String,
    pub scope: String,
    pub rating: i64,
    pub min_rating: i64,
    pub max_rating: i64,
    pub created_at: u64,
    pub source: WotRatingEventSource,
}

impl WotRatingFactEvent {
    pub fn new(
        id: impl Into<String>,
        rater: impl Into<String>,
        subject: impl Into<String>,
        scope: impl Into<String>,
        rating: i64,
        created_at: u64,
        source: WotRatingEventSource,
    ) -> Self {
        Self {
            id: id.into(),
            kind: RATING_FACT_KIND,
            rater: rater.into(),
            subject: subject.into(),
            scope: scope.into(),
            rating,
            min_rating: 0,
            max_rating: 100,
            created_at,
            source,
        }
    }

    /// Nostr fact-event tags used by the real FIPS rating importer.
    pub fn nostr_fact_tags(&self) -> Vec<Vec<String>> {
        vec![
            vec!["i".to_string(), self.scope.to_lowercase()],
            vec!["type".to_string(), "rating".to_string()],
            vec!["schema".to_string(), "1".to_string()],
            vec!["created_at".to_string(), self.created_at.to_string()],
            vec!["rater".to_string(), self.rater.clone()],
            vec!["subject".to_string(), self.subject.clone()],
            vec!["scope".to_string(), self.scope.clone()],
            vec!["rating".to_string(), self.rating.to_string()],
            vec!["min_rating".to_string(), self.min_rating.to_string()],
            vec!["max_rating".to_string(), self.max_rating.to_string()],
        ]
    }

    pub fn indexed_i_values(&self) -> Vec<String> {
        self.nostr_fact_tags()
            .into_iter()
            .filter_map(|tag| {
                if tag.first().is_some_and(|key| key == "i") {
                    tag.get(1).cloned()
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn normalized_score(&self) -> Option<i64> {
        normalize_rating_score(self.rating, self.min_rating, self.max_rating)
    }
}

/// Normal Nostr filter shape used for historic rating lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotNostrFilter {
    pub kinds: Vec<u16>,
    #[serde(rename = "#i")]
    pub i_tags: Vec<String>,
    pub limit: usize,
}

impl WotNostrFilter {
    pub fn rating_scope(scope: &str, limit: usize) -> Self {
        Self {
            kinds: vec![RATING_FACT_KIND],
            i_tags: vec![scope.trim().to_lowercase()],
            limit,
        }
    }
}

/// Counters for the simulated rating exchange.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotRatingExchangeStats {
    pub historic_seed_events: usize,
    pub local_published_events: usize,
    pub indexed_events: usize,
    pub history_queries: usize,
    pub history_events_returned: usize,
}

/// Reason a peer was admitted or deferred in a phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WotAdmissionReason {
    TrustedRating,
    NewcomerProbe,
    DeferredTrustedCapacity,
    DeferredNewcomerCapacity,
    DeferredNegative,
    LastResortNegative,
}

/// Per-peer decision in one admission phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotPeerAdmissionDecision {
    pub peer_id: String,
    pub profile: WotPeerProfile,
    pub trust_score: Option<i64>,
    pub selected: bool,
    pub admission_order: Option<usize>,
    pub reason: WotAdmissionReason,
}

/// One admission phase of the scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotAdmissionPhaseReport {
    pub label: String,
    pub history_filter: WotNostrFilter,
    pub selected_peers: Vec<String>,
    pub decisions: Vec<WotPeerAdmissionDecision>,
    pub rating_events_seen: usize,
}

/// Whole deterministic WoT admission report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotAdmissionSimReport {
    pub config: WotAdmissionSimConfig,
    pub peers: Vec<WotPeerSpec>,
    pub phases: Vec<WotAdmissionPhaseReport>,
    pub rating_events: Vec<WotRatingFactEvent>,
    pub exchange: WotRatingExchangeStats,
}

/// Run the default deterministic WoT admission scenario.
pub fn run_default_wot_admission_sim() -> WotAdmissionSimReport {
    WotAdmissionSimulation::new(WotAdmissionSimConfig::default()).run()
}

/// Deterministic control-plane simulation for open-discovery trust admission.
pub struct WotAdmissionSimulation {
    config: WotAdmissionSimConfig,
    peers: Vec<WotPeerSpec>,
    exchange: WotRatingExchange,
}

impl WotAdmissionSimulation {
    pub fn new(config: WotAdmissionSimConfig) -> Self {
        let peers = default_peers();
        let mut exchange = WotRatingExchange::default();
        seed_historic_ratings(&config, &mut exchange);
        Self {
            config,
            peers,
            exchange,
        }
    }

    pub fn run(mut self) -> WotAdmissionSimReport {
        let cold_start = self.admission_phase("cold_start");
        self.publish_local_probe_rating("fips-sim:newcomer", 85, 200);
        let after_newcomer_probe = self.admission_phase("after_newcomer_probe");
        self.publish_degradation_rating("fips-sim:degrading", 0, 300);
        let after_degradation = self.admission_phase("after_degradation");

        WotAdmissionSimReport {
            config: self.config,
            peers: self.peers,
            phases: vec![cold_start, after_newcomer_probe, after_degradation],
            rating_events: self.exchange.events,
            exchange: self.exchange.stats,
        }
    }

    fn admission_phase(&mut self, label: impl Into<String>) -> WotAdmissionPhaseReport {
        let history_filter = WotNostrFilter::rating_scope(
            &self.config.rating_scope,
            self.config.history_lookup_limit,
        );
        let events = self.exchange.query_events(&history_filter);
        let trust_scores = latest_trust_scores(&events);
        let decisions = order_admission_decisions(
            &self.peers,
            &trust_scores,
            self.config.max_pending,
            self.config.newcomer_probe_slots,
        );
        let selected_peers = decisions
            .iter()
            .filter(|decision| decision.selected)
            .map(|decision| decision.peer_id.clone())
            .collect();

        WotAdmissionPhaseReport {
            label: label.into(),
            history_filter,
            selected_peers,
            decisions,
            rating_events_seen: events.len(),
        }
    }

    fn publish_local_probe_rating(&mut self, subject: &str, rating: i64, created_at: u64) {
        self.exchange.publish_local(WotRatingFactEvent::new(
            "fips-sim-rating-newcomer-probe",
            LOCAL_RATER,
            subject,
            self.config.rating_scope.clone(),
            rating,
            created_at,
            WotRatingEventSource::LocalProbe,
        ));
    }

    fn publish_degradation_rating(&mut self, subject: &str, rating: i64, created_at: u64) {
        self.exchange.publish_local(WotRatingFactEvent::new(
            "fips-sim-rating-degradation",
            LOCAL_RATER,
            subject,
            self.config.rating_scope.clone(),
            rating,
            created_at,
            WotRatingEventSource::LocalDegradation,
        ));
    }
}

#[derive(Debug, Clone, Default)]
struct WotRatingExchange {
    events: Vec<WotRatingFactEvent>,
    stats: WotRatingExchangeStats,
}

impl WotRatingExchange {
    fn seed_historic(&mut self, event: WotRatingFactEvent) {
        self.stats.historic_seed_events += 1;
        self.index(event);
    }

    fn publish_local(&mut self, event: WotRatingFactEvent) {
        self.stats.local_published_events += 1;
        self.index(event);
    }

    fn index(&mut self, event: WotRatingFactEvent) {
        self.stats.indexed_events += 1;
        self.events.push(event);
    }

    fn query_events(&mut self, filter: &WotNostrFilter) -> Vec<WotRatingFactEvent> {
        self.stats.history_queries += 1;
        let mut events = self
            .events
            .iter()
            .filter(|event| matches_nostr_filter(event, filter))
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        events.truncate(filter.limit);
        self.stats.history_events_returned += events.len();
        events
    }
}

fn matches_nostr_filter(event: &WotRatingFactEvent, filter: &WotNostrFilter) -> bool {
    if !filter.kinds.is_empty() && !filter.kinds.contains(&event.kind) {
        return false;
    }
    if filter.i_tags.is_empty() {
        return true;
    }
    let indexed = event.indexed_i_values();
    filter
        .i_tags
        .iter()
        .any(|wanted| indexed.iter().any(|value| value == wanted))
}

fn default_peers() -> Vec<WotPeerSpec> {
    vec![
        peer("fips-sim:good", WotPeerProfile::Reliable, 120),
        peer("fips-sim:backup", WotPeerProfile::BackupReliable, 110),
        peer("fips-sim:newcomer", WotPeerProfile::Newcomer, 140),
        peer("fips-sim:degrading", WotPeerProfile::Degrading, 130),
        peer("fips-sim:bad", WotPeerProfile::Bad, 150),
    ]
}

fn peer(id: &str, profile: WotPeerProfile, advertised_at: u64) -> WotPeerSpec {
    WotPeerSpec {
        id: id.to_string(),
        profile,
        advertised_at,
    }
}

fn seed_historic_ratings(config: &WotAdmissionSimConfig, exchange: &mut WotRatingExchange) {
    for (id, subject, rating, created_at) in [
        ("fips-sim-rating-good", "fips-sim:good", 90, 100),
        ("fips-sim-rating-backup", "fips-sim:backup", 70, 100),
        (
            "fips-sim-rating-degrading-good",
            "fips-sim:degrading",
            95,
            100,
        ),
        ("fips-sim-rating-bad", "fips-sim:bad", 0, 100),
    ] {
        exchange.seed_historic(WotRatingFactEvent::new(
            id,
            "fips-sim:historic-crawler",
            subject,
            config.rating_scope.clone(),
            rating,
            created_at,
            WotRatingEventSource::HistoricIndex,
        ));
    }
}

fn latest_trust_scores(events: &[WotRatingFactEvent]) -> BTreeMap<String, i64> {
    let mut latest = BTreeMap::<String, (u64, i64)>::new();
    for event in events {
        let Some(score) = event.normalized_score() else {
            continue;
        };
        let entry = latest
            .entry(event.subject.clone())
            .or_insert((event.created_at, score));
        if event.created_at >= entry.0 {
            *entry = (event.created_at, score);
        }
    }
    latest
        .into_iter()
        .map(|(subject, (_, score))| (subject, score))
        .collect()
}

fn order_admission_decisions(
    peers: &[WotPeerSpec],
    trust_scores: &BTreeMap<String, i64>,
    max_pending: usize,
    newcomer_probe_slots: usize,
) -> Vec<WotPeerAdmissionDecision> {
    let mut positive = Vec::new();
    let mut unknown = Vec::new();
    let mut negative = Vec::new();

    for peer in peers {
        match trust_scores.get(&peer.id).copied() {
            Some(score) if score > 0 => positive.push((score, peer)),
            Some(score) if score < 0 => negative.push((score, peer)),
            _ => unknown.push(peer),
        }
    }

    positive.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| right.advertised_at.cmp(&left.advertised_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    unknown.sort_by(|left, right| {
        right
            .advertised_at
            .cmp(&left.advertised_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    negative.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| right.advertised_at.cmp(&left.advertised_at))
            .then_with(|| left.id.cmp(&right.id))
    });

    let reserved_newcomers = newcomer_probe_slots.min(max_pending).min(unknown.len());
    let trusted_slots = max_pending.saturating_sub(reserved_newcomers);
    let mut ordered = Vec::new();

    for (_, peer) in positive.iter().take(trusted_slots) {
        ordered.push(*peer);
    }
    for peer in unknown.iter().take(reserved_newcomers) {
        ordered.push(*peer);
    }
    for (_, peer) in positive.iter().skip(trusted_slots) {
        ordered.push(*peer);
    }
    for peer in unknown.iter().skip(reserved_newcomers) {
        ordered.push(*peer);
    }
    for (_, peer) in &negative {
        ordered.push(*peer);
    }

    ordered
        .into_iter()
        .enumerate()
        .map(|(index, peer)| {
            let trust_score = trust_scores.get(&peer.id).copied();
            let selected = index < max_pending;
            let reason = admission_reason(trust_score, selected);
            WotPeerAdmissionDecision {
                peer_id: peer.id.clone(),
                profile: peer.profile,
                trust_score,
                selected,
                admission_order: selected.then_some(index),
                reason,
            }
        })
        .collect()
}

fn admission_reason(trust_score: Option<i64>, selected: bool) -> WotAdmissionReason {
    match (selected, trust_score) {
        (true, Some(score)) if score > 0 => WotAdmissionReason::TrustedRating,
        (true, Some(score)) if score < 0 => WotAdmissionReason::LastResortNegative,
        (true, _) => WotAdmissionReason::NewcomerProbe,
        (false, Some(score)) if score > 0 => WotAdmissionReason::DeferredTrustedCapacity,
        (false, Some(score)) if score < 0 => WotAdmissionReason::DeferredNegative,
        (false, _) => WotAdmissionReason::DeferredNewcomerCapacity,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wot_admission_prioritizes_good_probes_newcomer_and_penalizes_degraded() {
        let report = run_default_wot_admission_sim();
        let cold_start = phase(&report, "cold_start");
        assert_eq!(
            cold_start.selected_peers,
            vec!["fips-sim:degrading", "fips-sim:good", "fips-sim:newcomer"]
        );
        assert_decision(
            cold_start,
            "fips-sim:newcomer",
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
        );
        assert_decision(
            cold_start,
            "fips-sim:bad",
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );

        let after_probe = phase(&report, "after_newcomer_probe");
        assert_decision(
            after_probe,
            "fips-sim:newcomer",
            true,
            Some(70),
            WotAdmissionReason::TrustedRating,
        );
        assert_decision(
            after_probe,
            "fips-sim:bad",
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );

        let after_degradation = phase(&report, "after_degradation");
        assert_eq!(
            after_degradation.selected_peers,
            vec!["fips-sim:good", "fips-sim:newcomer", "fips-sim:backup"]
        );
        assert_decision(
            after_degradation,
            "fips-sim:degrading",
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );
        assert_decision(
            after_degradation,
            "fips-sim:backup",
            true,
            Some(40),
            WotAdmissionReason::TrustedRating,
        );

        assert_eq!(report.exchange.historic_seed_events, 4);
        assert_eq!(report.exchange.local_published_events, 2);
        assert_eq!(report.exchange.indexed_events, 6);
        assert_eq!(report.exchange.history_queries, 3);
        assert_eq!(report.rating_events.len(), 6);
    }

    #[test]
    fn rating_fact_tags_use_scope_for_pubsub_and_history_lookup() {
        let event = WotRatingFactEvent::new(
            "rating-1",
            "fips-sim:rater",
            "fips-sim:subject",
            "fips.peer",
            80,
            42,
            WotRatingEventSource::LocalProbe,
        );
        let tags = event.nostr_fact_tags();

        assert!(tags.contains(&tag("i", "fips.peer")));
        assert!(tags.contains(&tag("scope", "fips.peer")));
        assert!(tags.contains(&tag("type", "rating")));
        assert!(
            !tags
                .iter()
                .any(|tag| tag.first().is_some_and(|key| key == "context"))
        );

        let filter = WotNostrFilter::rating_scope("fips.peer", 64);
        assert_eq!(filter.kinds, vec![RATING_FACT_KIND]);
        assert_eq!(filter.i_tags, vec!["fips.peer"]);
        assert_eq!(
            serde_json::to_value(&filter).unwrap(),
            serde_json::json!({
                "kinds": [7368],
                "#i": ["fips.peer"],
                "limit": 64,
            })
        );
    }

    #[test]
    fn history_lookup_uses_normal_nostr_filter_kind_and_i_tag() {
        let mut exchange = WotRatingExchange::default();
        exchange.seed_historic(WotRatingFactEvent::new(
            "rating-good",
            "fips-sim:rater",
            "fips-sim:good",
            "fips.peer",
            90,
            100,
            WotRatingEventSource::HistoricIndex,
        ));
        exchange.seed_historic(WotRatingFactEvent::new(
            "rating-other-scope",
            "fips-sim:rater",
            "fips-sim:other-scope",
            "other.scope",
            90,
            101,
            WotRatingEventSource::HistoricIndex,
        ));
        let mut wrong_kind = WotRatingFactEvent::new(
            "rating-wrong-kind",
            "fips-sim:rater",
            "fips-sim:wrong-kind",
            "fips.peer",
            90,
            102,
            WotRatingEventSource::HistoricIndex,
        );
        wrong_kind.kind = 1;
        exchange.seed_historic(wrong_kind);

        let events = exchange.query_events(&WotNostrFilter::rating_scope("fips.peer", 64));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "rating-good");
    }

    fn phase<'a>(report: &'a WotAdmissionSimReport, label: &str) -> &'a WotAdmissionPhaseReport {
        report
            .phases
            .iter()
            .find(|phase| phase.label == label)
            .expect("phase exists")
    }

    fn assert_decision(
        phase: &WotAdmissionPhaseReport,
        peer_id: &str,
        selected: bool,
        trust_score: Option<i64>,
        reason: WotAdmissionReason,
    ) {
        let decision = phase
            .decisions
            .iter()
            .find(|decision| decision.peer_id == peer_id)
            .expect("peer decision exists");
        assert_eq!(decision.selected, selected);
        assert_eq!(decision.trust_score, trust_score);
        assert_eq!(decision.reason, reason);
    }

    fn tag(key: &str, value: &str) -> Vec<String> {
        vec![key.to_string(), value.to_string()]
    }
}
