use fips_core::config::NostrDiscoveryConfig;
use fips_core::discovery::nostr::NostrDiscovery;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{
    Alphabet, Event, EventBuilder, Filter, Kind, SingleLetterTag, Tag, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const DEFAULT_SCOPE: &str = "fips.peer";
const RATING_FACT_KIND: u16 = 7368;
const TRUSTED_RATING_SIGNER_SEED: u64 = 1;
const LOCAL_RATER_SEED: u64 = 2;
const HISTORIC_RATER_SEED: u64 = 3;

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
    /// Event signer identities trusted to publish rating facts.
    pub trusted_rating_authors: Vec<String>,
    /// Decentralized pubsub fanout used when local machine ratings are published.
    pub rating_pubsub: WotRatingPubsubConfig,
}

impl Default for WotAdmissionSimConfig {
    fn default() -> Self {
        Self {
            max_pending: 3,
            newcomer_probe_slots: 1,
            rating_scope: DEFAULT_SCOPE.to_string(),
            history_lookup_limit: 64,
            trusted_rating_authors: vec![trusted_rating_signer_npub()],
            rating_pubsub: WotRatingPubsubConfig::default(),
        }
    }
}

/// Small inv/want-style accounting model for local rating fact publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotRatingPubsubConfig {
    /// Nodes that hear inventory for each locally published rating fact.
    pub peer_count: usize,
    /// Interested peers that send wants and receive the full event payload.
    pub subscriber_count: usize,
    /// Untrusted rating spam seen alongside each trusted local rating publish.
    pub spam_events_per_publish: usize,
    /// Approximate bytes for one inventory notice.
    pub inventory_bytes: usize,
    /// Approximate bytes for one want request.
    pub want_bytes: usize,
    /// Approximate bytes for one signed rating fact event payload.
    pub payload_bytes: usize,
}

impl Default for WotRatingPubsubConfig {
    fn default() -> Self {
        Self {
            peer_count: 8,
            subscriber_count: 4,
            spam_events_per_publish: 8,
            inventory_bytes: 96,
            want_bytes: 64,
            payload_bytes: 512,
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
    UntrustedSpam,
}

/// Real signed Nostr rating event plus simulation-only provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotRatingFactEvent {
    pub source: WotRatingEventSource,
    pub event: Event,
}

impl WotRatingFactEvent {
    pub fn signed_by(
        keys: &nostr::Keys,
        rater: &str,
        subject: &str,
        scope: &str,
        rating: i64,
        created_at: u64,
        source: WotRatingEventSource,
    ) -> Self {
        signed_rating_fact_event(
            keys,
            rater,
            subject,
            scope,
            rating,
            created_at,
            source,
            Kind::Custom(RATING_FACT_KIND),
        )
    }

    pub fn id(&self) -> String {
        self.event.id.to_hex()
    }

    pub fn kind(&self) -> u16 {
        self.event.kind.as_u16()
    }

    pub fn signer(&self) -> String {
        self.event.pubkey.to_bech32().expect("sim signer npub")
    }

    /// Nostr fact-event tags consumed by the real FIPS rating importer.
    pub fn nostr_fact_tags(&self) -> Vec<Vec<String>> {
        event_tag_rows(&self.event)
    }

    pub fn indexed_i_values(&self) -> Vec<String> {
        event_tag_values(&self.event, "i")
    }

    pub fn rater(&self) -> Option<String> {
        event_tag_value(&self.event, "rater")
    }

    pub fn subject(&self) -> Option<String> {
        event_tag_value(&self.event, "subject")
    }

    pub fn scope(&self) -> Option<String> {
        event_tag_value(&self.event, "scope")
    }

    pub fn created_at(&self) -> u64 {
        event_tag_value(&self.event, "created_at")
            .and_then(|created_at| created_at.parse::<u64>().ok())
            .unwrap_or_else(|| self.event.created_at.as_secs())
    }

    pub fn normalized_score(&self) -> Option<i64> {
        let rating = event_tag_value(&self.event, "rating")?
            .parse::<i64>()
            .ok()?;
        let min_rating = event_tag_value(&self.event, "min_rating")?
            .parse::<i64>()
            .ok()?;
        let max_rating = event_tag_value(&self.event, "max_rating")?
            .parse::<i64>()
            .ok()?;
        normalize_rating_score(rating, min_rating, max_rating)
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

    pub fn to_nostr_filter(&self) -> Filter {
        let mut filter = Filter::new().limit(self.limit);
        for kind in &self.kinds {
            filter = filter.kind(Kind::Custom(*kind));
        }
        for i_tag in &self.i_tags {
            filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::I), i_tag.clone());
        }
        filter
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
    pub pubsub_published_events: usize,
    pub pubsub_inventory_messages: usize,
    pub pubsub_want_messages: usize,
    pub pubsub_delivered_events: usize,
    pub pubsub_inv_want_bytes: usize,
    pub pubsub_flood_bytes: usize,
    pub pubsub_spam_events_seen: usize,
    pub pubsub_spam_events_dropped: usize,
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
    pub trusted_rating_author_count: usize,
    pub rating_events: Vec<WotRatingFactEvent>,
    pub exchange: WotRatingExchangeStats,
}

/// Run the default deterministic WoT admission scenario.
pub async fn run_default_wot_admission_sim() -> WotAdmissionSimReport {
    WotAdmissionSimulation::new(WotAdmissionSimConfig::default())
        .run()
        .await
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
        let exchange = WotRatingExchange::new(&config);
        Self {
            config,
            peers,
            exchange,
        }
    }

    pub async fn run(mut self) -> WotAdmissionSimReport {
        seed_historic_ratings(&self.config, &mut self.exchange).await;

        let cold_start = self.admission_phase("cold_start").await;
        let newcomer = self.peer_id(WotPeerProfile::Newcomer);
        self.publish_local_probe_rating(&newcomer, 85, 200).await;
        let after_newcomer_probe = self.admission_phase("after_newcomer_probe").await;
        let degrading = self.peer_id(WotPeerProfile::Degrading);
        self.publish_degradation_rating(&degrading, 0, 300).await;
        let after_degradation = self.admission_phase("after_degradation").await;

        WotAdmissionSimReport {
            config: self.config,
            peers: self.peers,
            phases: vec![cold_start, after_newcomer_probe, after_degradation],
            trusted_rating_author_count: self.exchange.trusted_rating_author_count(),
            rating_events: self.exchange.events,
            exchange: self.exchange.stats,
        }
    }

    async fn admission_phase(&mut self, label: impl Into<String>) -> WotAdmissionPhaseReport {
        let history_filter = WotNostrFilter::rating_scope(
            &self.config.rating_scope,
            self.config.history_lookup_limit,
        );
        let events = self.exchange.query_events(&history_filter);
        self.exchange.import_history_results(&events).await;
        let trust_scores = self.exchange.trust_scores_for_peers(&self.peers).await;
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

    async fn publish_local_probe_rating(&mut self, subject: &str, rating: i64, created_at: u64) {
        self.exchange
            .publish_local(
                &self.config.rating_pubsub,
                WotRatingFactEvent::signed_by(
                    &trusted_rating_signer_keys(),
                    &local_rater_npub(),
                    subject,
                    &self.config.rating_scope,
                    rating,
                    created_at,
                    WotRatingEventSource::LocalProbe,
                ),
            )
            .await;
    }

    async fn publish_degradation_rating(&mut self, subject: &str, rating: i64, created_at: u64) {
        self.exchange
            .publish_local(
                &self.config.rating_pubsub,
                WotRatingFactEvent::signed_by(
                    &trusted_rating_signer_keys(),
                    &local_rater_npub(),
                    subject,
                    &self.config.rating_scope,
                    rating,
                    created_at,
                    WotRatingEventSource::LocalDegradation,
                ),
            )
            .await;
    }

    fn peer_id(&self, profile: WotPeerProfile) -> String {
        self.peers
            .iter()
            .find(|peer| peer.profile == profile)
            .map(|peer| peer.id.clone())
            .expect("default peer exists")
    }
}

struct WotRatingExchange {
    events: Vec<WotRatingFactEvent>,
    stats: WotRatingExchangeStats,
    discovery: NostrDiscovery,
}

impl Default for WotRatingExchange {
    fn default() -> Self {
        Self::new(&WotAdmissionSimConfig::default())
    }
}

impl WotRatingExchange {
    fn new(config: &WotAdmissionSimConfig) -> Self {
        let discovery = NostrDiscovery::new_for_sim_with_config(NostrDiscoveryConfig {
            open_discovery_trust_ratings_enabled: true,
            open_discovery_trusted_rating_authors: config.trusted_rating_authors.clone(),
            open_discovery_rating_scope: config.rating_scope.clone(),
            ..Default::default()
        });
        Self {
            events: Vec::new(),
            stats: WotRatingExchangeStats::default(),
            discovery,
        }
    }

    fn trusted_rating_author_count(&self) -> usize {
        self.discovery.trusted_rating_author_count()
    }

    async fn seed_historic(&mut self, event: WotRatingFactEvent) {
        self.stats.historic_seed_events += 1;
        self.ingest(event).await;
    }

    async fn publish_local(&mut self, pubsub: &WotRatingPubsubConfig, event: WotRatingFactEvent) {
        self.stats.local_published_events += 1;
        self.publish_over_pubsub(pubsub);
        let scope = event.scope().unwrap_or_else(|| DEFAULT_SCOPE.to_string());
        self.ingest(event).await;
        self.drop_untrusted_spam(&scope, pubsub.spam_events_per_publish)
            .await;
    }

    async fn ingest(&mut self, event: WotRatingFactEvent) -> bool {
        if self
            .discovery
            .process_rating_fact_event_for_sim(&event.event)
            .await
        {
            self.stats.indexed_events += 1;
            self.events.push(event);
            return true;
        }

        self.stats.pubsub_spam_events_seen = self.stats.pubsub_spam_events_seen.saturating_add(1);
        self.stats.pubsub_spam_events_dropped =
            self.stats.pubsub_spam_events_dropped.saturating_add(1);
        false
    }

    async fn import_history_results(&self, events: &[WotRatingFactEvent]) {
        for event in events {
            let _ = self
                .discovery
                .process_rating_fact_event_for_sim(&event.event)
                .await;
        }
    }

    async fn trust_scores_for_peers(&self, peers: &[WotPeerSpec]) -> BTreeMap<String, i64> {
        let npubs = peers.iter().map(|peer| peer.id.clone()).collect::<Vec<_>>();
        self.trust_scores_for_npubs(&npubs).await
    }

    async fn trust_scores_for_npubs(&self, npubs: &[String]) -> BTreeMap<String, i64> {
        self.discovery
            .trust_scores_for_npubs_for_sim(npubs)
            .await
            .into_iter()
            .collect()
    }

    fn publish_over_pubsub(&mut self, pubsub: &WotRatingPubsubConfig) {
        self.stats.pubsub_published_events += 1;
        let inventory_targets = pubsub.peer_count.saturating_sub(1);
        let subscribers = pubsub.subscriber_count.min(inventory_targets);

        self.stats.pubsub_inventory_messages = self
            .stats
            .pubsub_inventory_messages
            .saturating_add(inventory_targets);
        self.stats.pubsub_want_messages =
            self.stats.pubsub_want_messages.saturating_add(subscribers);
        self.stats.pubsub_delivered_events = self
            .stats
            .pubsub_delivered_events
            .saturating_add(subscribers);
        self.stats.pubsub_inv_want_bytes = self.stats.pubsub_inv_want_bytes.saturating_add(
            inventory_targets
                .saturating_mul(pubsub.inventory_bytes)
                .saturating_add(
                    subscribers
                        .saturating_mul(pubsub.want_bytes.saturating_add(pubsub.payload_bytes)),
                ),
        );
        self.stats.pubsub_flood_bytes = self
            .stats
            .pubsub_flood_bytes
            .saturating_add(inventory_targets.saturating_mul(pubsub.payload_bytes));
    }

    async fn drop_untrusted_spam(&mut self, scope: &str, count: usize) {
        for index in 0..count {
            let seed = 1_000 + u64::try_from(index).unwrap_or(u64::MAX);
            let spam_keys = sim_keys(seed);
            let spam_subject = sim_npub(seed + 10_000);
            let spam_event = WotRatingFactEvent::signed_by(
                &spam_keys,
                &spam_keys.public_key().to_bech32().expect("spam rater npub"),
                &spam_subject,
                scope,
                100,
                1_000 + u64::try_from(index).unwrap_or(u64::MAX),
                WotRatingEventSource::UntrustedSpam,
            );
            self.ingest(spam_event).await;
        }
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
                .created_at()
                .cmp(&left.created_at())
                .then_with(|| left.id().cmp(&right.id()))
        });
        events.truncate(filter.limit);
        self.stats.history_events_returned += events.len();
        events
    }
}

fn matches_nostr_filter(event: &WotRatingFactEvent, filter: &WotNostrFilter) -> bool {
    if !filter.kinds.is_empty() && !filter.kinds.contains(&event.kind()) {
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
        peer(
            peer_npub(WotPeerProfile::Reliable),
            WotPeerProfile::Reliable,
            120,
        ),
        peer(
            peer_npub(WotPeerProfile::BackupReliable),
            WotPeerProfile::BackupReliable,
            110,
        ),
        peer(
            peer_npub(WotPeerProfile::Newcomer),
            WotPeerProfile::Newcomer,
            140,
        ),
        peer(
            peer_npub(WotPeerProfile::Degrading),
            WotPeerProfile::Degrading,
            130,
        ),
        peer(peer_npub(WotPeerProfile::Bad), WotPeerProfile::Bad, 150),
    ]
}

fn peer(id: String, profile: WotPeerProfile, advertised_at: u64) -> WotPeerSpec {
    WotPeerSpec {
        id,
        profile,
        advertised_at,
    }
}

async fn seed_historic_ratings(config: &WotAdmissionSimConfig, exchange: &mut WotRatingExchange) {
    let signer = trusted_rating_signer_keys();
    let rater = historic_rater_npub();
    for (profile, rating, created_at) in [
        (WotPeerProfile::Reliable, 90, 100),
        (WotPeerProfile::BackupReliable, 70, 100),
        (WotPeerProfile::Degrading, 95, 100),
        (WotPeerProfile::Bad, 0, 100),
    ] {
        exchange
            .seed_historic(WotRatingFactEvent::signed_by(
                &signer,
                &rater,
                &peer_npub(profile),
                &config.rating_scope,
                rating,
                created_at,
                WotRatingEventSource::HistoricIndex,
            ))
            .await;
    }
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

fn signed_rating_fact_event(
    keys: &nostr::Keys,
    rater_npub: &str,
    subject_npub: &str,
    scope: &str,
    rating: i64,
    created_at: u64,
    source: WotRatingEventSource,
    kind: Kind,
) -> WotRatingFactEvent {
    let created_at_string = created_at.to_string();
    let rating_string = rating.to_string();
    let rater_index = rater_npub.to_lowercase();
    let subject_index = subject_npub.to_lowercase();
    let scope_index = scope.to_lowercase();
    let fact_id = format!("rating:{scope_index}:{subject_index}:{created_at}");
    let tags = vec![
        rating_fact_tag(["i", &fact_id, "subject"]),
        rating_fact_tag(["i", &rater_index]),
        rating_fact_tag(["i", &subject_index]),
        rating_fact_tag(["i", &scope_index]),
        rating_fact_tag(["type", "rating"]),
        rating_fact_tag(["schema", "1"]),
        rating_fact_tag(["created_at", &created_at_string]),
        rating_fact_tag(["rater", rater_npub]),
        rating_fact_tag(["subject", subject_npub]),
        rating_fact_tag(["scope", scope]),
        rating_fact_tag(["rating", &rating_string]),
        rating_fact_tag(["min_rating", "0"]),
        rating_fact_tag(["max_rating", "100"]),
    ];
    let event = EventBuilder::new(kind, "")
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .expect("sim rating event signs");
    WotRatingFactEvent { source, event }
}

fn rating_fact_tag<const N: usize>(parts: [&str; N]) -> Tag {
    Tag::parse(parts).expect("valid rating fact tag")
}

fn event_tag_rows(event: &Event) -> Vec<Vec<String>> {
    let Ok(value) = serde_json::to_value(event) else {
        return Vec::new();
    };
    value
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tag| {
            let parts = tag.as_array()?;
            Some(
                parts
                    .iter()
                    .filter_map(|part| part.as_str().map(ToOwned::to_owned))
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn event_tag_values(event: &Event, key: &str) -> Vec<String> {
    event_tag_rows(event)
        .into_iter()
        .filter_map(|tag| {
            if tag.first().is_some_and(|tag_key| tag_key == key) {
                tag.get(1).cloned()
            } else {
                None
            }
        })
        .filter(|value| !value.trim().is_empty())
        .collect()
}

fn event_tag_value(event: &Event, key: &str) -> Option<String> {
    event_tag_values(event, key).into_iter().next()
}

fn trusted_rating_signer_keys() -> nostr::Keys {
    sim_keys(TRUSTED_RATING_SIGNER_SEED)
}

fn trusted_rating_signer_npub() -> String {
    sim_npub(TRUSTED_RATING_SIGNER_SEED)
}

fn local_rater_npub() -> String {
    sim_npub(LOCAL_RATER_SEED)
}

fn historic_rater_npub() -> String {
    sim_npub(HISTORIC_RATER_SEED)
}

fn peer_npub(profile: WotPeerProfile) -> String {
    sim_npub(match profile {
        WotPeerProfile::Reliable => 11,
        WotPeerProfile::BackupReliable => 12,
        WotPeerProfile::Newcomer => 13,
        WotPeerProfile::Degrading => 14,
        WotPeerProfile::Bad => 15,
    })
}

fn sim_npub(seed: u64) -> String {
    sim_keys(seed).public_key().to_bech32().expect("sim npub")
}

fn sim_keys(seed: u64) -> nostr::Keys {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&seed.max(1).to_be_bytes());
    nostr::Keys::parse(&hex::encode(bytes)).expect("valid deterministic sim key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wot_admission_prioritizes_good_probes_newcomer_and_penalizes_degraded() {
        let report = run_default_wot_admission_sim().await;
        assert_eq!(report.trusted_rating_author_count, 1);

        assert_eq!(
            selected_profiles(&report, "cold_start"),
            vec![
                WotPeerProfile::Degrading,
                WotPeerProfile::Reliable,
                WotPeerProfile::Newcomer,
            ]
        );
        let newcomer = peer_id(&report, WotPeerProfile::Newcomer);
        let bad = peer_id(&report, WotPeerProfile::Bad);
        assert_decision(
            phase(&report, "cold_start"),
            &newcomer,
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
        );
        assert_decision(
            phase(&report, "cold_start"),
            &bad,
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );

        let after_probe = phase(&report, "after_newcomer_probe");
        assert_decision(
            after_probe,
            &newcomer,
            true,
            Some(70),
            WotAdmissionReason::TrustedRating,
        );
        assert_decision(
            after_probe,
            &bad,
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );

        assert_eq!(
            selected_profiles(&report, "after_degradation"),
            vec![
                WotPeerProfile::Reliable,
                WotPeerProfile::Newcomer,
                WotPeerProfile::BackupReliable,
            ]
        );
        let degrading = peer_id(&report, WotPeerProfile::Degrading);
        let backup = peer_id(&report, WotPeerProfile::BackupReliable);
        assert_decision(
            phase(&report, "after_degradation"),
            &degrading,
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );
        assert_decision(
            phase(&report, "after_degradation"),
            &backup,
            true,
            Some(40),
            WotAdmissionReason::TrustedRating,
        );

        assert_eq!(report.exchange.historic_seed_events, 4);
        assert_eq!(report.exchange.local_published_events, 2);
        assert_eq!(report.exchange.indexed_events, 6);
        assert_eq!(report.exchange.history_queries, 3);
        assert_eq!(report.rating_events.len(), 6);
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.event.verify().is_ok())
        );
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.signer() == trusted_rating_signer_npub())
        );
    }

    #[tokio::test]
    async fn local_rating_publish_uses_inv_want_pubsub_before_history_lookup() {
        let report = run_default_wot_admission_sim().await;
        let subscriber_count = report
            .config
            .rating_pubsub
            .subscriber_count
            .min(report.config.rating_pubsub.peer_count.saturating_sub(1));

        assert_eq!(
            report.exchange.pubsub_published_events,
            report.exchange.local_published_events
        );
        assert_eq!(
            report.exchange.pubsub_delivered_events,
            report.exchange.local_published_events * subscriber_count
        );
        assert_eq!(
            report.exchange.pubsub_inventory_messages,
            report.exchange.local_published_events
                * report.config.rating_pubsub.peer_count.saturating_sub(1)
        );
        assert_eq!(
            report.exchange.pubsub_want_messages,
            report.exchange.pubsub_delivered_events
        );
        assert!(
            report.exchange.pubsub_inv_want_bytes < report.exchange.pubsub_flood_bytes,
            "inv/want publish accounting should be cheaper than full-payload flooding"
        );

        assert_eq!(phase(&report, "cold_start").rating_events_seen, 4);
        assert_eq!(phase(&report, "after_newcomer_probe").rating_events_seen, 5);
        assert_eq!(phase(&report, "after_degradation").rating_events_seen, 6);
    }

    #[tokio::test]
    async fn untrusted_rating_spam_is_not_indexed_into_history() {
        let report = run_default_wot_admission_sim().await;
        let spam_per_publish = report.config.rating_pubsub.spam_events_per_publish;

        assert_eq!(
            report.exchange.pubsub_spam_events_seen,
            report.exchange.local_published_events * spam_per_publish
        );
        assert_eq!(
            report.exchange.pubsub_spam_events_dropped,
            report.exchange.pubsub_spam_events_seen
        );
        assert_eq!(
            report.exchange.indexed_events,
            report.exchange.historic_seed_events + report.exchange.local_published_events
        );
        assert_eq!(report.rating_events.len(), report.exchange.indexed_events);
        assert_eq!(
            phase(&report, "after_degradation").rating_events_seen,
            report.exchange.indexed_events
        );
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.source != WotRatingEventSource::UntrustedSpam)
        );
    }

    #[tokio::test]
    async fn trusted_rating_signer_can_differ_from_rater_fact() {
        let mut exchange = WotRatingExchange::default();
        let signer = trusted_rating_signer_keys();
        let external_rater = sim_npub(30);
        let subject = sim_npub(31);
        let spam_subject = sim_npub(32);
        let trusted = WotRatingFactEvent::signed_by(
            &signer,
            &external_rater,
            &subject,
            "fips.peer",
            90,
            10,
            WotRatingEventSource::HistoricIndex,
        );
        let spam = WotRatingFactEvent::signed_by(
            &sim_keys(90),
            &trusted_rating_signer_npub(),
            &spam_subject,
            "fips.peer",
            100,
            11,
            WotRatingEventSource::HistoricIndex,
        );

        exchange.seed_historic(spam).await;
        exchange.seed_historic(trusted).await;

        let events = exchange.query_events(&WotNostrFilter::rating_scope("fips.peer", 64));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signer(), trusted_rating_signer_npub());
        assert_eq!(events[0].rater().as_deref(), Some(external_rater.as_str()));
        assert_eq!(events[0].subject().as_deref(), Some(subject.as_str()));
        assert_eq!(events[0].normalized_score(), Some(80));
        assert_eq!(
            exchange
                .trust_scores_for_npubs(std::slice::from_ref(&subject))
                .await
                .get(&subject),
            Some(&80)
        );
        assert_eq!(exchange.stats.pubsub_spam_events_seen, 1);
        assert_eq!(exchange.stats.pubsub_spam_events_dropped, 1);
        assert_eq!(exchange.stats.indexed_events, 1);
    }

    #[test]
    fn rating_fact_tags_use_scope_for_pubsub_and_history_lookup() {
        let subject = sim_npub(40);
        let event = WotRatingFactEvent::signed_by(
            &trusted_rating_signer_keys(),
            &local_rater_npub(),
            &subject,
            "fips.peer",
            80,
            42,
            WotRatingEventSource::LocalProbe,
        );
        let tags = event.nostr_fact_tags();

        assert!(event.event.verify().is_ok());
        assert_eq!(event.kind(), RATING_FACT_KIND);
        assert_eq!(event.signer(), trusted_rating_signer_npub());
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
        let nostr_filter = serde_json::to_value(filter.to_nostr_filter()).unwrap();
        assert_eq!(nostr_filter["kinds"], serde_json::json!([7368]));
        assert_eq!(nostr_filter["#i"], serde_json::json!(["fips.peer"]));
        assert_eq!(nostr_filter["limit"], 64);
    }

    #[test]
    fn history_lookup_uses_normal_nostr_filter_kind_and_i_tag() {
        let signer = trusted_rating_signer_keys();
        let mut exchange = WotRatingExchange::default();
        let good_subject = sim_npub(50);
        let other_scope_subject = sim_npub(51);
        let wrong_kind_subject = sim_npub(52);
        exchange.events.push(WotRatingFactEvent::signed_by(
            &signer,
            &local_rater_npub(),
            &good_subject,
            "fips.peer",
            90,
            100,
            WotRatingEventSource::HistoricIndex,
        ));
        exchange.events.push(WotRatingFactEvent::signed_by(
            &signer,
            &local_rater_npub(),
            &other_scope_subject,
            "other.scope",
            90,
            101,
            WotRatingEventSource::HistoricIndex,
        ));
        exchange.events.push(signed_rating_fact_event(
            &signer,
            &local_rater_npub(),
            &wrong_kind_subject,
            "fips.peer",
            90,
            102,
            WotRatingEventSource::HistoricIndex,
            Kind::Custom(1),
        ));

        let events = exchange.query_events(&WotNostrFilter::rating_scope("fips.peer", 64));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].subject().as_deref(), Some(good_subject.as_str()));
    }

    fn phase<'a>(report: &'a WotAdmissionSimReport, label: &str) -> &'a WotAdmissionPhaseReport {
        report
            .phases
            .iter()
            .find(|phase| phase.label == label)
            .expect("phase exists")
    }

    fn selected_profiles(report: &WotAdmissionSimReport, label: &str) -> Vec<WotPeerProfile> {
        phase(report, label)
            .selected_peers
            .iter()
            .map(|peer_id| profile(report, peer_id))
            .collect()
    }

    fn profile(report: &WotAdmissionSimReport, peer_id: &str) -> WotPeerProfile {
        report
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .map(|peer| peer.profile)
            .expect("peer exists")
    }

    fn peer_id(report: &WotAdmissionSimReport, profile: WotPeerProfile) -> String {
        report
            .peers
            .iter()
            .find(|peer| peer.profile == profile)
            .map(|peer| peer.id.clone())
            .expect("peer exists")
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
        assert_eq!(decision.admission_order.is_some(), selected);
    }

    fn tag(key: &str, value: &str) -> Vec<String> {
        vec![key.to_string(), value.to_string()]
    }
}
