use fips_core::config::NostrDiscoveryConfig;
use fips_core::discovery::nostr::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, NostrDiscovery, OverlayAdvert,
    OverlayEndpointAdvert, OverlayTransportKind, PROTOCOL_VERSION,
};
use fips_core::peer_rating::compute_peer_rating;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{
    Alphabet, Event, EventBuilder, Filter, JsonUtil, Kind, SingleLetterTag, Tag, TagKind, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const DEFAULT_SCOPE: &str = "fips.peer";
const RATING_FACT_KIND: u16 = 7368;
const TRUSTED_RATING_SIGNER_SEED: u64 = 1;
const LOCAL_RATER_SEED: u64 = 2;
const LOCAL_PUBSUB_NODE: usize = 0;
const FIRST_REMOTE_PUBSUB_NODE: usize = 1;
const DEFAULT_PUBSUB_NODE_COUNT: usize = 128;
const DEFAULT_DISCOVERY_APP: &str = "fips-overlay-v1";
const WOT_NOSTR_EVENT_STREAM: &str = "nostr.events.v1";

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

/// Small in-process inv/want pubsub model for local rating facts and peer ads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotRatingPubsubConfig {
    /// Nodes in the decentralized pubsub graph, including the local node.
    pub peer_count: usize,
    /// Interested non-origin peers that send wants and receive event payloads.
    pub subscriber_count: usize,
    /// FIPS entry nodes known by the local node before decentralized discovery.
    pub known_entry_nodes: usize,
    /// Deterministic overlay degree used by remote pubsub nodes.
    pub gossip_degree: usize,
    /// Maximum inventory messages processed during one virtual-clock tick.
    pub max_messages_per_tick: usize,
    /// Virtual milliseconds represented by one pubsub scheduler tick.
    pub virtual_tick_ms: u64,
    /// Untrusted rating spam seen alongside each trusted local rating publish.
    pub spam_events_per_publish: usize,
    /// Approximate bytes for one inventory notice.
    pub inventory_bytes: usize,
    /// Approximate bytes for one want request.
    pub want_bytes: usize,
    /// Fallback estimate retained for reports; signed event JSON length is used on publish.
    pub payload_bytes: usize,
}

impl Default for WotRatingPubsubConfig {
    fn default() -> Self {
        Self {
            peer_count: DEFAULT_PUBSUB_NODE_COUNT,
            subscriber_count: DEFAULT_PUBSUB_NODE_COUNT - 1,
            known_entry_nodes: 2,
            gossip_degree: 8,
            max_messages_per_tick: 256,
            virtual_tick_ms: 25,
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
    pub probe_requests: usize,
    pub probe_valid_payloads: usize,
    pub probe_invalid_payloads: usize,
    pub probe_useful_bytes: usize,
    pub probe_junk_bytes: usize,
    pub probe_low_throughput_valid_payloads: usize,
    pub pubsub_published_events: usize,
    pub pubsub_inventory_messages: usize,
    pub pubsub_want_messages: usize,
    pub pubsub_delivered_events: usize,
    pub pubsub_local_delivered_events: usize,
    pub pubsub_inv_want_bytes: usize,
    pub pubsub_flood_bytes: usize,
    pub pubsub_payload_bytes: usize,
    pub pubsub_payload_events_decoded: usize,
    pub pubsub_payload_decode_failures: usize,
    pub pubsub_duplicate_inventories: usize,
    pub pubsub_virtual_ticks: u64,
    pub pubsub_virtual_time_ms: u64,
    pub pubsub_spam_events_seen: usize,
    pub pubsub_spam_events_dropped: usize,
    pub pubsub_peer_advert_events_published: usize,
    pub pubsub_peer_advert_events_cached: usize,
    pub pubsub_peer_advert_events_rejected: usize,
}

/// Peer-advert discovery result from the decentralized pubsub phase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotPeerDiscoveryPubsubReport {
    pub node_count: usize,
    pub known_entry_nodes: usize,
    pub tracked_peer_count: usize,
    pub advert_events_published: usize,
    pub advert_events_delivered_to_local: usize,
    pub advert_events_cached: usize,
    pub cached_open_discovery_candidates: usize,
    pub tracked_candidates_cached: usize,
    pub virtual_ticks: u64,
    pub virtual_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WotPubsubEventSource {
    Rating(WotRatingEventSource),
    PeerAdvert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WotPubsubDelivery {
    stream_id: String,
    seq: u64,
    origin_node: usize,
    subscriber_node: usize,
    delivered_at_tick: u64,
    source: WotPubsubEventSource,
    payload: Vec<u8>,
}

impl WotPubsubDelivery {
    fn rating_source(&self) -> WotRatingEventSource {
        match self.source {
            WotPubsubEventSource::Rating(source) => source,
            WotPubsubEventSource::PeerAdvert => WotRatingEventSource::UntrustedSpam,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WotPubsubInventory {
    from: usize,
    to: usize,
    tick: u64,
}

#[derive(Debug, Clone)]
struct WotDecentralizedPubsub {
    adjacency: Vec<Vec<usize>>,
    next_seq: u64,
    clock_tick: u64,
    known_entry_nodes: usize,
}

impl WotDecentralizedPubsub {
    fn new(config: WotRatingPubsubConfig) -> Self {
        let node_count = config.peer_count.max(2);
        let remote_count = node_count - 1;
        let known_entry_nodes = config.known_entry_nodes.clamp(1, remote_count.min(3));
        let gossip_degree = config
            .gossip_degree
            .clamp(2, remote_count.saturating_sub(1).max(2));
        let mut edges = BTreeSet::new();

        for entry in FIRST_REMOTE_PUBSUB_NODE..=known_entry_nodes {
            insert_pubsub_edge(&mut edges, LOCAL_PUBSUB_NODE, entry);
        }

        let ring_fanout = (gossip_degree / 2).max(1);
        for node in FIRST_REMOTE_PUBSUB_NODE..node_count {
            for offset in 1..=ring_fanout {
                let peer = FIRST_REMOTE_PUBSUB_NODE
                    + ((node - FIRST_REMOTE_PUBSUB_NODE + offset) % remote_count);
                insert_pubsub_edge(&mut edges, node, peer);
            }
            let chord = FIRST_REMOTE_PUBSUB_NODE + ((node * 7 + 3) % remote_count);
            insert_pubsub_edge(&mut edges, node, chord);
        }

        let mut adjacency = vec![Vec::new(); node_count];
        for (left, right) in edges {
            adjacency[left].push(right);
            adjacency[right].push(left);
        }
        for peers in &mut adjacency {
            peers.sort_unstable();
        }

        Self {
            adjacency,
            next_seq: 1,
            clock_tick: 0,
            known_entry_nodes,
        }
    }

    fn remote_node_count(&self) -> usize {
        self.adjacency.len().saturating_sub(1)
    }

    fn known_entry_nodes(&self) -> usize {
        self.known_entry_nodes
    }

    fn publish_event(
        &mut self,
        config: &WotRatingPubsubConfig,
        origin_node: usize,
        event: &Event,
        source: WotPubsubEventSource,
        stats: &mut WotRatingExchangeStats,
    ) -> Vec<WotPubsubDelivery> {
        let node_count = self.adjacency.len().max(2);
        let origin_node = origin_node.min(node_count - 1);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        stats.pubsub_published_events = stats.pubsub_published_events.saturating_add(1);

        let payload = event.as_json().into_bytes();
        let payload_len = payload.len().max(1);
        let mut deliveries = Vec::new();
        let mut seen = BTreeSet::from([origin_node]);
        let mut queue = VecDeque::new();
        let mut tick_load = BTreeMap::new();

        if origin_node == LOCAL_PUBSUB_NODE {
            stats.pubsub_local_delivered_events =
                stats.pubsub_local_delivered_events.saturating_add(1);
            deliveries.push(WotPubsubDelivery {
                stream_id: WOT_NOSTR_EVENT_STREAM.to_string(),
                seq,
                origin_node,
                subscriber_node: LOCAL_PUBSUB_NODE,
                delivered_at_tick: self.clock_tick,
                source,
                payload: payload.clone(),
            });
        }

        for peer in self.adjacency[origin_node].clone() {
            schedule_pubsub_inventory(
                &mut queue,
                &mut tick_load,
                config.max_messages_per_tick,
                WotPubsubInventory {
                    from: origin_node,
                    to: peer,
                    tick: self.clock_tick.saturating_add(1),
                },
            );
        }

        let subscriber_limit = config.subscriber_count.min(node_count.saturating_sub(1));
        while let Some(inventory) = queue.pop_front() {
            self.clock_tick = self.clock_tick.max(inventory.tick);
            stats.pubsub_inventory_messages = stats.pubsub_inventory_messages.saturating_add(1);
            stats.pubsub_inv_want_bytes = stats
                .pubsub_inv_want_bytes
                .saturating_add(config.inventory_bytes);
            stats.pubsub_flood_bytes = stats.pubsub_flood_bytes.saturating_add(payload_len);

            if !seen.insert(inventory.to) {
                stats.pubsub_duplicate_inventories =
                    stats.pubsub_duplicate_inventories.saturating_add(1);
                continue;
            }

            let interested_receivers = seen.len().saturating_sub(1);
            if interested_receivers > subscriber_limit && inventory.to != LOCAL_PUBSUB_NODE {
                continue;
            }

            stats.pubsub_want_messages = stats.pubsub_want_messages.saturating_add(1);
            stats.pubsub_delivered_events = stats.pubsub_delivered_events.saturating_add(1);
            stats.pubsub_payload_bytes = stats.pubsub_payload_bytes.saturating_add(payload_len);
            stats.pubsub_inv_want_bytes = stats
                .pubsub_inv_want_bytes
                .saturating_add(config.want_bytes.saturating_add(payload_len));

            if inventory.to == LOCAL_PUBSUB_NODE {
                stats.pubsub_local_delivered_events =
                    stats.pubsub_local_delivered_events.saturating_add(1);
                deliveries.push(WotPubsubDelivery {
                    stream_id: WOT_NOSTR_EVENT_STREAM.to_string(),
                    seq,
                    origin_node,
                    subscriber_node: LOCAL_PUBSUB_NODE,
                    delivered_at_tick: self.clock_tick,
                    source,
                    payload: payload.clone(),
                });
            }

            for peer in self.adjacency[inventory.to].clone() {
                if peer == inventory.from {
                    continue;
                }
                schedule_pubsub_inventory(
                    &mut queue,
                    &mut tick_load,
                    config.max_messages_per_tick,
                    WotPubsubInventory {
                        from: inventory.to,
                        to: peer,
                        tick: self.clock_tick.saturating_add(1),
                    },
                );
            }
        }

        stats.pubsub_virtual_ticks = stats.pubsub_virtual_ticks.max(self.clock_tick);
        stats.pubsub_virtual_time_ms = stats
            .pubsub_virtual_ticks
            .saturating_mul(config.virtual_tick_ms);
        deliveries
    }
}

fn insert_pubsub_edge(edges: &mut BTreeSet<(usize, usize)>, left: usize, right: usize) {
    if left == right {
        return;
    }
    let edge = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    edges.insert(edge);
}

fn schedule_pubsub_inventory(
    queue: &mut VecDeque<WotPubsubInventory>,
    tick_load: &mut BTreeMap<u64, usize>,
    max_messages_per_tick: usize,
    mut inventory: WotPubsubInventory,
) {
    let capacity = max_messages_per_tick.max(1);
    loop {
        let load = tick_load.entry(inventory.tick).or_default();
        if *load < capacity {
            *load += 1;
            queue.push_back(inventory);
            return;
        }
        inventory.tick = inventory.tick.saturating_add(1);
    }
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
    pub peer_discovery: WotPeerDiscoveryPubsubReport,
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
    observed_peer_ratings: BTreeMap<String, i64>,
}

impl WotAdmissionSimulation {
    pub fn new(config: WotAdmissionSimConfig) -> Self {
        let peers = default_peers();
        let exchange = WotRatingExchange::new(&config);
        Self {
            config,
            peers,
            exchange,
            observed_peer_ratings: BTreeMap::new(),
        }
    }

    pub async fn run(mut self) -> WotAdmissionSimReport {
        let peer_discovery = self
            .exchange
            .run_peer_discovery_pubsub(&self.config.rating_pubsub, &self.peers)
            .await;

        let cold_start = self.admission_phase("cold_start").await;
        self.publish_probe_observations(&cold_start.selected_peers, 100, false)
            .await;
        let after_initial_probe = self.admission_phase("after_initial_probe").await;
        self.publish_probe_observations(&after_initial_probe.selected_peers, 200, true)
            .await;
        let after_degradation = self.admission_phase("after_degradation").await;

        WotAdmissionSimReport {
            config: self.config,
            peers: self.peers,
            peer_discovery,
            phases: vec![cold_start, after_initial_probe, after_degradation],
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
        let advertised_peers = self.exchange.advertised_tracked_peers(&self.peers).await;
        let trust_scores = self
            .exchange
            .trust_scores_for_peers(&advertised_peers)
            .await;
        let decisions = order_admission_decisions(
            &advertised_peers,
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

    async fn publish_probe_observations(
        &mut self,
        selected_peers: &[String],
        created_at: u64,
        degradation_seen: bool,
    ) {
        for peer_id in selected_peers {
            let Some(peer) = self.peer_by_id(peer_id).cloned() else {
                continue;
            };
            let observation = observed_rating_for_probe(&peer, degradation_seen, created_at);
            self.exchange.stats.probe_requests += 1;
            if observation.valid_payload {
                self.exchange.stats.probe_valid_payloads += 1;
                self.exchange.stats.probe_useful_bytes = self
                    .exchange
                    .stats
                    .probe_useful_bytes
                    .saturating_add(observation.useful_bytes);
            } else {
                self.exchange.stats.probe_invalid_payloads += 1;
                self.exchange.stats.probe_junk_bytes = self
                    .exchange
                    .stats
                    .probe_junk_bytes
                    .saturating_add(observation.junk_bytes);
            }
            if observation.low_throughput_valid_payload {
                self.exchange.stats.probe_low_throughput_valid_payloads += 1;
            }
            let Some(rating) = observation.rating else {
                continue;
            };
            if self
                .observed_peer_ratings
                .get(peer_id)
                .is_some_and(|previous| *previous == rating)
            {
                continue;
            }
            self.observed_peer_ratings.insert(peer_id.clone(), rating);
            self.exchange
                .publish_local(
                    &self.config.rating_pubsub,
                    WotRatingFactEvent::signed_by(
                        &trusted_rating_signer_keys(),
                        &local_rater_npub(),
                        peer_id,
                        &self.config.rating_scope,
                        rating,
                        created_at,
                        observation.source,
                    ),
                )
                .await;
        }
    }

    fn peer_by_id(&self, peer_id: &str) -> Option<&WotPeerSpec> {
        self.peers.iter().find(|peer| peer.id == peer_id)
    }
}

struct WotRatingExchange {
    events: Vec<WotRatingFactEvent>,
    stats: WotRatingExchangeStats,
    discovery: NostrDiscovery,
    pubsub: WotDecentralizedPubsub,
    indexed_event_ids: BTreeSet<String>,
    dropped_spam_event_ids: BTreeSet<String>,
    cached_advert_event_ids: BTreeSet<String>,
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
            pubsub: WotDecentralizedPubsub::new(config.rating_pubsub),
            indexed_event_ids: BTreeSet::new(),
            dropped_spam_event_ids: BTreeSet::new(),
            cached_advert_event_ids: BTreeSet::new(),
        }
    }

    fn trusted_rating_author_count(&self) -> usize {
        self.discovery.trusted_rating_author_count()
    }

    #[cfg(test)]
    async fn seed_historic(&mut self, event: WotRatingFactEvent) {
        self.stats.historic_seed_events += 1;
        self.ingest(event).await;
    }

    async fn publish_local(&mut self, pubsub: &WotRatingPubsubConfig, event: WotRatingFactEvent) {
        self.stats.local_published_events += 1;
        let scope = event.scope().unwrap_or_else(|| DEFAULT_SCOPE.to_string());
        let source = WotPubsubEventSource::Rating(event.source);
        let deliveries = self.pubsub.publish_event(
            pubsub,
            LOCAL_PUBSUB_NODE,
            &event.event,
            source,
            &mut self.stats,
        );
        self.ingest_pubsub_deliveries(deliveries).await;
        self.publish_untrusted_spam(pubsub, &scope, pubsub.spam_events_per_publish)
            .await;
    }

    async fn ingest(&mut self, event: WotRatingFactEvent) -> bool {
        let event_id = event.id();
        if self
            .discovery
            .process_rating_fact_event_for_sim(&event.event)
            .await
        {
            if self.indexed_event_ids.insert(event_id) {
                self.stats.indexed_events += 1;
                self.events.push(event);
            }
            return true;
        }

        if self.dropped_spam_event_ids.insert(event_id) {
            self.stats.pubsub_spam_events_seen =
                self.stats.pubsub_spam_events_seen.saturating_add(1);
            self.stats.pubsub_spam_events_dropped =
                self.stats.pubsub_spam_events_dropped.saturating_add(1);
        }
        false
    }

    async fn ingest_pubsub_deliveries(&mut self, deliveries: Vec<WotPubsubDelivery>) {
        for delivery in deliveries {
            if delivery.stream_id != WOT_NOSTR_EVENT_STREAM {
                self.stats.pubsub_payload_decode_failures =
                    self.stats.pubsub_payload_decode_failures.saturating_add(1);
                continue;
            }
            let Ok(payload) = std::str::from_utf8(&delivery.payload) else {
                self.stats.pubsub_payload_decode_failures =
                    self.stats.pubsub_payload_decode_failures.saturating_add(1);
                continue;
            };
            let Ok(event) = Event::from_json(payload) else {
                self.stats.pubsub_payload_decode_failures =
                    self.stats.pubsub_payload_decode_failures.saturating_add(1);
                continue;
            };
            self.stats.pubsub_payload_events_decoded =
                self.stats.pubsub_payload_events_decoded.saturating_add(1);

            match event.kind {
                Kind::Custom(RATING_FACT_KIND) => {
                    let source = delivery.rating_source();
                    self.ingest(WotRatingFactEvent { source, event }).await;
                }
                Kind::Custom(ADVERT_KIND) => {
                    let event_id = event.id.to_hex();
                    if self.discovery.process_advert_event_for_sim(&event).await {
                        if self.cached_advert_event_ids.insert(event_id) {
                            self.stats.pubsub_peer_advert_events_cached = self
                                .stats
                                .pubsub_peer_advert_events_cached
                                .saturating_add(1);
                        }
                    } else {
                        self.stats.pubsub_peer_advert_events_rejected = self
                            .stats
                            .pubsub_peer_advert_events_rejected
                            .saturating_add(1);
                    }
                }
                _ => {
                    self.stats.pubsub_payload_decode_failures =
                        self.stats.pubsub_payload_decode_failures.saturating_add(1);
                }
            }
        }
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

    async fn publish_untrusted_spam(
        &mut self,
        pubsub: &WotRatingPubsubConfig,
        scope: &str,
        count: usize,
    ) {
        let base_index = self.stats.pubsub_spam_events_seen;
        for index in 0..count {
            let spam_index = base_index.saturating_add(index);
            let seed = 1_000 + u64::try_from(spam_index).unwrap_or(u64::MAX);
            let spam_keys = sim_keys(seed);
            let spam_subject = sim_npub(seed + 10_000);
            let spam_event = WotRatingFactEvent::signed_by(
                &spam_keys,
                &spam_keys.public_key().to_bech32().expect("spam rater npub"),
                &spam_subject,
                scope,
                100,
                1_000 + u64::try_from(spam_index).unwrap_or(u64::MAX),
                WotRatingEventSource::UntrustedSpam,
            );
            let deliveries = self.pubsub.publish_event(
                pubsub,
                FIRST_REMOTE_PUBSUB_NODE + (index % self.pubsub.remote_node_count().max(1)),
                &spam_event.event,
                WotPubsubEventSource::Rating(WotRatingEventSource::UntrustedSpam),
                &mut self.stats,
            );
            self.ingest_pubsub_deliveries(deliveries).await;
        }
    }

    async fn run_peer_discovery_pubsub(
        &mut self,
        pubsub: &WotRatingPubsubConfig,
        tracked_peers: &[WotPeerSpec],
    ) -> WotPeerDiscoveryPubsubReport {
        self.pubsub = WotDecentralizedPubsub::new(*pubsub);
        let remote_nodes = self.pubsub.remote_node_count();
        let tracked_by_origin = tracked_peers
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, peer)| (FIRST_REMOTE_PUBSUB_NODE + index, peer))
            .collect::<BTreeMap<_, _>>();

        for origin in FIRST_REMOTE_PUBSUB_NODE..=remote_nodes {
            let event = if let Some(peer) = tracked_by_origin.get(&origin) {
                signed_peer_advert_event(
                    &keys_for_peer_profile(peer.profile),
                    origin,
                    DEFAULT_DISCOVERY_APP,
                )
            } else {
                signed_peer_advert_event(
                    &sim_keys(20_000 + origin as u64),
                    origin,
                    DEFAULT_DISCOVERY_APP,
                )
            };
            self.stats.pubsub_peer_advert_events_published = self
                .stats
                .pubsub_peer_advert_events_published
                .saturating_add(1);
            let deliveries = self.pubsub.publish_event(
                pubsub,
                origin,
                &event,
                WotPubsubEventSource::PeerAdvert,
                &mut self.stats,
            );
            self.ingest_pubsub_deliveries(deliveries).await;
        }

        let candidates = self
            .discovery
            .cached_open_discovery_candidates(pubsub.peer_count)
            .await;
        let candidate_ids = candidates
            .iter()
            .map(|(npub, _, _)| npub.clone())
            .collect::<BTreeSet<_>>();
        let tracked_candidates_cached = tracked_peers
            .iter()
            .filter(|peer| candidate_ids.contains(&peer.id))
            .count();

        WotPeerDiscoveryPubsubReport {
            node_count: pubsub.peer_count,
            known_entry_nodes: self.pubsub.known_entry_nodes(),
            tracked_peer_count: tracked_peers.len(),
            advert_events_published: remote_nodes,
            advert_events_delivered_to_local: self.stats.pubsub_peer_advert_events_cached
                + self.stats.pubsub_peer_advert_events_rejected,
            advert_events_cached: self.stats.pubsub_peer_advert_events_cached,
            cached_open_discovery_candidates: candidates.len(),
            tracked_candidates_cached,
            virtual_ticks: self.stats.pubsub_virtual_ticks,
            virtual_time_ms: self.stats.pubsub_virtual_time_ms,
        }
    }

    async fn advertised_tracked_peers(&self, peers: &[WotPeerSpec]) -> Vec<WotPeerSpec> {
        let candidates = self
            .discovery
            .cached_open_discovery_candidates(self.pubsub.remote_node_count().max(peers.len()))
            .await
            .into_iter()
            .map(|(npub, _, _)| npub)
            .collect::<BTreeSet<_>>();
        peers
            .iter()
            .filter(|peer| candidates.contains(&peer.id))
            .cloned()
            .collect()
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

#[derive(Debug, Clone)]
struct WotProbeObservation {
    rating: Option<i64>,
    source: WotRatingEventSource,
    valid_payload: bool,
    useful_bytes: usize,
    junk_bytes: usize,
    low_throughput_valid_payload: bool,
}

#[derive(Debug, Clone)]
struct WotProbeTransfer {
    received_payload: Vec<u8>,
    srtt_ms: f64,
    goodput_bps: f64,
    smoothed_loss: f64,
    smoothed_etx: f64,
    delivery_ratio: f64,
    decrypt_failures: u64,
    replay_suppressed: u64,
}

fn observed_rating_for_probe(
    peer: &WotPeerSpec,
    degradation_seen: bool,
    created_at: u64,
) -> WotProbeObservation {
    let expected_payload = expected_probe_payload(peer, created_at);
    let transfer = probe_transfer(peer.profile, degradation_seen, &expected_payload);
    let valid_payload = transfer.received_payload == expected_payload;
    let useful_bytes = valid_payload
        .then_some(transfer.received_payload.len())
        .unwrap_or_default();
    let junk_bytes = (!valid_payload)
        .then_some(transfer.received_payload.len())
        .unwrap_or_default();
    let low_throughput_valid_payload = valid_payload && transfer.goodput_bps < 1_000_000.0;
    let rating_peer = rating_peer_value(peer, &transfer, valid_payload);
    let rating = compute_peer_rating(&rating_peer).map(|health| health.score);
    let source = if peer.profile == WotPeerProfile::Degrading && degradation_seen && !valid_payload
    {
        WotRatingEventSource::LocalDegradation
    } else {
        WotRatingEventSource::LocalProbe
    };
    WotProbeObservation {
        rating,
        source,
        valid_payload,
        useful_bytes,
        junk_bytes,
        low_throughput_valid_payload,
    }
}

fn expected_probe_payload(peer: &WotPeerSpec, created_at: u64) -> Vec<u8> {
    let prefix = format!("fips-wot-probe|{}|{created_at}|", peer.id);
    super::fixed_payload(prefix.as_bytes(), 1024)
}

fn probe_transfer(
    profile: WotPeerProfile,
    degradation_seen: bool,
    expected_payload: &[u8],
) -> WotProbeTransfer {
    match profile {
        WotPeerProfile::Reliable => valid_probe_transfer(expected_payload, 24.0, 8_000_000.0),
        WotPeerProfile::BackupReliable => valid_probe_transfer(expected_payload, 95.0, 120_000.0),
        WotPeerProfile::Newcomer => valid_probe_transfer(expected_payload, 80.0, 80_000.0),
        WotPeerProfile::Degrading if degradation_seen => invalid_probe_transfer(expected_payload),
        WotPeerProfile::Degrading => valid_probe_transfer(expected_payload, 30.0, 6_000_000.0),
        WotPeerProfile::Bad => invalid_probe_transfer(expected_payload),
    }
}

fn valid_probe_transfer(
    expected_payload: &[u8],
    srtt_ms: f64,
    goodput_bps: f64,
) -> WotProbeTransfer {
    WotProbeTransfer {
        received_payload: expected_payload.to_vec(),
        srtt_ms,
        goodput_bps,
        smoothed_loss: 0.001,
        smoothed_etx: if srtt_ms <= 50.0 { 1.01 } else { 1.10 },
        delivery_ratio: 0.999,
        decrypt_failures: 0,
        replay_suppressed: 0,
    }
}

fn invalid_probe_transfer(expected_payload: &[u8]) -> WotProbeTransfer {
    WotProbeTransfer {
        received_payload: junk_probe_payload(expected_payload),
        srtt_ms: 0.0,
        goodput_bps: 0.0,
        smoothed_loss: 0.0,
        smoothed_etx: 1.0,
        delivery_ratio: 0.0,
        decrypt_failures: 4,
        replay_suppressed: 6,
    }
}

fn junk_probe_payload(expected_payload: &[u8]) -> Vec<u8> {
    expected_payload.iter().map(|byte| byte ^ 0xA5).collect()
}

fn rating_peer_value(
    peer: &WotPeerSpec,
    transfer: &WotProbeTransfer,
    valid_payload: bool,
) -> serde_json::Value {
    let packet_count = if transfer.received_payload.is_empty() {
        0
    } else {
        1
    };
    if valid_payload {
        serde_json::json!({
            "npub": peer.id,
            "stats": {"packets_sent": 1, "packets_recv": packet_count},
            "mmp": {
                "smoothed_loss": transfer.smoothed_loss,
                "smoothed_etx": transfer.smoothed_etx,
                "delivery_ratio_forward": transfer.delivery_ratio,
                "delivery_ratio_reverse": transfer.delivery_ratio,
                "srtt_ms": transfer.srtt_ms,
                "goodput_bps": transfer.goodput_bps
            },
            "replay_suppressed": transfer.replay_suppressed,
            "consecutive_decrypt_failures": transfer.decrypt_failures
        })
    } else {
        serde_json::json!({
            "npub": peer.id,
            "stats": {"packets_sent": 1, "packets_recv": packet_count},
            "replay_suppressed": transfer.replay_suppressed,
            "consecutive_decrypt_failures": transfer.decrypt_failures
        })
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

fn signed_peer_advert_event(keys: &nostr::Keys, node_index: usize, app: &str) -> Event {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: format!("node-{node_index}.fips.test:{}", 20_000 + node_index),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_secs();
    let expires_at = now_secs.saturating_add(3_600);
    let tags = vec![
        Tag::identifier(advert_d_tag_for_sim(app)),
        Tag::custom(TagKind::custom("protocol"), [app.to_string()]),
        Tag::custom(TagKind::custom("version"), [PROTOCOL_VERSION.to_string()]),
        Tag::expiration(Timestamp::from(expires_at)),
    ];
    EventBuilder::new(
        Kind::Custom(ADVERT_KIND),
        serde_json::to_string(&advert).expect("sim advert serializes"),
    )
    .tags(tags)
    .custom_created_at(Timestamp::from(now_secs))
    .sign_with_keys(keys)
    .expect("sim advert event signs")
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

fn advert_d_tag_for_sim(app: &str) -> String {
    let app = app.trim();
    if app.is_empty() {
        ADVERT_IDENTIFIER.to_string()
    } else {
        app.to_string()
    }
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

fn keys_for_peer_profile(profile: WotPeerProfile) -> nostr::Keys {
    sim_keys(match profile {
        WotPeerProfile::Reliable => 11,
        WotPeerProfile::BackupReliable => 12,
        WotPeerProfile::Newcomer => 13,
        WotPeerProfile::Degrading => 14,
        WotPeerProfile::Bad => 15,
    })
}

fn peer_npub(profile: WotPeerProfile) -> String {
    keys_for_peer_profile(profile)
        .public_key()
        .to_bech32()
        .expect("sim npub")
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
        assert!(report.peer_discovery.node_count >= 100);
        assert!((1..=3).contains(&report.peer_discovery.known_entry_nodes));
        assert_eq!(
            report.peer_discovery.tracked_candidates_cached,
            report.peer_discovery.tracked_peer_count
        );
        assert!(
            report.peer_discovery.cached_open_discovery_candidates
                >= report.peer_discovery.tracked_peer_count
        );
        assert_eq!(
            report.peer_discovery.advert_events_published,
            report.config.rating_pubsub.peer_count.saturating_sub(1)
        );
        assert_eq!(
            report.peer_discovery.advert_events_cached,
            report.peer_discovery.advert_events_published
        );
        assert!(report.peer_discovery.virtual_ticks > 0);

        assert_eq!(
            selected_profiles(&report, "cold_start"),
            vec![
                WotPeerProfile::Bad,
                WotPeerProfile::Newcomer,
                WotPeerProfile::Degrading,
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
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
        );

        let after_probe = phase(&report, "after_initial_probe");
        let reliable = peer_id(&report, WotPeerProfile::Reliable);
        let degrading = peer_id(&report, WotPeerProfile::Degrading);
        assert_decision(
            after_probe,
            &degrading,
            true,
            Some(100),
            WotAdmissionReason::TrustedRating,
        );
        assert_decision(
            after_probe,
            &newcomer,
            true,
            Some(68),
            WotAdmissionReason::TrustedRating,
        );
        assert_decision(
            after_probe,
            &reliable,
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
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
            None,
            WotAdmissionReason::NewcomerProbe,
        );

        assert_eq!(report.exchange.historic_seed_events, 0);
        assert_eq!(report.exchange.local_published_events, 5);
        assert_eq!(report.exchange.indexed_events, 5);
        assert_eq!(report.exchange.history_queries, 3);
        assert_eq!(report.exchange.probe_requests, 6);
        assert_eq!(report.exchange.probe_valid_payloads, 4);
        assert_eq!(report.exchange.probe_invalid_payloads, 2);
        assert_eq!(report.exchange.probe_useful_bytes, 4 * 1024);
        assert_eq!(report.exchange.probe_junk_bytes, 2 * 1024);
        assert_eq!(report.exchange.probe_low_throughput_valid_payloads, 2);
        assert_eq!(report.rating_events.len(), 5);
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
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.source != WotRatingEventSource::HistoricIndex)
        );
    }

    #[tokio::test]
    async fn local_rating_publish_uses_inv_want_pubsub_before_history_lookup() {
        let report = run_default_wot_admission_sim().await;
        let spam_publish_count = report.exchange.local_published_events
            * report.config.rating_pubsub.spam_events_per_publish;
        let expected_pubsub_published = report.peer_discovery.advert_events_published
            + report.exchange.local_published_events
            + spam_publish_count;

        assert_eq!(
            report.exchange.pubsub_published_events,
            expected_pubsub_published
        );
        assert!(report.exchange.pubsub_delivered_events > expected_pubsub_published);
        assert!(
            report.exchange.pubsub_inventory_messages > report.exchange.pubsub_delivered_events
        );
        assert_eq!(
            report.exchange.pubsub_want_messages,
            report.exchange.pubsub_delivered_events
        );
        assert_eq!(
            report.exchange.pubsub_payload_events_decoded,
            report.exchange.pubsub_local_delivered_events
        );
        assert_eq!(report.exchange.pubsub_payload_decode_failures, 0);
        assert!(report.exchange.pubsub_payload_bytes > 0);
        assert!(report.exchange.pubsub_duplicate_inventories > 0);
        assert!(report.exchange.pubsub_virtual_ticks > 0);
        assert!(
            report.exchange.pubsub_inv_want_bytes < report.exchange.pubsub_flood_bytes,
            "inv/want publish accounting should be cheaper than full-payload flooding"
        );

        assert_eq!(phase(&report, "cold_start").rating_events_seen, 0);
        assert_eq!(phase(&report, "after_initial_probe").rating_events_seen, 3);
        assert_eq!(phase(&report, "after_degradation").rating_events_seen, 5);
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

    #[test]
    fn low_throughput_valid_probe_is_not_downvoted() {
        let peer = peer(
            peer_npub(WotPeerProfile::Newcomer),
            WotPeerProfile::Newcomer,
            100,
        );
        let observation = observed_rating_for_probe(&peer, false, 123);

        assert!(observation.valid_payload);
        assert!(observation.low_throughput_valid_payload);
        assert_eq!(observation.rating, Some(84));
        assert_eq!(normalize_rating_score(84, 0, 100), Some(68));
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
