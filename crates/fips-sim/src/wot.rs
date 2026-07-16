use crate::util::recv_endpoint_batch_into;
use fips_core::config::{NostrDiscoveryConfig, PeerConfig, SimTransportConfig, TransportInstances};
use fips_core::discovery::nostr::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, NostrDiscovery, OverlayAdvert,
    OverlayEndpointAdvert, OverlayTransportKind, PROTOCOL_VERSION,
};
use fips_core::peer_rating::compute_peer_rating;
use fips_core::{
    Config, FipsEndpoint, Identity, IdentityConfig, PeerIdentity, SimLink, SimNetwork,
    SimNetworkStats, register_sim_network, unregister_sim_network,
};
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{
    Alphabet, Event, EventBuilder, Filter, JsonUtil, Kind, SingleLetterTag, Tag, TagKind, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;
use tokio::time::Instant;

const DEFAULT_SCOPE: &str = "fips.peer";
const RATING_FACT_KIND: u16 = 7368;
const TRUSTED_RATING_SIGNER_SEED: u64 = 1;
const LOCAL_RATER_SEED: u64 = 2;
const LOCAL_PUBSUB_NODE: usize = 0;
const FIRST_REMOTE_PUBSUB_NODE: usize = 1;
const DEFAULT_PUBSUB_NODE_COUNT: usize = 128;
const DEFAULT_DISCOVERY_APP: &str = "fips-overlay-v1";
const WOT_NOSTR_EVENT_STREAM: &str = "nostr.events.v1";
const WOT_PROBE_NETWORK_SEED: u64 = 0x66_69_70_73_77_6f_74;
const WOT_PROBE_LOCAL_ADDR: &str = "wot-probe-local";
const WOT_PROBE_CONVERGENCE_TIMEOUT_SECS: u64 = 8;
const WOT_PROBE_TIMEOUT_MS: u64 = 2_000;

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
    pub probe_timeouts: usize,
    pub probe_useful_bytes: usize,
    pub probe_junk_bytes: usize,
    pub probe_low_throughput_valid_payloads: usize,
    pub probe_network_packets_sent: u64,
    pub probe_network_packets_delivered: u64,
    pub probe_network_bytes_sent: u64,
    pub probe_network_bytes_delivered: u64,
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
        let mut probe_runtime = WotProbeRuntime::start(&self.peers)
            .await
            .expect("start real FIPS WoT probe runtime");

        let cold_start = self.admission_phase("cold_start").await;
        self.publish_probe_observations(&mut probe_runtime, &cold_start.selected_peers, 100, false)
            .await;
        let after_initial_probe = self.admission_phase("after_initial_probe").await;
        self.publish_probe_observations(
            &mut probe_runtime,
            &after_initial_probe.selected_peers,
            200,
            true,
        )
        .await;
        let after_degradation = self.admission_phase("after_degradation").await;
        probe_runtime
            .shutdown()
            .await
            .expect("shutdown real FIPS WoT probe runtime");

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
        probe_runtime: &mut WotProbeRuntime,
        selected_peers: &[String],
        created_at: u64,
        degradation_seen: bool,
    ) {
        for peer_id in selected_peers {
            let Some(peer) = self.peer_by_id(peer_id).cloned() else {
                continue;
            };
            let observation = probe_runtime
                .observed_rating_for_probe(&peer, degradation_seen, created_at)
                .await;
            self.exchange.stats.probe_requests += 1;
            self.exchange.stats.probe_network_packets_sent = self
                .exchange
                .stats
                .probe_network_packets_sent
                .saturating_add(observation.network_delta.packets_sent);
            self.exchange.stats.probe_network_packets_delivered = self
                .exchange
                .stats
                .probe_network_packets_delivered
                .saturating_add(observation.network_delta.packets_delivered);
            self.exchange.stats.probe_network_bytes_sent = self
                .exchange
                .stats
                .probe_network_bytes_sent
                .saturating_add(observation.network_delta.bytes_sent);
            self.exchange.stats.probe_network_bytes_delivered = self
                .exchange
                .stats
                .probe_network_bytes_delivered
                .saturating_add(observation.network_delta.bytes_delivered);
            if observation.valid_payload {
                self.exchange.stats.probe_valid_payloads += 1;
                self.exchange.stats.probe_useful_bytes = self
                    .exchange
                    .stats
                    .probe_useful_bytes
                    .saturating_add(observation.useful_bytes);
            } else if observation.timed_out {
                self.exchange.stats.probe_timeouts += 1;
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

include!("wot_exchange.rs");
include!("wot_probe.rs");
include!("wot_tests.rs");
