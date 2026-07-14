use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nostr::nips::nip19::ToBech32;
use nostr::prelude::{
    Alphabet, Event, EventBuilder, EventId, Filter, Kind, PublicKey, SingleLetterTag,
    SubscriptionId, Tag, TagKind, Timestamp,
};
use nostr_sdk::{Client, ClientOptions, prelude::RelayPoolNotification};
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use super::failure_state::{FailureDecision, FailureState, NostrPeerKey};
use super::signal::{
    FreshnessOutcome, SignalEnvelope, TraversalSignalTiming, create_traversal_answer,
    create_traversal_offer, estimate_clock_skew, validate_offer_freshness,
    validate_traversal_answer_for_offer,
};
use super::stun::{ADVERT_STUN_TIMEOUT, TRAVERSAL_STUN_TIMEOUT, observe_traversal_addresses};
use super::traversal::{nonce, now_ms, planned_remote_endpoints, run_punch_attempt};
use super::types::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, BootstrapError, BootstrapEvent,
    CachedOverlayAdvert, MeshTraversalSignal, NostrAdvertIngestOutcome, NostrFailureDecision,
    NostrPeerFailureView, NostrRefetchOutcome, NostrRelayStatus, OverlayAdvert,
    OverlayEndpointAdvert, PROTOCOL_VERSION, PunchHint, TraversalAnswer, TraversalOffer,
    advert_d_tag,
};
use crate::config::{NostrDiscoveryConfig, PeerConfig};
use crate::discovery::EstablishedTraversal;
use crate::{NodeAddr, PeerIdentity};

mod advert;
mod events;
mod notifications;
mod ratings;
mod tasks;
mod traversal;
mod verified_event;

#[cfg(any(test, feature = "sim-transport"))]
mod test_support;
#[cfg(test)]
mod tests;

pub(in crate::discovery::nostr) use ratings::RATING_FACT_KIND;
pub(in crate::discovery::nostr) use verified_event::VerifiedEvent;

const ADVERT_CACHE_STALE_GRACE_MULTIPLIER: u64 = 2;

fn bind_traversal_udp_socket() -> std::io::Result<std::net::UdpSocket> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = socket.set_reuse_address(true);
        let _ = socket.set_reuse_port(true);
        socket.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
        let socket: std::net::UdpSocket = socket.into();
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
}

fn short_npub(npub: &str) -> String {
    npub.strip_prefix("npub1")
        .filter(|s| s.len() >= 8)
        .map(|s| format!("npub1{}..{}", &s[..4], &s[s.len() - 4..]))
        .unwrap_or_else(|| npub.to_string())
}

fn short_id(id: &str) -> String {
    if id.len() > 8 {
        id[..8].to_string()
    } else {
        id.to_string()
    }
}

#[derive(Clone, Copy)]
pub(super) enum TraversalSignalPath {
    Mesh,
}

impl TraversalSignalPath {
    fn cache_key(self, session_id: &str) -> String {
        format!("session:{session_id}")
    }
}

/// Decide whether an incoming-offer responder session should be suppressed
/// in favor of our own already-running outbound initiator session.
///
/// Dual `auto_connect` peers can otherwise run two traversal sessions in each
/// direction and adopt mismatched sockets. Keep the session initiated by the
/// smaller `NodeAddr`, but only when we know there is a co-active outbound
/// initiator for this same peer. One-sided traversal never suppresses.
pub(super) fn suppress_responder_for_own_initiator(
    our_addr: &NodeAddr,
    peer_addr: &NodeAddr,
    have_active_initiator: bool,
) -> bool {
    have_active_initiator && our_addr < peer_addr
}

fn endpoint_summary(endpoints: &[OverlayEndpointAdvert]) -> String {
    endpoints
        .iter()
        .map(|e| format!("{:?}:{}", e.transport, e.addr).to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

fn is_unroutable_direct_advert_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn endpoint_advert_is_publicly_usable(endpoint: &OverlayEndpointAdvert) -> bool {
    let addr = endpoint.addr.trim();
    if addr.is_empty() {
        return false;
    }

    if endpoint.transport == super::types::OverlayTransportKind::Udp
        && addr.eq_ignore_ascii_case("nat")
    {
        return true;
    }
    if addr.eq_ignore_ascii_case("nat") {
        return false;
    }

    match endpoint.transport {
        super::types::OverlayTransportKind::Udp | super::types::OverlayTransportKind::Tcp => {
            let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
                let Some((host, port)) = addr.rsplit_once(':') else {
                    return false;
                };
                let host = host.trim().trim_start_matches('[').trim_end_matches(']');
                if host.is_empty() || port.trim().parse::<u16>().ok().is_none_or(|p| p == 0) {
                    return false;
                }
                if host.eq_ignore_ascii_case("localhost") {
                    return false;
                }
                return host
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .is_none_or(|ip| !is_unroutable_direct_advert_ip(ip));
            };
            socket_addr.port() != 0 && !is_unroutable_direct_advert_ip(socket_addr.ip())
        }
        super::types::OverlayTransportKind::Tor => true,
        super::types::OverlayTransportKind::WebRtc => is_compressed_pubkey_hex(addr),
        super::types::OverlayTransportKind::NostrRelay => nostr::PublicKey::parse(addr).is_ok(),
    }
}

fn is_compressed_pubkey_hex(addr: &str) -> bool {
    addr.len() == 66
        && (addr.starts_with("02") || addr.starts_with("03"))
        && addr.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

/// Cached STUN-derived public address for an advert-eligible UDP transport
/// bound to a wildcard. Lives on `NostrDiscovery` so the freshness window
/// survives advert refresh cycles.
struct CachedPublicUdpAddr {
    /// Most recent STUN observation. `None` means the last attempt failed
    /// (recorded so we don't re-spam STUN every refresh tick on broken
    /// network conditions).
    addr: Option<SocketAddr>,
    fetched_at: Instant,
}

/// Cache lifetime for a *failed* STUN observation. Held briefly so that
/// transient flakes (slow startup network, momentary STUN-server
/// blip) get retried within ~a minute and the advert grows its UDP
/// endpoint as soon as STUN starts working — rather than waiting a
/// full `advert_refresh_secs` (30 min) for the success-path TTL to
/// expire. Successful results use the longer per-config TTL.
const PUBLIC_UDP_ADDR_FAILURE_TTL: Duration = Duration::from_secs(60);
const RELAY_STARTUP_OP_TIMEOUT: Duration = Duration::from_secs(5);
const ADVERT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
const ADVERT_PUBLISH_RETRY_INITIAL: Duration = Duration::from_secs(2);
const ADVERT_PUBLISH_RETRY_MAX: Duration = Duration::from_secs(30);

fn next_advert_publish_retry_delay(current: Duration) -> Duration {
    current.saturating_mul(2).min(ADVERT_PUBLISH_RETRY_MAX)
}

fn signal_answer_timeout(config: &NostrDiscoveryConfig) -> Duration {
    Duration::from_secs(
        config
            .signal_ttl_secs
            .min(config.attempt_timeout_secs)
            .max(1),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdvertRelayConfig {
    advert_relays: Vec<String>,
}

impl From<&NostrDiscoveryConfig> for AdvertRelayConfig {
    fn from(config: &NostrDiscoveryConfig) -> Self {
        Self {
            advert_relays: config.advert_relays.clone(),
        }
    }
}

impl AdvertRelayConfig {
    fn active_relays(&self, uses_relay_peerfinding: bool) -> HashSet<String> {
        if uses_relay_peerfinding {
            self.advert_relays.iter().cloned().collect()
        } else {
            HashSet::new()
        }
    }
}

pub struct NostrDiscovery {
    client: Client,
    keys: nostr::Keys,
    pubkey: PublicKey,
    npub: String,
    config: NostrDiscoveryConfig,
    relay_config: RwLock<AdvertRelayConfig>,
    advert_cache: RwLock<HashMap<NostrPeerKey, CachedOverlayAdvert>>,
    peer_trust_scores: RwLock<HashMap<NostrPeerKey, NostrPeerTrustScore>>,
    local_advert: RwLock<Option<OverlayAdvert>>,
    current_advert_event_id: RwLock<Option<EventId>>,
    pending_answers: Mutex<HashMap<String, oneshot::Sender<SignalEnvelope<TraversalAnswer>>>>,
    active_initiators: Mutex<HashSet<NostrPeerKey>>,
    active_refetches: Mutex<HashSet<NostrPeerKey>>,
    seen_sessions: Mutex<HashMap<String, u64>>,
    last_incoming_offer_ms: Mutex<HashMap<NostrPeerKey, u64>>,
    offer_slots: Arc<Semaphore>,
    event_tx: mpsc::Sender<BootstrapEvent>,
    event_rx: Mutex<mpsc::Receiver<BootstrapEvent>>,
    mesh_signal_tx: mpsc::Sender<MeshTraversalSignal>,
    mesh_signal_rx: Mutex<mpsc::Receiver<MeshTraversalSignal>>,
    relay_task: Mutex<Option<JoinHandle<()>>>,
    relay_refresh: Notify,
    publish_task: Mutex<Option<JoinHandle<()>>>,
    publish_notify: Notify,
    notify_task: Mutex<Option<JoinHandle<()>>>,
    advertise_task: Mutex<Option<JoinHandle<()>>>,
    child_tasks: Mutex<Vec<JoinHandle<()>>>,
    shutting_down: AtomicBool,
    failure_state: FailureState,
    /// STUN-derived public address per advert-eligible UDP transport
    /// (keyed by `TransportId.as_u32()`). Populated on demand by
    /// `learn_public_udp_addr()` and refreshed by TTL.
    public_udp_addr_cache: RwLock<HashMap<u32, CachedPublicUdpAddr>>,
    /// Capacity gate refreshed by `Node` once per tick. The inbound Msg1 gate
    /// remains authoritative; this only suppresses wasted traversal work.
    outbound_admission: AtomicBool,
    /// Capacity gate for racing a better path to an already-authenticated
    /// peer. This bypasses the peer-slot cap while still honoring
    /// connection/link caps.
    direct_refresh_admission: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
struct NostrPeerTrustScore {
    score: i64,
    updated_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrPeerTrustScoreView {
    pub npub: String,
    pub score: i64,
    pub updated_at_secs: u64,
}

impl NostrDiscovery {
    fn empty_failure_decision() -> NostrFailureDecision {
        NostrFailureDecision {
            consecutive_failures: 0,
            should_warn: false,
            cooldown_until_ms: None,
            crossed_threshold: false,
        }
    }

    fn failure_decision_from(decision: FailureDecision) -> NostrFailureDecision {
        NostrFailureDecision {
            consecutive_failures: decision.consecutive_failures,
            should_warn: decision.should_warn,
            cooldown_until_ms: decision.cooldown_until_ms,
            crossed_threshold: decision.crossed_threshold,
        }
    }

    pub async fn start(
        identity: &crate::Identity,
        config: NostrDiscoveryConfig,
    ) -> Result<Arc<Self>, BootstrapError> {
        if !config.enabled {
            return Err(BootstrapError::Disabled);
        }

        let keys = nostr::Keys::parse(&hex::encode(identity.keypair().secret_bytes()))
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        let client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();

        let relay_union =
            AdvertRelayConfig::from(&config).active_relays(config.uses_relay_peerfinding());
        for relay in relay_union {
            client
                .add_relay(&relay)
                .await
                .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        }
        let pubkey = keys.public_key();
        let npub = crate::encode_npub(&identity.pubkey());
        let (event_tx, event_rx) = mpsc::channel(event_channel_capacity(&config));
        let (mesh_signal_tx, mesh_signal_rx) = mpsc::channel(event_channel_capacity(&config));
        let offer_slots = Arc::new(Semaphore::new(config.max_concurrent_incoming_offers));

        let failure_state = FailureState::new(
            config.failure_streak_threshold,
            config.extended_cooldown_secs,
            config.warn_log_interval_secs,
            config.failure_state_max_entries,
        );

        let uses_relay_peerfinding = config.uses_relay_peerfinding();
        let has_runtime_relays = uses_relay_peerfinding && !config.advert_relays.is_empty();
        let runtime = Arc::new(Self {
            client,
            keys,
            pubkey,
            npub,
            relay_config: RwLock::new(AdvertRelayConfig::from(&config)),
            config,
            advert_cache: RwLock::new(HashMap::new()),
            peer_trust_scores: RwLock::new(HashMap::new()),
            local_advert: RwLock::new(None),
            current_advert_event_id: RwLock::new(None),
            pending_answers: Mutex::new(HashMap::new()),
            active_initiators: Mutex::new(HashSet::new()),
            active_refetches: Mutex::new(HashSet::new()),
            seen_sessions: Mutex::new(HashMap::new()),
            last_incoming_offer_ms: Mutex::new(HashMap::new()),
            offer_slots,
            event_tx,
            event_rx: Mutex::new(event_rx),
            mesh_signal_tx,
            mesh_signal_rx: Mutex::new(mesh_signal_rx),
            relay_task: Mutex::new(None),
            relay_refresh: Notify::new(),
            publish_task: Mutex::new(None),
            publish_notify: Notify::new(),
            notify_task: Mutex::new(None),
            advertise_task: Mutex::new(None),
            child_tasks: Mutex::new(Vec::new()),
            shutting_down: AtomicBool::new(false),
            failure_state,
            public_udp_addr_cache: RwLock::new(HashMap::new()),
            outbound_admission: AtomicBool::new(true),
            direct_refresh_admission: AtomicBool::new(true),
        });

        // Subscribe to the relay-pool broadcast channel BEFORE issuing the
        // Nostr REQs. tokio's broadcast channel only delivers messages sent
        // after the receiver is created — historical events that arrive in
        // response to subscribe() (REQ replays) would otherwise be dropped
        // by the pool's `external_notification_sender.send(...)` returning
        // `Err(SendError)` when no subscriber exists yet. Without this,
        // freshly-restarted nodes with `policy: open` waited up to one
        // `advert_refresh_secs` interval (default 30 min) for non-configured
        // peers to re-publish before discovering them.
        let notifications = runtime.client.notifications();
        runtime.load_rating_fact_events_from_files().await;
        if uses_relay_peerfinding {
            *runtime.publish_task.lock().await = Some(runtime.clone().spawn_publish_loop());
            *runtime.advertise_task.lock().await = Some(runtime.clone().spawn_advertise_loop());
        }
        if has_runtime_relays {
            *runtime.relay_task.lock().await = Some(runtime.clone().spawn_relay_loop());
            *runtime.notify_task.lock().await =
                Some(runtime.clone().spawn_notify_loop(notifications));
        }

        Ok(runtime)
    }

    pub fn set_outbound_admission(&self, allow: bool) {
        self.outbound_admission.store(allow, Ordering::Relaxed);
    }

    pub async fn record_peer_trust_score(
        &self,
        peer: &str,
        score: i64,
        updated_at_secs: u64,
    ) -> Result<(), String> {
        let key =
            NostrPeerKey::parse(peer).map_err(|error| format!("invalid peer key: {error}"))?;
        let incoming = NostrPeerTrustScore {
            score: score.clamp(-100, 100),
            updated_at_secs,
        };
        self.peer_trust_scores
            .write()
            .await
            .entry(key)
            .and_modify(|existing| {
                if incoming.updated_at_secs >= existing.updated_at_secs {
                    *existing = incoming;
                }
            })
            .or_insert(incoming);
        Ok(())
    }

    pub(crate) async fn trust_scores_for_npubs(&self, npubs: &[String]) -> HashMap<String, i64> {
        let scores = self.peer_trust_scores.read().await;
        npubs
            .iter()
            .filter_map(|npub| {
                let key = NostrPeerKey::parse(npub).ok()?;
                let score = scores.get(&key)?.score;
                Some((npub.clone(), score))
            })
            .collect()
    }

    pub fn trust_ratings_enabled(&self) -> bool {
        self.config.open_discovery_trust_ratings_enabled
    }

    pub fn trust_rating_scope(&self) -> &str {
        self.config.open_discovery_rating_scope.as_str()
    }

    pub fn trusted_rating_author_count(&self) -> usize {
        self.config.open_discovery_trusted_rating_authors.len()
    }

    pub fn peer_trust_score_snapshot(&self) -> Result<Vec<NostrPeerTrustScoreView>, &'static str> {
        let scores = self
            .peer_trust_scores
            .try_read()
            .map_err(|_| "peer trust score cache is busy")?;
        let mut rows = scores
            .iter()
            .map(|(peer, score)| NostrPeerTrustScoreView {
                npub: peer.npub(),
                score: score.score,
                updated_at_secs: score.updated_at_secs,
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.updated_at_secs.cmp(&left.updated_at_secs))
                .then_with(|| left.npub.cmp(&right.npub))
        });
        Ok(rows)
    }

    pub(crate) fn outbound_admission_allowed(&self) -> bool {
        self.outbound_admission.load(Ordering::Relaxed)
    }

    pub fn set_direct_refresh_admission(&self, allow: bool) {
        self.direct_refresh_admission
            .store(allow, Ordering::Relaxed);
    }

    pub(crate) fn direct_refresh_admission_allowed(&self) -> bool {
        self.direct_refresh_admission.load(Ordering::Relaxed)
    }

    fn self_peer_key(&self) -> NostrPeerKey {
        NostrPeerKey::from_public_key_ref(&self.pubkey)
    }

    fn traversal_initiator_admission_allowed(&self, mesh_signaling_allowed: bool) -> bool {
        if mesh_signaling_allowed {
            self.direct_refresh_admission_allowed()
        } else {
            self.outbound_admission_allowed()
        }
    }

    pub async fn relay_statuses(&self) -> Vec<NostrRelayStatus> {
        let relay_config = self.relay_config.read().await.clone();
        let mut statuses = relay_config
            .active_relays(self.config.uses_relay_peerfinding())
            .into_iter()
            .map(|url| {
                (
                    url.clone(),
                    NostrRelayStatus {
                        url: url.clone(),
                        status: "unknown".to_string(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        for (relay_url, relay) in self.client.relays().await {
            let url = relay_url.to_string();
            statuses.insert(
                url.clone(),
                NostrRelayStatus {
                    url,
                    status: relay.status().to_string().to_ascii_lowercase(),
                },
            );
        }

        let mut statuses = statuses.into_values().collect::<Vec<_>>();
        statuses.sort_by(|lhs, rhs| lhs.url.cmp(&rhs.url));
        statuses
    }

    pub async fn update_relays(&self, advert_relays: Vec<String>) -> Result<(), BootstrapError> {
        let next = AdvertRelayConfig { advert_relays };

        let previous = self.relay_config.read().await.clone();
        let include_advert_relays = self.config.uses_relay_peerfinding();
        let previous_union = previous.active_relays(include_advert_relays);
        let next_union = next.active_relays(include_advert_relays);

        for relay in &next_union {
            self.client
                .add_relay(relay)
                .await
                .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        }

        for relay in previous_union.difference(&next_union) {
            self.client
                .force_remove_relay(relay)
                .await
                .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        }

        {
            let mut relay_config = self.relay_config.write().await;
            *relay_config = next;
        }

        self.relay_refresh.notify_one();
        Ok(())
    }

    pub(super) async fn publish_delete<I>(
        &self,
        relays: &[String],
        ids: I,
    ) -> Result<(), BootstrapError>
    where
        I: IntoIterator<Item = EventId>,
    {
        let event = EventBuilder::delete(nostr::nips::nip09::EventDeletionRequest::new().ids(ids))
            .sign_with_keys(&self.keys)
            .map_err(|error| BootstrapError::Nostr(error.to_string()))?;
        self.client
            .send_event_to(relays.to_vec(), &event)
            .await
            .map_err(|error| BootstrapError::Nostr(error.to_string()))?;
        Ok(())
    }

    pub(super) async fn mark_session_seen(
        &self,
        session_id: &str,
        signal_path: TraversalSignalPath,
    ) -> Result<(), BootstrapError> {
        let now = now_ms();
        let expiry = now + self.config.replay_window_secs * 1000;
        let cache_key = signal_path.cache_key(session_id);
        let mut seen = self.seen_sessions.lock().await;
        seen.retain(|_, expires_at| *expires_at > now);
        if seen.contains_key(&cache_key) {
            return Err(BootstrapError::Replay(session_id.to_string()));
        }
        seen.insert(cache_key, expiry);
        if seen.len() > self.config.seen_sessions_max_entries {
            let mut oldest = seen
                .iter()
                .map(|(session, expires_at)| (session.clone(), *expires_at))
                .collect::<Vec<_>>();
            oldest.sort_by_key(|(_, expires_at)| *expires_at);
            let overflow = seen
                .len()
                .saturating_sub(self.config.seen_sessions_max_entries);
            for (session, _) in oldest.into_iter().take(overflow) {
                seen.remove(&session);
            }
            debug!(
                evicted = overflow,
                retained = seen.len(),
                cap = self.config.seen_sessions_max_entries,
                "seen traversal sessions overflow; evicted oldest entries"
            );
        }
        Ok(())
    }

    /// Record a NAT-traversal failure for `npub`, returning the
    /// resulting decision (WARN suppression + extended cooldown +
    /// threshold-crossing flag for the B6 re-fetch).
    pub fn record_traversal_failure(&self, npub: &str, now_ms: u64) -> NostrFailureDecision {
        let Ok(peer) = NostrPeerKey::parse(npub) else {
            return Self::empty_failure_decision();
        };
        Self::failure_decision_from(self.failure_state.record_failure(peer, now_ms))
    }

    pub(crate) fn record_traversal_failure_for_peer(
        &self,
        peer: PeerIdentity,
        now_ms: u64,
    ) -> NostrFailureDecision {
        Self::failure_decision_from(
            self.failure_state
                .record_failure(NostrPeerKey::from_peer_identity(peer), now_ms),
        )
    }

    /// Mark a traversal-backed path as unstable after it completed but later
    /// died under link liveness. This records diagnostics and threshold
    /// crossing without creating a new peer-wide cooldown; direct probing is
    /// paced by the node retry loop.
    pub fn record_unstable_path(&self, npub: &str, now_ms: u64) -> NostrFailureDecision {
        let Ok(peer) = NostrPeerKey::parse(npub) else {
            return Self::empty_failure_decision();
        };
        Self::failure_decision_from(self.failure_state.record_unstable_path(peer, now_ms))
    }

    pub(crate) fn record_unstable_path_for_peer(
        &self,
        peer: PeerIdentity,
        now_ms: u64,
    ) -> NostrFailureDecision {
        Self::failure_decision_from(
            self.failure_state
                .record_unstable_path(NostrPeerKey::from_peer_identity(peer), now_ms),
        )
    }

    /// Record a successful traversal — clears the streak/cooldown.
    pub fn record_traversal_success(&self, npub: &str, now_ms: u64) {
        if let Ok(peer) = NostrPeerKey::parse(npub) {
            self.failure_state.record_success(peer, now_ms);
        }
    }

    /// Cooldown wall-clock ms if the peer is currently suppressed,
    /// else None. Used by the open-discovery sweep to skip enqueue.
    pub fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        let Ok(peer) = NostrPeerKey::parse(npub) else {
            return None;
        };
        self.failure_state.cooldown_until(peer, now_ms)
    }

    pub(crate) fn cooldown_until_peer(&self, peer: PeerIdentity, now_ms: u64) -> Option<u64> {
        self.failure_state
            .cooldown_until(NostrPeerKey::from_peer_identity(peer), now_ms)
    }

    /// Record a fatal protocol mismatch (e.g. `Unknown FMP version` on a
    /// Nostr-adopted bootstrap transport). Returns `true` if this is a
    /// fresh observation worth a WARN log; `false` if the peer is already
    /// inside a comparable mismatch cooldown.
    ///
    /// The cooldown is `protocol_mismatch_cooldown_secs` from config —
    /// much longer than `extended_cooldown_secs` because mismatches are
    /// structural (only resolves when one side upgrades) rather than
    /// transient.
    pub fn record_protocol_mismatch(&self, npub: &str, now_ms: u64) -> bool {
        let Ok(peer) = NostrPeerKey::parse(npub) else {
            return false;
        };
        let cooldown_ms = self
            .config
            .protocol_mismatch_cooldown_secs
            .saturating_mul(1000);
        self.failure_state
            .record_protocol_mismatch(peer, now_ms, cooldown_ms)
    }

    /// Configured protocol-mismatch cooldown in seconds. Exposed so log
    /// emitters can include the duration without re-reading config.
    pub fn protocol_mismatch_cooldown_secs(&self) -> u64 {
        self.config.protocol_mismatch_cooldown_secs
    }

    /// Snapshot of per-npub failure state for `show_peers` rendering.
    pub fn failure_state_snapshot(&self) -> Vec<NostrPeerFailureView> {
        self.failure_state
            .snapshot()
            .into_iter()
            .map(|(peer, rec)| NostrPeerFailureView {
                npub: peer.npub(),
                consecutive_failures: rec.consecutive_failures,
                cooldown_until_ms: rec.cooldown_until_ms,
                last_observed_skew_ms: rec.last_observed_skew_ms,
            })
            .collect()
    }
}

fn event_channel_capacity(config: &NostrDiscoveryConfig) -> usize {
    let work_limit = config
        .open_discovery_max_pending
        .max(config.max_concurrent_incoming_offers)
        .max(1);

    // This channel carries traversal outcomes/signals back to the node, not
    // just permission to start new open-discovery work. Give it enough burst
    // room for roster peers, startup cache sweeps, and inbound offers without
    // turning the open-discovery cap into an event-loss trigger.
    work_limit.saturating_mul(4).clamp(64, 4096)
}
