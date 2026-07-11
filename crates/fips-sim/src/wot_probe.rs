#[derive(Debug, Clone)]
struct WotProbeObservation {
    rating: Option<i64>,
    source: WotRatingEventSource,
    valid_payload: bool,
    timed_out: bool,
    useful_bytes: usize,
    junk_bytes: usize,
    low_throughput_valid_payload: bool,
    network_delta: SimNetworkStats,
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

#[derive(Debug, Clone, Copy)]
struct WotProbeMetrics {
    srtt_ms: f64,
    goodput_bps: f64,
    smoothed_loss: f64,
    smoothed_etx: f64,
    delivery_ratio: f64,
}

struct WotProbeRuntime {
    network_id: String,
    network: SimNetwork,
    local: WotProbeEndpoint,
    peers: BTreeMap<String, WotProbeEndpoint>,
}

struct WotProbeEndpoint {
    peer_identity: PeerIdentity,
    endpoint: FipsEndpoint,
}

#[derive(Debug, Clone)]
struct WotProbeNodeSpec {
    npub: String,
    peer_identity: PeerIdentity,
    secret_hex: String,
    sim_addr: String,
    alias: String,
}

impl WotProbeRuntime {
    async fn start(peers: &[WotPeerSpec]) -> Result<Self, String> {
        let network_id = format!(
            "fips-wot-probe-{WOT_PROBE_NETWORK_SEED:x}-{}",
            rand::random::<u64>()
        );
        let network = SimNetwork::new(WOT_PROBE_NETWORK_SEED);
        let local_node =
            wot_probe_node_for_seed(LOCAL_RATER_SEED, WOT_PROBE_LOCAL_ADDR, "local-rater");
        let peer_nodes = peers
            .iter()
            .map(wot_probe_node_for_peer)
            .collect::<Vec<_>>();

        for (peer, node) in peers.iter().zip(peer_nodes.iter()) {
            network.set_link(
                local_node.sim_addr.clone(),
                node.sim_addr.clone(),
                probe_link_for_profile(peer.profile),
            );
        }
        register_sim_network(network_id.clone(), network.clone());

        let local_peer_configs = peer_nodes
            .iter()
            .map(peer_config_for_probe_node)
            .collect::<Vec<_>>();
        let local_endpoint = match bind_wot_probe_endpoint(wot_probe_endpoint_config(
            &network_id,
            &local_node,
            local_peer_configs,
        ))
        .await
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                unregister_sim_network(&network_id);
                return Err(error);
            }
        };

        let mut peer_endpoints: BTreeMap<String, WotProbeEndpoint> = BTreeMap::new();
        for (peer, node) in peers.iter().zip(peer_nodes.iter()) {
            let config = wot_probe_endpoint_config(
                &network_id,
                node,
                vec![peer_config_for_probe_node(&local_node)],
            );
            let endpoint = match bind_wot_probe_endpoint(config).await {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    for (_, endpoint) in peer_endpoints {
                        let _ = endpoint.endpoint.shutdown().await;
                    }
                    let _ = local_endpoint.shutdown().await;
                    unregister_sim_network(&network_id);
                    return Err(error);
                }
            };
            peer_endpoints.insert(
                peer.id.clone(),
                WotProbeEndpoint {
                    peer_identity: node.peer_identity,
                    endpoint,
                },
            );
        }

        tokio::time::sleep(Duration::from_millis(WOT_PROBE_CONVERGENCE_MS)).await;
        Ok(Self {
            network_id,
            network,
            local: WotProbeEndpoint {
                peer_identity: local_node.peer_identity,
                endpoint: local_endpoint,
            },
            peers: peer_endpoints,
        })
    }

    async fn observed_rating_for_probe(
        &mut self,
        peer: &WotPeerSpec,
        degradation_seen: bool,
        created_at: u64,
    ) -> WotProbeObservation {
        let expected_payload = expected_probe_payload(peer, created_at);
        let before = self.network.stats();
        let received_payload = self
            .run_probe_transfer(peer, degradation_seen, &expected_payload)
            .await;
        let network_delta = self.network.stats().delta_since(&before);
        let timed_out = received_payload.is_empty();
        let valid_payload = !timed_out && received_payload == expected_payload;
        let useful_bytes = valid_payload
            .then_some(received_payload.len())
            .unwrap_or_default();
        let junk_bytes = (!valid_payload && !timed_out)
            .then_some(received_payload.len())
            .unwrap_or_default();
        let metrics = probe_metrics_for_profile(peer.profile);
        let transfer = WotProbeTransfer {
            received_payload,
            srtt_ms: metrics.srtt_ms,
            goodput_bps: metrics.goodput_bps,
            smoothed_loss: metrics.smoothed_loss,
            smoothed_etx: metrics.smoothed_etx,
            delivery_ratio: metrics.delivery_ratio,
            decrypt_failures: if valid_payload || timed_out { 0 } else { 4 },
            replay_suppressed: if valid_payload || timed_out { 0 } else { 6 },
        };
        let low_throughput_valid_payload = valid_payload && transfer.goodput_bps < 1_000_000.0;
        let rating = (!timed_out)
            .then(|| rating_peer_value(peer, &transfer, valid_payload))
            .and_then(|rating_peer| compute_peer_rating(&rating_peer).map(|health| health.score));
        let source =
            if peer.profile == WotPeerProfile::Degrading && degradation_seen && !valid_payload {
                WotRatingEventSource::LocalDegradation
            } else {
                WotRatingEventSource::LocalProbe
            };
        WotProbeObservation {
            rating,
            source,
            valid_payload,
            timed_out,
            useful_bytes,
            junk_bytes,
            low_throughput_valid_payload,
            network_delta,
        }
    }

    async fn run_probe_transfer(
        &self,
        peer: &WotPeerSpec,
        degradation_seen: bool,
        expected_payload: &[u8],
    ) -> Vec<u8> {
        let Some(remote) = self.peers.get(&peer.id) else {
            return Vec::new();
        };
        let timeout = Duration::from_millis(WOT_PROBE_TIMEOUT_MS);
        if self
            .local
            .endpoint
            .send_batch_to_peer(remote.peer_identity, vec![expected_payload.to_vec()])
            .await
            .is_err()
        {
            return Vec::new();
        }
        if !recv_probe_exact(&remote.endpoint, expected_payload, timeout).await {
            return Vec::new();
        }

        let response = if profile_returns_junk(peer.profile, degradation_seen) {
            junk_probe_payload(expected_payload)
        } else {
            expected_payload.to_vec()
        };
        if remote
            .endpoint
            .send_batch_to_peer(self.local.peer_identity, vec![response])
            .await
            .is_err()
        {
            return Vec::new();
        }
        recv_probe_payload(&self.local.endpoint, timeout)
            .await
            .unwrap_or_default()
    }

    async fn shutdown(self) -> Result<(), String> {
        let mut shutdown_error = None;
        for (_, endpoint) in self.peers {
            if let Err(error) = endpoint.endpoint.shutdown().await {
                shutdown_error = Some(error.to_string());
            }
        }
        if let Err(error) = self.local.endpoint.shutdown().await {
            shutdown_error = Some(error.to_string());
        }
        unregister_sim_network(&self.network_id);
        if let Some(error) = shutdown_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

fn expected_probe_payload(peer: &WotPeerSpec, created_at: u64) -> Vec<u8> {
    let prefix = format!("fips-wot-probe|{}|{created_at}|", peer.id);
    super::fixed_payload(prefix.as_bytes(), 1024)
}

async fn bind_wot_probe_endpoint(config: Config) -> Result<FipsEndpoint, String> {
    FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .packet_channel_capacity(8192)
        .bind()
        .await
        .map_err(|error| error.to_string())
}

fn wot_probe_endpoint_config(
    network_id: &str,
    node: &WotProbeNodeSpec,
    peers: Vec<PeerConfig>,
) -> Config {
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(node.secret_hex.clone()),
        persistent: false,
    };
    config.node.limits.max_connections = 64;
    config.node.limits.max_peers = 64;
    config.node.limits.max_links = 64;
    config.node.limits.max_pending_inbound = 256;
    config.node.rate_limit.handshake_burst = 10_000;
    config.node.rate_limit.handshake_rate = 10_000.0;
    config.node.rate_limit.handshake_timeout_secs = 8;
    config.node.rate_limit.handshake_resend_interval_ms = 100;
    config.node.rate_limit.handshake_max_resends = 20;
    config.node.retry.base_interval_secs = 1;
    config.node.retry.max_retries = 20;
    config.node.retry.max_backoff_secs = 4;
    config.node.discovery.attempt_timeouts_secs = vec![1, 1, 2];
    config.node.discovery.forward_min_interval_secs = 0;
    config.node.tree.announce_min_interval_ms = 25;
    config.node.tree.parent_hysteresis = 0.0;
    config.node.tree.hold_down_secs = 0;
    config.node.tree.reeval_interval_secs = 1;
    config.node.heartbeat_interval_secs = 1;
    config.node.link_dead_timeout_secs = 4;
    config.tun.enabled = false;
    config.dns.enabled = false;
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network_id.to_string()),
        addr: Some(node.sim_addr.clone()),
        mtu: Some(1280),
        auto_connect: Some(false),
        accept_connections: Some(true),
    });
    config.peers = peers;
    config
}

fn peer_config_for_probe_node(node: &WotProbeNodeSpec) -> PeerConfig {
    PeerConfig::new(node.npub.clone(), "sim", node.sim_addr.clone()).with_alias(node.alias.clone())
}

fn wot_probe_node_for_peer(peer: &WotPeerSpec) -> WotProbeNodeSpec {
    let seed = seed_for_peer_profile(peer.profile);
    let node = wot_probe_node_for_seed(seed, probe_addr_for_profile(peer.profile), "tracked-peer");
    debug_assert_eq!(node.npub, peer.id);
    node
}

fn wot_probe_node_for_seed(
    seed: u64,
    sim_addr: impl Into<String>,
    alias: impl Into<String>,
) -> WotProbeNodeSpec {
    let (identity, secret_hex) = sim_identity(seed);
    WotProbeNodeSpec {
        npub: identity.npub(),
        peer_identity: PeerIdentity::from_pubkey_full(identity.pubkey_full()),
        secret_hex,
        sim_addr: sim_addr.into(),
        alias: alias.into(),
    }
}

fn probe_addr_for_profile(profile: WotPeerProfile) -> String {
    format!("wot-probe-peer-{}", seed_for_peer_profile(profile))
}

fn probe_link_for_profile(profile: WotPeerProfile) -> SimLink {
    let (latency_ms, throughput_mbps) = match profile {
        WotPeerProfile::Reliable => (6, 25.0),
        WotPeerProfile::BackupReliable => (35, 8.0),
        WotPeerProfile::Newcomer => (25, 6.0),
        WotPeerProfile::Degrading => (10, 15.0),
        WotPeerProfile::Bad => (10, 15.0),
    };
    SimLink {
        latency_ms,
        throughput_mbps,
        loss_probability: 0.0,
        up: true,
    }
}

fn probe_metrics_for_profile(profile: WotPeerProfile) -> WotProbeMetrics {
    let (srtt_ms, goodput_bps) = match profile {
        WotPeerProfile::Reliable => (24.0, 8_000_000.0),
        WotPeerProfile::BackupReliable => (95.0, 120_000.0),
        WotPeerProfile::Newcomer => (80.0, 80_000.0),
        WotPeerProfile::Degrading => (30.0, 6_000_000.0),
        WotPeerProfile::Bad => (0.0, 0.0),
    };
    WotProbeMetrics {
        srtt_ms,
        goodput_bps,
        smoothed_loss: if matches!(profile, WotPeerProfile::Bad) {
            0.0
        } else {
            0.001
        },
        smoothed_etx: if srtt_ms <= 50.0 { 1.01 } else { 1.10 },
        delivery_ratio: if matches!(profile, WotPeerProfile::Bad) {
            0.0
        } else {
            0.999
        },
    }
}

fn profile_returns_junk(profile: WotPeerProfile, degradation_seen: bool) -> bool {
    matches!(profile, WotPeerProfile::Bad)
        || (profile == WotPeerProfile::Degrading && degradation_seen)
}

async fn recv_probe_exact(endpoint: &FipsEndpoint, expected: &[u8], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut messages = Vec::new();
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        let Some(received) = recv_endpoint_batch_into(endpoint, &mut messages, remaining).await
        else {
            return false;
        };
        for message in messages.iter().take(received) {
            if message.data.as_slice() == expected {
                return true;
            }
        }
    }
}

async fn recv_probe_payload(endpoint: &FipsEndpoint, timeout: Duration) -> Option<Vec<u8>> {
    let mut messages = Vec::new();
    recv_endpoint_batch_into(endpoint, &mut messages, timeout).await?;
    messages
        .first()
        .map(|message| message.data.as_slice().to_vec())
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
    sim_keys(seed_for_peer_profile(profile))
}

fn seed_for_peer_profile(profile: WotPeerProfile) -> u64 {
    match profile {
        WotPeerProfile::Reliable => 11,
        WotPeerProfile::BackupReliable => 12,
        WotPeerProfile::Newcomer => 13,
        WotPeerProfile::Degrading => 14,
        WotPeerProfile::Bad => 15,
    }
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

fn sim_identity(seed: u64) -> (Identity, String) {
    let bytes = sim_secret_bytes(seed);
    (
        Identity::from_secret_bytes(&bytes).expect("valid deterministic FIPS sim identity"),
        hex::encode(bytes),
    )
}

fn sim_keys(seed: u64) -> nostr::Keys {
    nostr::Keys::parse(&hex::encode(sim_secret_bytes(seed))).expect("valid deterministic sim key")
}

fn sim_secret_bytes(seed: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&seed.max(1).to_be_bytes());
    bytes
}
