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
