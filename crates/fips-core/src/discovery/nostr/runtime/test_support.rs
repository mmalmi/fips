use super::*;

impl NostrDiscovery {
    #[cfg(test)]
    pub(crate) fn new_for_test_with_bind_interface(
        bind_interface: Option<String>,
    ) -> Arc<NostrDiscovery> {
        Arc::new(Self::new_for_test_with_config(NostrDiscoveryConfig {
            bind_interface,
            ..NostrDiscoveryConfig::default()
        }))
    }

    #[cfg(test)]
    pub(crate) async fn bind_interface_for_test(&self) -> Option<String> {
        self.bind_interface.read().await.clone()
    }

    /// Build a minimal `NostrDiscovery` for unit tests. No relay client is
    /// connected and no background tasks are spawned; only the in-memory
    /// `advert_cache` and `npub` are usable. Intended for cache-injection
    /// tests of consumers (e.g. `Node::run_open_discovery_sweep`).
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self::new_for_test_with_config(NostrDiscoveryConfig::default())
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_identity(identity: &crate::Identity) -> Self {
        let mut discovery = Self::new_for_test();
        let keys = nostr::Keys::parse(&hex::encode(identity.keypair().secret_bytes()))
            .expect("test identity key");
        discovery.client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();
        discovery.pubkey = keys.public_key();
        discovery.npub = identity.npub();
        discovery.keys = keys;
        discovery
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_config(config: NostrDiscoveryConfig) -> Self {
        Self::new_unstarted_with_config(config)
    }

    #[cfg(feature = "sim-transport")]
    pub fn new_for_sim_with_config(config: NostrDiscoveryConfig) -> Self {
        Self::new_unstarted_with_config(config)
    }

    #[cfg(any(test, feature = "sim-transport"))]
    fn new_unstarted_with_config(config: NostrDiscoveryConfig) -> Self {
        let keys = nostr::Keys::generate();
        let pubkey = keys.public_key();
        let npub = pubkey.to_bech32().expect("bech32 encode");
        let client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();
        let offer_admission = OfferAdmission::new(
            config.max_concurrent_incoming_offers,
            config.max_concurrent_offers_per_npub,
        );
        let (event_tx, event_rx) = mpsc::channel(event_channel_capacity(&config));
        let (mesh_signal_tx, mesh_signal_rx) = mpsc::channel(event_channel_capacity(&config));
        let failure_state = FailureState::new(
            config.failure_streak_threshold,
            config.extended_cooldown_secs,
            config.warn_log_interval_secs,
            config.failure_state_max_entries,
        );
        Self {
            client,
            keys,
            pubkey,
            npub,
            bind_interface: RwLock::new(config.bind_interface.clone()),
            relay_config: RwLock::new(AdvertRelayConfig::from(&config)),
            config,
            advert_cache: RwLock::new(HashMap::new()),
            peer_trust_scores: RwLock::new(HashMap::new()),
            local_advert: RwLock::new(None),
            current_advert_event_id: RwLock::new(None),
            pending_answers: Mutex::new(HashMap::new()),
            answered_offers: Mutex::new(HashMap::new()),
            active_initiators: Mutex::new(HashMap::new()),
            active_refetches: Mutex::new(HashSet::new()),
            seen_sessions: Mutex::new(HashMap::new()),
            #[cfg(test)]
            received_mesh_offer_count: std::sync::atomic::AtomicUsize::new(0),
            offer_admission,
            event_tx,
            event_rx: Mutex::new(event_rx),
            mesh_signal_tx,
            mesh_signal_rx: Mutex::new(mesh_signal_rx),
            node_event_notify: Arc::new(Notify::new()),
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
        }
    }

    #[cfg(feature = "sim-transport")]
    pub async fn process_rating_fact_event_for_sim(&self, event: &nostr::Event) -> bool {
        self.process_rating_fact_event(event).await
    }

    #[cfg(feature = "sim-transport")]
    pub async fn process_advert_event_for_sim(&self, event: &nostr::Event) -> bool {
        self.ingest_advert_event(event).await.cached()
    }

    #[cfg(feature = "sim-transport")]
    pub async fn trust_scores_for_npubs_for_sim(&self, npubs: &[String]) -> HashMap<String, i64> {
        self.trust_scores_for_npubs(npubs).await
    }

    /// Build a `CachedOverlayAdvert` for tests with a single endpoint and
    /// a generous validity window (one hour from `now_ms()`).
    #[cfg(test)]
    pub(crate) fn cached_advert_for_test(
        author_npub: String,
        endpoint: OverlayEndpointAdvert,
        created_at_secs: u64,
    ) -> CachedOverlayAdvert {
        CachedOverlayAdvert {
            author_npub: author_npub.clone(),
            advert: OverlayAdvert {
                identifier: ADVERT_IDENTIFIER.to_string(),
                version: ADVERT_VERSION,
                endpoints: vec![endpoint],
                stun_servers: None,
            },
            created_at: created_at_secs,
            valid_until_ms: now_ms().saturating_add(3_600_000),
        }
    }

    /// Insert a cached advert directly into the in-memory cache. Used by
    /// unit tests to set up consumer-side state without needing live relays.
    #[cfg(test)]
    pub(crate) async fn insert_advert_for_test(&self, npub: String, advert: CachedOverlayAdvert) {
        let mut cache = self.advert_cache.write().await;
        cache.insert(NostrPeerKey::parse(&npub).expect("valid test npub"), advert);
    }

    /// Queue a bootstrap event directly for lifecycle tests without live relays
    /// or a running traversal task.
    #[cfg(test)]
    pub(crate) fn push_event_for_test(&self, event: BootstrapEvent) {
        let _ = self.event_tx.try_send(event);
    }

    #[cfg(test)]
    pub(crate) async fn emit_event_for_test(&self, event: BootstrapEvent) {
        self.emit_event(event).await;
    }

    #[cfg(test)]
    pub(crate) fn push_mesh_signal_for_test(&self, signal: MeshTraversalSignal) {
        let _ = self.mesh_signal_tx.try_send(signal);
    }

    #[cfg(test)]
    pub(crate) async fn emit_mesh_signal_for_test(&self, signal: MeshTraversalSignal) -> bool {
        self.emit_mesh_signal(signal).await
    }

    #[cfg(test)]
    pub(crate) fn npub_for_test(&self) -> String {
        self.npub.clone()
    }

    #[cfg(test)]
    pub(crate) fn received_mesh_offer_count_for_test(&self) -> usize {
        self.received_mesh_offer_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) async fn active_initiator_count_for_test(&self) -> usize {
        self.active_initiators.lock().await.len()
    }

    #[cfg(test)]
    pub(crate) async fn start_pending_initiator_for_test(&self, npub: &str) {
        self.active_initiators.lock().await.insert(
            NostrPeerKey::parse(npub).expect("valid test npub"),
            now_ms(),
        );
        assert!(
            self.spawn_child_task(std::future::pending()).await,
            "test discovery should accept a pending traversal task"
        );
    }

    #[cfg(test)]
    pub(crate) async fn accept_incoming_offer_for_test(&self, session_id: &str) -> bool {
        self.accept_incoming_offer_session(session_id).await
    }
}
