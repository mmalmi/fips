use super::*;

impl NostrDiscovery {
    /// Build a minimal `NostrDiscovery` for unit tests. No relay client is
    /// connected and no background tasks are spawned; only the in-memory
    /// `advert_cache` and `npub` are usable. Intended for cache-injection
    /// tests of consumers (e.g. `Node::run_open_discovery_sweep`).
    pub(crate) fn new_for_test() -> Self {
        Self::new_for_test_with_config(NostrDiscoveryConfig::default())
    }

    pub(crate) fn new_for_test_with_config(config: NostrDiscoveryConfig) -> Self {
        let keys = nostr::Keys::generate();
        let pubkey = keys.public_key();
        let npub = pubkey.to_bech32().expect("bech32 encode");
        let client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();
        let offer_slots = Arc::new(Semaphore::new(config.max_concurrent_incoming_offers));
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
            relay_config: RwLock::new(NostrRelayConfig::from(&config)),
            config,
            advert_cache: RwLock::new(HashMap::new()),
            local_advert: RwLock::new(None),
            current_advert_event_id: RwLock::new(None),
            pending_answers: Mutex::new(HashMap::new()),
            active_initiators: Mutex::new(HashSet::new()),
            active_refetches: Mutex::new(HashSet::new()),
            seen_sessions: Mutex::new(HashMap::new()),
            offer_slots,
            event_tx,
            event_rx: Mutex::new(event_rx),
            mesh_signal_tx,
            mesh_signal_rx: Mutex::new(mesh_signal_rx),
            connect_task: Mutex::new(None),
            relay_startup_task: Mutex::new(None),
            publish_task: Mutex::new(None),
            publish_notify: Notify::new(),
            notify_task: Mutex::new(None),
            advertise_task: Mutex::new(None),
            failure_state,
            public_udp_addr_cache: RwLock::new(HashMap::new()),
            outbound_admission: AtomicBool::new(true),
            direct_refresh_admission: AtomicBool::new(true),
        }
    }

    /// Build a `CachedOverlayAdvert` for tests with a single endpoint and
    /// a generous validity window (one hour from `now_ms()`).
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
                signal_relays: None,
                stun_servers: None,
            },
            created_at: created_at_secs,
            valid_until_ms: now_ms().saturating_add(3_600_000),
        }
    }

    /// Insert a cached advert directly into the in-memory cache. Used by
    /// unit tests to set up consumer-side state without needing live relays.
    pub(crate) async fn insert_advert_for_test(&self, npub: String, advert: CachedOverlayAdvert) {
        let mut cache = self.advert_cache.write().await;
        cache.insert(NostrPeerKey::parse(&npub).expect("valid test npub"), advert);
    }

    /// Queue a bootstrap event directly for lifecycle tests without live relays
    /// or a running traversal task.
    pub(crate) fn push_event_for_test(&self, event: BootstrapEvent) {
        let _ = self.event_tx.try_send(event);
    }

    pub(crate) fn push_mesh_signal_for_test(&self, signal: MeshTraversalSignal) {
        let _ = self.mesh_signal_tx.try_send(signal);
    }

    pub(crate) async fn active_initiator_count_for_test(&self) -> usize {
        self.active_initiators.lock().await.len()
    }
}
