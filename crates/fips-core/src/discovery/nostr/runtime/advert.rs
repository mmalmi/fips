use super::*;

impl NostrDiscovery {
    pub(in crate::discovery::nostr) fn advert_event_targets_app(
        event: &Event,
        expected_app: &str,
    ) -> bool {
        event.kind == Kind::Custom(ADVERT_KIND)
            && event
                .tags
                .identifier()
                .is_some_and(|identifier| identifier == advert_d_tag(expected_app))
            && event
                .tags
                .find(TagKind::custom("protocol"))
                .and_then(|tag| tag.content())
                .is_some_and(|protocol| protocol == expected_app)
    }

    pub fn ambient_advert_filter(&self) -> Filter {
        Filter::new()
            .kind(Kind::Custom(ADVERT_KIND))
            .identifier(advert_d_tag(&self.config.app))
    }

    pub fn peer_advert_filter(&self, target_pubkey: PublicKey) -> Filter {
        self.ambient_advert_filter().author(target_pubkey)
    }

    /// Ingest a normal signed Nostr advert event from any peerfinding source.
    ///
    /// This is the adapter boundary for FIPS-carried pubsub, hashtree-backed
    /// history, and relay subscriptions: every source feeds ordinary kind
    /// 37195 events through the same signature, app, freshness, and schema
    /// checks before the advert becomes a cache candidate. Direct relay query
    /// remains only the fallback used when this cache has no usable entry.
    pub async fn ingest_advert_event(&self, event: &Event) -> NostrAdvertIngestOutcome {
        if !Self::advert_event_targets_app(event, &self.config.app) {
            return NostrAdvertIngestOutcome::Rejected;
        }
        let Some(valid_until_ms) = self.event_valid_until_ms(event) else {
            return NostrAdvertIngestOutcome::Rejected;
        };
        let Ok(verified_event) = VerifiedEvent::try_from(event) else {
            return NostrAdvertIngestOutcome::Rejected;
        };
        let author_key = NostrPeerKey::from_public_key_ref(verified_event.pubkey());
        let author_npub = verified_event.pubkey().to_bech32().expect("infallible");
        let Ok(advert) = Self::parse_overlay_advert_event(verified_event, &self.config.app) else {
            return NostrAdvertIngestOutcome::Rejected;
        };

        let created_at = event.created_at.as_secs();
        let mut cache = self.advert_cache.write().await;
        let existing_created_at = cache.get(&author_key).map(|existing| existing.created_at);
        if existing_created_at.is_some_and(|existing| existing > created_at) {
            return NostrAdvertIngestOutcome::Stale;
        }

        let outcome = if existing_created_at.is_some() {
            NostrAdvertIngestOutcome::Replaced
        } else {
            NostrAdvertIngestOutcome::Cached
        };
        if author_key != self.self_peer_key() {
            debug!(
                peer = %short_npub(&author_npub),
                endpoints = %endpoint_summary(&advert.endpoints),
                event = %short_id(&event.id.to_string()),
                "advert: peer cached"
            );
        }
        cache.insert(
            author_key,
            CachedOverlayAdvert {
                author_npub,
                advert,
                created_at,
                valid_until_ms,
            },
        );
        drop(cache);
        self.prune_advert_cache().await;
        outcome
    }

    /// Discover (or return cached) the public-Internet address for an
    /// advert-eligible UDP transport bound to a wildcard. Used by
    /// `build_overlay_advert` to avoid emitting `udp:0.0.0.0:port`,
    /// which is invalid as an advertised endpoint. Result is the
    /// reflexive IP (from STUN against the daemon's first
    /// `stun_servers` reachable) combined with the configured
    /// `advertise_port`.
    ///
    /// Asymmetric cache TTL: a successful observation is cached for
    /// `advert_refresh_secs` (default 1800 = same as advert refresh)
    /// so we don't re-STUN every refresh tick. A failed observation
    /// is cached for `PUBLIC_UDP_ADDR_FAILURE_TTL` (60s) so we retry
    /// soon after a transient STUN flake at startup, instead of
    /// blocking advertise-as-public for half an hour. Once a success
    /// is cached, subsequent ticks are zero-overhead.
    pub async fn learn_public_udp_addr(
        &self,
        transport_id_key: u32,
        advertise_port: u16,
    ) -> Option<SocketAddr> {
        if let Some(entry) = self
            .public_udp_addr_cache
            .read()
            .await
            .get(&transport_id_key)
        {
            let ttl = if entry.addr.is_some() {
                Duration::from_secs(self.config.advert_refresh_secs.max(60))
            } else {
                PUBLIC_UDP_ADDR_FAILURE_TTL
            };
            if entry.fetched_at.elapsed() < ttl {
                return entry.addr;
            }
        }
        let resolved = self.stun_observe_public_ip(advertise_port).await;
        let mut cache = self.public_udp_addr_cache.write().await;
        cache.insert(
            transport_id_key,
            CachedPublicUdpAddr {
                addr: resolved,
                fetched_at: Instant::now(),
            },
        );
        resolved
    }

    /// Run a one-shot STUN observation against an ephemeral UDP socket
    /// to learn this host's public IPv4 (or IPv6, if the local STUN
    /// server returns one). Returns `<reflexive_ip>:<advertise_port>`,
    /// or `None` if STUN failed or no `stun_servers` are configured.
    ///
    /// The STUN-reported port is the ephemeral source port and is
    /// discarded — what we want to advertise is the bound listener
    /// port, which the kernel preserves through 1:1 NAT (AWS EIP,
    /// GCP/Azure external IPs) and which the operator has explicitly
    /// chosen via `bind_addr`.
    async fn stun_observe_public_ip(&self, advertise_port: u16) -> Option<SocketAddr> {
        if self.config.stun_servers.is_empty() {
            return None;
        }
        let socket = match bind_traversal_udp_socket() {
            Ok(s) => s,
            Err(err) => {
                debug!(error = %err, "public-udp-addr: ephemeral bind failed");
                return None;
            }
        };
        let observed = match observe_traversal_addresses(
            &socket,
            &self.config.stun_servers,
            false,
            ADVERT_STUN_TIMEOUT,
        )
        .await
        {
            Ok((reflexive, _local, stun_server)) => {
                debug!(
                    stun = %stun_server.as_deref().unwrap_or("-"),
                    reflexive = %reflexive
                        .as_ref()
                        .map(|a| format!("{}:{}", a.ip, a.port))
                        .unwrap_or_else(|| "-".into()),
                    "public-udp-addr: STUN observation"
                );
                reflexive
            }
            Err(err) => {
                debug!(error = %err, "public-udp-addr: STUN failed");
                return None;
            }
        };
        observed.and_then(|addr| {
            let parsed_ip: std::net::IpAddr = addr.ip.parse().ok()?;
            Some(SocketAddr::new(parsed_ip, advertise_port))
        })
    }

    /// Stale-advert re-check (B6). Called by lifecycle on the
    /// streak-threshold transition. Actively re-queries the peer's
    /// Kind 37195 advert from `advert_relays`; evicts the cache entry
    /// if absent, refreshes if newer than the cached `created_at`,
    /// otherwise leaves the cache untouched.
    pub async fn refetch_advert_for_stale_check(&self, peer_npub: &str) -> NostrRefetchOutcome {
        let target_pubkey = match PublicKey::parse(peer_npub) {
            Ok(p) => p,
            Err(_) => return NostrRefetchOutcome::Skipped,
        };
        let peer_key = NostrPeerKey::from_public_key_ref(&target_pubkey);
        let relay_config = self.relay_config.read().await.clone();
        if relay_config.advert_relays.is_empty() {
            return NostrRefetchOutcome::Skipped;
        }
        let cached_created_at = self
            .advert_cache
            .read()
            .await
            .get(&peer_key)
            .map(|c| c.created_at);

        let events = match self
            .client
            .fetch_events_from(
                relay_config.advert_relays.clone(),
                self.peer_advert_filter(target_pubkey),
                Duration::from_secs(2),
            )
            .await
        {
            Ok(e) => e,
            Err(_) => return NostrRefetchOutcome::Skipped,
        };

        let mut newest: Option<(u64, &Event)> = None;
        for ev in events.iter() {
            let ts = ev.created_at.as_secs();
            match newest {
                Some((cur, _)) if ts <= cur => {}
                _ => newest = Some((ts, ev)),
            }
        }

        let Some((relay_created_at, ev)) = newest else {
            // Absent on relays. Evict any stale cache entry.
            self.advert_cache.write().await.remove(&peer_key);
            self.failure_state.reset_streak_after_refresh(peer_key);
            return NostrRefetchOutcome::Evicted;
        };

        match cached_created_at {
            Some(cached) if relay_created_at <= cached => NostrRefetchOutcome::SameAdvert,
            _ => {
                let Some(valid_until_ms) = self.event_valid_until_ms(ev) else {
                    return NostrRefetchOutcome::Skipped;
                };
                let Ok(verified_event) = VerifiedEvent::try_from(ev) else {
                    return NostrRefetchOutcome::Skipped;
                };
                let Ok(advert) = Self::parse_overlay_advert_event(verified_event, &self.config.app)
                else {
                    return NostrRefetchOutcome::Skipped;
                };
                let updated = CachedOverlayAdvert {
                    author_npub: peer_npub.to_string(),
                    advert,
                    created_at: relay_created_at,
                    valid_until_ms,
                };
                self.advert_cache.write().await.insert(peer_key, updated);
                self.failure_state.reset_streak_after_refresh(peer_key);
                NostrRefetchOutcome::Refreshed
            }
        }
    }

    pub async fn request_advert_stale_check(self: &Arc<Self>, peer_npub: String) -> bool {
        let Ok(peer_key) = NostrPeerKey::parse(&peer_npub) else {
            return false;
        };
        let relay_config = self.relay_config.read().await.clone();
        if relay_config.advert_relays.is_empty() {
            return false;
        }
        {
            let mut active = self.active_refetches.lock().await;
            if !active.insert(peer_key) {
                return false;
            }
        }

        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let outcome = runtime.refetch_advert_for_stale_check(&peer_npub).await;
            match outcome {
                NostrRefetchOutcome::Evicted => info!(
                    npub = %peer_npub,
                    "stale-advert sweep: peer evicted from advert cache"
                ),
                NostrRefetchOutcome::Refreshed => info!(
                    npub = %peer_npub,
                    "stale-advert sweep: peer republished, cache refreshed and streak reset"
                ),
                NostrRefetchOutcome::SameAdvert => debug!(
                    npub = %peer_npub,
                    "stale-advert sweep: relay still has same advert"
                ),
                NostrRefetchOutcome::Skipped => debug!(
                    npub = %peer_npub,
                    "stale-advert sweep: skipped"
                ),
            }
            runtime.active_refetches.lock().await.remove(&peer_key);
        });
        true
    }

    pub async fn update_local_advert(
        self: &Arc<Self>,
        advert: Option<OverlayAdvert>,
    ) -> Result<(), BootstrapError> {
        let changed = {
            let mut slot = self.local_advert.write().await;
            if *slot == advert {
                false
            } else {
                *slot = advert;
                true
            }
        };
        if !changed {
            return Ok(());
        }
        self.request_publish_advert();
        Ok(())
    }

    pub async fn local_advert_endpoints(&self) -> Vec<OverlayEndpointAdvert> {
        self.local_advert
            .read()
            .await
            .as_ref()
            .map(|advert| advert.endpoints.clone())
            .unwrap_or_default()
    }

    pub async fn advert_endpoints_for_peer(
        &self,
        peer_npub: &str,
    ) -> Result<Vec<OverlayEndpointAdvert>, BootstrapError> {
        let target_pubkey =
            PublicKey::parse(peer_npub).map_err(|e| BootstrapError::InvalidPeerNpub {
                npub: peer_npub.to_string(),
                reason: e.to_string(),
            })?;
        let advert = self.fetch_advert(peer_npub, target_pubkey).await?;
        Ok(advert.endpoints)
    }

    pub async fn cached_advert_endpoints_for_peer(
        &self,
        peer_npub: &str,
    ) -> Option<Vec<OverlayEndpointAdvert>> {
        self.cached_advert_endpoints_with_created_at_for_peer(peer_npub)
            .await
            .map(|(endpoints, _)| endpoints)
    }

    pub async fn cached_advert_endpoints_with_created_at_for_peer(
        &self,
        peer_npub: &str,
    ) -> Option<(Vec<OverlayEndpointAdvert>, u64)> {
        let peer_key = NostrPeerKey::parse(peer_npub).ok()?;
        self.prune_advert_cache().await;
        let now = now_ms();
        self.advert_cache
            .read()
            .await
            .get(&peer_key)
            .filter(|cached| cached.valid_until_ms > now)
            .map(|cached| (cached.advert.endpoints.clone(), cached.created_at))
    }

    pub async fn cached_open_discovery_candidates(
        &self,
        max: usize,
    ) -> Vec<(String, Vec<OverlayEndpointAdvert>, u64)> {
        self.prune_advert_cache().await;
        let now = now_ms();
        let self_key = self.self_peer_key();
        let cache = self.advert_cache.read().await;
        cache
            .iter()
            .filter(|(peer_key, _)| **peer_key != self_key)
            .map(|(_, entry)| entry)
            .filter(|entry| entry.valid_until_ms > now)
            .map(|entry| {
                (
                    entry.author_npub.clone(),
                    entry.advert.endpoints.clone(),
                    entry.created_at,
                )
            })
            .take(max)
            .collect()
    }

    pub(super) async fn publish_advert(&self) -> Result<(), BootstrapError> {
        let previous_event_id = self.current_advert_event_id.read().await.to_owned();
        if !self.config.advertise {
            if let Some(event_id) = previous_event_id {
                let relay_config = self.relay_config.read().await.clone();
                self.publish_delete(&relay_config.advert_relays, [event_id])
                    .await?;
                *self.current_advert_event_id.write().await = None;
            }
            return Ok(());
        }

        let mut advert = match self.local_advert.read().await.clone() {
            Some(advert) => advert,
            // Transient absence (e.g., a single tick during startup where
            // build_overlay_advert briefly returns None). Don't proactively
            // emit a NIP-09 delete: the next publish supersedes the old
            // event via parameterized-replaceable semantics, and the NIP-40
            // expiration tag bounds the worst case if we never re-publish.
            None => return Ok(()),
        };

        advert.identifier = ADVERT_IDENTIFIER.to_string();
        advert.version = ADVERT_VERSION;
        advert.endpoints.retain(endpoint_advert_is_publicly_usable);
        // Defensive: build_overlay_advert returns None on empty endpoints,
        // so this is only reachable from non-lifecycle callers.
        if advert.endpoints.is_empty() {
            return Ok(());
        }

        if advert.has_udp_nat_endpoint() {
            if advert
                .signal_relays
                .as_ref()
                .is_none_or(|relays| relays.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires non-empty signalRelays".to_string(),
                ));
            }
            if advert
                .stun_servers
                .as_ref()
                .is_none_or(|servers| servers.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires non-empty stunServers".to_string(),
                ));
            }
        } else {
            advert.signal_relays = None;
            advert.stun_servers = None;
        }

        let expires_at = now_ms() + self.config.advert_ttl_secs * 1000;
        let tags = vec![
            Tag::identifier(advert_d_tag(&self.config.app)),
            Tag::custom(TagKind::custom("protocol"), [self.config.app.clone()]),
            Tag::custom(TagKind::custom("version"), [PROTOCOL_VERSION.to_string()]),
            Tag::expiration(Timestamp::from((expires_at / 1000).max(1))),
        ];

        let event = EventBuilder::new(Kind::Custom(ADVERT_KIND), serde_json::to_string(&advert)?)
            .tags(tags)
            .sign_with_keys(&self.keys)
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        let relay_config = self.relay_config.read().await.clone();
        self.client
            .send_event_to(relay_config.advert_relays.clone(), &event)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        debug!(
            event = %short_id(&event.id.to_string()),
            relays = relay_config.advert_relays.len(),
            endpoints = %endpoint_summary(&advert.endpoints),
            ttl_secs = self.config.advert_ttl_secs,
            "advert: published"
        );
        // Kind 37195 lives in NIP-01's parameterized replaceable range
        // (30000–39999). Relays supersede the previous event for the same
        // (pubkey, kind, d-tag) triple by created_at — emitting an explicit
        // NIP-09 delete here is redundant and races with the replacement
        // publish, which strict relays (e.g. Damus) honor by removing the
        // new advert too.
        *self.current_advert_event_id.write().await = Some(event.id);
        Ok(())
    }

    pub(super) async fn fetch_advert(
        &self,
        peer_npub: &str,
        target_pubkey: PublicKey,
    ) -> Result<OverlayAdvert, BootstrapError> {
        let peer_key = NostrPeerKey::from_public_key_ref(&target_pubkey);
        self.prune_advert_cache().await;
        if let Some(cached) = self.advert_cache.read().await.get(&peer_key).cloned() {
            debug!(
                peer = %short_npub(peer_npub),
                source = "cache",
                endpoints = %endpoint_summary(&cached.advert.endpoints),
                "advert: resolved"
            );
            return Ok(cached.advert);
        }

        let relay_config = self.relay_config.read().await.clone();
        if relay_config.advert_relays.is_empty() {
            return Err(BootstrapError::MissingAdvert(peer_npub.to_string()));
        }
        let events = self
            .client
            .fetch_events_from(
                relay_config.advert_relays.clone(),
                self.peer_advert_filter(target_pubkey),
                Duration::from_secs(2),
            )
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

        let mut best: Option<CachedOverlayAdvert> = None;
        for event in events.iter() {
            let Some(valid_until_ms) = self.event_valid_until_ms(event) else {
                continue;
            };
            let Ok(verified_event) = VerifiedEvent::try_from(event) else {
                continue;
            };
            if *verified_event.pubkey() != target_pubkey {
                continue;
            }
            let Ok(advert) = Self::parse_overlay_advert_event(verified_event, &self.config.app)
            else {
                continue;
            };
            let replace = best
                .as_ref()
                .map(|current| event.created_at.as_secs() >= current.created_at)
                .unwrap_or(true);
            if replace {
                best = Some(CachedOverlayAdvert {
                    author_npub: peer_npub.to_string(),
                    advert,
                    created_at: event.created_at.as_secs(),
                    valid_until_ms,
                });
            }
        }

        let cached = best.ok_or_else(|| BootstrapError::MissingAdvert(peer_npub.to_string()))?;
        debug!(
            peer = %short_npub(peer_npub),
            source = "relay-fetch-fallback",
            endpoints = %endpoint_summary(&cached.advert.endpoints),
            "advert: resolved"
        );
        self.advert_cache
            .write()
            .await
            .insert(peer_key, cached.clone());
        self.prune_advert_cache().await;
        Ok(cached.advert)
    }

    pub(in crate::discovery::nostr) fn parse_overlay_advert_event(
        event: VerifiedEvent<'_>,
        expected_app: &str,
    ) -> Result<OverlayAdvert, BootstrapError> {
        let event = event.as_event();
        if event.kind != Kind::Custom(ADVERT_KIND) {
            return Err(BootstrapError::InvalidAdvert(
                "unexpected advert event kind".to_string(),
            ));
        }

        let advertised_app = event
            .tags
            .find(TagKind::custom("protocol"))
            .and_then(|tag| tag.content())
            .ok_or_else(|| {
                BootstrapError::InvalidAdvert("missing required protocol tag".to_string())
            })?;
        if advertised_app != expected_app {
            return Err(BootstrapError::InvalidAdvert(format!(
                "unsupported protocol '{}'",
                advertised_app
            )));
        }

        let advert: OverlayAdvert = serde_json::from_str(&event.content)?;
        Self::validate_overlay_advert(advert)
    }

    pub(in crate::discovery::nostr) fn validate_overlay_advert(
        mut advert: OverlayAdvert,
    ) -> Result<OverlayAdvert, BootstrapError> {
        if advert.identifier != ADVERT_IDENTIFIER {
            return Err(BootstrapError::InvalidAdvert(format!(
                "unsupported identifier '{}'",
                advert.identifier
            )));
        }
        if advert.version != ADVERT_VERSION {
            return Err(BootstrapError::InvalidAdvert(format!(
                "unsupported version '{}'",
                advert.version
            )));
        }
        if advert.endpoints.is_empty() {
            return Err(BootstrapError::InvalidAdvert(
                "missing required endpoints".to_string(),
            ));
        }
        advert.endpoints.retain(endpoint_advert_is_publicly_usable);
        if advert.endpoints.is_empty() {
            return Err(BootstrapError::InvalidAdvert(
                "missing publicly routable endpoints".to_string(),
            ));
        }

        let has_nat = advert.has_udp_nat_endpoint();
        let has_webrtc = advert
            .endpoints
            .iter()
            .any(|endpoint| endpoint.transport == OverlayTransportKind::WebRtc);
        if has_nat {
            if advert
                .signal_relays
                .as_ref()
                .is_none_or(|relays| relays.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires signalRelays".to_string(),
                ));
            }
            if advert
                .stun_servers
                .as_ref()
                .is_none_or(|servers| servers.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires stunServers".to_string(),
                ));
            }
        } else if has_webrtc {
            if advert
                .signal_relays
                .as_ref()
                .is_none_or(|relays| relays.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "webrtc endpoint requires signalRelays".to_string(),
                ));
            }
        } else {
            advert.signal_relays = None;
            advert.stun_servers = None;
        }

        Ok(advert)
    }

    pub(super) async fn prune_advert_cache(&self) {
        let now = now_ms();
        let mut cache = self.advert_cache.write().await;
        cache.retain(|_, entry| entry.valid_until_ms > now);
        if cache.len() <= self.config.advert_cache_max_entries {
            return;
        }

        let mut oldest = cache
            .iter()
            .map(|(peer_key, entry)| (*peer_key, entry.valid_until_ms))
            .collect::<Vec<_>>();
        oldest.sort_by_key(|(_, ts)| *ts);
        let overflow = cache
            .len()
            .saturating_sub(self.config.advert_cache_max_entries);
        for (peer_key, _) in oldest.into_iter().take(overflow) {
            cache.remove(&peer_key);
        }
        debug!(
            evicted = overflow,
            retained = cache.len(),
            cap = self.config.advert_cache_max_entries,
            "advert cache overflow; evicted oldest entries"
        );
    }

    fn advert_max_age_ms(&self) -> u64 {
        self.config.advert_ttl_secs * 1000 * ADVERT_CACHE_STALE_GRACE_MULTIPLIER
    }

    pub(super) fn event_valid_until_ms(&self, event: &Event) -> Option<u64> {
        Self::compute_advert_valid_until_ms(event, self.advert_max_age_ms(), now_ms())
    }

    pub(in crate::discovery::nostr) fn compute_advert_valid_until_ms(
        event: &Event,
        advert_max_age_ms: u64,
        now_ms: u64,
    ) -> Option<u64> {
        if event.is_expired() {
            return None;
        }

        let created_ms = event.created_at.as_secs().saturating_mul(1000);
        let created_window_until = created_ms.saturating_add(advert_max_age_ms);
        if created_window_until <= now_ms {
            return None;
        }

        let expires_ms = event
            .tags
            .expiration()
            .map(|timestamp| timestamp.as_secs().saturating_mul(1000));
        let valid_until_ms = expires_ms
            .map(|expires| expires.min(created_window_until))
            .unwrap_or(created_window_until);

        (valid_until_ms > now_ms).then_some(valid_until_ms)
    }
}
