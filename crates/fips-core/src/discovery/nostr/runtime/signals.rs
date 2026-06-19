use super::*;

impl NostrDiscovery {
    pub(super) async fn preferred_signal_relays(
        &self,
        target_pubkey: PublicKey,
        advert: Option<&OverlayAdvert>,
    ) -> Result<Vec<String>, BootstrapError> {
        let mut merged = self.find_recipient_inbox_relays(target_pubkey).await?;
        if let Some(advert) = advert
            && let Some(relays) = advert.signal_relays.as_ref()
        {
            for relay in relays {
                if !merged.contains(relay) {
                    merged.push(relay.clone());
                }
            }
        }
        let relay_config = self.relay_config.read().await.clone();
        for relay in &relay_config.dm_relays {
            if !merged.contains(relay) {
                merged.push(relay.clone());
            }
        }
        Ok(merged)
    }

    async fn find_recipient_inbox_relays(
        &self,
        target_pubkey: PublicKey,
    ) -> Result<Vec<String>, BootstrapError> {
        let relay_config = self.relay_config.read().await.clone();
        let mut lookup_relays = relay_config.dm_relays.clone();
        for relay in &relay_config.advert_relays {
            if !lookup_relays.contains(relay) {
                lookup_relays.push(relay.clone());
            }
        }
        let events = self
            .client
            .fetch_events_from(
                lookup_relays,
                Filter::new()
                    .author(target_pubkey)
                    .kind(Kind::InboxRelays)
                    .since(Timestamp::from(
                        Timestamp::now().as_secs().saturating_sub(30 * 24 * 60 * 60),
                    )),
                Duration::from_millis(1500),
            )
            .await;
        let events = match events {
            Ok(events) => events,
            Err(err) => {
                debug!(error = %err, "failed to fetch inbox relays, falling back to configured DM relays");
                return Ok(self.relay_config.read().await.dm_relays.clone());
            }
        };
        let newest = events.iter().max_by_key(|event| event.created_at.as_secs());
        if let Some(event) = newest {
            let relays = nip17::extract_relay_list(event)
                .map(|relay| relay.to_string())
                .collect::<Vec<_>>();
            if !relays.is_empty() {
                return Ok(relays);
            }
        }
        Ok(self.relay_config.read().await.dm_relays.clone())
    }

    pub(super) async fn send_signal<T: Serialize>(
        &self,
        relays: &[String],
        receiver: PublicKey,
        payload: &T,
    ) -> Result<Event, BootstrapError> {
        let rumor = EventBuilder::private_msg_rumor(receiver, serde_json::to_string(payload)?)
            .build(self.pubkey);
        let signal = build_signal_event(
            &self.keys,
            receiver,
            rumor,
            Timestamp::from((now_ms() + self.config.signal_ttl_secs * 1000) / 1000),
        )
        .await?;
        let relays = self.ensure_signal_relays(relays).await?;
        self.client
            .send_event_to(relays, &signal)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        Ok(signal)
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
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        let relays = self.ensure_signal_relays(relays).await?;
        self.client
            .send_event_to(relays, &event)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        Ok(())
    }

    async fn ensure_signal_relays(&self, relays: &[String]) -> Result<Vec<String>, BootstrapError> {
        let mut usable = Vec::new();
        for relay in relays {
            match self.client.add_relay(relay).await {
                Ok(_) => usable.push(relay.clone()),
                Err(error) => {
                    debug!(relay = %relay, error = %error, "failed to add signal relay");
                }
            }
        }
        if usable.is_empty() {
            return Err(BootstrapError::Nostr("no usable signal relays".to_string()));
        }
        self.client.connect().await;
        Ok(usable)
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
                "seen-sessions cache overflow; evicted oldest entries"
            );
        }
        Ok(())
    }
}
