use super::*;

impl NostrDiscovery {
    pub async fn shutdown(&self) -> Result<(), BootstrapError> {
        if let Some(handle) = self.advertise_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.connect_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.relay_startup_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.publish_task.lock().await.take() {
            handle.abort();
        }

        // Don't proactively retract the advert via NIP-09 on shutdown.
        // Parameterized-replaceable semantics handle restart supersedence,
        // and NIP-40 expiration (advert_ttl_secs) bounds staleness on
        // permanent shutdown. An explicit retraction races with the next
        // daemon's republish on strict relays (e.g. Damus rate-limits the
        // burst, leaving the advert deleted and never restored).
        let _ = self.current_advert_event_id.write().await.take();

        if let Some(handle) = self.notify_task.lock().await.take() {
            handle.abort();
        }

        Ok(())
    }

    pub(super) fn spawn_advertise_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(self.config.advert_refresh_secs.max(1)));
            // Swallow the immediate first tick: Node::start() requests the
            // initial advert publish via update_local_advert().
            interval.tick().await;
            loop {
                interval.tick().await;
                self.request_publish_advert();
            }
        })
    }

    pub(super) fn spawn_relay_startup_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut retry_delay = Duration::from_secs(2);
            loop {
                let subscribed =
                    match tokio::time::timeout(RELAY_STARTUP_OP_TIMEOUT, self.subscribe()).await {
                        Ok(Ok(())) => true,
                        Ok(Err(err)) => {
                            warn!(error = %err, "failed to subscribe to Nostr discovery relays");
                            false
                        }
                        Err(_) => {
                            warn!(
                                timeout_ms = RELAY_STARTUP_OP_TIMEOUT.as_millis() as u64,
                                "Nostr discovery relay subscribe timed out"
                            );
                            false
                        }
                    };
                match tokio::time::timeout(RELAY_STARTUP_OP_TIMEOUT, self.publish_inbox_relays())
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!(error = %err, "failed to publish Nostr inbox relay list");
                    }
                    Err(_) => {
                        warn!(
                            timeout_ms = RELAY_STARTUP_OP_TIMEOUT.as_millis() as u64,
                            "Nostr inbox relay publish timed out"
                        );
                    }
                }

                self.request_publish_advert();

                if subscribed {
                    break;
                }

                tokio::time::sleep(retry_delay).await;
                retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(60));
            }
        })
    }

    pub(super) fn spawn_connect_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.client.connect().await;
        })
    }

    pub(super) fn spawn_publish_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                self.publish_notify.notified().await;
                let mut retry_delay = ADVERT_PUBLISH_RETRY_INITIAL;
                loop {
                    match tokio::time::timeout(ADVERT_PUBLISH_TIMEOUT, self.publish_advert()).await
                    {
                        Ok(Ok(())) => break,
                        Ok(Err(err)) => {
                            warn!(
                                error = %err,
                                retry_after_ms = retry_delay.as_millis() as u64,
                                "failed to publish traversal advert"
                            );
                        }
                        Err(_) => {
                            warn!(
                                timeout_ms = ADVERT_PUBLISH_TIMEOUT.as_millis() as u64,
                                retry_after_ms = retry_delay.as_millis() as u64,
                                "Nostr traversal advert publish timed out"
                            );
                        }
                    }

                    tokio::select! {
                        _ = self.publish_notify.notified() => {
                            retry_delay = ADVERT_PUBLISH_RETRY_INITIAL;
                        }
                        _ = tokio::time::sleep(retry_delay) => {
                            retry_delay = next_advert_publish_retry_delay(retry_delay);
                        }
                    }
                }
            }
        })
    }

    pub(super) fn request_publish_advert(&self) {
        self.publish_notify.notify_one();
    }

    pub(super) fn punch_hint(&self) -> PunchHint {
        PunchHint {
            start_at_ms: now_ms() + self.config.punch_start_delay_ms,
            interval_ms: self.config.punch_interval_ms,
            duration_ms: self.config.punch_duration_ms,
        }
    }

    pub(super) fn should_subscribe_ambient_adverts(&self) -> bool {
        self.config.policy == crate::config::NostrDiscoveryPolicy::Open
    }

    pub(super) async fn subscribe(&self) -> Result<(), BootstrapError> {
        let relay_config = self.relay_config.read().await.clone();
        self.client
            .subscribe_to(
                relay_config.dm_relays.clone(),
                Filter::new()
                    .kind(Kind::Custom(SIGNAL_KIND))
                    .pubkey(self.pubkey)
                    .limit(0),
                None,
            )
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

        if self.should_subscribe_ambient_adverts() {
            self.client
                .subscribe_to(
                    relay_config.advert_relays.clone(),
                    Filter::new()
                        .kind(Kind::Custom(ADVERT_KIND))
                        .identifier(advert_d_tag(&self.config.app)),
                    None,
                )
                .await
                .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        } else {
            debug!(
                policy = ?self.config.policy,
                "skipping ambient Nostr advert subscription"
            );
        }

        Ok(())
    }

    pub(super) async fn publish_inbox_relays(&self) -> Result<(), BootstrapError> {
        let relay_config = self.relay_config.read().await.clone();
        let tags = relay_config
            .dm_relays
            .iter()
            .filter_map(|relay| RelayUrl::parse(relay).ok())
            .map(|relay| {
                Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::R)),
                    [relay.to_string()],
                )
            })
            .collect::<Vec<_>>();

        let event = EventBuilder::new(Kind::InboxRelays, "")
            .tags(tags)
            .sign_with_keys(&self.keys)
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        self.client
            .send_event_to(relay_config.dm_relays.clone(), &event)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        Ok(())
    }
}
