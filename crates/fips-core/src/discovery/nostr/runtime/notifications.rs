use super::*;

impl NostrDiscovery {
    pub(super) fn spawn_notify_loop(
        self: Arc<Self>,
        mut notifications: broadcast::Receiver<RelayPoolNotification>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let started_at = Instant::now();
            let mut first_event_seen = false;
            info!("nostr notify loop entered");
            loop {
                let notification = match notifications.recv().await {
                    Ok(notification) => notification,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            skipped,
                            "nostr notification channel lagged; advert/signal events dropped"
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("nostr notification channel closed; notify loop exiting");
                        break;
                    }
                };
                if !first_event_seen {
                    first_event_seen = true;
                    info!(
                        elapsed_ms = started_at.elapsed().as_millis() as u64,
                        "nostr notify loop received first event"
                    );
                }
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(ADVERT_KIND) {
                        let _ = self.ingest_advert_event(event.as_ref()).await;
                        continue;
                    }

                    if event.kind == Kind::Custom(RATING_FACT_KIND) {
                        if self.process_rating_fact_event(event.as_ref()).await {
                            trace!(
                                event = %short_id(&event.id.to_string()),
                                "rating fact accepted for open-discovery trust cache"
                            );
                        }
                        continue;
                    }

                    if event.kind != Kind::Custom(SIGNAL_KIND) {
                        continue;
                    }

                    let unwrapped = match unwrap_signal_event(&self.keys, &event).await {
                        Ok(unwrapped) => unwrapped,
                        Err(err) => {
                            trace!(error = %err, "failed to unwrap traversal signal");
                            continue;
                        }
                    };
                    let sender_npub = match unwrapped.sender.to_bech32() {
                        Ok(npub) => npub,
                        Err(err) => {
                            debug!(error = %err, "failed to encode traversal sender npub");
                            continue;
                        }
                    };

                    if let Ok(answer) =
                        serde_json::from_str::<TraversalAnswer>(&unwrapped.rumor.content)
                        && answer.message_type == "answer"
                        && answer.recipient_npub == self.npub
                    {
                        if let Some(tx) = self
                            .pending_answers
                            .lock()
                            .await
                            .remove(&answer.in_reply_to)
                        {
                            let _ = tx.send(SignalEnvelope {
                                payload: answer,
                                event_id: Some(event.id),
                                sender_npub: sender_npub.clone(),
                            });
                        }
                        continue;
                    }

                    if let Ok(offer) =
                        serde_json::from_str::<TraversalOffer>(&unwrapped.rumor.content)
                        && offer.message_type == "offer"
                        && offer.recipient_npub == self.npub
                    {
                        let Ok(permit) = self.offer_slots.clone().try_acquire_owned() else {
                            debug!(
                                sender_npub = %sender_npub,
                                limit = self.config.max_concurrent_incoming_offers,
                                "rate-limited inbound traversal offer (max_concurrent_incoming_offers reached); offer dropped"
                            );
                            continue;
                        };
                        let runtime = Arc::clone(&self);
                        self.spawn_child_task(async move {
                            let _permit = permit;
                            if let Err(err) = runtime
                                .handle_incoming_offer(offer, unwrapped.sender, sender_npub)
                                .await
                            {
                                debug!(error = %err, "failed to handle traversal offer");
                            }
                        })
                        .await;
                    }
                }
            }
        })
    }
}
