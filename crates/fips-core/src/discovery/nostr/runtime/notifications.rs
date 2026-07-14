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
                            "nostr notification channel lagged; advert events dropped"
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
                }
            }
        })
    }
}
