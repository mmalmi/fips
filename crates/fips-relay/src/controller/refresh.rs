//! Explicit source authorization for automatic route refresh.
use super::*;

const REFRESH_SECONDS: u64 = 5;

#[derive(Clone, Serialize, Deserialize)]
pub struct WatchedRoute {
    #[serde(
        default,
        skip_serializing_if = "crate::ledger::BillingBasis::is_legacy"
    )]
    pub billing: crate::ledger::BillingBasis,
    pub destination: String,
    pub max_rate_msat_per_kib: u64,
    pub paused: bool,
    pending: Option<RouteOffer>,
}

impl WatchedRoute {
    fn accepts(&self, offer: &RouteOffer) -> bool {
        offer.destination.npub() == self.destination
            && offer.billing == self.billing
            && offer.price.per_bytes == 1024
            && offer.price.msat <= self.max_rate_msat_per_kib
    }
}

impl Controller {
    pub(super) fn validate_watched_routes(j: &Journal) -> Result<(), String> {
        if j.watched_routes.len() > MAX_ROUTES {
            return Err("watched route capacity".into());
        }
        for (id, watch) in &j.watched_routes {
            let destination = PeerIdentity::from_npub(&watch.destination)
                .map_err(|_| "invalid watched destination")?;
            if id != &watch.destination
                || destination.node_addr() == &j.local
                || watch.max_rate_msat_per_kib == 0
                || watch.pending.as_ref().is_some_and(|offer| {
                    !watch.accepts(offer)
                        || offer.buyer != j.local
                        || offer.mint_url != j.policy.mint_url
                })
            {
                return Err("invalid watched route authorization".into());
            }
        }
        Ok(())
    }

    pub(super) fn offer_paused(j: &Journal, offer_id: &str) -> bool {
        j.route_changes.get(offer_id).is_some_and(|c| c.paused)
            || j.watched_routes
                .values()
                .any(|w| w.paused && w.pending.as_ref().is_some_and(|o| o.id == offer_id))
    }

    pub async fn watched_routes(&self) -> Result<Vec<WatchedRoute>, String> {
        Ok(self
            .snapshot()
            .await?
            .watched_routes
            .into_values()
            .collect())
    }

    /// Authorize only this source destination, under an explicit future price
    /// ceiling. Forwarded traffic never calls this method or creates a watch.
    pub async fn watch_route(
        &self,
        destination: PeerIdentity,
        max_rate_msat_per_kib: u64,
    ) -> Result<Purchase, String> {
        let _work = self.refresh_work.lock().await;
        if destination.node_addr() == self.services.endpoint.node_addr()
            || max_rate_msat_per_kib == 0
            || max_rate_msat_per_kib > self.services.quotes.max_rate_msat_per_kib()
        {
            return Err("invalid automatic route price ceiling".into());
        }
        let id = destination.npub();
        let saved = id.clone();
        let billing = self.services.quotes.billing_basis();
        let pending = self
            .change(move |j| {
                if let Some(old) = j.watched_routes.get_mut(&saved) {
                    if old.billing != billing {
                        return Err("saved watch billing basis cannot change".into());
                    }
                    if (old.pending.is_some() || !old.paused)
                        && old.max_rate_msat_per_kib != max_rate_msat_per_kib
                    {
                        return Err(
                            "finish pending purchase or pause before changing authorization".into(),
                        );
                    }
                    old.paused = false;
                    old.max_rate_msat_per_kib = max_rate_msat_per_kib;
                    return Ok(old.pending.clone());
                } else {
                    if j.watched_routes.len() >= MAX_ROUTES {
                        return Err("watched route capacity".into());
                    }
                    j.watched_routes.insert(
                        saved.clone(),
                        WatchedRoute {
                            billing,
                            destination: saved,
                            max_rate_msat_per_kib,
                            paused: false,
                            pending: None,
                        },
                    );
                }
                Ok(None)
            })
            .await?;
        self.refresh_checks
            .lock()
            .map_err(|_| "refresh timer poisoned")?
            .insert(id.clone(), tokio::time::Instant::now());
        let offer = match pending {
            Some(offer) => offer,
            None => self.services.quotes.request_route(destination).await?,
        };
        self.purchase_watched_offer(&id, offer).await
    }

    async fn purchase_watched_offer(
        &self,
        id: &str,
        offer: RouteOffer,
    ) -> Result<Purchase, String> {
        let snapshot = self.snapshot().await?;
        let watch = snapshot
            .watched_routes
            .get(id)
            .ok_or("source authorization missing")?;
        if watch.paused || !watch.accepts(&offer) {
            return Err("route exceeds source authorization".into());
        }
        let timestamp = now()?;
        // An unchanged monitoring result changes no financial state and needs
        // no journal write. A retained pending purchase still runs recovery.
        if watch.pending.is_none()
            && let Some(old) = snapshot.outgoing.values().find(|o| {
                o.accepted
                    && !o.retired
                    && o.offer == offer
                    && o.purchase.contract.expires_unix > timestamp
                    && !snapshot
                        .buyer_settlements
                        .contains_key(&o.purchase.channel.id)
            })
        {
            return Ok(old.purchase.clone());
        }
        let key = id.to_string();
        let saved = offer.clone();
        self.change(move |j| {
            let watch = j
                .watched_routes
                .get_mut(&key)
                .ok_or("source authorization missing")?;
            if watch.paused || !watch.accepts(&saved) {
                return Err("route exceeds source authorization".into());
            }
            if watch.pending.as_ref().is_some_and(|o| o != &saved) {
                return Err("previous watched purchase unfinished".into());
            }
            watch.pending = Some(saved);
            Ok(())
        })
        .await?;
        let purchase = self.purchase_offer(offer.clone()).await?;
        let id = id.to_string();
        self.change(move |j| {
            let watch = j
                .watched_routes
                .get_mut(&id)
                .ok_or("source authorization missing")?;
            if watch.pending.as_ref() != Some(&offer) {
                return Err("watched purchase changed".into());
            }
            watch.pending = None;
            Ok(())
        })
        .await?;
        Ok(purchase)
    }

    pub async fn pause_route_refresh(&self) -> Result<(), String> {
        let _work = self.refresh_work.lock().await;
        self.change(|j| {
            for watch in j.watched_routes.values_mut() {
                watch.paused = true;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn refresh_watched_routes(&self) -> Result<(), String> {
        let _work = self.refresh_work.lock().await;
        let snapshot = self.snapshot().await?;
        let timestamp = now()?;
        let mut first_error = None;
        for (id, watch) in snapshot.watched_routes {
            if watch.paused {
                continue;
            }
            // Let the existing renewal controller settle/refund near-expiry or
            // exhausted channels. A route poll must not retire its active
            // purchase and hide the channel from that controller's due scan.
            if watch.pending.is_none()
                && snapshot.outgoing.values().any(|o| {
                    o.accepted
                        && !o.retired
                        && o.offer.destination.npub() == watch.destination
                        && (snapshot
                            .renewals
                            .get(&o.purchase.channel.id)
                            .is_some_and(|r| !r.is_completed())
                            || self
                                .policy
                                .renewal
                                .as_ref()
                                .is_some_and(|p| self.renewal_due(&o.purchase, p, timestamp)))
                })
            {
                continue;
            }
            {
                let mut checks = self
                    .refresh_checks
                    .lock()
                    .map_err(|_| "refresh timer poisoned")?;
                if checks
                    .get(&id)
                    .is_some_and(|last| last.elapsed() < Duration::from_secs(REFRESH_SECONDS))
                {
                    continue;
                }
                checks.insert(id.clone(), tokio::time::Instant::now());
            }
            let result = async {
                if self.services.buyer.remaining_budget_sat().unwrap_or(0) == 0 {
                    return Err("source spending budget exhausted".into());
                }
                let offer = if let Some(pending) = watch.pending {
                    pending
                } else {
                    let destination = PeerIdentity::from_npub(&watch.destination)
                        .map_err(|_| "invalid watched destination")?;
                    self.services.quotes.refresh_route(destination).await?
                };
                self.purchase_watched_offer(&id, offer).await.map(|_| ())
            }
            .await;
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
