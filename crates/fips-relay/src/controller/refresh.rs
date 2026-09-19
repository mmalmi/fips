//! Explicit source authorization for automatic route refresh.
use super::*;

const REFRESH_SECONDS: u64 = 5;
pub(super) const REFRESH_RECHECK: Duration = Duration::from_secs(2);

#[cfg(test)]
pub(super) mod tests;

pub(super) struct RefreshCheck {
    checked: tokio::time::Instant,
    free: Option<RouteOffer>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedRoute {
    #[serde(
        default,
        skip_serializing_if = "crate::ledger::BillingBasis::is_legacy"
    )]
    pub billing: crate::ledger::BillingBasis,
    pub destination: String,
    pub max_rate_msat_per_kib: u64,
    pub paused: bool,
    pub(super) pending: Option<RouteOffer>,
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
    pub(super) fn next_refresh_delay(&self, _scan_started: tokio::time::Instant) -> Duration {
        let now = tokio::time::Instant::now();
        self.refresh_checks
            .lock()
            .ok()
            .and_then(|checks| {
                checks
                    .values()
                    .filter_map(|last| {
                        (last.checked + Duration::from_secs(REFRESH_SECONDS))
                            .checked_duration_since(now)
                            .filter(|delay| !delay.is_zero())
                    })
                    .min()
            })
            // Expired checks may belong to paused watches or ongoing renewals.
            // They must not cause a busy loop; refresh reports any poisoned lock.
            .unwrap_or(REFRESH_RECHECK)
            .min(REFRESH_RECHECK)
    }

    pub(super) fn validate_watched_routes(j: &Journal) -> Result<(), String> {
        if j.watched_routes.len() > MAX_ROUTES {
            return Err("watched route capacity".into());
        }
        for (id, watch) in &j.watched_routes {
            let destination = PeerIdentity::from_npub(&watch.destination)
                .map_err(|_| "invalid watched destination")?;
            if id != &watch.destination
                || destination.node_addr() == &j.local
                || (watch.max_rate_msat_per_kib == 0 && !watch.billing.has_free_handshakes())
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
        j.recovery_only.contains(offer_id)
            || j.route_changes.get(offer_id).is_some_and(|c| c.paused)
            || j.watched_routes
                .values()
                .any(|w| w.paused && w.pending.as_ref().is_some_and(|o| o.id == offer_id))
    }

    /// Bind a source watch in the transaction that reserves its purchase. A
    /// quote rejected before that boundary must leave fresh selection possible.
    pub(super) fn reserve_watched_offer(
        j: &mut Journal,
        expected: Option<&WatchedRoute>,
        offer: &RouteOffer,
    ) -> Result<(), String> {
        let Some(expected) = expected else {
            return Ok(());
        };
        if Self::offer_paused(j, &offer.id) {
            return Err("route change paused".into());
        }
        let watch = j
            .watched_routes
            .get_mut(&expected.destination)
            .ok_or("source authorization missing")?;
        if watch.paused
            || expected.paused
            || watch.destination != expected.destination
            || watch.billing != expected.billing
            || watch.max_rate_msat_per_kib != expected.max_rate_msat_per_kib
            || !watch.accepts(offer)
            || offer.buyer != j.local
            || offer.mint_url != j.policy.mint_url
        {
            return Err("route exceeds source authorization".into());
        }
        if watch.pending.as_ref().is_some_and(|saved| saved != offer)
            || (expected.pending.is_some() && watch.pending != expected.pending)
        {
            return Err("previous watched purchase unfinished or changed".into());
        }
        watch.pending = Some(offer.clone());
        Ok(())
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
    ) -> Result<RouteAccess, String> {
        let _work = self.refresh_work.lock().await;
        if destination.node_addr() == self.services.endpoint.node_addr()
            || (max_rate_msat_per_kib == 0
                && !self.services.quotes.billing_basis().has_free_handshakes())
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
            .insert(
                id.clone(),
                RefreshCheck {
                    checked: tokio::time::Instant::now(),
                    free: None,
                },
            );
        let offer = match pending {
            Some(offer) => offer,
            None => self.services.quotes.request_route(destination).await?,
        };
        self.accept_watched_offer(&id, offer).await
    }

    async fn accept_watched_offer(
        &self,
        id: &str,
        offer: RouteOffer,
    ) -> Result<RouteAccess, String> {
        let snapshot = self.snapshot().await?;
        let watch = snapshot
            .watched_routes
            .get(id)
            .ok_or("source authorization missing")?;
        if watch.paused || !watch.accepts(&offer) {
            return Err("route exceeds source authorization".into());
        }
        if offer.price.msat == 0 {
            if watch.pending.is_some() {
                return Err("previous watched purchase unfinished".into());
            }
            self.activate_source_route(&offer).await?;
            self.refresh_checks
                .lock()
                .map_err(|_| "refresh timer poisoned")?
                .get_mut(id)
                .ok_or("refresh state missing")?
                .free = Some(offer.clone());
            return Ok(RouteAccess::Free(offer));
        }
        let timestamp = now()?;
        // An unchanged monitoring result changes no financial state and needs
        // no journal write. A retained pending purchase still runs recovery.
        if watch.pending.is_none()
            && let Some(old) = snapshot.outgoing.values().find(|o| {
                o.accepted
                    && Self::routing_eligible(&snapshot, o)
                    && o.offer == offer
                    && o.purchase.contract.expires_unix > timestamp
                    && !snapshot
                        .buyer_settlements
                        .contains_key(&o.purchase.channel.id)
            })
        {
            self.activate_source_route(&old.offer).await?;
            return Ok(RouteAccess::Paid(old.purchase.clone()));
        }
        let purchase = self
            .purchase_watched_offer(offer.clone(), watch.clone())
            .await
            .inspect_err(|_| {
                self.services
                    .quotes
                    .invalidate_price(offer.provider, *offer.destination.node_addr());
            })?;
        let key = id.to_string();
        let mut expected = watch.clone();
        let completed = purchase.clone();
        self.change(move |j| {
            let outgoing = j
                .outgoing
                .get(&completed.contract.id)
                .ok_or("purchase intent missing")?;
            if outgoing.purchase != completed
                || !outgoing.accepted
                || !Self::routing_eligible(j, outgoing)
                || j.buyer_settlements.contains_key(&completed.channel.id)
            {
                return Err("watched purchase changed".into());
            }
            expected.pending = Some(outgoing.offer.clone());
            let watch = j
                .watched_routes
                .get_mut(&key)
                .ok_or("source authorization missing")?;
            if *watch != expected || !watch.accepts(&outgoing.offer) {
                return Err("watched purchase changed".into());
            }
            watch.pending = None;
            Ok(())
        })
        .await?;
        if let Some(check) = self
            .refresh_checks
            .lock()
            .map_err(|_| "refresh timer poisoned")?
            .get_mut(id)
        {
            check.free = None;
        }
        Ok(RouteAccess::Paid(purchase))
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
        self.withdraw_disconnected_purchases().await?;
        let snapshot = self.snapshot().await?;
        let timestamp = now()?;
        let mut first_error = None;
        for (id, watch) in snapshot.watched_routes.clone() {
            if watch.paused {
                continue;
            }
            // Let the existing renewal controller settle/refund near-expiry or
            // exhausted channels. A route poll must not retire its active
            // purchase and hide the channel from that controller's due scan.
            if watch.pending.is_none()
                && snapshot.outgoing.values().any(|o| {
                    o.accepted
                        && Self::routing_eligible(&snapshot, o)
                        && !o.offer.trial
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
            let free = {
                let mut checks = self
                    .refresh_checks
                    .lock()
                    .map_err(|_| "refresh timer poisoned")?;
                if checks.get(&id).is_some_and(|last| {
                    last.checked.elapsed() < Duration::from_secs(REFRESH_SECONDS)
                }) {
                    continue;
                }
                let check = checks.entry(id.clone()).or_insert(RefreshCheck {
                    checked: tokio::time::Instant::now(),
                    free: None,
                });
                check.checked = tokio::time::Instant::now();
                check.free.clone()
            };
            let result = async {
                let offer = if let Some(pending) = watch.pending {
                    pending
                } else {
                    let destination = PeerIdentity::from_npub(&watch.destination)
                        .map_err(|_| "invalid watched destination")?;
                    if let Some(old) = free.filter(|offer| !offer.trial) {
                        let remaining = self.services.quotes.free.remaining_units(&old);
                        let headroom = old.max_units.div_ceil(4).max(2_048).min(old.max_units);
                        let has_quota = remaining
                            .is_some_and(|units| units == old.max_units || units > headroom);
                        let same_provider = self
                            .services
                            .endpoint
                            .resolve_next_hop(destination, None)
                            .await
                            .map_err(|e| e.to_string())?
                            .is_some_and(|peer| peer.node_addr() == &old.provider);
                        if has_quota
                            && same_provider
                            && old.expires_unix > timestamp.saturating_add(REFRESH_SECONDS)
                            && !self.services.quotes.price_selection_enabled()
                        {
                            return Ok(());
                        }
                        if !has_quota
                            || !same_provider
                            || old.expires_unix <= timestamp.saturating_add(REFRESH_SECONDS)
                        {
                            // A fresh recursive request replaces the whole free
                            // continuation. Cached grants cannot renew its quota.
                            self.services.quotes.request_route(destination).await?
                        } else {
                            self.services.quotes.refresh_route(destination).await?
                        }
                    } else {
                        // Keep the selector's evidence and retry rules for trials;
                        // exhaustion alone must not authorize another trial quota.
                        self.services.quotes.refresh_route(destination).await?
                    }
                };
                if offer.price.msat != 0
                    && self.services.buyer.remaining_budget_sat().unwrap_or(0) == 0
                {
                    return Err("source spending budget exhausted".into());
                }
                self.accept_watched_offer(&id, offer).await.map(|_| ())
            }
            .await;
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
