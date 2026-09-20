//! Withdraw routing authority without discarding an uncertain financial operation.
use super::*;

#[cfg(test)]
mod expiry_tests;
#[cfg(test)]
mod funded_expiry_state_tests;
#[cfg(test)]
mod funded_expiry_tests;
#[cfg(test)]
mod tests;
mod transit_expiry;
#[cfg(test)]
mod transit_expiry_tests;

impl Store {
    /// Only a reservation which never reached a wallet intent can expire
    /// without financial reconciliation. Select and remove under one lock.
    fn retire_unfunded_reservations(&mut self, timestamp: u64) -> Result<usize, String> {
        self.ensure_ready()?;
        let expired: Vec<_> = self
            .journal
            .requested
            .values()
            .filter(|offer| {
                Controller::expired_unfunded_reservation(&self.journal, offer, timestamp)
            })
            .map(|offer| (offer.id.clone(), offer.expires_unix))
            .collect();
        if expired.is_empty() {
            return Ok(0);
        }
        self.change(move |j| {
            for (id, expiry) in &expired {
                j.requested.remove(id);
                j.recovery_only.remove(id);
                // This is an offer replay fence, not evidence of a refund or
                // completed accounting. Preserve every financial history field.
                let history = j.history.get_or_insert_with(History::default);
                history.through_unix = history.through_unix.max(*expiry);
            }
            j.advance_history_version(3);
            Ok(expired.len())
        })
    }

    /// Retain withdrawal before touching other journals. The caller holds the
    /// store mutex through reconciliation, also fencing local quote insertion.
    fn withdraw_purchase(
        &mut self,
        watch: &WatchedRoute,
        reconcile: impl FnOnce(&Journal) -> Result<(), String>,
    ) -> Result<bool, String> {
        let changed = self.change(|j| Controller::withdraw_watched_purchase(j, watch))?;
        if changed && let Err(error) = reconcile(&self.journal) {
            // Load runs the same reconciliation before exposing the controller.
            self.ready = false;
            return Err(error);
        }
        Ok(changed)
    }
}

impl Controller {
    fn expired_unfunded_reservation(j: &Journal, offer: &RouteOffer, timestamp: u64) -> bool {
        j.recovery_only.contains(&offer.id)
            && offer.expires_unix != 0
            && offer.expires_unix <= timestamp
            && !j.funding.values().any(|f| f.provider == offer.provider)
            && !j
                .outgoing
                .values()
                .any(|o| o.purchase.provider == offer.provider)
            && !j.incoming.values().any(|i| {
                i.downstream
                    .as_ref()
                    .is_some_and(|d| d.provider == offer.provider)
            })
            && !j.route_changes.values().any(|c| {
                c.offer.provider == offer.provider
                    || c.previous.iter().any(|p| p.provider == offer.provider)
            })
            && !j.renewals.values().any(|r| {
                r.requests(&offer.id)
                    || r.previous
                        .iter()
                        .any(|o| o.purchase.provider == offer.provider)
            })
            && !j.requested.values().any(|other| {
                other.provider == offer.provider && !j.recovery_only.contains(&other.id)
            })
            && !j.watched_routes.values().any(|w| {
                w.pending
                    .as_ref()
                    .is_some_and(|o| o.provider == offer.provider)
            })
    }

    pub(super) async fn retire_unfunded_reservations(&self) -> Result<usize, String> {
        let store = self.store.clone();
        blocking(move || {
            let mut store = store.lock().map_err(|_| "controller state poisoned")?;
            // Existing cross-journal recovery must finish before local cleanup.
            if store.journal.history.as_ref().is_some_and(History::pending) {
                return Ok(0);
            }
            store.retire_unfunded_reservations(now()?)
        })
        .await
    }

    pub(super) fn routing_eligible(j: &Journal, outgoing: &Outgoing) -> bool {
        !outgoing.retired && !j.recovery_only.contains(&outgoing.offer.id)
    }

    pub(super) fn validate_recovery_only(j: &Journal) -> Result<(), String> {
        if j.recovery_only.len() > MAX_ROUTES
            || (!j.recovery_only.is_empty() && j.version & journal::RECOVERY_ONLY_VERSION == 0)
            || j.recovery_only.iter().any(|id| {
                !j.requested.contains_key(id)
                    && !j.route_changes.contains_key(id)
                    && !j.outgoing.values().any(|o| &o.offer.id == id)
            })
            || j.watched_routes.values().any(|watch| {
                watch
                    .pending
                    .as_ref()
                    .is_some_and(|o| j.recovery_only.contains(&o.id))
            })
        {
            return Err("invalid recovery-only purchase disposition".into());
        }
        Ok(())
    }

    /// The caller observed native peer eviction. Recheck the exact source
    /// authorization atomically; absence changes routing, never financial facts.
    pub(super) fn withdraw_watched_purchase(
        j: &mut Journal,
        expected: &WatchedRoute,
    ) -> Result<bool, String> {
        if expected.paused || j.watched_routes.get(&expected.destination) != Some(expected) {
            return Ok(false);
        }
        let Some(offer) = &expected.pending else {
            return Ok(false);
        };
        if j.requested.get(&offer.id) != Some(offer)
            && j.route_changes
                .get(&offer.id)
                .is_none_or(|c| c.offer != *offer)
        {
            return Err("pending purchase has no retained reservation".into());
        }
        if j.recovery_only.len() >= MAX_ROUTES {
            return Err("recovery-only purchase capacity".into());
        }
        j.recovery_only.insert(offer.id.clone());
        j.watched_routes
            .get_mut(&expected.destination)
            .unwrap()
            .pending = None;
        for incoming in j.incoming.values_mut() {
            if incoming.downstream.as_ref() == Some(offer) {
                incoming.phase = Phase::Stopped;
            }
        }
        // Earlier readers must reject this authorization fence, without
        // changing the validation of any existing accounting checkpoint.
        j.version |= journal::RECOVERY_ONLY_VERSION;
        Ok(true)
    }

    pub(super) fn reconcile_withdrawn_routes(
        j: &Journal,
        buyer: &BuyerAuthorizer,
    ) -> Result<(), String> {
        let mut first_error = None;
        for outgoing in j
            .outgoing
            .values()
            .filter(|o| j.recovery_only.contains(&o.offer.id))
        {
            // A crash may precede local quote installation. Both installation
            // and withdrawal take the store mutex, so none can appear afterward.
            if buyer
                .observed_units(&outgoing.purchase.contract.id)
                .is_some()
                && let Err(error) = buyer.close_quote(&outgoing.purchase.contract.id)
            {
                first_error.get_or_insert(error.to_string());
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) async fn withdraw_disconnected_purchases(&self) -> Result<(), String> {
        let watches: Vec<_> = self
            .snapshot()
            .await?
            .watched_routes
            .into_values()
            .filter(|w| !w.paused && w.pending.is_some())
            .collect();
        if watches.is_empty() {
            return Ok(());
        }
        let _work = self.route_work.lock().await;
        let peers = self
            .services
            .endpoint
            .peers()
            .await
            .map_err(|e| e.to_string())?;
        for watch in watches {
            let offer = watch.pending.as_ref().unwrap().clone();
            if peers
                .iter()
                .any(|p| p.connected && p.node_addr == offer.provider)
            {
                continue;
            }
            let services = self.services.clone();
            let store = self.store.clone();
            if blocking(move || {
                store
                    .lock()
                    .map_err(|_| "controller state poisoned")?
                    .withdraw_purchase(&watch, |j| Self::reconcile_route_stops(j, &services))
            })
            .await?
            {
                self.services
                    .quotes
                    .invalidate_price(offer.provider, *offer.destination.node_addr());
            }
        }
        Ok(())
    }

    /// Check in the same mutation that reserves whole-channel settlement. A
    /// detached route cannot close another destination's usable shared channel.
    pub(super) fn check_recovery_settlement(j: &Journal, id: &str) -> Result<(), String> {
        let outgoing = j
            .outgoing
            .values()
            .find(|o| o.purchase.channel.id == id && j.recovery_only.contains(&o.offer.id))
            .ok_or("no recovery-only purchase on channel")?;
        if j.outgoing
            .values()
            .any(|o| o.purchase.channel.id == id && Self::routing_eligible(j, o))
            || j.requested.values().any(|offer| {
                offer.provider == outgoing.purchase.provider && !j.recovery_only.contains(&offer.id)
            })
            || j.route_changes.values().any(|change| {
                change.offer.provider == outgoing.purchase.provider
                    && !j.recovery_only.contains(&change.offer.id)
                    && !change.is_finished(j)
            })
            || j.renewals
                .values()
                .any(|r| r.reserves_provider(outgoing.purchase.provider))
        {
            return Err("channel still serves eligible routing work".into());
        }
        Ok(())
    }

    pub(super) async fn recover_withdrawn_channels(&self) -> Result<(), String> {
        let snapshot = self.snapshot().await?;
        let ids: std::collections::BTreeSet<_> = snapshot
            .outgoing
            .values()
            .filter(|o| snapshot.recovery_only.contains(&o.offer.id))
            .filter(|o| {
                !snapshot
                    .buyer_settlements
                    .contains_key(&o.purchase.channel.id)
            })
            .map(|o| (o.purchase.channel.id.clone(), o.purchase.provider))
            .collect();
        let mut first_error = None;
        for (id, provider) in ids {
            if Self::check_recovery_settlement(&snapshot, &id).is_err()
                || self.neighbor(provider).await.is_err()
            {
                continue;
            }
            let _channel = self.channel_work(&id)?.lock_owned().await;
            if let Err(error) = self.settle_purchase(&id, true).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
