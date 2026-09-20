//! Expiry withdraws unowned purchases and their exact expired source watches.
use super::*;

impl Controller {
    fn expired_purchase_unowned(j: &Journal, offer: &RouteOffer, timestamp: u64) -> bool {
        offer.expires_unix != 0
            && offer.expires_unix <= timestamp
            && !j.recovery_only.contains(&offer.id)
            && !j.incoming.values().any(|i| {
                i.phase != Phase::Stopped
                    && i.contract.expires_unix > timestamp
                    && i.downstream.as_ref().is_some_and(|o| o.id == offer.id)
            })
            && !j.watched_routes.values().any(|w| {
                // A matching pending quote expires with this reservation. A
                // same-id watch with different terms needs reconciliation first.
                w.pending
                    .as_ref()
                    .is_some_and(|o| o.id == offer.id && o != offer)
            })
            && !j.route_changes.values().any(|c| {
                !c.is_finished(j)
                    && (c.offer.id == offer.id
                        || c.previous.iter().any(|p| {
                            j.outgoing
                                .get(&p.contract.id)
                                .is_some_and(|o| o.offer.id == offer.id)
                        }))
            })
            && !j.renewals.values().any(|r| {
                !r.is_completed()
                    && (r.requests(&offer.id) || r.previous.iter().any(|o| o.offer.id == offer.id))
            })
    }

    pub(in crate::controller) async fn withdraw_expired_purchases(&self) -> Result<(), String> {
        let store = self.store.clone();
        let services = self.services.clone();
        blocking(move || {
            let mut store = store.lock().map_err(|_| "controller state poisoned")?;
            // Let the existing cross-journal retirement finish before selecting
            // another change. Expiry never discards a financial operation.
            if store.journal.history.as_ref().is_some_and(History::pending) {
                return Ok(());
            }
            store.withdraw_expired_purchases(now()?, |j| {
                Self::reconcile_route_stops(j, &services)
            })?;
            Ok(())
        })
        .await
    }
}

impl Store {
    pub(super) fn withdraw_expired_purchases(
        &mut self,
        timestamp: u64,
        reconcile: impl FnOnce(&Journal) -> Result<(), String>,
    ) -> Result<bool, String> {
        self.ensure_ready()?;
        let incoming: Vec<_> = self
            .journal
            .incoming
            .iter()
            .filter(|(_, i)| i.phase != Phase::Stopped && i.contract.expires_unix <= timestamp)
            .map(|(id, _)| id.clone())
            .collect();
        let offers: std::collections::BTreeSet<_> = self
            .journal
            .requested
            .values()
            .filter(|o| Controller::expired_purchase_unowned(&self.journal, o, timestamp))
            .map(|o| o.id.clone())
            .collect();
        if incoming.is_empty() && offers.is_empty() {
            return Ok(false);
        }
        if self.journal.recovery_only.len() + offers.len() > MAX_ROUTES {
            return Err("recovery-only purchase capacity".into());
        }
        self.change(move |j| {
            for id in incoming {
                j.incoming.get_mut(&id).unwrap().phase = Phase::Stopped;
            }
            if !offers.is_empty() {
                j.version |= journal::RECOVERY_ONLY_VERSION;
                for watch in j.watched_routes.values_mut() {
                    if watch
                        .pending
                        .as_ref()
                        .is_some_and(|o| offers.contains(&o.id))
                    {
                        // Keep the user's pause, price ceiling and selected
                        // trial accounting while withdrawing only this quote.
                        watch.pending = None;
                    }
                }
                j.recovery_only.extend(offers);
            }
            Ok(())
        })?;
        // Serialize local forwarding closure with delayed activation and quote
        // installation. Startup repeats reconciliation after a failed write.
        if let Err(error) = reconcile(&self.journal) {
            self.ready = false;
            return Err(error);
        }
        Ok(true)
    }
}
