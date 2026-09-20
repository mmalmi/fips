//! Recoverable local transaction across controller, buyer and seller journals.
use super::*;
use crate::ledger::RouteRetirementPlan;
use std::collections::BTreeSet;

mod never_installed;
#[cfg(test)]
mod never_installed_regression;
#[cfg(test)]
mod never_installed_tests;
mod selection;

fn closed_purchase(j: &Journal, o: &Outgoing) -> bool {
    // A verified refund is terminal even when the accepted route was never
    // replaced (and therefore has no separate replacement-retirement marker).
    o.retired
        || j.buyer_settlements
            .get(&o.purchase.channel.id)
            .is_some_and(|s| s.refunded)
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct History {
    pub(super) through_unix: u64,
    /// Proof that a retained funded channel was accepted before route removal.
    pub(super) buyers: BTreeSet<String>,
    /// Settlement still needs immutable channel terms after its last route goes.
    pub(super) sellers: BTreeMap<String, ChannelTerms>,
    pending: Option<Retirement>,
    #[serde(default)]
    pub(super) channels: Option<super::channel_history::ChannelHistory>,
    #[serde(default)]
    pub(super) seller: Option<super::seller_history::SellerHistory>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Retirement {
    through_unix: u64,
    buyer: Vec<RouteRetirementPlan>,
    seller: Vec<RouteRetirementPlan>,
    #[serde(default)]
    never_installed: Vec<Contract>,
}

impl Retirement {
    fn outgoing(&self) -> BTreeSet<String> {
        self.buyer
            .iter()
            .flat_map(|p| p.contracts.iter().map(|c| c.id.clone()))
            .collect()
    }
    fn incoming(&self) -> BTreeSet<String> {
        self.seller
            .iter()
            .flat_map(|p| p.contracts.iter().map(|c| c.id.clone()))
            .collect()
    }
    fn count(&self) -> usize {
        self.outgoing().len() + self.incoming().len()
    }

    fn finish(&self, j: &mut Journal) -> Result<(), String> {
        let outgoing = self.outgoing();
        let incoming = self.incoming();
        j.route_changes
            .retain(|_, c| !c.previous.iter().all(|p| outgoing.contains(&p.contract.id)));
        j.renewals.retain(|_, r| {
            !r.previous
                .iter()
                .all(|o| outgoing.contains(&o.purchase.contract.id))
        });
        for id in outgoing {
            let old = j.outgoing.remove(&id).ok_or("retiring purchase missing")?;
            if old.accepted {
                j.history
                    .get_or_insert_with(History::default)
                    .buyers
                    .insert(old.purchase.channel.id.clone());
            }
            j.requested.remove(&old.offer.id);
            j.recovery_only.remove(&old.offer.id);
            for watch in j.watched_routes.values_mut() {
                if watch.pending.as_ref().is_some_and(|o| o.id == old.offer.id) {
                    watch.pending = None;
                }
            }
        }
        let history = j.history.get_or_insert_with(History::default);
        history.through_unix = history.through_unix.max(self.through_unix);
        for id in &incoming {
            let old = j.incoming.remove(id).ok_or("retiring sale missing")?;
            if history
                .sellers
                .insert(old.channel.id.clone(), old.channel.clone())
                .is_some_and(|prior| prior != old.channel)
            {
                return Err("retired seller channel changed".into());
            }
        }
        for i in j.incoming.values_mut() {
            if i.replaces.as_ref().is_some_and(|id| incoming.contains(id)) {
                // Retain the exact request identity for lost Accept replies.
                i.replacement_retired = true;
            }
        }
        history.pending = None;
        j.advance_history_version(3);
        Ok(())
    }

    fn validate(&self, j: &Journal) -> Result<(), String> {
        self.validate_uninstalled(j)?;
        if self.count() == 0 || self.buyer.len() > MAX_CHANNELS || self.seller.len() > MAX_CHANNELS
        {
            return Err("invalid retirement size".into());
        }
        for (plans, buying) in [(&self.buyer, true), (&self.seller, false)] {
            let mut channels = HashSet::new();
            for p in plans {
                if !channels.insert(&p.channel)
                    || p.contracts.is_empty()
                    || p.contracts.len() > MAX_ROUTES
                    || p.contracts
                        .iter()
                        .map(|c| &c.id)
                        .collect::<HashSet<_>>()
                        .len()
                        != p.contracts.len()
                    || p.through_unix > self.through_unix
                    || p.after.contracts
                        != p.before
                            .contracts
                            .checked_add(p.contracts.len() as u64)
                            .ok_or("retirement overflow")?
                {
                    return Err("invalid retirement prefix".into());
                }
                for c in &p.contracts {
                    if c.channel_id != p.channel
                        || c.expires_unix > p.through_unix
                        || c.billing.is_legacy()
                    {
                        return Err("invalid retired contract".into());
                    }
                    let matches = if buying {
                        j.outgoing.get(&c.id).is_some_and(|o| {
                            closed_purchase(j, o)
                                && o.purchase.contract == *c
                                && o.offer.expires_unix <= self.through_unix
                        })
                    } else {
                        j.incoming.get(&c.id).is_some_and(|i| {
                            i.phase == Phase::Stopped
                                && i.contract == *c
                                && i.offer.expires_unix <= self.through_unix
                        })
                    };
                    if !matches {
                        return Err("retirement agreement changed".into());
                    }
                }
            }
        }
        let outgoing = self.outgoing();
        if j.watched_routes.values().any(|watch| {
            watch
                .selected_trial
                .as_ref()
                .is_some_and(|id| outgoing.contains(id))
        }) {
            return Err("retirement crosses retained trial accounting".into());
        }
        let incoming = self.incoming();
        for c in j.route_changes.values() {
            let touched = c.previous.iter().any(|p| outgoing.contains(&p.contract.id))
                || j.outgoing
                    .values()
                    .any(|o| o.offer == c.offer && outgoing.contains(&o.purchase.contract.id));
            if touched
                && (!c.prepared
                    || !c.is_finished(j)
                    || !c.previous.iter().all(|p| outgoing.contains(&p.contract.id)))
            {
                return Err("retirement crosses unfinished route change".into());
            }
        }
        for r in j.renewals.values() {
            let touched = r
                .previous
                .iter()
                .any(|o| outgoing.contains(&o.purchase.contract.id))
                || j.outgoing
                    .values()
                    .any(|o| r.requests(&o.offer.id) && outgoing.contains(&o.purchase.contract.id));
            if touched
                && (!r.is_completed()
                    || !r
                        .previous
                        .iter()
                        .all(|o| outgoing.contains(&o.purchase.contract.id)))
            {
                return Err("retirement crosses unfinished renewal".into());
            }
        }
        if j.incoming.values().any(|i| {
            i.phase == Phase::Prepared
                && i.replaces.as_ref().is_some_and(|id| incoming.contains(id))
        }) {
            return Err("retirement crosses prepared acceptance".into());
        }
        let mut projected = j.clone();
        self.finish(&mut projected)?;
        Controller::validate_journal(&projected, &projected.policy, projected.local)
    }
}

impl History {
    pub(super) fn pending(&self) -> bool {
        self.routes_pending()
            || self.channels.as_ref().is_some_and(|h| h.pending())
            || self.seller.as_ref().is_some_and(|h| h.pending())
    }
    pub(super) fn routes_pending(&self) -> bool {
        self.pending.is_some()
    }
}

impl Controller {
    pub(super) fn settlement_terms(
        j: &Journal,
        id: &str,
    ) -> Result<(NodeAddr, ChannelTerms), String> {
        if let Some(o) = j.outgoing.values().find(|o| {
            (o.accepted || j.recovery_only.contains(&o.offer.id)) && o.purchase.channel.id == id
        }) {
            return Ok((o.purchase.provider, o.purchase.channel.clone()));
        }
        if j.history.as_ref().is_some_and(|h| h.buyers.contains(id))
            && let Some((provider, terms)) = j.funding.values().find_map(|f| {
                f.funded
                    .as_ref()
                    .filter(|funded| funded.terms.id == id)
                    .map(|funded| (f.provider, funded.terms.clone()))
            })
        {
            return Ok((provider, terms));
        }
        Err("recover purchase acceptance before settlement".into())
    }

    pub(super) fn retired_offer(j: &Journal, offer: &RouteOffer) -> bool {
        j.history
            .as_ref()
            .is_some_and(|h| h.through_unix != 0 && offer.expires_unix <= h.through_unix)
    }

    pub(super) fn validate_history(j: &Journal) -> Result<(), String> {
        let Some(h) = &j.history else {
            return if j.history_version() == 2 {
                Ok(())
            } else {
                Err("missing controller history".into())
            };
        };
        if !matches!(j.history_version(), 3..=6)
            || h.sellers.len() > MAX_CHANNELS
            || h.buyers.len() > MAX_CHANNELS
        {
            return Err("invalid controller history".into());
        }
        if h.buyers.iter().any(|id| {
            !j.funding
                .values()
                .any(|f| f.funded.as_ref().is_some_and(|v| &v.terms.id == id))
        }) {
            return Err("retired buyer funding missing".into());
        }
        for (id, terms) in &h.sellers {
            validate_channel(terms).map_err(|e| e.to_string())?;
            if id != &terms.id
                || terms.buyer == j.local
                || terms.mint_url != j.policy.mint_url
                || h.through_unix == 0
                || j.incoming
                    .values()
                    .any(|i| i.channel.id == *id && i.channel != *terms)
            {
                return Err("invalid retired seller channel".into());
            }
        }
        if let Some(p) = &h.pending {
            if !p.never_installed.is_empty()
                && j.version & journal::UNINSTALLED_RETIREMENT_VERSION == 0
            {
                return Err("unsupported uninstalled retirement format".into());
            }
            p.validate(j)?;
        }
        Ok(())
    }

    pub(super) async fn retire_history(&self) -> Result<usize, String> {
        // No network awaits under the journal lock. Other workers recheck their
        // durable intent, and lower stores reject already retired agreements.
        let store = self.store.clone();
        let buyer = self.services.buyer.clone();
        let seller = self.services.seller.clone();
        blocking(move || {
            let mut store = store.lock().map_err(|_| "controller state poisoned")?;
            let timestamp = now()?;
            store.retire_routes(&buyer, &seller, timestamp)
        })
        .await
    }
}

impl Store {
    pub(super) fn prepare_retirement(
        &mut self,
        buyer: &BuyerAuthorizer,
        seller: &DurableRelay,
        timestamp: u64,
    ) -> Result<(), String> {
        if !self.ready {
            return Err("controller journal suspended".into());
        }
        if self.journal.history.as_ref().is_some_and(History::pending) {
            return Ok(());
        }
        let Some(plan) = selection::select(&self.journal, buyer, seller, timestamp)? else {
            return Ok(());
        };
        let mut candidate = self.journal.clone();
        candidate.advance_history_version(3);
        if !plan.never_installed.is_empty() {
            candidate.version |= journal::UNINSTALLED_RETIREMENT_VERSION;
        }
        candidate
            .history
            .get_or_insert_with(History::default)
            .pending = Some(plan);
        Controller::validate_journal(&candidate, &candidate.policy, candidate.local)?;
        self.journal = candidate;
        self.persist()
    }

    pub(super) fn retire_routes(
        &mut self,
        buyer: &BuyerAuthorizer,
        seller: &DurableRelay,
        timestamp: u64,
    ) -> Result<usize, String> {
        self.prepare_retirement(buyer, seller, timestamp)?;
        self.resume_retirement(buyer, seller)
    }

    pub(super) fn resume_retirement(
        &mut self,
        buyer: &BuyerAuthorizer,
        seller: &DurableRelay,
    ) -> Result<usize, String> {
        if !self.ready {
            return Err("controller journal suspended".into());
        }
        let Some(plan) = self
            .journal
            .history
            .as_ref()
            .and_then(|h| h.pending.clone())
        else {
            return Ok(0);
        };
        plan.validate(&self.journal)?;
        // A failed write leaves this intent intact. No controller mutation is
        // allowed until all stores match the saved post-retirement evidence.
        for p in &plan.buyer {
            let current = buyer
                .retirement_plan(&p.channel, p.through_unix)
                .map_err(|e| e.to_string())?;
            if current.contracts.is_empty() && current.before == p.after {
                continue;
            }
            if current != *p {
                return Err("buyer retirement evidence changed".into());
            }
            buyer
                .retire_closed_routes(&p.channel, p.through_unix)
                .map_err(|e| e.to_string())?;
        }
        for p in &plan.seller {
            let uninstalled = plan.uninstalled_on(&p.channel);
            let current = seller
                .retirement_plan_with_uninstalled(&p.channel, p.through_unix, &uninstalled)
                .map_err(|e| e.to_string())?;
            if current.contracts.is_empty() && current.before == p.after {
                continue;
            }
            if current != *p {
                return Err("seller retirement evidence changed".into());
            }
            seller
                .retire_closed_routes_with_uninstalled(&p.channel, p.through_unix, &uninstalled)
                .map_err(|e| e.to_string())?;
        }
        let mut candidate = self.journal.clone();
        plan.finish(&mut candidate)?;
        Controller::validate_journal(&candidate, &candidate.policy, candidate.local)?;
        self.journal = candidate;
        self.persist()?;
        Ok(plan.count())
    }
}
