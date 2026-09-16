//! Recoverable replacement of route agreements without resetting neighbour credit.
use super::*;
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct RouteChange {
    pub(super) offer: RouteOffer,
    previous: Vec<Purchase>,
    prepared: bool,
    #[serde(default)]
    pub(super) paused: bool,
    stopped_remotes: BTreeSet<String>,
}

impl Controller {
    pub(super) fn changed_route_retires(j: &Journal, purchase: &Purchase) -> bool {
        j.route_changes
            .values()
            .any(|c| c.prepared && c.previous.contains(purchase))
    }

    pub(super) fn validate_route_changes(j: &Journal) -> Result<(), String> {
        if j.route_changes.len() > MAX_ROUTES {
            return Err("route change history full".into());
        }
        for (id, c) in &j.route_changes {
            if id != &c.offer.id
                || c.previous.is_empty()
                || c.previous.len() > MAX_ROUTES
                || c.offer.buyer != j.local
                || c.offer.mint_url != j.policy.mint_url
                || c.previous
                    .iter()
                    .map(|p| &p.contract.id)
                    .collect::<HashSet<_>>()
                    .len()
                    != c.previous.len()
                || c.previous.iter().any(|p| {
                    p.contract.destination != *c.offer.destination.node_addr()
                        || j.outgoing.get(&p.contract.id).is_none_or(|o| {
                            o.purchase != *p || !o.accepted || (c.prepared && !o.retired)
                        })
                })
                || c.stopped_remotes
                    .iter()
                    .any(|id| !c.previous.iter().any(|p| &p.contract.id == id))
                || (c.prepared
                    && j.requested.get(id) != Some(&c.offer)
                    && !j.outgoing.values().any(|o| o.offer == c.offer))
            {
                return Err("invalid route change intent".into());
            }
        }
        Ok(())
    }

    /// Repair cross-journal stop boundaries before the service opens its startup
    /// gate. Unknown submissions remain in their original accounting records.
    pub(super) fn reconcile_route_stops(
        j: &Journal,
        services: &ControllerServices,
    ) -> Result<(), String> {
        for i in j.incoming.values().filter(|i| i.phase == Phase::Stopped) {
            services.quotes.stop_reusing(&i.offer.id)?;
            if services.seller.usage(&i.contract.id).is_some() {
                services
                    .seller
                    .close_contract(&i.contract.id)
                    .map_err(|e| e.to_string())?;
            }
        }
        for c in j.route_changes.values() {
            for old in &c.previous {
                services
                    .buyer
                    .close_quote(&old.contract.id)
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    pub(super) async fn prepare_changed_route(&self, offered: &RouteOffer) -> Result<(), String> {
        let _work = self.route_work.lock().await;
        let snapshot = self.snapshot().await?;
        if Self::offer_paused(&snapshot, &offered.id) {
            return Err("route change paused".into());
        }
        let timestamp = now()?;
        let previous: Vec<_> = snapshot
            .outgoing
            .values()
            .filter(|o| {
                !o.retired && o.purchase.contract.destination == *offered.destination.node_addr()
            })
            .cloned()
            .collect();
        let changed = previous.iter().any(|o| {
            o.purchase.provider != offered.provider
                || o.offer.price != offered.price
                || o.offer.billing != offered.billing
                || o.offer.next_hop != offered.next_hop
                || o.offer.path != offered.path
                || o.offer.max_units != offered.max_units
                || o.offer.trial != offered.trial
                || (offered.trial && o.offer.id != offered.id)
                || o.purchase.contract.expires_unix <= timestamp
        });
        let existing = snapshot
            .route_changes
            .values()
            .find(|c| c.offer.id == offered.id)
            .cloned();
        if !changed && existing.is_none() {
            return Ok(());
        }
        let intent = if let Some(c) = existing {
            if c.offer != *offered {
                return Err("route change offer changed".into());
            }
            if Self::offer_paused(&snapshot, &offered.id) {
                return Err("route change paused".into());
            }
            c
        } else {
            if offered.expires_unix <= now()?
                || previous.iter().any(|o| {
                    !o.accepted
                        || snapshot
                            .buyer_settlements
                            .get(&o.purchase.channel.id)
                            .is_some_and(|s| !s.refunded)
                        || snapshot
                            .renewals
                            .get(&o.purchase.channel.id)
                            .is_some_and(|r| !r.is_completed())
                })
            {
                return Err(
                    "finish pending acceptance, settlement or renewal before changing route".into(),
                );
            }
            let intent = RouteChange {
                offer: offered.clone(),
                previous: previous.iter().map(|o| o.purchase.clone()).collect(),
                prepared: false,
                paused: false,
                stopped_remotes: BTreeSet::new(),
            };
            let saved = intent.clone();
            self.change(move |j| {
                if j.route_changes.len() >= MAX_ROUTES
                    || j.route_changes.values().any(|c| {
                        c.offer.destination.node_addr() == saved.offer.destination.node_addr()
                            && !j
                                .outgoing
                                .values()
                                .any(|o| o.offer == c.offer && o.accepted)
                    })
                {
                    return Err("route change capacity or unfinished transition".into());
                }
                j.route_changes.insert(saved.offer.id.clone(), saved);
                Ok(())
            })
            .await?;
            intent
        };
        if intent.prepared {
            return Ok(());
        }
        let saved = intent.clone();
        self.change(move |j| {
            // Other upstream customers cannot continue at their old resale
            // prices after this shared onward agreement changes.
            for incoming in j.incoming.values_mut().filter(|i| i.phase == Phase::Active) {
                if incoming.downstream.as_ref().is_some_and(|d| {
                    saved.previous.iter().any(|p| {
                        p.provider == d.provider
                            && p.contract.destination == *d.destination.node_addr()
                    })
                }) {
                    incoming.phase = Phase::Stopped;
                }
            }
            Ok(())
        })
        .await?;
        let snapshot = self.snapshot().await?;
        let services = self.services.clone();
        blocking(move || Self::reconcile_route_stops(&snapshot, &services)).await?;
        let id = intent.offer.id.clone();
        self.change(move |j| {
            for p in &intent.previous {
                let old = j
                    .outgoing
                    .get_mut(&p.contract.id)
                    .ok_or("previous route missing")?;
                if old.purchase != *p {
                    return Err("previous route changed".into());
                }
                old.retired = true;
                j.requested.remove(&old.offer.id);
            }
            if j.requested.len() >= MAX_ROUTES
                || j.requested.values().any(|o| {
                    o.provider == intent.offer.provider
                        && o.destination.node_addr() == intent.offer.destination.node_addr()
                })
            {
                return Err("replacement request conflict".into());
            }
            j.requested.insert(id.clone(), intent.offer);
            j.route_changes
                .get_mut(&id)
                .ok_or("route change missing")?
                .prepared = true;
            Ok(())
        })
        .await
    }

    pub(super) async fn replaces_for(&self, offer: &RouteOffer) -> Result<Option<String>, String> {
        Ok(self
            .snapshot()
            .await?
            .route_changes
            .get(&offer.id)
            .and_then(|c| {
                c.previous
                    .iter()
                    .find(|p| p.provider == offer.provider)
                    .map(|p| p.contract.id.clone())
            }))
    }

    pub(super) async fn handle_stop_route(
        &self,
        peer: PeerIdentity,
        id: &str,
    ) -> Result<ControllerResponse, String> {
        let id = id.to_string();
        let saved = id.clone();
        let offer_id = self
            .change(move |j| {
                let old = j.incoming.get_mut(&saved).ok_or("unknown route")?;
                if old.channel.buyer != *peer.node_addr() {
                    return Err("wrong route buyer".into());
                }
                old.phase = Phase::Stopped;
                Ok(old.offer.id.clone())
            })
            .await?;
        self.services.quotes.stop_reusing(&offer_id)?;
        let seller = self.services.seller.clone();
        let saved = id.clone();
        blocking(move || {
            if seller.usage(&saved).is_some() {
                seller.close_contract(&saved).map_err(|e| e.to_string())?;
            }
            Ok(())
        })
        .await?;
        Ok(ControllerResponse::RouteStopped { contract_id: id })
    }

    pub(super) async fn resume_route_changes(&self) -> Result<(), String> {
        let snapshot = self.snapshot().await?;
        let mut first_error = None;
        for change in snapshot
            .route_changes
            .values()
            .filter(|c| !c.prepared && !Self::offer_paused(&snapshot, &c.offer.id))
        {
            if let Err(error) = self.prepare_changed_route(&change.offer).await {
                first_error.get_or_insert(error);
            }
        }
        // An unreachable former neighbour cannot prevent use of the new route.
        // Its old channel stays accounted and locked; stop notices are retried
        // when that direct neighbour returns, before final bilateral settlement.
        for change in snapshot.route_changes.values().filter(|c| c.prepared) {
            for old in change
                .previous
                .iter()
                .filter(|p| !change.stopped_remotes.contains(&p.contract.id))
            {
                let Ok(peer) = self.neighbor(old.provider).await else {
                    continue;
                };
                let response = self
                    .services
                    .acceptance
                    .request(
                        peer,
                        serde_json::to_vec(&ControllerRequest::StopRoute {
                            contract_id: old.contract.id.clone(),
                        })
                        .map_err(|e| e.to_string())?,
                    )
                    .await;
                if let Ok(bytes) = response
                    && matches!(serde_json::from_slice::<ControllerResponse>(&bytes),Ok(ControllerResponse::RouteStopped{contract_id}) if contract_id==old.contract.id)
                {
                    let id = change.offer.id.clone();
                    let old_id = old.contract.id.clone();
                    self.change(move |j| {
                        j.route_changes
                            .get_mut(&id)
                            .ok_or("route change missing")?
                            .stopped_remotes
                            .insert(old_id);
                        Ok(())
                    })
                    .await?;
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
