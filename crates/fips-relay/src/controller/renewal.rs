//! Replace settled neighbor channels while retaining price and risk boundaries.

use super::*;
use crate::ledger::ChannelUsage;
use fips_core::node::ForwardingPolicy;

#[cfg(test)]
#[path = "renewal_admission_tests.rs"]
mod admission_tests;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalPolicy {
    /// Renew near capacity using local submissions, authorized payments or the
    /// provider's retained crash exposure. These hints never authorize a payment.
    pub at_capacity_percent: u8,
    pub before_expiry_secs: u64,
}

impl RenewalPolicy {
    fn due(
        &self,
        purchase: &Purchase,
        evidence_msat: u64,
        authorized_sat: u64,
        observed_units: u64,
        timestamp: u64,
    ) -> bool {
        // Preserve saved renewal settings, but keep the lead below the shorter
        // service window of newly funded channels.
        let lead = purchase
            .channel
            .refund_after_unix
            .map_or(self.before_expiry_secs, |refund| {
                self.before_expiry_secs
                    .min(refund.saturating_sub(purchase.channel.expires_unix) / 2)
            });
        let nearing = timestamp.saturating_add(lead);
        purchase.channel.expires_unix <= nearing
            || purchase.contract.expires_unix <= nearing
            || self.capacity_due(
                &purchase.channel,
                evidence_msat.max(authorized_sat.saturating_mul(1_000)),
            )
            || u128::from(observed_units) * 100
                >= u128::from(purchase.contract.max_units) * u128::from(self.at_capacity_percent)
    }

    fn capacity_due(&self, channel: &ChannelTerms, reserved_msat: u64) -> bool {
        u128::from(reserved_msat) * 100
            >= u128::from(channel.capacity_sat) * 1_000 * u128::from(self.at_capacity_percent)
    }

    pub(super) fn recovery_due(&self, channel: &ChannelTerms, usage: ChannelUsage) -> bool {
        usage.lost_msat > 0
            && settlement::valid_usage(channel, usage)
            && self.capacity_due(channel, usage.reserved_msat)
    }
}

impl Store {
    /// A provider can consume its allowance on recovery without a billable
    /// submission. Reuse the normal settlement/refund-before-funding path;
    /// never erase that exposure or sign a payment for the reported loss.
    pub(super) fn renew_after_recovery(
        &mut self,
        purchase: &Purchase,
        usage: ChannelUsage,
    ) -> Result<(), String> {
        self.ensure_ready()?;
        let j = &self.journal;
        if j.renewals_paused
            || j.renewals.contains_key(&purchase.channel.id)
            || !j
                .policy
                .renewal
                .as_ref()
                .is_some_and(|policy| policy.recovery_due(&purchase.channel, usage))
            || !j.outgoing.values().any(|o| {
                o.accepted && o.purchase == *purchase && Controller::routing_eligible(j, o)
            })
            || j.outgoing.values().any(|o| {
                o.purchase.channel.id == purchase.channel.id
                    && Controller::routing_eligible(j, o)
                    && o.offer.trial
            })
        {
            return Ok(());
        }
        self.change(|j| Controller::reserve_renewal(j, purchase.channel.id.clone()))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Renewal {
    pub(super) previous: Vec<Outgoing>,
    replacements: Option<Vec<RouteOffer>>,
    completed: bool,
}

impl Renewal {
    pub(super) fn is_completed(&self) -> bool {
        self.completed
    }

    pub(super) fn reserves_provider(&self, provider: NodeAddr) -> bool {
        !self.completed
            && self
                .previous
                .iter()
                .any(|o| o.purchase.provider == provider)
    }

    pub(super) fn requests(&self, id: &str) -> bool {
        self.replacements
            .as_ref()
            .is_some_and(|offers| offers.iter().any(|offer| offer.id == id))
    }
}

pub(super) fn same_service(previous: &RouteOffer, next: &RouteOffer) -> bool {
    previous.buyer == next.buyer
        && previous.provider == next.provider
        && previous.destination.node_addr() == next.destination.node_addr()
        && previous.next_hop == next.next_hop
        && previous.path == next.path
        && previous.price == next.price
        && previous.billing == next.billing
        && previous.trial == next.trial
        && previous.mint_url == next.mint_url
        && next.max_units >= previous.max_units
}

impl Controller {
    pub(super) fn funding_released(journal: &Journal, funding: &FundingIntent) -> bool {
        funding.reclaim_terminal()
            || funding.funded.as_ref().is_some_and(|f| {
                journal
                    .buyer_settlements
                    .get(&f.terms.id)
                    .is_some_and(|s| s.refunded)
            })
    }

    pub(super) fn validate_renewals(journal: &Journal) -> Result<(), String> {
        if journal.renewals.len() > MAX_CHANNELS {
            return Err("renewal history capacity".into());
        }
        for (id, renewal) in &journal.renewals {
            if !renewal.completed && Self::route_change_pending_on(journal, id) {
                return Err("conflicting route and renewal intents".into());
            }
            if renewal.previous.is_empty()
                || renewal.previous.len() > MAX_ROUTES
                || renewal.previous.iter().any(|old| {
                    old.retired
                        || !old.accepted
                        || old.purchase.channel.id != *id
                        || journal
                            .outgoing
                            .get(&old.purchase.contract.id)
                            .is_none_or(|saved| {
                                saved.purchase != old.purchase
                                    || saved.offer != old.offer
                                    || saved.funding_id != old.funding_id
                            })
                })
            {
                return Err("invalid retained renewal purchase".into());
            }
            if let Some(offers) = &renewal.replacements {
                if !journal
                    .buyer_settlements
                    .get(id)
                    .is_some_and(|s| s.refunded)
                    || offers.len() != renewal.previous.len()
                    || offers.iter().zip(&renewal.previous).any(|(offer, old)| {
                        !same_service(&old.offer, offer)
                            || !journal.outgoing[&old.purchase.contract.id].retired
                    })
                    || (renewal.completed
                        && offers.iter().any(|offer| {
                            !journal.outgoing.values().any(|o| {
                                o.accepted && o.offer == *offer && o.purchase.channel.id != *id
                            })
                        }))
                {
                    return Err("invalid replacement agreement".into());
                }
            } else if renewal.completed {
                return Err("renewal completed without replacements".into());
            }
        }
        Ok(())
    }

    /// Retained individual routes. Compacted channels remain in settlement and
    /// financial history, and are included by `settle_all`.
    pub async fn purchase_history(&self) -> Result<Vec<Purchase>, String> {
        Ok(self
            .snapshot()
            .await?
            .outgoing
            .into_values()
            .filter(|o| o.accepted)
            .map(|o| o.purchase)
            .collect())
    }

    /// Wait for current renewal work before preventing new automatic purchases.
    /// Keep incomplete intents for explicit recovery; never discard funding.
    pub async fn pause_renewals(&self) -> Result<(), String> {
        let _work = self.renewal_work.write().await;
        self.change(|j| {
            j.renewals_paused = true;
            Ok(())
        })
        .await
    }

    pub async fn resume_renewals(&self) -> Result<(), String> {
        let _work = self.renewal_work.write().await;
        self.change(|j| {
            j.renewals_paused = false;
            Ok(())
        })
        .await
    }

    pub(super) fn renewal_due(
        &self,
        purchase: &Purchase,
        policy: &RenewalPolicy,
        timestamp: u64,
    ) -> bool {
        let evidence = self
            .services
            .buyer
            .evidence_msat(&purchase.channel.id)
            .unwrap_or(0);
        let observed = self
            .services
            .buyer
            .observed_units(&purchase.contract.id)
            .unwrap_or(0);
        let authorized = self
            .services
            .buyer
            .authorized_sat(&purchase.channel.id)
            .unwrap_or(0);
        policy.due(purchase, evidence, authorized, observed, timestamp)
    }

    pub(super) fn reserve_renewal(j: &mut Journal, id: String) -> Result<(), String> {
        if j.renewals.contains_key(&id) {
            return Ok(());
        }
        if j.renewals.len() >= MAX_CHANNELS {
            return Err("renewal history full".into());
        }
        if Self::route_change_pending_on(j, &id) {
            return Err("channel has an unfinished route change".into());
        }
        let previous: Vec<_> = j
            .outgoing
            .values()
            .filter(|o| Self::routing_eligible(j, o) && o.purchase.channel.id == id)
            .cloned()
            .collect();
        if previous.is_empty()
            || j.buyer_settlements.contains_key(&id)
            || previous.iter().any(|o| !o.accepted || o.offer.trial)
        {
            return Err("renewal purchase no longer active".into());
        }
        // Acceptance may be durable before its parent renewal completes. A
        // successor reservation would then block both replacements at purchase.
        if j.renewals.values().any(|renewal| {
            previous
                .iter()
                .any(|outgoing| renewal.reserves_provider(outgoing.purchase.provider))
        }) {
            return Err("provider has an unfinished renewal".into());
        }
        j.renewals.insert(
            id,
            Renewal {
                previous,
                replacements: None,
                completed: false,
            },
        );
        Ok(())
    }

    pub(super) async fn maintain_renewals(&self) -> Result<(), String> {
        let (pending, mut first_error) = self.pending_renewals().await?;
        for id in pending {
            if let Err(error) = self.resume_renewal(&id).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) async fn pending_renewals(&self) -> Result<(Vec<String>, Option<String>), String> {
        let _work = self.renewal_work.read().await;
        let snapshot = self.snapshot().await?;
        if snapshot.renewals_paused {
            return Ok((Vec::new(), None));
        }
        let mut first_error = None;
        if let Some(policy) = &self.policy.renewal {
            let timestamp = now()?;
            let due: HashSet<_> = self
                .purchases()
                .await?
                .into_iter()
                .filter(|p| {
                    !snapshot.renewals.contains_key(&p.channel.id)
                        && !snapshot.outgoing.values().any(|o| {
                            o.purchase.channel.id == p.channel.id
                                && Self::routing_eligible(&snapshot, o)
                                && o.offer.trial
                        })
                        && self.renewal_due(p, policy, timestamp)
                })
                .map(|p| p.channel.id)
                .collect();
            for id in due {
                if let Err(error) = self.change(move |j| Self::reserve_renewal(j, id)).await {
                    first_error.get_or_insert(error);
                }
            }
        }
        let pending = self
            .snapshot()
            .await?
            .renewals
            .into_iter()
            .filter_map(|(id, renewal)| (!renewal.completed).then_some(id))
            .collect();
        Ok((pending, first_error))
    }

    pub(super) async fn resume_renewal(&self, id: &str) -> Result<(), String> {
        // Readers allow independent channels to progress. An orderly pause
        // waits for them all before persisting the gate against new work.
        let _work = self.renewal_work.read().await;
        let claim = format!("renew/{id}");
        if !self.accepting.lock().unwrap().insert(claim.clone()) {
            return Ok(());
        }
        let _claim = AcceptGuard {
            claims: &self.accepting,
            id: claim,
        };
        let renewal = {
            let mut snapshot = self.snapshot().await?;
            if snapshot.renewals_paused {
                return Ok(());
            }
            snapshot.renewals.remove(id)
        };
        if let Some(renewal) = renewal
            && !renewal.completed
        {
            self.advance_renewal(id, renewal).await?;
        }
        Ok(())
    }

    // The caller owns this renewal's claim and a shared pause guard. Settlement
    // separately serializes payment and closure of this particular channel.
    async fn advance_renewal(&self, id: &str, mut renewal: Renewal) -> Result<(), String> {
        let admission_pause = self
            .services
            .buyer
            .pause_for_renewal(
                renewal.previous.iter().map(|old| &old.purchase.contract),
                self.services.seller.admission_notify(),
            )
            .map_err(|error| error.to_string())?;
        let started = std::time::Instant::now();
        let progress = |phase| {
            tracing::debug!(target: "fips_relay::controller::renewal",
            channel_id = id, phase, elapsed_us = started.elapsed().as_micros(),
            "Renewal pause progress")
        };
        progress("paused");
        if !self
            .snapshot()
            .await?
            .buyer_settlements
            .get(id)
            .is_some_and(|s| s.kind == SettlementKind::Expiry && s.refunded)
        {
            self.settle_channel(id).await?;
        }
        progress("settled");
        if self
            .services
            .buyer
            .remaining_budget_sat()
            .is_none_or(|left| left == 0)
        {
            return Err("lifetime spending budget exhausted; no replacement funded".into());
        }
        if renewal.replacements.is_none() {
            let mut offers = Vec::new();
            for old in &renewal.previous {
                let offer = self.services.quotes.renewal_offer(&old.offer).await?;
                if !same_service(&old.offer, &offer) {
                    return Err(
                        "renewal price or route changed; new upstream agreement required".into(),
                    );
                }
                offers.push(offer);
            }
            let previous = renewal.previous.clone();
            let saved = offers.clone();
            let channel_id = id.to_string();
            self.change(move |j| {
                if !j
                    .buyer_settlements
                    .get(&channel_id)
                    .is_some_and(|s| s.refunded)
                {
                    return Err("previous channel refund incomplete".into());
                }
                for old in &previous {
                    j.outgoing
                        .get_mut(&old.purchase.contract.id)
                        .ok_or("old purchase missing")?
                        .retired = true;
                    j.requested.remove(&old.offer.id);
                }
                for offer in &saved {
                    if j.requested.len() >= MAX_ROUTES
                        || j.requested.contains_key(&offer.id)
                        || j.requested.values().any(|o| {
                            o.provider == offer.provider
                                && o.destination.node_addr() == offer.destination.node_addr()
                        })
                    {
                        return Err("replacement request capacity or identity conflict".into());
                    }
                    j.requested.insert(offer.id.clone(), offer.clone());
                }
                j.renewals
                    .get_mut(&channel_id)
                    .ok_or("renewal intent missing")?
                    .replacements = Some(saved);
                Ok(())
            })
            .await?;
            renewal.replacements = Some(offers);
        }
        progress("replacements_ready");
        for offer in renewal.replacements.ok_or("replacement offers missing")? {
            let purchase = self.purchase_offer(offer).await?;
            if purchase.channel.id == id {
                return Err("replacement reused closed funding".into());
            }
        }
        // Each replacement is accepted, saved and active. The completion marker
        // only closes recovery bookkeeping; fresh traffic can use its own credit.
        drop(admission_pause);
        progress("resumed");
        #[cfg(feature = "testbench")]
        wallet_barrier::hold(&self.services.wallet_directory, id, "renewal-complete").await?;
        let id = id.to_string();
        self.change(move |j| {
            j.renewals
                .get_mut(&id)
                .ok_or("renewal intent missing")?
                .completed = true;
            Ok(())
        })
        .await
    }
}
