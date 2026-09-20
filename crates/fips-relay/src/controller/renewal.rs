//! Replace settled neighbor channels while retaining price and risk boundaries.

use super::*;

#[cfg(test)]
#[path = "renewal_admission_tests.rs"]
mod admission_tests;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalPolicy {
    /// Use local submission evidence, never an untrusted usage report, to decide
    /// when the funded channel is near capacity. 100 also tests exhaustion.
    pub at_capacity_percent: u8,
    pub before_expiry_secs: u64,
}

impl RenewalPolicy {
    fn due(
        &self,
        purchase: &Purchase,
        evidence_msat: u64,
        observed_units: u64,
        timestamp: u64,
    ) -> bool {
        let nearing = timestamp.saturating_add(self.before_expiry_secs);
        purchase.channel.expires_unix <= nearing
            || purchase.contract.expires_unix <= nearing
            || u128::from(evidence_msat) * 100
                >= u128::from(purchase.channel.capacity_sat)
                    * 1_000
                    * u128::from(self.at_capacity_percent)
            || u128::from(observed_units) * 100
                >= u128::from(purchase.contract.max_units) * u128::from(self.at_capacity_percent)
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
        funding.reclaimed().is_some()
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
        let _work = self.renewal_work.lock().await;
        self.change(|j| {
            j.renewals_paused = true;
            Ok(())
        })
        .await
    }

    pub async fn resume_renewals(&self) -> Result<(), String> {
        let _work = self.renewal_work.lock().await;
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
        policy.due(purchase, evidence, observed, timestamp)
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
        let _work = self.renewal_work.lock().await;
        let snapshot = self.snapshot().await?;
        if snapshot.renewals_paused {
            return Ok(());
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
        let snapshot = self.snapshot().await?;
        for (id, renewal) in snapshot.renewals {
            if !renewal.completed
                && let Err(error) = self.advance_renewal(&id, renewal).await
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    // renewal_work excludes another replacement worker and orderly pausing.
    // Settlement takes the payment mutex only for its own final balance/refund.
    async fn advance_renewal(&self, id: &str, mut renewal: Renewal) -> Result<(), String> {
        self.settle_channel(id).await?;
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
        for offer in renewal.replacements.ok_or("replacement offers missing")? {
            let purchase = self.purchase_offer(offer).await?;
            if purchase.channel.id == id {
                return Err("replacement reused closed funding".into());
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> RouteOffer {
        let destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
        let provider = NodeAddr::from_bytes([2; 16]);
        RouteOffer {
            trial: false,
            billing: Default::default(),
            id: "offer".into(),
            buyer: NodeAddr::from_bytes([1; 16]),
            provider,
            destination,
            next_hop: *destination.node_addr(),
            path: vec![provider, *destination.node_addr()],
            price: crate::ledger::BytePrice {
                msat: 1_024,
                per_bytes: 1_024,
            },
            expires_unix: 500,
            max_units: 30_000,
            mint_url: "http://127.0.0.1:1234".into(),
            receiver_pubkey_hex: format!("02{}", "11".repeat(32)),
            capacity_sat: 16,
            grace_msat: 8_000,
        }
    }

    #[test]
    fn renewal_does_not_silently_change_resale_price_route_or_limits() {
        let old = offer();
        assert!(same_service(&old, &old));
        let mutations: Vec<fn(&mut RouteOffer)> = vec![
            |o| o.billing = crate::ledger::BillingBasis::ForwardingAttempt,
            |o| o.price.msat += 1,
            |o| o.provider = NodeAddr::from_bytes([3; 16]),
            |o| o.next_hop = NodeAddr::from_bytes([4; 16]),
            |o| o.path.push(NodeAddr::from_bytes([5; 16])),
            |o| o.trial = !o.trial,
            |o| o.mint_url = "http://127.0.0.1:5678".into(),
            |o| o.max_units -= 1,
        ];
        for mutate in mutations {
            let mut changed = old.clone();
            mutate(&mut changed);
            assert!(!same_service(&old, &changed));
        }
    }

    #[test]
    fn renewal_triggers_at_local_capacity_byte_limit_and_service_expiry() {
        let offer = offer();
        let mut purchase = Purchase {
            provider: offer.provider,
            channel: ChannelTerms {
                id: "channel".into(),
                buyer: offer.buyer,
                mint_url: offer.mint_url.clone(),
                capacity_sat: 16,
                grace_msat: 8_000,
                expires_unix: 600,
            },
            contract: Contract {
                billing: Default::default(),
                id: "contract".into(),
                channel_id: "channel".into(),
                destination: *offer.destination.node_addr(),
                next_hop: offer.next_hop,
                price: offer.price,
                max_units: 30_000,
                expires_unix: 500,
            },
        };
        let policy = RenewalPolicy {
            at_capacity_percent: 100,
            before_expiry_secs: 30,
        };
        assert!(!policy.due(&purchase, 15_999, 29_999, 469));
        assert!(policy.due(&purchase, 16_000, 0, 100));
        assert!(policy.due(&purchase, 0, 30_000, 100));
        assert!(policy.due(&purchase, 0, 0, 470));
        purchase.contract.expires_unix = 600;
        assert!(!policy.due(&purchase, 0, 0, 569));
        assert!(policy.due(&purchase, 0, 0, 570));
    }

    #[test]
    fn renewal_policy_rejects_unbounded_or_immediate_expiry_cycles() {
        let mut policy = ControllerPolicy {
            mint_url: "http://127.0.0.1:1234".into(),
            channel_capacity_sat: 16,
            max_locked_sat: 32,
            max_funding_overhead_sat: 0,
            max_wallet_spend_sat: 1024,
            channel_lifetime_secs: 600,
            renewal: Some(RenewalPolicy {
                at_capacity_percent: 100,
                before_expiry_secs: 30,
            }),
        };
        Controller::validate_policy(&policy).unwrap();
        policy.renewal.as_mut().unwrap().at_capacity_percent = 0;
        assert!(Controller::validate_policy(&policy).is_err());
        policy.renewal.as_mut().unwrap().at_capacity_percent = 101;
        assert!(Controller::validate_policy(&policy).is_err());
        policy.renewal.as_mut().unwrap().at_capacity_percent = 100;
        policy.renewal.as_mut().unwrap().before_expiry_secs = 301;
        assert!(Controller::validate_policy(&policy).is_err());
    }
}
