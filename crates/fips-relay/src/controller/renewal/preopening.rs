//! Prepare one exact successor without closing or authorizing its predecessor.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
pub(in super::super) struct Preopening {
    pub(in super::super) offers: Vec<RouteOffer>,
    pub(in super::super) funding_id: Option<String>,
}

impl Controller {
    pub(in super::super) fn selected_funding<'a>(
        j: &'a Journal,
        offer: &RouteOffer,
        renewal: Option<&str>,
    ) -> Result<Option<&'a FundingIntent>, String> {
        if let Some(id) = renewal {
            Self::check_preopening(j, offer, id)?;
            return Ok(j.renewals[id]
                .preopening
                .as_ref()
                .unwrap()
                .funding_id
                .as_ref()
                .map(|id| &j.funding[id]));
        }
        Ok(j.funding
            .values()
            .find(|f| f.provider == offer.provider && !Self::funding_released(j, f)))
    }

    pub(in super::super) fn check_preopening(
        j: &Journal,
        offer: &RouteOffer,
        id: &str,
    ) -> Result<(), String> {
        let r = j.renewals.get(id).ok_or("renewal intent missing")?;
        if r.completed
            || j.renewals_paused
            || r.replacements.is_some()
            || offer.expires_unix <= now()?
            || r.preopening
                .as_ref()
                .is_none_or(|p| !p.offers.contains(offer))
            || (j.buyer_settlements.contains_key(id)
                && r.preopening.as_ref().is_none_or(|p| p.funding_id.is_none()))
            || r.previous.iter().any(|old| {
                j.outgoing
                    .get(&old.purchase.contract.id)
                    .is_none_or(|saved| {
                        saved.retired
                            || saved.purchase != old.purchase
                            || saved.offer != old.offer
                            || !Self::routing_eligible(j, saved)
                    })
            })
        {
            return Err("renewal preopening authorization changed".into());
        }
        Ok(())
    }

    pub(in super::super) fn validate_preopening(
        j: &Journal,
        id: &str,
        r: &Renewal,
    ) -> Result<(), String> {
        let Some(p) = &r.preopening else {
            return Ok(());
        };
        if p.offers.len() != r.previous.len()
            || p.offers.is_empty()
            || p.offers.iter().zip(&r.previous).any(|(offer, old)| {
                offer.id == old.offer.id
                    || !same_service(&old.offer, offer)
                    || offer.receiver_pubkey_hex != p.offers[0].receiver_pubkey_hex
            })
            || r.replacements
                .as_ref()
                .is_some_and(|offers| offers != &p.offers)
            || (r.replacements.is_some() && p.funding_id.is_none())
        {
            return Err("invalid renewal preopening agreement".into());
        }
        if let Some(funding) = &p.funding_id {
            let f = j
                .funding
                .get(funding)
                .ok_or("renewal preopening funding missing")?;
            if r.replacements.as_ref().is_some_and(|offers| {
                j.outgoing
                    .values()
                    .any(|o| offers.contains(&o.offer) && o.funding_id != *funding)
            }) || r.previous.iter().any(|old| {
                old.funding_id == *funding
                    || old.purchase.channel.id != id
                    || old.purchase.provider != f.provider
                    || old.funding_id != r.previous[0].funding_id
            }) || f.receiver_pubkey_hex != p.offers[0].receiver_pubkey_hex
                || f.reclaim.is_some()
                || p.offers
                    .iter()
                    .any(|o| f.capacity_sat > o.capacity_sat || f.grace_msat > o.grace_msat)
            {
                return Err("invalid renewal preopening funding binding".into());
            }
        }
        Ok(())
    }

    pub(in super::super) fn validate_funding_neighbors(j: &Journal) -> Result<(), String> {
        let mut providers = BTreeMap::<NodeAddr, Vec<&FundingIntent>>::new();
        for f in j.funding.values().filter(|f| !Self::funding_released(j, f)) {
            providers.entry(f.provider).or_default().push(f);
        }
        for funds in providers.values().filter(|funds| funds.len() > 1) {
            let bound_pair = funds.len() == 2
                && j.renewals.values().any(|r| {
                    !r.completed
                        && r.preopening.as_ref().is_some_and(|p| {
                            p.funding_id.as_ref().is_some_and(|id| {
                                funds.iter().any(|f| &f.id == id)
                                    && r.previous.iter().all(|old| {
                                        old.funding_id != *id
                                            && funds.iter().any(|f| f.id == old.funding_id)
                                    })
                            })
                        })
                });
            if !bound_pair {
                return Err("unbound concurrent provider funding".into());
            }
        }
        Ok(())
    }

    fn preopening_fits(j: &Journal, r: &Renewal) -> Result<bool, String> {
        let budget = Self::capital(j)?;
        let capacity = r
            .preopening
            .as_ref()
            .map_or_else(
                || {
                    r.previous
                        .iter()
                        .map(|o| j.policy.channel_capacity_sat.min(o.offer.capacity_sat))
                        .min()
                },
                |p| {
                    p.offers
                        .iter()
                        .map(|o| j.policy.channel_capacity_sat.min(o.capacity_sat))
                        .min()
                },
            )
            .ok_or("renewal has no purchases")?;
        let reserve = capacity
            .checked_add(j.policy.max_funding_overhead_sat)
            .ok_or("funding cost overflow")?;
        Ok(j.funding.len() < MAX_CHANNELS
            && budget
                .locked_sat
                .checked_add(reserve)
                .is_some_and(|n| n <= j.policy.max_locked_sat)
            && budget
                .exposure_sat
                .checked_add(reserve)
                .is_some_and(|n| n <= j.policy.max_wallet_spend_sat))
    }

    async fn without_preopening(&self, id: &str, mut r: Renewal) -> Result<Renewal, String> {
        if r.preopening.is_some() {
            let owner = id.to_string();
            self.change(move |j| {
                let p = j
                    .renewals
                    .get(&owner)
                    .ok_or("renewal intent missing")?
                    .preopening
                    .as_ref();
                if p.and_then(|p| p.funding_id.as_ref())
                    .is_some_and(|funding| !Self::funding_released(j, &j.funding[funding]))
                {
                    return Err("renewal funding still owns capital".into());
                }
                j.renewals.get_mut(&owner).unwrap().preopening = None;
                Ok(())
            })
            .await?;
            r.preopening = None;
        }
        Ok(r)
    }

    pub(super) async fn prepare_renewal_funding(
        &self,
        id: &str,
        mut r: Renewal,
    ) -> Result<Renewal, String> {
        if r.replacements.is_some() {
            return Ok(r);
        }
        let snapshot = self.snapshot().await?;
        let released = r
            .preopening
            .as_ref()
            .and_then(|p| p.funding_id.as_ref())
            .is_some_and(|funding| Self::funding_released(&snapshot, &snapshot.funding[funding]));
        if released {
            return self.without_preopening(id, r).await;
        }
        if snapshot.buyer_settlements.contains_key(id) && r.preopening.is_none() {
            return Ok(r);
        }
        if self
            .services
            .buyer
            .remaining_budget_sat()
            .is_none_or(|left| left == 0)
        {
            return Err("lifetime spending budget exhausted; no replacement funded".into());
        }
        let reserved = r
            .preopening
            .as_ref()
            .is_some_and(|p| p.funding_id.is_some());
        if !reserved && !Self::preopening_fits(&snapshot, &r)? {
            return self.without_preopening(id, r).await;
        }
        if r.preopening.as_ref().is_none_or(|p| {
            p.offers
                .iter()
                .any(|o| o.expires_unix <= now().unwrap_or(u64::MAX))
        }) {
            let mut offers = Vec::new();
            for old in &r.previous {
                let offer = self.services.quotes.renewal_offer(&old.offer).await?;
                if !same_service(&old.offer, &offer) {
                    return Err(
                        "renewal price or route changed; new upstream agreement required".into(),
                    );
                }
                self.services.quotes.free.accept(&offer)?;
                offers.push(offer);
            }
            let owner = id.to_string();
            let saved = offers.clone();
            self.change(move |j| {
                let r = j.renewals.get_mut(&owner).ok_or("renewal intent missing")?;
                if r.completed || r.replacements.is_some() {
                    return Err("renewal advanced".into());
                }
                let funding_id = r.preopening.as_ref().and_then(|p| p.funding_id.clone());
                r.preopening = Some(Preopening {
                    offers: saved,
                    funding_id,
                });
                Ok(())
            })
            .await?;
            r.preopening = Some(Preopening {
                offers,
                funding_id: r.preopening.and_then(|p| p.funding_id),
            });
        }
        if !reserved && !Self::preopening_fits(&self.snapshot().await?, &r)? {
            return self.without_preopening(id, r).await;
        }
        let offer = &r
            .preopening
            .as_ref()
            .ok_or("renewal preopening missing")?
            .offers[0];
        self.fund_for(offer, Some(id)).await?;
        self.snapshot()
            .await?
            .renewals
            .remove(id)
            .ok_or("renewal intent missing".into())
    }
}

#[cfg(test)]
mod tests;
