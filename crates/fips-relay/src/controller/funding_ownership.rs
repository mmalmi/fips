//! Retained settled accounting does not own another intent's withdrawn funds.
use super::*;

impl Controller {
    fn settled_other_funding(j: &Journal, intent: &FundingIntent, old: &Outgoing) -> bool {
        let Some(saved) = j.outgoing.get(&old.purchase.contract.id) else {
            return false;
        };
        let Some(funding) = j.funding.get(&old.funding_id) else {
            return false;
        };
        saved.offer == old.offer
            && saved.purchase == old.purchase
            && saved.funding_id == old.funding_id
            && funding.id == old.funding_id
            && funding.id != intent.id
            && funding.provider == intent.provider
            && funding.provider == old.purchase.provider
            && funding
                .funded
                .as_ref()
                .is_some_and(|f| f.terms == old.purchase.channel)
            && j.buyer_settlements
                .get(&old.purchase.channel.id)
                .is_some_and(|s| {
                    s.provider == funding.provider
                        && s.channel == old.purchase.channel
                        && s.terminal()
                        && s.wallet_refund_sat.is_some()
                })
    }

    pub(super) fn funding_exclusively_withdrawn(j: &Journal, intent: &FundingIntent) -> bool {
        // Reuse the settlement validator: a refund flag alone is not evidence
        // that the original wallet refund, report and terms agree.
        if j.funding.get(&intent.id) != Some(intent) || Self::validate_settlements(j).is_err() {
            return false;
        }
        let historical_offer = |offer: &RouteOffer| {
            j.outgoing
                .values()
                .any(|old| old.offer == *offer && Self::settled_other_funding(j, intent, old))
        };
        let historical_purchase = |purchase: &Purchase| {
            j.outgoing.get(&purchase.contract.id).is_some_and(|old| {
                old.purchase == *purchase && Self::settled_other_funding(j, intent, old)
            })
        };
        j.requested
            .values()
            .any(|o| o.provider == intent.provider && j.recovery_only.contains(&o.id))
            && !j.requested.values().any(|o| {
                o.provider == intent.provider
                    && !j.recovery_only.contains(&o.id)
                    && !historical_offer(o)
            })
            && !j.outgoing.values().any(|o| {
                o.purchase.provider == intent.provider && !Self::settled_other_funding(j, intent, o)
            })
            && !j.incoming.values().any(|i| {
                i.downstream
                    .as_ref()
                    .is_some_and(|o| o.provider == intent.provider)
            })
            && !j.route_changes.values().any(|c| {
                (c.offer.provider == intent.provider
                    && !j.recovery_only.contains(&c.offer.id)
                    && !historical_offer(&c.offer))
                    || c.previous
                        .iter()
                        .any(|p| p.provider == intent.provider && !historical_purchase(p))
            })
            && !j.renewals.values().any(|r| {
                r.previous.iter().any(|o| {
                    o.purchase.provider == intent.provider
                        && (!r.is_completed() || !Self::settled_other_funding(j, intent, o))
                })
            })
            && !j.watched_routes.values().any(|w| {
                w.pending
                    .as_ref()
                    .is_some_and(|o| o.provider == intent.provider)
            })
    }
}
