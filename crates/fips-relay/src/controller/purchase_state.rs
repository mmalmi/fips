//! Atomic authorization and channel checks for purchase workers.
use super::*;

impl Controller {
    pub(super) fn check_purchase(
        j: &Journal,
        offer: &RouteOffer,
        channel: Option<&str>,
    ) -> Result<(), String> {
        if offer.expires_unix <= now()?
            || Self::retired_offer(j, offer)
            || Self::offer_paused(j, &offer.id)
        {
            return Err("purchase authorization expired or paused".into());
        }
        if j.outgoing
            .values()
            .any(|o| o.retired && o.offer.id == offer.id)
        {
            return Err("purchase authorization retired".into());
        }
        if channel.is_some_and(|id| j.buyer_settlements.contains_key(id))
            || j.funding.values().any(|f| {
                f.provider == offer.provider
                    && !Self::funding_released(j, f)
                    && f.funded
                        .as_ref()
                        .is_some_and(|funded| j.buyer_settlements.contains_key(&funded.terms.id))
            })
        {
            return Err("provider channel is settling or closed".into());
        }
        if j.renewals
            .values()
            .any(|r| r.reserves_provider(offer.provider) && !r.requests(&offer.id))
        {
            return Err("provider channel is renewing".into());
        }
        Ok(())
    }

    pub(super) fn reserve_purchase(
        j: &mut Journal,
        offer: RouteOffer,
    ) -> Result<RouteOffer, String> {
        Self::check_purchase(j, &offer, None)?;
        if let Some(old) = j.requested.values().find(|old| {
            old.provider == offer.provider
                && old.destination.node_addr() == offer.destination.node_addr()
        }) {
            if old.price != offer.price
                || old.next_hop != offer.next_hop
                || old.billing != offer.billing
                || old.path != offer.path
                || old.max_units != offer.max_units
                || old.trial != offer.trial
            {
                return Err("pending route needs explicit replacement".into());
            }
            return Ok(old.clone());
        }
        if j.requested.len() >= MAX_ROUTES {
            return Err("requested route capacity".into());
        }
        if j.requested.contains_key(&offer.id) {
            return Err("conflicting requested offer identity".into());
        }
        j.requested.insert(offer.id.clone(), offer.clone());
        Ok(offer)
    }

    pub(super) fn record_purchase(j: &mut Journal, saved: Outgoing) -> Result<Outgoing, String> {
        Self::check_purchase(j, &saved.offer, Some(&saved.purchase.channel.id))?;
        if let Some(old) = j.outgoing.values().find(|o| {
            !o.retired
                && o.purchase.provider == saved.purchase.provider
                && o.purchase.contract.destination == saved.purchase.contract.destination
        }) {
            if old.purchase.channel != saved.purchase.channel
                || old.offer.price != saved.offer.price
                || old.offer.billing != saved.offer.billing
                || old.offer.next_hop != saved.offer.next_hop
                || old.offer.path != saved.offer.path
                || old.offer.max_units != saved.offer.max_units
                || old.offer.trial != saved.offer.trial
            {
                return Err("conflicting concurrent route purchase".into());
            }
            return Ok(old.clone());
        }
        if j.outgoing.len() >= MAX_ROUTES {
            return Err("outgoing route capacity".into());
        }
        j.outgoing
            .insert(saved.purchase.contract.id.clone(), saved.clone());
        Ok(saved)
    }

    /// Closing the channel wins over a late Accept response. Keep the request
    /// as unacknowledged locally until its confirmed refund retires it. No
    /// channel lock spans the provider's multi-hop acceptance work.
    pub(super) fn finish_acceptance(j: &mut Journal, id: &str) -> Result<bool, String> {
        let outgoing = j.outgoing.get_mut(id).ok_or("purchase intent missing")?;
        if outgoing.retired
            || j.buyer_settlements
                .contains_key(&outgoing.purchase.channel.id)
        {
            return Ok(false);
        }
        outgoing.accepted = true;
        Ok(true)
    }

    /// A confirmed refund closes any interrupted acceptance on that channel.
    /// Keep its financial record, and prevent a stale recovery snapshot from
    /// creating the same authorization again on a freshly funded channel.
    pub(super) fn retire_refunded_purchases(j: &mut Journal, channel: &str) -> Result<(), String> {
        if !j.buyer_settlements.get(channel).is_some_and(|s| s.refunded) {
            return Err("purchase retirement requires confirmed refund".into());
        }
        for outgoing in j
            .outgoing
            .values_mut()
            .filter(|o| o.purchase.channel.id == channel && !o.accepted && !o.retired)
        {
            outgoing.retired = true;
            j.requested.remove(&outgoing.offer.id);
            for watch in j.watched_routes.values_mut() {
                if watch
                    .pending
                    .as_ref()
                    .is_some_and(|offer| offer.id == outgoing.offer.id)
                {
                    watch.pending = None;
                }
            }
        }
        Ok(())
    }
}
