//! Activate owned successor credit before collecting the predecessor's refund.
use super::*;

impl Controller {
    pub(in super::super) fn handover_for<'a>(
        j: &'a Journal,
        offer: &RouteOffer,
    ) -> Option<(&'a str, &'a Renewal)> {
        j.renewals.iter().find_map(|(id, r)| {
            (r.handover
                && r.replacements
                    .as_ref()
                    .is_some_and(|offers| offers.contains(offer)))
            .then_some((id.as_str(), r))
        })
    }

    pub(in super::super) fn handover_retires(j: &Journal, purchase: &Purchase) -> bool {
        j.renewals
            .values()
            .any(|r| r.handover && r.previous.iter().any(|old| old.purchase == *purchase))
    }

    pub(super) fn funded_successor<'a>(j: &'a Journal, r: &Renewal) -> Option<&'a FundingIntent> {
        let funding = j.funding.get(r.preopening.as_ref()?.funding_id.as_ref()?)?;
        (funding.funded.is_some() && !Self::funding_released(j, funding)).then_some(funding)
    }

    pub(super) fn validate_handover(j: &Journal, id: &str, r: &Renewal) -> Result<(), String> {
        if !r.handover {
            return Ok(());
        }
        let previous = j.buyer_settlements.get(id).ok_or("handover seal missing")?;
        let funding = r
            .preopening
            .as_ref()
            .and_then(|p| p.funding_id.as_ref())
            .and_then(|id| j.funding.get(id));
        if r.replacements.is_none()
            || funding.is_none_or(|f| f.funded.is_none() || f.reclaim.is_some())
            || previous.kind != SettlementKind::Cooperative
            || previous.usage.is_none()
            || previous.payment.is_none()
            || (r.completed && !previous.refunded)
        {
            return Err("invalid funded handover".into());
        }
        Ok(())
    }

    pub(super) fn replace_renewal_routes(
        j: &mut Journal,
        id: &str,
        offers: Vec<RouteOffer>,
        handover: bool,
    ) -> Result<(), String> {
        let r = j.renewals.get(id).ok_or("renewal intent missing")?;
        let settlement = j.buyer_settlements.get(id).ok_or("renewal seal missing")?;
        if r.completed
            || r.replacements.is_some()
            || (!settlement.refunded && !handover)
            || (handover
                && (Self::funded_successor(j, r).is_none()
                    || settlement.kind != SettlementKind::Cooperative
                    || settlement.usage.is_none()
                    || settlement.payment.is_none()
                    || r.preopening.as_ref().is_none_or(|p| p.offers != offers)))
            || offers.len() != r.previous.len()
            || offers
                .iter()
                .zip(&r.previous)
                .any(|(offer, old)| !same_service(&old.offer, offer))
        {
            return Err("renewal replacement authority changed".into());
        }
        let previous = r.previous.clone();
        for old in &previous {
            j.outgoing
                .get_mut(&old.purchase.contract.id)
                .ok_or("old purchase missing")?
                .retired = true;
            j.requested.remove(&old.offer.id);
        }
        for offer in &offers {
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
        let r = j.renewals.get_mut(id).unwrap();
        r.replacements = Some(offers);
        r.handover = handover;
        Ok(())
    }

    pub(super) async fn acknowledge_final_payment(
        &self,
        old: &BuyerSettlement,
    ) -> Result<(), String> {
        let payment = old.payment.clone().ok_or("handover payment missing")?;
        let expected = payment
            .balance
            .checked_mul(1_000)
            .ok_or("payment overflow")?;
        let peer = self.neighbor(old.provider).await?;
        let response = self
            .services
            .payments
            .request(
                peer,
                serde_json::to_vec(&PaymentRequest::Update {
                    channel_id: old.channel.id.clone(),
                    payment,
                })
                .map_err(|e| e.to_string())?,
            )
            .await?;
        match serde_json::from_slice::<PaymentResponse>(&response)
            .map_err(|_| "invalid handover payment response")?
        {
            PaymentResponse::Status { channel_id, usage }
                if channel_id == old.channel.id
                    && usage.paid_msat >= expected
                    && settlement::valid_usage(&old.channel, usage) =>
            {
                Ok(())
            }
            _ => Err("provider did not acknowledge final handover payment".into()),
        }
    }
}
