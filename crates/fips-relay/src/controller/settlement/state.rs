use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReport {
    pub channel_id: String,
    /// Value after the funding swap, including reserves for settlement fees.
    pub value_after_stage1_sat: u64,
    /// Final signed traffic charge, excluding redemption-fee reserves.
    pub paid_sat: u64,
    /// Extra receiver proof value reserved for later redemption, not a paid fee.
    #[serde(default)]
    pub receiver_fee_reserve_sat: u64,
    /// Original sender refund proof value, before any later redemption fees.
    pub refunded_sat: u64,
    /// Reported value not returned in either party's proofs. Excludes reserves.
    pub fee_sat: u64,
}

impl SettlementReport {
    pub(in crate::controller) fn receiver_value_sat(&self) -> Option<u64> {
        self.paid_sat.checked_add(self.receiver_fee_reserve_sat)
    }

    pub(super) fn from_close(
        closed: &cashu_service::CashuSpilmanReceiverCloseResult,
    ) -> Result<Self, String> {
        let returned = closed
            .receiver_sum
            .checked_add(closed.sender_sum)
            .ok_or("close value overflow")?;
        Ok(Self {
            channel_id: closed.channel_id.clone(),
            value_after_stage1_sat: closed.total_value,
            paid_sat: closed.closed_amount,
            receiver_fee_reserve_sat: closed
                .receiver_sum
                .checked_sub(closed.closed_amount)
                .ok_or("receiver proof value below signed payment")?,
            refunded_sat: closed.sender_sum,
            fee_sat: closed
                .total_value
                .checked_sub(returned)
                .ok_or("close exceeds funding")?,
        })
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::controller) enum SettlementKind {
    #[default]
    Cooperative,
    Expiry,
}

#[derive(Clone, Serialize, Deserialize)]
pub(in crate::controller) struct BuyerSettlement {
    #[serde(default)]
    pub(in crate::controller) kind: SettlementKind,
    #[serde(with = "node_addr")]
    pub(in crate::controller) provider: NodeAddr,
    pub(in crate::controller) channel: ChannelTerms,
    pub(in crate::controller) usage: Option<ChannelUsage>,
    pub(in crate::controller) payment: Option<CashuSpilmanPayment>,
    pub(in crate::controller) report: Option<SettlementReport>,
    #[serde(default)]
    pub(in crate::controller) released: bool,
    pub(in crate::controller) refunded: bool,
    pub(in crate::controller) wallet_refund_sat: Option<u64>,
}

impl BuyerSettlement {
    pub(in crate::controller) fn terminal(&self) -> bool {
        self.refunded && (self.kind == SettlementKind::Expiry || self.released)
    }

    pub(in crate::controller) fn final_signed_sat(&self) -> Result<u64, String> {
        if self.kind == SettlementKind::Expiry {
            return Ok(0);
        }
        self.payment
            .as_ref()
            .map(|p| p.balance)
            .ok_or("final payment missing".into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(in crate::controller) struct SellerSettlement {
    pub(in crate::controller) channel: ChannelTerms,
    pub(in crate::controller) usage: Option<ChannelUsage>,
    pub(in crate::controller) payment: Option<CashuSpilmanPayment>,
    pub(in crate::controller) report: Option<SettlementReport>,
    #[serde(default)]
    pub(in crate::controller) released: bool,
}

pub(super) fn valid_usage(channel: &ChannelTerms, usage: ChannelUsage) -> bool {
    channel.capacity_sat.checked_mul(1_000).is_some_and(|cap| {
        usage.paid_msat <= cap
            && usage.reserved_msat <= cap
            && usage.submitted_msat <= usage.reserved_msat
            && usage.lost_msat <= usage.reserved_msat - usage.submitted_msat
    })
}

pub(super) fn valid_report(channel: &ChannelTerms, report: &SettlementReport, paid: u64) -> bool {
    report.channel_id == channel.id
        && report.paid_sat == paid
        && report.value_after_stage1_sat >= channel.capacity_sat
        && report
            .receiver_value_sat()
            .and_then(|n| n.checked_add(report.refunded_sat))
            .and_then(|n| n.checked_add(report.fee_sat))
            == Some(report.value_after_stage1_sat)
}

impl Controller {
    pub(in crate::controller) fn validate_settlements(j: &Journal) -> Result<(), String> {
        if j.buyer_settlements.len() > MAX_CHANNELS || j.seller_settlements.len() > MAX_CHANNELS {
            return Err("settlement history capacity".into());
        }
        for (id, s) in &j.buyer_settlements {
            if s.kind == SettlementKind::Expiry {
                Self::validate_expiry_settlement(j, id, s)?;
                continue;
            }
            if id != &s.channel.id
                || !j.funding.values().any(|f| {
                    f.provider == s.provider
                        && f.funded.as_ref().is_some_and(|f| f.terms == s.channel)
                })
                || s.usage.is_some_and(|u| !valid_usage(&s.channel, u))
                || s.payment.as_ref().is_some_and(|p| {
                    s.usage.is_none() || p.channel_id != *id || p.balance > s.channel.capacity_sat
                })
                || s.report.as_ref().is_some_and(|r| {
                    s.payment
                        .as_ref()
                        .is_none_or(|p| !valid_report(&s.channel, r, p.balance))
                        || j.funding
                            .values()
                            .find_map(|f| f.funded.as_ref().filter(|f| f.terms.id == *id))
                            .is_none_or(|f| {
                                r.value_after_stage1_sat > f.wallet_cost.token_amount_sat
                            })
                })
                || (s.released && !s.refunded)
                || (s.refunded != s.wallet_refund_sat.is_some())
                || s.wallet_refund_sat.is_some_and(|amount| {
                    s.report.as_ref().is_none_or(|r| amount != r.refunded_sat)
                })
            {
                return Err("invalid buyer settlement".into());
            }
        }
        for (id, s) in &j.seller_settlements {
            if id != &s.channel.id
                || (s.released && s.report.is_none())
                || (!j.incoming.values().any(|i| i.channel == s.channel)
                    && j.history.as_ref().and_then(|h| h.sellers.get(id)) != Some(&s.channel))
                || j.incoming
                    .values()
                    .any(|i| i.channel.id == *id && i.phase != Phase::Stopped)
                || s.usage.is_some_and(|u| !valid_usage(&s.channel, u))
                || s.payment.as_ref().is_some_and(|p| {
                    s.usage.is_none() || p.channel_id != *id || p.balance > s.channel.capacity_sat
                })
                || s.report.as_ref().is_some_and(|r| {
                    s.payment
                        .as_ref()
                        .is_none_or(|p| !valid_report(&s.channel, r, p.balance))
                })
            {
                return Err("invalid seller settlement".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
