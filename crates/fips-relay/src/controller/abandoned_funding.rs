//! Reclaim an abandoned original wallet send without granting route authority.
use super::*;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(super) enum FundingReclaim {
    Pending,
    Cancelled,
    PreparedCancelled { wallet_operation_id: String },
    Complete { result: ReclaimedFunding },
}

impl FundingReclaim {
    pub(super) fn cancelled(&self) -> bool {
        matches!(self, Self::Cancelled | Self::PreparedCancelled { .. })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReclaimedFunding {
    pub wallet_operation_id: String,
    pub wallet_cost: cashu_service::CashuSendCost,
    pub recovered_amount_sat: u64,
}

impl FundingIntent {
    pub(super) fn cancelled(&self) -> bool {
        self.reclaim.as_ref().is_some_and(FundingReclaim::cancelled)
    }

    pub(super) fn reclaim_terminal(&self) -> bool {
        self.cancelled() || self.reclaimed().is_some()
    }

    pub(super) fn reclaimed(&self) -> Option<&ReclaimedFunding> {
        match &self.reclaim {
            Some(FundingReclaim::Complete { result }) => Some(result),
            _ => None,
        }
    }

    pub(super) fn validate_reclaim(&self, result: &ReclaimedFunding) -> Result<(), String> {
        self.validate_wallet_cost(&result.wallet_operation_id, &result.wallet_cost)?;
        if result.recovered_amount_sat > result.wallet_cost.token_amount_sat {
            return Err("wallet reclaim exceeds the original token".into());
        }
        Ok(())
    }
}

impl Controller {
    pub(super) fn provider_reclaiming(j: &Journal, provider: NodeAddr) -> bool {
        j.funding
            .values()
            .any(|f| f.provider == provider && matches!(f.reclaim, Some(FundingReclaim::Pending)))
    }

    pub(super) fn abandoned_funding(j: &Journal, intent: &FundingIntent) -> bool {
        intent.funded.is_none()
            && !intent.reclaim_terminal()
            && Self::funding_exclusively_withdrawn(j, intent)
    }

    /// The caller owns the wallet mutex. Persist this routing fence before the
    /// SDK can reclaim money; new source or transit work cannot reuse the intent.
    pub(super) fn prepare_funding_reclaim(
        j: &mut Journal,
        expected: &FundingIntent,
    ) -> Result<FundingIntent, String> {
        if !Self::abandoned_funding(j, expected) {
            return Err("funding is not exclusively withdrawn".into());
        }
        j.version |= journal::FUNDING_RECLAIM_VERSION;
        let intent = j.funding.get_mut(&expected.id).unwrap();
        intent.reclaim = Some(FundingReclaim::Pending);
        Ok(intent.clone())
    }

    pub(super) fn record_funding_reclaim(
        j: &mut Journal,
        expected: &FundingIntent,
        result: ReclaimedFunding,
    ) -> Result<(), String> {
        expected.validate_reclaim(&result)?;
        Self::record_reclaim_disposition(j, expected, FundingReclaim::Complete { result })
    }

    pub(super) fn record_wallet_reclaim(
        j: &mut Journal,
        expected: &FundingIntent,
        result: cashu_service::CashuSpilmanFundingReclaim,
    ) -> Result<(), String> {
        use cashu_service::CashuSpilmanFundingReclaim as Wallet;
        match result {
            Wallet::Missing | Wallet::NoPlan => Ok(()),
            Wallet::Cancelled => {
                Self::record_reclaim_disposition(j, expected, FundingReclaim::Cancelled)
            }
            Wallet::PreparedCancelled {
                wallet_operation_id,
            } => {
                FundingIntent::validate_wallet_operation(&wallet_operation_id)?;
                Self::record_reclaim_disposition(
                    j,
                    expected,
                    FundingReclaim::PreparedCancelled {
                        wallet_operation_id,
                    },
                )
            }
            Wallet::Reclaimed {
                wallet_operation_id,
                wallet_cost,
                recovered_amount_sat,
            } => Self::record_funding_reclaim(
                j,
                expected,
                ReclaimedFunding {
                    wallet_operation_id,
                    wallet_cost,
                    recovered_amount_sat,
                },
            ),
        }
    }

    fn record_reclaim_disposition(
        j: &mut Journal,
        expected: &FundingIntent,
        disposition: FundingReclaim,
    ) -> Result<(), String> {
        let current = j
            .funding
            .get(&expected.id)
            .ok_or("reclaim intent missing")?;
        if current.reclaim.as_ref() == Some(&disposition)
            && (matches!(expected.reclaim, Some(FundingReclaim::Pending))
                || expected.reclaim.as_ref() == Some(&disposition))
        {
            let mut previous = current.clone();
            previous.reclaim = expected.reclaim.clone();
            if previous == *expected {
                return Ok(());
            }
        }
        if current != expected
            || !matches!(current.reclaim, Some(FundingReclaim::Pending))
            || !Self::abandoned_funding(j, current)
        {
            return Err("wallet reclaim intent or result changed".into());
        }
        if disposition.cancelled() {
            j.version |= journal::FUNDING_CANCELLED_VERSION;
        }
        if matches!(disposition, FundingReclaim::PreparedCancelled { .. }) {
            j.version |= journal::PREPARED_CANCELLED_VERSION;
        }
        j.funding.get_mut(&expected.id).unwrap().reclaim = Some(disposition);
        Ok(())
    }

    /// Only restore-only SDK evidence may replace our pending disposition with
    /// an existing channel. An SDK reclaim fence rejects that restore; a terminal
    /// reclaimed result and ordinary late opening replies can never take this path.
    pub(super) fn record_restored_funding(
        j: &mut Journal,
        mut expected: FundingIntent,
        funded: Funded,
    ) -> Result<(), String> {
        if matches!(expected.reclaim, Some(FundingReclaim::Pending)) {
            if !Self::abandoned_funding(j, &expected) {
                return Err("restored funding withdrawal changed".into());
            }
            j.funding.get_mut(&expected.id).unwrap().reclaim = None;
            expected.reclaim = None;
        }
        Self::record_funding(j, expected, funded)
    }

    pub(super) fn validate_funding_reclaims(j: &Journal) -> Result<(), String> {
        for intent in j.funding.values().filter(|f| f.reclaim.is_some()) {
            if j.version & journal::FUNDING_RECLAIM_VERSION == 0 || intent.funded.is_some() {
                return Err("invalid reclaimed funding format".into());
            }
            match intent.reclaim.as_ref().unwrap() {
                FundingReclaim::Pending if !Self::abandoned_funding(j, intent) => {
                    return Err("pending reclaim acquired route authority".into());
                }
                FundingReclaim::Complete { result } => {
                    intent.validate_reclaim(result)?;
                    if j.outgoing.values().any(|o| o.funding_id == intent.id) {
                        return Err("reclaimed funding has an outgoing route".into());
                    }
                }
                FundingReclaim::Cancelled | FundingReclaim::PreparedCancelled { .. } => {
                    if j.version & journal::FUNDING_CANCELLED_VERSION == 0
                        || j.outgoing.values().any(|o| o.funding_id == intent.id)
                    {
                        return Err("invalid cancelled funding evidence".into());
                    }
                    if let Some(FundingReclaim::PreparedCancelled {
                        wallet_operation_id,
                    }) = &intent.reclaim
                    {
                        FundingIntent::validate_wallet_operation(wallet_operation_id)?;
                        if j.version & journal::PREPARED_CANCELLED_VERSION == 0 {
                            return Err("unsupported prepared cancellation evidence".into());
                        }
                    }
                }
                FundingReclaim::Pending => (),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod cancelled_tests;
#[cfg(test)]
mod tests;
