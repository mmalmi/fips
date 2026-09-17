//! One durable reservation per wallet operation; verified refunds release capital.
use super::*;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingBudget {
    pub pending_reserved_sat: u64,
    pub wallet_debited_sat: u64,
    pub wallet_refunded_sat: u64,
    pub locked_sat: u64,
    /// Worst-case net wallet spend, including all unresolved reservations.
    pub exposure_sat: u64,
}

impl FundingIntent {
    pub(super) fn validate_cost(&self, funded: &Funded) -> Result<(), String> {
        let cost = &funded.wallet_cost;
        if funded.wallet_operation_id.is_empty()
            || funded.wallet_operation_id.len() > 64
            || cost.token_amount_sat < self.capacity_sat
            || cost.token_amount_sat.checked_add(cost.swap_fee_sat) != Some(cost.wallet_debit_sat)
            || cost.wallet_debit_sat > self.max_wallet_debit_sat
        {
            return Err("funding cost does not match wallet approval".into());
        }
        Ok(())
    }
}

impl Controller {
    pub(super) fn capital(j: &Journal) -> Result<FundingBudget, String> {
        let mut budget = FundingBudget::default();
        if let Some(h) = j.history.as_ref().and_then(|h| h.channels.as_ref()) {
            budget.wallet_debited_sat = h.totals.cost.wallet_debit_sat;
            budget.wallet_refunded_sat = h.totals.refund_sat;
            budget.exposure_sat = budget
                .wallet_debited_sat
                .checked_sub(budget.wallet_refunded_sat)
                .ok_or("invalid retired capital")?;
        }
        let mut operations = HashSet::new();
        for f in j.funding.values() {
            if f.capacity_sat
                .checked_add(j.policy.max_funding_overhead_sat)
                != Some(f.max_wallet_debit_sat)
            {
                return Err("funding reservation changed".into());
            }
            let (debit, refund) = match &f.funded {
                Some(funded) => {
                    f.validate_cost(funded)?;
                    if !operations.insert(&funded.wallet_operation_id) {
                        return Err("wallet operation belongs to multiple funding intents".into());
                    }
                    let debit = funded.wallet_cost.wallet_debit_sat;
                    budget.wallet_debited_sat = add(budget.wallet_debited_sat, debit)?;
                    let settlement = j.buyer_settlements.get(&funded.terms.id);
                    let refund = settlement
                        .filter(|s| s.refunded)
                        .map(|s| {
                            s.wallet_refund_sat
                                .ok_or("completed settlement has no wallet refund evidence")
                        })
                        .transpose()?;
                    (debit, refund)
                }
                None => {
                    budget.pending_reserved_sat =
                        add(budget.pending_reserved_sat, f.max_wallet_debit_sat)?;
                    (f.max_wallet_debit_sat, None)
                }
            };
            if let Some(refund) = refund {
                if refund > debit {
                    return Err("wallet refund exceeds funding debit".into());
                }
                budget.wallet_refunded_sat = add(budget.wallet_refunded_sat, refund)?;
            } else {
                budget.locked_sat = add(budget.locked_sat, debit)?;
            }
            budget.exposure_sat = add(budget.exposure_sat, debit - refund.unwrap_or(0))?;
        }
        Ok(budget)
    }

    pub(super) fn validate_capital(j: &Journal) -> Result<(), String> {
        Self::validate_settlements(j)?;
        let budget = Self::capital(j)?;
        if budget.locked_sat > j.policy.max_locked_sat {
            return Err("working capital exhausted".into());
        }
        if budget.exposure_sat > j.policy.max_wallet_spend_sat {
            return Err("lifetime wallet spending budget exhausted".into());
        }
        Ok(())
    }

    pub async fn funding_budget(&self) -> Result<FundingBudget, String> {
        Self::capital(&self.snapshot().await?)
    }
}

fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b).ok_or("funding budget overflow".into())
}

#[cfg(test)]
mod tests;
