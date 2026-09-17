//! Completed seller channels keep unpaid exposure attached to buyer and mint.
use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct History {
    pub channels: u64,
    pub expires_through_unix: u64,
    pub capacity_sat: u64,
    pub usage: ChannelUsage,
    pub routes: RetiredRouteEvidence,
    debts: Vec<Debt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Debt {
    #[serde(with = "node_addr")]
    buyer: NodeAddr,
    mint: String,
    msat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Plan {
    pub before: History,
    pub after: History,
    pub channels: Vec<ChannelSnapshot>,
}

impl History {
    pub(super) fn debt(&self, terms: &ChannelTerms) -> u64 {
        self.debts
            .iter()
            .find(|d| d.buyer == terms.buyer && d.mint == terms.mint_url)
            .map_or(0, |d| d.msat)
    }

    pub(crate) fn valid(&self, max_debts: usize) -> bool {
        if self.channels == 0 {
            return *self == Self::default();
        }
        let mut seen = std::collections::HashSet::new();
        let debt = self.debts.iter().try_fold(0u64, |sum, d| {
            if d.msat == 0
                || d.mint.is_empty()
                || d.mint.len() > 512
                || !seen.insert((d.buyer, &d.mint))
            {
                return None;
            }
            sum.checked_add(d.msat)
        });
        self.debts.len() <= max_debts
            && self.debts.len() as u64 <= self.channels
            && self.channels <= self.capacity_sat
            && self.expires_through_unix != 0
            && self.usage.paid_msat as u128 <= self.capacity_sat as u128 * 1000
            && self.usage.reserved_msat as u128 <= self.capacity_sat as u128 * 1000
            && self.routes.valid(self.expires_through_unix)
            && self.routes.reserved_msat.checked_add(self.usage.lost_msat)
                == Some(self.usage.reserved_msat)
            && self.routes.submitted_msat == self.usage.submitted_msat
            && debt.is_some_and(|d| {
                d <= self.usage.reserved_msat
                    && d >= self
                        .usage
                        .reserved_msat
                        .saturating_sub(self.usage.paid_msat)
            })
    }

    fn added(&self, c: &ChannelSnapshot) -> Result<Self, LedgerError> {
        let mut next = self.clone();
        next.channels = add(next.channels, 1)?;
        next.capacity_sat = add(next.capacity_sat, c.terms.capacity_sat)?;
        next.expires_through_unix = next.expires_through_unix.max(c.terms.expires_unix);
        next.usage = ChannelUsage {
            reserved_msat: add(next.usage.reserved_msat, c.usage.reserved_msat)?,
            submitted_msat: add(next.usage.submitted_msat, c.usage.submitted_msat)?,
            lost_msat: add(next.usage.lost_msat, c.usage.lost_msat)?,
            paid_msat: add(next.usage.paid_msat, c.usage.paid_msat)?,
        };
        next.routes = next
            .routes
            .merged(c.retired.ok_or(LedgerError::InvalidSnapshot)?)
            .ok_or(LedgerError::Capacity)?;
        let debt = c.usage.reserved_msat.saturating_sub(c.usage.paid_msat);
        if debt != 0 {
            if let Some(d) = next
                .debts
                .iter_mut()
                .find(|d| d.buyer == c.terms.buyer && d.mint == c.terms.mint_url)
            {
                d.msat = add(d.msat, debt)?;
            } else {
                next.debts.push(Debt {
                    buyer: c.terms.buyer,
                    mint: c.terms.mint_url.clone(),
                    msat: debt,
                });
                next.debts.sort_by(|a, b| {
                    (a.buyer.as_bytes(), &a.mint).cmp(&(b.buyer.as_bytes(), &b.mint))
                });
            }
        }
        Ok(next)
    }
}

impl Plan {
    pub(crate) fn validate(&self, limit: usize) -> Result<(), LedgerError> {
        let mut after = self.before.clone();
        let mut ids = std::collections::HashSet::new();
        for c in &self.channels {
            let capacity = validate_channel(&c.terms)?;
            let routes = c.retired.ok_or(LedgerError::InvalidSnapshot)?;
            if c.active
                || !ids.insert(&c.terms.id)
                || !routes.valid(c.terms.expires_unix)
                || c.usage.paid_msat > capacity
                || c.usage.reserved_msat > capacity
                || c.usage.reserved_msat > c.usage.paid_msat.saturating_add(c.terms.grace_msat)
                || routes.reserved_msat.checked_add(c.usage.lost_msat)
                    != Some(c.usage.reserved_msat)
                || routes.submitted_msat != c.usage.submitted_msat
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            after = after.added(c)?;
        }
        if self.channels.is_empty()
            || self.channels.len() > limit
            || after != self.after
            || !self.before.valid(limit)
            || !self.after.valid(limit)
        {
            return Err(LedgerError::Capacity);
        }
        Ok(())
    }
}

impl RelayLedger {
    pub(crate) fn channel_retirement_plan(
        &self,
        ids: &[String],
        now: u64,
    ) -> Result<Plan, LedgerError> {
        let state = self.state.lock().unwrap();
        let before = state.history.clone().unwrap_or_default();
        let mut plan = Plan {
            after: before.clone(),
            before,
            channels: Vec::new(),
        };
        for id in ids {
            let c = state.channels.get(id).ok_or(LedgerError::UnknownContract)?;
            if c.active
                || c.terms.expires_unix >= now
                || state
                    .accounts
                    .values()
                    .any(|a| a.contract.channel_id == *id)
            {
                return Err(LedgerError::InvalidContract);
            }
            let c = ChannelSnapshot {
                terms: c.terms.clone(),
                usage: c.usage,
                retired: Some(c.retired),
                active: false,
            };
            plan.after = plan.after.added(&c)?;
            plan.channels.push(c);
        }
        plan.validate(self.limits.max_channels)?;
        Ok(plan)
    }

    pub(crate) fn retire_channels(&self, plan: &Plan) -> Result<bool, LedgerError> {
        plan.validate(self.limits.max_channels)?;
        let mut state = self.state.lock().unwrap();
        if state.history.as_ref() == Some(&plan.after)
            && plan
                .channels
                .iter()
                .all(|c| !state.channels.contains_key(&c.terms.id))
        {
            return Ok(false);
        }
        if state.history.clone().unwrap_or_default() != plan.before
            || plan.channels.iter().any(|c| {
                state.channels.get(&c.terms.id).is_none_or(|s| {
                    s.active
                        || s.terms != c.terms
                        || s.usage != c.usage
                        || Some(s.retired) != c.retired
                }) || state
                    .accounts
                    .values()
                    .any(|a| a.contract.channel_id == c.terms.id)
            })
        {
            return Err(LedgerError::InvalidSnapshot);
        }
        for c in &plan.channels {
            state.channels.remove(&c.terms.id);
        }
        state.history = Some(plan.after.clone());
        Ok(true)
    }
}

/// Each old channel contributes its own nonnegative debt. An overpayment on a
/// different channel never erases it or turns lost evidence into a new bill.
pub(super) fn relationship_reservation_limit<'a>(
    terms: &ChannelTerms,
    paid_msat: u64,
    channels: impl Iterator<Item = (&'a ChannelTerms, ChannelUsage)>,
    history: Option<&History>,
) -> Option<u64> {
    let carried = channels
        .filter(|(old, _)| {
            old.id != terms.id && old.buyer == terms.buyer && old.mint_url == terms.mint_url
        })
        .try_fold(history.map_or(0, |h| h.debt(terms)), |sum, (_, usage)| {
            sum.checked_add(usage.reserved_msat.saturating_sub(usage.paid_msat))
        })?;
    Some(
        terms.capacity_sat.checked_mul(1000)?.min(
            paid_msat
                .saturating_add(terms.grace_msat)
                .saturating_sub(carried),
        ),
    )
}

fn add(a: u64, b: u64) -> Result<u64, LedgerError> {
    a.checked_add(b).ok_or(LedgerError::Capacity)
}

#[cfg(test)]
mod tests;
