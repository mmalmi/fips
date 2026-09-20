use super::*;
use std::collections::HashSet;

impl RelayLedger {
    /// Trusted maintenance after the controller has retained its retirement
    /// intent. Unresolved sends, active routes and legacy fingerprints block
    /// the whole expiry prefix. Financial totals and channel identity stay.
    pub fn retire_closed_routes(
        &self,
        channel: &str,
        through_unix: u64,
    ) -> Result<usize, LedgerError> {
        self.retire_closed_routes_with_uninstalled(channel, through_unix, &[])
    }

    pub(crate) fn retire_closed_routes_with_uninstalled(
        &self,
        channel: &str,
        through_unix: u64,
        uninstalled: &[Contract],
    ) -> Result<usize, LedgerError> {
        if uninstalled.len() > self.limits.max_contracts {
            return Err(LedgerError::Capacity);
        }
        let mut state = self.state.lock().unwrap();
        let plan = state.retirement_plan_with_uninstalled(channel, through_unix, uninstalled)?;
        let count = plan.contracts.len();
        for contract in plan.contracts {
            state.accounts.remove(&contract.id);
        }
        state.channels.get_mut(channel).unwrap().retired = plan.after;
        Ok(count)
    }

    pub(crate) fn retirement_plan(
        &self,
        channel: &str,
        through_unix: u64,
    ) -> Result<RouteRetirementPlan, LedgerError> {
        self.state
            .lock()
            .unwrap()
            .retirement_plan(channel, through_unix)
    }

    pub(crate) fn retirement_plan_with_uninstalled(
        &self,
        channel: &str,
        through_unix: u64,
        uninstalled: &[Contract],
    ) -> Result<RouteRetirementPlan, LedgerError> {
        if uninstalled.len() > self.limits.max_contracts {
            return Err(LedgerError::Capacity);
        }
        self.state.lock().unwrap().retirement_plan_with_uninstalled(
            channel,
            through_unix,
            uninstalled,
        )
    }

    pub fn retired_route_evidence(&self, channel: &str) -> Option<RetiredRouteEvidence> {
        Some(self.state.lock().ok()?.channels.get(channel)?.retired)
    }
}

impl State {
    fn retirement_plan(
        &self,
        channel: &str,
        through_unix: u64,
    ) -> Result<RouteRetirementPlan, LedgerError> {
        self.retirement_plan_with_uninstalled(channel, through_unix, &[])
    }

    fn retirement_plan_with_uninstalled(
        &self,
        channel: &str,
        through_unix: u64,
        uninstalled: &[Contract],
    ) -> Result<RouteRetirementPlan, LedgerError> {
        let terms = &self
            .channels
            .get(channel)
            .ok_or(LedgerError::UnknownContract)?
            .terms;
        let before = self
            .channels
            .get(channel)
            .ok_or(LedgerError::UnknownContract)?
            .retired;
        let mut plan = RouteRetirementPlan {
            channel: channel.into(),
            through_unix,
            contracts: Vec::new(),
            before,
            after: before,
        };
        for a in self
            .accounts
            .values()
            .filter(|a| a.contract.channel_id == channel && a.contract.expires_unix <= through_unix)
        {
            if a.active || a.contract.billing.is_legacy() || !a.attempts.is_empty() {
                return Err(LedgerError::InvalidContract);
            }
            plan.after = plan
                .after
                .added(&a.contract, a.usage)
                .ok_or(LedgerError::Capacity)?;
            plan.contracts.push(a.contract.clone());
        }
        let mut ids = HashSet::new();
        for contract in uninstalled {
            validate_contract(contract, terms)?;
            if contract.channel_id != channel
                || contract.expires_unix > through_unix
                || contract.billing.is_legacy()
                || !ids.insert(&contract.id)
                || self.accounts.contains_key(&contract.id)
            {
                return Err(LedgerError::InvalidContract);
            }
            // A completed handoff is observed through its exact saved rollup by
            // the controller. Never create an account or reset existing usage.
            if before.rejects(contract.expires_unix) {
                continue;
            }
            plan.after = plan
                .after
                .added(contract, Usage::default())
                .ok_or(LedgerError::Capacity)?;
            plan.contracts.push(contract.clone());
        }
        Ok(plan)
    }
}
