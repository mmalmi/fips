use super::*;

impl RelayLedger {
    /// Trusted maintenance after the controller has retained its retirement
    /// intent. Unresolved sends, active routes and legacy fingerprints block
    /// the whole expiry prefix. Financial totals and channel identity stay.
    pub fn retire_closed_routes(
        &self,
        channel: &str,
        through_unix: u64,
    ) -> Result<usize, LedgerError> {
        let mut state = self.state.lock().unwrap();
        let plan = state.retirement_plan(channel, through_unix)?;
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
        Ok(plan)
    }
}
