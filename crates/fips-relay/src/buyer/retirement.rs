use super::*;
use crate::ledger::Usage;

impl BuyerAuthorizer {
    /// Trusted controller maintenance after its durable route-stop/retirement
    /// intent. `through_unix` comes from the controller's clock, never a peer.
    /// Refuse the entire batch if an older route still has live, pending or
    /// legacy duplicate evidence. Channel signatures and lifetime budgets stay.
    pub fn retire_closed_routes(
        &self,
        channel: &str,
        through_unix: u64,
    ) -> Result<usize, BuyerError> {
        let mut count = 0;
        self.change(|s| {
            let plan = s.retirement_plan(channel, through_unix)?;
            count = plan.contracts.len();
            for contract in plan.contracts {
                s.quotes.remove(&contract.id);
            }
            s.channels.get_mut(channel).unwrap().retired = Some(plan.after);
            Ok(())
        })?;
        Ok(count)
    }

    pub(crate) fn retirement_plan(
        &self,
        channel: &str,
        through_unix: u64,
    ) -> Result<crate::ledger::RouteRetirementPlan, BuyerError> {
        let ready = self.writer_ready.lock().map_err(|_| BuyerError::Format)?;
        if !*ready {
            return Err(DurableError::Suspended.into());
        }
        self.state
            .lock()
            .map_err(|_| BuyerError::Format)?
            .retirement_plan(channel, through_unix)
    }

    pub fn retired_route_evidence(&self, channel: &str) -> Option<RetiredRouteEvidence> {
        self.state.lock().ok()?.channels.get(channel)?.retired
    }
}

impl State {
    fn retirement_plan(
        &self,
        channel: &str,
        through_unix: u64,
    ) -> Result<crate::ledger::RouteRetirementPlan, BuyerError> {
        let before = self
            .channels
            .get(channel)
            .ok_or(BuyerError::UnknownAgreement)?
            .retired
            .ok_or(BuyerError::Format)?;
        let mut plan = crate::ledger::RouteRetirementPlan {
            channel: channel.into(),
            through_unix,
            contracts: Vec::new(),
            before,
            after: before,
        };
        for q in self
            .quotes
            .values()
            .filter(|q| q.contract.channel_id == channel && q.contract.expires_unix <= through_unix)
        {
            if q.active || q.contract.billing.is_legacy() || !q.attempts.is_empty() {
                return Err(BuyerError::InvalidAgreement);
            }
            plan.after = plan
                .after
                .added(
                    &q.contract,
                    Usage {
                        reserved_units: q.observed_units,
                        submitted_units: q.submitted_units,
                        unconfirmed_units: q
                            .observed_units
                            .checked_sub(q.submitted_units)
                            .ok_or(BuyerError::Format)?,
                    },
                )
                .ok_or(BuyerError::Capacity)?;
            plan.contracts.push(q.contract.clone());
        }
        Ok(plan)
    }
}
