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
            let mut retired = s
                .channels
                .get(channel)
                .ok_or(BuyerError::UnknownAgreement)?
                .retired
                .ok_or(BuyerError::Format)?;
            let mut ids = Vec::new();
            for (id, q) in s.quotes.iter().filter(|(_, q)| {
                q.contract.channel_id == channel && q.contract.expires_unix <= through_unix
            }) {
                if q.active || q.contract.billing.is_legacy() || !q.attempts.is_empty() {
                    return Err(BuyerError::InvalidAgreement);
                }
                retired = retired
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
                ids.push(id.clone());
            }
            count = ids.len();
            for id in ids {
                s.quotes.remove(&id);
            }
            s.channels.get_mut(channel).unwrap().retired = Some(retired);
            Ok(())
        })?;
        Ok(count)
    }

    pub fn retired_route_evidence(&self, channel: &str) -> Option<RetiredRouteEvidence> {
        self.state.lock().ok()?.channels.get(channel)?.retired
    }
}
