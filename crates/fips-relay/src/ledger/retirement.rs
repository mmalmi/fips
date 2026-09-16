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
        let mut retired = state
            .channels
            .get(channel)
            .ok_or(LedgerError::UnknownContract)?
            .retired;
        let mut ids = Vec::new();
        for (id, a) in state.accounts.iter().filter(|(_, a)| {
            a.contract.channel_id == channel && a.contract.expires_unix <= through_unix
        }) {
            if a.active || a.contract.billing.is_legacy() || !a.attempts.is_empty() {
                return Err(LedgerError::InvalidContract);
            }
            retired = retired
                .added(&a.contract, a.usage)
                .ok_or(LedgerError::Capacity)?;
            ids.push(id.clone());
        }
        let count = ids.len();
        for id in ids {
            state.accounts.remove(&id);
        }
        state.channels.get_mut(channel).unwrap().retired = retired;
        Ok(count)
    }

    pub fn retired_route_evidence(&self, channel: &str) -> Option<RetiredRouteEvidence> {
        Some(self.state.lock().ok()?.channels.get(channel)?.retired)
    }
}
