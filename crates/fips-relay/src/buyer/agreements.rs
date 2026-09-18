use super::*;

impl BuyerAuthorizer {
    /// Trusted acceptance, separate from an untrusted provider's usage report.
    /// A funded channel starts at zero; any explicit advance is a total allowance
    /// for this channel, never a per-quote/per-update allowance.
    pub fn accept_channel(
        &self,
        provider: NodeAddr,
        terms: ChannelTerms,
        advance_msat: u64,
    ) -> Result<(), BuyerError> {
        let capacity = validate_channel(&terms).map_err(|_| BuyerError::InvalidAgreement)?;
        self.change(|state| {
            if terms.buyer != state.local || provider == state.local || advance_msat > capacity {
                return Err(BuyerError::InvalidAgreement);
            }
            if let Some(c) = state.channels.get(&terms.id) {
                return if c.provider == provider
                    && c.terms == terms
                    && c.advance_msat == advance_msat
                {
                    Ok(())
                } else {
                    Err(BuyerError::InvalidAgreement)
                };
            }
            if state
                .history
                .as_ref()
                .is_some_and(|h| terms.expires_unix <= h.expires_through_unix)
            {
                return Err(BuyerError::Expired);
            }
            if state.channels.len() >= state.limits.max_channels {
                return Err(BuyerError::Capacity);
            }
            if state
                .channels
                .values()
                .any(|c| c.active && c.provider == provider && c.terms.mint_url == terms.mint_url)
            {
                return Err(BuyerError::InvalidAgreement);
            }
            state.channels.insert(
                terms.id.clone(),
                PurchaseChannel {
                    provider,
                    terms,
                    advance_msat,
                    authorized_sat: 0,
                    retired: Some(RetiredRouteEvidence::default()),
                    active: true,
                },
            );
            Ok(())
        })
    }

    pub fn accept_quote(&self, contract: Contract) -> Result<(), BuyerError> {
        self.change(|state| {
            let c = state
                .channels
                .get(&contract.channel_id)
                .ok_or(BuyerError::UnknownAgreement)?;
            validate_contract(&contract, &c.terms).map_err(|_| BuyerError::InvalidAgreement)?;
            if c.retired
                .ok_or(BuyerError::Format)?
                .rejects(contract.expires_unix)
            {
                return Err(BuyerError::Expired);
            }
            if let Some(q) = state.quotes.get(&contract.id) {
                return if q.contract == contract {
                    Ok(())
                } else {
                    Err(BuyerError::InvalidAgreement)
                };
            }
            if !c.active || contract.destination == c.provider {
                return Err(BuyerError::InvalidAgreement);
            }
            if state.quotes.len() >= state.limits.max_contracts {
                return Err(BuyerError::Capacity);
            }
            if state.quotes.values().any(|q| {
                q.active
                    && q.contract.destination == contract.destination
                    && state.channels[&q.contract.channel_id].provider == c.provider
            }) {
                return Err(BuyerError::InvalidAgreement);
            }
            state.quotes.insert(
                contract.id.clone(),
                PurchaseQuote {
                    contract,
                    active: true,
                    attempts: Vec::new(),
                    observed_units: 0,
                    submitted_units: 0,
                    completed: CompletedEvidence::default(),
                },
            );
            Ok(())
        })
    }

    pub fn close_quote(&self, id: &str) -> Result<(), BuyerError> {
        // Withdrawal must stop packet admission even if a previous write failed.
        // Keep writer -> state ordering, and retain the error for recovery.
        let (mut ready, healthy) = match self.writer_ready.lock() {
            Ok(ready) => (ready, true),
            Err(poisoned) => (poisoned.into_inner(), false),
        };
        let snapshot = {
            let mut state = self.state.lock().map_err(|_| DurableError::Suspended)?;
            state
                .quotes
                .get_mut(id)
                .ok_or(BuyerError::UnknownAgreement)?
                .active = false;
            if !healthy || !*ready {
                return Err(DurableError::Suspended.into());
            }
            state.clone()
        };
        self.persist(&snapshot, &mut ready)
    }

    /// Stop new purchase evidence. Final claims can still be signed until expiry;
    /// mint settlement/refund and channel funding are separate controller work.
    pub fn close_channel(&self, id: &str) -> Result<(), BuyerError> {
        self.change(|s| {
            s.channels
                .get_mut(id)
                .ok_or(BuyerError::UnknownAgreement)?
                .active = false;
            for q in s
                .quotes
                .values_mut()
                .filter(|q| q.contract.channel_id == id)
            {
                q.active = false;
            }
            Ok(())
        })
    }
}
