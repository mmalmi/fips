//! Bound paid admission and complete local forwarding attempts.
use super::*;

impl RelayLedger {
    pub fn admit_at(&self, request: &ForwardingRequest<'_>, now_unix: u64) -> Option<u64> {
        self.admit_with_windows(request, now_unix, None)
    }

    pub(crate) fn admit_with_windows(
        &self,
        request: &ForwardingRequest<'_>,
        now_unix: u64,
        windows: Option<&BTreeMap<String, u64>>,
    ) -> Option<u64> {
        let units = u64::try_from(request.session_payload.len()).ok()?;
        if units == 0 {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        if state.pending.len() >= self.limits.max_pending {
            return None;
        }
        let id = state
            .accounts
            .iter()
            .find(|(_, a)| {
                a.active
                    && a.contract.destination == request.destination
                    && state.channels[&a.contract.channel_id].terms.buyer
                        == *request.ingress.node_addr()
            })?
            .0
            .clone();
        let token = state.next_token.checked_add(1)?;
        let a = &state.accounts[&id];
        if a.contract.billing.has_free_handshakes()
            && crate::bootstrap::is_handshake(
                request.session_payload,
                request.source,
                request.destination,
            )
        {
            // The external bootstrap policy may forward this within its own
            // limits. It must never create a paid seller reservation or claim.
            return None;
        }
        if a.contract.next_hop != request.next_hop
            || now_unix >= a.contract.expires_unix
            || (a.contract.billing.is_legacy()
                && a.attempts.len() >= self.limits.max_packets_per_contract)
        {
            return None;
        }
        let legacy = a.contract.billing.is_legacy();
        let digest = if legacy {
            fingerprint(request)
        } else {
            attempt_key(token)
        };
        if legacy && state.seen.contains(&(*request.ingress.node_addr(), digest)) {
            return None;
        }
        let prospective = a.usage.reserved_units.checked_add(units)?;
        if prospective > a.contract.max_units {
            return None;
        }
        let incremental_cost = a
            .contract
            .price
            .amount_due_msat(prospective)?
            .checked_sub(a.contract.price.amount_due_msat(a.usage.reserved_units)?)?;
        let channel_id = a.contract.channel_id.clone();
        let channel = &state.channels[&channel_id];
        if !channel.active || now_unix >= channel.terms.expires_unix {
            return None;
        }
        let channel_reserved = channel.usage.reserved_msat.checked_add(incremental_cost)?;
        let limit = relationship_reservation_limit(
            &channel.terms,
            channel.usage.paid_msat,
            state.channels.values().map(|c| (&c.terms, c.usage)),
            state.history.as_ref(),
        )?
        .min(windows.map_or(u64::MAX, |w| w.get(&channel_id).copied().unwrap_or(0)));
        if channel_reserved > limit {
            return None;
        }
        let a = state.accounts.get_mut(&id)?;
        a.usage.reserved_units = prospective;
        a.attempts.insert(
            digest,
            Attempt {
                token,
                units,
                state: AttemptState::Pending,
            },
        );
        state.channels.get_mut(&channel_id)?.usage.reserved_msat = channel_reserved;
        state.next_token = token;
        if legacy {
            state.seen.insert((*request.ingress.node_addr(), digest));
        }
        state.pending.insert(token, (id, digest));
        Some(token)
    }

    /// Used only by the durable wrapper, which must commit the recovered
    /// exposure and next windows before publishing this ledger to forwarding.
    pub(crate) fn recover_windows(
        snapshot: Snapshot,
        windows: &BTreeMap<String, u64>,
    ) -> Result<Self, LedgerError> {
        let recovered = Self::restore(snapshot.clone())?;
        let mut state = recovered.state.lock().unwrap();
        let mut buyers = std::collections::HashSet::new();
        let mut destinations = std::collections::HashSet::new();
        for saved in &snapshot.channels {
            let channel = state.channels.get_mut(&saved.terms.id).unwrap();
            if saved.active && !buyers.insert((saved.terms.buyer, saved.terms.mint_url.clone())) {
                return Err(LedgerError::InvalidSnapshot);
            }
            channel.active = saved.active;
        }
        for saved in &snapshot.accounts {
            let channel = &state.channels[&saved.contract.channel_id];
            if saved.active
                && (!channel.active
                    || !destinations.insert((channel.terms.buyer, saved.contract.destination)))
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            state.accounts.get_mut(&saved.contract.id).unwrap().active = saved.active;
        }
        for (id, ceiling) in windows {
            let has_quote = state
                .accounts
                .values()
                .any(|a| a.active && &a.contract.channel_id == id);
            let channel = state.channels.get(id).ok_or(LedgerError::InvalidSnapshot)?;
            let max = relationship_reservation_limit(
                &channel.terms,
                channel.usage.paid_msat,
                state.channels.values().map(|c| (&c.terms, c.usage)),
                state.history.as_ref(),
            )
            .ok_or(LedgerError::InvalidSnapshot)?;
            if !channel.active
                || !has_quote
                || *ceiling < channel.usage.reserved_msat
                || *ceiling > max
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            let channel = state.channels.get_mut(id).unwrap();
            let lost = ceiling - channel.usage.reserved_msat;
            channel.usage.lost_msat += lost;
            channel.usage.reserved_msat = *ceiling;
        }
        // Every active quote must have been bounded by a persisted window.
        if state
            .accounts
            .values()
            .any(|a| a.active && !windows.contains_key(&a.contract.channel_id))
        {
            return Err(LedgerError::InvalidSnapshot);
        }
        drop(state);
        Ok(recovered)
    }
}

impl ForwardingPolicy for RelayLedger {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.admit_at(
            request,
            SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs(),
        )
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some((id, digest)) = state.pending.remove(&token) else {
            return;
        };
        let a = state
            .accounts
            .get_mut(&id)
            .expect("pending account retained");
        let attempt = a
            .attempts
            .get_mut(&digest)
            .expect("pending digest retained");
        let old_cost = a
            .contract
            .price
            .amount_due_msat(a.usage.submitted_units)
            .expect("validated rate");
        match outcome {
            ForwardingOutcome::Submitted => {
                attempt.state = AttemptState::Submitted;
                a.usage.submitted_units += attempt.units;
            }
            ForwardingOutcome::Unconfirmed => {
                attempt.state = AttemptState::Unconfirmed;
                a.usage.unconfirmed_units += attempt.units;
            }
        }
        if !a.contract.billing.is_legacy() {
            let units = attempt.units;
            a.completed.reserved_units += units;
            match outcome {
                ForwardingOutcome::Submitted => a.completed.submitted_units += units,
                ForwardingOutcome::Unconfirmed => a.completed.unconfirmed_units += units,
            }
            a.attempts.remove(&digest);
        }
        let delta = a
            .contract
            .price
            .amount_due_msat(a.usage.submitted_units)
            .expect("validated rate")
            - old_cost;
        let channel_id = a.contract.channel_id.clone();
        state
            .channels
            .get_mut(&channel_id)
            .expect("account channel retained")
            .usage
            .submitted_msat += delta;
    }
}
