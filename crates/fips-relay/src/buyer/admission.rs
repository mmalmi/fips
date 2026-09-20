//! Share reservation between pre-seal source admission and admitted transit.
use super::*;

impl BuyerAuthorizer {
    pub(super) fn begin(
        &self,
        request: &OriginatedSessionRequest<'_>,
        local_only: bool,
    ) -> Option<u64> {
        self.begin_admitted(request, local_only, || Some(()))
            .map(|(token, ())| token)
    }

    /// Check the onward purchase before reserving upstream credit. Keep the
    /// buyer state locked across that short, memory-only admission so a renewal
    /// cannot close the onward quote between validation and reservation.
    pub(super) fn begin_admitted<T>(
        &self,
        request: &OriginatedSessionRequest<'_>,
        local_only: bool,
        admit: impl FnOnce() -> Option<T>,
    ) -> Option<(u64, T)> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let mut s = self.state.lock().ok()?;
        if (local_only && request.source != s.local)
            || request.next_hop == request.destination
            || request.session_payload.is_empty()
        {
            return None;
        }
        let id = s
            .quotes
            .iter()
            .find(|(_, q)| {
                let c = &s.channels[&q.contract.channel_id];
                q.active
                    && c.active
                    && c.provider == request.next_hop
                    && q.contract.destination == request.destination
                    && now < q.contract.expires_unix
                    && now < c.terms.expires_unix
            })?
            .0
            .clone();
        let billing = s.quotes[&id].contract.billing;
        if billing.has_free_handshakes()
            && crate::bootstrap::is_handshake(
                request.session_payload,
                request.source,
                request.destination,
            )
        {
            return None;
        }
        let legacy = billing.is_legacy();
        let digest = if legacy {
            session_fingerprint(request.source, request.destination, request.session_payload)
        } else {
            [0; 32]
        };
        let units = u64::try_from(request.session_payload.len()).ok()?;
        Self::reserve_attempt(&mut s, id, digest, units, local_only, admit)
    }

    pub(super) fn prepare_intent(
        &self,
        intent: &OriginatedSessionIntent,
    ) -> OriginatedSessionAdmission {
        use OriginatedSessionAdmission::{Defer, Reject, Track};
        let Some(now) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|t| t.as_secs())
        else {
            return Reject;
        };
        let Ok(mut state) = self.state.lock() else {
            return Reject;
        };
        if intent.source != state.local {
            return Reject;
        }
        if intent.next_hop == intent.destination {
            return Defer;
        }
        let matching = |q: &&PurchaseQuote| {
            state.channels[&q.contract.channel_id].provider == intent.next_hop
                && q.contract.destination == intent.destination
        };
        let active = state.quotes.values().filter(matching).find(|q| {
            let c = &state.channels[&q.contract.channel_id];
            q.active && c.active && now < q.contract.expires_unix && now < c.terms.expires_unix
        });
        let Some(quote) = active else {
            // A retained paid route cannot become an untracked send just because
            // its quota/account was closed, suspended or expired. Unknown routes
            // remain subject to the remote relay's bootstrap/return admission.
            return if state
                .quotes
                .values()
                .filter(matching)
                .any(|q| !q.contract.billing.is_legacy())
            {
                Reject
            } else {
                Defer
            };
        };
        if quote.contract.billing.is_legacy() {
            return Defer;
        }
        let id = quote.contract.id.clone();
        let Ok(units) = u64::try_from(intent.session_bytes) else {
            return Reject;
        };
        Self::reserve_attempt(&mut state, id, [0; 32], units, true, || Some(()))
            .map_or(Reject, |(token, ())| Track(token))
    }

    fn reserve_attempt<T>(
        s: &mut State,
        id: String,
        digest: [u8; 32],
        units: u64,
        source_admission: bool,
        admit: impl FnOnce() -> Option<T>,
    ) -> Option<(u64, T)> {
        if units == 0 || s.pending.len() >= s.limits.max_pending {
            return None;
        }
        let quote = s.quotes.get(&id)?;
        let provider = s.channels.get(&quote.contract.channel_id)?.provider;
        let legacy = quote.contract.billing.is_legacy();
        if legacy && s.seen.contains(&(provider, digest)) {
            return None;
        }
        let limit = s.limits.max_packets_per_contract;
        let token = s.next_token;
        let next_token = token.checked_add(1)?;
        let q = s.quotes.get_mut(&id)?;
        if legacy && q.attempts.len() >= limit {
            return None;
        }
        let Some(observed) = q
            .observed_units
            .checked_add(units)
            .filter(|n| *n <= q.contract.max_units)
        else {
            q.quota_blocked |= source_admission;
            return None;
        };
        let admitted = admit()?;
        q.observed_units = observed;
        let index = q.attempts.len();
        q.attempts.push(Attempt {
            digest,
            units,
            outcome: AttemptOutcome::Pending,
            token: if legacy { 0 } else { token },
        });
        s.pending.insert(token, (id, index));
        if legacy {
            s.seen.insert((provider, digest));
        }
        s.next_token = next_token;
        Some((token, admitted))
    }
}

impl BuyerAuthorizer {
    pub(crate) fn is_local(&self, local: NodeAddr) -> Result<bool, String> {
        Ok(self.state.lock().map_err(|_| "buyer state poisoned")?.local == local)
    }

    /// Retained accounting survives withdrawal and channel closure. It grants
    /// no routing authority; a replacement can carry only the unspent quota.
    pub(crate) fn retained_quota(
        &self,
        offer: &crate::route_quotes::RouteOffer,
    ) -> Result<Option<(bool, u64)>, String> {
        let state = self.state.lock().map_err(|_| "buyer state poisoned")?;
        let mut matching = matching_quotes(&state, offer);
        let retained = matching.next();
        if matching.next().is_some() {
            return Err("offer has ambiguous retained quota".into());
        }
        Ok(retained.map(|(quote, channel)| {
            (
                quote.active && channel.active,
                quote
                    .contract
                    .max_units
                    .saturating_sub(quote.observed_units),
            )
        }))
    }

    /// Read only actual local quota denial for the exact accepted offer. Quote
    /// IDs bind to channel-specific contract IDs; a matching destination alone
    /// cannot attribute denial to a new trial or changed agreement.
    pub(crate) fn quota_blocked(
        &self,
        offer: &crate::route_quotes::RouteOffer,
    ) -> Result<Option<bool>, String> {
        let state = self.state.lock().map_err(|_| "buyer state poisoned")?;
        Ok(matching_quotes(&state, offer)
            .find(|(quote, channel)| quote.active && channel.active)
            .map(|(quote, _)| quote.quota_blocked))
    }
}

fn matching_quotes<'a>(
    state: &'a State,
    offer: &'a crate::route_quotes::RouteOffer,
) -> impl Iterator<Item = (&'a PurchaseQuote, &'a PurchaseChannel)> {
    state.quotes.values().filter_map(move |quote| {
        let channel = &state.channels[&quote.contract.channel_id];
        (offer.buyer == state.local
            && channel.provider == offer.provider
            && crate::route_quotes::contract_from_offer(offer, &channel.terms)
                .is_ok_and(|contract| contract == quote.contract))
        .then_some((quote, channel))
    })
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
