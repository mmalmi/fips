//! Record local sends and couple onward purchases to upstream admission.
use super::*;

impl BuyerAuthorizer {
    fn begin(&self, request: &OriginatedSessionRequest<'_>, local_only: bool) -> Option<u64> {
        self.begin_admitted(request, local_only, || Some(()))
            .map(|(token, ())| token)
    }

    /// Check the onward purchase before reserving upstream credit. Keep the
    /// buyer state locked across that short, memory-only admission so a renewal
    /// cannot close the onward quote between validation and reservation.
    fn begin_admitted<T>(
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
            || s.pending.len() >= s.limits.max_pending
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
        if legacy && s.seen.contains(&(request.next_hop, digest)) {
            return None;
        }
        let limit = s.limits.max_packets_per_contract;
        let token = s.next_token;
        let next_token = token.checked_add(1)?;
        let q = s.quotes.get_mut(&id)?;
        let units = u64::try_from(request.session_payload.len()).ok()?;
        let observed = q.observed_units.checked_add(units)?;
        if (legacy && q.attempts.len() >= limit) || observed > q.contract.max_units {
            return None;
        }
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
            s.seen.insert((request.next_hop, digest));
        }
        s.next_token = next_token;
        Some((token, admitted))
    }
}

impl OriginatedSessionObserver for BuyerAuthorizer {
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64> {
        self.begin(request, true)
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let Ok(mut s) = self.state.lock() else {
            return;
        };
        let Some((id, index)) = s.pending.remove(&token) else {
            return;
        };
        let q = s.quotes.get_mut(&id).expect("retained quote");
        let a = &mut q.attempts[index];
        a.outcome = match outcome {
            ForwardingOutcome::Submitted => {
                q.submitted_units += a.units;
                AttemptOutcome::Submitted
            }
            ForwardingOutcome::Unconfirmed => AttemptOutcome::Unconfirmed,
        };
        if !q.contract.billing.is_legacy() {
            let a = q.attempts.swap_remove(index);
            q.completed.observed_units += a.units;
            if outcome == ForwardingOutcome::Submitted {
                q.completed.submitted_units += a.units;
            }
            let moved = q.attempts.get(index).map(|a| a.token);
            if let Some(token) = moved {
                s.pending
                    .get_mut(&token)
                    .expect("pending attempt retained")
                    .1 = index;
            }
        }
    }
}

/// Transit evidence can incur a downstream obligation only after the upstream
/// seller policy admits that packet. The received packet's claimed source alone
/// never authorizes a purchase. A direct final endpoint needs no onward channel.
#[derive(Debug)]
pub struct PaidForwarder {
    seller: Arc<DurableRelay>,
    buyer: Arc<BuyerAuthorizer>,
    pending: Mutex<BTreeMap<u64, Option<u64>>>,
    bootstrap: Option<Mutex<crate::bootstrap::Bootstrap>>,
}

impl PaidForwarder {
    pub fn new(seller: Arc<DurableRelay>, buyer: Arc<BuyerAuthorizer>) -> Self {
        Self::for_billing(seller, buyer, BillingBasis::UniqueSessionEnvelope)
    }

    /// Enable the bounded free handshake tier only for an explicitly selected
    /// tariff. Existing callers and saved legacy tariffs keep their semantics.
    pub fn for_billing(
        seller: Arc<DurableRelay>,
        buyer: Arc<BuyerAuthorizer>,
        billing: BillingBasis,
    ) -> Self {
        Self {
            seller,
            buyer,
            pending: Mutex::new(BTreeMap::new()),
            bootstrap: billing
                .has_free_handshakes()
                .then(|| Mutex::new(crate::bootstrap::Bootstrap::new())),
        }
    }

    pub fn bootstrap_stats(&self) -> Option<crate::bootstrap::BootstrapStats> {
        self.bootstrap.as_ref().map(|b| b.lock().unwrap().stats())
    }
}

impl ForwardingPolicy for PaidForwarder {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        if let Some(bootstrap) = &self.bootstrap
            && crate::bootstrap::is_handshake(
                request.session_payload,
                request.source,
                request.destination,
            )
        {
            // Seller tokens start at one and never wrap. Zero carries no paid
            // reservation; its completion is a no-op. The rate budget is spent
            // at admission even if transport submission later fails.
            return bootstrap
                .lock()
                .unwrap()
                .admit(*request.ingress.node_addr(), request.session_payload.len())
                .then_some(0);
        }
        let (seller_token, buyer_token) = if request.next_hop == request.destination {
            (self.seller.admit(request)?, None)
        } else {
            let (buyer_token, seller_token) = self.buyer.begin_admitted(
                &OriginatedSessionRequest {
                    source: request.source,
                    destination: request.destination,
                    next_hop: request.next_hop,
                    session_payload: request.session_payload,
                },
                false,
                || self.seller.admit(request),
            )?;
            (seller_token, Some(buyer_token))
        };
        self.pending
            .lock()
            .unwrap()
            .insert(seller_token, buyer_token);
        Some(seller_token)
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        if token == 0 {
            return;
        }
        if let Some(buyer_token) = self.pending.lock().unwrap().remove(&token) {
            self.seller.complete(token, outcome);
            if let Some(token) = buyer_token {
                self.buyer.complete(token, outcome);
            }
        }
    }
}
