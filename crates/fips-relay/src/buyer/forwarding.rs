//! Record local sends and couple onward purchases to upstream admission.
use super::*;

impl OriginatedSessionObserver for BuyerAuthorizer {
    fn prepare(&self, intent: &OriginatedSessionIntent) -> OriginatedSessionAdmission {
        self.prepare_intent(intent)
    }
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
    bootstrap: Option<Mutex<crate::unpaid_budget::UnpaidBudget>>,
    free: Arc<crate::free_routes::FreeRoutes>,
    returns: Option<Mutex<crate::return_allowance::ReturnAllowance>>,
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
        Self::with_free_routes(seller, buyer, billing, Arc::default())
    }

    pub fn with_free_routes(
        seller: Arc<DurableRelay>,
        buyer: Arc<BuyerAuthorizer>,
        billing: BillingBasis,
        free: Arc<crate::free_routes::FreeRoutes>,
    ) -> Self {
        Self {
            seller,
            buyer,
            pending: Mutex::new(BTreeMap::new()),
            free,
            returns: None,
            bootstrap: billing
                .has_free_handshakes()
                .then(|| Mutex::new(crate::unpaid_budget::UnpaidBudget::new())),
        }
    }

    pub fn bootstrap_stats(&self) -> Option<crate::bootstrap::BootstrapStats> {
        self.bootstrap.as_ref().map(|b| b.lock().unwrap().stats())
    }

    /// Optional complimentary replies, separate from existing paid agreements.
    pub fn with_return_allowance(mut self) -> Result<Self, String> {
        if self.bootstrap.is_none() {
            return Err("return allowance requires forwarding-data billing".into());
        }
        self.returns = Some(Mutex::new(crate::return_allowance::ReturnAllowance::new()));
        Ok(self)
    }

    pub fn return_stats(&self) -> Option<crate::return_allowance::ReturnStats> {
        self.returns.as_ref().map(|r| r.lock().unwrap().stats())
    }

    fn earn_return(&self, request: &ForwardingRequest<'_>) {
        if let Some(returns) = &self.returns {
            returns.lock().unwrap().earn(request);
        }
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
        if let Some(returns) = &self.returns {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            // Existing paid relationships keep their accounting semantics;
            // complimentary replies must not consume somebody else's channel.
            if !self
                .seller
                .has_active_route(*request.ingress.node_addr(), request.destination, now)
                && !self
                    .buyer
                    .has_active_route(request.next_hop, request.destination, now)
                && returns.lock().unwrap().admit(request)
            {
                return Some(0);
            }
        }
        if self.free.admit(request) {
            self.earn_return(request);
            return Some(0);
        }
        let (seller_token, buyer_token) = if request.next_hop == request.destination {
            (self.seller.admit(request)?, None)
        } else if let Some(token) = self.free.onward(
            request.next_hop,
            request.destination,
            request.session_payload.len(),
            || self.seller.admit(request),
        ) {
            (token, None)
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
        self.earn_return(request);
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

/// Source accounting shares the same negotiated free continuation as transit.
/// Free submissions cannot become evidence for a retained paid agreement.
#[derive(Debug)]
pub struct RouteObserver {
    pub buyer: Arc<BuyerAuthorizer>,
    pub free: Arc<crate::free_routes::FreeRoutes>,
}

impl OriginatedSessionObserver for RouteObserver {
    fn prepare(&self, intent: &OriginatedSessionIntent) -> OriginatedSessionAdmission {
        match self
            .free
            .prepare_onward(intent.next_hop, intent.destination, intent.session_bytes)
        {
            Some(true) => OriginatedSessionAdmission::Untracked,
            Some(false) => OriginatedSessionAdmission::Reject,
            None => self.buyer.prepare(intent),
        }
    }
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64> {
        if !crate::bootstrap::is_handshake(
            request.session_payload,
            request.source,
            request.destination,
        ) && self
            .free
            .onward(
                request.next_hop,
                request.destination,
                request.session_payload.len(),
                || Some(()),
            )
            .is_some()
        {
            return None;
        }
        self.buyer.observe(request)
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.buyer.complete(token, outcome);
    }
}
