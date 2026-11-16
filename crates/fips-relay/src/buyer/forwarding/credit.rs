//! Compose incoming credit with the same onward authorization as Cashu.
use super::*;
use fips_core::node::ForwardingDecision;

const MAX_PENDING: usize = 1024;

#[derive(Debug)]
enum Completion {
    Cashu(u64),
    Onward(u64),
}

#[derive(Debug, Default)]
struct Pending {
    next: u64,
    tokens: BTreeMap<u64, Completion>,
}

/// Existing Cashu routes take precedence, even when exhausted or waiting for a
/// renewal. Credit pays only the incoming hop; forwarding to another relay still
/// needs an independently approved onward contract or negotiated free route.
#[derive(Debug)]
pub struct PeerCreditForwarder {
    relay: PaidForwarder,
    credit: Arc<fips_credit::CreditForwarder>,
    pending: Mutex<Pending>,
}

impl PeerCreditForwarder {
    pub(super) fn new(relay: PaidForwarder, credit: Arc<fips_credit::CreditForwarder>) -> Self {
        Self {
            relay,
            credit,
            pending: Mutex::new(Pending::default()),
        }
    }

    fn admit_credit(
        &self,
        request: &ForwardingRequest<'_>,
    ) -> Result<Option<Completion>, ForwardingDecision> {
        let admit = || self.credit.admit(request);
        if request.next_hop == request.destination {
            admit().ok_or(ForwardingDecision::Reject)?;
            return Ok(None);
        }
        if self
            .relay
            .free
            .onward(
                request.next_hop,
                request.destination,
                request.session_payload.len(),
                admit,
            )
            .is_some()
        {
            return Ok(None);
        }
        // Buyer checks its budget before invoking the credit-admission callback.
        // Failed or paused onward purchases consume no incoming credit.
        let (token, _) = self.relay.buyer.begin_admitted(
            &OriginatedSessionRequest {
                source: request.source,
                destination: request.destination,
                next_hop: request.next_hop,
                session_payload: request.session_payload,
            },
            false,
            admit,
            || self.credit.can_admit(request),
        )?;
        Ok(Some(Completion::Onward(token)))
    }
}

impl ForwardingPolicy for PeerCreditForwarder {
    fn admission_notify(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.relay.admission_notify()
    }

    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.decide(request).admission().map(|a| a.token)
    }

    fn admit_classified(&self, request: &ForwardingRequest<'_>) -> Option<ForwardingAdmission> {
        self.decide(request).admission()
    }

    fn decide(&self, request: &ForwardingRequest<'_>) -> ForwardingDecision {
        self.decide_with_bid(request, &mut 0)
    }

    fn decide_with_bid(&self, request: &ForwardingRequest<'_>, bid: &mut u64) -> ForwardingDecision {
        *bid = 0;
        // Preserve the existing bounded bootstrap tier even when data completion
        // slots are full. It returns token zero and creates no paid reservation.
        if self.relay.bootstrap.is_some()
            && crate::bootstrap::is_handshake(
                request.session_payload,
                request.source,
                request.destination,
            )
        {
            return self.relay.decide_with_bid(request, bid);
        }
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return ForwardingDecision::Reject;
        };
        let Ok(mut pending) = self.pending.lock() else {
            return ForwardingDecision::Reject;
        };
        let Some(next) = pending.next.checked_add(1) else {
            return ForwardingDecision::Reject;
        };
        if pending.tokens.len() >= MAX_PENDING {
            return ForwardingDecision::Reject;
        }
        let use_cashu = !self.credit.has_route(request)
            || self.relay.seller.has_active_route(
                *request.ingress.node_addr(),
                request.destination,
                now.as_secs(),
            );
        let (completion, class) = if use_cashu {
            match self.relay.decide_with_bid(request, bid) {
                ForwardingDecision::Admit(admission) if admission.token == 0 => {
                    return ForwardingDecision::Admit(admission);
                }
                ForwardingDecision::Admit(admission) => {
                    (Some(Completion::Cashu(admission.token)), admission.class)
                }
                other => return other,
            }
        } else {
            match self.admit_credit(request) {
                Ok(completion) => (completion, ForwardingClass::Normal),
                Err(decision) => return decision,
            }
        };
        // Inner Cashu/buyer token namespaces may overlap. Only this wrapper's
        // monotonically allocated tokens escape to the node's completion hook.
        let token = if let Some(completion) = completion {
            pending.next = next;
            pending.tokens.insert(next, completion);
            next
        } else {
            0
        };
        ForwardingDecision::Admit(ForwardingAdmission { token, class })
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let completion = self
            .pending
            .lock()
            .ok()
            .and_then(|mut p| p.tokens.remove(&token));
        match completion {
            Some(Completion::Cashu(inner)) => self.relay.complete(inner, outcome),
            Some(Completion::Onward(inner)) => self.relay.buyer.complete(inner, outcome),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests;
