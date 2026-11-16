//! Application admission only: no new FIPS messages, routing rules or consensus.
//! A controller installs durably reserved windows outside the packet loop.
use fips_core::{
    NodeAddr, PeerIdentity,
    node::{
        ForwardingAdmission, ForwardingClass, ForwardingOutcome, ForwardingPolicy,
        ForwardingRequest,
    },
};
use peer_payments::{Allowance, Error};
use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// Charge the authenticated neighbor, never the claimed end-to-end source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub ingress_pubkey: [u8; 32],
    pub next_hop: NodeAddr,
    pub destination: NodeAddr,
}
impl Route {
    fn payer(&self) -> String {
        self.ingress_pubkey
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    pub fn resource(&self) -> String {
        format!(
            "forward:{}:{}:{}",
            self.payer(),
            self.next_hop,
            self.destination
        )
    }
    fn from_request(request: &ForwardingRequest<'_>) -> Self {
        Self {
            ingress_pubkey: request.ingress.pubkey().serialize(),
            next_hop: request.next_hop,
            destination: request.destination,
        }
    }
}

#[derive(Debug)]
pub struct CreditForwarder {
    provider: String,
    windows: Mutex<BTreeMap<Route, Allowance>>,
}
impl CreditForwarder {
    /// Presence selects this explicitly negotiated payment method, including
    /// when exhausted. It must not silently become an unlimited/free session.
    pub fn has_route(&self, request: &ForwardingRequest<'_>) -> bool {
        self.windows
            .lock()
            .is_ok_and(|windows| windows.contains_key(&Route::from_request(request)))
    }

    /// Read-only scheduling hint for an already approved onward purchase.
    /// Actual admission rechecks and consumes the window under the same lock.
    pub fn can_admit(&self, request: &ForwardingRequest<'_>) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let Ok(units) = u64::try_from(request.session_payload.len()) else {
            return false;
        };
        self.windows.lock().is_ok_and(|windows| {
            windows
                .get(&Route::from_request(request))
                .is_some_and(|window| window.can_admit(units, now.as_secs()))
        })
    }

    pub fn remove(&self, route: &Route) -> Result<(), Error> {
        self.windows
            .lock()
            .map_err(|_| Error::Closed)?
            .remove(route);
        Ok(())
    }
    pub fn new(provider: &PeerIdentity) -> Self {
        Self {
            provider: provider.pubkey().to_string(),
            windows: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn install(&self, route: Route, allowance: Allowance) -> Result<(), Error> {
        let a = allowance.agreement();
        if a.provider != self.provider || a.payer != route.payer() {
            return Err(Error::Authentication);
        }
        // An attempt has a different price/evidence contract from useful receipt
        // delivery. Local submission does not prove that a destination received it.
        if a.service != "fips.forwarding.attempt_bytes" || a.resource != route.resource() {
            return Err(Error::Invalid("forwarding service or route"));
        }
        let mut windows = self.windows.lock().map_err(|_| Error::Closed)?;
        if !windows.contains_key(&route) && windows.len() >= 128 {
            return Err(Error::Limit);
        }
        windows.insert(route, allowance);
        Ok(())
    }
}
impl ForwardingPolicy for CreditForwarder {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let mut windows = self.windows.lock().ok()?;
        let window = windows.get_mut(&Route::from_request(request))?;
        window
            .admit(request.session_payload.len().try_into().ok()?, now)
            .then_some(0)
    }
    fn admit_classified(&self, request: &ForwardingRequest<'_>) -> Option<ForwardingAdmission> {
        self.admit(request).map(|token| ForwardingAdmission {
            token,
            class: ForwardingClass::Normal,
        })
    }
    fn complete(&self, _: u64, _: ForwardingOutcome) {
        // No refunds for uncertain delivery and no payment claim from a local
        // send completion. Settlement still requires signed service receipts.
    }
}
