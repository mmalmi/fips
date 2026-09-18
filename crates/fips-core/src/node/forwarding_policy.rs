//! Optional admission at the native FMP transit boundary.
//!
//! The core supplies authenticated adjacency and local send outcomes. Pricing,
//! payment validation, durable accounting and delivery receipts belong to the
//! embedding service, not the FIPS packet format.

use crate::{NodeAddr, PeerIdentity};
use std::{fmt::Debug, sync::Arc};

/// Facts about a non-local SessionDatagram before it enters the send queue.
#[derive(Debug)]
pub struct ForwardingRequest<'a> {
    /// Noise-authenticated neighbor submitting the datagram. A service may
    /// charge this neighbor only under a previously authorized agreement.
    pub ingress: PeerIdentity,
    /// Next hop selected by the native FIPS router.
    pub next_hop: NodeAddr,
    /// Claimed end-to-end source; NOT authenticated to this transit router.
    pub source: NodeAddr,
    pub destination: NodeAddr,
    /// Unmodified session envelope, including ciphertext and session headers.
    /// Excludes mutable FMP TTL/MTU and link/radio headers. No plaintext is
    /// exposed. Applications can fingerprint this together with the addresses.
    pub session_payload: &'a [u8],
}

/// Local evidence only. Neither variant proves end-to-end delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardingOutcome {
    /// The local transport accepted the outgoing packet.
    Submitted,
    /// No successful local completion was observed (error, timeout, cancellation
    /// or teardown). The packet might still have reached the next hop.
    Unconfirmed,
}

/// Local scheduling authority, chosen together with admission. This is never
/// a peer-supplied preference or a claim about end-to-end payment or delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardingClass {
    /// Preserve the core's existing protocol classification.
    Unspecified,
    /// Essential protocol traffic admitted under a separate bounded allowance.
    Control,
    /// Ordinary data, including locally authorized paid forwarding.
    Normal,
    /// Complimentary data, served after control and ordinary data.
    Background,
}

/// One admission decision owns both accounting completion and scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardingAdmission {
    pub token: u64,
    pub class: ForwardingClass,
}

/// Application-owned transit admission. No policy preserves normal forwarding.
///
/// Calls run synchronously on the node loop: do not block on disk, networking or
/// payment validation here. Install bounded, already-validated allowances from
/// an external control service. Returning `None` drops the datagram silently.
/// An admitted token receives exactly one completion during normal process
/// execution, including dropped queues. Process crashes require recovery in the
/// embedding service; this interface is not a durable or financial receipt.
pub trait ForwardingPolicy: Debug + Send + Sync + 'static {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64>;
    fn admit_classified(&self, request: &ForwardingRequest<'_>) -> Option<ForwardingAdmission> {
        self.admit(request).map(|token| ForwardingAdmission {
            token,
            class: ForwardingClass::Unspecified,
        })
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome);
}

/// Owns the completion obligation across scalar, batched and deferred sends.
#[derive(Debug)]
pub(super) struct ForwardingPermit {
    policy: Arc<dyn ForwardingPolicy>,
    token: Option<u64>,
    class: ForwardingClass,
}

impl ForwardingPermit {
    pub(super) fn admit(
        policy: &Arc<dyn ForwardingPolicy>,
        request: &ForwardingRequest<'_>,
    ) -> Option<Self> {
        policy.admit_classified(request).map(|admission| Self {
            policy: Arc::clone(policy),
            token: Some(admission.token),
            class: admission.class,
        })
    }

    pub(super) fn packet_class(&self) -> Option<crate::dataplane::PacketClass> {
        use crate::dataplane::PacketClass;
        match self.class {
            ForwardingClass::Unspecified => None,
            ForwardingClass::Control => Some(PacketClass::Control),
            ForwardingClass::Normal => Some(PacketClass::Bulk),
            ForwardingClass::Background => Some(PacketClass::Background),
        }
    }

    pub(super) fn submitted(mut self) {
        if let Some(token) = self.token.take() {
            self.policy.complete(token, ForwardingOutcome::Submitted);
        }
    }
}

impl Drop for ForwardingPermit {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.policy.complete(token, ForwardingOutcome::Unconfirmed);
        }
    }
}

impl super::Node {
    /// Replace admission for future native FMP transit packets. Existing
    /// reservations complete against the policy that admitted them. Direct
    /// local services and locally originated packets do not use this hook.
    pub fn set_forwarding_policy(&mut self, policy: Option<Arc<dyn ForwardingPolicy>>) {
        self.forwarding_policy = policy;
    }
}
