use super::types::{
    BootstrapError, PunchHint, TraversalAddressObservation, TraversalAnswer, TraversalOffer,
};

/// Wall-clock skew tolerance applied to offer/answer freshness checks, in
/// milliseconds. Constant rather than configurable because loosening this
/// past ~minutes erodes the freshness guarantee that backstops session-id
/// replay protection. Tightening it below the size of a typical un-NTP'd
/// drift defeats the purpose. 60s sits comfortably between those.
pub(super) const FRESHNESS_SKEW_TOLERANCE_MS: u64 = 60_000;

pub(super) struct SignalEnvelope<T> {
    pub(super) payload: T,
    pub(super) sender_npub: String,
}

/// Result of a freshness check. `Fresh` means the offer/answer is within the
/// strict TTL window; `FreshWithinSkewTolerance` means it was only accepted
/// after applying `FRESHNESS_SKEW_TOLERANCE_MS` grace, which is a useful
/// signal for operators to know clock skew is in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FreshnessOutcome {
    Fresh,
    FreshWithinSkewTolerance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TraversalSignalTiming {
    issued_at: u64,
    ttl_ms: u64,
}

impl TraversalSignalTiming {
    pub(super) fn new(issued_at: u64, ttl_ms: u64) -> Self {
        Self { issued_at, ttl_ms }
    }

    fn expires_at(self) -> u64 {
        self.issued_at + self.ttl_ms
    }
}

pub(super) fn validate_offer_freshness(
    offer: &TraversalOffer,
    now: u64,
    signal_ttl_ms: u64,
    actual_sender_npub: &str,
    local_npub: &str,
) -> Result<FreshnessOutcome, BootstrapError> {
    if offer.message_type != "offer" {
        return Err(BootstrapError::Protocol("invalid-offer".to_string()));
    }
    let outcome = match check_freshness(offer.issued_at, offer.expires_at, now, signal_ttl_ms) {
        Some(o) => o,
        None => return Err(BootstrapError::Protocol("expired-offer".to_string())),
    };
    if offer.sender_npub != actual_sender_npub || offer.recipient_npub != local_npub {
        return Err(BootstrapError::Protocol("identity-mismatch".to_string()));
    }
    Ok(outcome)
}

pub(super) fn create_traversal_offer(
    session_id: String,
    timing: TraversalSignalTiming,
    nonce: String,
    sender_npub: String,
    recipient_npub: String,
    observation: TraversalAddressObservation,
) -> TraversalOffer {
    let TraversalAddressObservation {
        reflexive_address,
        local_addresses,
        stun_server,
    } = observation;
    TraversalOffer {
        message_type: "offer".to_string(),
        session_id,
        issued_at: timing.issued_at,
        expires_at: timing.expires_at(),
        nonce,
        sender_npub,
        recipient_npub,
        reflexive_address,
        local_addresses,
        stun_server,
    }
}

pub(super) fn create_traversal_answer(
    offer: &TraversalOffer,
    timing: TraversalSignalTiming,
    nonce: String,
    sender_npub: String,
    observation: TraversalAddressObservation,
    punch: Option<PunchHint>,
    offer_received_at: Option<u64>,
) -> TraversalAnswer {
    let accepted = observation.has_usable_address();
    let TraversalAddressObservation {
        reflexive_address,
        local_addresses,
        stun_server,
    } = observation;
    TraversalAnswer {
        message_type: "answer".to_string(),
        session_id: offer.session_id.clone(),
        issued_at: timing.issued_at,
        expires_at: timing.expires_at(),
        nonce,
        sender_npub,
        recipient_npub: offer.sender_npub.clone(),
        in_reply_to: offer.nonce.clone(),
        accepted,
        reflexive_address,
        local_addresses,
        stun_server,
        punch: if accepted { punch } else { None },
        reason: (!accepted).then_some("no-usable-addresses".to_string()),
        offer_received_at,
    }
}

pub(super) fn validate_traversal_answer_for_offer(
    offer: &TraversalOffer,
    answer: &TraversalAnswer,
    now: u64,
    signal_ttl_ms: u64,
    actual_sender_npub: &str,
    local_npub: &str,
) -> Result<FreshnessOutcome, BootstrapError> {
    if answer.message_type != "answer" {
        return Err(BootstrapError::Protocol("invalid-answer".to_string()));
    }
    let offer_outcome = match check_freshness(offer.issued_at, offer.expires_at, now, signal_ttl_ms)
    {
        Some(o) => o,
        None => return Err(BootstrapError::Protocol("expired-answer".to_string())),
    };
    let answer_outcome =
        match check_freshness(answer.issued_at, answer.expires_at, now, signal_ttl_ms) {
            Some(o) => o,
            None => return Err(BootstrapError::Protocol("expired-answer".to_string())),
        };
    if offer.session_id != answer.session_id || answer.in_reply_to != offer.nonce {
        return Err(BootstrapError::Protocol("session-mismatch".to_string()));
    }
    if offer.sender_npub != local_npub
        || offer.recipient_npub != actual_sender_npub
        || answer.sender_npub != actual_sender_npub
        || answer.recipient_npub != local_npub
    {
        return Err(BootstrapError::Protocol("identity-mismatch".to_string()));
    }
    if answer.accepted && answer.reflexive_address.is_none() && answer.local_addresses.is_empty() {
        return Err(BootstrapError::Protocol("missing-addresses".to_string()));
    }
    if !answer.accepted && answer.reason.as_deref().unwrap_or_default().is_empty() {
        return Err(BootstrapError::Protocol(
            "missing-rejection-reason".to_string(),
        ));
    }
    // Surface skew if either side was tolerated. The strict-Fresh case wins
    // when both are strict; otherwise tolerance applied somewhere.
    Ok(
        if offer_outcome == FreshnessOutcome::Fresh && answer_outcome == FreshnessOutcome::Fresh {
            FreshnessOutcome::Fresh
        } else {
            FreshnessOutcome::FreshWithinSkewTolerance
        },
    )
}

/// NTP-style clock-skew estimate from a completed offer/answer round-trip.
/// Returns the responder's apparent offset relative to the initiator in
/// milliseconds (positive = responder clock ahead). Requires the responder
/// to have populated `answer.offer_received_at`; older responders won't, in
/// which case this returns `None`.
///
/// Symmetric one-way-delay assumption (the standard NTP offset formula):
///   offset = ((T2 - T1) + (T3 - T4)) / 2
/// where T1 = offer.issued_at, T2 = answer.offer_received_at,
///       T3 = answer.issued_at, T4 = answer_received_at.
pub(super) fn estimate_clock_skew(
    offer: &TraversalOffer,
    answer: &TraversalAnswer,
    answer_received_at: u64,
) -> Option<i64> {
    let t1 = offer.issued_at as i64;
    let t2 = answer.offer_received_at? as i64;
    let t3 = answer.issued_at as i64;
    let t4 = answer_received_at as i64;
    Some(((t2 - t1) + (t3 - t4)) / 2)
}

/// Returns Some(outcome) if the (issued_at, expires_at) pair is acceptable
/// against `now` under the configured TTL plus `FRESHNESS_SKEW_TOLERANCE_MS`
/// of clock-skew grace on each side. Returns None if the message is
/// genuinely outside the tolerated window.
fn check_freshness(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    signal_ttl_ms: u64,
) -> Option<FreshnessOutcome> {
    let strict_ok = expires_at > now && now.saturating_sub(issued_at) <= signal_ttl_ms;
    if strict_ok {
        return Some(FreshnessOutcome::Fresh);
    }
    let tolerated_ok = expires_at.saturating_add(FRESHNESS_SKEW_TOLERANCE_MS) > now
        && now.saturating_sub(issued_at) <= signal_ttl_ms + FRESHNESS_SKEW_TOLERANCE_MS;
    if tolerated_ok {
        Some(FreshnessOutcome::FreshWithinSkewTolerance)
    } else {
        None
    }
}
