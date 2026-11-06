use super::signal::{TraversalSignalTiming, create_traversal_answer, validate_offer_freshness};
use super::traversal::nonce;
use super::types::{TraversalAddressObservation, TraversalAnswer, TraversalOffer};

/// Reply only after the Node has admitted the authenticated session peer.
/// No discovery runtime, address observation, task, or retained capability
/// state is needed. A fresh encrypted retry can recover a lost rejection;
/// the session's ordinary replay window still rejects replayed ciphertext.
pub(crate) fn unsupported_mesh_traversal_answer(
    body: &[u8],
    now: u64,
    signal_ttl_ms: u64,
    actual_sender_npub: &str,
    local_npub: &str,
) -> Option<TraversalAnswer> {
    // This endpoint cannot use candidates. Bound parsing and echoed opaque
    // identifiers before constructing a reply, without changing validation
    // or candidate handling for peers that do support traversal.
    if body.len() > 4096 || signal_ttl_ms == 0 || now.checked_add(signal_ttl_ms).is_none() {
        return None;
    }
    let offer: TraversalOffer = serde_json::from_slice(body).ok()?;
    let bounded_id = |id: &str| {
        !id.is_empty() && id.len() <= 128 && id.bytes().all(|byte| byte.is_ascii_graphic())
    };
    if !bounded_id(&offer.session_id)
        || !bounded_id(&offer.nonce)
        || offer.expires_at <= offer.issued_at
    {
        return None;
    }
    validate_offer_freshness(&offer, now, signal_ttl_ms, actual_sender_npub, local_npub).ok()?;
    let mut answer = create_traversal_answer(
        &offer,
        TraversalSignalTiming::new(now, signal_ttl_ms),
        nonce(),
        local_npub.to_owned(),
        TraversalAddressObservation::default(),
        None,
        Some(now),
    );
    answer.reason = Some("traversal-unsupported".to_owned());
    Some(answer)
}

#[cfg(test)]
mod tests;
