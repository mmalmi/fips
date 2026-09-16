//! Bind immutable offers and reject incompatible route or billing terms.
use super::*;

pub(crate) fn contract_from_offer(
    offer: &RouteOffer,
    channel: &ChannelTerms,
) -> Result<Contract, String> {
    let id = &offer.id;
    crate::ledger::validate_channel(channel).map_err(|e| e.to_string())?;
    if offer.price.msat == 0
        || channel.buyer != offer.buyer
        || channel.mint_url != offer.mint_url
        || channel.capacity_sat > offer.capacity_sat
        || channel.grace_msat > offer.grace_msat
        || channel.expires_unix <= unix_now()?
    {
        return Err("channel does not fit the offered terms".into());
    }
    // Same offer and channel produce the same bounded identifier on retries.
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"fips-relay/accepted-quote/1");
    digest.update((id.len() as u64).to_be_bytes());
    digest.update(id.as_bytes());
    digest.update(channel.id.as_bytes());
    Ok(Contract {
        billing: offer.billing,
        id: format!("{:x}", digest.finalize()),
        channel_id: channel.id.clone(),
        destination: *offer.destination.node_addr(),
        next_hop: offer.next_hop,
        expires_unix: channel.expires_unix.min(offer.expires_unix),
        price: offer.price,
        max_units: offer.max_units,
    })
}

pub(super) fn validate_offer(
    policy: &QuotePolicy,
    local: NodeAddr,
    offer: &RouteOffer,
    peer: PeerIdentity,
    request: &QuoteRequest,
    now: u64,
) -> Result<(), String> {
    if offer.id.is_empty()
        || offer.trial != request.requested_max_units.is_some()
        || offer.billing != policy.billing
        || offer.id.len() > 128
        || offer.buyer != local
        || offer.provider != *peer.node_addr()
        || offer.destination.node_addr() != request.destination.node_addr()
        || offer.path.len() < 2
        || offer.path.len() + request.ancestors.len() > MAX_PAID_HOPS + 2
        || offer.path.first() != Some(&offer.provider)
        || offer.path.last() != Some(offer.destination.node_addr())
        || offer.path.get(1) != Some(&offer.next_hop)
        || offer.path.iter().collect::<HashSet<_>>().len() != offer.path.len()
        || offer.path.iter().any(|p| request.ancestors.contains(p))
        || offer.price.per_bytes != PRICE_BYTES
        || (offer.price.msat == 0 && !offer.billing.has_free_handshakes())
        || offer.price.msat > policy.max_rate_msat_per_kib
        || offer.expires_unix <= now
        || offer.expires_unix > now.saturating_add(3_600)
        || (offer.price.msat != 0 && offer.mint_url != policy.mint_url)
        || !valid_key(&offer.receiver_pubkey_hex)
        || offer.max_units == 0
        || request
            .requested_max_units
            .is_some_and(|limit| offer.max_units > limit)
        || offer.price.amount_due_msat(offer.max_units).is_none()
        || offer.capacity_sat == 0
        || offer
            .capacity_sat
            .checked_mul(1_000)
            .is_none_or(|cap| offer.grace_msat > cap)
    {
        return Err("invalid or unacceptable downstream quote".into());
    }
    Ok(())
}

/// Shared authenticated wire request for native and priced source discovery.
pub(super) async fn fetch_offer(
    control: &ControlTransport,
    policy: &QuotePolicy,
    local: NodeAddr,
    peer: PeerIdentity,
    request: &QuoteRequest,
) -> Result<RouteOffer, String> {
    let seconds = request
        .deadline_unix
        .checked_sub(unix_now()?)
        .filter(|n| *n > 0 && *n <= MAX_REQUEST_SECONDS)
        .ok_or("quote deadline")?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(seconds),
        control.request(
            peer,
            serde_json::to_vec(request).map_err(|e| e.to_string())?,
        ),
    )
    .await
    .map_err(|_| "quote deadline")??;
    let reply: QuoteResponse =
        serde_json::from_slice(&bytes).map_err(|_| "invalid quote response")?;
    let QuoteResponse::Offer { offer } = reply else {
        return Err("provider rejected quote request".into());
    };
    validate_offer(policy, local, &offer, peer, request, unix_now()?)?;
    Ok(*offer)
}
