//! Cashu validation at the control boundary, outside packet forwarding.

use crate::ledger::ChannelTerms;
use cashu_service::{
    CashuSpilmanPayment, CashuSpilmanPaymentReceiver,
    process_streaming_route_cashu_payment_with_receiver,
    validate_streaming_route_cashu_payment_with_receiver,
};
use fips_core::PeerIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCredit {
    pub channel_id: String,
    pub paid_msat: u64,
}

/// Verify a sat-denominated channel payment from the neighbor's authenticated
/// buyer, then let the existing receiver durably record it. The controller must
/// separately retain the immutable contract/channel binding and reserve its
/// forwarding exposure before publishing an allowance to the ledger.
///
/// This returns a redeemable signed claim, not proof of successful redemption
/// or packet delivery. Mint availability and settlement must be tested separately.
pub fn process_payment<R: CashuSpilmanPaymentReceiver<String>>(
    receiver: &R,
    channel: &ChannelTerms,
    authenticated_buyer: PeerIdentity,
    payment: &CashuSpilmanPayment,
    opening: bool,
) -> Result<VerifiedCredit, String> {
    if *authenticated_buyer.node_addr() != channel.buyer {
        return Err("payment sender is not the authorized contract buyer".into());
    }
    if channel.capacity_sat == 0 || channel.capacity_sat.checked_mul(1_000).is_none() {
        return Err("invalid channel capacity".into());
    }
    let paid_msat = payment
        .balance
        .checked_mul(1_000)
        .ok_or("payment amount overflow")?;
    if opening || payment.params.is_some() {
        let params = payment
            .params
            .as_ref()
            .ok_or("missing channel parameters")?;
        // Native validation can retain new funding. Reject terms outside the
        // agreement before handing that financial obligation to the receiver.
        let capacity = params
            .get("capacity")
            .and_then(|v| v.as_u64())
            .ok_or("missing channel capacity")?;
        if capacity > channel.capacity_sat {
            return Err("funded channel exceeds the agreed capacity limit".into());
        }
        let expiry = params
            .get("expiry_timestamp")
            .and_then(|v| v.as_u64())
            .ok_or("missing channel expiry")?;
        if expiry < channel.expires_unix {
            return Err("channel expires before the forwarding agreement".into());
        }
        if params.get("mint").and_then(|v| v.as_str()) != Some(channel.mint_url.as_str()) {
            return Err("channel mint does not match the neighbor agreement".into());
        }
        if params.get("unit").and_then(|v| v.as_str()).unwrap_or("sat") != "sat" {
            return Err("prototype requires sat-denominated channels".into());
        }
    }
    // Usage lives in our cumulative ledger. Replaying a payment must not apply
    // any additional incremental usage in the underlying receiver.
    let context = String::from("{}");
    let validated = validate_streaming_route_cashu_payment_with_receiver(
        receiver,
        payment,
        &channel.id,
        "sat",
        paid_msat,
        channel.capacity_sat,
        opening,
        &context,
    )?;
    if validated.receiver.capacity > channel.capacity_sat {
        return Err("funded channel exceeds the agreed capacity limit".into());
    }
    let processed = process_streaming_route_cashu_payment_with_receiver(
        receiver,
        payment,
        &channel.id,
        "sat",
        paid_msat,
        channel.capacity_sat,
        opening,
        &context,
    )?;
    Ok(VerifiedCredit {
        channel_id: processed.claim.channel_id,
        paid_msat: processed.claim.paid_msat,
    })
}
