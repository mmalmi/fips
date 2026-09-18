use super::*;

pub(super) fn completed<'a>(j: &'a Journal, f: &'a FundingIntent, now: u64) -> Option<&'a Funded> {
    let funded = f.funded.as_ref()?;
    let id = &funded.terms.id;
    if f.expires_unix.checked_add(60)? >= now
        || !j.buyer_settlements.get(id)?.terminal()
        || j.outgoing.values().any(|o| o.purchase.channel.id == *id)
        || j.renewals
            .values()
            .any(|r| r.previous.iter().any(|o| o.purchase.channel.id == *id))
        || j.route_changes
            .values()
            .any(|r| r.previous.iter().any(|p| p.channel.id == *id))
    {
        return None;
    }
    Some(funded)
}

pub(super) fn accumulate(
    j: &Journal,
    mut total: Totals,
    f: &FundingIntent,
) -> Result<Totals, String> {
    let funded = f.funded.as_ref().ok_or("channel not funded")?;
    let settlement = j
        .buyer_settlements
        .get(&funded.terms.id)
        .ok_or("settlement missing")?;
    total.through = sequence(j, &f.id).ok_or("funding sequence missing")?;
    total.channels = add(total.channels, 1)?;
    total.capacity_sat = add(total.capacity_sat, funded.terms.capacity_sat)?;
    total.signed_sat = add(total.signed_sat, settlement.final_signed_sat()?)?;
    total.refund_sat = add(
        total.refund_sat,
        settlement
            .wallet_refund_sat
            .ok_or("refund evidence missing")?,
    )?;
    total.cost.token_amount_sat = add(
        total.cost.token_amount_sat,
        funded.wallet_cost.token_amount_sat,
    )?;
    total.cost.swap_fee_sat = add(total.cost.swap_fee_sat, funded.wallet_cost.swap_fee_sat)?;
    total.cost.wallet_debit_sat = add(
        total.cost.wallet_debit_sat,
        funded.wallet_cost.wallet_debit_sat,
    )?;
    total.expires_through_unix = total
        .expires_through_unix
        .max(f.expires_unix.checked_add(60).ok_or("expiry overflow")?);
    Ok(total)
}

pub(super) fn select(
    j: &Journal,
    buyer: &BuyerAuthorizer,
    now: u64,
) -> Result<Option<Plan>, String> {
    let before = j
        .history
        .as_ref()
        .and_then(|h| h.channels.as_ref())
        .map(|h| h.totals.clone())
        .unwrap_or_default();
    let mut ordered: Vec<_> = j
        .funding
        .values()
        .filter_map(|f| sequence(j, &f.id).map(|n| (n, f)))
        .collect();
    ordered.sort_by_key(|(n, _)| *n);
    let mut after = before.clone();
    let mut funding = Vec::new();
    let mut channels = Vec::new();
    let mut never_installed = Vec::new();
    for (_, f) in ordered {
        let Some(funded) = completed(j, f, now) else {
            break;
        };
        after = accumulate(j, after, f)?;
        funding.push(f.id.clone());
        if j.buyer_settlements[&funded.terms.id].kind == SettlementKind::Expiry
            && buyer.authorized_sat(&funded.terms.id).is_none()
        {
            never_installed.push(funded.terms.clone());
        } else {
            channels.push(funded.terms.id.clone());
        }
    }
    if funding.is_empty() {
        return Ok(None);
    }
    let buyer = buyer
        .channel_retirement_plan(&channels, &never_installed, now)
        .map_err(|e| e.to_string())?;
    Ok(Some(Plan {
        before,
        after,
        funding,
        buyer,
    }))
}

fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or("retired channel accounting overflow".into())
}
