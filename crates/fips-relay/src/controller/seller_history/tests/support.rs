//! SDK callback fixtures; production coordinator and validators remain in use.
use super::*;
use serde_json::json;

// Storage-only payout identities, not signed mint money.
pub(super) fn payout(id: &str, amount: u64) -> serde_json::Value {
    let proofs = (0..64)
        .filter(|bit| amount & (1u64 << bit) != 0)
        .map(|bit| {
            json!({"amount":1u64 << bit, "id":"009a1f293253e41e",
                "secret":format!("receiver-retirement-{id}-{bit}"),
                "C":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"})
        })
        .collect::<Vec<_>>();
    json!({"channel_id":id, "proofs":proofs})
}

pub(super) fn receiver_plan(j: &Journal, ids: &[String]) -> Result<ReceiverPlan, String> {
    let before = j
        .history
        .as_ref()
        .and_then(|h| h.seller.as_ref())
        .and_then(|h| h.totals.receiver.clone())
        .unwrap_or_default();
    let mut after = serde_json::to_value(&before).unwrap();
    let mut channels = Vec::new();
    let mut payouts = Vec::new();
    for id in ids {
        let sale = &j.seller_settlements[id];
        let report = sale.report.as_ref().unwrap();
        let totals = json!({"mint":sale.channel.mint_url, "unit":"sat", "channels":1,
            "capacity":sale.channel.capacity_sat, "funding_token_amount":report.value_after_stage1_sat + 2,
            "signed_amount":report.signed_sat, "closed_amount":report.paid_sat, "value_after_stage1":report.value_after_stage1_sat,
            "receiver_sum":report.receiver_value_sat().unwrap(), "sender_sum":report.refunded_sat,
            "usage":{"fixture_requests":1}});
        let expiry = sale.channel.expires_unix + 60;
        let previous = after["expires_through_unix"].as_u64().unwrap();
        after["expires_through_unix"] = previous.max(expiry).into();
        if after["totals"].as_array().unwrap().is_empty() {
            after["totals"].as_array_mut().unwrap().push(totals.clone());
        } else {
            let t = &mut after["totals"][0];
            for name in [
                "channels",
                "capacity",
                "funding_token_amount",
                "signed_amount",
                "closed_amount",
                "value_after_stage1",
                "receiver_sum",
                "sender_sum",
            ] {
                t[name] = (t[name].as_u64().unwrap() + totals[name].as_u64().unwrap()).into();
            }
            t["usage"]["fixture_requests"] =
                (t["usage"]["fixture_requests"].as_u64().unwrap() + 1).into();
        }
        channels.push(json!({"id":id, "expires_unix":expiry, "totals":totals}));
        payouts.push(payout(id, report.receiver_value_sat().unwrap()));
    }
    let plan: ReceiverPlan = serde_json::from_value(json!({
        "accounting":{"before":before, "after":after, "channels":channels},
        "payouts":payouts,
        "binding":"00".repeat(32)
    }))
    .unwrap();
    plan.validate()?;
    Ok(plan)
}

pub(super) fn prepare_sales(
    store: &mut Store,
    seller: &DurableRelay,
    timestamp: u64,
) -> Result<(), String> {
    let j = store.journal.clone();
    store.prepare_sales(seller, timestamp, |ids| receiver_plan(&j, ids))
}

pub(super) fn resume_sales(store: &mut Store, seller: &DurableRelay) -> Result<usize, String> {
    let j = store.journal.clone();
    store.resume_sales(
        seller,
        |ids| receiver_plan(&j, ids),
        |p| Ok(p.accounting.after.clone()),
    )
}

pub(super) fn retire_sales(
    store: &mut Store,
    seller: &DurableRelay,
    timestamp: u64,
) -> Result<usize, String> {
    let j = store.journal.clone();
    store.retire_sales(
        seller,
        timestamp,
        |ids| receiver_plan(&j, ids),
        |p| Ok(p.accounting.after.clone()),
    )
}
