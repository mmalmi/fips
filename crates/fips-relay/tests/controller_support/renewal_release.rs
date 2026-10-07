//! Report retention acknowledgments cannot hold a refunded renewal closed.
use super::*;
use fips_relay::controller::Purchase;
use serde_json::Value;
use std::path::Path;

pub(super) async fn observe(
    root: &Path,
    gate: Option<&payment_mobility::Gate>,
    previous: &Purchase,
    controller: &Controller,
    buyer: &BuyerAuthorizer,
    seller: &DurableRelay,
) -> Result<(), String> {
    let Some(gate) = gate else { return Ok(()) };
    let journal = root.join("controller-0/controller.json");
    let read = || -> Result<Value, String> {
        serde_json::from_slice(&std::fs::read(&journal).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    };
    let original = read()?["funding"].clone();
    gate.pause_releases();
    let result = async {
        if !gate.held().await {
            return Err("original settlement release was not observed".into());
        }
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let state = read()?;
                let settlement = &state["buyer_settlements"][&previous.channel.id];
                if settlement["refunded"] != true || settlement["released"] != false {
                    return Err(
                        "held release requires a verified refund and retained report".into(),
                    );
                }
                for (id, funding) in original.as_object().unwrap() {
                    if state["funding"][id] != *funding {
                        return Err("renewal changed its original funding intent".into());
                    }
                }
                if state["renewals"][&previous.channel.id]["completed"] == true {
                    for purchase in controller.purchases().await? {
                        if purchase.channel.id != previous.channel.id
                            && purchase.contract.destination == previous.contract.destination
                            && buyer.evidence_msat(&purchase.channel.id).unwrap_or(0) > 0
                            && seller
                                .channel_usage(&purchase.channel.id)
                                .is_some_and(|usage| usage.paid_msat > 0)
                        {
                            return Ok(());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "renewal or paid forwarding waited for report release".to_string())?
    }
    .await;
    // Let the normal fixture settle and collect every wallet before reporting
    // a liveness failure, including when running against the unfixed controller.
    gate.release();
    result
}
