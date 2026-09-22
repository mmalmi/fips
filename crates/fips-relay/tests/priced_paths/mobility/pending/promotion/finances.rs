use super::*;
use fips_relay::{controller::SettlementReport, ledger::ChannelTerms};
use std::collections::BTreeSet;

pub(super) struct Anchor {
    pub(super) trial: Purchase,
    funding: Value,
    sequence: u64,
    policy: Value,
    pub(super) used: u64,
    remaining: u64,
}

fn channels(saved: &Value) -> Result<BTreeMap<String, ChannelTerms>, String> {
    let mut channels = BTreeMap::new();
    for funding in saved["funding"]
        .as_object()
        .ok_or("funding map missing")?
        .values()
    {
        if funding["funded"].is_null() {
            continue;
        }
        let terms: ChannelTerms = serde_json::from_value(funding["funded"]["terms"].clone())
            .map_err(|_| "funded channel terms missing")?;
        if channels.insert(terms.id.clone(), terms).is_some() {
            return Err("duplicate funding for the same channel".into());
        }
    }
    Ok(channels)
}

fn verified_refunds(
    saved: &Value,
    channels: &BTreeMap<String, ChannelTerms>,
) -> Result<(u64, u64), String> {
    let (mut released, mut refunded) = (0, 0);
    for (id, terms) in channels {
        let settlement = &saved["buyer_settlements"][id];
        if settlement["refunded"] != true {
            continue;
        }
        let report: SettlementReport = serde_json::from_value(settlement["report"].clone())
            .map_err(|_| "verified refund has no settlement report")?;
        if settlement["channel"] != serde_json::to_value(terms).unwrap()
            || report.channel_id != *id
            || report.value_after_stage1_sat != 64
            || report.paid_sat + report.refunded_sat != 64
            || report.fee_sat + report.receiver_fee_reserve_sat != 0
            || settlement["wallet_refund_sat"].as_u64() != Some(report.refunded_sat)
        {
            return Err("released capital lacks exact channel and refund evidence".into());
        }
        released += 64;
        refunded += report.refunded_sat;
    }
    Ok((released, refunded))
}

impl Anchor {
    pub(super) async fn capture(bench: &bench::Bench, trial: &Purchase) -> Self {
        let current = saved(bench, 0);
        let remaining = bench.buyers[0].remaining_budget_sat().unwrap();
        eprintln!(
            "promotion: captured capital {}",
            serde_json::json!({
                "budget": bench.controllers[0].funding_budget().await.unwrap(),
                "remaining_sat": remaining,
            })
        );
        Self {
            trial: trial.clone(),
            funding: current["funding"].clone(),
            sequence: current["next_funding"].as_u64().unwrap(),
            policy: current["policy"].clone(),
            used: bench.buyers[0].observed_units(&trial.contract.id).unwrap(),
            remaining,
        }
    }

    pub(super) async fn check(&mut self, bench: &bench::Bench) -> Result<(), String> {
        let budget = bench.controllers[0].funding_budget().await?;
        // Settlement can advance between observations. Read its durable proof
        // after the budget, and require at least the release already observed.
        let current = saved(bench, 0);
        let original = self.funding.as_object().unwrap();
        let funding = current["funding"]
            .as_object()
            .ok_or("funding map missing")?;
        if original.len() != 1
            || !(1..=2).contains(&funding.len())
            || original
                .iter()
                .any(|(id, record)| funding.get(id) != Some(record))
            || current["next_funding"].as_u64() != Some(self.sequence + (funding.len() - 1) as u64)
            || current["policy"] != self.policy
        {
            return Err("recovery changed original funding or exceeded one replacement".into());
        }
        let first = original.values().next().unwrap();
        if funding.values().any(|f| {
            f["provider"] != first["provider"]
                || f["receiver_pubkey_hex"] != first["receiver_pubkey_hex"]
                || f["capacity_sat"] != 64
                || f["max_wallet_debit_sat"] != 64
        }) {
            return Err("replacement exceeded original provider or funding terms".into());
        }
        let channels = channels(&current)?;
        if channels.get(&self.trial.channel.id) != Some(&self.trial.channel)
            || channels.values().any(|c| {
                c.capacity_sat != 64
                    || c.buyer != self.trial.channel.buyer
                    || c.mint_url != self.trial.channel.mint_url
                    || c.grace_msat != self.trial.channel.grace_msat
            })
            || (funding.len() == 2
                && current["buyer_settlements"][&self.trial.channel.id]["refunded"] != true)
        {
            return Err(
                "replacement did not preserve the original settled channel evidence".into(),
            );
        }
        let (released, refunded) = verified_refunds(&current, &channels)?;
        let remaining = bench.buyers[0]
            .remaining_budget_sat()
            .ok_or("buyer budget missing")?;
        let committed = budget.wallet_debited_sat + budget.pending_reserved_sat;
        if !matches!(budget.wallet_debited_sat, 64 | 128)
            || !matches!(budget.pending_reserved_sat, 0 | 64)
            || committed > 128
            || budget.locked_sat > committed
            || committed - budget.locked_sat > released
            || budget.wallet_refunded_sat > refunded
            || budget.exposure_sat + budget.wallet_refunded_sat != committed
            || remaining > self.remaining
        {
            eprintln!(
                "promotion: bounded capital mismatch {}",
                serde_json::json!({
                    "actual": budget, "maximum_committed_sat": 128,
                    "verified_released_sat": released, "verified_refunded_sat": refunded,
                    "remaining_sat": remaining, "previous_remaining_sat": self.remaining,
                })
            );
            return Err("promotion recovery widened capital or spending authority".into());
        }
        let watches = bench.controllers[0].watched_routes().await?;
        if watches.len() != 1
            || watches[0].paused
            || watches[0].destination != bench.peers[3].npub()
            || watches[0].max_rate_msat_per_kib != CEILING
            || watches[0].billing != BillingBasis::ForwardingData
        {
            return Err("the original bounded Watch changed".into());
        }
        if bench.buyers[0].observed_units(&self.trial.contract.id) != Some(self.used)
            || current["outgoing"][&self.trial.contract.id]["purchase"]
                != serde_json::to_value(&self.trial).unwrap()
        {
            return Err("retired trial evidence changed".into());
        }
        let mut granted = self.used;
        for (id, record) in current["outgoing"].as_object().unwrap() {
            let purchase: Purchase = serde_json::from_value(record["purchase"].clone())
                .map_err(|_| "outgoing purchase missing")?;
            if channels.get(&purchase.channel.id) != Some(&purchase.channel)
                || purchase.provider != self.trial.provider
                || purchase.contract.destination != self.trial.contract.destination
            {
                return Err("recovery purchase escaped the bounded provider channels".into());
            }
            if id != &self.trial.contract.id && record["offer"]["trial"] == true {
                granted = granted
                    .checked_add(
                        record["offer"]["max_units"]
                            .as_u64()
                            .ok_or("trial quota missing")?,
                    )
                    .ok_or("trial allowance overflow")?;
            }
        }
        if granted > self.trial.contract.max_units {
            return Err("same-path recovery refilled consumed trial allowance".into());
        }
        self.remaining = remaining;
        Ok(())
    }
}

pub(super) async fn finish(mut bench: bench::Bench, gate: ResponseGate) {
    for controller in &bench.controllers {
        controller.pause_route_refresh().await.unwrap();
        controller.pause_renewals().await.unwrap();
    }
    let before = saved(&bench, 0);
    let funded = channels(&before).unwrap();
    let bounded = (1..=2).contains(&funded.len());
    let all_funded = funded.len() == before["funding"].as_object().unwrap().len();
    let reports = bench.controllers[0].settle_all().await.unwrap();
    assert_eq!(reports.len(), funded.len());
    let mut settled = BTreeSet::new();
    let mut paid = 0;
    let mut refunded = 0;
    for report in reports {
        assert!(funded.contains_key(&report.channel_id));
        assert!(settled.insert(report.channel_id.clone()));
        assert_eq!(report.value_after_stage1_sat, 64);
        assert_eq!(report.paid_sat + report.refunded_sat, 64);
        assert_eq!(report.fee_sat + report.receiver_fee_reserve_sat, 0);
        paid += report.paid_sat;
        refunded += report.refunded_sat;
    }
    assert_eq!(settled, funded.keys().cloned().collect());
    let budget = bench.controllers[0].funding_budget().await.unwrap();
    assert_eq!(
        budget,
        FundingBudget {
            pending_reserved_sat: 0,
            wallet_debited_sat: 64 * funded.len() as u64,
            wallet_refunded_sat: refunded,
            locked_sat: 0,
            exposure_sat: paid,
        }
    );
    assert_eq!(
        verified_refunds(&saved(&bench, 0), &funded).unwrap(),
        (64 * funded.len() as u64, refunded)
    );
    let expected = [256 - paid, 1 + paid, 1, 1];
    for task in bench.tasks.drain(..) {
        task.stop().await;
    }
    assert_eq!(expected.iter().sum::<u64>(), 259);
    bench::collect_wallets(
        bench.root.path(),
        &bench.wallets,
        bench.mint.url(),
        &expected,
    )
    .await;
    gate.stop().await;
    drop(bench.controllers);
    drop(bench.services);
    for server in bench.quote_servers {
        server.stop().await;
    }
    for server in bench.payment_servers {
        server.stop().await;
    }
    for node in bench.nodes {
        node.shutdown().await.unwrap();
    }
    fips_core::unregister_sim_network(&bench.network_name);
    eprintln!(
        "promotion: all {} original/replacement accounts settled, paid_sat={paid}, refunded_sat={refunded}, and all 259 test sats collected",
        funded.len()
    );
    assert!(bounded, "recovery exceeded one replacement channel");
    assert!(all_funded, "cleanup left an unresolved funding intent");
}
