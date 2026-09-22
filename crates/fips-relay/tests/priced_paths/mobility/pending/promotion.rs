//! A withdrawn full promotion cannot strand its retired, already-used trial.
use super::*;
use fips_relay::route_quotes::RouteOffer;
use serde_json::Value;
use std::collections::BTreeSet;

const CEILING: u64 = 192;
const PORT: u16 = 44_740;

fn feedback_window() -> Duration {
    Duration::from_millis(PriceSelectionPolicy::default().feedback_timeout_ms)
}

fn saved(bench: &bench::Bench, node: usize) -> Value {
    journal(bench.root.path(), node)
}

async fn connected(bench: &bench::Bench, a: usize, b: usize) -> bool {
    bench.nodes[a]
        .peers()
        .await
        .unwrap()
        .iter()
        .any(|p| p.connected && p.node_addr == *bench.peers[b].node_addr())
}

fn carrier(bench: &bench::Bench, up: bool) {
    bench.network.set_link_up("0", "1", up);
    bench.network.set_link_up("1", "3", up);
}

fn working(q: &fips_core::SourceRouteQuality, provider: fips_core::NodeAddr) -> bool {
    let policy = PriceSelectionPolicy::default();
    q.next_hop == Some(provider)
        && q.has_recent_delivery_feedback
        && !q.delivery_feedback_timed_out
        && q.loss_rate
            .is_some_and(|loss| loss <= f64::from(policy.max_loss_percent) / 100.0)
        && q.rtt_ms.is_some_and(|rtt| rtt <= policy.max_rtt_ms as f64)
}

#[path = "promotion/finances.rs"]
mod finances;
use finances::{Anchor, finish};

async fn qualify(bench: &mut bench::Bench, trial: &Purchase) -> Result<(), String> {
    let mut sent = 0;
    let mut received = 0;
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            // One bounded warmup stream. Native feedback, not injected samples
            // or another Watch, must authorize the automatic full promotion.
            if sent < 64 {
                bench.nodes[0].send_datagram(bench.peers[3], PORT, PORT, vec![71; 200])
                    .await.unwrap();
                sent += 1;
            }
            let mut batch = Vec::new();
            if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100),
                bench.receivers[3].recv_batch_into(&mut batch, 32)).await
            {
                received += batch.iter().filter(|m| {
                    m.source_peer.node_addr() == bench.peers[0].node_addr()
                        && m.data.as_slice() == [71; 200]
                }).count();
            }
            let quality = bench.nodes[0].source_route_quality(bench.peers[3], feedback_window())
                .await.unwrap();
            if received >= 8 && working(&quality, trial.provider) {
                eprintln!("promotion: real qualified trial, sent={sent}, received={received}, sent_packets={}", quality.sent_packets);
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.map_err(|_| "trial did not gain real native quality before the unchanged promotion deadline".into())
}

async fn prepare(
    bench: &mut bench::Bench,
    gate: &mut ResponseGate,
    trial: &Purchase,
) -> Result<Anchor, String> {
    qualify(bench, trial).await?;
    let accepted = gate.try_accepted().await.map_err(|error| {
        format!("normal promotion acceptance did not reach the held-response boundary: {error}")
    })?;
    if accepted.purchase.channel != trial.channel
        || accepted.purchase.contract.max_units <= trial.contract.max_units
        || accepted.purchase.contract.price != trial.contract.price
    {
        return Err("held acceptance was not the original channel's full promotion".into());
    }
    let buyer = saved(bench, 0);
    let old = &buyer["outgoing"][&trial.contract.id];
    let full = &buyer["outgoing"][&accepted.purchase.contract.id];
    let provider = saved(bench, 1);
    // The canonical full offer omits `trial: false`. Decode through its real
    // schema so an absent optional flag differs from a missing/malformed offer.
    let offer = serde_json::from_value::<RouteOffer>(full["offer"].clone());
    let pending_matches =
        buyer["watched_routes"][bench.peers[3].npub()]["pending"]["id"] == accepted.offer_id;
    let provider_active = provider["incoming"][&accepted.purchase.contract.id]["phase"] == "Active";
    eprintln!(
        "promotion: held boundary {}",
        serde_json::json!({
            "old_retired": old["retired"].as_bool(),
            "full_accepted": full["accepted"].as_bool(),
            "full_trial": offer.as_ref().ok().map(|offer| offer.trial),
            "watch_pending_matches": pending_matches,
            "provider_active": provider_active,
        })
    );
    let offer = offer.map_err(|_| "held promotion has no valid journaled offer")?;
    if old["retired"] != true
        || full["accepted"] != false
        || offer.trial
        || offer.id != accepted.offer_id
        || !pending_matches
        || !provider_active
    {
        return Err(
            "normal acceptance timing did not leave a retired trial and held full promotion".into(),
        );
    }
    let mut anchor = Anchor::capture(bench, trial).await;
    if anchor.used == 0 || anchor.used >= trial.contract.max_units {
        return Err(
            "the real qualified trial must have positive, partially consumed allowance".into(),
        );
    }
    // Stop data for the existing 15s feedback window. A timed-out outstanding
    // send exercises ordinary failure/cooldown, not this hypothesis. Native
    // reports may still refresh their own evidence while application data idles.
    let idle_started = Instant::now();
    tokio::time::timeout(feedback_window() + Duration::from_secs(5), async {
        loop {
            let quality = bench.nodes[0].source_route_quality(bench.peers[3], feedback_window())
                .await.unwrap();
            if quality.delivery_feedback_timed_out {
                return Err("warmup left outstanding delivery; idle/unknown premise was not reached".to_string());
            }
            if idle_started.elapsed() >= feedback_window() {
                eprintln!("promotion: idle application window without feedback timeout; recent_feedback={}, loss_known={}", quality.has_recent_delivery_feedback, quality.loss_rate.is_some());
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.map_err(|_| "native idle observation exceeded its normal window")??;
    carrier(bench, false);
    let cut = Instant::now();
    tokio::time::timeout(Duration::from_secs(50), async {
        loop {
            let current = saved(bench, 0);
            let fenced = current["recovery_only"].as_array().is_some_and(|ids| {
                ids.iter().any(|id| id == &accepted.offer_id)
            });
            if !connected(bench, 0, 1).await && !connected(bench, 1, 0).await
                && fenced
                && current["watched_routes"][bench.peers[3].npub()]["pending"].is_null()
            {
                eprintln!("promotion: provider departure and withdrawal observed after {:.2}s; used_trial_units={}", cut.elapsed().as_secs_f64(), anchor.used);
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.map_err(|_| "normal Accept/peer deadlines did not reach the intended withdrawn-promotion boundary")?;
    let quiet = bench.nodes[0]
        .source_route_quality(bench.peers[3], feedback_window())
        .await
        .unwrap();
    if quiet.delivery_feedback_timed_out || quiet.loss_rate.is_some() {
        return Err(
            "withdrawal did not leave unknown quality without failed-provider feedback".into(),
        );
    }
    anchor.check(bench).await?;
    Ok(anchor)
}

async fn recover(bench: &mut bench::Bench, anchor: &mut Anchor) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(45), async {
        while !connected(bench, 0, 1).await
            || !connected(bench, 1, 0).await
            || !connected(bench, 1, 3).await
            || !connected(bench, 3, 1).await
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "native provider rejoin deadline")?;
    let idle = bench.nodes[0]
        .source_route_quality(bench.peers[3], feedback_window())
        .await
        .unwrap();
    if idle.delivery_feedback_timed_out || idle.loss_rate.is_some() {
        return Err("rejoin did not preserve the intended idle/unknown quality state".into());
    }
    let mut paid_before = BTreeMap::new();
    let mut sent = 0_u8;
    let mut sent_on = BTreeMap::new();
    let mut delivered = BTreeSet::new();
    let mut delivered_on = BTreeSet::new();
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            anchor.check(bench).await?;
            let full = bench.controllers[0].purchases().await?.into_iter().find(|p| {
                p.provider == anchor.trial.provider
                    && p.contract.destination == anchor.trial.contract.destination
                    && p.contract.max_units > anchor.trial.contract.max_units
            });
            if let Some(purchase) = &full {
                let usage = bench.sellers[1].channel_usage(&purchase.channel.id)
                    .ok_or("current full channel has no seller accounting")?;
                paid_before.entry(purchase.channel.id.clone()).or_insert(usage.paid_msat);
            }
            if sent < 120 {
                let mut payload = vec![if full.is_some() { 73 } else { 72 }; 200];
                payload[0] = sent;
                if let Some(purchase) = &full {
                    sent_on.insert(sent, purchase.contract.id.clone());
                }
                bench.nodes[0].send_datagram(bench.peers[3], PORT, PORT, payload).await.unwrap();
                sent += 1;
            }
            let mut batch = Vec::new();
            if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100),
                bench.receivers[3].recv_batch_into(&mut batch, 32)).await
            {
                for message in batch {
                    let payload = message.data.as_slice();
                    if message.source_peer.node_addr() == bench.peers[0].node_addr()
                        && payload.len() == 200 && payload[0] < sent
                        && (payload[1..].iter().all(|byte| *byte == 72)
                            || payload[1..].iter().all(|byte| *byte == 73))
                    {
                        delivered.insert(payload[0]);
                        if payload[1] == 73
                            && let Some(contract) = sent_on.get(&payload[0])
                        {
                            delivered_on.insert(contract.clone());
                        }
                    }
                }
            }
            let quality = bench.nodes[0].source_route_quality(bench.peers[3], feedback_window()).await.unwrap();
            if let Some(purchase) = full {
                let usage = bench.sellers[1].channel_usage(&purchase.channel.id)
                    .ok_or("current full channel has no seller accounting")?;
                let evidence = bench.buyers[0].evidence_msat(&purchase.channel.id)
                    .ok_or("current full channel has no buyer evidence")?;
                let target = usage.submitted_msat.min(evidence).div_ceil(1_000) * 1_000;
                if delivered_on.contains(&purchase.contract.id) && working(&quality, purchase.provider)
                    && target > paid_before[&purchase.channel.id] && usage.paid_msat >= target
                    && bench.controllers[0].purchases().await?.contains(&purchase)
                {
                    anchor.check(bench).await?;
                    eprintln!("promotion: automatic recovery after {:.2}s, sent={sent}, received={}, replacement_channel={}, credited_msat={} target={target}", started.elapsed().as_secs_f64(), delivered.len(), purchase.channel.id != anchor.trial.channel.id, usage.paid_msat);
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }).await;
    match result {
        Ok(result) => result,
        Err(_) => {
            let state = saved(bench, 0);
            eprintln!(
                "promotion recovery deadline: sent={sent}, received={}, old_retired={}, watch_pending={}, fenced_count={}, last_error={:?}",
                delivered.len(),
                state["outgoing"][&anchor.trial.contract.id]["retired"],
                state["watched_routes"][bench.peers[3].npub()]["pending"].is_object(),
                state["recovery_only"].as_array().map_or(0, Vec::len),
                bench.controllers[0].last_error()
            );
            Err("automatic same-provider promotion recovery stalled".into())
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_same_provider_promotion_preserves_trial_allowance() {
    run(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_promotion_controller_reload_preserves_trial_allowance() {
    run(true).await;
}

async fn reload_source(bench: &mut bench::Bench, anchor: &mut Anchor) -> Result<(), String> {
    use fips_core::node::{
        OriginatedSessionAdmission, OriginatedSessionIntent, OriginatedSessionObserver,
    };
    // Reload only controller and selector; keep native sessions, transport,
    // wallet and buyer accounting alive. No process-restart claim is made.
    let incoming = tokio::time::timeout(Duration::from_secs(20), bench.tasks.remove(0).stop())
        .await
        .map_err(|_| "source workers did not stop within the reload bound")?
        .ok_or("source control request stream lost during reload")?;
    let before = saved(bench, 0);
    let watch = before["watched_routes"].clone();
    if watch[bench.peers[3].npub()]["selected_trial"] != anchor.trial.contract.id {
        bench.tasks.insert(
            0,
            ControllerTasks::start(bench.controllers[0].clone(), incoming),
        );
        return Err("withdrawal lost the original selected trial reference".into());
    }
    let budget = bench.buyers[0].remaining_budget_sat();
    drop(bench.controllers.remove(0));
    bench.nodes[0]
        .set_source_route(bench.peers[3], None)
        .await
        .unwrap();
    let (transport, policy) = &bench.quote_inputs[0];
    bench.services[0].quotes = Arc::new(
        RouteQuotes::new(bench.nodes[0].clone(), transport.clone(), policy.clone())
            .unwrap()
            .with_price_selection(PriceSelectionPolicy::default(), bench.buyers[0].clone())
            .unwrap(),
    );
    let controller = Arc::new(
        Controller::load(
            &bench.root.path().join("controller-0"),
            bench.controller_policy.clone(),
            bench.services[0].clone(),
        )
        .unwrap(),
    );
    bench.controllers.insert(0, controller.clone());
    let resumed = tokio::time::timeout(Duration::from_secs(20), controller.resume_pending()).await;
    let after = saved(bench, 0);
    let inactive = controller.purchases().await?.is_empty()
        && bench.buyers[0].prepare(&OriginatedSessionIntent {
            source: *bench.peers[0].node_addr(),
            destination: *bench.peers[3].node_addr(),
            next_hop: anchor.trial.provider,
            session_bytes: 1,
        }) == OriginatedSessionAdmission::Reject;
    bench
        .tasks
        .insert(0, ControllerTasks::start(controller, incoming));
    resumed.map_err(|_| "controller reload recovery exceeded its bound")??;
    if !inactive
        || after["watched_routes"] != watch
        || after["funding"] != before["funding"]
        || bench.buyers[0].remaining_budget_sat() != budget
        || bench.buyers[0].observed_units(&anchor.trial.contract.id) != Some(anchor.used)
    {
        return Err(
            "controller reload changed trial allowance, funding or current authority".into(),
        );
    }
    anchor.check(bench).await?;
    eprintln!(
        "promotion: controller+selector reloaded with retained trial reference; retired admission rejected, consumed_units={}",
        anchor.used
    );
    Ok(())
}

async fn run(reload: bool) {
    tokio::time::timeout(Duration::from_secs(300), async {
        let mut bench = bench::start_with_promotion_gate(0, 122).await;
        tokio::time::timeout(Duration::from_secs(15), async {
            while !connected(&bench, 0, 1).await || !connected(&bench, 1, 3).await {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("initial original provider adjacency");
        assert!(!connected(&bench, 0, 2).await);
        let RouteAccess::Paid(trial) = bench.controllers[0]
            .watch_route(bench.peers[3], CEILING)
            .await
            .unwrap()
        else {
            panic!("initial source route must be a paid trial");
        };
        assert_eq!(trial.provider, *bench.peers[1].node_addr());
        assert_eq!(
            trial.contract.max_units,
            PriceSelectionPolicy::default().trial_max_units
        );
        let mut gate = bench.interrupted_acceptance.take().unwrap();
        let prepared = match prepare(&mut bench, &mut gate, &trial).await {
            Ok(mut anchor) if reload => reload_source(&mut bench, &mut anchor)
                .await
                .map(|()| anchor),
            result => result,
        };
        // Restore and drain the original held responses before either recovery
        // or cleanup, including when a fixture premise failed. Never replay Buy.
        carrier(&bench, true);
        let released = gate.release().await;
        let result = match prepared {
            Ok(mut anchor) if released.attempted > 0 => recover(&mut bench, &mut anchor).await,
            Ok(_) => Err("no real full acceptance response was held".into()),
            Err(error) => Err(error),
        };
        assert_eq!(released.attempted, released.delivered + released.canceled);
        tokio::time::timeout(Duration::from_secs(90), finish(bench, gate))
            .await
            .expect("bounded promotion recovery settlement and collection");
        result.expect(
            "original Watch must recover without trial refill or widened spending authority",
        );
    })
    .await
    .expect("interrupted promotion scenario deadline");
}
