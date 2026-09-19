//! Newly heard neighbors must not starve control for an existing funded route.
use super::*;
use bench::Bench;
use cashu_service::{receive_payment_token, send_payment_token};
use fips_relay::controller::FundingBudget;
use std::collections::BTreeMap;
use tokio::time::Instant;

#[path = "control_saturation/attack.rs"]
mod attack;

#[derive(PartialEq, Eq)]
struct Authority {
    funding: BTreeMap<String, (String, String)>,
    incoming: Vec<String>,
    budget: FundingBudget,
}

async fn authority(bench: &Bench) -> Vec<Authority> {
    let mut result = Vec::new();
    for (i, controller) in bench.controllers.iter().enumerate() {
        let saved: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                bench
                    .root
                    .path()
                    .join(format!("controller-{i}/controller.json")),
            )
            .unwrap(),
        )
        .unwrap();
        // Only non-secret identities are compared; bearer funding proofs must
        // never become assertion diagnostics.
        let funding = saved["funding"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(id, record)| {
                let funded = record["funded"].as_object().expect("completed funding");
                (
                    id.clone(),
                    (
                        funded["terms"]["id"].as_str().unwrap().into(),
                        funded["wallet_operation_id"].as_str().unwrap().into(),
                    ),
                )
            })
            .collect();
        let budget = controller.funding_budget().await.unwrap();
        assert_eq!(budget.pending_reserved_sat, 0);
        result.push(Authority {
            funding,
            incoming: saved["incoming"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect(),
            budget,
        });
    }
    result
}

async fn paid_batch(bench: &mut Bench, channel: &str, tag: u8) -> Result<u64, String> {
    let prior = bench.sellers[1].channel_usage(channel).unwrap().paid_msat;
    let started = Instant::now();
    for sequence in 0..12u8 {
        let mut payload = vec![tag; 900];
        payload[0] = sequence;
        bench.nodes[0]
            .send_datagram(bench.peers[2], 44_740, 44_740, payload)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut received = [false; 12];
    tokio::time::timeout(Duration::from_secs(4), async {
        while received.iter().any(|value| !value) {
            let mut batch = Vec::new();
            assert!(
                bench.receivers[2]
                    .recv_batch_into(&mut batch, 32)
                    .await
                    .is_some()
            );
            for message in batch {
                let bytes = message.data.as_slice();
                if message.source_peer.node_addr() == bench.peers[0].node_addr()
                    && bytes.len() == 900
                    && bytes[1..].iter().all(|&byte| byte == tag)
                    && let Some(found) = received.get_mut(bytes[0] as usize)
                {
                    *found = true;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| format!("fresh batch {tag} delivery stalled: {received:?}"))?;
    let evidence = bench.buyers[0].evidence_msat(channel).unwrap();
    let submitted = bench.sellers[1]
        .channel_usage(channel)
        .unwrap()
        .submitted_msat;
    let target = evidence.min(submitted).div_ceil(1000) * 1000;
    assert!(
        target > prior,
        "fresh data must require another cumulative payment"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while bench.sellers[1].channel_usage(channel).unwrap().paid_msat < target {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("batch {tag} delivered all 12 payloads but automatic payment stalled"))?;
    let paid = bench.sellers[1].channel_usage(channel).unwrap().paid_msat;
    eprintln!(
        "control saturation batch {tag}: 12/12 delivered, credited_msat={paid}, elapsed_ms={}",
        started.elapsed().as_millis()
    );
    Ok(paid)
}

async fn settle(bench: &Bench, channel: &str, credited: u64) {
    let remaining = bench.buyers[0].remaining_budget_sat().unwrap();
    for controller in &bench.controllers {
        controller.pause_route_refresh().await.unwrap();
        controller.pause_renewals().await.unwrap();
    }
    let mut expected = [256u64; 3];
    for (i, controller) in bench.controllers.iter().enumerate() {
        let reports = controller.settle_all().await.unwrap();
        assert_eq!(reports.len(), usize::from(i == 0));
        for report in reports {
            assert_eq!(report.channel_id, channel);
            assert!(report.paid_sat * 1000 >= credited);
            assert_eq!(report.paid_sat + report.refunded_sat, 64);
            assert_eq!(report.fee_sat + report.receiver_fee_reserve_sat, 0);
            expected[0] -= report.paid_sat;
            expected[1] += report.paid_sat;
        }
        let budget = controller.funding_budget().await.unwrap();
        assert_eq!(budget.locked_sat + budget.pending_reserved_sat, 0);
        assert_eq!(budget.wallet_debited_sat, if i == 0 { 64 } else { 0 });
    }
    assert!(bench.buyers[0].remaining_budget_sat().unwrap() <= remaining);
    let mut total = 0;
    for (i, wallet) in bench.wallets.iter().enumerate() {
        let balance = load_mint_balance(wallet, bench.mint.url())
            .await
            .unwrap()
            .balance_sat;
        assert_eq!(balance, expected[i]);
        total += balance;
        let token = send_payment_token(wallet, bench.mint.url(), balance)
            .await
            .unwrap();
        receive_payment_token(&bench.root.path().join("collector"), &token.token)
            .await
            .unwrap();
        assert_eq!(
            load_mint_balance(wallet, bench.mint.url())
                .await
                .unwrap()
                .balance_sat,
            0
        );
    }
    assert_eq!(total, 768);
    assert_eq!(
        load_mint_balance(&bench.root.path().join("collector"), bench.mint.url())
            .await
            .unwrap()
            .balance_sat,
        total
    );
    eprintln!(
        "control saturation settlement: exact relay earnings, all {total} test sats collected"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn established_paid_route_progresses_during_incomplete_neighbor_requests() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut bench = bench::start(0, Scenario::ControlSaturation, 118).await;
        tokio::time::timeout(Duration::from_secs(12), async {
            while bench.nodes[1]
                .peers()
                .await
                .unwrap()
                .iter()
                .filter(|p| p.connected)
                .count()
                != 2
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let RouteAccess::Paid(purchase) = bench.controllers[0]
            .watch_route(bench.peers[2], 128)
            .await
            .unwrap()
        else {
            panic!("the forwarding route must be funded");
        };
        assert_eq!(purchase.provider, *bench.peers[1].node_addr());
        assert_eq!(purchase.contract.price.msat, 128);
        // This test fixes the topology and measures payment progress, not route
        // refresh. Automatic cumulative payments stay enabled throughout.
        bench.controllers[0].pause_route_refresh().await.unwrap();
        let mut credited = paid_batch(&mut bench, &purchase.channel.id, 10)
            .await
            .unwrap();
        let before = authority(&bench).await;
        let remaining = bench.buyers[0].remaining_budget_sat().unwrap();
        let attack = attack::start(&bench).await;
        let attackers = attack.peers();
        tokio::time::timeout(Duration::from_secs(3), async {
            while attackers.iter().any(|peer| {
                bench.admissions[1].active_unconfigured_exchanges(*peer.node_addr()) != 4
            }) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("each attacker must really hold four shared admission permits");
        eprintln!("two newly discovered identities hold all eight ordinary control permits");
        let mut progress = Ok(());
        for tag in 20..23 {
            attack.assert_live().await;
            for peer in attackers {
                assert_eq!(
                    bench.admissions[1].active_unconfigured_exchanges(*peer.node_addr()),
                    4
                );
            }
            match paid_batch(&mut bench, &purchase.channel.id, tag).await {
                Ok(paid) => credited = paid,
                Err(error) => {
                    eprintln!("control saturation failure: {error}");
                    progress = Err(error);
                    break;
                }
            }
            assert!(
                authority(&bench).await == before,
                "attack changed channel/funding/capital authority"
            );
            assert!(bench.buyers[0].remaining_budget_sat().unwrap() <= remaining);
        }
        if progress.is_ok() {
            tokio::time::timeout(
                Duration::from_secs(8),
                settle(&bench, &purchase.channel.id, credited),
            )
            .await
            .expect("cooperative settlement must also progress during control saturation");
        }
        attack.assert_live().await;
        for peer in attackers {
            assert_eq!(
                bench.admissions[1].active_unconfigured_exchanges(*peer.node_addr()),
                4
            );
        }
        assert!(
            attack.hold_age() < Duration::from_secs(25),
            "payments cannot pass by waiting for the 30-second control expiry"
        );
        attack.stop().await;
        tokio::time::timeout(Duration::from_secs(3), async {
            while attackers.iter().any(|peer| {
                bench.admissions[1].active_unconfigured_exchanges(*peer.node_addr()) != 0
            }) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("aborting partial streams must release every permit");
        if progress.is_err() {
            assert!(authority(&bench).await == before);
            let recovered = paid_batch(&mut bench, &purchase.channel.id, 30)
                .await
                .unwrap();
            settle(&bench, &purchase.channel.id, credited.max(recovered)).await;
        }
        for task in bench.tasks {
            task.stop().await;
        }
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
        assert!(progress.is_ok(), "{}", progress.unwrap_err());
    })
    .await
    .expect("paid control saturation deadline");
}
