//! Real relay processes cross a native UDP/TCP or UDP/WebSocket boundary. Payment
//! control remains TCP-over-FIPS, independent of those physical transports.

use cashu_service::{
    load_mint_balance,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_relay::{
    controller::FundingBudget,
    service::{AdminRequest, request},
};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[path = "mixed_transport/bench.rs"]
mod bench;
use crate::process_support;
use bench::{MixedBench, SecondHop};
#[cfg(feature = "testbench")]
#[path = "mixed_transport/accept_barrier.rs"]
mod accept_barrier;
#[cfg(feature = "measurements")]
#[path = "mixed_transport/payment_progress.rs"]
mod payment_progress;
#[path = "mixed_transport/proxy.rs"]
mod proxy;
#[path = "mixed_transport/round_trip.rs"]
mod round_trip;
#[path = "mixed_transport/service_carrier.rs"]
mod service_carrier;
#[path = "mixed_transport/tls.rs"]
mod tls;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_udp_tcp_daemons_preserve_paid_limits_through_exhaustion_and_restart() {
    mixed_daemons_preserve_paid_limits(SecondHop::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_udp_websocket_daemons_preserve_paid_limits_through_exhaustion_and_restart() {
    mixed_daemons_preserve_paid_limits(SecondHop::WebSocket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_udp_websocket_seed_daemons_preserve_paid_limits_without_a_websocket_peer_roster() {
    mixed_daemons_preserve_paid_limits(SecondHop::WebSocketSeed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_udp_websocket_tls_daemons_validate_certificates_and_preserve_paid_limits() {
    mixed_daemons_preserve_paid_limits(SecondHop::WebSocketTls).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_udp_websocket_self_signed_daemons_authenticate_fips_and_preserve_paid_limits() {
    mixed_daemons_preserve_paid_limits(SecondHop::WebSocketSelfSigned).await;
}

async fn mixed_daemons_preserve_paid_limits(second_hop: SecondHop) {
    tokio::time::timeout(Duration::from_secs(240), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(109, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "mixed-carrier",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = MixedBench::start_with_second_hop(mint.url(), &network, second_hop).await;
        bench.set_stage("unfunded-admission");
        bench.assert_carriers().await;
        service_carrier::assert_status(&bench, false).await;
        #[cfg(feature = "measurements")]
        payment_progress::assert_empty(&bench).await;

        // Authentication and control connectivity cannot spend wallet funds.
        for (source, destination) in [(0, 2), (2, 0)] {
            bench.expect_denied(source, destination).await;
        }
        for config in &bench.configs {
            let state = request(config, &AdminRequest::Status).await.unwrap();
            assert_eq!(state["remaining_budget_sat"], 64);
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
            assert!(state["history"].as_array().unwrap().is_empty());
            assert_eq!(
                load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                    .await
                    .unwrap()
                    .balance_sat,
                128
            );
        }
        bench.set_renewals_paused(true).await;

        bench.set_stage("initial-paid");
        let mut original_channels = Vec::new();
        for (source, destination) in [(0, 2), (2, 0)] {
            let bought = request(
                &bench.configs[source],
                &AdminRequest::Buy {
                    destination: bench.npubs[destination].clone(),
                },
            )
            .await
            .unwrap();
            let channel = bought["purchase"]["channel"]["id"]
                .as_str()
                .unwrap()
                .to_owned();
            bench.deliver(source, destination).await;
            bench.wait_paid(&channel).await;
            original_channels.push(channel);
        }
        if second_hop != SecondHop::Tcp {
            round_trip::assert_paid_round_trip(&bench, &"64".repeat(16)).await;
        }
        #[cfg(feature = "measurements")]
        payment_progress::assert_reconciled(&bench, &original_channels).await;
        service_carrier::assert_status(&bench, true).await;

        // Fill a small channel with renewals explicitly paused. This tests a
        // financial denial, not an inference from a lost carrier connection.
        bench.set_stage("exhaustion");
        for (index, (source, destination)) in [(0, 2), (2, 0)].into_iter().enumerate() {
            bench.send_probe(source, destination, 40, 256, 8).await;
            bench.wait_exhausted(source).await;
            bench.wait_paid(&original_channels[index]).await;
            bench.expect_denied(source, destination).await;
            let state = request(&bench.configs[source], &AdminRequest::Status)
                .await
                .unwrap();
            assert_eq!(state["history"].as_array().unwrap().len(), 1);
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 8);
            assert_eq!(state["remaining_budget_sat"], 56);
        }
        bench.set_stage("renewal");
        let exhausted = bench.states().await;
        bench.set_renewals_paused(false).await;
        bench.wait_replacements(&original_channels).await;
        for (source, destination) in [(0, 2), (2, 0)] {
            bench.deliver(source, destination).await;
            let state = request(&bench.configs[source], &AdminRequest::Status)
                .await
                .unwrap();
            assert_eq!(state["history"].as_array().unwrap().len(), 2);
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 16);
            assert!(state["funding_budget"]["locked_sat"].as_u64().unwrap() <= 16);
            assert!(
                state["remaining_budget_sat"].as_u64().unwrap()
                    <= exhausted[source]["remaining_budget_sat"].as_u64().unwrap()
            );
            bench
                .wait_paid(state["purchases"][0]["channel"]["id"].as_str().unwrap())
                .await;
        }

        if second_hop.is_seed() {
            bench.set_stage("carrier-interruption");
            bench.recover_seed_carrier(false).await;
            if second_hop == SecondHop::WebSocketSeed {
                bench.set_stage("carrier-silent-loss");
                bench.recover_seed_carrier(true).await;
            }
        }

        // A process crash preserves accounts. Whether any individual stream write
        // was submitted is covered by deterministic core completion tests.
        bench.set_stage("middle-restart");
        let original_funding = bench.funding_intents();
        let before = bench.states().await;
        let tls_connections = bench.tls.as_ref().map(tls::TlsProxy::connections);
        bench.children[1].kill().await.unwrap();
        bench.children[1] = process_support::start(&bench.paths[1]).await;
        process_support::ready(
            &bench.configs,
            &bench.paths,
            &bench.npubs,
            &mut bench.children,
        )
        .await;
        bench.assert_carriers().await;
        if let Some(previous) = tls_connections {
            assert!(bench.tls.as_ref().unwrap().connections() > previous);
        }
        bench.set_stage("post-restart-paid");
        for (source, destination) in [(0, 2), (2, 0)] {
            if second_hop.is_seed() {
                bench.deliver_sized(source, destination, 512).await;
            } else {
                bench.deliver(source, destination).await;
            }
        }
        if second_hop.is_seed() {
            bench.set_stage("crash-allowance-renewal");
            let channels: Vec<_> = [0, 2]
                .into_iter()
                .map(|source| {
                    before[source]["purchases"][0]["channel"]["id"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect();
            // Recovery traffic plus the lost checkpoint window requires
            // renewal. Observe automatic replacement before starting
            // the fixed cohort, which deliberately must not cross a settlement.
            bench.wait_replacements(&channels).await;
            let ledger: serde_json::Value = serde_json::from_slice(
                &std::fs::read(bench.configs[1].state_directory.join("seller/ledger.json"))
                    .unwrap(),
            )
            .unwrap();
            for channel in &channels {
                let usage = &ledger["ledger"]["channels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["terms"]["id"] == *channel)
                    .unwrap()["usage"];
                let submitted = usage["submitted_msat"].as_u64().unwrap();
                assert!(usage["lost_msat"].as_u64().unwrap() > 0);
                assert_eq!(usage["paid_msat"], submitted.div_ceil(1_000) * 1_000);
                assert!(
                    usage["paid_msat"].as_u64().unwrap() < usage["reserved_msat"].as_u64().unwrap(),
                    "crash exposure stays retained and unbilled after replacement"
                );
            }
        }
        assert_restart_accounts(&bench, &before, &original_funding, second_hop.is_seed()).await;
        if second_hop != SecondHop::Tcp {
            round_trip::assert_paid_round_trip(&bench, &"65".repeat(16)).await;
        }
        bench.set_stage("settlement");
        for config in &bench.configs {
            request(config, &AdminRequest::Settle).await.unwrap();
        }
        let settled = bench.states().await;
        #[cfg(feature = "measurements")]
        payment_progress::assert_empty(&bench).await;
        for child in &mut bench.children {
            process_support::stop(child).await;
        }
        let mut total = 0;
        for (node, config) in bench.configs.iter().enumerate() {
            let amount = load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
            if node == 1 {
                assert!(amount > 128, "the relay must redeem its earned payment");
            } else {
                let budget: FundingBudget =
                    serde_json::from_value(settled[node]["funding_budget"].clone()).unwrap();
                assert_eq!(budget.pending_reserved_sat, 0);
                assert_eq!(budget.locked_sat, 0);
                assert_eq!(amount + budget.exposure_sat, 128);
            }
            total += amount;
        }
        assert_eq!(total, 384);
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("mixed native transport acceptance deadline");
}

async fn assert_restart_accounts(
    bench: &MixedBench,
    before: &[Value],
    original_funding: &[serde_json::Map<String, Value>],
    renewed: bool,
) {
    let after = bench.states().await;
    let funding = bench.funding_intents();
    for (node, (old, recovered)) in before.iter().zip(&after).enumerate() {
        // A completed refund or replacement may change aggregate counters.
        // Original wallet operations and purchase identities must remain exact.
        for (id, intent) in &original_funding[node] {
            assert!(
                funding[node].get(id) == Some(intent),
                "restart changed an original funding intent at node {node}"
            );
        }
        let previous = old["history"].as_array().unwrap();
        let history = recovered["history"].as_array().unwrap();
        assert!(previous.iter().all(|purchase| history.contains(purchase)));
        let replacements = usize::from(node != 1);
        assert!(funding[node].len() <= original_funding[node].len() + replacements);
        assert!(history.len() <= previous.len() + replacements);

        let old_budget: FundingBudget =
            serde_json::from_value(old["funding_budget"].clone()).unwrap();
        let budget: FundingBudget =
            serde_json::from_value(recovered["funding_budget"].clone()).unwrap();
        let policy = &bench.configs[node].terms.controller;
        assert!(budget.wallet_debited_sat >= old_budget.wallet_debited_sat);
        assert!(budget.wallet_refunded_sat >= old_budget.wallet_refunded_sat);
        assert!(
            budget.wallet_debited_sat + budget.pending_reserved_sat
                <= old_budget.wallet_debited_sat
                    + replacements as u64 * policy.channel_capacity_sat
        );
        assert_eq!(
            budget.exposure_sat,
            budget.pending_reserved_sat + budget.wallet_debited_sat - budget.wallet_refunded_sat
        );
        assert!(budget.exposure_sat <= policy.max_wallet_spend_sat);
        assert!(budget.locked_sat <= policy.max_locked_sat);
        assert!(
            recovered["remaining_budget_sat"].as_u64().unwrap()
                <= old["remaining_budget_sat"].as_u64().unwrap()
        );
        if renewed && node != 1 {
            assert_eq!(history.len(), previous.len() + 1);
            assert_eq!(funding[node].len(), original_funding[node].len() + 1);
            assert_eq!(
                budget.wallet_debited_sat,
                old_budget.wallet_debited_sat + policy.channel_capacity_sat
            );
        }
    }
}
