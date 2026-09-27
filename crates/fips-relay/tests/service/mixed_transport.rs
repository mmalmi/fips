//! Real relay processes cross a native UDP/TCP or UDP/WebSocket boundary. Payment
//! control remains TCP-over-FIPS, independent of those physical transports.

use cashu_service::{
    load_mint_balance,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_relay::service::{AdminRequest, request};
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
            request(config, &AdminRequest::PauseRenewals).await.unwrap();
        }

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
        for config in &bench.configs {
            request(config, &AdminRequest::ResumeRenewals)
                .await
                .unwrap();
        }
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
            bench.recover_seed_carrier().await;
        }

        // A process crash preserves accounts. Whether any individual stream write
        // was submitted is covered by deterministic core completion tests.
        bench.set_stage("middle-restart");
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
        let after = bench.states().await;
        for (old, recovered) in before.iter().zip(&after) {
            assert_eq!(recovered["history"], old["history"]);
            assert_eq!(recovered["funding_budget"], old["funding_budget"]);
            assert!(
                recovered["remaining_budget_sat"].as_u64().unwrap()
                    <= old["remaining_budget_sat"].as_u64().unwrap()
            );
        }
        bench.set_stage("post-restart-paid");
        for (source, destination) in [(0, 2), (2, 0)] {
            bench.deliver(source, destination).await;
        }
        if second_hop != SecondHop::Tcp {
            round_trip::assert_paid_round_trip(&bench, &"65".repeat(16)).await;
        }
        bench.set_stage("settlement");
        for config in &bench.configs {
            request(config, &AdminRequest::Settle).await.unwrap();
        }
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
            }
            total += amount;
        }
        assert_eq!(total, 384);
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("mixed native transport acceptance deadline");
}
