//! The private stream diagnostic uses ordinary paid application admission.
use super::*;
use fips_relay::{probe::stream::StreamProbe, service::ServiceConfig};

async fn duplex(bench: &MixedBench, duration: u64, bytes: u64) -> [Result<Value, String>; 2] {
    let run = |source: usize, destination: usize| {
        let config: ServiceConfig = bench.configs[source].clone();
        let probe = StreamProbe {
            peer: bench.npubs[destination].clone(),
            stream_id: "74".repeat(16),
            bytes,
            bytes_per_second: 64 * 1024,
            duration_secs: duration,
            connect: source == 0,
        };
        async move { request(&config, &AdminRequest::StreamProbe { probe }).await }
    };
    let (a, b) = tokio::join!(run(0, 2), run(2, 0));
    [a, b]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_stream_probe_requires_paid_routes_and_preserves_settlement() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(174, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "stream-probe",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench =
            MixedBench::start_configured(mint.url(), &network, SecondHop::Tcp, |_, cfg| {
                // Match the hardware stream price without changing capital or
                // spending limits. This case tests delivery, not channel exhaustion.
                cfg.terms.fee_msat_per_kib = 1;
                cfg.terms.quote_max_units = 1024 * 1024;
            })
            .await;
        bench.set_stage("stream-unfunded");
        let denied = duplex(&bench, 2, 1024).await;
        let unfunded = bench.states().await;
        for (source, destination) in [(0, 2), (2, 0)] {
            request(
                &bench.configs[source],
                &AdminRequest::Buy {
                    destination: bench.npubs[destination].clone(),
                },
            )
            .await
            .unwrap();
        }
        let funding = bench.funding_intents(false);
        let before = bench.states().await;
        bench.set_stage("stream-paid");
        let delivery = duplex(&bench, 6, 128 * 1024).await;
        let after = bench.states().await;
        // Close accounts even if the fixed measured workload failed; no new
        // application traffic or purchase can repair that recorded verdict.
        for config in &bench.configs {
            request(config, &AdminRequest::Settle).await.unwrap();
        }
        let settled = bench.states().await;
        for child in &mut bench.children {
            process_support::stop(child).await;
        }
        let mut total = 0;
        for config in &bench.configs {
            total += load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
        }
        assert_eq!(total, 384);
        assert!(network.accounting().unwrap().is_conserved());
        for state in &settled {
            assert_eq!(state["funding_budget"]["locked_sat"], 0);
            assert_eq!(state["funding_budget"]["pending_reserved_sat"], 0);
        }
        assert!(
            denied.iter().all(Result::is_err),
            "an unpaid TCP probe must not deliver application data"
        );
        for node in [0, 2] {
            assert_eq!(unfunded[node]["stream_probe"]["received_bytes"], 0);
            assert_eq!(unfunded[node]["funding_budget"]["wallet_debited_sat"], 0);
            assert_eq!(
                before[node]["purchases"][0]["channel"]["id"],
                after[node]["purchases"][0]["channel"]["id"]
            );
            assert_eq!(
                before[node]["funding_budget"],
                after[node]["funding_budget"]
            );
        }
        assert!(
            bench
                .funding_intents(false)
                .iter()
                .zip(&funding)
                .all(|(after, before)| {
                    before
                        .iter()
                        .all(|(id, value)| after.get(id) == Some(value))
                }),
            "original funding evidence must survive settlement"
        );
        let reports: Vec<_> = delivery
            .into_iter()
            .map(|r| r.unwrap()["probe"].clone())
            .collect();
        for report in &reports {
            assert_eq!(report["accepted_bytes"], 128 * 1024);
            assert_eq!(report["received_bytes"], 128 * 1024);
            assert_eq!(report["acknowledged_bytes"], 128 * 1024);
            assert_eq!(report["finished"], true);
            assert!(report["stopped_reason"].is_null());
        }
        assert_eq!(reports[0]["received_sha256"], reports[1]["received_sha256"]);
        for node in [0, 2] {
            assert_eq!(after[node]["stream_carrier"]["service_port"], 44_744);
            assert!(
                after[node]["stream_carrier"]["transports"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|transport| transport["submitted_packets"].as_u64().unwrap() > 0)
            );
            let progress = after[node]["payment_progress"].as_object().unwrap();
            assert!(
                progress
                    .values()
                    .any(|p| p["evidence_msat"].as_u64().unwrap() > 0)
            );
        }
    })
    .await
    .expect("operator stream acceptance and cleanup deadline");
}
