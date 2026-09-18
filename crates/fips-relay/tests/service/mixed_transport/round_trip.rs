//! Diagnostic echo remains independently priced in both directions.
use super::*;
use fips_relay::probe::{ReceiveProbe, SendProbe, encode_packet};
use serde_json::Value;

async fn arm(bench: &MixedBench, id: &str, count: u32) {
    request(
        &bench.configs[2],
        &AdminRequest::ReceiveProbe {
            probe: ReceiveProbe {
                source: bench.npubs[0].clone(),
                stream_id: id.into(),
                packet_count: count,
                payload_bytes: 128,
                reflect: true,
                measure_one_way_latency: false,
            },
        },
    )
    .await
    .unwrap();
}

async fn measure(bench: &MixedBench, id: &str, count: u32) {
    let sent = request(
        &bench.configs[0],
        &AdminRequest::SendProbe {
            probe: SendProbe {
                destination: bench.npubs[2].clone(),
                stream_id: id.into(),
                packet_count: count,
                payload_bytes: 128,
                packets_per_second: 10,
                measure_round_trip: true,
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(sent["probe"]["submitted_packets"], count);
    assert!(sent["probe"]["stopped_reason"].is_null());
}

async fn wait_probe(bench: &MixedBench, index: usize, count: u32) -> Value {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let state = request(&bench.configs[index], &AdminRequest::Status)
                .await
                .unwrap();
            if state["probe"]["unique_packets"] == count {
                return state["probe"].clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("probe delivery")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_trip_is_priced_in_both_directions_and_never_reflects_invalid_or_duplicate_data() {
    tokio::time::timeout(Duration::from_secs(150), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(117, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "round-trip",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = MixedBench::start(mint.url(), &network).await;
        bench.assert_carriers().await;
        request(
            &bench.configs[0],
            &AdminRequest::Buy {
                destination: bench.npubs[2].clone(),
            },
        )
        .await
        .unwrap();
        bench.deliver(0, 2).await;
        let id = "61".repeat(16);
        arm(&bench, &id, 1).await;
        measure(&bench, &id, 1).await;
        wait_probe(&bench, 2, 1).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let states = bench.states().await;
        assert_eq!(states[2]["probe"]["reflected_submitted_packets"], 1);
        assert_eq!(
            states[0]["probe"]["unique_packets"], 0,
            "unpaid reverse path cannot produce RTT"
        );
        assert_eq!(states[0]["probe"]["round_trip_latency"]["samples"], 0);
        assert!(states[2]["purchases"].as_array().unwrap().is_empty());
        assert_eq!(
            states[2]["funding_budget"]["wallet_debited_sat"], 0,
            "reflection never purchases a route"
        );

        request(
            &bench.configs[2],
            &AdminRequest::Buy {
                destination: bench.npubs[0].clone(),
            },
        )
        .await
        .unwrap();
        bench.deliver(2, 0).await;
        let before: Value = serde_json::from_slice(
            &std::fs::read(bench.configs[1].state_directory.join("seller/ledger.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(before["ledger"]["channels"].as_array().unwrap().len(), 2);
        let id = "62".repeat(16);
        arm(&bench, &id, 6).await;
        measure(&bench, &id, 6).await;
        let report = wait_probe(&bench, 0, 6).await;
        assert_eq!(report["missing_packets"], 0);
        assert_eq!(report["unique_bytes"], 768);
        assert_eq!(report["invalid_packets"], 0);
        assert_eq!(report["duplicate_packets"], 0);
        assert!(report["latency"].is_null());
        assert_eq!(report["round_trip_latency"]["samples"], 6);
        assert_eq!(report["round_trip_latency"]["invalid_timestamps"], 0);
        assert!(report["round_trip_latency"]["min_us"].as_u64().unwrap() > 0);
        assert_eq!(
            report["round_trip_latency"]["bucket_counts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap())
                .sum::<u64>(),
            6
        );

        // Replay a seen sequence, corrupt the shape and present reply magic.
        // All go through ordinary paid DATA_PORT service handling.
        let duplicate = encode_packet(&id, 0, 128, 0).unwrap();
        let mut invalid = encode_packet(&id, 7, 128, 0).unwrap();
        invalid[127] = 0;
        let mut echo = duplicate.clone();
        echo[..8].copy_from_slice(b"FIPSRPL1");
        for payload in [duplicate, invalid, echo] {
            request(
                &bench.configs[0],
                &AdminRequest::Send {
                    destination: bench.npubs[2].clone(),
                    payload: String::from_utf8(payload).unwrap(),
                },
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let states = bench.states().await;
                if states[2]["probe"]["ignored_packets"] == 1 {
                    assert_eq!(states[2]["probe"]["invalid_packets"], 1);
                    assert_eq!(states[2]["probe"]["duplicate_packets"], 1);
                    assert_eq!(states[2]["probe"]["unique_packets"], 6);
                    assert_eq!(states[2]["probe"]["reflected_submitted_packets"], 6);
                    assert_eq!(states[2]["probe"]["reflection_failed_packets"], 0);
                    assert_eq!(states[0]["probe"]["unique_packets"], 6);
                    assert_eq!(states[0]["probe"]["reflected_submitted_packets"], 0);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("invalid and duplicate probes processed");
        // The durable JSON snapshot trails hot-path accounting. Wait for the
        // normal checkpoint/payment cycle instead of reading it as live state.
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let after: Value = serde_json::from_slice(
                    &std::fs::read(bench.configs[1].state_directory.join("seller/ledger.json"))
                        .unwrap(),
                )
                .unwrap();
                let billed = before["ledger"]["channels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|old| {
                        let new = after["ledger"]["channels"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|new| new["terms"]["id"] == old["terms"]["id"])
                            .unwrap();
                        new["usage"]["submitted_msat"].as_u64().unwrap()
                            >= old["usage"]["submitted_msat"].as_u64().unwrap() + 6 * 128
                    });
                if billed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("ordinary paid accounting charges both request and reply traffic");
        // An expired arm cannot reflect even a previously unseen, valid packet.
        // Use the real service deadline; no diagnostic-only clock bypass.
        let expired_id = "63".repeat(16);
        arm(&bench, &expired_id, 1).await;
        tokio::time::sleep(Duration::from_millis(60_100)).await;
        request(
            &bench.configs[0],
            &AdminRequest::Send {
                destination: bench.npubs[2].clone(),
                payload: String::from_utf8(encode_packet(&expired_id, 0, 128, 0).unwrap()).unwrap(),
            },
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let state = request(&bench.configs[2], &AdminRequest::Status)
                    .await
                    .unwrap();
                if state["probe"]["ignored_packets"] == 1 {
                    assert_eq!(state["probe"]["unique_packets"], 0);
                    assert_eq!(state["probe"]["reflected_submitted_packets"], 0);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("expired reflection rejected");
        let states = bench.states().await;
        for node in [0, 2] {
            let channel = states[node]["purchases"][0]["channel"]["id"]
                .as_str()
                .unwrap();
            bench.wait_paid(channel).await;
        }
        let mut settlements = 0;
        for config in &bench.configs {
            settlements += request(config, &AdminRequest::Settle).await.unwrap()["settlements"]
                .as_array()
                .unwrap()
                .len();
        }
        assert_eq!(settlements, 2);
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
    })
    .await
    .expect("round trip service deadline");
}
