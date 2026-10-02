//! Temporary allowance shortages cross the actual service forwarding wrapper.
use super::*;
use fips_relay::service::native_request;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn temporary_allowance_waits_in_the_running_service() {
    tokio::time::timeout(Duration::from_secs(150), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(131, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "admission-wait",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench =
            MixedBench::start_configured(mint.url(), &network, SecondHop::Tcp, |_, config| {
                config.terms.window_msat = 512
            })
            .await;
        bench.set_renewals_paused(true).await;
        let bought = request(
            &bench.configs[0],
            &AdminRequest::Buy {
                destination: bench.npubs[2].clone(),
            },
        )
        .await
        .unwrap();
        let provider = &bench.configs[1];
        let before = native_request(provider, &json!({"command":"show_status"}))
            .await
            .unwrap();

        // One finite burst fits the channel and waiting queue, but crosses
        // several durable windows. No application resend or explicit flush.
        bench.send_probe(0, 2, 16, 256, 10_000).await;
        let delivered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = request(&bench.configs[2], &AdminRequest::Status)
                    .await
                    .unwrap();
                if status["probe"]["unique_packets"] == 16 {
                    break status["probe"].clone();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the original waiting packets must resume without an application retry");
        assert_eq!(delivered["unique_bytes"], 4_096);
        assert_eq!(delivered["duplicate_packets"], 0);
        assert_eq!(delivered["invalid_packets"], 0);
        let after = native_request(provider, &json!({"command":"show_status"}))
            .await
            .unwrap();
        let (a, b) = (&before["data"]["forwarding"], &after["data"]["forwarding"]);
        let deferred = b["deferred_policy_packets"].as_u64().unwrap()
            - a["deferred_policy_packets"].as_u64().unwrap();
        assert!(
            deferred > 0,
            "the installed service policy must actually defer packets"
        );
        assert_eq!(
            b["drop_policy_denied_packets"],
            a["drop_policy_denied_packets"]
        );
        eprintln!("service admission deferred={deferred}, delivered=16, duplicates=0");
        bench
            .wait_paid(bought["purchase"]["channel"]["id"].as_str().unwrap())
            .await;
        for config in &bench.configs {
            request(config, &AdminRequest::Settle).await.unwrap();
        }
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
    .expect("service admission test deadline");
}
