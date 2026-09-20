//! Exercise the private barrier against actual daemon/controller commitment.
use super::*;
use serde_json::Value;

fn journal(config: &fips_relay::service::ServiceConfig) -> Value {
    serde_json::from_slice(
        &std::fs::read(config.state_directory.join("controller/controller.json")).unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_accept_barrier_holds_real_provider_commit_until_release() {
    tokio::time::timeout(Duration::from_secs(150), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(127, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "accept-barrier",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = MixedBench::start(mint.url(), &network).await;
        bench.assert_carriers().await;
        for config in &bench.configs {
            request(config, &AdminRequest::PauseRenewals).await.unwrap();
        }
        let provider = &bench.configs[1];
        let arm = AdminRequest::TestAcceptBarrierArm {
            buyer: bench.npubs[0].clone(),
            destination: bench.npubs[2].clone(),
            trial_max_units: 8_192,
            hold_ms: 60_000,
        };
        let armed = request(provider, &arm).await.unwrap();
        assert_eq!(armed["active"], true);
        assert!(armed["captured"].is_null());
        let buy_request = AdminRequest::Buy {
            destination: bench.npubs[2].clone(),
        };
        let buy = request(&bench.configs[0], &buy_request);
        tokio::pin!(buy);
        let capture = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    result = &mut buy => panic!("Buy finished before held commitment: {result:?}"),
                    status = request(provider, &AdminRequest::TestAcceptBarrierStatus) => {
                        let status = status.unwrap();
                        assert_eq!(status["active"], true);
                        if status["held_responses"].as_u64().unwrap() > 0 {
                            break status["captured"].clone();
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real provider acceptance capture deadline");
        let purchase = &capture["purchase"];
        assert!(purchase["contract"]["max_units"].as_u64().unwrap() > 8_192);
        let provider_saved = journal(provider);
        let incoming = provider_saved["incoming"]
            .as_object()
            .unwrap()
            .values()
            .find(|record| record["offer"]["id"] == capture["offer_id"])
            .expect("provider durably recorded the captured acceptance");
        assert_eq!(incoming["phase"], "Active");
        assert!(incoming["channel"] == purchase["channel"]);
        assert!(incoming["contract"] == purchase["contract"]);
        let source_saved = journal(&bench.configs[0]);
        let outgoing = source_saved["outgoing"]
            .as_object()
            .unwrap()
            .values()
            .find(|record| record["offer"]["id"] == capture["offer_id"])
            .unwrap();
        assert_eq!(outgoing["accepted"], false);
        assert_eq!(outgoing["retired"], false);
        assert!(outgoing["purchase"] == *purchase);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut buy)
                .await
                .is_err(),
            "real caller must still be waiting for the held response"
        );
        let released = request(provider, &AdminRequest::TestAcceptBarrierRelease)
            .await
            .unwrap();
        assert_eq!(released["terminal_reason"], "released");
        assert_eq!(released["held_responses"], 0);
        assert!(released["forwarded_replies"].as_u64().unwrap() > 0);
        assert_eq!(released["closed_responders"], 0);
        assert!(released["captured"] == capture);
        let bought = tokio::time::timeout(Duration::from_secs(10), &mut buy)
            .await
            .unwrap()
            .unwrap();
        assert!(bought["purchase"] == *purchase);
        assert!(
            request(provider, &arm)
                .await
                .unwrap_err()
                .contains("one-shot")
        );
        bench.deliver(0, 2).await;
        bench
            .wait_paid(purchase["channel"]["id"].as_str().unwrap())
            .await;
        let terminal = request(provider, &AdminRequest::TestAcceptBarrierStatus)
            .await
            .unwrap();
        assert!(terminal["captured"] == capture);
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
    .expect("private acceptance barrier process test deadline");
}
