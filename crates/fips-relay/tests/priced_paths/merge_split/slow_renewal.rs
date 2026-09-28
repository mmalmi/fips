//! Delayed replacement funding preserves other neighbors' paid service.
use super::*;
use cashu_service::spilman_client_store_path;
use pending_funding::{healthy_progress, journal, read};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_renewal_funding_preserves_healthy_credit_and_original_authority() {
    tokio::time::timeout(Duration::from_secs(480), exercise())
        .await
        .expect("slow renewal and settlement deadline");
}

async fn exercise() {
    let (mut bench, proxy) = bench::start_with_renewal_proxy(0, 122).await;
    bench.network.set_link("2", "3", SimLink::default());
    converge(&bench, true, "connected mesh before slow renewal").await;
    for (source, destination, tag) in [(2, 0, 20), (2, 5, 21)] {
        watch(&bench, source, destination).await;
        traffic(&mut bench, source, destination, tag).await;
    }
    payments(&bench).await;
    let original = journal(&bench, 2);
    let hops = hop_usage(&bench).await;
    let healthy = hops[&(2, 1)].channel.clone();
    let previous = hops[&(2, 3)].channel.clone();
    let store = spilman_client_store_path(&bench.wallets[2]);
    let saved = read(&store);
    let pending_store = store.clone();
    let initial: Vec<_> = saved["openings"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let (mut committed, release) = proxy.state.pause_matching_swap_reply(move |request| {
        let saved = read(&store);
        saved["openings"]
            .as_object()
            .unwrap()
            .iter()
            .any(|(id, opening)| {
                !initial.contains(id)
                    && opening["swap_request_json"].as_str().is_some_and(|wire| {
                        let original: cashu::nuts::SwapRequest =
                            serde_json::from_str(wire).unwrap();
                        original.outputs() == request.outputs()
                    })
            })
    });
    // Stop generating renewal traffic as soon as the real replacement commits.
    // Its response stays held while the opposite paid direction makes progress.
    tokio::time::timeout(Duration::from_secs(120), async {
        for tag in 30..50 {
            tokio::select! {
                signal = &mut committed => {
                    signal.expect("replacement funding reached the real mint");
                    return;
                }
                _ = traffic(&mut bench, 2, 5, tag) => {}
            }
        }
        committed
            .await
            .expect("bounded traffic triggers replacement funding");
    })
    .await
    .expect("replacement funding observation deadline");

    let held = journal(&bench, 2);
    let pending: Vec<_> = held["funding"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, intent)| intent["funded"].is_null())
        .collect();
    assert_eq!(pending.len(), 1);
    let (id, intent) = pending[0];
    assert_eq!(held["funding"].as_object().unwrap().len(), 3);
    assert_eq!(
        held["next_funding"].as_u64().unwrap(),
        original["next_funding"].as_u64().unwrap() + 1
    );
    assert!(held["policy"] == original["policy"]);
    assert_eq!(held["buyer_settlements"][&previous]["refunded"], true);
    assert_eq!(intent["capacity_sat"], 64);
    assert_eq!(intent["max_wallet_debit_sat"], 64);
    let budget = bench.controllers[2].funding_budget().await.unwrap();
    assert_eq!(budget.pending_reserved_sat, 64);
    assert_eq!(budget.locked_sat, 128);
    assert!(budget.exposure_sat <= bench.controller_policy.max_wallet_spend_sat);
    let opening = read(&pending_store)["openings"][format!("r:{id}")].clone();
    let operation = opening["wallet_send"]["operation_id"].as_str().unwrap();
    assert!(!operation.is_empty());
    assert!(!release.is_closed());
    let progressed = healthy_progress(&mut bench, &healthy).await;
    let after = journal(&bench, 2);
    assert!(after["funding"][id] == *intent);
    assert!(after["next_funding"] == held["next_funding"]);
    assert!(after["policy"] == original["policy"]);
    assert_eq!(bench.controllers[2].funding_budget().await.unwrap(), budget);
    assert!(
        !release.is_closed(),
        "credit observation must precede the mint timeout"
    );
    assert!(
        progressed,
        "replacement funding blocked another neighbor's payment"
    );
    release
        .send(())
        .expect("release the original replacement response");

    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let active = hop_usage(&bench).await;
            if active
                .get(&(2, 3))
                .is_some_and(|hop| hop.channel != previous)
            {
                assert_eq!(active[&(2, 1)].channel, healthy);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the retained replacement becomes active after release");
    let restored = journal(&bench, 2);
    let mut completed = restored["funding"][id].clone();
    let funded = completed["funded"].take();
    assert_eq!(funded["wallet_operation_id"], operation);
    assert!(
        completed == *intent,
        "replacement cannot change its funding authority"
    );
    assert!(restored["next_funding"] == held["next_funding"]);
    for (source, destination, tag) in [(2, 0, 60), (2, 5, 61)] {
        traffic(&mut bench, source, destination, tag).await;
    }
    payments(&bench).await;
    collect(bench).await;
}

async fn collect(mut bench: Bench) {
    for controller in &bench.controllers {
        controller.pause_route_refresh().await.unwrap();
        controller.pause_renewals().await.unwrap();
    }
    let mut expected = vec![256u64; bench.wallets.len()];
    let mut channels = 0;
    for (buyer, controller) in bench.controllers.iter().enumerate() {
        let providers: BTreeMap<_, _> = controller
            .purchase_history()
            .await
            .unwrap()
            .into_iter()
            .map(|purchase| (purchase.channel.id, purchase.provider))
            .collect();
        let reports = controller.settle_all().await.unwrap();
        assert_eq!(reports.len(), providers.len());
        for report in reports {
            let seller = bench
                .peers
                .iter()
                .position(|p| *p.node_addr() == providers[&report.channel_id])
                .unwrap();
            assert_eq!(report.paid_sat + report.refunded_sat, 64);
            assert_eq!(report.fee_sat + report.receiver_fee_reserve_sat, 0);
            expected[buyer] -= report.paid_sat;
            expected[seller] += report.paid_sat;
            channels += 1;
        }
        let budget = controller.funding_budget().await.unwrap();
        assert_eq!(budget.pending_reserved_sat, 0);
        assert_eq!(budget.locked_sat, 0);
        assert!(budget.exposure_sat <= bench.controller_policy.max_wallet_spend_sat);
    }
    assert!(
        channels >= 4,
        "three initial channels and a real replacement settled"
    );
    for task in bench.tasks.drain(..) {
        task.stop().await.unwrap();
    }
    assert_eq!(expected.iter().sum::<u64>(), 1536);
    let mint = &bench.controller_policy.mint_url;
    bench::collect_wallets(bench.root.path(), &bench.wallets, mint, &expected).await;
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
}
