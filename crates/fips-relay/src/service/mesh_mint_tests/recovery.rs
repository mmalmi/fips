//! Lost funding and close replies must recover the original financial authority.
use super::*;
use cashu_service::spilman_client_store_path;
use std::collections::BTreeSet;

pub(super) async fn interrupt_close(
    phone: &mut CustomerClient,
    configs: &[ServiceConfig],
    nodes: &mut Vec<RelayService>,
    mint: &mut restart::ProcessMint,
    customer_root: &Path,
    channel: &str,
) {
    let buyer_path = customer_root.join("state/controller/controller.json");
    let seller_path = configs[0]
        .state_directory
        .join("controller/controller.json");
    let original: Value = read_json(&buyer_path).unwrap();
    let wallet = customer_root.join("state/wallet");
    let saved: Value = read_json(&spilman_client_store_path(&wallet)).unwrap();
    let funding: Vec<cashu::nuts::Proof> = serde_json::from_str(
        saved["funding"][channel]["funding_proofs_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let originals: BTreeSet<_> = funding
        .iter()
        .map(|proof| proof.y().unwrap().to_string())
        .collect();
    assert!(!originals.is_empty());
    let (committed, release) = mint.proxy.state.pause_matching_swap_reply(move |swap| {
        swap.inputs().len() == originals.len()
            && swap
                .inputs()
                .iter()
                .all(|proof| proof.y().is_ok_and(|y| originals.contains(&y.to_string())))
    });
    let swaps = mint.proxy.state.swaps.load(Ordering::SeqCst);
    let failed_relay = *nodes[1].endpoint.node_addr();
    let counts = lose_reply(
        phone.execute(CustomerCommand::Finish),
        nodes,
        1,
        mint,
        (committed, release),
        &buyer_path,
    )
    .await;
    assert_eq!(counts.swaps, swaps + 1);
    let interrupted: Value = read_json(&seller_path).unwrap();
    assert_eq!(
        interrupted["seller_settlements"].as_object().unwrap().len(),
        1
    );
    assert!(interrupted["seller_settlements"][channel]["payment"].is_object());
    assert!(interrupted["seller_settlements"][channel]["report"].is_null());

    // Keep the original transit relay offline. The replacement has its own
    // identity and empty journals, and needs no client-specific return tariff.
    mint.reopen().await;
    nodes.insert(1, RelayService::load(configs[3].clone()).await.unwrap());
    let alternate = *nodes[1].endpoint.node_addr();
    // Only read journals until both ordinary workers release the original
    // channel. No second Finish/Settle request may drive recovery.
    let recovered = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let buyer: Value = read_json(&buyer_path).unwrap();
            let seller: Value = read_json(&seller_path).unwrap();
            assert_eq!(buyer["funding"], original["funding"]);
            assert_eq!(buyer["next_funding"], original["next_funding"]);
            assert_eq!(buyer["policy"], original["policy"]);
            counts.unchanged(&mint.proxy);
            let purchase = &buyer["buyer_settlements"][channel];
            let sale = &seller["seller_settlements"][channel];
            if purchase["released"] == true
                && purchase["refunded"] == true
                && sale["released"] == true
            {
                assert_eq!(purchase["report"], sale["report"]);
                assert_eq!(purchase["payment"], sale["payment"]);
                assert_eq!(buyer["buyer_settlements"].as_object().unwrap().len(), 1);
                assert_eq!(seller["seller_settlements"].as_object().unwrap().len(), 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "automatic mesh settlement recovery: provider {:?}",
        nodes[0].controller.last_error()
    );
    counts.recovered(&mint.proxy);
    assert_ne!(alternate, failed_relay);
    for node in [&nodes[0], &nodes[2]] {
        let peers = node.endpoint.peers().await.unwrap();
        assert!(
            peers
                .iter()
                .all(|p| !p.connected || p.node_addr != failed_relay)
        );
        assert!(
            peers
                .iter()
                .any(|peer| peer.connected && peer.node_addr == alternate),
            "both ends must connect through the alternate relay"
        );
    }
    assert!(nodes[1].free.stats().admitted_session_bytes > 0);
    assert!(
        nodes[1]
            .forwarding
            .relay
            .return_stats()
            .unwrap()
            .traffic
            .admitted_packets
            > 0
    );
    let status = phone.execute(CustomerCommand::Status).await.unwrap();
    assert_eq!(status["relay"]["locked_sat"], 0);
    assert_eq!(status["relay"]["funding_budget"]["wallet_debited_sat"], 8);
    assert_eq!(status["relay"]["history"].as_array().unwrap().len(), 1);
}

struct Counters {
    swaps: usize,
    attempts: usize,
    restores: usize,
}

impl Counters {
    fn unchanged(&self, proxy: &MintProxy) {
        assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), self.swaps);
        assert_eq!(
            proxy.state.swap_attempts.load(Ordering::SeqCst),
            self.attempts
        );
    }

    fn recovered(&self, proxy: &MintProxy) {
        self.unchanged(proxy);
        assert!(proxy.state.restores.load(Ordering::SeqCst) > self.restores);
        proxy
            .state
            .reject_swap_replay
            .store(false, Ordering::SeqCst);
    }
}

async fn lose_reply(
    request: impl std::future::Future<Output = Result<Value, String>>,
    nodes: &mut Vec<RelayService>,
    failed: usize,
    mint: &mut restart::ProcessMint,
    gate: (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
    buyer_path: &Path,
) -> Counters {
    let (committed, release) = gate;
    tokio::pin!(request);
    let committed = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = committed => result.unwrap(),
            result = &mut request => panic!("request finished before the committed mint reply: {result:?}"),
        }
    }).await;
    if committed.is_err() {
        let buyer: Value = read_json(buyer_path).unwrap();
        let pending: Vec<_> = ["funding", "requested", "outgoing", "buyer_settlements"]
            .iter()
            .map(|key| (*key, buyer[key].as_object().map(|v| v.len())))
            .collect();
        let providers: Vec<_> = nodes
            .iter()
            .map(|node| (node.controller.last_error(), node.free.stats()))
            .collect();
        panic!(
            "original operation did not reach committed mint response: buyer {pending:?}; providers {providers:?}"
        );
    }
    let counts = Counters {
        swaps: mint.proxy.state.swaps.load(Ordering::SeqCst),
        attempts: mint.proxy.state.swap_attempts.load(Ordering::SeqCst),
        restores: mint.proxy.state.restores.load(Ordering::SeqCst),
    };
    mint.proxy
        .state
        .reject_swap_replay
        .store(true, Ordering::SeqCst);
    // Lose the committed reply and the mint process itself. Preserve its
    // SQLite database, keys and fixed URL for the eventual background recovery.
    nodes.remove(failed).shutdown().await.unwrap();
    mint.crash().await;
    let _ = release.send(());
    let result = tokio::time::timeout(Duration::from_secs(70), request)
        .await
        .expect("original request must fail within its existing deadline");
    assert!(
        result.is_err(),
        "financial request bypassed the absent mint path"
    );
    counts.unchanged(&mint.proxy);
    counts
}

pub(super) async fn interrupt_funding(
    phone: &mut CustomerClient,
    configs: &[ServiceConfig],
    nodes: &mut Vec<RelayService>,
    mint: &mut restart::ProcessMint,
    customer_root: &Path,
) {
    let buyer_path = customer_root.join("state/controller/controller.json");
    let store = spilman_client_store_path(&customer_root.join("state/wallet"));
    let retained = store.clone();
    // Match the durable channel-opening request, not an earlier wallet split.
    let gate = mint.proxy.state.pause_matching_swap_reply(move |request| {
        let Ok(saved) = read_json::<Value>(&retained) else {
            return false;
        };
        saved["openings"]
            .as_object()
            .into_iter()
            .flat_map(|o| o.values())
            .any(|opening| {
                let original: cashu::nuts::SwapRequest =
                    serde_json::from_str(opening["swap_request_json"].as_str().unwrap()).unwrap();
                original.outputs() == request.outputs()
            })
    });
    let counts = lose_reply(
        phone.execute(CustomerCommand::Buy),
        nodes,
        2,
        mint,
        gate,
        &buyer_path,
    )
    .await;
    let original: Value = read_json(&buyer_path).unwrap();
    let intents = original["funding"].as_object().unwrap();
    assert_eq!(intents.len(), 1);
    let (id, intent) = intents.iter().next().unwrap();
    assert!(intent["funded"].is_null());
    assert!(original["outgoing"].as_object().unwrap().is_empty());
    let pending: Value = read_json(&store).unwrap();
    assert_eq!(pending["openings"].as_object().unwrap().len(), 1);
    let opening = &pending["openings"][format!("r:{id}")];
    let operation = opening["wallet_send"]["operation_id"].clone();
    assert!(operation.as_str().is_some_and(|s| !s.is_empty()));

    mint.reopen().await;
    nodes.push(RelayService::load(configs[2].clone()).await.unwrap());
    // Observe automatic funding recovery and activation; do not retry Buy or
    // open another wallet service, which could repair state during observation.
    let restored = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let buyer: Value = read_json(&buyer_path).unwrap();
            counts.unchanged(&mint.proxy);
            assert_eq!(buyer["next_funding"], original["next_funding"]);
            assert_eq!(buyer["policy"], original["policy"]);
            assert_eq!(buyer["funding"].as_object().unwrap().len(), 1);
            let funded = buyer["funding"][id]["funded"].clone();
            let mut authority = buyer["funding"][id].clone();
            authority["funded"] = Value::Null;
            assert_eq!(&authority, intent);
            if funded.is_object() {
                assert_eq!(funded["wallet_operation_id"], operation);
                assert_eq!(funded["wallet_cost"]["wallet_debit_sat"], 8);
                assert_eq!(funded["opening"]["balance"], 0);
                let status = phone.execute(CustomerCommand::Status).await.unwrap();
                let purchases = status["relay"]["purchases"].as_array().unwrap();
                if !purchases.is_empty() {
                    assert_eq!(purchases.len(), 1);
                    assert_eq!(purchases[0]["channel"], funded["terms"]);
                    return status;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("background recovery must activate only the original funded channel");
    counts.recovered(&mint.proxy);
    assert_eq!(restored["relay"]["funding_budget"]["wallet_debited_sat"], 8);
    assert_eq!(restored["relay"]["locked_sat"], 8);
    assert_eq!(restored["relay"]["history"].as_array().unwrap().len(), 1);
}
