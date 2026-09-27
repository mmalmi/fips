//! A killed buyer recovers spent funding after its route authority expires.
use super::*;
use cashu_service::{
    StreamingRouteOpenCashuSpilmanChannelFromWalletRequest, restore_cashu_spilman_wallet_funding,
    simulation::MintProxy, spilman_client_store_path,
};
use serde_json::Value;
use std::{path::Path, sync::atomic::Ordering};

pub(super) fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(super) async fn wait_journal(
    path: &Path,
    seconds: u64,
    condition: impl Fn(&Value) -> bool,
) -> Value {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            let state = read(path);
            if condition(&state) {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("bounded financial journal transition")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_funding_restores_after_route_expiry_without_new_spending() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9620).await;
        let proxy = MintProxy::start(mint.url()).await;
        let setup::Bench {
            mint: _mint,
            configs,
            paths,
            npubs,
            mut children,
        } = setup::start_nodes(root.path(), mint, network, &proxy.url, 60, 5).await;
        let cfg = &configs[0];
        let wallet = cfg.state_directory.join("wallet");
        let store = spilman_client_store_path(&wallet);
        let journal = cfg.state_directory.join("controller/controller.json");
        let retained = store.clone();
        let (committed, release) = proxy.state.pause_matching_swap_reply(move |request| {
            let Ok(bytes) = std::fs::read(&retained) else {
                return false;
            };
            let state: Value = serde_json::from_slice(&bytes).unwrap();
            state["openings"]
                .as_object()
                .into_iter()
                .flat_map(|openings| openings.values())
                .any(|opening| {
                    let saved: cashu::nuts::SwapRequest =
                        serde_json::from_str(opening["swap_request_json"].as_str().unwrap())
                            .unwrap();
                    saved.outputs() == request.outputs()
                })
        });
        let owner = cfg.clone();
        let destination = npubs[2].clone();
        let buying = tokio::spawn(async move {
            request(
                &owner,
                &AdminRequest::Watch {
                    destination,
                    max_rate_msat_per_kib: 8_192,
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(30), committed)
            .await
            .expect("the persisted channel funding swap must reach the mint")
            .unwrap();
        children[0].kill().await.unwrap();
        assert!(!children[0].wait().await.unwrap().success());
        assert!(buying.await.unwrap().is_err());
        // A killed client's closed connection may already cancel the response
        // waiter. The committed mint result still exists in either case.
        let _ = release.send(());

        let interrupted = read(&journal);
        let intents = interrupted["funding"].as_object().unwrap();
        assert_eq!(intents.len(), 1);
        let (id, intent) = intents.iter().next().unwrap();
        assert!(intent["funded"].is_null());
        let pending = read(&store);
        assert!(pending["funding"].as_object().unwrap().is_empty());
        let opening = &pending["openings"][format!("r:{id}")];
        let wallet_request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest =
            serde_json::from_value(opening["wallet_request"].clone()).unwrap();
        let operation = opening["wallet_send"]["operation_id"].clone();
        assert!(operation.as_str().is_some_and(|id| !id.is_empty()));
        let swaps = proxy.state.swaps.load(Ordering::SeqCst);
        let balance = load_mint_balance(&wallet, &proxy.url)
            .await
            .unwrap()
            .balance_sat;
        let offer = interrupted["requested"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        let offer_id = offer["id"].as_str().unwrap();
        let expiry = offer["expires_unix"].as_u64().unwrap();

        // A departed provider withdraws this watch through the ordinary native
        // adjacency path. No journal editing grants the later expiry refund.
        stop(&mut children[1]).await;
        while now() <= expiry {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        children[0] = start(&paths[0]).await;
        wait_journal(&journal, 15, |state| {
            state["recovery_only"]
                .as_array()
                .unwrap()
                .iter()
                .any(|id| id == offer_id)
        })
        .await;
        request(cfg, &AdminRequest::PauseRouteRefresh)
            .await
            .unwrap();
        let automatic = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if !read(&journal)["funding"][id]["funded"].is_null() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok();
        if !automatic {
            // Preserve the failing assertion until test-money recovery finishes.
            // This explicit fixture rescue is never used by the service.
            stop(&mut children[0]).await;
            restore_cashu_spilman_wallet_funding(&wallet, &wallet_request)
                .await
                .unwrap()
                .expect("the committed mint response remains recoverable");
            children[0] = start(&paths[0]).await;
        }
        let recovered = wait_journal(&journal, 10, |state| {
            !state["funding"][id]["funded"].is_null()
        })
        .await;
        assert!(now() < wallet_request.expiry_unix);
        let mut original = recovered["funding"][id].clone();
        original["funded"] = Value::Null;
        assert!(
            original == *intent,
            "funding authority must remain immutable"
        );
        assert!(recovered["next_funding"] == interrupted["next_funding"]);
        assert!(recovered["funding"][id]["funded"]["wallet_operation_id"] == operation);
        assert_eq!(recovered["funding"][id]["funded"]["opening"]["balance"], 0);
        assert!(recovered["outgoing"].as_object().unwrap().is_empty());
        assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), swaps);
        assert_eq!(
            load_mint_balance(&wallet, &proxy.url)
                .await
                .unwrap()
                .balance_sat,
            balance
        );
        let status = request(cfg, &AdminRequest::Status).await.unwrap();
        assert!(status["purchases"].as_array().unwrap().is_empty());
        let debit = status["funding_budget"]["wallet_debited_sat"]
            .as_u64()
            .unwrap();
        assert!(debit > 32 && debit <= 40);
        assert_eq!(status["funding_budget"]["locked_sat"], debit);
        assert_eq!(128 - balance, debit);
        children[1] = start(&paths[1]).await;
        ready(&configs, &paths, &npubs, &mut children).await;

        // The original wallet expiry, not an edited timestamp or a replacement
        // channel, permits refund and history retirement of the unused funding.
        let retired = wait_journal(&journal, 155, |state| {
            state["funding"].as_object().unwrap().is_empty()
        })
        .await;
        assert!(now() > wallet_request.expiry_unix);
        assert!(retired["outgoing"].as_object().unwrap().is_empty());
        assert!(retired["next_funding"] == interrupted["next_funding"]);
        assert_eq!(retired["history"]["channels"]["totals"]["channels"], 1);
        let wallet_retired = read(&store);
        assert!(wallet_retired["funding"].as_object().unwrap().is_empty());
        assert!(wallet_retired["openings"].get(format!("r:{id}")).is_none());
        assert!(wallet_retired["open_requests"].get(id).is_none());
        let final_status = request(cfg, &AdminRequest::Status).await.unwrap();
        let budget = &final_status["funding_budget"];
        assert_eq!(budget["locked_sat"], 0);
        assert_eq!(budget["wallet_debited_sat"], debit);
        let refund = budget["wallet_refunded_sat"].as_u64().unwrap();
        assert!(refund > 0 && refund < debit);
        assert_eq!(budget["exposure_sat"], debit - refund);
        assert!(final_status["purchases"].as_array().unwrap().is_empty());
        for child in &mut children {
            stop(child).await;
        }
        let mut spendable = 0;
        for (index, cfg) in configs.iter().enumerate() {
            let available = load_mint_balance(&cfg.state_directory.join("wallet"), &proxy.url)
                .await
                .unwrap()
                .balance_sat;
            assert_eq!(
                available,
                if index == 0 {
                    128 - debit + refund
                } else {
                    128
                }
            );
            spendable += available;
        }
        assert_eq!(
            spendable + proxy.state.fees_collected.load(Ordering::SeqCst),
            384
        );
        assert!(
            automatic,
            "expired-route recovery left already-spent funding unresolved"
        );
    })
    .await
    .expect("bounded expired-route funding restoration and retirement");
}
