//! Lose an actual committed close reply; ordinary upkeep must retain its money.
use super::*;
use cashu_service::spilman_client_store_path;
use std::collections::BTreeSet;

pub(super) async fn interrupt_close(
    phone: &mut CustomerClient,
    configs: &[ServiceConfig],
    nodes: &mut [RelayService],
    proxy: &MintProxy,
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
    let (committed, release) = proxy.state.pause_matching_swap_reply(move |swap| {
        swap.inputs().len() == originals.len()
            && swap
                .inputs()
                .iter()
                .all(|proof| proof.y().is_ok_and(|y| originals.contains(&y.to_string())))
    });
    let swaps = proxy.state.swaps.load(Ordering::SeqCst);
    let attempts = proxy.state.swap_attempts.load(Ordering::SeqCst);
    let restores = proxy.state.restores.load(Ordering::SeqCst);
    {
        let finishing = phone.execute(CustomerCommand::Finish);
        tokio::pin!(finishing);
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                result = committed => result.unwrap(),
                result = &mut finishing => panic!("finish before the committed close: {result:?}"),
            }
        })
        .await
        .expect("original funding proofs must reach the mint-close boundary");
        assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), swaps + 1);
        assert_eq!(
            proxy.state.swap_attempts.load(Ordering::SeqCst),
            attempts + 1
        );

        // Cut the real TCP/FIPS stream after the mint commits, before the
        // signed outputs reach the provider. The HTTP backend stays alive.
        nodes[2].mint.take().unwrap().shutdown().await.unwrap();
        proxy.state.reject_swap_replay.store(true, Ordering::SeqCst);
        let _ = release.send(());
        let result = tokio::time::timeout(Duration::from_secs(70), finishing)
            .await
            .expect("original settlement call must fail within its existing deadline");
        assert!(
            result.is_err(),
            "settlement bypassed the absent mint adapter"
        );
    }
    let interrupted: Value = read_json(&seller_path).unwrap();
    assert_eq!(
        interrupted["seller_settlements"].as_object().unwrap().len(),
        1
    );
    assert!(interrupted["seller_settlements"][channel]["payment"].is_object());
    assert!(interrupted["seller_settlements"][channel]["report"].is_null());

    let export = configs[2].mint_export.as_ref().unwrap();
    nodes[2].mint = Some(
        MeshMintBridge::serve(
            nodes[2].endpoint.clone(),
            export.service_port,
            export.backend,
        )
        .await
        .unwrap(),
    );
    // Only read journals until both ordinary workers release the original
    // channel. No second Finish/Settle request may drive recovery.
    let recovered = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let buyer: Value = read_json(&buyer_path).unwrap();
            let seller: Value = read_json(&seller_path).unwrap();
            assert_eq!(buyer["funding"], original["funding"]);
            assert_eq!(buyer["next_funding"], original["next_funding"]);
            assert_eq!(buyer["policy"], original["policy"]);
            assert_eq!(
                proxy.state.swap_attempts.load(Ordering::SeqCst),
                attempts + 1
            );
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
    assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), swaps + 1);
    assert!(proxy.state.restores.load(Ordering::SeqCst) > restores);
    let status = phone.execute(CustomerCommand::Status).await.unwrap();
    assert_eq!(status["relay"]["locked_sat"], 0);
    assert_eq!(status["relay"]["funding_budget"]["wallet_debited_sat"], 8);
    assert_eq!(status["relay"]["history"].as_array().unwrap().len(), 1);
    proxy
        .state
        .reject_swap_replay
        .store(false, Ordering::SeqCst);
}
