//! A crash before sending releases only its exact, durably cancelled reservation.
use super::{preopening_support::*, restore::*, *};
use cashu_service::{
    CashuRequestSequence, CashuSendCost, CashuSendSequenceHistory, CashuSpilmanRetiredHistory,
    simulation::MintProxy, spilman_client_store_path,
};
use serde_json::Value;
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crashed_metadata_wait_cancels_and_retires_without_a_wallet_send() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9625).await;
        let proxy = MintProxy::start(mint.url()).await;
        let setup::Bench { mint: _mint, configs, paths, npubs, mut children } =
            setup::start_nodes_with_funding_limit(root.path(), mint, network,
                &proxy.url, 60, 5, 48).await;
        let cfg = &configs[0];
        let wallet = cfg.state_directory.join("wallet");
        let sdk_path = spilman_client_store_path(&wallet);
        let journal_path = cfg.state_directory.join("controller/controller.json");
        let swaps = proxy.state.swaps.load(Ordering::SeqCst);
        let provider_pids: Vec<_> = children[1..].iter().map(|child| child.id()).collect();
        let (metadata, release) = proxy.state.pause_next_keysets_reply();
        let owner = cfg.clone();
        let destination = npubs[2].clone();
        let mut buying = tokio::spawn(async move {
            request(&owner, &AdminRequest::Buy { destination }).await
        });
        let captured = tokio::select! {
            signal = metadata => signal.is_ok(),
            _ = &mut buying => false,
            _ = tokio::time::sleep(Duration::from_secs(20)) => false,
        };
        if !captured {
            let _ = release.send(());
            let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
            buying.abort();
            if !conserved { let _ = root.keep(); }
            panic!("metadata admission barrier missing; conserved={conserved}");
        }
        // A one-time Buy creates no recurring Watch. Recovery must finish the
        // original intent without obtaining authority for another purchase.
        let original = read(&journal_path);
        let sdk = read(&sdk_path);
        let sends = send_journal(&wallet).await;
        let funding = original["funding"].as_object().unwrap();
        assert_eq!(funding.len(), 1);
        let (id, intent) = funding.iter().next().unwrap();
        let authority = funding_authority(intent);
        let admission = &sdk["admissions"][id];
        let wanted = admission["request"].clone();
        assert_eq!(wanted["client_request_id"], *id);
        let sequence = CashuRequestSequence::from_request_id(id).unwrap().unwrap();
        let retired_evidence = CashuSpilmanRetiredHistory {
            send: CashuSendSequenceHistory {
                mint_url: wanted["mint_url"].as_str().unwrap().to_owned(),
                through: sequence.number(),
                requests: 0,
                requested_sat: 0,
                cost: CashuSendCost::default(),
            },
            abandoned_requests: 0,
            cancelled_requests: 1,
            capacity_sat: 0,
            signed_sat: 0,
            refund_sat: 0,
            expires_through_unix: wanted["expiry_unix"].as_u64().unwrap(),
        };
        assert_eq!(admission["funding_started"], false);
        assert!(admission["reclaim"].is_null());
        assert_eq!(entries(&sdk, "admissions"), 1);
        assert_eq!(entries(&sdk, "openings") + entries(&sdk, "funding"), 0);
        assert_eq!(request_count(&sends), 0);
        assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), swaps);
        assert_eq!(entries(&original, "watched_routes"), 0);
        assert_eq!(entries(&original, "requested"), 1);
        let offer = original["requested"].as_object().unwrap().values().next().unwrap().clone();
        let offer_id = offer["id"].as_str().unwrap();
        let expiry = offer["expires_unix"].as_u64().unwrap();
        assert_eq!(original["requested"][offer_id], offer);
        children[0].kill().await.unwrap();
        assert!(!children[0].wait().await.unwrap().success());
        assert!(buying.await.unwrap().is_err());
        let _ = release.send(());
        // No failed-call cleanup runs in the killed process: its admitted,
        // never-started request is the durable recovery authority.
        assert_eq!(read(&sdk_path)["admissions"][id], *admission);
        while now() <= expiry { tokio::time::sleep(Duration::from_millis(100)).await; }
        children[0] = start(&paths[0]).await;
        ready(&configs, &paths, &npubs, &mut children).await;
        let mut errors = Vec::new();
        let mut cancelled = false;
        let mut retired = false;
        let mut last_status = Value::Null;
        while now() <= wanted["expiry_unix"].as_u64().unwrap() + 10 {
            let current = read(&journal_path);
            let sdk = read(&sdk_path);
            let sdk_retired = serde_json::from_value::<CashuSpilmanRetiredHistory>(
                sdk["retirement"]["scopes"][sequence.scope()].clone(),
            ).is_ok_and(|history| history == retired_evidence);
            check(&mut errors, current["next_funding"] == original["next_funding"]
                && current["policy"] == original["policy"], "funding authority changed");
            check(&mut errors, current["watched_routes"] == original["watched_routes"],
                "one-time purchase gained a recurring Watch");
            check(&mut errors, entries(&current, "outgoing") == 0
                && entries(&sdk, "openings") == 0 && entries(&sdk, "funding") == 0,
                "cancelled admission opened a channel or purchase");
            check(&mut errors, children[1..].iter_mut().zip(&provider_pids).all(|(child, pid)|
                child.id() == *pid && child.try_wait().unwrap().is_none()),
                "an unrelated daemon restarted");
            if let Some(saved) = current["funding"].get(id) {
                check(&mut errors, funding_authority(saved) == authority,
                    "original cancellation terms changed");
                cancelled |= saved["reclaim"]["state"] == "cancelled";
                if saved["reclaim"]["state"] == "cancelled" {
                    // SDK retirement replaces the admission before the controller
                    // finishes its handoff; either durable form must remain exact.
                    let exact = sdk["admissions"].get(id).map_or(sdk_retired, |admission|
                        admission["reclaim"]["result"] == "Cancelled"
                            && admission["request"] == wanted);
                    check(&mut errors, exact,
                        "controller cancellation has no exact SDK evidence");
                }
            }
            let history = &current["history"]["channels"]["totals"];
            retired = history["cancelled_requests"] == 1 && entries(&current, "funding") == 0;
            if retired {
                check(&mut errors, sdk_retired && entries(&sdk, "admissions") == 0,
                    "retired cancellation has no exact SDK history");
            }
            cancelled |= retired;
            if let Ok(Ok(status)) = tokio::time::timeout(Duration::from_secs(2),
                request(cfg, &AdminRequest::Status)).await {
                check(&mut errors, status["purchases"].as_array().unwrap().is_empty()
                    && status["remaining_budget_sat"] == cfg.terms.buyer_budget_sat,
                    "cancellation changed buyer authority");
                let budget = &status["funding_budget"];
                check(&mut errors, budget["wallet_debited_sat"] == 0
                    && budget["wallet_refunded_sat"] == 0, "cancellation invented monetary totals");
                if cancelled {
                    check(&mut errors, budget["locked_sat"] == 0
                        && budget["pending_reserved_sat"] == 0 && budget["exposure_sat"] == 0,
                        "terminal cancellation kept a reservation");
                }
                last_status = status;
            }
            if retired { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        check(&mut errors, cancelled && retired, "ordinary upkeep did not cancel and retire the original request");
        let mut available = 0;
        for cfg in &configs {
            let wallet = cfg.state_directory.join("wallet");
            available += spendable_balance(&wallet, &proxy.url).await;
            check(&mut errors, request_count(&send_journal(&wallet).await) == 0,
                "cancellation created a wallet send");
        }
        check(&mut errors, available == 384 && proxy.state.swaps.load(Ordering::SeqCst) == swaps
            && proxy.state.fees_collected.load(Ordering::SeqCst) == 0,
            "pre-send cancellation changed actual wallet value");
        if retired {
            let before = read(&journal_path);
            let sdk_before = read(&sdk_path);
            stop(&mut children[0]).await;
            children[0] = start(&paths[0]).await;
            ready(&configs, &paths, &npubs, &mut children).await;
            let after = read(&journal_path);
            check(&mut errors, after["history"]["channels"] == before["history"]["channels"]
                && after["next_funding"] == before["next_funding"]
                && read(&sdk_path)["retirement"] == sdk_before["retirement"],
                "restart changed cancellation cutoff or financial history");
        }
        eprintln!("pre-send cancellation cancelled={cancelled} retired={retired} spendable_sat={available} budget={}",
            last_status["funding_budget"]);
        // Determine success before administrative cleanup, which never supplies
        // cancellation evidence or rewrites the controller to make the test pass.
        let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
        check(&mut errors, conserved, "fixture cleanup did not conserve test funds");
        if !conserved { let _ = root.keep(); }
        assert!(errors.is_empty(), "pre-send cancellation: {errors:?}");
    }).await.expect("bounded pre-send crash recovery and history retirement");
}
