//! Recover wallet-committed funding without reviving expired routing permission.
use super::*;
use fips_relay::{controller::WatchedRoute, route_quotes::RouteOffer};

pub(super) async fn exercise(
    root: &std::path::Path,
    policy: ControllerPolicy,
    services: ControllerServices,
) {
    let directory = root.join("controller-4");
    let path = directory.join("controller.json");
    let read =
        || -> serde_json::Value { serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap() };
    let mut original = read();
    assert!(original["outgoing"].as_object().unwrap().is_empty());
    let (original_id, funding) = original["funding"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap();
    assert_eq!(funding["funded"]["opening"]["balance"], 0);
    let balance = load_mint_balance(&services.wallet_directory, &policy.mint_url)
        .await
        .unwrap()
        .balance_sat;
    let acceptance = services.acceptance.statistics().snapshot();
    let mut recovered = None;
    for mode in [
        "missing-wallet-record",
        "changed-terms",
        "expired",
        "paused",
        "orphaned",
    ] {
        let mut journal = original.clone();
        let mut expected = funding.clone();
        expected["funded"] = serde_json::Value::Null;
        let id = if mode == "missing-wallet-record" {
            let sequence = journal["next_funding"].as_u64().unwrap();
            let id = format!("{}-{sequence}", journal["epoch"].as_str().unwrap());
            journal["next_funding"] = (sequence + 1).into();
            expected["id"] = id.clone().into();
            id
        } else {
            original_id.clone()
        };
        if mode == "changed-terms" {
            expected["receiver_pubkey_hex"] = format!("02{}", "22".repeat(32)).into();
        }
        journal["funding"] = serde_json::json!({id.clone(): expected});
        let requested = journal["requested"].as_object_mut().unwrap();
        let offer = requested.values_mut().next().unwrap();
        if mode == "paused" {
            let offer: RouteOffer = serde_json::from_value(offer.clone()).unwrap();
            let destination = offer.destination.npub();
            let watch: WatchedRoute = serde_json::from_value(serde_json::json!({
                "destination": destination, "billing": offer.billing,
                "max_rate_msat_per_kib": 8192, "paused":true, "pending": offer
            }))
            .unwrap();
            journal["watched_routes"] = serde_json::json!({destination: watch});
        } else {
            // Exercise the expiry boundary without sleeping out the quote's
            // lifetime. Funding terms and wallet records remain immutable.
            offer["expires_unix"] = 1.into();
        }
        if mode == "orphaned" {
            journal["requested"] = serde_json::json!({});
        }
        std::fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        let mut expected_funded = if matches!(mode, "expired" | "paused" | "orphaned") {
            funding["funded"].clone()
        } else {
            serde_json::Value::Null
        };
        for attempt in 0..2 {
            let controller =
                Controller::load(&directory, policy.clone(), services.clone()).unwrap();
            let result = controller.resume_pending().await;
            if matches!(mode, "paused" | "orphaned") {
                result.unwrap();
            } else {
                assert!(result.is_err());
            }
            let after = read();
            let funded = &after["funding"][&id]["funded"];
            if attempt == 0 && !expected_funded.is_null() {
                // The wallet can retain a later signature at the same zero
                // balance. Its channel, terms, parameters and proofs must match.
                expected_funded["opening"]["signature"] = funded["opening"]["signature"].clone();
                assert!(
                    funded["opening"]["signature"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                );
                recovered = Some(funded.clone());
            }
            assert!(
                *funded == expected_funded,
                "{mode}: recover only the existing wallet-committed identity"
            );
            assert_eq!(after["next_funding"], journal["next_funding"]);
            assert_eq!(after["requested"], journal["requested"]);
            assert_eq!(after["watched_routes"], journal["watched_routes"]);
            assert!(after["outgoing"].as_object().unwrap().is_empty());
            assert!(controller.purchases().await.unwrap().is_empty());
            assert_eq!(
                controller.locked_capital_sat().await.unwrap(),
                policy.channel_capacity_sat
            );
            assert_eq!(
                load_mint_balance(&services.wallet_directory, &policy.mint_url)
                    .await
                    .unwrap()
                    .balance_sat,
                balance,
                "recovery must not spend another token"
            );
            assert_eq!(
                services.acceptance.statistics().snapshot(),
                acceptance,
                "expired/paused recovery cannot send Accept RPCs"
            );
            drop(controller);
        }
    }
    // Return the original live offer to the enclosing scenario; it subsequently
    // reconstructs the same purchase, transfers paid data and conserves funds.
    let original_id = original_id.clone();
    original["funding"][&original_id]["funded"] = recovered.unwrap();
    std::fs::write(path, serde_json::to_vec(&original).unwrap()).unwrap();
}
