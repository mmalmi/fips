//! Customer reconnect while a funded successor overlaps an unresolved mint close.
use super::*;

#[path = "../process_support/mint.rs"]
mod mint;

fn journal(config: &ServiceConfig) -> Value {
    serde_json::from_slice(
        &std::fs::read(config.state_directory.join("controller/controller.json")).unwrap(),
    )
    .unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn status(config: &ServiceConfig) -> Value {
    request(config, &AdminRequest::Status).await.unwrap()
}

async fn port(config: &ServiceConfig) -> u16 {
    native_request(config, &json!({"command":"show_transports"}))
        .await
        .unwrap()["data"]["transports"][0]["local_addr"]
        .as_str()
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap()
        .port()
}

fn assert_held(configs: &[ServiceConfig], original: &str) {
    let buyer = journal(&configs[1]);
    assert_eq!(buyer["renewals"][original]["completed"], false);
    assert_eq!(buyer["buyer_settlements"][original]["refunded"], false);
    assert!(journal(&configs[2])["seller_settlements"][original]["report"].is_null());
}

pub(super) async fn rebind_during_close(
    configs: &[ServiceConfig],
    npubs: &[String],
    client: &mut CustomerClient,
    proxy: &MintProxy,
) {
    let before = client.execute(Action::Status).await.unwrap();
    assert_eq!(before["relay"]["purchases"].as_array().unwrap().len(), 1);
    let purchase = &before["relay"]["purchases"][0];
    let original = purchase["channel"]["id"].as_str().unwrap();
    let expiry = purchase["contract"]["expires_unix"].as_u64().unwrap();
    let saved = journal(&configs[1]);
    assert_eq!(saved["policy"]["renewal"]["before_expiry_secs"], 30);
    let (committed, release) =
        mint::pause_channel_close(proxy, &configs[1].state_directory.join("wallet"), original);
    tokio::time::timeout(Duration::from_secs(75), committed)
        .await
        .expect("the phone's automatic expiry close must commit")
        .unwrap();
    assert!(now() < expiry && now() + 30 >= expiry);
    assert_held(configs, original);
    let successor = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = status(&configs[1]).await;
            let purchases = state["purchases"].as_array().unwrap();
            if purchases.len() == 1 && purchases[0]["channel"]["id"] != original {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("funded successor must activate before the held close returns");
    let replacement = &successor["purchases"][0];
    assert_eq!(replacement["provider"], purchase["provider"]);
    for field in ["destination", "next_hop", "price", "max_units", "billing"] {
        assert_eq!(replacement["contract"][field], purchase["contract"][field]);
    }
    assert!(replacement["contract"]["expires_unix"].as_u64().unwrap() > expiry);
    assert!(
        before["relay"]["payment_progress"][original]["authorized_sat"]
            .as_u64()
            .unwrap()
            < 25
    );

    assert_eq!(replacement["channel"]["capacity_sat"], 32);
    assert_eq!(successor["funding_budget"]["locked_sat"], 64);
    assert_eq!(successor["funding_budget"]["pending_reserved_sat"], 0);
    assert_eq!(successor["funding_budget"]["wallet_debited_sat"], 64);
    assert_eq!(successor["funding_budget"]["wallet_refunded_sat"], 0);
    let next = replacement["channel"]["id"].as_str().unwrap();
    assert_ne!(next, original);
    let retained = journal(&configs[1]);
    assert_eq!(retained["policy"], saved["policy"]);
    assert_eq!(retained["funding"].as_object().unwrap().len(), 2);
    for (id, funding) in saved["funding"].as_object().unwrap() {
        assert_eq!(&retained["funding"][id], funding);
    }

    let prior_port = port(&configs[1]).await;
    assert_eq!(
        client.execute(Action::NetworkChanged).await.unwrap()["rebound_transports"],
        1
    );
    assert_ne!(port(&configs[1]).await, prior_port);
    // This is fresh traffic on the successor, not delayed delivery from the
    // original channel. The real customer policy handles all onward purchases.
    let reports = duplex(configs, npubs, 77, 1024 * 1024, 15).await;
    assert_delivery(&reports, 1024 * 1024);
    let after = client.execute(Action::Status).await.unwrap();
    assert_eq!(after["profile"], before["profile"]);
    assert_eq!(after["relay"]["npub"], before["relay"]["npub"]);
    assert_eq!(after["relay"]["purchases"], successor["purchases"]);
    assert_eq!(
        after["relay"]["funding_budget"],
        successor["funding_budget"]
    );
    let progress = &after["relay"]["payment_progress"][next];
    for field in ["evidence_msat", "authorized_sat", "acknowledged_msat"] {
        let previous = successor["payment_progress"][next][field]
            .as_u64()
            .unwrap_or(0);
        assert!(
            progress[field].as_u64().unwrap() > previous,
            "successor {field} must advance during fresh transit"
        );
    }
    let ledger: Value = serde_json::from_slice(
        &std::fs::read(configs[2].state_directory.join("seller/ledger.json")).unwrap(),
    )
    .unwrap();
    let sale = ledger["ledger"]["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sale| sale["terms"]["id"] == next)
        .unwrap();
    assert!(sale["usage"]["submitted_msat"].as_u64().unwrap() > 0);
    assert_eq!(sale["usage"]["paid_msat"], progress["acknowledged_msat"]);
    assert_eq!(journal(&configs[1])["funding"], retained["funding"]);
    assert_held(configs, original);
    assert!(!release.is_closed());
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let state = journal(&configs[1]);
            if state["renewals"][original]["completed"] == true {
                assert_eq!(state["buyer_settlements"][original]["refunded"], true);
                assert_eq!(state["funding"], retained["funding"]);
                assert_eq!(state["renewals"].as_object().unwrap().len(), 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("original close must refund and finish exactly one renewal");
    // Orderly pause drains active renewals, so release the held close first.
    for config in configs {
        request(config, &AdminRequest::PauseRenewals).await.unwrap();
    }
    let closed = status(&configs[1]).await;
    assert_eq!(closed["purchases"], successor["purchases"]);
    assert_eq!(closed["funding_budget"]["locked_sat"], 32);
    assert_eq!(closed["funding_budget"]["wallet_debited_sat"], 64);
    assert!(
        closed["funding_budget"]["wallet_refunded_sat"]
            .as_u64()
            .unwrap()
            > 0
    );
    eprintln!(
        "customer renewed near quote expiry, rebound and paid on its successor while the original committed mint reply remained held"
    );
}
