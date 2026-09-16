//! Cancel acceptance, then hold a real Seal while another route is requested.
use super::*;

pub(super) async fn exercise(
    controllers: &[Arc<Controller>],
    services: &[ControllerServices],
    peers: &[PeerIdentity],
    gates: &[Option<payment_mobility::Gate>],
    root: &std::path::Path,
) {
    let buyer = &controllers[0];
    let old = buyer.purchases().await.unwrap().remove(0);
    for destination in [peers[2], peers[3]] {
        let offer = services[0].quotes.request_route(destination).await.unwrap();
        assert_eq!(offer.provider, old.provider);
        assert_ne!(*offer.destination.node_addr(), old.contract.destination);
    }
    let gate = gates[1].as_ref().unwrap();
    gate.pause();
    let purchasing = buyer.clone();
    let destination = peers[3];
    let purchase = tokio::spawn(async move { purchasing.buy_route(destination).await });
    assert!(
        gate.held().await,
        "hold the new destination's real Accept request"
    );
    let read = || -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(root.join("controller-0/controller.json")).unwrap())
            .unwrap()
    };
    let waiting = read();
    let pending = waiting["outgoing"]
        .as_object()
        .unwrap()
        .values()
        .find(|o| o["accepted"] == false)
        .unwrap()
        .clone();
    assert_eq!(pending["purchase"]["channel"]["id"], old.channel.id);
    let settling = buyer.clone();
    let id = old.channel.id.clone();
    let close = tokio::spawn(async move { settling.settle_channel(&id).await });
    assert!(
        gate.held().await,
        "Seal proceeds while Accept is still held"
    );
    // Cancel the caller and lose this held RPC before its handler runs. This
    // retains the funded intent until the channel refund is confirmed.
    purchase.abort();
    assert!(purchase.await.unwrap_err().is_cancelled());
    gate.discard_held().await;
    let before = read();
    assert!(!before["buyer_settlements"][&old.channel.id].is_null());
    let requested = tokio::time::timeout(Duration::from_secs(5), buyer.buy_route(peers[2])).await;
    let after = read();
    gate.release();
    tokio::time::timeout(Duration::from_secs(20), close)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        requested.is_ok(),
        "a closing shared channel must reject new purchases promptly"
    );
    assert!(
        requested.unwrap().is_err(),
        "cannot buy on a channel being sealed"
    );
    for field in ["funding", "requested", "outgoing"] {
        assert_eq!(
            after[field], before[field],
            "rejection must not retain a new {field} record"
        );
    }
    let closed = read();
    let id = pending["purchase"]["contract"]["id"].as_str().unwrap();
    assert_eq!(closed["outgoing"][id]["retired"], true);
    assert_eq!(closed["outgoing"][id]["accepted"], false);
    assert_eq!(closed["outgoing"][id]["funding_id"], pending["funding_id"]);
    assert_eq!(closed["funding"], waiting["funding"]);
    assert!(closed["requested"][pending["offer"]["id"].as_str().unwrap()].is_null());
}
