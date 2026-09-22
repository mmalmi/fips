//! Opt-in, non-atomic counters around the unchanged mobile traffic window.
use super::*;

pub(super) async fn capture(bench: &Bench, stage: &str, encounter: Option<u8>) {
    if std::env::var("FIPS_CROWDED_PAYMENTS").as_deref() != Ok("1") {
        return;
    }
    let start = Instant::now();
    let mut nodes = Vec::new();
    for (buyer, controller) in bench.controllers.iter().enumerate() {
        let before_us = start.elapsed().as_micros();
        let progress = controller.payment_progress().await.unwrap();
        let eligible = controller.purchases().await.unwrap();
        let history = controller.purchase_history().await.unwrap();
        assert!(history.len() <= 16, "bounded encounter purchase snapshot");
        let mut channels = BTreeMap::new();
        let mut purchases = Vec::new();
        for purchase in history {
            let seller = bench
                .peers
                .iter()
                .position(|peer| *peer.node_addr() == purchase.provider)
                .unwrap();
            channels
                .entry(purchase.channel.id.clone())
                .or_insert_with(|| {
                    serde_json::json!({
                        "seller": seller,
                        "buyer": progress.get(&purchase.channel.id),
                        "seller_usage": bench.sellers[seller].channel_usage(&purchase.channel.id),
                    })
                });
            let observed = bench.buyers[buyer].observed_units(&purchase.contract.id);
            purchases.push(serde_json::json!({
                "contract": purchase.contract.id,
                "channel": purchase.channel.id,
                "destination": bench.peers.iter().position(|peer| *peer.node_addr() == purchase.contract.destination),
                "eligible": eligible.iter().any(|p| p.contract.id == purchase.contract.id),
                "expires_unix": purchase.contract.expires_unix,
                "observed_units": observed,
                "remaining_units": observed.map(|used| purchase.contract.max_units.saturating_sub(used)),
            }));
        }
        let gate = &bench.gates[buyer];
        nodes.push(serde_json::json!({
            "node": buyer, "query_us": [before_us, start.elapsed().as_micros()],
            "channels": channels, "purchases": purchases,
            "forwarding_refused": gate.refused.load(Ordering::Relaxed),
            "forwarding_dropped": gate.dropped.load(Ordering::Relaxed),
        }));
    }
    eprintln!(
        "crowded payment snapshot: {}",
        serde_json::json!({"stage": stage, "encounter": encounter, "nodes": nodes})
    );
}
