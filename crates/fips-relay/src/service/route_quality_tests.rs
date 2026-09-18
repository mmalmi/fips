use super::*;
use fips_core::{
    Config, SimLink, SimNetwork,
    config::{SimTransportConfig, TransportInstances},
};

#[test]
fn request_rejects_a_feedback_window_override() {
    let destination = Identity::generate().npub();
    let value = json!({"type": "route_quality", "destination": destination});
    let request: AdminRequest = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(request, AdminRequest::RouteQuality { .. }));
    assert_eq!(serde_json::to_value(request).unwrap(), value);
    let mut extra = value;
    extra["feedback_window_ms"] = json!(1);
    assert!(serde_json::from_value::<AdminRequest>(extra).is_err());
}

async fn endpoint(network: &str, address: &str) -> FipsEndpoint {
    let mut config = Config::new();
    config.node.identity.persistent = false;
    config.node.control.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network.into()),
        addr: Some(address.into()),
        auto_connect: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    });
    FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn unknown_destination_stays_unknown_without_creating_a_peer_or_sending() {
    let name = format!("query-{}", Identity::generate().node_addr());
    fips_core::register_sim_network(name.clone(), SimNetwork::new(54));
    let node = endpoint(&name, "0").await;
    let destination = Identity::generate().npub();
    let report = route_quality(&node, None, &destination).await.unwrap();
    assert_eq!(report["destination"], destination);
    assert!(report["price_selection"].is_null());
    assert_eq!(report["feedback_window_ms"], 15_000);
    assert_eq!(report["quality"]["sent_packets"], 0);
    assert_eq!(report["quality"]["sent_bytes"], 0);
    assert_eq!(report["quality"]["has_recent_delivery_feedback"], false);
    assert_eq!(report["quality"]["delivery_feedback_timed_out"], false);
    for field in ["next_hop", "rtt_ms", "loss_rate", "goodput_bps"] {
        assert!(report["quality"].get(field).unwrap().is_null(), "{field}");
    }
    assert!(node.peers().await.unwrap().is_empty());
    assert_eq!(
        route_quality(&node, None, &destination).await.unwrap(),
        report
    );
    assert_eq!(
        route_quality(&node, None, "invalid").await.unwrap_err(),
        "invalid destination npub"
    );
    node.shutdown().await.unwrap();
    fips_core::unregister_sim_network(&name);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_native_carrier_and_uses_configured_feedback_window() {
    let name = format!("query-{}", Identity::generate().node_addr());
    let carrier = SimNetwork::new(55);
    fips_core::register_sim_network(name.clone(), carrier.clone());
    let source = endpoint(&name, "0").await;
    let destination = endpoint(&name, "1").await;
    let peer = PeerIdentity::from_npub(destination.npub()).unwrap();
    source
        .update_peers(vec![PeerConfig::new(peer.npub(), "sim", "1")])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !source
            .peers()
            .await
            .unwrap()
            .iter()
            .any(|p| p.connected && p.node_addr == *peer.node_addr())
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("native authenticated adjacency");
    let policy = PriceSelectionPolicy {
        feedback_timeout_ms: 1_000,
        ..Default::default()
    };
    let receiver = destination
        .register_service_receiver(DATA_PORT)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut delivered = false;
        loop {
            source
                .send_datagram(peer, DATA_PORT, DATA_PORT, vec![7; 200])
                .await
                .unwrap();
            let mut batch = Vec::new();
            if let Ok(Some(_)) = tokio::time::timeout(
                Duration::from_millis(200),
                receiver.recv_batch_into(&mut batch, 32),
            )
            .await
            {
                delivered |= batch
                    .iter()
                    .any(|packet| packet.data.as_slice() == [7; 200]);
            }
            let report = route_quality(&source, Some(&policy), &peer.npub())
                .await
                .unwrap();
            let quality = &report["quality"];
            if delivered
                && quality["has_recent_delivery_feedback"] == true
                && quality["loss_rate"].is_number()
            {
                assert_eq!(quality["next_hop"], json!(peer.node_addr().as_bytes()));
                assert_eq!(quality["receiver_reports_enabled"], true);
                assert_eq!(quality["delivery_feedback_timed_out"], false);
                assert!(quality["rtt_ms"].as_f64().unwrap() >= 0.0);
                assert_eq!(quality["loss_rate"], 0.0);
                assert!(quality["goodput_bps"].as_f64().unwrap() > 0.0);
                assert_eq!(report["price_selection"], json!(policy));
                assert_eq!(report["feedback_window_ms"], 1_000);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("real delivery and fresh native receiver reports");

    // A new carrier epoch cannot inherit the old feedback. Drop outgoing
    // frames, then compare the same unanswered burst under two real windows.
    carrier.set_directed_link(
        "0",
        "1",
        Some(SimLink {
            up: false,
            ..Default::default()
        }),
    );
    source.set_source_route(peer, Some(peer)).await.unwrap();
    source
        .send_datagram(peer, DATA_PORT, DATA_PORT, vec![8; 200])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let short = route_quality(&source, Some(&policy), &peer.npub())
        .await
        .unwrap();
    let ordinary = route_quality(&source, None, &peer.npub()).await.unwrap();
    assert_eq!(short["quality"]["delivery_feedback_timed_out"], true);
    assert_eq!(ordinary["quality"]["delivery_feedback_timed_out"], false);
    for field in ["rtt_ms", "loss_rate", "goodput_bps"] {
        assert!(short["quality"].get(field).unwrap().is_null(), "{field}");
    }
    for field in ["next_hop", "sent_packets", "sent_bytes"] {
        assert_eq!(
            short["quality"][field], ordinary["quality"][field],
            "query changed {field}"
        );
    }
    source.shutdown().await.unwrap();
    destination.shutdown().await.unwrap();
    fips_core::unregister_sim_network(&name);
}
