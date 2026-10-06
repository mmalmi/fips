use fips_core::config::{TransportInstances, UdpConfig, WebRtcConfig};
use fips_core::{Config, FipsEndpoint};
use std::time::Duration;

fn config() -> Config {
    let mut config = Config::new();
    config.node.identity.persistent = false;
    config.node.control.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.nostr.advertise = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        ..Default::default()
    });
    config
}

#[tokio::test]
async fn endpoint_transport_stats_are_aggregate_and_include_webrtc_conservation() {
    let mut config = config();
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(1),
        stun_servers: Some(vec![]),
        ..Default::default()
    });
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .unwrap();
    let rows = tokio::time::timeout(Duration::from_secs(1), endpoint.transport_stats())
        .await
        .unwrap()
        .unwrap();
    let rtc = rows.iter().find(|row| row["type"] == "webrtc").unwrap();
    let resources = rtc["stats"]["resources"].as_object().unwrap();
    assert_eq!(resources["capacity"], 1);
    assert_eq!(resources["creating"], 0);
    assert_eq!(resources["active"], 0);
    assert_eq!(resources["closing"], 0);
    assert_eq!(resources["abandoned"], 0);
    assert!(resources.values().all(|value| value.is_u64()));
    let encoded = serde_json::to_string(&rows).unwrap();
    assert!(encoded.len() < 4096);
    for forbidden in [
        "npub",
        "nsec",
        "local_addr",
        "remote_addr",
        "candidate",
        "payload",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    endpoint.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabled_webrtc_does_not_fabricate_zero_capacity() {
    let endpoint = FipsEndpoint::builder()
        .config(config())
        .without_system_tun()
        .bind()
        .await
        .unwrap();
    let rows = endpoint.transport_stats().await.unwrap();
    assert!(rows.iter().any(|row| row["type"] == "udp"));
    assert!(!rows.iter().any(|row| row["type"] == "webrtc"));
    endpoint.shutdown().await.unwrap();
}
