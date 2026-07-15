use super::*;
use std::collections::HashMap;

#[test]
fn resolved_ice_fanout_rejects_unsafe_webrtc_capacity() {
    let mut config = Config::default();
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(9),
        ..WebRtcConfig::default()
    });
    let error = config
        .validate()
        .expect_err("three STUN URLs cap capacity at eight");
    assert!(error.to_string().contains("maximum is 8"));

    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(8),
        ..WebRtcConfig::default()
    });
    config
        .validate()
        .expect("eight default-STUN PCs fit the configured socket budget");

    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(16),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    });
    config
        .validate()
        .expect("sixteen host-only PCs fit the configured socket budget");

    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(17),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    });
    assert!(config.validate().is_err());
}

#[test]
fn resolved_ice_url_count_is_bounded_before_transport_creation() {
    let mut config = Config::default();
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(1),
        stun_servers: Some(
            (0..4)
                .map(|index| format!("stun:stun-{index}.example:3478"))
                .collect(),
        ),
        ..WebRtcConfig::default()
    });
    let error = config
        .validate()
        .expect_err("STUN URL fanout above three is rejected");
    assert!(error.to_string().contains("STUN URLs exceed"));
}

#[test]
fn unsupported_turn_urls_are_rejected_before_transport_creation() {
    let mut config = Config::default();
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(1),
        stun_servers: Some(vec!["turn:turn.example:3478".into()]),
        ..WebRtcConfig::default()
    });

    let error = config
        .validate()
        .expect_err("string-only ICE configuration cannot provide TURN credentials");
    assert!(error.to_string().contains("only non-empty `stun:`"));
}

#[cfg(feature = "webrtc-transport")]
#[test]
fn malformed_stun_urls_are_rejected_during_config_validation() {
    let mut config = Config::default();
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        max_connections: Some(1),
        stun_servers: Some(vec!["stun:stun.example:bad".into()]),
        ..WebRtcConfig::default()
    });

    let error = config
        .validate()
        .expect_err("the WebRTC parser should reject malformed STUN syntax");
    assert!(error.to_string().contains("invalid WebRTC STUN URL"));
}

#[test]
fn multiple_webrtc_instances_share_one_configured_socket_budget() {
    let mut config = Config::default();
    config.transports.webrtc = TransportInstances::Named(HashMap::from([
        ("first".into(), WebRtcConfig::default()),
        ("second".into(), WebRtcConfig::default()),
    ]));

    let error = config
        .validate()
        .expect_err("two default WebRTC transports reserve 144 candidate sockets");
    assert!(
        error
            .to_string()
            .contains("configured candidate socket budget")
    );
    assert!(error.to_string().contains("144"));
}
