use super::*;

#[test]
fn test_ecn_config_defaults() {
    let c = EcnConfig::default();
    assert!(c.enabled);
    assert!((c.loss_threshold - 0.05).abs() < 1e-9);
    assert!((c.etx_threshold - 3.0).abs() < 1e-9);
}

#[test]
fn test_rekey_config_defaults() {
    let c = RekeyConfig::default();
    assert!(c.enabled);
    assert_eq!(c.after_secs, 120);
    assert_eq!(c.after_messages, 1 << 48);
}

#[test]
fn test_rekey_config_partial_yaml_uses_defaults() {
    let yaml = "after_secs: 30\n";
    let c: RekeyConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(c.enabled);
    assert_eq!(c.after_secs, 30);
    assert_eq!(c.after_messages, 1 << 48);
}

#[test]
fn test_connected_udp_config_defaults() {
    let c = ConnectedUdpConfig::default();
    #[cfg(target_os = "macos")]
    assert!(!c.enabled);
    #[cfg(not(target_os = "macos"))]
    assert!(c.enabled);
    assert_eq!(c.max_peers, 0);
    assert_eq!(c.fd_reserve, 128);
}

#[test]
fn test_connected_udp_config_yaml() {
    let yaml = "enabled: false\nmax_peers: 32\nfd_reserve: 4096\n";
    let c: ConnectedUdpConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(!c.enabled);
    assert_eq!(c.max_peers, 32);
    assert_eq!(c.fd_reserve, 4096);
}

#[test]
fn test_routing_config_defaults() {
    let c = RoutingConfig::default();
    assert_eq!(c.mode, RoutingMode::Tree);
    assert_eq!(c.learned_ttl_secs, 300);
    assert_eq!(c.max_learned_routes_per_dest, 4);
    assert_eq!(c.learned_fallback_explore_interval, 16);
}

#[test]
fn test_routing_config_yaml() {
    let yaml = "mode: reply_learned\nlearned_ttl_secs: 120\nmax_learned_routes_per_dest: 2\nlearned_fallback_explore_interval: 8\n";
    let c: RoutingConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(c.mode, RoutingMode::ReplyLearned);
    assert_eq!(c.learned_ttl_secs, 120);
    assert_eq!(c.max_learned_routes_per_dest, 2);
    assert_eq!(c.learned_fallback_explore_interval, 8);
}

#[test]
fn test_ecn_config_yaml_roundtrip() {
    let yaml = "loss_threshold: 0.10\netx_threshold: 2.5\nenabled: false\n";
    let c: EcnConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(!c.enabled);
    assert!((c.loss_threshold - 0.10).abs() < 1e-9);
    assert!((c.etx_threshold - 2.5).abs() < 1e-9);
}

#[test]
fn test_ecn_config_partial_yaml() {
    // Only specify loss_threshold — others should get defaults
    let yaml = "loss_threshold: 0.02\n";
    let c: EcnConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(c.enabled); // default
    assert!((c.loss_threshold - 0.02).abs() < 1e-9);
    assert!((c.etx_threshold - 3.0).abs() < 1e-9); // default
}

#[test]
fn test_nostr_discovery_startup_sweep_defaults() {
    let c = NostrDiscoveryConfig::default();
    assert_eq!(c.startup_sweep_delay_secs, 5);
    assert_eq!(c.startup_sweep_max_age_secs, 3_600);
}

#[test]
fn test_nostr_discovery_startup_sweep_yaml_override() {
    let yaml = "enabled: true\npolicy: open\nstartup_sweep_delay_secs: 10\nstartup_sweep_max_age_secs: 1800\n";
    let c: NostrDiscoveryConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(c.enabled);
    assert_eq!(c.policy, NostrDiscoveryPolicy::Open);
    assert_eq!(c.startup_sweep_delay_secs, 10);
    assert_eq!(c.startup_sweep_max_age_secs, 1_800);
}

#[test]
fn test_nostr_discovery_startup_sweep_partial_yaml_uses_defaults() {
    // Only override delay; max_age should fall back to default.
    let yaml = "enabled: true\nstartup_sweep_delay_secs: 30\n";
    let c: NostrDiscoveryConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(c.startup_sweep_delay_secs, 30);
    assert_eq!(c.startup_sweep_max_age_secs, 3_600);
}

#[test]
fn test_log_level_parser() {
    // Pin the observed behavior of NodeConfig::log_level():
    // - 5 explicit lowercased match arms (trace/debug/warn|warning/error)
    // - INFO is the default (no explicit "info" arm; falls through default)
    // - Case-insensitive via .to_lowercase()
    // - Unknown strings and None both fall through to INFO
    let cases: &[(Option<&str>, tracing::Level)] = &[
        // Explicit arms (lowercase canonical form)
        (Some("trace"), tracing::Level::TRACE),
        (Some("debug"), tracing::Level::DEBUG),
        (Some("warn"), tracing::Level::WARN),
        (Some("warning"), tracing::Level::WARN),
        (Some("error"), tracing::Level::ERROR),
        // "info" has no explicit arm — falls through default
        (Some("info"), tracing::Level::INFO),
        // None → default INFO
        (None, tracing::Level::INFO),
        // Case-insensitivity (parser lowercases via .to_lowercase())
        (Some("TRACE"), tracing::Level::TRACE),
        (Some("Debug"), tracing::Level::DEBUG),
        (Some("Warning"), tracing::Level::WARN),
        (Some("WARN"), tracing::Level::WARN),
        (Some("ERROR"), tracing::Level::ERROR),
        (Some("INFO"), tracing::Level::INFO),
        // Unknown strings → INFO default (no error path)
        (Some("verbose"), tracing::Level::INFO),
        (Some("nonsense"), tracing::Level::INFO),
        (Some(""), tracing::Level::INFO),
    ];

    for (input, expected) in cases {
        let cfg = NodeConfig {
            log_level: input.map(|s| s.to_string()),
            ..NodeConfig::default()
        };
        assert_eq!(
            cfg.log_level(),
            *expected,
            "input {:?} should map to {:?}",
            input,
            expected
        );
    }
}

#[cfg(windows)]
#[test]
fn test_default_socket_path_windows() {
    let config = ControlConfig::default();
    // On Windows, socket_path is a TCP port number
    let port: u16 = config
        .socket_path
        .parse()
        .expect("should be a valid port number");
    assert_eq!(port, 21210);
}
