use super::*;
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_empty_config() {
    let config = Config::new();
    assert!(config.node.identity.nsec.is_none());
    assert!(!config.has_identity());
}

#[test]
fn test_parse_yaml_with_nsec() {
    let yaml = r#"
node:
  identity:
    nsec: nsec1qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxfnm5g9
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.node.identity.nsec.is_some());
    assert!(config.has_identity());
}

#[test]
fn test_parse_yaml_with_hex() {
    let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.node.identity.nsec.is_some());

    let identity = config.create_identity().unwrap();
    assert!(!identity.npub().is_empty());
}

#[test]
fn test_parse_yaml_empty() {
    let yaml = "";
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.node.identity.nsec.is_none());
}

#[test]
fn test_parse_yaml_partial() {
    let yaml = r#"
node:
  identity: {}
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.node.identity.nsec.is_none());
}

#[test]
fn test_merge_configs() {
    let mut base = Config::new();
    base.node.identity.nsec = Some("base_nsec".to_string());

    let mut override_config = Config::new();
    override_config.node.identity.nsec = Some("override_nsec".to_string());

    base.merge(override_config);
    assert_eq!(base.node.identity.nsec, Some("override_nsec".to_string()));
}

#[test]
fn test_merge_preserves_base_when_override_empty() {
    let mut base = Config::new();
    base.node.identity.nsec = Some("base_nsec".to_string());

    let override_config = Config::new();

    base.merge(override_config);
    assert_eq!(base.node.identity.nsec, Some("base_nsec".to_string()));
}

#[test]
fn test_create_identity_from_nsec() {
    let mut config = Config::new();
    config.node.identity.nsec =
        Some("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string());

    let identity = config.create_identity().unwrap();
    assert!(!identity.npub().is_empty());
}

#[test]
fn test_create_identity_generates_new() {
    let config = Config::new();
    let identity = config.create_identity().unwrap();
    assert!(!identity.npub().is_empty());
}

#[test]
fn test_load_from_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");

    let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
    fs::write(&config_path, yaml).unwrap();

    let config = Config::load_file(&config_path).unwrap();
    assert!(config.node.identity.nsec.is_some());
}

#[test]
fn test_load_from_paths_merges() {
    let temp_dir = TempDir::new().unwrap();

    // Create two config files
    let low_priority = temp_dir.path().join("low.yaml");
    let high_priority = temp_dir.path().join("high.yaml");

    fs::write(
        &low_priority,
        r#"
node:
  identity:
    nsec: "low_priority_nsec"
"#,
    )
    .unwrap();

    fs::write(
        &high_priority,
        r#"
node:
  identity:
    nsec: "high_priority_nsec"
"#,
    )
    .unwrap();

    let paths = vec![low_priority.clone(), high_priority.clone()];
    let (config, loaded) = Config::load_from_paths(&paths).unwrap();

    assert_eq!(loaded.len(), 2);
    assert_eq!(
        config.node.identity.nsec,
        Some("high_priority_nsec".to_string())
    );
}

#[test]
fn test_load_from_paths_deep_merges_partial_node_sections() {
    let temp_dir = TempDir::new().unwrap();
    let low_priority = temp_dir.path().join("low.yaml");
    let high_priority = temp_dir.path().join("high.yaml");

    fs::write(
        &low_priority,
        r#"
node:
  limits:
    max_peers: 4096
  routing:
    learned_ttl_secs: 120
    max_learned_routes_per_dest: 2
"#,
    )
    .unwrap();

    fs::write(
        &high_priority,
        r#"
node:
  identity:
    nsec: "high_priority_nsec"
  routing:
    learned_fallback_explore_interval: 8
"#,
    )
    .unwrap();

    let (config, loaded) =
        Config::load_from_paths(&[low_priority.clone(), high_priority.clone()]).unwrap();

    assert_eq!(loaded, vec![low_priority, high_priority]);
    assert_eq!(config.node.limits.max_peers, 4096);
    assert_eq!(config.node.routing.learned_ttl_secs, 120);
    assert_eq!(config.node.routing.max_learned_routes_per_dest, 2);
    assert_eq!(config.node.routing.learned_fallback_explore_interval, 8);
    assert_eq!(
        config.node.identity.nsec,
        Some("high_priority_nsec".to_string())
    );
}

#[test]
fn test_load_skips_missing_files() {
    let temp_dir = TempDir::new().unwrap();
    let existing = temp_dir.path().join("exists.yaml");
    let missing = temp_dir.path().join("missing.yaml");

    fs::write(
        &existing,
        r#"
node:
  identity:
    nsec: "existing_nsec"
"#,
    )
    .unwrap();

    let paths = vec![missing, existing.clone()];
    let (config, loaded) = Config::load_from_paths(&paths).unwrap();

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0], existing);
    assert_eq!(config.node.identity.nsec, Some("existing_nsec".to_string()));
}

#[test]
fn test_search_paths_includes_expected() {
    let paths = Config::search_paths();

    // Should include current directory
    assert!(paths.iter().any(|p| p.ends_with("fips.yaml")));

    // Should include /etc/fips on Unix
    #[cfg(unix)]
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with("/etc/fips") && p.ends_with("fips.yaml"))
    );
}

#[test]
fn test_to_yaml() {
    let mut config = Config::new();
    config.node.identity.nsec = Some("test_nsec".to_string());

    let yaml = config.to_yaml().unwrap();
    assert!(yaml.contains("node:"));
    assert!(yaml.contains("identity:"));
    assert!(yaml.contains("nsec:"));
    assert!(yaml.contains("test_nsec"));
}

#[test]
fn test_key_file_write_read_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    let identity = crate::Identity::generate();
    let nsec = crate::encode_nsec(&identity.keypair().secret_key());

    write_key_file(&key_path, &nsec).unwrap();

    let loaded_nsec = read_key_file(&key_path).unwrap();
    assert_eq!(loaded_nsec, nsec);

    // Verify the loaded nsec produces the same identity
    let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
    assert_eq!(loaded_identity.npub(), identity.npub());
}

#[cfg(unix)]
#[test]
fn test_key_file_permissions() {
    use std::os::unix::fs::MetadataExt;

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    write_key_file(&key_path, "nsec1test").unwrap();

    let metadata = fs::metadata(&key_path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn test_key_file_permissions_are_tightened_on_overwrite() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");
    fs::write(&key_path, "old\n").unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

    write_key_file(&key_path, "nsec1test").unwrap();

    let metadata = fs::metadata(&key_path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(read_key_file(&key_path).unwrap(), "nsec1test");
}

#[cfg(unix)]
#[test]
fn test_pub_file_permissions() {
    use std::os::unix::fs::MetadataExt;

    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("fips.pub");

    write_pub_file(&pub_path, "npub1test").unwrap();

    let metadata = fs::metadata(&pub_path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o644);
}

#[test]
fn test_key_file_empty_error() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    fs::write(&key_path, "").unwrap();

    let result = read_key_file(&key_path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("empty"));
}

#[test]
fn test_key_file_whitespace_trimmed() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    fs::write(&key_path, "  nsec1test  \n").unwrap();

    let nsec = read_key_file(&key_path).unwrap();
    assert_eq!(nsec, "nsec1test");
}

#[test]
fn test_key_file_path_derivation() {
    let config_path = PathBuf::from("/etc/fips/fips.yaml");
    assert_eq!(
        key_file_path(&config_path),
        PathBuf::from("/etc/fips/fips.key")
    );
    assert_eq!(
        pub_file_path(&config_path),
        PathBuf::from("/etc/fips/fips.pub")
    );
}

#[cfg(windows)]
#[test]
fn test_key_file_write_read_roundtrip_windows() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    let identity = crate::Identity::generate();
    let nsec = crate::encode_nsec(&identity.keypair().secret_key());

    write_key_file(&key_path, &nsec).unwrap();

    // Verify file was created and can be read back
    let loaded_nsec = read_key_file(&key_path).unwrap();
    assert_eq!(loaded_nsec, nsec);

    // Verify the loaded nsec produces the same identity
    let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
    assert_eq!(loaded_identity.npub(), identity.npub());
}

#[test]
fn test_resolve_identity_from_config() {
    let mut config = Config::new();
    config.node.identity.nsec =
        Some("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string());

    let resolved = resolve_identity(&config, &[]).unwrap();
    assert!(matches!(resolved.source, IdentitySource::Config));
}

#[test]
fn test_resolve_identity_ephemeral_by_default() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");

    fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

    let config = Config::load_file(&config_path).unwrap();
    assert!(!config.node.identity.persistent);

    let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    assert!(matches!(resolved.source, IdentitySource::Ephemeral));

    // Key files should still be written for operator visibility
    let key_path = temp_dir.path().join("fips.key");
    let pub_path = temp_dir.path().join("fips.pub");
    assert!(key_path.exists());
    assert!(pub_path.exists());
}

#[test]
fn test_resolve_identity_ephemeral_changes_each_call() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");

    fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

    let config = Config::load_file(&config_path).unwrap();
    let first = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    let second = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

    // Each call generates a different key
    assert_ne!(first.nsec, second.nsec);
}

#[test]
fn test_resolve_identity_persistent_from_key_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");
    let key_path = temp_dir.path().join("fips.key");

    fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

    // Write a key file
    let identity = crate::Identity::generate();
    let nsec = crate::encode_nsec(&identity.keypair().secret_key());
    write_key_file(&key_path, &nsec).unwrap();

    let config = Config::load_file(&config_path).unwrap();
    assert!(config.node.identity.persistent);

    let resolved = resolve_identity(&config, &[config_path]).unwrap();
    assert!(matches!(resolved.source, IdentitySource::KeyFile(_)));
    assert_eq!(resolved.nsec, nsec);
}

#[test]
fn test_resolve_identity_persistent_generates_and_persists() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");

    fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

    let config = Config::load_file(&config_path).unwrap();
    let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

    assert!(matches!(resolved.source, IdentitySource::Generated(_)));

    // Key file and pub file should now exist
    let key_path = temp_dir.path().join("fips.key");
    let pub_path = temp_dir.path().join("fips.pub");
    assert!(key_path.exists());
    assert!(pub_path.exists());

    // Second resolve should load from key file (not generate new)
    let resolved2 = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    assert!(matches!(resolved2.source, IdentitySource::KeyFile(_)));
    assert_eq!(resolved.nsec, resolved2.nsec);
}

#[test]
fn test_to_yaml_empty_nsec_omitted() {
    let config = Config::new();
    let yaml = config.to_yaml().unwrap();

    // Empty nsec should not be serialized
    assert!(!yaml.contains("nsec:"));
}

#[test]
fn test_parse_transport_single_instance() {
    let yaml = r#"
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    mtu: 1400
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.transports.udp.len(), 1);
    let instances: Vec<_> = config.transports.udp.iter().collect();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].0, None); // Single instance has no name
    assert_eq!(instances[0].1.bind_addr(), "0.0.0.0:2121");
    assert_eq!(instances[0].1.mtu(), 1400);
}

#[test]
fn test_parse_transport_named_instances() {
    let yaml = r#"
transports:
  udp:
    main:
      bind_addr: "0.0.0.0:2121"
    backup:
      bind_addr: "192.168.1.100:2122"
      mtu: 1280
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.transports.udp.len(), 2);

    let instances: std::collections::HashMap<_, _> = config.transports.udp.iter().collect();

    // Named instances have Some(name)
    assert!(instances.contains_key(&Some("main")));
    assert!(instances.contains_key(&Some("backup")));
    assert_eq!(instances[&Some("main")].bind_addr(), "0.0.0.0:2121");
    assert_eq!(instances[&Some("backup")].bind_addr(), "192.168.1.100:2122");
    assert_eq!(instances[&Some("backup")].mtu(), 1280);
}

#[test]
fn test_parse_transport_empty() {
    let yaml = r#"
transports: {}
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.transports.udp.is_empty());
    assert!(config.transports.is_empty());
}

#[test]
fn test_transport_instances_iter() {
    // Single instance - no name
    let single = TransportInstances::Single(UdpConfig {
        bind_addr: Some("0.0.0.0:2121".to_string()),
        mtu: None,
        ..Default::default()
    });
    let items: Vec<_> = single.iter().collect();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].0, None);

    // Named instances - have names
    let mut map = HashMap::new();
    map.insert("a".to_string(), UdpConfig::default());
    map.insert("b".to_string(), UdpConfig::default());
    let named = TransportInstances::Named(map);
    let items: Vec<_> = named.iter().collect();
    assert_eq!(items.len(), 2);
    // All named instances should have Some(name)
    assert!(items.iter().all(|(name, _)| name.is_some()));
}

#[test]
fn test_parse_peer_config() {
    let yaml = r#"
peers:
  - npub: "npub1abc123"
    alias: "gateway"
    addresses:
      - transport: udp
        addr: "192.168.1.1:2121"
        priority: 1
      - transport: tor
        addr: "xyz.onion:2121"
        priority: 2
    connect_policy: auto_connect
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.peers.len(), 1);
    let peer = &config.peers[0];
    assert_eq!(peer.npub, "npub1abc123");
    assert_eq!(peer.alias, Some("gateway".to_string()));
    assert_eq!(peer.addresses.len(), 2);
    assert!(peer.is_auto_connect());

    // Check addresses are sorted by priority
    let sorted = peer.addresses_by_priority();
    assert_eq!(sorted[0].transport, "udp");
    assert_eq!(sorted[0].priority, 1);
    assert_eq!(sorted[1].transport, "tor");
    assert_eq!(sorted[1].priority, 2);
}

#[test]
fn test_parse_peer_minimal() {
    let yaml = r#"
peers:
  - npub: "npub1xyz"
    addresses:
      - transport: udp
        addr: "10.0.0.1:2121"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.peers.len(), 1);
    let peer = &config.peers[0];
    assert_eq!(peer.npub, "npub1xyz");
    assert!(peer.alias.is_none());
    // Default connect_policy is auto_connect
    assert!(peer.is_auto_connect());
    // Default priority is 100
    assert_eq!(peer.addresses[0].priority, 100);
}

#[test]
fn test_parse_multiple_peers() {
    let yaml = r#"
peers:
  - npub: "npub1peer1"
    addresses:
      - transport: udp
        addr: "10.0.0.1:2121"
  - npub: "npub1peer2"
    addresses:
      - transport: udp
        addr: "10.0.0.2:2121"
    connect_policy: on_demand
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.auto_connect_peers().count(), 1);
}

#[test]
fn test_peer_config_builder() {
    let peer = PeerConfig::new("npub1test", "udp", "192.168.1.1:2121")
        .with_alias("test-peer")
        .with_address(PeerAddress::with_priority("tor", "xyz.onion:2121", 50));

    assert_eq!(peer.npub, "npub1test");
    assert_eq!(peer.alias, Some("test-peer".to_string()));
    assert_eq!(peer.addresses.len(), 2);
    assert!(peer.is_auto_connect());
}

#[test]
fn test_parse_nostr_discovery_config() {
    let yaml = r#"
node:
  discovery:
    nostr:
      enabled: true
      advertise: false
      peerfinding_source: external
      policy: configured_only
      open_discovery_max_pending: 12
      app: "fips.nat.test.v1"
      signal_ttl_secs: 45
      advert_relays:
        - "wss://relay-a.example"
      stun_servers:
        - "stun:stun.example.org:3478"
peers:
  - npub: "npub1peer"
    addresses:
      - transport: udp
        addr: "nat"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.node.discovery.nostr.enabled);
    assert!(!config.node.discovery.nostr.advertise);
    assert_eq!(
        config.node.discovery.nostr.peerfinding_source,
        NostrPeerfindingSource::External
    );
    assert_eq!(config.node.discovery.nostr.app, "fips.nat.test.v1");
    assert_eq!(config.node.discovery.nostr.signal_ttl_secs, 45);
    assert_eq!(
        config.node.discovery.nostr.policy,
        NostrDiscoveryPolicy::ConfiguredOnly
    );
    assert_eq!(config.node.discovery.nostr.open_discovery_max_pending, 12);
    assert_eq!(
        config.node.discovery.nostr.advert_relays,
        vec!["wss://relay-a.example".to_string()]
    );
    assert_eq!(
        config.node.discovery.nostr.stun_servers,
        vec!["stun:stun.example.org:3478".to_string()]
    );
    assert_eq!(
        config.peers[0].addresses[0].addr, "nat",
        "udp:nat address should parse without special-casing in YAML"
    );
}

#[test]
fn test_validate_transport_advert_requires_nostr_enabled() {
    let mut config = Config::default();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        advertise_on_nostr: Some(true),
        ..Default::default()
    });
    config.node.discovery.nostr.enabled = false;

    let err = config.validate().expect_err("validation should fail");
    assert!(err.to_string().contains("advertise_on_nostr"));

    config.transports.udp = TransportInstances::default();
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        advertise_on_nostr: Some(true),
        ..Default::default()
    });

    let err = config.validate().expect_err("validation should fail");
    assert!(err.to_string().contains("advertise_on_nostr"));
}

#[test]
fn test_validate_empty_peer_addresses_require_nostr_enabled() {
    let mut config = Config {
        peers: vec![PeerConfig {
            npub: "npub1peer".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    config.node.discovery.nostr.enabled = false;

    let err = config.validate().expect_err("validation should fail");
    assert!(err.to_string().contains("node.discovery.nostr"));
}

#[test]
fn test_validate_peer_addresses_optional_with_nostr_enabled() {
    // Empty addresses + Nostr discovery disabled -> error.
    let mut config = Config {
        peers: vec![PeerConfig {
            npub: "npub1peer".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = config.validate().expect_err("validation should fail");
    assert!(err.to_string().contains("at least one address"));

    // Empty addresses + Nostr discovery enabled -> ok.
    config.node.discovery.nostr.enabled = true;
    config
        .validate()
        .expect("Nostr discovery should allow empty addresses");
}

#[test]
fn test_validate_nat_udp_advert_requires_stun() {
    let mut config = Config::default();
    config.node.discovery.nostr.enabled = true;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        advertise_on_nostr: Some(true),
        public: Some(false),
        ..Default::default()
    });

    config.node.discovery.nostr.stun_servers.clear();
    let err = config.validate().expect_err("validation should fail");
    assert!(err.to_string().contains("stun_servers"));
}

#[test]
fn test_webrtc_advert_uses_fips_session_signaling_without_relay_config() {
    let mut config = Config::default();
    config.node.discovery.nostr.enabled = true;
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        advertise_on_nostr: Some(true),
        ..Default::default()
    });

    config
        .validate()
        .expect("WebRTC signaling should not require a relay set");
}

#[test]
fn webrtc_inbound_acceptance_follows_advertisement_unless_explicit() {
    let mut config = WebRtcConfig::default();
    assert!(!config.accept_connections());

    config.advertise_on_nostr = Some(true);
    assert!(config.accept_connections());

    config.accept_connections = Some(false);
    assert!(!config.accept_connections());
}

#[test]
fn webrtc_mdns_candidate_resolution_defaults_on_and_can_be_disabled() {
    assert!(WebRtcConfig::default().resolve_mdns_candidates());

    let config: WebRtcConfig =
        serde_yaml::from_str("resolve_mdns_candidates: false\n").expect("WebRTC mDNS config");
    assert!(!config.resolve_mdns_candidates());
    assert_eq!(config.resolve_mdns_candidates, Some(false));
}

#[test]
fn deprecated_dm_and_webrtc_signal_relay_fields_are_rejected() {
    let dm_error = serde_yaml::from_str::<Config>(
        "node:\n  discovery:\n    nostr:\n      dm_relays: [wss://relay.example]\n",
    )
    .expect_err("dm_relays should no longer be a configuration concept");
    assert!(dm_error.to_string().contains("dm_relays"));

    let signal_error =
        serde_yaml::from_str::<WebRtcConfig>("signal_relays: [wss://relay.example]\n")
            .expect_err("WebRTC signal_relays should no longer be configurable");
    assert!(signal_error.to_string().contains("signal_relays"));
}
