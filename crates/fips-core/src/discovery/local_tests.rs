use super::*;
use crate::config::TransportInstances;
use crate::{Config, FipsEndpoint, UdpConfig};

fn config_for(dir: &Path) -> LocalInstanceDiscoveryConfig {
    LocalInstanceDiscoveryConfig {
        enabled: true,
        dir: Some(dir.to_string_lossy().to_string()),
        ..LocalInstanceDiscoveryConfig::default()
    }
}

#[test]
fn same_host_scope_does_not_replace_lan_scope() {
    let mut config = Config::new();
    config.node.discovery.local.scope = Some("iris-local-v1".to_string());
    config.node.discovery.lan.scope = Some("nostr-vpn:private-network".to_string());

    assert_eq!(
        local_discovery_scope(&config).as_deref(),
        Some("iris-local-v1")
    );
    assert_eq!(
        lan_discovery_scope(&config).as_deref(),
        Some("nostr-vpn:private-network")
    );
}

fn record(npub: &str, scope: &str, pid: u32, updated_at_ms: u64) -> LocalInstanceRecord {
    LocalInstanceRecord {
        version: LOCAL_INSTANCE_RECORD_VERSION,
        npub: npub.to_string(),
        discovery_scope: scope.to_string(),
        pid,
        started_at_ms: 1,
        updated_at_ms,
        contacts: vec![LocalInstanceContact {
            transport: "udp".to_string(),
            addr: "127.0.0.1:22121".to_string(),
        }],
    }
}

fn capability(name: &str, fsp_port: Option<u16>) -> LocalInstanceCapability {
    match fsp_port {
        Some(port) => LocalInstanceCapability::service(name, port),
        None => LocalInstanceCapability::role(name),
    }
}

#[test]
fn wildcard_ipv4_contact_uses_loopback() {
    let contact =
        contact_for_transport_addr("udp", "0.0.0.0:22121".parse().unwrap()).expect("contact");

    assert_eq!(contact.transport, "udp");
    assert_eq!(contact.addr, "127.0.0.1:22121");
}

#[test]
fn wildcard_ipv6_contact_uses_loopback() {
    let contact =
        contact_for_transport_addr("udp", "[::]:22121".parse().unwrap()).expect("contact");

    assert_eq!(contact.addr, "[::1]:22121");
}

#[test]
fn publish_and_remove_record() {
    let temp = tempfile::tempdir().unwrap();
    let registry =
        LocalInstanceRegistry::new("npub-self", "scope-a", &config_for(temp.path()), 100).unwrap();

    registry
        .publish(
            vec![LocalInstanceContact {
                transport: "udp".to_string(),
                addr: "127.0.0.1:22121".to_string(),
            }],
            200,
        )
        .unwrap();

    let text = fs::read_to_string(&registry.record_path).unwrap();
    let parsed: LocalInstanceRecord = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed.npub, "npub-self");
    assert_eq!(parsed.discovery_scope, "scope-a");
    assert_eq!(parsed.updated_at_ms, 200);

    registry.remove().unwrap();
    assert!(!registry.record_path.exists());
}

#[test]
fn capability_advert_preserves_v1_instance_discovery() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_for(temp.path());
    let provider =
        LocalInstanceRegistry::new("npub-provider", "iris-local-v1", &config, 100).unwrap();
    let contacts = vec![LocalInstanceContact {
        transport: "udp".to_string(),
        addr: "127.0.0.1:49152".to_string(),
    }];

    provider
        .publish_with_capabilities(
            contacts,
            vec![
                capability("hashtree.blob/1", Some(39_018)),
                capability("nostr.pubsub/1", Some(7_368)),
                LocalInstanceCapability::role("fips.egress/1").with_priority(100),
            ],
            200,
        )
        .unwrap();

    // The registry keeps emitting the immutable v1 shape so released
    // FIPS readers with deny_unknown_fields still discover this peer.
    let v1_text = fs::read_to_string(&provider.record_path).unwrap();
    assert!(!v1_text.contains("capabilities"));
    let v1: LocalInstanceRecord = serde_json::from_str(&v1_text).unwrap();
    assert_eq!(v1.version, LOCAL_INSTANCE_RECORD_VERSION);

    let consumer =
        LocalInstanceRegistry::new("npub-consumer", "iris-local-v1", &config, 150).unwrap();
    let legacy_records = consumer.scan(250, 1_000).unwrap();
    assert_eq!(legacy_records.len(), 1);
    assert_eq!(legacy_records[0].npub, "npub-provider");

    let adverts = consumer.scan_advertisements(250, 1_000).unwrap();
    assert_eq!(adverts.len(), 1);
    assert_eq!(adverts[0].instance.npub, "npub-provider");
    assert_eq!(
        provider.scan_advertisements(250, 1_000).unwrap()[0]
            .instance
            .npub,
        "npub-provider",
        "provider election must include the local instance"
    );
    assert_eq!(
        adverts[0].capabilities,
        vec![
            capability("hashtree.blob/1", Some(39_018)),
            capability("nostr.pubsub/1", Some(7_368)),
            LocalInstanceCapability::role("fips.egress/1").with_priority(100),
        ]
    );

    // A v1 heartbeat may be renamed just before the unchanged v2 file.
    // Matching the stable instance ID keeps capabilities continuously
    // visible through that harmless update window.
    let mut refreshed_v1 = v1;
    refreshed_v1.updated_at_ms = 201;
    write_private_json(&provider.record_path, &refreshed_v1, provider.pid).unwrap();
    let adverts = consumer.scan_advertisements(250, 1_000).unwrap();
    assert_eq!(adverts[0].capabilities.len(), 3);

    provider.remove().unwrap();
    assert!(!provider.record_path.exists());
    assert!(!provider.advertisement_path.exists());
    assert!(consumer.scan_advertisements(300, 1_000).unwrap().is_empty());
}

#[test]
fn scan_ignores_orphaned_capability_advert_without_deleting_files() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_for(temp.path());
    let provider =
        LocalInstanceRegistry::new("npub-provider", "iris-local-v1", &config, 100).unwrap();
    provider
        .publish_with_capabilities(
            vec![LocalInstanceContact {
                transport: "udp".to_string(),
                addr: "127.0.0.1:49152".to_string(),
            }],
            vec![capability("hashtree.blob/1", Some(39_018))],
            200,
        )
        .unwrap();
    fs::remove_file(&provider.record_path).unwrap();
    assert!(provider.advertisement_path.exists());

    let consumer =
        LocalInstanceRegistry::new("npub-consumer", "iris-local-v1", &config, 150).unwrap();
    assert!(consumer.scan_advertisements(250, 1_000).unwrap().is_empty());
    assert!(
        provider.advertisement_path.exists(),
        "read-only scans must not race and delete a fresh publication"
    );
}

#[test]
fn capability_provider_selection_fails_over_after_withdrawal() {
    let temp = tempfile::tempdir().unwrap();
    let config = config_for(temp.path());
    let contacts = || {
        vec![LocalInstanceContact {
            transport: "udp".to_string(),
            addr: "127.0.0.1:49152".to_string(),
        }]
    };
    let low = LocalInstanceRegistry::new("npub-low", "iris-local-v1", &config, 100).unwrap();
    let high = LocalInstanceRegistry::new("npub-high", "iris-local-v1", &config, 100).unwrap();
    low.publish_with_capabilities(
        contacts(),
        vec![LocalInstanceCapability::role("fips.egress/1").with_priority(10)],
        200,
    )
    .unwrap();
    high.publish_with_capabilities(
        contacts(),
        vec![LocalInstanceCapability::role("fips.egress/1").with_priority(20)],
        200,
    )
    .unwrap();

    let consumer =
        LocalInstanceRegistry::new("npub-consumer", "iris-local-v1", &config, 150).unwrap();
    let adverts = consumer.scan_advertisements(250, 1_000).unwrap();
    assert_eq!(
        rank_capability_providers(&adverts, "fips.egress/1")
            .into_iter()
            .map(|advert| advert.instance.npub.as_str())
            .collect::<Vec<_>>(),
        vec!["npub-high", "npub-low"]
    );
    assert_eq!(
        select_capability_provider(&adverts, "fips.egress/1")
            .unwrap()
            .instance
            .npub,
        "npub-high"
    );

    high.publish_with_capabilities(contacts(), Vec::new(), 300)
        .unwrap();
    let adverts = consumer.scan_advertisements(300, 1_000).unwrap();
    assert_eq!(
        select_capability_provider(&adverts, "fips.egress/1")
            .unwrap()
            .instance
            .npub,
        "npub-low"
    );
    assert_eq!(consumer.scan(300, 1_000).unwrap().len(), 2);
}

#[tokio::test]
async fn endpoint_heartbeat_publishes_runtime_capabilities() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = Config::new();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    config.node.discovery.lan.scope = Some("iris-local-v1".to_string());
    config.node.discovery.local = config_for(temp.path());

    let endpoint = FipsEndpoint::builder()
        .config(config.clone())
        .discovery_scope("iris-local-v1")
        .local_role("fips.egress/1", 100)
        .without_system_tun()
        .bind()
        .await
        .expect("provider endpoint should bind");
    let consumer = LocalInstanceRegistry::new(
        "npub-consumer",
        "iris-local-v1",
        &config.node.discovery.local,
        1,
    )
    .unwrap();
    let adverts = consumer
        .scan_advertisements(u64::MAX / 2, u64::MAX)
        .unwrap();

    assert_eq!(adverts.len(), 1);
    assert_eq!(adverts[0].instance.npub, endpoint.npub());
    assert_eq!(
        adverts[0].capabilities,
        vec![LocalInstanceCapability::role("fips.egress/1").with_priority(100)]
    );

    let service = endpoint
        .register_service_receiver_with_capability(LocalInstanceCapability::service(
            "hashtree.blob/1",
            39_018,
        ))
        .await
        .expect("Hashtree service should register");
    let adverts = consumer
        .scan_advertisements(u64::MAX / 2, u64::MAX)
        .unwrap();
    assert_eq!(
        adverts[0].capabilities,
        vec![
            LocalInstanceCapability::role("fips.egress/1").with_priority(100),
            LocalInstanceCapability::service("hashtree.blob/1", 39_018),
        ]
    );

    drop(service);
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let adverts = consumer
                .scan_advertisements(u64::MAX / 2, u64::MAX)
                .unwrap();
            if adverts
                .first()
                .and_then(|advert| advert.capability("hashtree.blob/1"))
                .is_none()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("dropped service must withdraw its capability");
    let _replacement = endpoint
        .register_service_receiver_with_capability(LocalInstanceCapability::service(
            "hashtree.blob/1",
            39_018,
        ))
        .await
        .expect("withdrawn service port should be reusable");

    endpoint
        .shutdown()
        .await
        .expect("provider should shut down");
    assert!(
        consumer
            .scan_advertisements(u64::MAX / 2, u64::MAX)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn scan_filters_self_scope_and_stale_records() {
    let temp = tempfile::tempdir().unwrap();
    let registry =
        LocalInstanceRegistry::new("npub-self", "scope-a", &config_for(temp.path()), 100).unwrap();
    ensure_private_dir(temp.path()).unwrap();

    let cases = [
        record("npub-peer", "scope-a", 2, 900),
        record("npub-self", "scope-a", registry.pid, 900),
        record("npub-other-scope", "scope-b", 3, 900),
        record("npub-stale", "scope-a", 4, 100),
    ];
    for (index, record) in cases.iter().enumerate() {
        let path = temp.path().join(format!("{index}.json"));
        fs::write(path, serde_json::to_vec(record).unwrap()).unwrap();
    }

    let records = registry.scan(1000, 500).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].npub, "npub-peer");
}
