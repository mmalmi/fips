use super::*;

fn advert(
    npub: &str,
    epoch: u8,
    capabilities: Vec<LocalInstanceCapability>,
) -> LocalInstanceAdvertisement {
    LocalInstanceAdvertisement {
        npub: npub.to_string(),
        startup_epoch: [epoch; 8],
        capabilities,
    }
}

#[test]
fn default_config_uses_one_disabled_fixed_loopback_anchor() {
    let config = LocalInstanceDiscoveryConfig::default();

    assert!(!config.enabled);
    assert_eq!(
        config.rendezvous_addr,
        "127.0.0.1:21211".parse::<std::net::SocketAddrV4>().unwrap()
    );
    assert!(config.has_valid_rendezvous_addr());
    assert_eq!(config.retry_interval_ms, 1_000);
}

#[test]
fn config_allows_test_port_but_rejects_obsolete_filesystem_fields() {
    let config: LocalInstanceDiscoveryConfig = serde_json::from_str(
        r#"{"enabled":true,"rendezvous_addr":"127.0.0.1:32112","retry_interval_ms":7}"#,
    )
    .unwrap();

    assert_eq!(config.rendezvous_addr.port(), 32_112);
    assert_eq!(config.retry_interval_ms, 7);
    assert!(
        serde_json::from_str::<LocalInstanceDiscoveryConfig>(
            r#"{"enabled":true,"dir":"/tmp/fips"}"#
        )
        .is_err()
    );

    let mut invalid = config;
    invalid.rendezvous_addr = "0.0.0.0:21211".parse().unwrap();
    assert!(!invalid.has_valid_rendezvous_addr());
}

#[test]
fn directory_clones_share_deterministic_in_memory_snapshots() {
    let directory = LocalCapabilityDirectory::new();
    let clone = directory.clone();
    directory.upsert(advert(
        "npub-z",
        1,
        vec![LocalInstanceCapability::service("hashtree.blob/1", 39_018)],
    ));
    clone.upsert(advert(
        "npub-a",
        2,
        vec![LocalInstanceCapability::service("nostr.pubsub/1", 7_368)],
    ));

    assert_eq!(
        directory
            .snapshot()
            .into_iter()
            .map(|provider| provider.npub)
            .collect::<Vec<_>>(),
        ["npub-a", "npub-z"]
    );
    assert_eq!(clone.snapshot().len(), 2);
}

#[test]
fn replace_is_atomic_and_last_duplicate_identity_wins() {
    let directory = LocalCapabilityDirectory::new();
    directory.upsert(advert("npub-old", 1, Vec::new()));
    directory.replace([
        advert("npub-provider", 1, Vec::new()),
        advert("npub-provider", 2, Vec::new()),
    ]);

    assert_eq!(directory.snapshot().len(), 1);
    assert_eq!(directory.snapshot()[0].startup_epoch, [2; 8]);
}

#[test]
fn service_provider_priority_and_ties_are_deterministic() {
    let service = |priority| {
        LocalInstanceCapability::service("hashtree.blob/1", 39_018).with_priority(priority)
    };
    let adverts = vec![
        advert("npub-z", 1, vec![service(20)]),
        advert("npub-b", 1, vec![service(30)]),
        advert("npub-a", 2, vec![service(30)]),
        advert(
            "npub-unrelated",
            1,
            vec![LocalInstanceCapability::service("nostr.pubsub/1", 7_368)],
        ),
    ];

    assert_eq!(
        rank_capability_providers(&adverts, "hashtree.blob/1")
            .into_iter()
            .map(|provider| provider.npub.as_str())
            .collect::<Vec<_>>(),
        ["npub-a", "npub-b", "npub-z"]
    );
    assert_eq!(
        select_capability_provider(&adverts, "hashtree.blob/1")
            .unwrap()
            .npub,
        "npub-a"
    );
}

#[test]
fn provider_prefers_its_highest_priority_duplicate_capability() {
    let provider = advert(
        "npub-provider",
        1,
        vec![
            LocalInstanceCapability::service("hashtree.blob/1", 40_000).with_priority(1),
            LocalInstanceCapability::service("hashtree.blob/1", 39_018).with_priority(2),
        ],
    );

    assert_eq!(
        provider.capability("hashtree.blob/1").unwrap().fsp_port,
        Some(39_018)
    );
}
