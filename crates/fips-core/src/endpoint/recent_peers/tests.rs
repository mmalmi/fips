use super::*;
use crate::Identity;
use crate::node::NodeEndpointPeer;

fn npub() -> String {
    Identity::generate().npub()
}

fn endpoint_peer(npub: String, transport: &str, addr: &str) -> FipsEndpointPeer {
    NodeEndpointPeer {
        npub,
        node_addr: crate::NodeAddr::from_bytes([7; 16]),
        connected: true,
        transport_addr: Some(addr.to_string()),
        transport_type: Some(transport.to_string()),
        link_id: 1,
        srtt_ms: None,
        srtt_age_ms: None,
        packets_sent: 0,
        packets_recv: 0,
        bytes_sent: 0,
        bytes_recv: 0,
        rekey_in_progress: false,
        rekey_draining: false,
        current_k_bit: None,
        last_outbound_route: None,
        direct_probe_pending: false,
        direct_probe_after_ms: None,
        direct_probe_retry_count: 0,
        direct_probe_auto_reconnect: false,
        direct_probe_expires_at_ms: None,
        nostr_traversal_consecutive_failures: 0,
        nostr_traversal_in_cooldown: false,
        nostr_traversal_cooldown_until_ms: None,
        nostr_traversal_last_observed_skew_ms: None,
    }
    .into()
}

#[test]
fn json_round_trip_is_bound_to_version_identity_and_scope() {
    let local = npub();
    let remote = npub();
    let mut recent = RecentPeers::new(&local, "iris-drive:test").unwrap();
    recent
        .observe_authenticated_peer(
            &endpoint_peer(remote.clone(), "udp", "192.0.2.1:32112"),
            1_000,
        )
        .unwrap();

    let json = recent.to_json().unwrap();
    let value = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<HashSet<_>>(),
        HashSet::from([
            "version".to_string(),
            "local_npub".to_string(),
            "scope".to_string(),
            "peers".to_string(),
        ])
    );
    assert_eq!(
        RecentPeers::from_json(&json, &local, "iris-drive:test").unwrap(),
        recent
    );
    assert!(matches!(
        RecentPeers::from_json(&json, &local, "other"),
        Err(RecentPeersError::ScopeMismatch { .. })
    ));
    assert!(matches!(
        RecentPeers::from_json(&json, &npub(), "iris-drive:test"),
        Err(RecentPeersError::LocalIdentityMismatch { .. })
    ));

    let mut wrong_version = value.clone();
    wrong_version["version"] = 2.into();
    assert!(matches!(
        RecentPeers::from_json(
            &serde_json::to_string(&wrong_version).unwrap(),
            &local,
            "iris-drive:test"
        ),
        Err(RecentPeersError::UnsupportedVersion { actual: 2 })
    ));

    let mut unknown_field = value;
    unknown_field["unexpected"] = true.into();
    assert!(matches!(
        RecentPeers::from_json(
            &serde_json::to_string(&unknown_field).unwrap(),
            &local,
            "iris-drive:test"
        ),
        Err(RecentPeersError::Json(_))
    ));
}

#[test]
fn only_connected_reusable_udp_paths_become_restart_endpoints() {
    let local = npub();
    let remote = npub();
    let mut recent = RecentPeers::new(local, "scope").unwrap();

    assert!(
        recent
            .observe_authenticated_peer(
                &endpoint_peer(remote.clone(), "tcp", "192.0.2.1:443"),
                1_000,
            )
            .unwrap()
    );
    assert!(
        !recent
            .observe_authenticated_peer(
                &endpoint_peer(remote.clone(), "tcp", "192.0.2.1:443"),
                1_000,
            )
            .unwrap(),
        "an identical observation must not report a mutation"
    );
    assert!(recent.peers[&remote].endpoints.is_empty());

    recent
        .observe_authenticated_peer(
            &endpoint_peer(remote.clone(), "websocket", "ws-peer://example/1"),
            2_000,
        )
        .unwrap();
    recent
        .observe_authenticated_peer(
            &endpoint_peer(remote.clone(), "udp", "0.0.0.0:32112"),
            3_000,
        )
        .unwrap();
    assert!(recent.peers[&remote].endpoints.is_empty());

    recent
        .observe_authenticated_peer(
            &endpoint_peer(remote.clone(), "udp", "192.168.1.20:32112"),
            4_000,
        )
        .unwrap();
    assert_eq!(recent.peers[&remote].endpoints.len(), 1);
    assert_eq!(
        recent.peers[&remote].endpoints[0].addr,
        "192.168.1.20:32112"
    );
    assert!(
        !recent
            .observe_authenticated_peer(
                &endpoint_peer(remote.clone(), "udp", "192.168.1.20:32112"),
                4_000,
            )
            .unwrap(),
        "an identical UDP observation must not report a mutation"
    );

    let mut disconnected = endpoint_peer(remote, "udp", "192.0.2.2:32112");
    disconnected.connected = false;
    assert!(
        !recent
            .observe_authenticated_peer(&disconnected, 5_000)
            .unwrap()
    );
}

#[test]
fn validation_rejects_endpoint_newer_than_peer_authentication() {
    let local = npub();
    let remote = npub();
    let mut recent = RecentPeers::new(&local, "scope").unwrap();
    recent.peers.insert(
        remote,
        RecentPeer {
            last_authenticated_at_ms: 1_000,
            endpoints: vec![RecentPeerEndpoint {
                transport: RecentPeerTransport::Udp,
                addr: "192.0.2.1:32112".to_string(),
                last_authenticated_at_ms: 1_001,
            }],
        },
    );

    assert!(matches!(
        recent.to_json(),
        Err(RecentPeersError::EndpointNewerThanPeer {
            endpoint_at_ms: 1_001,
            peer_at_ms: 1_000,
            ..
        })
    ));
    let unchecked_json = serde_json::to_string(&recent).unwrap();
    assert!(matches!(
        RecentPeers::from_json(&unchecked_json, &local, "scope"),
        Err(RecentPeersError::EndpointNewerThanPeer { .. })
    ));
}

#[test]
fn observations_are_bounded_and_pruned_by_authentication_age() {
    let local = npub();
    let remote = npub();
    let mut recent = RecentPeers::new(local, "scope").unwrap();
    for index in 0..=RECENT_PEERS_MAX_ENDPOINTS_PER_PEER {
        recent
            .observe_authenticated_peer(
                &endpoint_peer(
                    remote.clone(),
                    "udp",
                    &format!("192.0.2.{}:32112", index + 1),
                ),
                1_000 + index as u64,
            )
            .unwrap();
    }
    assert_eq!(
        recent.peers[&remote].endpoints.len(),
        RECENT_PEERS_MAX_ENDPOINTS_PER_PEER
    );
    assert_eq!(recent.peers[&remote].endpoints[0].addr, "192.0.2.5:32112");

    recent
        .observe_authenticated_peer(&endpoint_peer(remote.clone(), "webrtc", &remote), 4_000)
        .unwrap();
    recent.prune(5_000, 1_500);
    assert!(recent.peers.contains_key(&remote));
    assert!(recent.peers[&remote].endpoints.is_empty());

    for index in 0..=RECENT_PEERS_MAX_PEERS {
        let remote = npub();
        recent
            .observe_authenticated_peer(
                &endpoint_peer(remote, "webrtc", "signaled"),
                10_000 + index as u64,
            )
            .unwrap();
    }
    assert_eq!(recent.peers.len(), RECENT_PEERS_MAX_PEERS);
}

#[test]
fn merge_only_augments_existing_configs_with_authenticated_udp_hints() {
    let local = npub();
    let cached_identity = Identity::generate();
    let cached = cached_identity.npub();
    let cached_hex = cached_identity.pubkey().to_string();
    let unrelated = npub();
    let mut recent = RecentPeers::new(local, "scope").unwrap();
    recent
        .observe_authenticated_peer(
            &endpoint_peer(cached.clone(), "udp", "192.0.2.1:32112"),
            7_000,
        )
        .unwrap();

    let mut configs = vec![PeerConfig {
        npub: cached.clone(),
        ..PeerConfig::default()
    }];
    assert_eq!(recent.merge_into_peer_configs(&mut configs), 1);
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].addresses.len(), 1);
    assert_eq!(
        configs[0].addresses[0].provenance,
        PeerAddressProvenance::Authenticated
    );
    assert_eq!(configs[0].addresses[0].seen_at_ms, Some(7_000));

    let mut hex_config = vec![PeerConfig {
        npub: cached_hex.clone(),
        ..PeerConfig::default()
    }];
    assert_eq!(recent.merge_into_peer_configs(&mut hex_config), 1);
    assert_eq!(
        hex_config[0].addresses[0].provenance,
        PeerAddressProvenance::Authenticated
    );

    let mut unrelated_configs = vec![PeerConfig {
        npub: unrelated,
        ..PeerConfig::default()
    }];
    assert_eq!(recent.merge_into_peer_configs(&mut unrelated_configs), 0);
    assert!(unrelated_configs[0].addresses.is_empty());

    let configured = PeerAddress::new("udp", "192.0.2.1:32112");
    let mut configured_peer = vec![PeerConfig {
        npub: cached,
        addresses: vec![configured],
        ..PeerConfig::default()
    }];
    assert_eq!(recent.merge_into_peer_configs(&mut configured_peer), 0);
    assert_eq!(
        configured_peer[0].addresses[0].provenance,
        PeerAddressProvenance::Configured
    );
    assert_eq!(configured_peer[0].addresses[0].seen_at_ms, None);

    let mut invalid_persisted_key = RecentPeers::new(npub(), "scope").unwrap();
    invalid_persisted_key.peers.insert(
        cached_hex,
        RecentPeer {
            last_authenticated_at_ms: 7_000,
            endpoints: Vec::new(),
        },
    );
    assert!(matches!(
        invalid_persisted_key.to_json(),
        Err(RecentPeersError::InvalidPeerNpub { .. })
    ));
}
