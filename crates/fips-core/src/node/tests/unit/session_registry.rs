use super::*;

#[test]
fn session_registry_owns_endpoint_session_storage() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let mut registry = SessionRegistry::default();
    let first = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x01; 8], [0x02; 8])),
        1_000,
        true,
    );
    assert!(registry.insert(peer_addr, first).is_none());
    assert_eq!(registry.len(), 1);
    assert!(registry.get(&peer_addr).is_some());
    assert_eq!(
        registry.get(&peer_addr).map(SessionEntry::remote_pubkey),
        Some(&peer.pubkey_full())
    );

    let replacement = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x03; 8], [0x04; 8])),
        2_000,
        true,
    );
    let replaced = registry
        .insert(peer_addr, replacement)
        .expect("session replacement should return the previous entry");
    assert_eq!(replaced.remote_pubkey(), &peer.pubkey_full());
    assert!(registry.get_mut(&peer_addr).is_some());

    assert_eq!(
        registry
            .iter()
            .map(|(addr, entry)| (*addr, entry.remote_pubkey()))
            .collect::<Vec<_>>(),
        vec![(peer_addr, &peer.pubkey_full())]
    );

    let removed = registry
        .remove(&peer_addr)
        .expect("session storage should live in the session owner");
    assert_eq!(removed.remote_pubkey(), &peer.pubkey_full());
    assert!(registry.get(&peer_addr).is_none());
    assert!(registry.is_empty());
}

#[test]
fn configured_peer_send_weights_own_identity_parse_and_default_policy() {
    let configured = Identity::generate();
    let configured_npub = configured.npub();
    let configured_addr = *PeerIdentity::from_npub(&configured_npub)
        .expect("configured peer identity")
        .node_addr();
    let on_demand = Identity::generate();
    let on_demand_npub = on_demand.npub();
    let on_demand_addr = *PeerIdentity::from_npub(&on_demand_npub)
        .expect("on-demand peer identity")
        .node_addr();
    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        configured_npub.clone(),
        "udp",
        "127.0.0.1:1",
    ));
    let mut on_demand_peer =
        crate::config::PeerConfig::new(on_demand_npub.clone(), "udp", "127.0.0.1:3");
    on_demand_peer.connect_policy = crate::config::ConnectPolicy::OnDemand;
    config.peers.push(on_demand_peer);
    config.peers.push(crate::config::PeerConfig::new(
        "not-a-valid-peer-id",
        "udp",
        "127.0.0.1:2",
    ));

    let weights = ConfiguredPeerSendWeights::from_config(&config);

    assert_eq!(
        weights.peer_addr_for_npub(&configured_npub),
        Some(configured_addr),
        "configured peer npubs are parsed once into a reverse address lookup"
    );
    assert_eq!(
        weights.peer_addr_for_npub(&on_demand_npub),
        Some(on_demand_addr),
        "non-auto configured peers should still be addressable by npub"
    );
    assert!(
        weights.peer_addr_for_npub("not-a-valid-peer-id").is_none(),
        "invalid peer identities must not create phantom scheduling policy"
    );
    assert_eq!(
        weights
            .peer_config(&configured_addr)
            .expect("configured peer metadata")
            .addresses[0]
            .addr,
        "127.0.0.1:1",
        "configured peer metadata is parsed once into the runtime lookup cache"
    );
    let auto_connect_addrs = weights
        .auto_connect_peer_configs()
        .map(|(addr, _)| *addr)
        .collect::<Vec<_>>();
    assert_eq!(
        auto_connect_addrs,
        vec![configured_addr],
        "runtime auto-connect iteration must preserve Config::auto_connect_peers semantics"
    );
    assert!(
        weights
            .peer_config(
                PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full()).node_addr()
            )
            .is_none(),
        "unconfigured peers must not have cached peer metadata"
    );
}
