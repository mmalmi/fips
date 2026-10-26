use crate::config::{NostrDiscoveryPolicy, PeerConfig, UdpConfig};
use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};
use crate::peer::ActivePeer;
use crate::transport::udp::UdpTransport;
use crate::transport::{LinkId, TransportAddr, TransportHandle, TransportId, packet_channel};
use crate::{Config, Identity, Node, NodeAddr, PeerIdentity};
use std::sync::Arc;
use std::time::Duration;

fn client_config() -> Config {
    let mut config = Config::new();
    config.node.leaf_only = true;
    config.node.system_files_enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.open_discovery_max_pending = 64;
    config
}

fn add_neighbor(node: &mut Node, supports_client: bool) -> NodeAddr {
    let identity = Identity::generate();
    let address = *identity.node_addr();
    let mut peer = ActivePeer::new(
        PeerIdentity::from_pubkey_full(identity.pubkey_full()),
        LinkId::new(100),
        Node::now_ms(),
    );
    peer.client_only_supported = supports_client;
    node.peers.insert(address, peer);
    node.refresh_client_role();
    assert_eq!(node.is_leaf_only(), supports_client);
    address
}

async fn cache_advert(bootstrap: &NostrDiscovery, identity: &Identity, address: &str) {
    let advert = NostrDiscovery::cached_advert_for_test(
        identity.npub(),
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: address.to_string(),
        },
        crate::time::now_secs(),
    );
    bootstrap
        .insert_advert_for_test(identity.npub(), advert)
        .await;
}

#[tokio::test]
async fn requested_client_skips_ambient_sweeps_during_legacy_fallback() {
    for supports_client in [false, true] {
        for max_age in [None, Some(3_600)] {
            let mut node = Node::new(client_config()).unwrap();
            let neighbor = add_neighbor(&mut node, supports_client);
            let ambient = Identity::generate();
            let bootstrap = Arc::new(NostrDiscovery::new_for_test());
            cache_advert(&bootstrap, &ambient, "203.0.113.7:2121").await;

            node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                .await;
            assert!(node.retry_pending.is_empty());
            assert!(node.peers.get(&neighbor).unwrap().can_send());
            assert_eq!(node.is_leaf_only(), supports_client);

            // Stale is still sendable until ordinary liveness declares loss.
            node.peers.get_mut(&neighbor).unwrap().mark_stale();
            node.refresh_client_role();
            assert_eq!(node.is_leaf_only(), supports_client);
            node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                .await;
            assert!(node.retry_pending.is_empty());

            // Positive control: the same advert still grows an ordinary router.
            node.config.node.leaf_only = false;
            node.refresh_client_role();
            node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                .await;
            assert!(node.retry_pending.contains_key(ambient.node_addr()));
        }
    }
}

#[tokio::test]
async fn requested_client_discovers_initial_uplink_without_a_reachable_seed() {
    for nat_only_configured_peer in [false, true] {
        for max_age in [None, Some(3_600)] {
            let mut config = client_config();
            config.node.discovery.nostr.open_discovery_max_pending = 2;
            let nat_peer = Identity::generate();
            if nat_only_configured_peer {
                config
                    .peers
                    .push(PeerConfig::new(nat_peer.npub(), "udp", "nat"));
            }
            let mut node = Node::new(config).unwrap();
            assert!(node.find_next_hop(nat_peer.node_addr()).is_none());
            let bootstrap = Arc::new(NostrDiscovery::new_for_test());
            for _ in 0..3 {
                cache_advert(&bootstrap, &Identity::generate(), "203.0.113.7:2121").await;
            }

            node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                .await;
            assert_eq!(
                node.retry_pending.len(),
                2,
                "initial discovery retains its budget"
            );
            assert!(!node.retry_pending.contains_key(nat_peer.node_addr()));
            for retry in node.retry_pending.values() {
                assert!(!retry.peer_config.auto_reconnect);
                assert!(!retry.reconnect);
                assert!(retry.expires_at_ms.is_some());
                assert_eq!(retry.peer_config.addresses[0].addr, "203.0.113.7:2121");
            }
        }
    }
}

#[tokio::test]
async fn requested_client_does_not_treat_a_client_neighbor_as_an_uplink() {
    for max_age in [None, Some(3_600)] {
        let mut node = Node::new(client_config()).unwrap();
        let neighbor = add_neighbor(&mut node, true);
        node.peers.get_mut(&neighbor).unwrap().client_only = true;
        assert!(node.peers.get(&neighbor).unwrap().can_send());
        let ambient = Identity::generate();
        let bootstrap = Arc::new(NostrDiscovery::new_for_test());
        cache_advert(&bootstrap, &ambient, "203.0.113.7:2121").await;

        node.run_open_discovery_sweep(&bootstrap, max_age, "test")
            .await;
        assert!(node.retry_pending.contains_key(ambient.node_addr()));
        assert!(node.is_leaf_only());
    }
}

#[tokio::test]
async fn requested_client_reopens_discovery_after_uplink_loss_and_stops_after_recovery() {
    for supports_client in [false, true] {
        for reconnecting in [false, true] {
            for max_age in [None, Some(3_600)] {
                let mut node = Node::new(client_config()).unwrap();
                let neighbor = add_neighbor(&mut node, supports_client);
                let ambient = Identity::generate();
                let bootstrap = Arc::new(NostrDiscovery::new_for_test());
                cache_advert(&bootstrap, &ambient, "203.0.113.7:2121").await;
                node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                    .await;
                assert!(node.retry_pending.is_empty());

                if reconnecting {
                    node.peers.get_mut(&neighbor).unwrap().mark_reconnecting();
                } else {
                    node.peers.get_mut(&neighbor).unwrap().mark_disconnected();
                }
                node.refresh_client_role();
                assert!(node.is_leaf_only());
                node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                    .await;
                assert!(node.retry_pending.contains_key(ambient.node_addr()));

                node.peers
                    .get_mut(&neighbor)
                    .unwrap()
                    .mark_connected(Node::now_ms());
                node.refresh_client_role();
                assert_eq!(node.is_leaf_only(), supports_client);
                let later = Identity::generate();
                cache_advert(&bootstrap, &later, "203.0.113.8:2121").await;
                node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                    .await;
                assert!(!node.retry_pending.contains_key(later.node_addr()));
                assert!(
                    node.retry_pending.contains_key(ambient.node_addr()),
                    "existing recovery work is not pruned"
                );
            }
        }
    }
}

#[tokio::test]
async fn requested_client_preserves_configured_bootstrap_and_retry_policy() {
    for auto_reconnect in [false, true] {
        let configured = Identity::generate();
        let mut peer_config = PeerConfig::new(configured.npub(), "udp", "203.0.113.9:2121");
        peer_config.auto_reconnect = auto_reconnect;
        let mut config = client_config();
        config.node.discovery.nostr.open_discovery_max_pending = 0;
        config.peers.push(peer_config.clone());
        let mut node = Node::new(config).unwrap();
        add_neighbor(&mut node, false);

        // No transport is installed: bootstrap must still attempt the configured
        // peer and retain its retry instead of treating it as an ambient advert.
        node.initiate_peer_connections().await;
        assert!(node.retry_pending.contains_key(configured.node_addr()));
        let bootstrap = Arc::new(NostrDiscovery::new_for_test());
        cache_advert(&bootstrap, &configured, "203.0.113.10:2121").await;

        for max_age in [None, Some(3_600)] {
            let scheduled = Node::now_ms() + 60_000;
            node.retry_pending
                .get_mut(configured.node_addr())
                .unwrap()
                .retry_after_ms = scheduled;
            node.run_open_discovery_sweep(&bootstrap, max_age, "test")
                .await;
            let retry = node.retry_pending.get(configured.node_addr()).unwrap();
            if auto_reconnect {
                assert!(retry.retry_after_ms < scheduled);
                assert!(retry.retry_after_ms <= Node::now_ms());
            } else {
                assert_eq!(retry.retry_after_ms, scheduled);
            }
            assert_eq!(
                serde_json::to_value(&retry.peer_config).unwrap(),
                serde_json::to_value(&peer_config).unwrap()
            );
        }
        assert!(
            !node.is_leaf_only(),
            "the legacy adjacency still requires router behavior"
        );
    }
}

#[tokio::test]
async fn requested_client_can_explicitly_dial_a_skipped_ambient_peer() {
    for supports_client in [false, true] {
        let mut node = Node::new(client_config()).unwrap();
        add_neighbor(&mut node, supports_client);
        let remote = Identity::generate();
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = sink.local_addr().unwrap().to_string();
        let bootstrap = Arc::new(NostrDiscovery::new_for_test());
        cache_advert(&bootstrap, &remote, &address).await;
        node.nostr_discovery = Some(bootstrap.clone());
        node.run_open_discovery_sweep(&bootstrap, None, "test")
            .await;
        assert!(node.retry_pending.is_empty());

        let transport_id = TransportId::new(1);
        let (packet_tx, packet_rx) = packet_channel(64);
        node.packet_tx = Some(packet_tx.clone());
        node.packet_rx = Some(packet_rx);
        let mut transport = UdpTransport::new(
            transport_id,
            None,
            UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..UdpConfig::default()
            },
            packet_tx,
        );
        transport.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(transport));

        node.api_connect(&remote.npub(), &address, "udp")
            .await
            .unwrap();
        assert!(
            node.find_link_by_addr(transport_id, &TransportAddr::from_string(&address))
                .is_some()
        );
        let mut packet = [0u8; 2048];
        let (received, _) =
            tokio::time::timeout(Duration::from_secs(1), sink.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert!(received > 0, "an explicit request must emit its handshake");
        assert_eq!(node.is_leaf_only(), supports_client);
        for transport in node.transports.values_mut() {
            transport.stop().await.unwrap();
        }
    }
}
