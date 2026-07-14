use std::time::Duration;

use fips_core::config::{NostrPeerfindingSource, NostrRelayConfig, PeerConfig, TransportInstances};
use fips_core::discovery::nostr::{OverlayAdvert, OverlayTransportKind};
use fips_core::{Config, FipsEndpoint, Identity, IdentityConfig, Node, encode_npub};
use tokio::time::timeout;

fn relay_endpoint_config(secret: [u8; 32], peer_npub: String) -> Config {
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(hex::encode(secret)),
        persistent: false,
    };
    config.node.rate_limit.handshake_burst = 1_000;
    config.node.rate_limit.handshake_rate = 1_000.0;
    config.transports.nostr_relay = TransportInstances::Single(NostrRelayConfig::default());
    config.peers = vec![PeerConfig::new(peer_npub.clone(), "nostr_relay", peer_npub)];
    config
}

#[tokio::test]
async fn public_advert_exposes_relay_fallback_without_a_relay_list() {
    let identity = Identity::from_secret_bytes(&[33; 32]).expect("identity");
    let mut config = relay_endpoint_config([33; 32], encode_npub(&identity.pubkey()));
    config.peers.clear();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.peerfinding_source = NostrPeerfindingSource::External;
    config.node.discovery.nostr.advert_relays.clear();
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .expect("relay-advert endpoint");

    let event = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(event) = endpoint
                .local_nostr_discovery_advert_event()
                .await
                .expect("local advert")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("local relay capability advert");
    let advert: OverlayAdvert = serde_json::from_str(&event.content).expect("advert JSON");
    assert!(advert.endpoints.iter().any(|candidate| {
        candidate.transport == OverlayTransportKind::NostrRelay
            && candidate.addr == encode_npub(&identity.pubkey())
    }));

    endpoint.shutdown().await.expect("endpoint shutdown");
}

#[tokio::test]
async fn two_endpoints_establish_fips_link_over_ephemeral_relay_events() {
    let alice_identity = Identity::from_secret_bytes(&[31; 32]).expect("alice identity");
    let bob_identity = Identity::from_secret_bytes(&[32; 32]).expect("bob identity");
    let alice_npub = encode_npub(&alice_identity.pubkey());
    let bob_npub = encode_npub(&bob_identity.pubkey());
    let alice = FipsEndpoint::builder()
        .config(relay_endpoint_config([31; 32], bob_npub.clone()))
        .without_system_tun()
        .bind()
        .await
        .expect("alice endpoint");
    let bob = FipsEndpoint::builder()
        .config(relay_endpoint_config([32; 32], alice_npub.clone()))
        .without_system_tun()
        .bind()
        .await
        .expect("bob endpoint");

    timeout(Duration::from_secs(5), async {
        loop {
            for event in alice
                .drain_nostr_relay_events(64)
                .await
                .expect("alice relay outbox")
            {
                bob.ingest_nostr_event(event)
                    .await
                    .expect("bob event ingest");
            }
            for event in bob
                .drain_nostr_relay_events(64)
                .await
                .expect("bob relay outbox")
            {
                alice
                    .ingest_nostr_event(event)
                    .await
                    .expect("alice event ingest");
            }
            let alice_connected = alice
                .peers()
                .await
                .expect("alice peers")
                .iter()
                .any(|peer| {
                    peer.connected
                        && peer.npub == bob_npub
                        && peer.transport_type.as_deref() == Some("nostr_relay")
                });
            let bob_connected = bob.peers().await.expect("bob peers").iter().any(|peer| {
                peer.connected
                    && peer.npub == alice_npub
                    && peer.transport_type.as_deref() == Some("nostr_relay")
            });
            if alice_connected && bob_connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("relay-carried FIPS handshake");

    alice.shutdown().await.expect("alice shutdown");
    bob.shutdown().await.expect("bob shutdown");
}

#[tokio::test]
async fn direct_node_embedder_drains_relay_events_through_attached_io() {
    let peer = Identity::from_secret_bytes(&[42; 32]).expect("peer identity");
    let mut node = Node::new(relay_endpoint_config([41; 32], encode_npub(&peer.pubkey())))
        .expect("relay node");
    let io = node
        .attach_nostr_relay_io(16)
        .expect("attach relay I/O before start");
    node.start().await.expect("start relay node");

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let result = tokio::select! {
            result = node.run_rx_loop() => result,
            _ = &mut shutdown_rx => Ok(()),
        };
        node.stop().await.expect("stop relay node");
        result
    });

    let event = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(event) = io
                .drain_events(8)
                .await
                .expect("drain direct-node relay events")
                .into_iter()
                .next()
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("direct Node relay handshake event");
    assert_eq!(
        event.kind,
        nostr::Kind::Custom(fips_core::transport::nostr_relay::NOSTR_RELAY_DATAGRAM_KIND)
    );

    shutdown_tx.send(()).expect("request relay node shutdown");
    task.await
        .expect("relay node task")
        .expect("relay node loop");
}
