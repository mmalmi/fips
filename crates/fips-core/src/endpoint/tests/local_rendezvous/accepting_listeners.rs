use super::*;
use crate::config::{PeerAdmissionConfig, PeerConfig, TransportInstances, UdpConfig};

async fn bind_accepting_provider(address: SocketAddrV4) -> FipsEndpoint {
    let mut config = local_config(address);
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        accept_connections: Some(true),
        ..Default::default()
    });
    FipsEndpoint::builder()
        .config(config)
        .local_rendezvous()
        .without_system_tun()
        .bind()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepting_listener_first_read_works_for_every_anchor_start_order() {
    // Each permutation has an actual separate anonymous FMP/FSP endpoint.
    // No session, observed source socket, or identified anchor route is shared.
    for first in ["app", "provider", "other"] {
        let rendezvous = reserve_rendezvous_addr();
        let other = if first == "other" {
            Some(bind_local(rendezvous).await)
        } else {
            None
        };
        let (app, provider) = if first == "provider" {
            let provider = bind_accepting_provider(rendezvous).await;
            (bind_local(rendezvous).await, provider)
        } else {
            let app = bind_local(rendezvous).await;
            (app, bind_accepting_provider(rendezvous).await)
        };
        let service = provider
            .register_service_receiver_with_capability(LocalInstanceCapability::service(
                SERVICE_CAPABILITY,
                SERVICE_PORT,
            ))
            .await
            .unwrap();
        wait_for_capability(&app, SERVICE_CAPABILITY, provider.npub()).await;
        let identity = PeerIdentity::from_npub(provider.npub()).unwrap();
        // Exactly one query at capability readiness: the API owns any wait
        // for reordered listener metadata, rather than losing the first GET.
        let addresses = app
            .authenticated_local_udp_listen_addrs(identity)
            .await
            .unwrap();
        assert_eq!(
            addresses,
            provider.bound_udp_listen_addrs().await.unwrap(),
            "{first}"
        );
        assert!(!addresses.is_empty(), "accepting provider in {first} order");

        let mut config = Config::new();
        config.node.strict_client_only = true;
        config.node.peer_admission = PeerAdmissionConfig {
            configured_only: true,
            denied_npubs: std::iter::once(app.npub().to_owned())
                .chain(other.as_ref().map(|node| node.npub().to_owned()))
                .collect(),
        };
        config.node.discovery.local.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            accept_connections: Some(false),
            ..Default::default()
        });
        config.peers = vec![PeerConfig::new(
            provider.npub(),
            "udp",
            addresses[0].to_string(),
        )];
        let reader = FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .unwrap();
        let replies = reader
            .register_service_receiver(CONSUMER_PORT)
            .await
            .unwrap();
        reader
            .send_datagram(identity, CONSUMER_PORT, SERVICE_PORT, b"first GET".to_vec())
            .await
            .unwrap();
        let request = receive_service_datagram(&service, b"first GET").await;
        assert_eq!(
            request.source_peer,
            PeerIdentity::from_npub(reader.npub()).unwrap()
        );
        provider
            .send_datagram(
                request.source_peer,
                SERVICE_PORT,
                CONSUMER_PORT,
                b"first blob".to_vec(),
            )
            .await
            .unwrap();
        receive_service_datagram(&replies, b"first blob").await;
        let peers = reader.peers().await.unwrap();
        assert!(
            peers
                .iter()
                .filter(|peer| peer.connected)
                .all(|peer| peer.npub == provider.npub())
        );
        assert!(reader.routing_status().await.unwrap().client_only);
        reader.shutdown().await.unwrap();
        app.shutdown().await.unwrap();
        provider.shutdown().await.unwrap();
        if let Some(other) = other {
            other.shutdown().await.unwrap();
        }
    }
}
