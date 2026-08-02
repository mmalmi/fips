use super::*;
use crate::Identity;
use crate::config::{PeerConfig, RoutingMode, TransportInstances};
use crate::discovery::EstablishedTraversal;
use crate::discovery::nostr::{
    BootstrapEvent, MeshTraversalSignal, NostrDiscovery, TraversalOffer,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_control_and_shutdown_progress_under_payload_and_ready_nostr_events() {
    const CONTROL_BUDGET: Duration = Duration::from_millis(250);
    const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

    let server_identity = Identity::generate();
    let server_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("reserve server UDP port")
        .local_addr()
        .expect("reserved server UDP address")
        .port();
    let discovery = Arc::new(NostrDiscovery::new_for_test());
    let mut server_config = Config::new();
    server_config.node.identity.nsec =
        Some(crate::encode_nsec(&server_identity.keypair().secret_key()));
    server_config.node.routing.mode = RoutingMode::ReplyLearned;
    server_config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some(format!("127.0.0.1:{server_port}")),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    let server = Arc::new(
        FipsEndpoint::builder()
            .config(server_config)
            .without_system_tun()
            .bind_with_nostr_discovery_for_test(Arc::clone(&discovery))
            .await
            .expect("bind server endpoint"),
    );

    let client_identity = Identity::generate();
    let mut client_config = Config::new();
    client_config.node.identity.nsec =
        Some(crate::encode_nsec(&client_identity.keypair().secret_key()));
    client_config.node.routing.mode = RoutingMode::ReplyLearned;
    client_config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    client_config.peers.push(PeerConfig::new(
        server.npub(),
        "udp",
        format!("127.0.0.1:{server_port}"),
    ));
    let client_discovery = Arc::new(NostrDiscovery::new_for_test_with_identity(&client_identity));
    let client = Arc::new(
        FipsEndpoint::builder()
            .config(client_config)
            .without_system_tun()
            .bind_with_nostr_discovery_for_test(Arc::clone(&client_discovery))
            .await
            .expect("bind client endpoint"),
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client.peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|peer| peer.npub == server.npub() && peer.connected)
            }) && server.peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|peer| peer.npub == client.npub() && peer.connected)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("endpoint pair should authenticate");

    let traversal_socket =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("bind observable traversal socket");
    let traversal_server_addr = traversal_socket
        .local_addr()
        .expect("observable traversal address");
    let traversal_peer_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("reserve traversal peer port")
        .local_addr()
        .expect("traversal peer address")
        .port();
    let mut traversal_peer_config = Config::new();
    traversal_peer_config.node.routing.mode = RoutingMode::ReplyLearned;
    traversal_peer_config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some(format!("127.0.0.1:{traversal_peer_port}")),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    traversal_peer_config.peers.push(PeerConfig::new(
        server.npub(),
        "udp",
        traversal_server_addr.to_string(),
    ));
    let traversal_peer = Arc::new(
        FipsEndpoint::builder()
            .config(traversal_peer_config)
            .without_system_tun()
            .bind()
            .await
            .expect("bind observable traversal peer"),
    );
    let observable_traversal = BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "observable-pressure-traversal",
            traversal_peer.npub(),
            format!("127.0.0.1:{traversal_peer_port}")
                .parse()
                .expect("traversal peer endpoint"),
            traversal_socket,
        ),
    };
    let established_backlog = (1..=128u64)
        .map(|sequence| {
            let peer = Identity::generate();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind traversal socket");
            BootstrapEvent::Established {
                traversal: EstablishedTraversal::new(
                    format!("pressure-{sequence}"),
                    peer.npub(),
                    "127.0.0.1:9".parse().expect("discard endpoint"),
                    socket,
                ),
            }
        })
        .collect::<std::collections::VecDeque<_>>();

    let shutdown_started = Arc::new(AtomicBool::new(false));
    let (pressure_stop_tx, pressure_stop_rx) = tokio::sync::watch::channel(false);
    let (pressure_start_tx, pressure_start_rx) = tokio::sync::watch::channel(false);
    let (payload_stop_tx, payload_stop_rx) = tokio::sync::watch::channel(false);
    let established_emitted = Arc::new(AtomicUsize::new(0));
    let mesh_signals_emitted = Arc::new(AtomicUsize::new(0));
    let established_flood = {
        let discovery = Arc::clone(&discovery);
        let emitted = Arc::clone(&established_emitted);
        let mut stop = pressure_stop_rx.clone();
        let mut start = pressure_start_rx.clone();
        tokio::spawn(async move {
            while !*start.borrow() {
                start.changed().await.expect("discovery pressure start");
            }
            let mut sequence = 128u64;
            let mut backlog = established_backlog;
            loop {
                sequence += 1;
                let event = backlog.pop_front().unwrap_or_else(|| {
                    let peer = Identity::generate();
                    let socket =
                        std::net::UdpSocket::bind("127.0.0.1:0").expect("bind traversal socket");
                    BootstrapEvent::Established {
                        traversal: EstablishedTraversal::new(
                            format!("pressure-{sequence}"),
                            peer.npub(),
                            "127.0.0.1:9".parse().expect("discard endpoint"),
                            socket,
                        ),
                    }
                });
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = discovery.emit_event_for_test(event) => {
                        emitted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    };
    let mesh_signal_flood = {
        let discovery = Arc::clone(&discovery);
        let emitted = Arc::clone(&mesh_signals_emitted);
        let mut stop = pressure_stop_rx;
        let mut start = pressure_start_rx;
        let sender_npub = server.npub().to_string();
        let route_npub = client.npub().to_string();
        let recipient_npub = client_discovery.npub_for_test();
        tokio::spawn(async move {
            while !*start.borrow() {
                start.changed().await.expect("mesh pressure start");
            }
            let mut sequence = 0u64;
            loop {
                sequence += 1;
                let now_ms = crate::time::now_ms();
                let session_id = format!("mesh-pressure-{sequence}");
                let signal = MeshTraversalSignal::Offer {
                    peer_npub: route_npub.clone(),
                    offer: TraversalOffer {
                        message_type: "offer".to_string(),
                        session_id: session_id.clone(),
                        issued_at: now_ms,
                        expires_at: now_ms + 60_000,
                        nonce: format!("nonce-{sequence}"),
                        sender_npub: sender_npub.clone(),
                        recipient_npub: recipient_npub.clone(),
                        reflexive_address: None,
                        local_addresses: Vec::new(),
                        stun_server: None,
                    },
                };
                tokio::select! {
                    _ = stop.changed() => break,
                    accepted = discovery.emit_mesh_signal_for_test(signal) => {
                        assert!(accepted, "production mesh-signal emitter must remain open");
                        emitted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    };
    let payload_flood = {
        let client = Arc::clone(&client);
        let server_peer = PeerIdentity::from_npub(server.npub()).expect("server identity");
        let shutdown_started = Arc::clone(&shutdown_started);
        let mut stop = payload_stop_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    result = client.send_batch_to_peer(
                        server_peer,
                        vec![vec![0x5a; 512]; 16],
                    ) => {
                        if let Err(error) = result {
                            assert!(
                                shutdown_started.load(Ordering::Relaxed),
                                "sustained endpoint payload failed before shutdown: {error}"
                            );
                            break;
                        }
                    }
                }
                tokio::task::yield_now().await;
            }
        })
    };
    let delivered = Arc::new(AtomicUsize::new(0));
    let payload_drain = {
        let server = Arc::clone(&server);
        let delivered = Arc::clone(&delivered);
        let mut stop = payload_stop_rx;
        tokio::spawn(async move {
            let mut messages = Vec::with_capacity(128);
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    received = server.recv_batch_into(&mut messages, 128) => {
                        let Some(received) = received else { break; };
                        delivered.fetch_add(received, Ordering::Relaxed);
                    }
                }
            }
        })
    };

    discovery.emit_event_for_test(observable_traversal).await;
    pressure_start_tx
        .send(true)
        .expect("start production discovery pressure");
    let pressure_ready = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let traversal_connected = traversal_peer.peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|peer| peer.npub == server.npub() && peer.connected)
            });
            let mesh_offer_received = client_discovery.received_mesh_offer_count_for_test() > 0;
            if delivered.load(Ordering::Relaxed) >= 1
                && established_emitted.load(Ordering::Relaxed) >= 72
                && mesh_signals_emitted.load(Ordering::Relaxed) >= 72
                && traversal_connected
                && mesh_offer_received
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    if pressure_ready.is_err() {
        let traversal_connected = traversal_peer.peers().await.is_ok_and(|peers| {
            peers
                .iter()
                .any(|peer| peer.npub == server.npub() && peer.connected)
        });
        let mesh_offer_received = client_discovery.received_mesh_offer_count_for_test() > 0;
        panic!(
            "production pressure incomplete: delivered={}, established={}, mesh={}, traversal_connected={traversal_connected}, mesh_offer_received={mesh_offer_received}",
            delivered.load(Ordering::Relaxed),
            established_emitted.load(Ordering::Relaxed),
            mesh_signals_emitted.load(Ordering::Relaxed),
        );
    }
    let delivered_before_control = delivered.load(Ordering::Relaxed);
    let peers = tokio::time::timeout(CONTROL_BUDGET, server.peers())
        .await
        .expect("peer snapshot must keep reserved progress under Nostr and payload pressure")
        .expect("peer snapshot under pressure");
    assert!(
        peers
            .iter()
            .any(|peer| peer.npub == client.npub() && peer.connected),
        "authenticated session must remain live under control pressure"
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while delivered.load(Ordering::Relaxed) <= delivered_before_control {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("authenticated payload delivery must continue after the control turn");

    shutdown_started.store(true, Ordering::Relaxed);
    tokio::time::timeout(SHUTDOWN_BUDGET, server.shutdown())
        .await
        .expect("graceful shutdown must finish comfortably below the endpoint API timeout")
        .expect("server graceful shutdown");
    payload_stop_tx.send(true).expect("stop payload pressure");
    tokio::time::timeout(SHUTDOWN_BUDGET, payload_flood)
        .await
        .expect("payload producer cleanup budget")
        .expect("payload producer task");
    tokio::time::timeout(SHUTDOWN_BUDGET, payload_drain)
        .await
        .expect("payload receiver cleanup budget")
        .expect("payload receiver task");
    pressure_stop_tx
        .send(true)
        .expect("stop production discovery pressure");
    tokio::time::timeout(SHUTDOWN_BUDGET, established_flood)
        .await
        .expect("established producer cleanup budget")
        .expect("established event producer");
    tokio::time::timeout(SHUTDOWN_BUDGET, mesh_signal_flood)
        .await
        .expect("mesh-signal producer cleanup budget")
        .expect("mesh-signal producer");
    tokio::time::timeout(SHUTDOWN_BUDGET, client.shutdown())
        .await
        .expect("client graceful shutdown budget")
        .expect("client graceful shutdown");
    tokio::time::timeout(SHUTDOWN_BUDGET, traversal_peer.shutdown())
        .await
        .expect("traversal peer graceful shutdown budget")
        .expect("traversal peer graceful shutdown");
}
