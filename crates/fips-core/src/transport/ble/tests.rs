use super::*;

use io::MockBleIo;

fn test_addr(n: u8) -> BleAddr {
    BleAddr::from_mac("hci0", [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n])
}

fn make_transport(io: MockBleIo) -> (BleTransport<MockBleIo>, crate::transport::PacketRx) {
    let (tx, rx) = crate::transport::packet_channel(64);
    let config = BleConfig::default();
    let transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
    (transport, rx)
}

#[test]
fn test_transport_type() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (transport, _rx) = make_transport(io);
    assert_eq!(transport.transport_type().name, "ble");
    assert!(transport.transport_type().connection_oriented);
    assert!(transport.transport_type().reliable);
}

#[test]
fn test_transport_initial_state() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (transport, _rx) = make_transport(io);
    assert_eq!(transport.state(), TransportState::Configured);
}

#[test]
fn test_transport_default_mtu() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (transport, _rx) = make_transport(io);
    assert_eq!(transport.mtu(), 2048);
}

#[tokio::test]
async fn test_transport_start_stop() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (mut transport, _rx) = make_transport(io);
    transport.start_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Up);

    transport.stop_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Down);
}

#[tokio::test]
async fn test_transport_advertises_platform_assigned_psm() {
    let io = MockBleIo::new("ios", test_addr(1)).with_listener_psm(0x0091);
    let (mut transport, _rx) = make_transport(io);
    transport.start_async().await.unwrap();

    assert_eq!(
        transport.io().advertised_bootstrap(),
        Some(bootstrap::BleBootstrap::new(0x0091, 2048).unwrap())
    );
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn stalled_inbound_pubkey_exchange_does_not_block_healthy_peer() {
    let local_addr = test_addr(1);
    let io = MockBleIo::new("hci0", local_addr.clone());
    let (tx, _rx) = crate::transport::packet_channel(64);
    let config = BleConfig {
        advertise: Some(false),
        scan: Some(false),
        ..BleConfig::default()
    };
    let local_identity = crate::Identity::generate();
    let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
    transport.set_local_pubkey(local_identity.pubkey().serialize());
    transport.start_async().await.unwrap();

    let (stalled_inbound, stalled_peer) =
        io::MockBleStream::pair(local_addr.clone(), test_addr(2), 2048);
    transport.io().inject_inbound(stalled_inbound).await;
    tokio::task::yield_now().await;

    let healthy_addr = test_addr(3);
    let (healthy_inbound, healthy_peer) =
        io::MockBleStream::pair(local_addr, healthy_addr.clone(), 2048);
    transport.io().inject_inbound(healthy_inbound).await;
    let peer_identity = crate::Identity::generate();
    let peer_pubkey = peer_identity.pubkey().serialize();
    let healthy_peer = FramedBleStream::new(healthy_peer, 2048);
    let peer_task = tokio::spawn(async move {
        tasks::pubkey_exchange(&healthy_peer, &peer_pubkey)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let healthy_addr = healthy_addr.to_transport_addr();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if transport.connection_state_sync(&healthy_addr) == ConnectionState::Connected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("healthy inbound connection must bypass the stalled exchange");

    peer_task.abort();
    drop(stalled_peer);
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn retired_receive_loop_does_not_remove_replacement_connection() {
    use std::sync::Arc;

    let local_addr = test_addr(1);
    let remote_addr = test_addr(2);
    let transport_addr = remote_addr.to_transport_addr();
    let pool = Arc::new(tokio::sync::Mutex::new(pool::ConnectionPool::new(2)));
    let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
    let stats = Arc::new(BleStats::new());

    let (old_stream, old_peer) =
        io::MockBleStream::pair(local_addr.clone(), remote_addr.clone(), 2048);
    let old_stream = Arc::new(FramedBleStream::new(old_stream, 2048));
    pool.lock()
        .await
        .insert(
            transport_addr.clone(),
            BleConnection {
                stream: Arc::clone(&old_stream),
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: tokio::time::Instant::now(),
                is_static: false,
                addr: remote_addr.clone(),
            },
        )
        .unwrap();
    let old_receive = tokio::spawn(tasks::receive_loop(
        old_stream,
        transport_addr.clone(),
        Arc::clone(&pool),
        packet_tx,
        TransportId::new(1),
        stats,
        2048,
    ));

    let (replacement, _replacement_peer) =
        io::MockBleStream::pair(local_addr, remote_addr.clone(), 2048);
    let replacement = Arc::new(FramedBleStream::new(replacement, 2048));
    pool.lock()
        .await
        .insert(
            transport_addr.clone(),
            BleConnection {
                stream: Arc::clone(&replacement),
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: tokio::time::Instant::now(),
                is_static: false,
                addr: remote_addr,
            },
        )
        .unwrap();

    drop(old_peer);
    old_receive.await.unwrap();

    let pool = pool.lock().await;
    assert!(
        pool.get(&transport_addr)
            .is_some_and(|connection| Arc::ptr_eq(&connection.stream, &replacement)),
        "an old receive task must not remove the replacement generation"
    );
}

#[tokio::test]
async fn configured_connection_limit_includes_in_flight_identity_exchange() {
    let local_addr = test_addr(1);
    let io = MockBleIo::new("hci0", local_addr.clone());
    let held_peers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let peers = std::sync::Arc::clone(&held_peers);
    io.set_connect_handler(move |addr, _psm| {
        let (stream, peer) = io::MockBleStream::pair(local_addr.clone(), addr.clone(), 2048);
        peers.lock().unwrap().push(peer);
        Ok(stream)
    });
    let (tx, _rx) = crate::transport::packet_channel(8);
    let config = BleConfig {
        max_connections: Some(1),
        ..BleConfig::default()
    };
    let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
    transport.set_local_pubkey([2; 32]);

    let first = test_addr(2).to_transport_addr();
    let second = test_addr(3).to_transport_addr();
    transport.connect_async(&first).await.unwrap();

    assert_eq!(
        transport.connection_state_sync(&first),
        ConnectionState::Connecting
    );
    assert!(matches!(
        transport.connect_async(&second).await,
        Err(TransportError::ConnectionRefused)
    ));

    transport.stop_async().await.unwrap();
    drop(held_peers);
}

#[tokio::test(start_paused = true)]
async fn test_scan_discovers_peers() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (mut transport, _rx) = make_transport(io);
    transport.start_async().await.unwrap();

    // Inject scan results via the I/O mock
    transport.io.inject_scan_result(test_addr(2)).await;
    transport.io.inject_scan_result(test_addr(3)).await;

    // Let scan_probe_loop pick up results and schedule jitter
    tokio::task::yield_now().await;
    // Advance past max jitter (5s) so probes fire
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    // Let the expired entries get processed
    tokio::task::yield_now().await;

    // Without pubkey set, scan results go to discovery buffer as bare MACs
    let peers = transport.discovery_buffer.take();
    assert_eq!(peers.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_scan_deduplicates() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (mut transport, _rx) = make_transport(io);
    transport.start_async().await.unwrap();

    // Same address twice
    transport.io.inject_scan_result(test_addr(2)).await;
    transport.io.inject_scan_result(test_addr(2)).await;

    // Let scan_probe_loop pick up results
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    let peers = transport.discovery_buffer.take();
    assert_eq!(peers.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn test_scan_retry_uses_refreshed_bootstrap_for_same_address() {
    use std::sync::{Arc, Mutex};

    let io = MockBleIo::new("hci0", test_addr(1));
    let attempted_psms = Arc::new(Mutex::new(Vec::new()));
    let recorded_psms = Arc::clone(&attempted_psms);
    io.set_connect_handler(move |_addr, psm| {
        recorded_psms.lock().unwrap().push(psm);
        Err(TransportError::ConnectionRefused)
    });

    let (tx, _rx) = crate::transport::packet_channel(64);
    let config = BleConfig {
        probe_cooldown_secs: Some(1),
        ..BleConfig::default()
    };
    let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
    transport.set_local_pubkey([2; 32]);
    transport.start_async().await.unwrap();

    let addr = test_addr(2);
    let stale = bootstrap::BleBootstrap::new(0x0091, 2048).unwrap();
    let refreshed = bootstrap::BleBootstrap::new(0x0093, 2048).unwrap();
    transport
        .io()
        .inject_scan_candidate(io::BleCandidate {
            addr: addr.clone(),
            bootstrap: stale,
        })
        .await;
    tokio::task::yield_now().await;

    transport
        .io()
        .inject_scan_candidate(io::BleCandidate {
            addr,
            bootstrap: refreshed,
        })
        .await;
    tokio::task::yield_now().await;

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    assert_eq!(
        *attempted_psms.lock().unwrap(),
        vec![stale.psm, refreshed.psm]
    );
    transport.stop_async().await.unwrap();
}

#[test]
fn test_transport_auto_connect_default() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (transport, _rx) = make_transport(io);
    assert!(!transport.auto_connect());
}

#[test]
fn test_connection_state_none() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (transport, _rx) = make_transport(io);
    let addr = test_addr(2).to_transport_addr();
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::None
    );
}

/// Verify that the cross-probe tie-breaker follows the same convention
/// as `cross_connection_winner`: smaller NodeAddr's outbound wins.
#[test]
fn test_tiebreaker_convention() {
    use secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let sk_a = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let sk_b = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let (pk_a, _) = sk_a.public_key(&secp).x_only_public_key();
    let (pk_b, _) = sk_b.public_key(&secp).x_only_public_key();

    let addr_a = NodeAddr::from_pubkey(&pk_a);
    let addr_b = NodeAddr::from_pubkey(&pk_b);

    // Determine which is smaller
    let (smaller, larger) = if addr_a < addr_b {
        (addr_a, addr_b)
    } else {
        (addr_b, addr_a)
    };

    // scan_loop (outbound): promotes when our_addr < peer_addr
    // Smaller node scanning larger → our_addr < peer_addr → promote (win)
    assert!(tasks::local_node_wins_outbound(&smaller, &larger));
    assert!(!tasks::local_node_wins_outbound(&larger, &smaller));

    // accept_loop (inbound): drops when our_addr < peer_addr
    // Smaller node accepting from larger → drops inbound (outbound wins)
    // This means: smaller always uses outbound, larger always uses inbound
}
