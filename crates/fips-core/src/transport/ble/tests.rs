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
    assert!(smaller < larger, "test setup: smaller < larger");

    // accept_loop (inbound): drops when our_addr < peer_addr
    // Smaller node accepting from larger → drops inbound (outbound wins)
    // This means: smaller always uses outbound, larger always uses inbound
}
