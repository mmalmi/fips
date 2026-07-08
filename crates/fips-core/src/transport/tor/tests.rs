use super::*;
use crate::transport::{Transport, packet_channel};

fn make_config() -> TorConfig {
    TorConfig {
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        ..Default::default()
    }
}

#[test]
fn test_parse_tor_addr_onion() {
    let addr = TransportAddr::from_string("abcdef1234567890.onion:2121");
    let tor_addr = parse_tor_addr(&addr).unwrap();
    match tor_addr {
        TorAddr::Onion(host, port) => {
            assert_eq!(host, "abcdef1234567890.onion");
            assert_eq!(port, 2121);
        }
        _ => panic!("expected Onion variant"),
    }
}

#[test]
fn test_parse_tor_addr_clearnet() {
    let addr = TransportAddr::from_string("192.168.1.1:8080");
    let tor_addr = parse_tor_addr(&addr).unwrap();
    match tor_addr {
        TorAddr::Clearnet(socket_addr) => {
            assert_eq!(
                socket_addr,
                "192.168.1.1:8080".parse::<SocketAddr>().unwrap()
            );
        }
        _ => panic!("expected Clearnet variant"),
    }
}

#[test]
fn test_parse_tor_addr_clearnet_hostname() {
    let addr = TransportAddr::from_string("peer1.example.com:2121");
    let tor_addr = parse_tor_addr(&addr).unwrap();
    match tor_addr {
        TorAddr::ClearnetHostname(host, port) => {
            assert_eq!(host, "peer1.example.com");
            assert_eq!(port, 2121);
        }
        _ => panic!("expected ClearnetHostname variant"),
    }
}

#[test]
fn test_parse_tor_addr_invalid() {
    // Bare name without a dot — not a valid hostname
    let addr = TransportAddr::from_string("localhost:2121");
    assert!(parse_tor_addr(&addr).is_err());

    // No port
    let addr = TransportAddr::from_string("not-a-valid-address");
    assert!(parse_tor_addr(&addr).is_err());

    // Invalid port
    let addr = TransportAddr::from_string("example.com:notaport");
    assert!(parse_tor_addr(&addr).is_err());
}

#[test]
fn test_config_defaults() {
    let config = TorConfig::default();
    assert_eq!(config.mode(), "socks5");
    assert_eq!(config.socks5_addr(), "127.0.0.1:9050");
    assert_eq!(config.connect_timeout_ms(), 120000);
    assert_eq!(config.mtu(), 1400);
    assert_eq!(config.advertised_port(), 443);
}

#[test]
fn test_advertised_port_override() {
    let config = TorConfig {
        advertised_port: Some(9001),
        ..Default::default()
    };
    assert_eq!(config.advertised_port(), 9001);
}

/// Pins the publisher/parser contract for Tor overlay adverts.
/// `build_overlay_advert` formats Tor endpoints as `<onion>:<port>`;
/// `parse_tor_addr` must accept that exact form back. A bare onion
/// (no port) was the production bug — assert it does not parse.
#[test]
fn test_advert_address_round_trips_through_parser() {
    let onion = "mwvj6q3pnsiaky7i6wg5s42xlfurt5uqr3qzckrlw2graa2ugcgwhiqd.onion";
    let cfg = TorConfig::default();
    let advertised = format!("{}:{}", onion, cfg.advertised_port());

    let parsed = parse_tor_addr(&TransportAddr::from_string(&advertised)).unwrap();
    match parsed {
        TorAddr::Onion(host, port) => {
            assert_eq!(host, onion);
            assert_eq!(port, 443);
        }
        other => panic!("expected Onion variant, got {:?}", other),
    }

    // Sanity-check the inverse: the bare-onion form (the bug) must
    // not parse, so any future regression in the publisher will be
    // caught by the round-trip test above.
    assert!(parse_tor_addr(&TransportAddr::from_string(onion)).is_err());
}

#[tokio::test]
async fn test_start_stop() {
    let (tx, _rx) = packet_channel(32);
    let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    transport.start_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Up);

    transport.stop_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Down);
}

#[tokio::test]
async fn test_double_start_fails() {
    let (tx, _rx) = packet_channel(32);
    let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    transport.start_async().await.unwrap();
    assert!(transport.start_async().await.is_err());
}

#[tokio::test]
async fn test_stop_not_started_fails() {
    let (tx, _rx) = packet_channel(32);
    let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    assert!(transport.stop_async().await.is_err());
}

#[tokio::test]
async fn test_send_not_started() {
    let (tx, _rx) = packet_channel(32);
    let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    let addr = TransportAddr::from_string("127.0.0.1:2121");
    let result = transport.send_async(&addr, &[0u8; 10]).await;
    assert!(result.is_err());
}

#[test]
fn test_transport_type() {
    let (tx, _rx) = packet_channel(32);
    let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    let tt = transport.transport_type();
    assert_eq!(tt.name, "tor");
    assert!(tt.connection_oriented);
    assert!(tt.reliable);
}

#[test]
fn test_sync_methods_return_not_supported() {
    let (tx, _rx) = packet_channel(32);
    let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    assert!(transport.start().is_err());
    assert!(transport.stop().is_err());
    let addr = TransportAddr::from_string("127.0.0.1:2121");
    assert!(transport.send(&addr, &[0u8; 10]).is_err());
}

#[test]
fn test_accept_connections_false() {
    let (tx, _rx) = packet_channel(32);
    let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    assert!(!transport.accept_connections());
}

#[test]
fn test_discover_returns_empty() {
    let (tx, _rx) = packet_channel(32);
    let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

    assert!(transport.discover().unwrap().is_empty());
}

#[tokio::test]
async fn test_invalid_socks5_addr_start_fails() {
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        socks5_addr: Some("not-a-socket-addr".to_string()),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
    assert!(transport.start_async().await.is_err());
}

#[tokio::test]
async fn test_unsupported_mode_start_fails() {
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        mode: Some("embedded".to_string()),
        socks5_addr: Some("127.0.0.1:9050".to_string()),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
    assert!(transport.start_async().await.is_err());
}

// ========================================================================
// Integration tests using MockSocks5Server
// ========================================================================

use crate::config::TcpConfig;
use crate::transport::tcp::TcpTransport;
use mock_socks5::MockSocks5Server;

/// msg1 wire size: 4 prefix + 4 sender_idx + 106 noise_msg1 = 114 bytes.
const MSG1_WIRE_SIZE: usize = 114;
/// msg1 payload_len: sender_idx(4) + noise_msg1(106) = 110.
const MSG1_PAYLOAD_LEN: u16 = (MSG1_WIRE_SIZE - 4) as u16;

/// Build a msg1 frame (114 bytes) for testing.
fn build_msg1_frame() -> Vec<u8> {
    let mut frame = vec![0xAA; MSG1_WIRE_SIZE];
    frame[0] = 0x01; // ver=0, phase=1
    frame[1] = 0x00; // flags
    frame[2..4].copy_from_slice(&MSG1_PAYLOAD_LEN.to_le_bytes());
    frame
}

#[tokio::test]
async fn test_send_recv_via_socks5() {
    // Set up a TCP transport as the "destination" with a listener
    let (dest_tx, mut dest_rx) = packet_channel(32);
    let dest_config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let mut dest = TcpTransport::new(TransportId::new(100), None, dest_config, dest_tx);
    dest.start_async().await.unwrap();
    let dest_addr = dest.local_addr().unwrap();

    // Set up the mock SOCKS5 proxy pointing at the destination
    let mock = MockSocks5Server::new(dest_addr).await.unwrap();
    let proxy_addr = mock.addr();
    let _proxy_handle = mock.spawn();

    // Set up the Tor transport pointing at the mock proxy
    let (tor_tx, _tor_rx) = packet_channel(32);
    let tor_config = TorConfig {
        socks5_addr: Some(proxy_addr.to_string()),
        ..Default::default()
    };
    let mut tor = TorTransport::new(TransportId::new(200), None, tor_config, tor_tx);
    tor.start_async().await.unwrap();

    // Send a valid FMP frame (msg1) through the Tor transport
    let frame = build_msg1_frame();
    let target = TransportAddr::from_string(&dest_addr.to_string());
    tor.send_async(&target, &frame).await.unwrap();

    // Receive it on the destination
    let received = tokio::time::timeout(Duration::from_secs(5), dest_rx.recv())
        .await
        .expect("timeout waiting for packet")
        .expect("channel closed");

    assert_eq!(received.data.as_slice(), frame.as_slice());

    // Clean up
    tor.stop_async().await.unwrap();
    dest.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_socks5_proxy_down() {
    // No SOCKS5 server running on this port
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        socks5_addr: Some("127.0.0.1:19999".to_string()),
        connect_timeout_ms: Some(2000),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();

    let addr = TransportAddr::from_string("192.168.1.1:2121");
    let result = transport.send_async(&addr, &build_msg1_frame()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_connect_timeout() {
    // Use a non-routable address as the SOCKS5 proxy to trigger timeout
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        // 192.0.2.1 is TEST-NET, should be non-routable and timeout
        socks5_addr: Some("192.0.2.1:9050".to_string()),
        connect_timeout_ms: Some(500),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();

    let addr = TransportAddr::from_string("10.0.0.1:2121");
    let result = transport.send_async(&addr, &build_msg1_frame()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_close_connection() {
    // Set up destination + mock proxy
    let (dest_tx, _dest_rx) = packet_channel(32);
    let dest_config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let mut dest = TcpTransport::new(TransportId::new(100), None, dest_config, dest_tx);
    dest.start_async().await.unwrap();
    let dest_addr = dest.local_addr().unwrap();

    let mock = MockSocks5Server::new(dest_addr).await.unwrap();
    let proxy_addr = mock.addr();
    let _proxy_handle = mock.spawn();

    let (tor_tx, _tor_rx) = packet_channel(32);
    let tor_config = TorConfig {
        socks5_addr: Some(proxy_addr.to_string()),
        ..Default::default()
    };
    let mut tor = TorTransport::new(TransportId::new(200), None, tor_config, tor_tx);
    tor.start_async().await.unwrap();

    // Send to establish a connection
    let target = TransportAddr::from_string(&dest_addr.to_string());
    tor.send_async(&target, &build_msg1_frame()).await.unwrap();

    // Verify pool has the connection
    {
        let pool = tor.pool.lock().await;
        assert_eq!(pool.len(), 1);
    }
    assert_eq!(tor.stats.snapshot().pool_outbound, 1);
    assert_eq!(tor.stats.snapshot().pool_inbound, 0);

    // Close the connection
    tor.close_connection_async(&target).await;

    // Verify pool is empty
    {
        let pool = tor.pool.lock().await;
        assert_eq!(pool.len(), 0);
    }
    assert_eq!(tor.stats.snapshot().pool_outbound, 0);

    tor.stop_async().await.unwrap();
    dest.stop_async().await.unwrap();
}

// ========================================================================
// Control port mode tests
// ========================================================================

use mock_control::MockTorControlServer;

#[tokio::test]
async fn test_control_port_start_stop() {
    let mock = MockTorControlServer::start().await;
    let (tx, _rx) = packet_channel(32);

    let config = TorConfig {
        mode: Some("control_port".to_string()),
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        control_addr: Some(mock.addr().to_string()),
        control_auth: Some("password:testpass".to_string()),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);

    transport.start_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Up);
    assert!(transport.onion_address().is_none());
    assert!(!transport.accept_connections());

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_config_defaults_phase2() {
    let config = TorConfig::default();
    assert_eq!(config.control_addr(), "/run/tor/control");
    assert_eq!(config.control_auth(), "cookie");
    assert_eq!(config.cookie_path(), "/var/run/tor/control.authcookie");
    assert_eq!(config.max_inbound_connections(), 64);
}

// ========================================================================
// Directory mode tests
// ========================================================================

use crate::config::DirectoryServiceConfig;
use tempfile::TempDir;

#[test]
fn test_directory_service_config_defaults() {
    let config = DirectoryServiceConfig::default();
    assert_eq!(
        config.hostname_file(),
        "/var/lib/tor/fips_onion_service/hostname"
    );
    assert_eq!(config.bind_addr(), "127.0.0.1:8443");
}

#[tokio::test]
async fn test_directory_mode_start_stop() {
    let dir = TempDir::new().unwrap();
    let hostname_path = dir.path().join("hostname");
    std::fs::write(
        &hostname_path,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.onion\n",
    )
    .unwrap();

    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        mode: Some("directory".to_string()),
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        directory_service: Some(DirectoryServiceConfig {
            hostname_file: Some(hostname_path.to_str().unwrap().to_string()),
            bind_addr: Some("127.0.0.1:0".to_string()),
        }),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);

    transport.start_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Up);
    assert_eq!(
        transport.onion_address(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.onion"),
    );
    assert!(transport.accept_connections());

    transport.stop_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Down);
}

#[tokio::test]
async fn test_directory_mode_missing_hostname_file() {
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        mode: Some("directory".to_string()),
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        directory_service: Some(DirectoryServiceConfig {
            hostname_file: Some("/nonexistent/hostname".to_string()),
            bind_addr: Some("127.0.0.1:0".to_string()),
        }),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);

    let result = transport.start_async().await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("hostname"));
}

#[tokio::test]
async fn test_directory_mode_invalid_hostname() {
    let dir = TempDir::new().unwrap();
    let hostname_path = dir.path().join("hostname");
    std::fs::write(&hostname_path, "not-an-onion-address\n").unwrap();

    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        mode: Some("directory".to_string()),
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        directory_service: Some(DirectoryServiceConfig {
            hostname_file: Some(hostname_path.to_str().unwrap().to_string()),
            bind_addr: Some("127.0.0.1:0".to_string()),
        }),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);

    let result = transport.start_async().await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("invalid onion address"));
}

#[tokio::test]
async fn test_directory_mode_accept_inbound() {
    let dir = TempDir::new().unwrap();
    let hostname_path = dir.path().join("hostname");
    std::fs::write(
        &hostname_path,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.onion\n",
    )
    .unwrap();

    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        mode: Some("directory".to_string()),
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        directory_service: Some(DirectoryServiceConfig {
            hostname_file: Some(hostname_path.to_str().unwrap().to_string()),
            bind_addr: Some("127.0.0.1:0".to_string()),
        }),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();
    assert!(transport.accept_connections());

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_socks5_mode_rejects_directory_service_config() {
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        mode: Some("socks5".to_string()),
        socks5_addr: Some("127.0.0.1:9050".to_string()),
        directory_service: Some(DirectoryServiceConfig::default()),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
    let result = transport.start_async().await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("directory"));
}
