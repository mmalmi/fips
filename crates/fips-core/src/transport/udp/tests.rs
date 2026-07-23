use super::*;

use crate::transport::packet_channel;
use tokio::time::{Duration, timeout};

fn make_config(port: u16) -> UdpConfig {
    UdpConfig {
        bind_addr: Some(format!("127.0.0.1:{}", port)),
        mtu: Some(1280),
        ..Default::default()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn udp_receive_batch_width_matches_dataplane_reference() {
    assert_eq!(UDP_RECV_BATCH_SIZE, 128);
}

#[test]
fn proc_net_snmp_udp_parser_reads_rcvbuf_errors() {
    let contents = "\
Ip: Forwarding DefaultTTL InReceives\n\
Ip: 1 64 123\n\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
Udp: 10 0 7 12 42 0 0 0 0\n\
";
    assert_eq!(parse_proc_net_snmp_udp_rcvbuf_errors(contents), Some(42));
    assert_eq!(
        parse_proc_net_snmp_udp_rcvbuf_errors("Udp: InDatagrams\n"),
        None
    );
}

#[test]
fn udp_namespace_drop_sampling_is_bounded_and_keeps_last_good_value() {
    let started_at = Instant::now();
    let mut snapshot = LinuxUdpRcvbufErrorSnapshot::new(10, started_at);
    let mut reads = 0;

    assert_eq!(
        snapshot.namespace_drops(started_at + Duration::from_secs(1), || {
            reads += 1;
            Some(15)
        }),
        0
    );
    assert_eq!(reads, 0, "the one-second node tick must not read /proc/net/snmp");

    assert_eq!(
        snapshot.namespace_drops(
            started_at + LINUX_UDP_RCVBUF_ERRORS_POLL_INTERVAL,
            || {
                reads += 1;
                Some(15)
            },
        ),
        5
    );
    assert_eq!(reads, 1);

    assert_eq!(
        snapshot.namespace_drops(started_at + Duration::from_secs(11), || {
            reads += 1;
            Some(99)
        }),
        5
    );
    assert_eq!(reads, 1);

    assert_eq!(
        snapshot.namespace_drops(started_at + Duration::from_secs(20), || {
            reads += 1;
            None
        }),
        5,
        "a transient procfs read failure must retain the last observed count"
    );
    assert_eq!(reads, 2);
}

#[tokio::test]
async fn test_start_stop() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    assert_eq!(transport.state(), TransportState::Configured);

    transport.start_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Up);
    assert!(transport.local_addr().is_some());

    transport.stop_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Down);
}

#[tokio::test]
async fn configured_udp_transport_recovers_socket_after_local_route_failure() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    transport.start_async().await.unwrap();
    #[cfg(unix)]
    let before = transport.send_snapshot().unwrap();

    assert!(transport.recover_local_route_socket().await.unwrap());
    assert_eq!(transport.state(), TransportState::Up);

    #[cfg(unix)]
    let after = transport.send_snapshot().unwrap();
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        assert_ne!(before.socket.as_raw_fd(), after.socket.as_raw_fd());
    }

    assert!(
        !transport.recover_local_route_socket().await.unwrap(),
        "repeated route errors must not churn the UDP socket during the recovery cooldown"
    );

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_double_start_fails() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    transport.start_async().await.unwrap();

    let result = transport.start_async().await;
    assert!(matches!(result, Err(TransportError::AlreadyStarted)));

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn exclusive_start_reports_address_in_use_and_can_retry() {
    let (owner_tx, _owner_rx) = packet_channel(100);
    let mut owner = UdpTransport::new(TransportId::new(1), None, make_config(0), owner_tx);
    owner.start_exclusive_async().await.unwrap();
    let owner_addr = owner.local_addr().unwrap();

    let (candidate_tx, _candidate_rx) = packet_channel(100);
    let mut candidate = UdpTransport::new(
        TransportId::new(2),
        None,
        make_config(owner_addr.port()),
        candidate_tx,
    );
    assert!(matches!(
        candidate.start_exclusive_async().await,
        Err(TransportError::AddressInUse { address, .. }) if address == owner_addr
    ));
    assert_eq!(candidate.state(), TransportState::Failed);

    owner.stop_async().await.unwrap();
    candidate.start_exclusive_async().await.unwrap();
    assert_eq!(candidate.local_addr(), Some(owner_addr));
    candidate.stop_async().await.unwrap();
}

#[tokio::test]
async fn exclusive_transport_recovery_preserves_ownership_bind() {
    let (owner_tx, _owner_rx) = packet_channel(100);
    let mut owner = UdpTransport::new(TransportId::new(1), None, make_config(0), owner_tx);
    owner.start_exclusive_async().await.unwrap();
    let owner_addr = owner.local_addr().unwrap();

    assert!(!owner.recover_local_route_socket().await.unwrap());

    let (candidate_tx, _candidate_rx) = packet_channel(100);
    let mut candidate = UdpTransport::new(
        TransportId::new(2),
        None,
        make_config(owner_addr.port()),
        candidate_tx,
    );
    assert!(matches!(
        candidate.start_exclusive_async().await,
        Err(TransportError::AddressInUse { address, .. }) if address == owner_addr
    ));

    owner.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_stop_not_started_fails() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    let result = transport.stop_async().await;
    assert!(matches!(result, Err(TransportError::NotStarted)));
}

#[tokio::test]
async fn test_send_recv() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = UdpTransport::new(TransportId::new(1), None, make_config(0), tx1);
    let mut t2 = UdpTransport::new(TransportId::new(2), None, make_config(0), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr1 = t1.local_addr().unwrap();
    let addr2 = t2.local_addr().unwrap();

    // Send from t1 to t2
    let data = b"hello world";
    let bytes_sent = t1
        .send_async(&TransportAddr::from_string(&addr2.to_string()), data)
        .await
        .unwrap();
    assert_eq!(bytes_sent, data.len());

    // Receive on t2
    let packet = timeout(Duration::from_secs(1), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(packet.data.as_slice(), &data[..]);
    assert_eq!(
        packet.remote_addr.as_str(),
        Some(addr1.to_string().as_str())
    );

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_bidirectional() {
    let (tx1, mut rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = UdpTransport::new(TransportId::new(1), None, make_config(0), tx1);
    let mut t2 = UdpTransport::new(TransportId::new(2), None, make_config(0), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr1 = TransportAddr::from_string(&t1.local_addr().unwrap().to_string());
    let addr2 = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());

    // Send from t1 to t2
    t1.send_async(&addr2, b"ping").await.unwrap();

    // Receive on t2
    let packet = timeout(Duration::from_secs(1), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(packet.data.as_slice(), &b"ping"[..]);

    // Send from t2 to t1
    t2.send_async(&addr1, b"pong").await.unwrap();

    // Receive on t1
    let packet = timeout(Duration::from_secs(1), rx1.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(packet.data.as_slice(), &b"pong"[..]);

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_mtu_exceeded() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = UdpTransport::new(
        TransportId::new(1),
        None,
        UdpConfig {
            mtu: Some(100),
            ..make_config(0)
        },
        tx,
    );

    transport.start_async().await.unwrap();

    let oversized = vec![0u8; 200];
    let result = transport
        .send_async(&TransportAddr::from_string("127.0.0.1:9999"), &oversized)
        .await;

    assert!(matches!(result, Err(TransportError::MtuExceeded { .. })));

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_send_not_started() {
    let (tx, _rx) = packet_channel(100);
    let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    let result = transport
        .send_async(&TransportAddr::from_string("127.0.0.1:9999"), b"test")
        .await;

    assert!(matches!(result, Err(TransportError::NotStarted)));
}

#[tokio::test]
async fn test_discover_returns_empty() {
    let (tx, _rx) = packet_channel(100);
    let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    // Discovery returns empty until multicast/DNS-SD is implemented
    let peers = transport.discover().unwrap();
    assert!(peers.is_empty());
}

#[test]
fn test_transport_type() {
    let (tx, _rx) = packet_channel(100);
    let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    assert_eq!(transport.transport_type().name, "udp");
    assert!(!transport.transport_type().connection_oriented);
    assert!(!transport.transport_type().reliable);
}

#[test]
fn test_sync_methods_return_not_supported() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    assert!(matches!(
        transport.start(),
        Err(TransportError::NotSupported(_))
    ));
    assert!(matches!(
        transport.stop(),
        Err(TransportError::NotSupported(_))
    ));
    assert!(matches!(
        transport.send(&TransportAddr::from_string("test"), b"data"),
        Err(TransportError::NotSupported(_))
    ));
}

#[tokio::test]
async fn test_resolve_socket_addr_ip() {
    let addr = TransportAddr::from_string("192.168.1.1:2121");
    let result = resolve_socket_addr(&addr).await.unwrap();
    assert_eq!(result.to_string(), "192.168.1.1:2121");
}

#[tokio::test]
async fn test_resolve_socket_addr_invalid() {
    let invalid = TransportAddr::from_string("nonexistent.invalid:2121");
    assert!(resolve_socket_addr(&invalid).await.is_err());

    let binary = TransportAddr::new(vec![0xff, 0x80]);
    assert!(resolve_socket_addr(&binary).await.is_err());
}

#[tokio::test]
async fn test_resolve_socket_addr_hostname() {
    let addr = TransportAddr::from_string("localhost:2121");
    let result = resolve_socket_addr(&addr).await.unwrap();
    // localhost should resolve to 127.0.0.1 or [::1]
    assert!(result.ip().is_loopback());
    assert_eq!(result.port(), 2121);
}

#[tokio::test]
async fn test_congestion_reports_kernel_drops() {
    let (tx, _rx) = packet_channel(100);
    let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

    // Before start, congestion should still report (from stats)
    let cong = transport.congestion();
    assert_eq!(cong.socket_recv_drops, Some(0));
    #[cfg(target_os = "linux")]
    assert_eq!(cong.recv_drops, cong.namespace_recv_drops);
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(cong.recv_drops, Some(0));
        assert_eq!(cong.namespace_recv_drops, None);
    }
}

#[test]
fn test_accept_connections_default_true() {
    let (tx, _rx) = packet_channel(100);
    let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);
    // Default UdpConfig has accept_connections unset → true.
    assert!(transport.accept_connections());
}

#[test]
fn test_accept_connections_false_when_configured() {
    let (tx, _rx) = packet_channel(100);
    let transport = UdpTransport::new(
        TransportId::new(1),
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            accept_connections: Some(false),
            ..Default::default()
        },
        tx,
    );
    assert!(!transport.accept_connections());
}

#[test]
fn test_accept_connections_forced_false_in_outbound_only() {
    let (tx, _rx) = packet_channel(100);
    let transport = UdpTransport::new(
        TransportId::new(1),
        None,
        UdpConfig {
            outbound_only: Some(true),
            accept_connections: Some(true), // explicit true; outbound_only wins
            ..Default::default()
        },
        tx,
    );
    assert!(!transport.accept_connections());
}

#[test]
fn public_inbound_udp_is_operator_routing_adjacency_only_for_responder() {
    let (packet_tx, _packet_rx) = packet_channel(8);
    let public = UdpTransport::new(
        TransportId::new(41),
        None,
        UdpConfig {
            bind_addr: Some("0.0.0.0:2121".to_string()),
            public: Some(true),
            accept_connections: Some(true),
            ..UdpConfig::default()
        },
        packet_tx.clone(),
    );
    assert!(public.is_operator_routing_adjacency(false));
    assert!(!public.is_operator_routing_adjacency(true));

    let ordinary = UdpTransport::new(
        TransportId::new(42),
        None,
        UdpConfig {
            bind_addr: Some("0.0.0.0:0".to_string()),
            public: Some(false),
            accept_connections: Some(true),
            ..UdpConfig::default()
        },
        packet_tx,
    );
    assert!(!ordinary.is_operator_routing_adjacency(false));
}

#[tokio::test]
async fn test_outbound_only_binds_ephemeral() {
    // outbound_only=true must override bind_addr to 0.0.0.0:0 so the
    // kernel picks a source port and there is no listener on a known
    // port. The runtime should bind successfully even if `bind_addr`
    // is explicitly set in the config (a warn fires; not asserted
    // here).
    let (tx, _rx) = packet_channel(100);
    let mut transport = UdpTransport::new(
        TransportId::new(1),
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:65535".to_string()),
            outbound_only: Some(true),
            ..Default::default()
        },
        tx,
    );

    transport.start_async().await.unwrap();
    let local = transport.local_addr().unwrap();
    // Ephemeral port: kernel-assigned, non-zero, never matches the
    // configured 65535 (since outbound_only ignored bind_addr).
    assert_ne!(local.port(), 65535);
    assert!(local.port() > 0);
    // Source IP picked by the kernel; v4 INADDR_ANY before binding,
    // resolves to 0.0.0.0 on the local end.
    assert!(local.ip().is_unspecified());
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_punch_probe_dropped() {
    let (tx_recv, mut rx_recv) = packet_channel(100);
    let (tx_send, _rx_send) = packet_channel(100);

    let mut t_recv = UdpTransport::new(TransportId::new(1), None, make_config(0), tx_recv);
    let mut t_send = UdpTransport::new(TransportId::new(2), None, make_config(0), tx_send);

    t_recv.start_async().await.unwrap();
    t_send.start_async().await.unwrap();

    let recv_addr = t_recv.local_addr().unwrap();
    let recv_addr_str = TransportAddr::from_string(&recv_addr.to_string());

    // Probe (PUNCH_MAGIC = "NPTC", be) followed by sequence + payload.
    let mut probe = vec![0u8; 16];
    probe[..4].copy_from_slice(&0x4E505443u32.to_be_bytes());
    t_send.send_async(&recv_addr_str, &probe).await.unwrap();

    // Ack (PUNCH_ACK_MAGIC = "NPTA", be).
    let mut ack = vec![0u8; 16];
    ack[..4].copy_from_slice(&0x4E505441u32.to_be_bytes());
    t_send.send_async(&recv_addr_str, &ack).await.unwrap();

    // A real (non-punch) packet must still arrive.
    let real = b"valid-fmp-frame";
    t_send.send_async(&recv_addr_str, real).await.unwrap();

    // First message read should be the real one — punch probe + ack
    // both filtered silently.
    let packet = timeout(Duration::from_secs(1), rx_recv.recv())
        .await
        .expect("timeout waiting for real packet")
        .expect("channel closed");
    assert_eq!(packet.data.as_slice(), &real[..]);

    // No further packets should be queued (probe + ack dropped).
    let no_more = timeout(Duration::from_millis(200), rx_recv.recv()).await;
    assert!(no_more.is_err(), "punch probe/ack leaked through filter");

    t_recv.stop_async().await.unwrap();
    t_send.stop_async().await.unwrap();
}

#[test]
fn test_is_punch_packet_helper() {
    use crate::discovery::is_punch_packet;
    // PUNCH_MAGIC ("NPTC", be)
    assert!(is_punch_packet(&[0x4E, 0x50, 0x54, 0x43, 0xAA, 0xBB]));
    // PUNCH_ACK_MAGIC ("NPTA", be)
    assert!(is_punch_packet(&[0x4E, 0x50, 0x54, 0x41]));
    // Non-magic packet
    assert!(!is_punch_packet(&[0x01, 0x02, 0x03, 0x04]));
    // Too short
    assert!(!is_punch_packet(&[0x4E, 0x50, 0x54]));
    assert!(!is_punch_packet(&[]));
}

#[tokio::test]
async fn test_send_recv_ip_string() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = UdpTransport::new(TransportId::new(1), None, make_config(0), tx1);
    let mut t2 = UdpTransport::new(TransportId::new(2), None, make_config(0), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let port2 = t2.local_addr().unwrap().port();

    // Send using IP string address
    let data = b"hello via ip string";
    let bytes_sent = t1
        .send_async(
            &TransportAddr::from_string(&format!("127.0.0.1:{}", port2)),
            data,
        )
        .await
        .unwrap();
    assert_eq!(bytes_sent, data.len());

    // Receive on t2
    let packet = timeout(Duration::from_secs(1), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(packet.data.as_slice(), &data[..]);

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}
