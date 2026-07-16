use super::*;

use crate::transport::packet_channel;
use tokio::time::{Duration, timeout};

fn make_config() -> TcpConfig {
    TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        ..Default::default()
    }
}

fn make_outbound_config() -> TcpConfig {
    TcpConfig {
        bind_addr: None,
        mtu: Some(1400),
        ..Default::default()
    }
}

fn build_msg1_frame(fill: u8) -> Vec<u8> {
    let mut frame = vec![fill; 114];
    frame[0] = 0x01;
    frame[1] = 0x00;
    frame[2..4].copy_from_slice(&110u16.to_le_bytes());
    frame
}

async fn unused_loopback_addr(except_port: u16) -> SocketAddr {
    for port in 49152..65535 {
        if port == except_port {
            continue;
        }
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpStream::connect(addr).await.is_err() {
            return addr;
        }
    }
    panic!("no unused loopback port found");
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn test_start_stop() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    assert_eq!(transport.state(), TransportState::Configured);

    transport.start_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Up);
    assert!(transport.local_addr().is_some());

    transport.stop_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Down);
}

#[tokio::test]
async fn connect_to_any_addr_tries_later_candidates() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good_addr = listener.local_addr().unwrap();
    let bad_addr = unused_loopback_addr(good_addr.port()).await;
    let accept = tokio::spawn(async move { listener.accept().await });

    let stream = connect_to_any_addr(&[bad_addr, good_addr], 1_000)
        .await
        .expect("second TCP candidate should connect");
    drop(stream);

    timeout(Duration::from_secs(1), accept)
        .await
        .expect("listener should accept")
        .expect("accept task should not panic")
        .expect("accept should succeed");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transport_handle_bounds_a_stalled_tcp_write() {
    use tokio::io::AsyncReadExt as _;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(stream);
    });

    let (tx, _rx) = packet_channel(100);
    let mut config = make_outbound_config();
    config.send_buf_size = Some(16 * 1024);
    let mut transport = TcpTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();
    let mut handle = crate::transport::TransportHandle::Tcp(transport);
    let remote = TransportAddr::from_string(&remote.to_string());
    let mut payload =
        vec![
            0u8;
            crate::proto::fsp_wire::FSP_HEADER_SIZE + u16::MAX as usize + crate::noise::TAG_SIZE
        ];
    payload[0] = crate::proto::fsp_wire::FSP_PHASE_ESTABLISHED;
    payload[1] = crate::proto::fsp_wire::FSP_FLAG_DIRECT_TRANSPORT;
    payload[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    let started = tokio::time::Instant::now();
    let mut sent = 0usize;

    loop {
        match handle.send(&remote, &payload).await {
            Ok(_) => sent += 1,
            Err(TransportError::Timeout) => break,
            Err(error) => panic!("unexpected stalled-write result: {error:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    assert!(sent > 0);
    assert!(started.elapsed() < Duration::from_secs(2));
    accept.abort();

    let crate::transport::TransportHandle::Tcp(tcp) = &handle else {
        unreachable!("test handle is TCP")
    };
    assert!(
        !tcp.pool.lock().await.contains_key(&remote),
        "a timed-out partial writer must not remain reusable"
    );

    let clean_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let clean_remote =
        TransportAddr::from_string(&clean_listener.local_addr().unwrap().to_string());
    let clean_frame = build_msg1_frame(0x5a);
    let expected = clean_frame.clone();
    let clean_accept = tokio::spawn(async move {
        let (mut stream, _) = clean_listener.accept().await.unwrap();
        let mut received = vec![0u8; expected.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
    });
    handle
        .send(&clean_remote, &clean_frame)
        .await
        .expect("a clean connection remains usable after evicting the poisoned writer");
    timeout(Duration::from_secs(1), clean_accept)
        .await
        .expect("clean connection should receive the complete next record")
        .expect("clean accept task should not panic");
    handle.stop().await.unwrap();
}

#[tokio::test]
async fn test_start_outbound_only() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);

    transport.start_async().await.unwrap();
    assert_eq!(transport.state(), TransportState::Up);
    // No listener, so no local_addr
    assert!(transport.local_addr().is_none());

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_double_start_fails() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    transport.start_async().await.unwrap();

    let result = transport.start_async().await;
    assert!(matches!(result, Err(TransportError::AlreadyStarted)));

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_stop_not_started_fails() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    let result = transport.stop_async().await;
    assert!(matches!(result, Err(TransportError::NotStarted)));
}

#[tokio::test]
async fn test_send_not_started() {
    let (tx, _rx) = packet_channel(100);
    let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    let result = transport
        .send_async(&TransportAddr::from_string("127.0.0.1:9999"), b"test")
        .await;

    assert!(matches!(result, Err(TransportError::NotStarted)));
}

#[tokio::test]
async fn test_send_recv() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
    let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr2 = t2.local_addr().unwrap();

    // Build a valid FMP established frame to send
    // [ver+phase:1][flags:1][payload_len:2 LE][12 bytes header][payload bytes][16 bytes tag]
    let payload_len = 4u16;
    let total = 4 + 12 + payload_len as usize + 16;
    let mut frame = vec![0u8; total];
    frame[0] = 0x00; // ver=0, phase=0 (established)
    frame[1] = 0x00; // flags
    frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
    // Fill the rest with a recognizable pattern
    for (i, byte) in frame[4..total].iter_mut().enumerate() {
        *byte = ((4 + i) & 0xFF) as u8;
    }

    let bytes_sent = t1
        .send_async(&TransportAddr::from_string(&addr2.to_string()), &frame)
        .await
        .unwrap();
    assert_eq!(bytes_sent, frame.len());

    // Receive on t2
    let packet = timeout(Duration::from_secs(2), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(packet.data.as_slice(), frame.as_slice());

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn inbound_first_frame_timeout_closes_slowloris_connection() {
    use tokio::io::AsyncWriteExt as _;

    let (tx, mut rx) = packet_channel(100);
    let config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        first_frame_timeout_ms: Some(50),
        max_inbound_connections: Some(1),
        ..Default::default()
    };
    let mut transport = TcpTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();

    let addr = transport.local_addr().unwrap();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"\x01").await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if transport.stats.snapshot().first_frame_timeouts >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("slowloris connection should hit first-frame timeout");

    let pool = transport.pool.lock().await;
    assert_eq!(pool.len(), 0);
    drop(pool);
    assert_eq!(transport.stats.snapshot().pool_inbound, 0);

    let mut successor = TcpStream::connect(addr).await.unwrap();
    let successor_frame = build_msg1_frame(0x77);
    successor.write_all(&successor_frame).await.unwrap();
    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("valid successor should recover the inbound slot")
        .expect("packet channel should remain open");
    assert_eq!(received.data.as_slice(), successor_frame.as_slice());
    drop(successor);

    timeout(Duration::from_secs(1), async {
        while transport.stats.snapshot().pool_inbound != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("successor EOF should release its exact generation");

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn stale_receive_cleanup_preserves_successor_generation_and_gauge() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old_client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (old_server, _) = listener.accept().await.unwrap();
    let (old_reader, old_writer) = old_server.into_split();
    let old_io = Arc::new(StreamConnectionIo::new(old_writer));

    let successor_client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (successor_server, _) = listener.accept().await.unwrap();
    let (_successor_reader, successor_writer) = successor_server.into_split();
    let successor_io = Arc::new(StreamConnectionIo::new(successor_writer));
    let successor_task = tokio::spawn(std::future::pending::<()>());

    let addr = TransportAddr::from_string("stale-generation.test:21211");
    let pool = Arc::new(Mutex::new(HashMap::new()));
    pool.lock().await.insert(
        addr.clone(),
        TcpConnection {
            io: successor_io.clone(),
            recv_task: successor_task,
            direction: Direction::Outbound,
        },
    );
    let stats = Arc::new(TcpStats::new());
    stats.record_pool_outbound_added();
    let (packet_tx, _packet_rx) = packet_channel(1);

    drop(old_client);
    tcp_receive_loop(
        old_reader,
        TcpReceiveContext {
            transport_id: TransportId::new(44),
            remote_addr: addr.clone(),
            packet_tx,
            pool: pool.clone(),
            stats: stats.clone(),
            first_frame_timeout: None,
            frame_completion_timeout: DEFAULT_FRAME_COMPLETION_TIMEOUT,
            direction: Direction::Inbound,
            io: old_io,
        },
    )
    .await;

    let mut pool = pool.lock().await;
    let successor = pool.get(&addr).expect("stale cleanup removed successor");
    assert!(Arc::ptr_eq(&successor.io, &successor_io));
    assert_eq!(stats.snapshot().pool_inbound, 0);
    assert_eq!(stats.snapshot().pool_outbound, 1);
    let successor = pool.remove(&addr).unwrap();
    successor.recv_task.abort();
    drop(pool);
    drop(successor_client);
}

#[tokio::test]
async fn concurrent_first_sends_share_one_pooled_generation() {
    use tokio::io::AsyncReadExt as _;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_socket = listener.local_addr().unwrap();
    let frame_a = build_msg1_frame(0x31);
    let frame_b = build_msg1_frame(0x42);
    let expected_a = frame_a.clone();
    let expected_b = frame_b.clone();
    let receive = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("candidate connection should arrive")
                .unwrap();
            let mut records = vec![0u8; expected_a.len() + expected_b.len()];
            match timeout(Duration::from_secs(1), stream.read_exact(&mut records)).await {
                Ok(Ok(_)) => return records,
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => continue,
                other => panic!("winning connection did not carry both records: {other:?}"),
            }
        }
        panic!("no winning candidate carried both records")
    });

    let (packet_tx, _packet_rx) = packet_channel(1);
    let mut transport = TcpTransport::new(
        TransportId::new(45),
        None,
        make_outbound_config(),
        packet_tx,
    );
    transport.start_async().await.unwrap();
    let remote = TransportAddr::from_string(&remote_socket.to_string());
    let (sent_a, sent_b) = tokio::join!(
        transport.send_async(&remote, &frame_a),
        transport.send_async(&remote, &frame_b),
    );
    sent_a.unwrap();
    sent_b.unwrap();

    let records = receive.await.unwrap();
    let (first, second) = records.split_at(frame_a.len());
    assert!(
        (first == frame_a && second == frame_b) || (first == frame_b && second == frame_a),
        "both exact records must traverse the winning generation"
    );
    assert_eq!(transport.pool.lock().await.len(), 1);
    assert_eq!(transport.stats.snapshot().pool_outbound, 1);
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn background_promotion_keeps_open_and_replaces_closed_generation_once() {
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = TcpTransport::new(
        TransportId::new(46),
        None,
        make_outbound_config(),
        packet_tx,
    );
    let addr = TransportAddr::from_string("promotion-generation.test:443");

    let (_existing_peer, existing_stream) = tcp_pair().await;
    let (_existing_reader, existing_writer) = existing_stream.into_split();
    let existing_io = Arc::new(StreamConnectionIo::new(existing_writer));
    transport.pool.lock().await.insert(
        addr.clone(),
        TcpConnection {
            io: existing_io.clone(),
            recv_task: tokio::spawn(std::future::pending::<()>()),
            direction: Direction::Outbound,
        },
    );
    transport.stats.record_pool_outbound_added();

    let (_discarded_peer, discarded_candidate) = tcp_pair().await;
    {
        let mut pool = transport.pool.lock().await;
        transport.promote_connection_in_pool(&mut pool, &addr, discarded_candidate);
        assert!(Arc::ptr_eq(&pool.get(&addr).unwrap().io, &existing_io));
    }
    assert_eq!(transport.stats.snapshot().pool_outbound, 1);
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::Connected
    );

    existing_io.mark_closed();
    let (_replacement_peer, replacement_candidate) = tcp_pair().await;
    {
        let mut pool = transport.pool.lock().await;
        transport.promote_connection_in_pool(&mut pool, &addr, replacement_candidate);
        let replacement = &pool.get(&addr).unwrap().io;
        assert!(!Arc::ptr_eq(replacement, &existing_io));
        assert!(!replacement.is_closed());
    }
    assert_eq!(transport.stats.snapshot().pool_outbound, 1);
    assert_eq!(transport.stats.snapshot().connections_established, 1);
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::Connected
    );

    transport.close_connection_async(&addr).await;
    assert_eq!(transport.stats.snapshot().pool_outbound, 0);
}

#[tokio::test]
async fn outbound_pool_entry_does_not_consume_inbound_budget() {
    use tokio::io::AsyncWriteExt as _;

    let (subject_tx, mut subject_rx) = packet_channel(100);
    let subject_config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        max_inbound_connections: Some(1),
        mtu: Some(1400),
        ..Default::default()
    };
    let mut subject = TcpTransport::new(TransportId::new(1), None, subject_config, subject_tx);

    let (dest_tx, _dest_rx) = packet_channel(100);
    let mut dest = TcpTransport::new(TransportId::new(2), None, make_config(), dest_tx);

    subject.start_async().await.unwrap();
    dest.start_async().await.unwrap();

    let dest_addr = dest.local_addr().unwrap();
    subject
        .send_async(
            &TransportAddr::from_string(&dest_addr.to_string()),
            &build_msg1_frame(0xA1),
        )
        .await
        .unwrap();

    {
        let pool = subject.pool.lock().await;
        assert_eq!(pool.len(), 1, "subject should hold one outbound connection");
    }

    let subject_addr = subject.local_addr().unwrap();
    let mut inbound = TcpStream::connect(subject_addr).await.unwrap();
    let inbound_frame = build_msg1_frame(0xB2);
    inbound.write_all(&inbound_frame).await.unwrap();

    let packet = timeout(Duration::from_secs(1), subject_rx.recv())
        .await
        .expect("inbound frame should be admitted despite outbound pool entry")
        .expect("subject packet channel should stay open");
    assert_eq!(packet.data.as_slice(), inbound_frame.as_slice());

    subject.stop_async().await.unwrap();
    dest.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_bidirectional() {
    let (tx1, mut rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_config(), tx1);
    let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr1 = t1.local_addr().unwrap();
    let addr2 = t2.local_addr().unwrap();

    // Build valid FMP msg1 frame (114 bytes)
    let mut msg1_frame = vec![0xAA; 114];
    msg1_frame[0] = 0x01; // phase=msg1
    msg1_frame[1] = 0x00;
    msg1_frame[2..4].copy_from_slice(&110u16.to_le_bytes()); // payload_len = 110

    // Send from t1 to t2
    t1.send_async(&TransportAddr::from_string(&addr2.to_string()), &msg1_frame)
        .await
        .unwrap();

    let packet = timeout(Duration::from_secs(2), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(packet.data.as_slice(), msg1_frame.as_slice());

    // Build valid FMP msg2 frame (69 bytes)
    let mut msg2_frame = vec![0xBB; 69];
    msg2_frame[0] = 0x02; // phase=msg2
    msg2_frame[1] = 0x00;
    msg2_frame[2..4].copy_from_slice(&65u16.to_le_bytes()); // payload_len = 65

    // Send from t2 to t1
    t2.send_async(&TransportAddr::from_string(&addr1.to_string()), &msg2_frame)
        .await
        .unwrap();

    let packet = timeout(Duration::from_secs(2), rx1.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(packet.data.as_slice(), msg2_frame.as_slice());

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_connect_timeout() {
    let (tx, _rx) = packet_channel(100);
    let config = TcpConfig {
        bind_addr: None,
        connect_timeout_ms: Some(100), // Very short timeout
        ..Default::default()
    };
    let mut transport = TcpTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();

    // Try to connect to a non-routable address (should timeout)
    let result = transport
        .send_async(
            &TransportAddr::from_string("192.0.2.1:2121"),
            b"\x00\x00\x04\x00test1234567890123456789012345678",
        )
        .await;

    assert!(result.is_err());

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_close_connection() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, _rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
    let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr2 = t2.local_addr().unwrap();
    let remote = TransportAddr::from_string(&addr2.to_string());

    // Build valid msg1 frame to establish connection
    let mut msg1 = vec![0xAA; 114];
    msg1[0] = 0x01;
    msg1[1] = 0x00;
    msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

    t1.send_async(&remote, &msg1).await.unwrap();

    // Connection should exist
    {
        let pool = t1.pool.lock().await;
        assert!(pool.contains_key(&remote));
    }

    // Close it
    t1.close_connection_async(&remote).await;

    // Connection should be gone
    {
        let pool = t1.pool.lock().await;
        assert!(!pool.contains_key(&remote));
    }

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_discover_returns_empty() {
    let (tx, _rx) = packet_channel(100);
    let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    let peers = transport.discover().unwrap();
    assert!(peers.is_empty());
}

#[test]
fn test_transport_type() {
    let (tx, _rx) = packet_channel(100);
    let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    assert_eq!(transport.transport_type().name, "tcp");
    assert!(transport.transport_type().connection_oriented);
    assert!(transport.transport_type().reliable);
}

#[test]
fn test_sync_methods_return_not_supported() {
    let (tx, _rx) = packet_channel(100);
    let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

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

#[test]
fn test_accept_connections_with_bind() {
    let (tx, _rx) = packet_channel(100);
    let config = TcpConfig {
        bind_addr: Some("0.0.0.0:0".to_string()),
        ..Default::default()
    };
    let transport = TcpTransport::new(TransportId::new(1), None, config, tx);
    assert!(transport.accept_connections());
}

#[test]
fn test_accept_connections_without_bind() {
    let (tx, _rx) = packet_channel(100);
    let config = TcpConfig {
        bind_addr: None,
        ..Default::default()
    };
    let transport = TcpTransport::new(TransportId::new(1), None, config, tx);
    assert!(!transport.accept_connections());
}

#[tokio::test]
async fn test_connection_drop_and_reconnect() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
    let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr2 = t2.local_addr().unwrap();
    let remote = TransportAddr::from_string(&addr2.to_string());

    // Build valid msg1 frame
    let mut msg1 = vec![0xAA; 114];
    msg1[0] = 0x01;
    msg1[1] = 0x00;
    msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

    // First send establishes connection
    t1.send_async(&remote, &msg1).await.unwrap();
    let _ = timeout(Duration::from_secs(1), rx2.recv()).await;

    // Force-close the connection
    t1.close_connection_async(&remote).await;

    // Second send should reconnect (connect-on-send)
    t1.send_async(&remote, &msg1).await.unwrap();

    let packet = timeout(Duration::from_secs(2), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(packet.data.as_slice(), msg1.as_slice());

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn completed_background_dial_waits_for_pool_then_promotes_once() {
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = TcpTransport::new(
        TransportId::new(47),
        None,
        make_outbound_config(),
        packet_tx,
    );
    let remote = TransportAddr::from_string("completed-background.test:443");
    let (_peer, candidate) = tcp_pair().await;
    let task = tokio::spawn(async move { Ok::<_, TransportError>(candidate) });
    while !task.is_finished() {
        tokio::task::yield_now().await;
    }
    transport
        .connecting
        .lock()
        .await
        .insert(remote.clone(), ConnectingEntry { task });

    let occupied_pool = transport.pool.lock().await;
    assert_eq!(
        transport.connection_state_sync(&remote),
        ConnectionState::Connecting
    );
    assert_eq!(transport.connecting.lock().await.len(), 1);
    drop(occupied_pool);

    assert_eq!(
        transport.connection_state_sync(&remote),
        ConnectionState::Connected
    );
    assert!(transport.connecting.lock().await.is_empty());
    assert_eq!(transport.pool.lock().await.len(), 1);
    assert_eq!(transport.stats.snapshot().pool_outbound, 1);
    transport.close_connection_async(&remote).await;
    assert_eq!(transport.stats.snapshot().pool_outbound, 0);
}

#[tokio::test]
async fn test_connect_async_timeout() {
    let (tx, _rx) = packet_channel(100);
    let config = TcpConfig {
        bind_addr: None,
        connect_timeout_ms: Some(100), // Very short timeout
        ..Default::default()
    };
    let mut transport = TcpTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();

    let remote = TransportAddr::from_string("192.0.2.1:2121");
    transport.connect_async(&remote).await.unwrap();

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(500)).await;

    let state = transport.connection_state_sync(&remote);
    assert!(matches!(state, ConnectionState::Failed(_)));

    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_connect_async_not_started() {
    let (tx, _rx) = packet_channel(100);
    let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    let result = transport
        .connect_async(&TransportAddr::from_string("127.0.0.1:9999"))
        .await;

    assert!(matches!(result, Err(TransportError::NotStarted)));
}

#[tokio::test]
async fn test_connect_async_already_connected() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, _rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
    let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr2 = t2.local_addr().unwrap();
    let remote = TransportAddr::from_string(&addr2.to_string());

    // Connect first time
    t1.connect_async(&remote).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        t1.connection_state_sync(&remote),
        ConnectionState::Connected
    );

    // Second connect should be a no-op (already connected)
    t1.connect_async(&remote).await.unwrap();

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_connect_async_then_send_recv() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
    let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let addr2 = t2.local_addr().unwrap();
    let remote = TransportAddr::from_string(&addr2.to_string());

    // Connect first, then send
    t1.connect_async(&remote).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        t1.connection_state_sync(&remote),
        ConnectionState::Connected
    );

    // Build valid FMP msg1 frame
    let mut msg1 = vec![0xAA; 114];
    msg1[0] = 0x01;
    msg1[1] = 0x00;
    msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

    // Send using the pre-established connection
    t1.send_async(&remote, &msg1).await.unwrap();

    let packet = timeout(Duration::from_secs(2), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(packet.data.as_slice(), msg1.as_slice());

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[test]
fn test_connection_state_none_for_unknown() {
    let (tx, _rx) = packet_channel(100);
    let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

    let state = transport.connection_state_sync(&TransportAddr::from_string("unknown:1234"));
    assert_eq!(state, ConnectionState::None);
}

#[tokio::test]
async fn test_connect_ip_string() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_config(), tx1);
    let mut t2 = TcpTransport::new(
        TransportId::new(2),
        None,
        TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        tx2,
    );

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let port2 = t2.local_addr().unwrap().port();

    // Connect using IP string — build a valid FMP frame (114 bytes)
    let addr = TransportAddr::from_string(&format!("127.0.0.1:{}", port2));
    let mut frame = vec![0xAA; 114];
    frame[0] = 0x01; // ver=0, phase=1
    frame[1] = 0x00; // flags
    frame[2..4].copy_from_slice(&110u16.to_le_bytes()); // payload_len
    t1.send_async(&addr, &frame).await.unwrap();

    // Receive on t2
    let packet = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(packet.data.as_slice(), frame.as_slice());

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_connect_async_ip_string() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, _rx2) = packet_channel(100);

    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_config(), tx1);
    let mut t2 = TcpTransport::new(
        TransportId::new(2),
        None,
        TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        tx2,
    );

    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();

    let port2 = t2.local_addr().unwrap().port();
    let addr = TransportAddr::from_string(&format!("127.0.0.1:{}", port2));

    // Non-blocking connect via IP string
    t1.connect_async(&addr).await.unwrap();

    // Poll until connected
    for _ in 0..50 {
        let state = t1.connection_state_sync(&addr);
        if state == ConnectionState::Connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(t1.connection_state_sync(&addr), ConnectionState::Connected,);

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}
