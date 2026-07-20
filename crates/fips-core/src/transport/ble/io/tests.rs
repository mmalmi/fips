use super::*;

fn test_addr(n: u8) -> BleAddr {
    BleAddr::from_mac("hci0", [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n])
}

#[tokio::test]
async fn test_mock_stream_pair_send_recv() {
    let (a, b) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);

    a.send(b"hello").await.unwrap();
    let mut buf = [0u8; 64];
    let n = b.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");

    b.send(b"world").await.unwrap();
    let n = a.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"world");
}

#[tokio::test]
async fn test_mock_stream_mtu() {
    let (a, b) = MockBleStream::pair(test_addr(1), test_addr(2), 512);
    assert_eq!(a.send_mtu(), 512);
    assert_eq!(a.recv_mtu(), 512);
    assert_eq!(b.send_mtu(), 512);
    assert_eq!(b.recv_mtu(), 512);
}

#[tokio::test]
async fn test_mock_stream_remote_addr() {
    let (a, b) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
    assert_eq!(a.remote_addr(), &test_addr(2));
    assert_eq!(b.remote_addr(), &test_addr(1));
}

#[tokio::test]
async fn test_mock_io_listen_accept() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let mut acceptor = io.listen(0x0085).await.unwrap();
    assert_eq!(acceptor.psm(), 0x0085);

    let (stream_a, _stream_b) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
    io.inject_inbound(stream_a).await;

    let accepted = acceptor.accept().await.unwrap();
    assert_eq!(accepted.remote_addr(), &test_addr(2));
}

#[tokio::test]
async fn test_mock_io_reports_platform_assigned_psm() {
    let io = MockBleIo::new("ios", test_addr(1)).with_listener_psm(0x0091);
    let acceptor = io.listen(0x0085).await.unwrap();
    assert_eq!(acceptor.psm(), 0x0091);
}

#[tokio::test]
async fn test_mock_io_connect() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let local = test_addr(1);
    io.set_connect_handler(move |addr, _psm| {
        let (stream, _peer) = MockBleStream::pair(local.clone(), addr.clone(), 2048);
        Ok(stream)
    });

    let stream = io.connect(&test_addr(2), 0x0085).await.unwrap();
    assert_eq!(stream.remote_addr(), &test_addr(2));
}

#[tokio::test]
async fn test_mock_io_connect_no_handler() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let result = io.connect(&test_addr(2), 0x0085).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_mock_io_scan() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let mut scanner = io.start_scanning().await.unwrap();

    io.inject_scan_result(test_addr(2)).await;
    io.inject_scan_result(test_addr(3)).await;

    assert_eq!(scanner.next().await.unwrap().addr, test_addr(2));
    assert_eq!(scanner.next().await.unwrap().addr, test_addr(3));
}

#[tokio::test]
async fn test_mock_io_local_addr() {
    let io = MockBleIo::new("hci0", test_addr(1));
    assert_eq!(io.local_addr().unwrap(), test_addr(1));
    assert_eq!(io.adapter_name(), "hci0");
}

#[tokio::test]
async fn test_mock_io_advertising_noop() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let bootstrap = BleBootstrap::new(DEFAULT_PSM, 2048).unwrap();
    io.start_advertising(bootstrap).await.unwrap();
    assert_eq!(io.advertised_bootstrap(), Some(bootstrap));
    io.stop_advertising().await.unwrap();
}

#[tokio::test]
async fn test_mock_io_listen_twice_fails() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let _acceptor = io.listen(0x0085).await.unwrap();
    assert!(io.listen(0x0085).await.is_err());
}
