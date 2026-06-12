use super::*;

#[test]
fn test_udp_socket_bind() {
    // Bind to an ephemeral port
    let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind UDP socket");

    let addr = sock.local_addr();
    assert!(addr.port() > 0, "should be assigned an ephemeral port");
    assert!(addr.ip().is_loopback());
}

#[test]
fn test_udp_socket_buffer_sizes() {
    let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind UDP socket");

    let recv_buf = sock.recv_buffer_size().expect("get recv buffer");
    let send_buf = sock.send_buffer_size().expect("get send buffer");
    assert!(recv_buf > 0, "recv buffer should be non-zero");
    assert!(send_buf > 0, "send buffer should be non-zero");
}

#[tokio::test]
async fn test_async_udp_socket_send_recv() {
    let sock1 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind socket 1");
    let addr1 = sock1.local_addr();
    let async1 = sock1.into_async().expect("into_async 1");

    let sock2 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind socket 2");
    let addr2 = sock2.local_addr();
    let async2 = sock2.into_async().expect("into_async 2");

    // Send from socket 1 to socket 2
    let payload = b"hello fips";
    let sent = async1.send_to(payload, &addr2).await.expect("send_to");
    assert_eq!(sent, payload.len());

    // Receive on socket 2
    let mut buf = [0u8; 1024];
    let (n, src, _drops) = async2.recv_from(&mut buf).await.expect("recv_from");
    assert_eq!(n, payload.len());
    assert_eq!(&buf[..n], payload);
    assert_eq!(src, addr1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recv_batch_writes_into_vec_spare_capacity() {
    let sock1 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind socket 1");
    let addr1 = sock1.local_addr();
    let async1 = sock1.into_async().expect("into_async 1");

    let sock2 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind socket 2");
    let addr2 = sock2.local_addr();
    let async2 = sock2.into_async().expect("into_async 2");

    let mut bufs: Vec<Vec<u8>> = (0..RECV_BATCH_SIZE)
        .map(|_| Vec::with_capacity(64))
        .collect();
    let mut addrs: [Option<SocketAddr>; RECV_BATCH_SIZE] = std::array::from_fn(|_| None);

    async1
        .send_to(b"first-packet", &addr2)
        .await
        .expect("send first");
    let (count, _drops) = async2
        .recv_batch(&mut bufs, &mut addrs)
        .await
        .expect("recv first batch");
    assert_eq!(count, 1);
    assert_eq!(bufs[0], b"first-packet");
    assert_eq!(addrs[0], Some(addr1));
    assert_eq!(bufs[1].len(), 0);

    async1.send_to(b"2", &addr2).await.expect("send second");
    let (count, _drops) = async2
        .recv_batch(&mut bufs, &mut addrs)
        .await
        .expect("recv second batch");
    assert_eq!(count, 1);
    assert_eq!(
        bufs[0], b"2",
        "recv_batch should clear and refill the Vec rather than append"
    );
    assert_eq!(addrs[0], Some(addr1));
}
