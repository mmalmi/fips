use super::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct TestPayloadBatch {
    payloads: Vec<Vec<Vec<u8>>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TestPayloadBatch {
    fn new(payloads: Vec<Vec<&[u8]>>) -> Self {
        Self {
            payloads: payloads
                .into_iter()
                .map(|payload| payload.into_iter().map(Vec::from).collect())
                .collect(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl crate::transport::udp::UdpPayloadBatch for TestPayloadBatch {
    fn len(&self) -> usize {
        self.payloads.len()
    }

    fn payload_len(&self, index: usize) -> usize {
        self.payloads[index].iter().map(Vec::len).sum()
    }

    fn payload_slices<'a>(
        &'a self,
        index: usize,
        out: &mut [Option<&'a [u8]>; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES],
    ) -> usize {
        out.fill(None);
        for (slot, slice) in self.payloads[index].iter().enumerate() {
            out[slot] = Some(slice.as_slice());
        }
        self.payloads[index].len()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn recv_datagrams(
    socket: &AsyncUdpSocket,
    expected_count: usize,
    capacity: usize,
) -> Vec<(Vec<u8>, SocketAddr, usize)> {
    let mut received = Vec::with_capacity(expected_count);
    while received.len() < expected_count {
        let mut bufs: Vec<Vec<u8>> = (0..RECV_BATCH_SIZE)
            .map(|_| Vec::with_capacity(capacity))
            .collect();
        let mut addrs: [Option<SocketAddr>; RECV_BATCH_SIZE] = std::array::from_fn(|_| None);
        let mut gro_segment_sizes = [usize::MAX; RECV_BATCH_SIZE];

        let (count, _drops) = socket
            .recv_batch(&mut bufs, &mut addrs, &mut gro_segment_sizes)
            .await
            .expect("recv batch");
        for index in 0..count {
            received.push((
                std::mem::take(&mut bufs[index]),
                addrs[index].expect("source address"),
                gro_segment_sizes[index],
            ));
        }
    }
    received
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn recv_datagrams(
    socket: &AsyncUdpSocket,
    expected_count: usize,
    capacity: usize,
) -> Vec<(Vec<u8>, SocketAddr, usize)> {
    let mut received = Vec::with_capacity(expected_count);
    while received.len() < expected_count {
        let mut buf = vec![0u8; capacity];
        let (len, src, _drops, gro_segment_size) = socket.recv_from(&mut buf).await.expect("recv");
        buf.truncate(len);
        received.push((buf, src, gro_segment_size));
    }
    received
}

#[test]
fn test_udp_socket_bind() {
    // Bind to an ephemeral port
    let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind UDP socket");

    let addr = sock.local_addr();
    assert!(addr.port() > 0, "should be assigned an ephemeral port");
    assert!(addr.ip().is_loopback());
}

#[cfg(target_os = "linux")]
#[test]
fn udp_gso_prefix_accepts_vectored_equal_len_payloads() {
    use crate::transport::udp::UdpPayloadBatch;

    let payloads = TestPayloadBatch::new(vec![
        vec![b"DFP1".as_slice(), b"aaaaaaaa".as_slice()],
        vec![b"DFP1".as_slice(), b"bbbbbbbb".as_slice()],
        vec![b"DFP1".as_slice(), b"cccccccc".as_slice()],
    ]);

    assert_eq!(super::platform::udp_gso_prefix_len(&payloads, 0, 64), 3);
}

#[cfg(target_os = "linux")]
#[test]
fn udp_gso_prefix_stops_before_longer_vectored_payload() {
    let payloads = TestPayloadBatch::new(vec![
        vec![b"DFP1".as_slice(), b"aaaa".as_slice()],
        vec![b"DFP1".as_slice(), b"bbbbbbbb".as_slice()],
    ]);

    assert_eq!(super::platform::udp_gso_prefix_len(&payloads, 0, 64), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn udp_gso_prefix_preserves_short_tail_segment() {
    let payloads = TestPayloadBatch::new(vec![
        vec![b"DFP1".as_slice(), b"aaaaaaaa".as_slice()],
        vec![b"DFP1".as_slice(), b"bbbbbbbb".as_slice()],
        vec![b"DFP1".as_slice(), b"cc".as_slice()],
        vec![b"DFP1".as_slice(), b"dddddddd".as_slice()],
    ]);

    assert_eq!(super::platform::udp_gso_prefix_len(&payloads, 0, 64), 3);
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

    let received = recv_datagrams(&async2, 1, 1024).await;
    let (data, src, gro_segment_size) = &received[0];
    assert_eq!(data.as_slice(), payload);
    assert_eq!(*src, addr1);
    assert_eq!(*gro_segment_size, 0);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn send_batch_to_sends_vectored_payloads() {
    use crate::transport::udp::UdpPayloadBatch;

    let sock1 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind socket 1");
    let addr1 = sock1.local_addr();
    let async1 = sock1.into_async().expect("into_async 1");

    let sock2 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
        .expect("failed to bind socket 2");
    let addr2 = sock2.local_addr();
    let async2 = sock2.into_async().expect("into_async 2");

    let payloads = TestPayloadBatch::new(vec![
        vec![b"DFP1".as_slice(), b"first".as_slice()],
        vec![b"second".as_slice()],
        vec![b"DFP1".as_slice(), b"third".as_slice()],
    ]);

    let sent = async1
        .send_batch_to(&payloads, 0, addr2)
        .await
        .expect("send batch");
    assert_eq!(sent, payloads.len());

    let received = recv_datagrams(&async2, payloads.len(), 1024).await;
    for ((data, src, gro_segment_size), expected) in received.iter().zip([
        b"DFP1first".as_slice(),
        b"second".as_slice(),
        b"DFP1third".as_slice(),
    ]) {
        assert_eq!(*src, addr1);
        assert_eq!(data.as_slice(), expected);
        assert_eq!(*gro_segment_size, 0);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    let mut gro_segment_sizes = [usize::MAX; RECV_BATCH_SIZE];

    async1
        .send_to(b"first-packet", &addr2)
        .await
        .expect("send first");
    let (count, _drops) = async2
        .recv_batch(&mut bufs, &mut addrs, &mut gro_segment_sizes)
        .await
        .expect("recv first batch");
    assert_eq!(count, 1);
    assert_eq!(bufs[0], b"first-packet");
    assert_eq!(addrs[0], Some(addr1));
    assert_eq!(gro_segment_sizes[0], 0);
    assert_eq!(bufs[1].len(), 0);
    assert_eq!(gro_segment_sizes[1], 0);

    async1.send_to(b"2", &addr2).await.expect("send second");
    let (count, _drops) = async2
        .recv_batch(&mut bufs, &mut addrs, &mut gro_segment_sizes)
        .await
        .expect("recv second batch");
    assert_eq!(count, 1);
    assert_eq!(
        bufs[0], b"2",
        "recv_batch should clear and refill the Vec rather than append"
    );
    assert_eq!(addrs[0], Some(addr1));
    assert_eq!(gro_segment_sizes[0], 0);
}
