use super::*;
use std::time::{Duration, Instant};

#[test]
fn unavailable_socket_options_are_not_zero() {
    let socket = PacketSocket {
        fd: -1,
        if_index: 0,
        ethertype: 0x2121,
        kernel_drops: KernelDropCounter::default(),
    };
    let stats = socket.socket_stats();
    assert_eq!(stats.kernel_drops, None);
    assert_eq!(stats.recv_buffer_bytes, None);
}

/// The caller supplies both ends of a disposable, up veth pair in an isolated
/// network namespace, plus CAP_NET_RAW. This test never changes interfaces.
#[test]
#[ignore = "requires isolated veth pair in FIPS_TEST_ETHERNET_RX/TX and CAP_NET_RAW"]
fn ethernet_socket_queue_drops_survive_diagnostic_reads() {
    let rx_interface = std::env::var("FIPS_TEST_ETHERNET_RX").expect("disposable receive veth");
    let tx_interface = std::env::var("FIPS_TEST_ETHERNET_TX").expect("disposable send veth");
    assert_ne!(
        rx_interface, tx_interface,
        "provide opposite veth endpoints"
    );
    let receiver = PacketSocket::open(&rx_interface, 0x2121).unwrap();
    let sender = PacketSocket::open(&tx_interface, 0x2121).unwrap();
    receiver.set_recv_buffer_size(4096).unwrap();
    let destination = receiver.local_mac().unwrap();
    let initial = receiver.socket_stats();
    assert_eq!(initial.kernel_drops, Some(0));
    let actual_buffer = initial.recv_buffer_bytes.expect("effective receive buffer");
    assert!((4096..512 * 1024).contains(&actual_buffer));

    // Leave the receiver undrained until its real AF_PACKET queue overflows.
    let payload = [0x5a; 1024];
    let deadline = Instant::now() + Duration::from_secs(2);
    for _ in 0..512 {
        loop {
            match sender.send_to(&payload, &destination) {
                Ok(len) => {
                    assert_eq!(len, payload.len());
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "bounded test sender stalled");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("test send failed: {error}"),
            }
        }
    }
    let first_drops = loop {
        let drops = receiver
            .socket_stats()
            .kernel_drops
            .expect("kernel drop counter");
        if drops > 0 {
            break drops;
        }
        assert!(Instant::now() < deadline, "expected receive queue overflow");
        std::thread::sleep(Duration::from_millis(1));
    };
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let receiver = &receiver;
            scope.spawn(move || {
                let stats = receiver.socket_stats();
                assert!(stats.kernel_drops.unwrap() >= first_drops);
                assert_eq!(stats.recv_buffer_bytes, Some(actual_buffer));
            });
        }
    });

    // Overflow is not a recvfrom error, and diagnostic reads must not consume data.
    let mut buffer = [0; 2048];
    let mut delivered = 0;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline, "bounded receive drain stalled");
        match receiver.recv_from(&mut buffer) {
            Ok((len, _)) => {
                assert_eq!(&buffer[..len], &payload);
                delivered += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("test receive failed: {error}"),
        }
    }
    assert!((1..512).contains(&delivered));
    let retained = receiver.socket_stats().kernel_drops.unwrap();
    assert!((first_drops..=512).contains(&retained));

    // The same socket remains usable after observation and overflow.
    let marker = [0xa5; 1024];
    assert_eq!(sender.send_to(&marker, &destination).unwrap(), marker.len());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            Instant::now() < deadline,
            "marker not received after queue drain"
        );
        match receiver.recv_from(&mut buffer) {
            Ok((len, _)) if buffer[..len] == marker => break,
            Ok((len, _)) => assert_eq!(&buffer[..len], &payload),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "marker not received after queue drain"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("test receive failed: {error}"),
        }
    }
    assert!(receiver.socket_stats().kernel_drops.unwrap() >= retained);
}
