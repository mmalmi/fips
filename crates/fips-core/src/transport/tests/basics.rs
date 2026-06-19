use super::super::*;

#[test]
fn test_transport_id() {
    let id = TransportId::new(42);
    assert_eq!(id.as_u32(), 42);
    assert_eq!(format!("{}", id), "transport:42");
}

#[test]
fn test_link_id() {
    let id = LinkId::new(12345);
    assert_eq!(id.as_u64(), 12345);
    assert_eq!(format!("{}", id), "link:12345");
}

#[test]
fn test_transport_state_transitions() {
    assert!(TransportState::Configured.can_start());
    assert!(TransportState::Down.can_start());
    assert!(TransportState::Failed.can_start());
    assert!(!TransportState::Starting.can_start());
    assert!(!TransportState::Up.can_start());

    assert!(TransportState::Up.is_operational());
    assert!(!TransportState::Starting.is_operational());
    assert!(!TransportState::Failed.is_operational());
}

#[test]
fn test_link_state() {
    assert!(LinkState::Connected.is_operational());
    assert!(!LinkState::Connecting.is_operational());
    assert!(!LinkState::Disconnected.is_operational());
    assert!(!LinkState::Failed.is_operational());

    assert!(LinkState::Disconnected.is_terminal());
    assert!(LinkState::Failed.is_terminal());
    assert!(!LinkState::Connected.is_terminal());
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_transport_type_constants() {
    // These assertions verify the constant definitions are correct
    assert!(!TransportType::UDP.connection_oriented);
    assert!(!TransportType::UDP.reliable);
    assert!(TransportType::UDP.is_connectionless());

    assert!(TransportType::TOR.connection_oriented);
    assert!(TransportType::TOR.reliable);
    assert!(!TransportType::TOR.is_connectionless());

    assert_eq!(TransportType::UDP.name, "udp");
    assert_eq!(TransportType::ETHERNET.name, "ethernet");
}

#[test]
fn permission_denied_send_errors_are_local_route_unavailable() {
    let io_error = TransportError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "operation not permitted",
    ));
    assert!(io_error.is_local_route_unavailable());

    let text_error = TransportError::SendFailed("Operation not permitted (os error 1)".to_string());
    assert!(text_error.is_local_route_unavailable());
}

#[test]
fn test_transport_addr_string() {
    let addr = TransportAddr::from_string("192.168.1.1:2121");
    assert_eq!(format!("{}", addr), "192.168.1.1:2121");
    assert_eq!(addr.as_str(), Some("192.168.1.1:2121"));
}

#[test]
fn transport_addr_clone_shares_immutable_bytes() {
    let addr = TransportAddr::from_string("192.168.1.1:2121");
    let cloned = addr.clone();

    assert_eq!(addr, cloned);
    assert!(std::ptr::eq(
        addr.as_bytes().as_ptr(),
        cloned.as_bytes().as_ptr()
    ));
}

#[test]
fn transport_addr_hashes_by_value_not_pointer() {
    use std::collections::HashSet;

    let original = TransportAddr::from_string("192.168.1.1:2121");
    let same_value = TransportAddr::from_bytes(b"192.168.1.1:2121");
    let mut addrs = HashSet::new();

    addrs.insert(original);

    assert!(addrs.contains(&same_value));
}

#[test]
fn test_transport_addr_binary() {
    // Binary address with invalid UTF-8 bytes (0xff, 0x80 are invalid UTF-8)
    let binary = TransportAddr::new(vec![0xff, 0x80, 0x2b, 0x3c, 0x4d, 0x5e]);
    assert_eq!(format!("{}", binary), "ff802b3c4d5e");
    assert!(binary.as_str().is_none());
    assert_eq!(binary.len(), 6);
}

#[test]
fn test_transport_addr_from_string() {
    let addr: TransportAddr = "test:1234".into();
    assert_eq!(addr.as_str(), Some("test:1234"));

    let addr2: TransportAddr = String::from("hello").into();
    assert_eq!(addr2.as_str(), Some("hello"));
}

#[test]
fn test_link_stats_basic() {
    let mut stats = LinkStats::new();

    stats.record_sent(100);
    stats.record_recv(200, 1000);

    assert_eq!(stats.packets_sent, 1);
    assert_eq!(stats.bytes_sent, 100);
    assert_eq!(stats.packets_recv, 1);
    assert_eq!(stats.bytes_recv, 200);
    assert_eq!(stats.last_recv_ms, 1000);
}

#[test]
fn test_link_stats_rtt() {
    let mut stats = LinkStats::new();

    assert!(stats.rtt_estimate().is_none());

    stats.update_rtt(Duration::from_millis(100));
    assert_eq!(stats.rtt_estimate(), Some(Duration::from_millis(100)));

    // Second update uses EMA
    stats.update_rtt(Duration::from_millis(200));
    // EMA: 0.2 * 200 + 0.8 * 100 = 120ms
    let rtt = stats.rtt_estimate().unwrap();
    assert!(rtt.as_millis() >= 110 && rtt.as_millis() <= 130);
}

#[test]
fn test_link_stats_time_since_recv() {
    let mut stats = LinkStats::new();

    // No receive yet
    assert_eq!(stats.time_since_recv(1000), u64::MAX);

    stats.record_recv(100, 500);
    assert_eq!(stats.time_since_recv(1000), 500);
    assert_eq!(stats.time_since_recv(500), 0);
}

#[test]
fn test_link_creation() {
    let link = Link::new(
        LinkId::new(1),
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    assert_eq!(link.state(), LinkState::Connecting);
    assert!(!link.is_operational());
    assert_eq!(link.direction(), LinkDirection::Outbound);
}

#[test]
fn test_link_connectionless() {
    let link = Link::connectionless(
        LinkId::new(1),
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Inbound,
        Duration::from_millis(5),
    );

    assert_eq!(link.state(), LinkState::Connected);
    assert!(link.is_operational());
}

#[test]
fn test_link_state_changes() {
    let mut link = Link::new(
        LinkId::new(1),
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    assert!(!link.is_operational());

    link.set_connected();
    assert!(link.is_operational());
    assert!(!link.is_terminal());

    link.set_disconnected();
    assert!(!link.is_operational());
    assert!(link.is_terminal());
}

#[test]
fn test_link_effective_rtt() {
    let mut link = Link::connectionless(
        LinkId::new(1),
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Inbound,
        Duration::from_millis(50),
    );

    // Before measurement, uses base RTT
    assert_eq!(link.effective_rtt(), Duration::from_millis(50));

    // After measurement, uses measured RTT
    link.stats_mut().update_rtt(Duration::from_millis(100));
    assert_eq!(link.effective_rtt(), Duration::from_millis(100));
}

#[test]
fn test_link_age() {
    let mut link = Link::new(
        LinkId::new(1),
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    // No timestamp set
    assert_eq!(link.age(1000), 0);

    link.set_created_at(500);
    assert_eq!(link.age(1000), 500);
    assert_eq!(link.age(500), 0);
}

#[test]
fn test_discovered_peer() {
    let peer = DiscoveredPeer::new(
        TransportId::new(1),
        TransportAddr::from_string("192.168.1.1:2121"),
    );

    assert_eq!(peer.transport_id, TransportId::new(1));
    assert!(peer.pubkey_hint.is_none());
}

#[test]
fn test_link_direction_display() {
    assert_eq!(format!("{}", LinkDirection::Outbound), "outbound");
    assert_eq!(format!("{}", LinkDirection::Inbound), "inbound");
}

#[test]
fn test_transport_state_display() {
    assert_eq!(format!("{}", TransportState::Up), "up");
    assert_eq!(format!("{}", TransportState::Failed), "failed");
}
