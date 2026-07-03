use super::*;

#[test]
fn test_tun_state_display() {
    assert_eq!(format!("{}", TunState::Disabled), "disabled");
    assert_eq!(format!("{}", TunState::Active), "active");
}

#[test]
fn tun_write_channel_prioritizes_priority_and_bounds_bulk() {
    let (tx, rx) = write_channel_with_bulk_capacity(2);

    tx.send_with_lane(vec![1], TunWriteLane::Bulk)
        .expect("first bulk packet fits");
    tx.send_with_lane(vec![2], TunWriteLane::Bulk)
        .expect("second bulk packet fits");
    let dropped = tx
        .send_with_lane(vec![3], TunWriteLane::Bulk)
        .expect_err("bulk cap should drop the tail");

    assert_eq!(dropped.kind(), TunWriteErrorKind::BulkFull);
    assert_eq!(dropped.into_packet(), vec![3]);

    tx.send_with_lane(vec![9], TunWriteLane::Priority)
        .expect("priority remains admitted under bulk pressure");

    assert_eq!(rx.try_recv().unwrap(), vec![9]);
    assert_eq!(rx.try_recv().unwrap(), vec![1]);
    assert_eq!(rx.try_recv().unwrap(), vec![2]);
    assert!(matches!(
        rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn tun_write_channel_returns_pooled_packets_after_write() {
    let (packet_tx, _packet_rx) = crate::transport::packet_channel(4);
    let mut raw = packet_tx.recv_buffer(1600);
    raw.clear();
    raw.extend_from_slice(&[1, 2, 3, 4]);
    let ptr = raw.as_ptr();
    let pooled = packet_tx.packet_buffer(raw);

    let (tx, rx) = write_channel_with_bulk_capacity(2);
    tx.send_with_lane(pooled, TunWriteLane::Bulk)
        .expect("pooled packet fits");

    let packet = rx.try_recv_packet().expect("queued pooled TUN packet");
    assert_eq!(packet.as_slice(), &[1, 2, 3, 4]);
    drop(packet);

    let reused = packet_tx.recv_buffer(1600);
    assert_eq!(reused.as_ptr(), ptr);
}

// Note: TUN device creation tests require elevated privileges
// and are better suited for integration tests.

// ========================================================================
// per_flow_max_mss — per-destination MSS clamp regression coverage
// ========================================================================

fn fips_addr_with_node_byte(b: u8) -> FipsAddress {
    let mut bytes = [0u8; 16];
    bytes[0] = crate::identity::FIPS_ADDRESS_PREFIX;
    bytes[1] = b;
    FipsAddress::from_bytes(bytes).unwrap()
}

fn empty_lookup() -> PathMtuLookup {
    Arc::new(RwLock::new(HashMap::new()))
}

#[test]
fn per_flow_empty_lookup_returns_conservative_ceiling() {
    // Cold-flow first-SYN race-window guard: when no per-destination
    // path_mtu has been learned yet, fall back to the IPv6-minimum-
    // derived ceiling (1280 - 77 - 60 = 1143) rather than the local
    // global ceiling. This ensures the first SYN to an unknown
    // destination clamps small enough to traverse any RFC-8200-
    // compliant IPv6 path.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1143);
}

#[test]
fn per_flow_empty_lookup_returns_global_when_global_smaller() {
    // When the local global ceiling is already <= the conservative
    // 1143 ceiling (e.g. a daemon configured with UDP-1280 only),
    // the empty-lookup fallback stays at the global rather than
    // expanding upward.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1100), 1100);
}

#[test]
fn per_flow_clamps_to_path_mtu_when_smaller() {
    // Discovery learned path_mtu=1280 for this destination; global
    // ceiling is 1360. Per-flow clamp should be min(1360, 1280-77-60)
    // = min(1360, 1143) = 1143.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    lookup.write().unwrap().insert(addr, 1280);
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1143);
}

#[test]
fn per_flow_keeps_global_when_path_mtu_larger() {
    // Discovery learned path_mtu=1452 (> global). Per-flow stays at
    // global 1143 (the smaller of the two).
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    lookup.write().unwrap().insert(addr, 1452);
    // global=1143 (UDP-1280-derived); path_max = 1452-77-60 = 1315.
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1143), 1143);
}

#[test]
fn per_flow_learned_value_overrides_conservative_ceiling() {
    // When discovery has learned a per-destination value LARGER than
    // the conservative 1143 ceiling, the learned value (capped by
    // the global ceiling) wins. The conservative ceiling is only the
    // empty-lookup fallback; once an entry exists, the actual
    // learned value governs.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    lookup.write().unwrap().insert(addr, 1452);
    // global=1360, path_max = 1452-77-60 = 1315; min(1360, 1315) = 1315.
    // 1315 > 1143, so the conservative ceiling did NOT clamp here.
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1315);
}

#[test]
fn per_flow_returns_conservative_ceiling_for_non_fips_addr() {
    // Non-fips IPv6 (e.g. fe80::/10 link-local) takes the empty-
    // lookup path. With global=1360, fall back to 1143.
    let lookup = empty_lookup();
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    assert_eq!(per_flow_max_mss(&lookup, &bytes, 1360), 1143);
}

#[test]
fn per_flow_returns_conservative_ceiling_on_short_addr_slice() {
    let lookup = empty_lookup();
    let bytes = [0u8; 8];
    assert_eq!(per_flow_max_mss(&lookup, &bytes, 1360), 1143);
}

#[test]
fn per_flow_independent_per_destination() {
    // Two different destinations with different path MTUs. Each
    // lookup honors its own value; cross-talk would be a regression.
    let lookup = empty_lookup();
    let a = fips_addr_with_node_byte(0x10);
    let b = fips_addr_with_node_byte(0x20);
    lookup.write().unwrap().insert(a, 1280);
    lookup.write().unwrap().insert(b, 1452);
    assert_eq!(per_flow_max_mss(&lookup, a.as_bytes(), 1360), 1143);
    assert_eq!(per_flow_max_mss(&lookup, b.as_bytes(), 1360), 1315);
}

// ========================================================================
// macOS utun packet-info header (AF_INET6 4-byte big-endian prefix)
//
// These tests are pure-data byte-buffer manipulation and require no
// privilege, no actual TUN device, no system calls. They pin the wire
// format that `TunWriter::run` emits ahead of every IPv6 frame on the
// dup'd utun fd, and the inverse parse used for round-trip checking.
// ========================================================================

#[cfg(target_os = "macos")]
mod macos_utun_header {
    use super::super::{UTUN_AF_INET6, parse_utun_af_prefix, utun_af_inet6_header};

    #[test]
    fn af_inet6_constant_matches_darwin() {
        // Darwin's <sys/socket.h> defines AF_INET6 = 30. If this ever
        // diverges, every utun write FIPS issues will be misclassified
        // by the kernel and dropped.
        assert_eq!(UTUN_AF_INET6, 30);
    }

    #[test]
    fn encode_produces_big_endian_af_inet6() {
        // The kernel reads the 4-byte prefix as a big-endian u32.
        // 30 == 0x0000001e, so the wire bytes are [0, 0, 0, 0x1e].
        let header = utun_af_inet6_header();
        assert_eq!(header, [0x00, 0x00, 0x00, 0x1e]);
    }

    #[test]
    fn encode_round_trips_through_parse() {
        let header = utun_af_inet6_header();
        let parsed = parse_utun_af_prefix(&header).expect("4 bytes is enough");
        assert_eq!(parsed, UTUN_AF_INET6);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        // Anything shorter than the 4-byte header is ill-formed.
        assert_eq!(parse_utun_af_prefix(&[]), None);
        assert_eq!(parse_utun_af_prefix(&[0x00]), None);
        assert_eq!(parse_utun_af_prefix(&[0x00, 0x00]), None);
        assert_eq!(parse_utun_af_prefix(&[0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn parse_accepts_minimum_header_with_trailing_payload() {
        // A real utun read returns header + IP packet concatenated.
        // The parser only consumes the first 4 bytes.
        let mut frame = utun_af_inet6_header().to_vec();
        frame.extend_from_slice(&[0x60; 40]); // dummy IPv6 header
        let parsed = parse_utun_af_prefix(&frame).expect("4 bytes is enough");
        assert_eq!(parsed, UTUN_AF_INET6);
    }

    #[test]
    fn parse_garbage_bytes_returns_garbage_value_not_panic() {
        // A well-formed 4-byte buffer whose value is not AF_INET6
        // should parse successfully (returning the raw u32) without
        // panicking. Discriminating "expected" vs "unexpected" AF
        // values is the caller's responsibility.
        let buf = [0xde, 0xad, 0xbe, 0xef];
        let parsed = parse_utun_af_prefix(&buf).expect("4 bytes is enough");
        assert_eq!(parsed, 0xdeadbeef);
        assert_ne!(parsed, UTUN_AF_INET6);
    }
}
