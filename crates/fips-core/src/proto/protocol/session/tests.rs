use super::*;

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

// ===== SessionMessageType Tests =====

#[test]
fn test_session_message_type_roundtrip() {
    let types = [
        SessionMessageType::DataPacket,
        SessionMessageType::SenderReport,
        SessionMessageType::ReceiverReport,
        SessionMessageType::PathMtuNotification,
        SessionMessageType::CoordsWarmup,
        SessionMessageType::EndpointData,
        SessionMessageType::TraversalOffer,
        SessionMessageType::TraversalAnswer,
        SessionMessageType::CoordsRequired,
        SessionMessageType::PathBroken,
        SessionMessageType::MtuExceeded,
    ];

    for ty in types {
        let byte = ty.to_byte();
        let restored = SessionMessageType::from_byte(byte);
        assert_eq!(restored, Some(ty));
    }
}

#[test]
fn test_session_message_type_invalid() {
    assert!(SessionMessageType::from_byte(0x18).is_none());
    assert!(SessionMessageType::from_byte(0xFF).is_none());
    assert!(SessionMessageType::from_byte(0x99).is_none());
}

// ===== SessionFlags Tests =====

#[test]
fn test_session_flags() {
    let flags = SessionFlags::new()
        .with_ack()
        .bidirectional()
        .with_direct_fsp_transport();

    assert!(flags.request_ack);
    assert!(flags.bidirectional);
    assert!(flags.direct_fsp_transport);
    assert_eq!(flags.to_byte(), 0x07);

    let byte = flags.to_byte();
    let restored = SessionFlags::from_byte(byte);

    assert_eq!(flags, restored);
}

#[test]
fn test_session_flags_default() {
    let flags = SessionFlags::new();
    assert!(!flags.request_ack);
    assert!(!flags.bidirectional);
    assert!(!flags.direct_fsp_transport);
    assert_eq!(flags.to_byte(), 0);
}

// ===== SessionSetup Tests =====

#[test]
fn test_session_setup() {
    let setup = SessionSetup::new(make_coords(&[1, 0]), make_coords(&[2, 0]))
        .with_flags(SessionFlags::new().with_ack());

    assert!(setup.flags.request_ack);
    assert!(!setup.flags.bidirectional);
}

// ===== CoordsRequired Tests =====

#[test]
fn test_coords_required() {
    let err = CoordsRequired::new(make_node_addr(1), make_node_addr(2));

    assert_eq!(err.dest_addr, make_node_addr(1));
    assert_eq!(err.reporter, make_node_addr(2));
}

// ===== PathBroken Tests =====

#[test]
fn test_path_broken() {
    let err = PathBroken::new(make_node_addr(2), make_node_addr(3))
        .with_last_coords(make_coords(&[2, 0]));

    assert_eq!(err.dest_addr, make_node_addr(2));
    assert_eq!(err.reporter, make_node_addr(3));
    assert!(err.last_known_coords.is_some());
}

// ===== Encode/Decode Roundtrip Tests =====

#[test]
fn test_session_setup_encode_decode() {
    let handshake = vec![0xAA; 82]; // typical Noise IK msg1
    let setup = SessionSetup::new(make_coords(&[1, 2, 0]), make_coords(&[3, 4, 0]))
        .with_flags(SessionFlags::new().with_ack().bidirectional())
        .with_handshake(handshake.clone());

    let encoded = setup.encode();

    // Verify FSP prefix: ver_phase=0x01 (version 0, phase MSG1)
    assert_eq!(encoded[0], 0x01);
    assert_eq!(encoded[1], 0x00); // flags = 0 for handshake
    let payload_len = u16::from_le_bytes([encoded[2], encoded[3]]);
    assert_eq!(payload_len as usize, encoded.len() - 4);

    // Decode (skip 4-byte FSP prefix)
    let decoded = SessionSetup::decode(&encoded[4..]).unwrap();

    assert_eq!(decoded.flags, setup.flags);
    assert_eq!(decoded.src_coords, setup.src_coords);
    assert_eq!(decoded.dest_coords, setup.dest_coords);
    assert_eq!(decoded.handshake_payload, handshake);
}

#[test]
fn test_session_setup_no_handshake() {
    let setup = SessionSetup::new(make_coords(&[5, 0]), make_coords(&[6, 0]));

    let encoded = setup.encode();
    let decoded = SessionSetup::decode(&encoded[4..]).unwrap();

    assert!(decoded.handshake_payload.is_empty());
    assert_eq!(decoded.src_coords, setup.src_coords);
    assert_eq!(decoded.dest_coords, setup.dest_coords);
}

#[test]
fn test_session_ack_encode_decode() {
    let handshake = vec![0xBB; 33]; // typical Noise IK msg2
    let ack = SessionAck::new(make_coords(&[7, 8, 0]), make_coords(&[3, 4, 0]))
        .with_direct_fsp_transport()
        .with_handshake(handshake.clone());

    let encoded = ack.encode();
    // Verify FSP prefix: ver_phase=0x02 (version 0, phase MSG2)
    assert_eq!(encoded[0], 0x02);
    assert_eq!(encoded[1], 0x00); // flags = 0 for handshake

    let decoded = SessionAck::decode(&encoded[4..]).unwrap();
    assert_eq!(decoded.src_coords, ack.src_coords);
    assert_eq!(decoded.dest_coords, ack.dest_coords);
    assert_eq!(decoded.handshake_payload, handshake);
    assert!(decoded.supports_direct_fsp_transport());
}

#[test]
fn test_coords_required_encode_decode() {
    let err = CoordsRequired::new(make_node_addr(0xAA), make_node_addr(0xBB));

    let encoded = err.encode();
    // 4 prefix + 1 msg_type + 1 flags + 16 dest + 16 reporter = 38
    assert_eq!(encoded.len(), 4 + COORDS_REQUIRED_SIZE);
    // Check FSP prefix: phase 0x0, U flag
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x04); // U flag
    // msg_type after prefix
    assert_eq!(encoded[4], 0x20);

    // decode after prefix + msg_type consumed
    let decoded = CoordsRequired::decode(&encoded[5..]).unwrap();
    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
}

#[test]
fn test_path_broken_encode_decode_no_coords() {
    let err = PathBroken::new(make_node_addr(0xCC), make_node_addr(0xDD));

    let encoded = err.encode();
    // Check FSP prefix
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x04); // U flag
    assert_eq!(encoded[4], 0x21); // msg_type

    let decoded = PathBroken::decode(&encoded[5..]).unwrap();
    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
    assert!(decoded.last_known_coords.is_none());
}

#[test]
fn test_path_broken_encode_decode_with_coords() {
    let coords = make_coords(&[0xCC, 0xDD, 0xEE]);
    let err = PathBroken::new(make_node_addr(0x11), make_node_addr(0x22))
        .with_last_coords(coords.clone());

    let encoded = err.encode();
    let decoded = PathBroken::decode(&encoded[5..]).unwrap();

    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
    assert_eq!(decoded.last_known_coords.unwrap(), coords);
}

#[test]
fn test_session_setup_decode_too_short() {
    assert!(SessionSetup::decode(&[]).is_err());
}

#[test]
fn test_session_ack_decode_too_short() {
    assert!(SessionAck::decode(&[]).is_err());
}

#[test]
fn test_coords_required_decode_too_short() {
    assert!(CoordsRequired::decode(&[]).is_err());
    assert!(CoordsRequired::decode(&[0x00; 10]).is_err());
}

#[test]
fn test_path_broken_decode_too_short() {
    assert!(PathBroken::decode(&[]).is_err());
    assert!(PathBroken::decode(&[0x00; 20]).is_err());
}

#[test]
fn test_session_setup_deep_coords() {
    // Depth-10 coordinate (11 entries: self + 10 ancestors)
    let addrs: Vec<u8> = (0..11).collect();
    let src = make_coords(&addrs);
    let dest = make_coords(&[20, 21, 22, 23, 24]);
    let setup = SessionSetup::new(src.clone(), dest.clone()).with_handshake(vec![0x55; 82]);

    let encoded = setup.encode();
    let decoded = SessionSetup::decode(&encoded[4..]).unwrap();

    assert_eq!(decoded.src_coords, src);
    assert_eq!(decoded.dest_coords, dest);
}

// ===== FspFlags Tests =====

#[test]
fn test_fsp_flags_default() {
    let flags = FspFlags::new();
    assert!(!flags.coords_present);
    assert!(!flags.key_epoch);
    assert!(!flags.unencrypted);
    assert_eq!(flags.to_byte(), 0x00);
}

#[test]
fn test_fsp_flags_roundtrip() {
    // All combinations of 3 bits
    for byte in 0u8..=0x07 {
        let flags = FspFlags::from_byte(byte);
        assert_eq!(flags.to_byte(), byte);
    }
}

#[test]
fn test_fsp_flags_individual_bits() {
    let cp = FspFlags::from_byte(0x01);
    assert!(cp.coords_present);
    assert!(!cp.key_epoch);
    assert!(!cp.unencrypted);

    let k = FspFlags::from_byte(0x02);
    assert!(!k.coords_present);
    assert!(k.key_epoch);
    assert!(!k.unencrypted);

    let u = FspFlags::from_byte(0x04);
    assert!(!u.coords_present);
    assert!(!u.key_epoch);
    assert!(u.unencrypted);
}

#[test]
fn test_fsp_flags_ignores_reserved_bits() {
    // Reserved bits in upper 5 bits are not preserved
    let flags = FspFlags::from_byte(0xFF);
    assert!(flags.coords_present);
    assert!(flags.key_epoch);
    assert!(flags.unencrypted);
    assert_eq!(flags.to_byte(), 0x07); // only lower 3 bits
}

// ===== FspInnerFlags Tests =====

#[test]
fn test_fsp_inner_flags_default() {
    let flags = FspInnerFlags::new();
    assert!(!flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x00);
}

#[test]
fn test_fsp_inner_flags_roundtrip() {
    let flags = FspInnerFlags::from_byte(0x01);
    assert!(flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x01);

    let flags = FspInnerFlags::from_byte(0x00);
    assert!(!flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x00);
}

#[test]
fn test_fsp_inner_flags_ignores_reserved() {
    let flags = FspInnerFlags::from_byte(0xFE);
    assert!(!flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x00);

    let flags = FspInnerFlags::from_byte(0xFF);
    assert!(flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x01);
}

// ===== New SessionMessageType Values =====

#[test]
fn test_session_message_type_new_values() {
    assert_eq!(SessionMessageType::SenderReport.to_byte(), 0x11);
    assert_eq!(SessionMessageType::ReceiverReport.to_byte(), 0x12);
    assert_eq!(SessionMessageType::PathMtuNotification.to_byte(), 0x13);
    assert_eq!(SessionMessageType::CoordsWarmup.to_byte(), 0x14);
    assert_eq!(SessionMessageType::EndpointData.to_byte(), 0x15);
    assert_eq!(SessionMessageType::TraversalOffer.to_byte(), 0x16);
    assert_eq!(SessionMessageType::TraversalAnswer.to_byte(), 0x17);
}

#[test]
fn test_session_message_type_display() {
    assert_eq!(
        format!("{}", SessionMessageType::SenderReport),
        "SenderReport"
    );
    assert_eq!(
        format!("{}", SessionMessageType::ReceiverReport),
        "ReceiverReport"
    );
    assert_eq!(
        format!("{}", SessionMessageType::PathMtuNotification),
        "PathMtuNotification"
    );
    assert_eq!(
        format!("{}", SessionMessageType::CoordsWarmup),
        "CoordsWarmup"
    );
    assert_eq!(
        format!("{}", SessionMessageType::EndpointData),
        "EndpointData"
    );
}

// ===== SessionSenderReport Tests =====

fn sample_session_sender_report() -> SessionSenderReport {
    SessionSenderReport {
        interval_start_counter: 100,
        interval_end_counter: 200,
        interval_start_timestamp: 5000,
        interval_end_timestamp: 6000,
        interval_bytes_sent: 50_000,
        cumulative_packets_sent: 10_000,
        cumulative_bytes_sent: 5_000_000,
    }
}

#[test]
fn test_session_sender_report_encode_size() {
    let sr = sample_session_sender_report();
    let encoded = sr.encode();
    assert_eq!(encoded.len(), SESSION_SENDER_REPORT_SIZE);
}

#[test]
fn test_session_sender_report_roundtrip() {
    let sr = sample_session_sender_report();
    let encoded = sr.encode();
    let decoded = SessionSenderReport::decode(&encoded).unwrap();
    assert_eq!(sr, decoded);
}

#[test]
fn test_session_sender_report_too_short() {
    assert!(SessionSenderReport::decode(&[0u8; 10]).is_err());
}

// ===== SessionReceiverReport Tests =====

fn sample_session_receiver_report() -> SessionReceiverReport {
    SessionReceiverReport {
        highest_counter: 195,
        cumulative_packets_recv: 9_500,
        cumulative_bytes_recv: 4_750_000,
        timestamp_echo: 5900,
        dwell_time: 5,
        max_burst_loss: 3,
        mean_burst_loss: 384,
        jitter: 1200,
        ecn_ce_count: 0,
        owd_trend: -50,
        burst_loss_count: 2,
        cumulative_reorder_count: 10,
        interval_packets_recv: 95,
        interval_bytes_recv: 47_500,
    }
}

#[test]
fn test_session_receiver_report_encode_size() {
    let rr = sample_session_receiver_report();
    let encoded = rr.encode();
    assert_eq!(encoded.len(), SESSION_RECEIVER_REPORT_SIZE);
}

#[test]
fn test_session_receiver_report_roundtrip() {
    let rr = sample_session_receiver_report();
    let encoded = rr.encode();
    let decoded = SessionReceiverReport::decode(&encoded).unwrap();
    assert_eq!(rr, decoded);
}

#[test]
fn test_session_receiver_report_too_short() {
    assert!(SessionReceiverReport::decode(&[0u8; 10]).is_err());
}

#[test]
fn test_session_receiver_report_negative_owd_trend() {
    let rr = SessionReceiverReport {
        owd_trend: -12345,
        ..sample_session_receiver_report()
    };
    let encoded = rr.encode();
    let decoded = SessionReceiverReport::decode(&encoded).unwrap();
    assert_eq!(decoded.owd_trend, -12345);
}

// ===== PathMtuNotification Tests =====

#[test]
fn test_path_mtu_notification_encode_size() {
    let n = PathMtuNotification::new(1400);
    let encoded = n.encode();
    assert_eq!(encoded.len(), PATH_MTU_NOTIFICATION_SIZE);
}

#[test]
fn test_path_mtu_notification_roundtrip() {
    let n = PathMtuNotification::new(1400);
    let encoded = n.encode();
    let decoded = PathMtuNotification::decode(&encoded).unwrap();
    assert_eq!(decoded.path_mtu, 1400);
}

#[test]
fn test_path_mtu_notification_too_short() {
    assert!(PathMtuNotification::decode(&[]).is_err());
    assert!(PathMtuNotification::decode(&[0x00]).is_err());
}

#[test]
fn test_path_mtu_notification_boundary_values() {
    for mtu in [0u16, 1280, 1500, u16::MAX] {
        let n = PathMtuNotification::new(mtu);
        let encoded = n.encode();
        let decoded = PathMtuNotification::decode(&encoded).unwrap();
        assert_eq!(decoded.path_mtu, mtu);
    }
}

// ===== MtuExceeded Tests =====

#[test]
fn test_mtu_exceeded_encode_size() {
    let err = MtuExceeded::new(make_node_addr(0xAA), make_node_addr(0xBB), 1400);
    let encoded = err.encode();
    // 4 prefix + 36 body = 40
    assert_eq!(encoded.len(), 4 + MTU_EXCEEDED_SIZE);
}

#[test]
fn test_mtu_exceeded_encode_decode() {
    let err = MtuExceeded::new(make_node_addr(0xAA), make_node_addr(0xBB), 1400);

    let encoded = err.encode();
    // Check FSP prefix: phase 0x0, U flag
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x04); // U flag
    // msg_type after prefix
    assert_eq!(encoded[4], 0x22);

    // decode after prefix + msg_type consumed
    let decoded = MtuExceeded::decode(&encoded[5..]).unwrap();
    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
    assert_eq!(decoded.mtu, 1400);
}

#[test]
fn test_mtu_exceeded_decode_too_short() {
    assert!(MtuExceeded::decode(&[]).is_err());
    assert!(MtuExceeded::decode(&[0x00; 20]).is_err());
    assert!(MtuExceeded::decode(&[0x00; 34]).is_err()); // exactly 1 byte short
}

#[test]
fn test_mtu_exceeded_boundary_mtu_values() {
    for mtu in [0u16, 1280, 1500, u16::MAX] {
        let err = MtuExceeded::new(make_node_addr(1), make_node_addr(2), mtu);
        let encoded = err.encode();
        let decoded = MtuExceeded::decode(&encoded[5..]).unwrap();
        assert_eq!(decoded.mtu, mtu);
    }
}

#[test]
fn test_mtu_exceeded_message_type_value() {
    assert_eq!(SessionMessageType::MtuExceeded.to_byte(), 0x22);
    assert_eq!(
        SessionMessageType::from_byte(0x22),
        Some(SessionMessageType::MtuExceeded)
    );
}

#[test]
fn test_mtu_exceeded_display() {
    assert_eq!(
        format!("{}", SessionMessageType::MtuExceeded),
        "MtuExceeded"
    );
}

// ===== SessionMsg3 Tests =====

#[test]
fn test_session_msg3_encode_decode() {
    let handshake = vec![0xCC; 73]; // typical XK msg3
    let msg3 = SessionMsg3::new(handshake.clone());

    let encoded = msg3.encode();
    // Verify FSP prefix: ver_phase=0x03 (version 0, phase MSG3)
    assert_eq!(encoded[0], 0x03);
    assert_eq!(encoded[1], 0x00); // flags = 0 for handshake
    let payload_len = u16::from_le_bytes([encoded[2], encoded[3]]);
    assert_eq!(payload_len as usize, encoded.len() - 4);

    // Decode (skip 4-byte FSP prefix)
    let decoded = SessionMsg3::decode(&encoded[4..]).unwrap();
    assert_eq!(decoded.flags, 0);
    assert_eq!(decoded.handshake_payload, handshake);
}

#[test]
fn test_session_msg3_decode_too_short() {
    assert!(SessionMsg3::decode(&[]).is_err());
    assert!(SessionMsg3::decode(&[0x00]).is_err()); // flags only, no hs_len
}

#[test]
fn test_session_msg3_empty_handshake() {
    let msg3 = SessionMsg3::new(vec![]);
    let encoded = msg3.encode();
    let decoded = SessionMsg3::decode(&encoded[4..]).unwrap();
    assert!(decoded.handshake_payload.is_empty());
}
