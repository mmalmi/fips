#![cfg(unix)]

use fips_core::{Identity, PeerIdentity};
use fips_relay::probe::{ProbeReceiver, ReceiveProbe, SendProbe, encode_packet};

fn peer() -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full())
}

#[test]
fn receiver_attributes_unique_packets_to_the_armed_source_and_stream() {
    let source = peer();
    let unrelated = peer();
    let id = "102030405060708090a0b0c0d0e0f000";
    let mut receiver = ProbeReceiver::new(ReceiveProbe {
        source: source.npub(),
        stream_id: id.into(),
        packet_count: 4,
        payload_bytes: 80,
        measure_one_way_latency: true,
    })
    .unwrap();
    let p0 = encode_packet(id, 0, 80, 1_000).unwrap();
    let p2 = encode_packet(id, 2, 80, 1_500).unwrap();
    let p1 = encode_packet(id, 1, 80, 1_700).unwrap();
    receiver.record(unrelated, &p0, 1_100);
    receiver.record(source, b"unrelated application payload", 1_100);
    receiver.record(
        source,
        &encode_packet(&"b".repeat(32), 0, 80, 1_000).unwrap(),
        1_100,
    );
    receiver.record(source, &p0, 1_200);
    receiver.record(source, &p0, 1_300);
    receiver.record(source, &p2, 2_000);
    receiver.record(source, &p1, 2_700);
    receiver.record(source, &encode_packet(id, 4, 80, 1_000).unwrap(), 3_000);
    let report = receiver.report();
    assert_eq!(report.unique_packets, 3);
    assert_eq!(report.unique_bytes, 240);
    assert_eq!(report.missing_packets, 1);
    assert_eq!(report.duplicate_packets, 1);
    assert_eq!(report.out_of_order_packets, 1);
    assert_eq!(report.ignored_packets, 3);
    assert_eq!(report.invalid_packets, 1);
    let latency = report.latency.unwrap();
    assert_eq!(latency.samples, 3);
    assert_eq!(latency.min_us, Some(200));
    assert_eq!(latency.max_us, Some(1_000));
    assert_eq!(latency.sum_us, 1_700);
    assert_eq!(latency.bucket_counts.iter().sum::<u64>(), 3);
}

#[test]
fn measurements_require_explicit_clock_assumption_and_ignore_invalid_timestamps() {
    let source = peer();
    let id = "00000000000000000000000000000001";
    let mut args = ReceiveProbe {
        source: source.npub(),
        stream_id: id.into(),
        packet_count: 2,
        payload_bytes: 64,
        measure_one_way_latency: false,
    };
    let mut receiver = ProbeReceiver::new(args.clone()).unwrap();
    receiver.record(source, &encode_packet(id, 0, 64, 2_000).unwrap(), 1_000);
    assert!(receiver.report().latency.is_none());
    args.measure_one_way_latency = true;
    let mut receiver = ProbeReceiver::new(args).unwrap();
    receiver.record(source, &encode_packet(id, 0, 64, 2_000).unwrap(), 1_000);
    receiver.record(source, &encode_packet(id, 1, 64, 100).unwrap(), 100_000_000);
    let report = receiver.report();
    assert_eq!(report.unique_packets, 2);
    assert_eq!(report.latency.unwrap().invalid_timestamps, 2);
}

#[test]
fn unbounded_or_malformed_probe_requests_are_rejected_before_sending() {
    let source = peer();
    let mut request = SendProbe {
        destination: source.npub(),
        stream_id: "a".repeat(32),
        packet_count: 100,
        payload_bytes: 1_000,
        packets_per_second: 100,
    };
    assert!(request.validate().is_ok());
    request.packets_per_second = 0;
    assert!(request.validate().is_err());
    request.packets_per_second = 16_001;
    assert!(request.validate().is_err());
    request.packets_per_second = 1;
    assert!(
        request.validate().is_err(),
        "a run must fit its duration limit"
    );
    request.packet_count = 65_537;
    request.packets_per_second = 16_000;
    assert!(request.validate().is_err());
    request.packet_count = 1;
    request.payload_bytes = 39;
    assert!(request.validate().is_err());
    request.payload_bytes = 1_001;
    assert!(request.validate().is_err());
    request.payload_bytes = 64;
    request.stream_id = "x".repeat(32);
    assert!(request.validate().is_err());
}
