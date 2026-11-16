use super::*;
use fips_core::Identity;

fn request() -> SendProbe {
    SendProbe {
        destination: PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full()).npub(),
        stream_id: "61".repeat(16),
        packet_count: 3,
        payload_bytes: 80,
        packets_per_second: 10,
        measure_round_trip: true,
        max_duration_secs: None,
    }
}

fn reflector(request: &SendProbe) -> ProbeReceiver {
    ProbeReceiver::new(ReceiveProbe {
        source: request.destination.clone(),
        stream_id: request.stream_id.clone(),
        packet_count: request.packet_count,
        payload_bytes: request.payload_bytes,
        reflect: true,
        measure_one_way_latency: false,
        lifetime_secs: None,
    })
    .unwrap()
}

#[test]
fn reflection_is_opt_in_bounded_unique_and_cannot_echo_a_reply() {
    let request = request();
    let peer = PeerIdentity::from_npub(&request.destination).unwrap();
    let mut receiver = reflector(&request);
    let first = encode_packet(&request.stream_id, 0, 80, u64::MAX).unwrap();
    receiver.reflect = false;
    assert!(receiver.record(peer, &first, 0).is_none());
    receiver = reflector(&request);
    let reply = receiver.record(peer, &first, 0).unwrap();
    assert_eq!(reply.len(), first.len());
    assert_eq!(&reply[8..], &first[8..]);
    assert!(receiver.record(peer, &first, 0).is_none());
    assert!(receiver.record(peer, &reply, 0).is_none());
    let other = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let mut second = encode_packet(&request.stream_id, 1, 80, 0).unwrap();
    assert!(receiver.record(other, &second, 0).is_none());
    second[79] = 0;
    assert!(receiver.record(peer, &second, 0).is_none());
    second[79] = 0x5a;
    second.truncate(79);
    assert!(receiver.record(peer, &second, 0).is_none());
    assert!(
        receiver
            .record(
                peer,
                &encode_packet(&request.stream_id, 3, 80, 0).unwrap(),
                0
            )
            .is_none()
    );
    receiver.expires = Instant::now();
    assert!(
        receiver
            .record(
                peer,
                &encode_packet(&request.stream_id, 1, 80, 0).unwrap(),
                0
            )
            .is_none()
    );
    assert_eq!(receiver.report.unique_packets, 1);
    assert_eq!(receiver.report.duplicate_packets, 1);
    assert_eq!(receiver.report.invalid_packets, 3);
    assert_eq!(receiver.report.ignored_packets, 3);
}

#[test]
fn round_trip_uses_local_monotonic_samples_and_rejects_unsent_or_changed_payloads() {
    let request = request();
    let peer = PeerIdentity::from_npub(&request.destination).unwrap();
    let mut receiver = ProbeReceiver::round_trip(&request).unwrap();
    let mut remote = reflector(&request);
    let first = encode_packet(&request.stream_id, 0, 80, u64::MAX).unwrap();
    let reply = remote.record(peer, &first, 0).unwrap();
    assert!(receiver.record(peer, &reply, 0).is_none());
    assert_eq!(
        receiver.report.unique_packets, 0,
        "unsent sequence cannot create a sample"
    );
    receiver.sent.as_mut().unwrap()[0] =
        Some((Instant::now() - Duration::from_millis(2), u64::MAX));
    let mut forged = reply.clone();
    forged[39] = 0;
    assert!(receiver.record(peer, &forged, 0).is_none());
    assert!(
        receiver.record(peer, &first, 0).is_none(),
        "request magic cannot stand in for reply"
    );
    assert!(
        receiver.record(peer, &reply, 0).is_none(),
        "replies never reflect"
    );
    receiver.record(peer, &reply, 0);
    let report = receiver.report();
    assert_eq!(report.unique_packets, 1);
    assert_eq!(report.invalid_packets, 2);
    assert_eq!(report.duplicate_packets, 1);
    assert!(report.latency.is_none());
    let timing = report.round_trip_latency.unwrap();
    assert_eq!(timing.samples, 1);
    assert!(timing.min_us.unwrap() >= 2_000);
    assert_eq!(
        timing.invalid_timestamps, 0,
        "remote wall clock is not a clock source"
    );
    receiver.sent.as_mut().unwrap()[1] = Some((Instant::now(), 5));
    receiver.expires = Instant::now();
    let second = encode_packet(&request.stream_id, 1, 80, 5).unwrap();
    let reply = remote.record(peer, &second, 0).unwrap();
    assert!(receiver.record(peer, &reply, 0).is_none());
    assert_eq!(receiver.report.unique_packets, 1);
}

#[test]
fn existing_json_requests_remain_passive_by_default() {
    let mut json = serde_json::to_value(request()).unwrap();
    json.as_object_mut().unwrap().remove("measure_round_trip");
    assert!(
        !serde_json::from_value::<SendProbe>(json)
            .unwrap()
            .measure_round_trip
    );
    let json = serde_json::json!({"source":request().destination, "stream_id":"61".repeat(16),
        "packet_count":1, "payload_bytes":80});
    let parsed: ReceiveProbe = serde_json::from_value(json).unwrap();
    assert!(!parsed.reflect);
    assert!(!parsed.measure_one_way_latency);
}

#[test]
fn explicit_long_probes_remain_bounded_and_preserve_short_defaults() {
    let mut json = serde_json::to_value(request()).unwrap();
    json["packet_count"] = 42_000.into();
    json["packets_per_second"] = 140.into();
    let short: SendProbe = serde_json::from_value(json.clone()).unwrap();
    assert!(short.validate().is_err());
    json["max_duration_secs"] = 300.into();
    let long: SendProbe = serde_json::from_value(json.clone()).unwrap();
    assert!(long.validate().is_ok());
    let round_trip = ProbeReceiver::round_trip(&long).unwrap();
    assert!(round_trip.expires > Instant::now() + Duration::from_secs(329));
    assert!(round_trip.expires <= Instant::now() + Duration::from_secs(330));
    for invalid in [0, 299, 301, u64::MAX] {
        json["max_duration_secs"] = invalid.into();
        assert!(
            serde_json::from_value::<SendProbe>(json.clone())
                .unwrap()
                .validate()
                .is_err()
        );
    }
    json["max_duration_secs"] = 300.into();
    json["packet_count"] = 65_537.into();
    json["packets_per_second"] = 1_000.into();
    assert!(
        serde_json::from_value::<SendProbe>(json)
            .unwrap()
            .validate()
            .is_err()
    );

    let mut json = serde_json::json!({"source":request().destination, "stream_id":"61".repeat(16),
        "packet_count":42_000, "payload_bytes":1_000});
    let receiver = ProbeReceiver::new(serde_json::from_value(json.clone()).unwrap()).unwrap();
    assert!(receiver.expires > Instant::now() + Duration::from_secs(59));
    assert!(receiver.expires <= Instant::now() + Duration::from_secs(60));
    json["lifetime_secs"] = 360.into();
    let receiver = ProbeReceiver::new(serde_json::from_value(json.clone()).unwrap()).unwrap();
    assert!(receiver.expires > Instant::now() + Duration::from_secs(359));
    for invalid in [0, 361, u64::MAX] {
        json["lifetime_secs"] = invalid.into();
        assert!(ProbeReceiver::new(serde_json::from_value(json.clone()).unwrap()).is_err());
    }
}
