use super::*;
use crate::endpoint::{ServiceCarrierDiagnostics, ServiceCarrierTransportSnapshot};

fn udp_counters(counters: &ServiceCarrierDiagnostics) -> ServiceCarrierTransportSnapshot {
    counters
        .snapshot()
        .transports
        .into_iter()
        .find(|value| value.transport == "udp")
        .unwrap()
}

fn sealed_service_packet(
    counters: Option<ServiceCarrierDiagnostics>,
    wrapped: bool,
) -> PacketOutput {
    let owner = fsp_owner(810);
    let next = fmp_owner(811);
    let route = DataplaneEndpointDataRoute::fsp(
        owner,
        1,
        crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        0,
    )
    .with_direct_transport();
    let payload = EndpointDataPayload::from_service_datagram(40000, 44743, vec![7; 700])
        .unwrap()
        .with_service_carrier(counters.clone());
    let mut packet = route
        .route_payloads(vec![payload], ActivityTick::new(1), None)
        .routed
        .pop()
        .unwrap();
    if wrapped {
        packet.post_seal = OutboundPostSeal::FmpWrap(DataplaneFspWrapRoute::new(
            next,
            1,
            811,
            test_node_addr(809),
            owner.node_addr(),
        ));
    }
    let expected_len = if wrapped {
        packet.fsp_wrapped_wire_len()
    } else {
        packet.fsp_session_wire_len()
    }
    .unwrap();
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8).with_fsp_session_start_ms(0));
    // Live FMP owners have a session clock, which supplies the four-byte timestamp.
    mover.register_owner(next, OwnerConfig::new(1, 8).with_fmp_session_start_ms(0));
    mover.submit_outbound_packet(packet).unwrap();
    let work = dispatch_outbound_available(&mut mover, 1).pop().unwrap();
    let mut untagged = work.packet.clone();
    untagged.service_carrier = None;
    let untagged = execute_seal_crypto_work(untagged, &work.reservation, &test_cipher(7));
    let mut result = execute_seal_crypto_work(work.packet, &work.reservation, &test_cipher(7));
    match (&result, untagged) {
        (CryptoResult::Sealed(measured), CryptoResult::Sealed(plain)) => {
            assert_eq!(measured.payload, plain.payload);
        }
        (CryptoResult::Outbound(measured), CryptoResult::Outbound(plain)) => {
            assert_eq!(measured.payload, plain.payload);
        }
        _ => panic!("local metadata must not change sealing or wrapping"),
    }
    if wrapped {
        let CryptoResult::Outbound(packet) = result else {
            panic!("FSP must be wrapped");
        };
        assert_eq!(packet.service_carrier, counters);
        mover.submit_outbound_packet(packet).unwrap();
        let work = dispatch_outbound_available(&mut mover, 1).pop().unwrap();
        assert_eq!(work.reservation.fmp_timestamp_ms, Some(1));
        result = execute_seal_crypto_work(work.packet, &work.reservation, &test_cipher(8));
    }
    let CryptoResult::Sealed(output) = result else {
        panic!("service payload must seal");
    };
    assert_eq!(output.service_carrier, counters);
    assert_eq!(output.payload_len(), expected_len);
    output
}

#[test]
fn service_carrier_metadata_survives_fsp_and_fmp_without_changing_wire() {
    for wrapped in [false, true] {
        let counters = ServiceCarrierDiagnostics::new(44743);
        let measured = sealed_service_packet(Some(counters.clone()), wrapped);
        let plain = sealed_service_packet(None, wrapped);
        assert_eq!(measured.payload_len(), plain.payload_len());
        assert_eq!(
            udp_counters(&counters).submitted_packets,
            0,
            "sealing is not submission"
        );
        let mut batch = DataplaneTransportPayloadBatch::with_capacity(1);
        let expected = measured.payload_len() as u64;
        batch.push_whole(measured);
        let mut sent = 0;
        let mut drops = Vec::new();
        batch.finish_send(1, &mut drops, &mut None, &mut sent);
        assert_eq!(udp_counters(&counters).fips_payload_bytes, expected);
        assert_eq!(udp_counters(&counters).submitted_packets, 1);
        assert_eq!(sent, 1);
        assert!(drops.is_empty());
    }
}

#[test]
fn service_carrier_counts_repeated_encoded_segments_but_not_unrelated_service_outputs() {
    let counters = ServiceCarrierDiagnostics::new(44743);
    let output = sealed_service_packet(Some(counters.clone()), false);
    let expected = output.payload_len() as u64;
    let mut batch = DataplaneTransportPayloadBatch::with_capacity(3);
    // The same encoded service record retransmitted still occupies carrier bytes.
    batch.push_whole(output.clone());
    batch.push_whole(output);
    batch.push_whole(sealed_service_packet(None, false));
    batch.finish_send(3, &mut Vec::new(), &mut None, &mut 0);
    assert_eq!(udp_counters(&counters).submitted_packets, 2);
    assert_eq!(udp_counters(&counters).fips_payload_bytes, expected * 2);
}

#[test]
fn service_carrier_partial_fragment_batch_retains_sent_prefix_cost_and_rejects_the_output() {
    let counters = ServiceCarrierDiagnostics::new(44743);
    let mut output = sealed_service_packet(Some(counters.clone()), false);
    output.path_mtu = 220;
    let DataplaneDirectFspTransportOutput::Segments(segments) =
        dataplane_direct_fsp_transport_output(output)
    else {
        panic!("expected real FSP transport fragmentation");
    };
    assert!(segments.len() > 2);
    let expected = segments.payload_len(0) + segments.payload_len(1);
    let mut batch = DataplaneTransportPayloadBatch::with_capacity(1);
    batch.push_direct_fsp_segments(segments);
    let mut sent = 0;
    let mut drops = Vec::new();
    let mut receipts = Vec::new();
    batch.finish_send(2, &mut drops, &mut Some(&mut receipts), &mut sent);
    assert_eq!(udp_counters(&counters).submitted_packets, 2);
    assert_eq!(udp_counters(&counters).fips_payload_bytes, expected as u64);
    assert_eq!(counters.snapshot().discarded_outputs, 1);
    assert_eq!(
        sent, 0,
        "whole-record success cannot hide a partial fragment send"
    );
    assert!(receipts.is_empty());
    assert_eq!(drops.len(), 1);
}

#[test]
fn service_carrier_failed_submission_has_no_invented_carrier_bytes() {
    let counters = ServiceCarrierDiagnostics::new(44743);
    let output = sealed_service_packet(Some(counters.clone()), false);
    let mut batch = DataplaneTransportPayloadBatch::with_capacity(1);
    batch.push_whole(output);
    batch.finish_send(0, &mut Vec::new(), &mut None, &mut 0);
    assert_eq!(udp_counters(&counters).submitted_packets, 0);
    assert_eq!(udp_counters(&counters).fips_payload_bytes, 0);
    assert_eq!(counters.snapshot().discarded_outputs, 1);
}

#[test]
fn service_carrier_partial_batch_counts_only_the_submitted_prefix_of_each_record() {
    let counters = ServiceCarrierDiagnostics::new(44743);
    let mut output = sealed_service_packet(Some(counters.clone()), false);
    output.path_mtu = 220;
    let DataplaneDirectFspTransportOutput::Segments(segments) =
        dataplane_direct_fsp_transport_output(output)
    else {
        panic!("expected fragmented service record");
    };
    assert!(segments.len() > 2);
    let expected = segments.payload_len(0) + segments.payload_len(1);
    let mut batch = DataplaneTransportPayloadBatch::with_capacity(3);
    batch.push_whole(sealed_service_packet(None, false));
    batch.push_direct_fsp_segments(segments);
    batch.push_whole(sealed_service_packet(Some(counters.clone()), false));
    let mut sent = 0;
    let mut drops = Vec::new();
    let mut receipts = Vec::new();
    batch.finish_send(3, &mut drops, &mut Some(&mut receipts), &mut sent);
    assert_eq!(udp_counters(&counters).submitted_packets, 2);
    assert_eq!(udp_counters(&counters).fips_payload_bytes, expected as u64);
    assert_eq!(counters.snapshot().discarded_outputs, 2);
    assert_eq!(sent, 1);
    assert_eq!(receipts.len(), 1);
    assert_eq!(drops.len(), 2);
}

#[tokio::test]
async fn service_carrier_actual_udp_submission_matches_received_fragment_bytes() {
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport_id = TransportId::new(812);
    let mut transport = unstarted_udp_transport(transport_id);
    transport.start().await.unwrap();
    let counters = ServiceCarrierDiagnostics::new(44743);
    let mut output = sealed_service_packet(Some(counters.clone()), false);
    output.path_mtu = 220;
    let wire_len = output.payload_len();
    let fragments = wire_len.div_ceil(220 - DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN);
    let remote = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
    let groups = vec![DataplaneTransportPlanGroup::new(
        transport_id,
        remote,
        output,
    )];
    let mut transports = HashMap::from([(transport_id, transport)]);
    let mut drops = Vec::new();
    let sent = send_dataplane_transport_groups(&transports, groups, &mut drops, 1, None).await;
    assert_eq!(sent, 1);
    assert!(drops.is_empty());
    let mut received_bytes = 0;
    let mut buffer = [0; 220];
    for _ in 0..fragments {
        received_bytes += tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.recv(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
    }
    transports
        .get_mut(&transport_id)
        .unwrap()
        .stop()
        .await
        .unwrap();
    assert_eq!(
        received_bytes,
        wire_len + fragments * DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN
    );
    assert_eq!(udp_counters(&counters).submitted_packets, fragments as u64);
    assert_eq!(
        udp_counters(&counters).fips_payload_bytes,
        received_bytes as u64
    );
    assert_eq!(udp_counters(&counters).ethernet_framing_bytes, 0);
    assert_eq!(counters.snapshot().discarded_outputs, 0);
}
