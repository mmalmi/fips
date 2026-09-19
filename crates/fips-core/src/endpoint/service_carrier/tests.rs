use super::*;
use crate::endpoint::{FipsEndpointOutboundDatagram, service_datagram_payloads};

#[test]
fn service_carrier_registration_is_bounded_idempotent_and_optional() {
    let registry = ServiceCarrierRegistry::default();
    assert!(registry.for_ports(40000, 44743).is_none());
    for port in 1..=SERVICE_CARRIER_DIAGNOSTICS_MAX_SERVICES as u16 {
        let handle = registry.enable(port).unwrap();
        assert_eq!(handle, registry.enable(port).unwrap());
    }
    assert!(matches!(
        registry.enable(44743),
        Err(FipsEndpointError::ServiceCarrierDiagnosticsLimit)
    ));
    assert!(registry.for_ports(40000, 44743).is_none());
}

#[test]
fn service_carrier_tags_requests_replies_and_ambiguity_without_changing_service_data() {
    let registry = ServiceCarrierRegistry::default();
    let payment = registry.enable(44743).unwrap();
    let other = registry.enable(12000).unwrap();
    for (source, destination, expected) in [
        (40000, 44743, Some(payment.clone())),
        (44743, 40000, Some(payment.clone())),
        (40000, 40001, None),
        (44743, 12000, Some(payment.clone())),
    ] {
        let payloads = service_datagram_payloads(
            vec![FipsEndpointOutboundDatagram::new(
                source,
                destination,
                vec![1, 2, 3],
            )],
            &registry,
        )
        .unwrap();
        let (kind, body, handle) = payloads.into_iter().next().unwrap().into_fsp_payload();
        assert_eq!(
            kind,
            crate::protocol::SessionMessageType::DataPacket.to_byte()
        );
        assert_eq!(&body.as_slice()[..2], &source.to_le_bytes());
        assert_eq!(&body.as_slice()[2..4], &destination.to_le_bytes());
        assert_eq!(&body.as_slice()[4..], &[1, 2, 3]);
        assert_eq!(handle, expected);
    }
    assert_eq!(payment.snapshot().ambiguous_port_datagrams, 1);
    assert_eq!(other.snapshot().ambiguous_port_datagrams, 0);
    assert!(
        payment
            .snapshot()
            .transports
            .iter()
            .all(|item| item.submitted_packets == 0)
    );
    assert_eq!(registry.for_ports(44743, 44743), Some(payment.clone()));
    assert_eq!(payment.snapshot().ambiguous_port_datagrams, 1);
}

#[test]
fn service_carrier_counts_known_framing_separately_and_saturates() {
    let counters = ServiceCarrierDiagnostics::new(44743);
    for transport in ["udp", "ethernet", "tcp", "unknown-carrier"] {
        counters.submitted(transport, 100);
    }
    let snapshot = counters.snapshot();
    for transport in ["udp", "ethernet", "tcp", "other"] {
        let value = snapshot
            .transports
            .iter()
            .find(|value| value.transport == transport)
            .unwrap();
        assert_eq!(value.submitted_packets, 1);
        assert_eq!(value.fips_payload_bytes, 100);
        assert_eq!(
            value.ethernet_framing_bytes,
            if transport == "ethernet" { 3 } else { 0 }
        );
    }
    counters.0.transports[0]
        .payload_bytes
        .store(u64::MAX - 1, Ordering::Relaxed);
    counters.submitted("udp", 100);
    assert_eq!(
        counters.snapshot().transports[0].fips_payload_bytes,
        u64::MAX
    );
}

#[tokio::test]
async fn service_carrier_loopback_has_no_transport_cost() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .unwrap();
    endpoint.register_service(44743).await.unwrap();
    let counters = endpoint.enable_service_carrier_diagnostics(44743).unwrap();
    let local = crate::PeerIdentity::from_npub(endpoint.npub()).unwrap();
    endpoint
        .send_datagram(local, 40000, 44743, vec![1, 2, 3])
        .await
        .unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        endpoint.recv_service_datagram_batch_into(&mut received, 1),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].data.as_slice(), &[1, 2, 3]);
    assert!(
        counters
            .snapshot()
            .transports
            .iter()
            .all(|item| item.submitted_packets == 0)
    );
    assert_eq!(counters.snapshot().discarded_outputs, 0);
    endpoint.shutdown().await.unwrap();
}
