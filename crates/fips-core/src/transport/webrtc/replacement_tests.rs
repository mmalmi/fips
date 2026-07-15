use super::*;
use crate::packet_channel;

#[tokio::test]
async fn one_mapless_closing_offer_waits_for_release_and_later_offers_are_refused() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(84),
        None,
        WebRtcConfig {
            max_connections: Some(1),
            resolve_mdns_candidates: Some(false),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let addr = TransportAddr::from_string("mapless-closing-peer");
    let pc = transport
        .physical
        .reserve(&addr)
        .expect("physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    let raw_pc = pc.raw();
    let completion = start_peer_connection_cleanup(pc);
    assert_eq!(
        transport.physical.phase(&addr),
        Some(PhysicalPhase::Closing)
    );

    let waiting_resources = transport.physical.clone();
    let waiting_addr = addr.clone();
    let first = tokio::spawn(async move {
        reserve_physical_for_incoming_offer(
            &waiting_resources,
            &waiting_addr,
            now_ms() + 2_000,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !transport.physical.has_peer_release_waiter(&addr) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first replacement owns the per-peer waiter");

    let second = tokio::time::timeout(
        Duration::from_millis(100),
        reserve_physical_for_incoming_offer(&transport.physical, &addr, now_ms() + 2_000),
    )
    .await
    .expect("later same-peer offer is rejected without waiting");
    assert!(matches!(
        second,
        Err(PhysicalReserveError::PeerBusy(PhysicalPhase::Closing))
    ));

    first.abort();
    match first.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("first replacement waiter was not cancelled"),
    }
    assert!(!transport.physical.has_peer_release_waiter(&addr));
    let waiting_resources = transport.physical.clone();
    let waiting_addr = addr.clone();
    let successor = tokio::spawn(async move {
        reserve_physical_for_incoming_offer(
            &waiting_resources,
            &waiting_addr,
            now_ms() + 2_000,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !transport.physical.has_peer_release_waiter(&addr) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled waiter releases the per-peer slot");

    drop(raw_pc);
    completion.wait().await;
    let replacement = successor
        .await
        .expect("replacement waiter task")
        .expect("first replacement reserves after real cleanup");
    drop(replacement);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = transport.resource_snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.creating + snapshot.active + snapshot.closing, 0);
}
