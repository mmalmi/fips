use super::*;
use fips_core::node::{ForwardingClass, ForwardingOutcome, ForwardingPolicy};

fn limited() -> FreeRoutes {
    FreeRoutes::default()
        .with_bandwidth(FreeBandwidthPolicy {
            global_bytes_per_second: 1,
            global_burst_bytes: 1_024,
            peer_bytes_per_second: 1,
            peer_burst_bytes: 512,
        })
        .unwrap()
}

fn install(routes: &FreeRoutes, buyer: u8, destination: u8, suffix: &str) -> RouteOffer {
    let mut incoming = offer(buyer, 2, 3);
    let mut onward = offer(2, 3, destination);
    for grant in [&mut incoming, &mut onward] {
        grant.id.push_str(suffix);
        grant.destination = peer(destination);
        grant.max_units = 4_096;
    }
    routes.offer(&incoming).unwrap();
    routes.accept(&onward).unwrap();
    onward
}

#[test]
fn free_bandwidth_is_shared_across_new_grants_destinations_and_identities() {
    let routes = limited();
    let onward = install(&routes, 1, 9, "a");
    let mut data = request(&[7; 256]);
    assert!(routes.admit(&data));
    assert!(routes.admit(&data));
    assert!(!routes.admit(&data));
    assert_eq!(routes.remaining_units(&onward), Some(3_584));

    install(&routes, 1, 9, "b");
    assert!(!routes.admit(&data), "a fresh quote cannot reset bandwidth");
    install(&routes, 1, 8, "c");
    data.destination = *peer(8).node_addr();
    data.source = *peer(7).node_addr();
    assert!(
        !routes.admit(&data),
        "claimed addresses cannot reset peer debt"
    );

    install(&routes, 4, 9, "d");
    data.ingress = peer(4);
    data.destination = *peer(9).node_addr();
    assert!(routes.admit(&data));
    assert!(routes.admit(&data));
    install(&routes, 5, 9, "e");
    data.ingress = peer(5);
    assert!(
        !routes.admit(&data),
        "new identities cannot evade the global cap"
    );
    let stats = routes.stats().bandwidth.unwrap();
    assert_eq!(
        (
            stats.admitted_packets,
            stats.charged_units,
            stats.tracked_peers
        ),
        (4, 1_024, 2)
    );
}

#[test]
fn denied_free_permissions_do_not_consume_bandwidth_or_onward_quota() {
    let routes = limited();
    let data = request(&[7; 256]);
    assert!(!routes.admit(&data));
    let mut incoming = offer(1, 2, 3);
    incoming.max_units = 4_096;
    routes.offer(&incoming).unwrap();
    assert!(!routes.admit(&data), "onward permission is still missing");
    assert_eq!(routes.stats().bandwidth.unwrap().charged_units, 0);
    let mut onward = offer(2, 3, 9);
    onward.max_units = 4_096;
    routes.accept(&onward).unwrap();
    assert!(routes.admit(&data));
    assert!(routes.admit(&data));
    assert!(!routes.admit(&data));
    assert_eq!(routes.remaining_units(&onward), Some(3_584));
    assert_eq!(routes.stats().admitted_session_bytes, 512);
}

#[test]
fn tiny_free_packets_pay_a_processing_floor() {
    let routes = limited();
    install(&routes, 1, 9, "tiny");
    let data = request(&[1]);
    assert!(routes.admit(&data));
    assert!(routes.admit(&data));
    assert!(!routes.admit(&data));
    let stats = routes.stats().bandwidth.unwrap();
    assert_eq!(
        (stats.admitted_session_bytes, stats.charged_units),
        (2, 512)
    );
}

#[test]
fn paid_prefix_does_not_spend_local_free_bandwidth_for_a_free_continuation() {
    let routes = limited();
    let onward = install(&routes, 1, 9, "paid-prefix");
    let data = request(&[7; 256]);
    assert!(routes.admit(&data));
    assert!(routes.admit(&data));
    assert!(!routes.admit(&data));
    assert_eq!(
        routes.onward(
            onward.provider,
            *onward.destination.node_addr(),
            256,
            || Some(9)
        ),
        Some(9)
    );
    assert_eq!(routes.stats().bandwidth.unwrap().charged_units, 512);
    assert_eq!(routes.remaining_units(&onward), Some(3_328));
}

#[test]
fn negotiated_free_class_is_bound_to_the_admission_and_rate_limit() {
    let root = tempfile::tempdir().unwrap();
    let seller = Arc::new(
        DurableRelay::create(&root.path().join("seller"), Limits::default(), 100).unwrap(),
    );
    let buyer = Arc::new(
        BuyerAuthorizer::create(
            &root.path().join("buyer"),
            *peer(2).node_addr(),
            10,
            Limits::default(),
        )
        .unwrap(),
    );
    let free = Arc::new(limited());
    install(&free, 1, 9, "classification");
    let forwarder = crate::buyer::PaidForwarder::with_free_routes(
        seller,
        buyer,
        BillingBasis::ForwardingData,
        free.clone(),
    );
    for _ in 0..2 {
        let admission = forwarder.admit_classified(&request(&[7; 256])).unwrap();
        assert_eq!(admission.class, ForwardingClass::Background);
        assert_eq!(admission.token, 0);
        forwarder.complete(admission.token, ForwardingOutcome::Submitted);
    }
    assert!(forwarder.admit_classified(&request(&[7; 256])).is_none());
    assert_eq!(free.stats().bandwidth.unwrap().charged_units, 512);
}
