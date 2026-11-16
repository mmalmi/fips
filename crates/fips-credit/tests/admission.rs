use fips_core::{
    Identity, NodeAddr, PeerIdentity,
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use fips_credit::{CreditForwarder, Route};
use peer_payments::{Agreement, Book, Keypair, Limits, SchnorrVerifier, WireMessage, sign_message};

fn key(n: u8) -> Keypair {
    format!("{n:02x}").repeat(32).parse().unwrap()
}
fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey())
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn window(payer: u8, seller: u8, route: &Route, units: u64) -> (Book, peer_payments::Allowance) {
    let (payer_key, seller_key) = (key(payer), key(seller));
    let a = Agreement {
        id: format!("{payer}-{seller}"),
        payer: peer(payer).pubkey().to_string(),
        provider: peer(seller).pubkey().to_string(),
        service: "fips.forwarding.attempt_bytes".into(),
        resource: route.resource(),
        max_units: units,
        price_sat: 1,
        price_per_units: units,
        max_amount_sat: 1,
        created_at: now(),
        expires_at: now() + 120,
    };
    let mut book = Book::new(&a.provider, Limits::default(), [a.payer.clone()]).unwrap();
    let m = WireMessage::Agreement(a.clone());
    book.accept(
        &a,
        &sign_message(&payer_key, &m).unwrap(),
        &sign_message(&seller_key, &m).unwrap(),
        &SchnorrVerifier,
        now(),
    )
    .unwrap();
    let allowance = book.reserve_window(&a.id, 0, units, now()).unwrap();
    (book, allowance)
}

#[test]
fn forwarding_binds_authenticated_ingress_route_quota_and_uncertain_sends() {
    let route = Route {
        ingress_pubkey: peer(1).pubkey().serialize(),
        next_hop: *peer(3).node_addr(),
        destination: *peer(4).node_addr(),
    };
    let (_book, allowance) = window(1, 2, &route, 100);
    let policy = CreditForwarder::new(&peer(2));
    policy.install(route.clone(), allowance).unwrap();
    let mut request = ForwardingRequest {
        ingress: peer(1),
        next_hop: route.next_hop,
        source: *peer(9).node_addr(),
        destination: route.destination,
        session_payload: &[0; 50],
    };
    // Claimed source is irrelevant: the authenticated neighbor pays this hop.
    let first = policy.admit(&request).unwrap();
    policy.complete(first, ForwardingOutcome::Unconfirmed);
    request.ingress = peer(9);
    assert!(policy.admit(&request).is_none());
    request.ingress = peer(1);
    request.destination = *peer(9).node_addr();
    assert!(policy.admit(&request).is_none());
    request.destination = route.destination;
    request.next_hop = NodeAddr::from_bytes([7; 16]);
    assert!(policy.admit(&request).is_none());
    request.next_hop = route.next_hop;
    let second = policy.admit(&request).unwrap();
    policy.complete(second, ForwardingOutcome::Submitted);
    assert!(policy.admit(&request).is_none()); // neither completion refunds quota
    let (_, wrong) = window(1, 2, &route, 100);
    assert!(
        CreditForwarder::new(&peer(3))
            .install(route, wrong)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_three_hop_service_works_without_a_mint_and_stops_when_revoked() {
    use fips_core::{
        Config, FipsEndpoint, SimLink, SimNetwork,
        config::{SimTransportConfig, TransportInstances},
    };
    use std::{sync::Arc, time::Duration};
    let name = format!("credit-test-{}", Identity::generate().node_addr());
    let network = SimNetwork::new(7);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    network.set_link("1", "2", SimLink::default());
    network.set_link("2", "3", SimLink::default());
    fips_core::register_sim_network(name.clone(), network);
    let policy = Arc::new(CreditForwarder::new(&peer(2)));
    let mut books = Vec::new();
    let mut routes = Vec::new();
    for (from, to) in [(1, 3), (3, 1)] {
        let route = Route {
            ingress_pubkey: peer(from).pubkey().serialize(),
            next_hop: *peer(to).node_addr(),
            destination: *peer(to).node_addr(),
        };
        let (book, allowance) = window(from, 2, &route, 100_000);
        books.push(book);
        policy.install(route.clone(), allowance).unwrap();
        routes.push(route);
    }
    let mut endpoints = Vec::new();
    for n in 1..=3 {
        let mut config = Config::new();
        config.node.identity.nsec = Some(format!("{n:02x}").repeat(32));
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(name.clone()),
            addr: Some(n.to_string()),
            mtu: Some(1280),
            auto_connect: Some(true),
            accept_connections: Some(true),
        });
        let builder = FipsEndpoint::builder().config(config).without_system_tun();
        endpoints.push(
            if n == 2 {
                builder.forwarding_policy(policy.clone())
            } else {
                builder
            }
            .bind()
            .await
            .unwrap(),
        );
    }
    let receiver = endpoints[2].register_service_receiver(41001).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let _ = endpoints[0]
                .send_datagram(peer(3), 41000, 41001, b"mintless service".to_vec())
                .await;
            if tokio::time::timeout(
                Duration::from_millis(200),
                receiver.recv_batch_into(&mut received, 8),
            )
            .await
            .is_ok()
            {
                break;
            }
        }
    })
    .await
    .expect("native routed service delivery");
    assert!(
        received
            .iter()
            .any(|d| d.data.as_slice() == b"mintless service")
    );
    for route in &routes {
        policy.remove(route).unwrap();
    }
    // Drain any data already admitted before removal, then use a unique marker.
    let _ = endpoints[0]
        .send_datagram(peer(3), 41000, 41001, b"revoked".to_vec())
        .await;
    let end = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Ok(Some(_)) =
        tokio::time::timeout_at(end, receiver.recv_batch_into(&mut received, 8)).await
    {
        assert!(received.iter().all(|d| d.data.as_slice() != b"revoked"));
    }
    drop(endpoints);
    fips_core::unregister_sim_network(&name);
}
