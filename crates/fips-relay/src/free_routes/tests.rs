use super::*;
use crate::{
    buyer::BuyerAuthorizer,
    durable::DurableRelay,
    ledger::{BillingBasis, BytePrice, ChannelTerms, Contract, Limits},
};
use fips_core::{Identity, PeerIdentity};

fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
}
fn offer(buyer: u8, provider: u8, next: u8) -> RouteOffer {
    RouteOffer {
        billing: BillingBasis::ForwardingData,
        id: format!("{buyer}-{provider}-{next}"),
        buyer: *peer(buyer).node_addr(),
        provider: *peer(provider).node_addr(),
        destination: peer(9),
        next_hop: *peer(next).node_addr(),
        path: vec![*peer(provider).node_addr(), *peer(next).node_addr()],
        price: BytePrice {
            msat: 0,
            per_bytes: 1024,
        },
        expires_unix: now().unwrap() + 60,
        max_units: 100,
        mint_url: "http://test.invalid".into(),
        receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
        capacity_sat: 32,
        grace_msat: 1_000,
    }
}
fn request<'a>(payload: &'a [u8]) -> ForwardingRequest<'a> {
    ForwardingRequest {
        ingress: peer(1),
        source: *peer(1).node_addr(),
        destination: *peer(9).node_addr(),
        next_hop: *peer(3).node_addr(),
        session_payload: payload,
    }
}

#[test]
fn free_transit_binds_every_hop_and_cannot_authorize_a_paid_continuation() {
    let routes = FreeRoutes::default();
    let incoming = offer(1, 2, 3);
    routes.offer(&incoming).unwrap();
    let mut packet = request(&[0; 50]);
    assert!(
        !routes.admit(&packet),
        "zero local fee is insufficient without a free onward offer"
    );
    let mut downstream = offer(2, 3, 9);
    downstream.price.msat = 1;
    routes.accept(&downstream).unwrap();
    assert!(!routes.admit(&packet));
    downstream.price.msat = 0;
    routes.accept(&downstream).unwrap();
    packet.ingress = peer(4);
    assert!(!routes.admit(&packet), "claimed source is not authority");
    packet.ingress = peer(1);
    packet.destination = *peer(8).node_addr();
    assert!(!routes.admit(&packet));
    packet.destination = *peer(9).node_addr();
    packet.next_hop = *peer(4).node_addr();
    assert!(
        !routes.admit(&packet),
        "a changed route needs a matching new offer"
    );
    packet.next_hop = *peer(3).node_addr();
    assert!(routes.admit(&packet));
    packet.source = *peer(7).node_addr();
    assert!(routes.admit(&packet));
    assert!(!routes.admit(&packet));
    routes.offer(&incoming).unwrap();
    routes.accept(&downstream).unwrap();
    assert!(
        !routes.admit(&packet),
        "repeating the same offer cannot reset its byte allowance"
    );
    assert_eq!(routes.stats().admitted_session_bytes, 100);
}

#[test]
fn reservations_are_atomic_and_expiry_never_falls_back_to_free() {
    let routes = FreeRoutes::default();
    let downstream = offer(2, 3, 9);
    routes.accept(&downstream).unwrap();
    assert!(
        routes
            .onward(
                downstream.provider,
                *peer(9).node_addr(),
                100,
                || None::<()>
            )
            .is_none()
    );
    routes.offer(&offer(1, 2, 3)).unwrap();
    assert!(
        routes.admit(&request(&[0; 100])),
        "failed paid admission must not consume free onward units"
    );
    let mut fresh = downstream.clone();
    fresh.id.push('x');
    routes.accept(&fresh).unwrap();
    assert!(
        !routes.admit(&request(&[0; 1])),
        "exhausted upstream allowance must not consume fresh onward units"
    );
    assert!(
        routes
            .onward(downstream.provider, *peer(9).node_addr(), 100, || Some(7))
            .is_some()
    );
    let final_hop = FreeRoutes::default();
    let grant = offer(1, 2, 9);
    final_hop.offer(&grant).unwrap();
    let mut packet = request(&[0; 1]);
    packet.next_hop = packet.destination;
    assert!(!final_hop.admit_at(&packet, grant.expires_unix));
    assert_eq!(final_hop.stats().admitted_packets, 0);
}

#[test]
fn free_offers_and_paid_activation_cannot_own_the_same_route() {
    let routes = FreeRoutes::default();
    let free = offer(1, 2, 9);
    let mut paid = free.clone();
    paid.price.msat = 1;
    let guard = routes.paid_guard(&paid).unwrap();
    assert!(routes.offer(&free).is_err());
    drop(guard);
    routes.offer(&free).unwrap();
    assert!(
        routes.paid_guard(&paid).is_err(),
        "a stale acceptance cannot replace a newer free permission"
    );
    routes.offer(&paid).unwrap();
    assert!(routes.paid_guard(&paid).is_ok());
}

#[test]
fn paid_accounts_must_close_before_a_free_switch_without_erasing_history() {
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
    let routes = FreeRoutes::for_accounts(seller.clone(), buyer.clone());
    let grant = offer(1, 2, 9);
    let mut terms = ChannelTerms {
        id: "in".into(),
        buyer: grant.buyer,
        mint_url: grant.mint_url.clone(),
        expires_unix: grant.expires_unix,
        capacity_sat: 10,
        grace_msat: 100,
    };
    let mut contract = Contract {
        billing: grant.billing,
        id: "route-in".into(),
        channel_id: terms.id.clone(),
        destination: *grant.destination.node_addr(),
        next_hop: grant.next_hop,
        expires_unix: terms.expires_unix,
        price: BytePrice {
            msat: 1,
            per_bytes: 1,
        },
        max_units: 100,
    };
    seller.open_channel_verified(terms.clone(), 0).unwrap();
    seller.add_contract(contract.clone()).unwrap();
    assert!(routes.offer(&grant).is_err());
    seller.seal_channel("in").unwrap();
    routes.offer(&grant).unwrap();
    assert!(seller.contract("route-in").is_some());
    terms.id = "out".into();
    terms.buyer = *peer(2).node_addr();
    contract.id = "route-out".into();
    contract.channel_id = terms.id.clone();
    buyer
        .accept_channel(*peer(3).node_addr(), terms, 0)
        .unwrap();
    buyer.accept_quote(contract).unwrap();
    let outgoing = offer(2, 3, 9);
    assert!(routes.accept(&outgoing).is_err());
    buyer.close_quote("route-out").unwrap();
    routes.accept(&outgoing).unwrap();
    assert_eq!(buyer.remaining_budget_sat(), Some(10));
    assert_eq!(buyer.evidence_msat("out"), Some(0));
}

#[test]
fn peer_churn_has_bounded_state_and_retirement_needs_expiry() {
    let mut leases = BTreeMap::new();
    let mut grant = offer(1, 2, 9);
    for p in 0..8 {
        for d in 0..16 {
            let key = (NodeAddr::from_bytes([p; 16]), NodeAddr::from_bytes([d; 16]));
            FreeRoutes::install(&mut leases, key, &grant, 0).unwrap();
        }
    }
    assert_eq!(leases.len(), 128);
    assert!(
        FreeRoutes::install(
            &mut leases,
            (*peer(1).node_addr(), *peer(9).node_addr()),
            &grant,
            0
        )
        .is_err()
    );
    let expired = grant.expires_unix;
    grant.expires_unix += 1;
    FreeRoutes::install(
        &mut leases,
        (*peer(1).node_addr(), *peer(9).node_addr()),
        &grant,
        expired,
    )
    .unwrap();
    assert_eq!(leases.len(), 1);
}
