use super::*;
use crate::{
    buyer::BuyerAuthorizer,
    durable::DurableRelay,
    ledger::{BillingBasis, BytePrice, ChannelTerms, Contract, Limits},
};
use fips_core::{Identity, PeerIdentity};

#[path = "bandwidth_tests.rs"]
mod bandwidth;

fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
}
fn offer(buyer: u8, provider: u8, next: u8) -> RouteOffer {
    RouteOffer {
        trial: false,
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
fn remaining_units_reads_exact_outgoing_usage_without_changing_it() {
    let routes = FreeRoutes::default();
    let grant = offer(2, 3, 9);
    let key = (grant.provider, *grant.destination.node_addr());
    assert_eq!(routes.remaining_units(&grant), None);
    routes.offer(&grant).unwrap();
    assert_eq!(routes.remaining_units(&grant), None);
    routes.accept(&grant).unwrap();
    assert_eq!(routes.remaining_units(&grant), Some(100));
    assert_eq!(routes.prepare_onward(key.0, key.1, 40), Some(true));
    for _ in 0..3 {
        assert_eq!(routes.remaining_units(&grant), Some(60));
    }
    assert_eq!(routes.stats().outgoing_leases, 1);
    assert!(routes.onward(key.0, key.1, 60, || Some(())).is_some());
    assert_eq!(routes.remaining_units(&grant), Some(0));
    assert_eq!(routes.prepare_onward(key.0, key.1, 1), Some(false));
    assert_eq!(routes.remaining_units(&grant), Some(0));
}

#[test]
fn remaining_units_rejects_changed_and_superseded_offers() {
    let routes = FreeRoutes::default();
    let grant = offer(2, 3, 9);
    let key = (grant.provider, *grant.destination.node_addr());
    routes.accept(&grant).unwrap();
    assert_eq!(routes.prepare_onward(key.0, key.1, 40), Some(true));
    for changed in [
        RouteOffer {
            max_units: 200,
            ..grant.clone()
        },
        RouteOffer {
            expires_unix: grant.expires_unix + 1,
            ..grant.clone()
        },
        RouteOffer {
            next_hop: *peer(4).node_addr(),
            ..grant.clone()
        },
        RouteOffer {
            buyer: *peer(5).node_addr(),
            ..grant.clone()
        },
    ] {
        assert_eq!(routes.remaining_units(&changed), None);
    }
    assert_eq!(routes.remaining_units(&grant), Some(60));
    let mut replacement = grant.clone();
    replacement.id.push('b');
    routes.accept(&replacement).unwrap();
    assert_eq!(routes.prepare_onward(key.0, key.1, 25), Some(true));
    assert_eq!(routes.remaining_units(&grant), None);
    assert_eq!(routes.remaining_units(&replacement), Some(75));
    routes.accept(&replacement).unwrap();
    assert!(routes.accept(&grant).is_err());
    assert_eq!(routes.remaining_units(&replacement), Some(75));
    assert_eq!(routes.stats().outgoing_leases, 2);
}

#[test]
fn remaining_units_keeps_expiry_separate_from_consumption() {
    let routes = FreeRoutes::default();
    let mut grant = offer(2, 3, 9);
    grant.expires_unix = 1;
    let key = (grant.provider, *grant.destination.node_addr());
    {
        let mut state = routes.state.lock().unwrap();
        state.outgoing.install(key, &grant, 0).unwrap();
        assert!(
            state
                .outgoing
                .get_mut(&key)
                .unwrap()
                .reserve(40, 0, || Some(()))
                .is_some()
        );
    }
    assert_eq!(routes.remaining_units(&grant), Some(60));
    assert_eq!(routes.prepare_onward(key.0, key.1, 1), Some(false));
    assert_eq!(routes.remaining_units(&grant), Some(60));
    assert_eq!(routes.stats().outgoing_leases, 1);
}

#[test]
fn remaining_units_returns_none_for_poisoned_state() {
    let routes = Arc::new(FreeRoutes::default());
    let grant = offer(2, 3, 9);
    routes.accept(&grant).unwrap();
    let poisoned = routes.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = poisoned.state.lock().unwrap();
            panic!("poison free route state");
        })
        .join()
        .is_err()
    );
    assert_eq!(routes.remaining_units(&grant), None);
}

#[test]
fn source_free_admission_reuses_the_same_lease_and_distinguishes_denial() {
    let routes = FreeRoutes::default();
    let offered = offer(2, 3, 9);
    let next = offered.provider;
    let destination = *offered.destination.node_addr();
    assert_eq!(routes.prepare_onward(next, destination, 40), None);
    routes.accept(&offered).unwrap();
    assert_eq!(routes.prepare_onward(next, destination, 40), Some(true));
    assert!(routes.onward(next, destination, 60, || Some(())).is_some());
    assert_eq!(routes.prepare_onward(next, destination, 1), Some(false));
    routes.accept(&offered).unwrap();
    assert_eq!(
        routes.prepare_onward(next, destination, 1),
        Some(false),
        "same offer cannot reset the cap"
    );
    let mut state = routes.state.lock().unwrap();
    state
        .outgoing
        .get_mut(&(next, destination))
        .unwrap()
        .offer
        .expires_unix = 0;
    drop(state);
    assert_eq!(routes.prepare_onward(next, destination, 0), Some(false));
}

#[test]
fn superseded_free_offers_cannot_reactivate_or_reset_consumed_quota() {
    let routes = FreeRoutes::default();
    let original = offer(1, 2, 9);
    let mut replacement = original.clone();
    replacement.id.push('b');
    let mut packet = request(&[0; 100]);
    packet.next_hop = packet.destination;
    routes.offer(&original).unwrap();
    assert!(routes.admit(&packet));
    assert!(routes.can_reuse_offer(&original));
    routes.offer(&replacement).unwrap();
    assert!(routes.admit(&packet));
    assert!(!routes.can_reuse_offer(&original));
    assert!(routes.can_reuse_offer(&replacement));
    assert!(
        routes.offer(&original).is_err(),
        "superseded grant must stay closed"
    );
    assert!(
        !routes.admit(&packet),
        "replay must not replenish the replacement"
    );
    assert_eq!(routes.stats().admitted_session_bytes, 200);

    let original = offer(2, 3, 9);
    let mut replacement = original.clone();
    replacement.id.push('b');
    let key = (original.provider, *original.destination.node_addr());
    routes.accept(&original).unwrap();
    assert_eq!(routes.prepare_onward(key.0, key.1, 100), Some(true));
    routes.accept(&replacement).unwrap();
    assert_eq!(routes.prepare_onward(key.0, key.1, 100), Some(true));
    assert!(
        routes.accept(&original).is_err(),
        "cached source offer cannot roll back"
    );
    assert_eq!(routes.prepare_onward(key.0, key.1, 1), Some(false));
}

#[test]
fn paid_switch_preserves_retired_free_offer_identity() {
    let routes = FreeRoutes::default();
    let original = offer(1, 2, 9);
    routes.offer(&original).unwrap();
    let mut paid = original.clone();
    paid.id.push('p');
    paid.price.msat = 1;
    routes.offer(&paid).unwrap();
    assert!(!routes.can_reuse_offer(&original));
    assert!(routes.can_reuse_offer(&paid));
    assert!(
        routes.offer(&original).is_err(),
        "paid switch cannot erase replay evidence"
    );

    let original = offer(2, 3, 9);
    routes.accept(&original).unwrap();
    let mut paid = original.clone();
    paid.id.push('p');
    paid.price.msat = 1;
    routes.accept(&paid).unwrap();
    assert!(routes.accept(&original).is_err());
}

#[test]
fn repeated_identity_cannot_change_terms_or_replenish_quota() {
    let routes = FreeRoutes::default();
    let original = offer(1, 2, 9);
    routes.offer(&original).unwrap();
    let mut packet = request(&[0; 60]);
    packet.next_hop = packet.destination;
    assert!(routes.admit(&packet));
    for changed in [
        RouteOffer {
            max_units: 200,
            ..original.clone()
        },
        RouteOffer {
            expires_unix: original.expires_unix + 1,
            ..original.clone()
        },
        RouteOffer {
            next_hop: *peer(4).node_addr(),
            ..original.clone()
        },
        RouteOffer {
            price: BytePrice {
                msat: 1,
                per_bytes: 1024,
            },
            ..original.clone()
        },
    ] {
        assert!(routes.offer(&changed).is_err());
        if changed.price.msat == 0 {
            assert!(!routes.can_reuse_offer(&changed));
        }
    }
    routes.offer(&original).unwrap();
    assert!(!routes.admit(&packet));
    packet.session_payload = &[0; 40];
    assert!(routes.admit(&packet));
    assert_eq!(routes.stats().incoming_leases, 1);
}

#[test]
fn new_offer_ids_count_toward_peer_and_global_capacity() {
    let routes = FreeRoutes::default();
    let mut grant = offer(1, 2, 9);
    for identity in 0..8 {
        grant.buyer = *peer(identity + 1).node_addr();
        for generation in 0..MAX_PER_PEER {
            grant.id = format!("{identity}/{generation}");
            routes.offer(&grant).unwrap();
        }
        let last = grant.clone();
        grant.id = format!("{identity}/overflow");
        assert!(
            routes.offer(&grant).is_err(),
            "replacement history counts per peer"
        );
        routes.offer(&last).unwrap();
    }
    assert_eq!(routes.stats().incoming_leases, MAX_LEASES);
    grant.buyer = *peer(30).node_addr();
    grant.id = "another-peer".into();
    assert!(
        routes.offer(&grant).is_err(),
        "retained grants count globally"
    );

    for identity in 0..8 {
        grant.provider = *peer(identity + 1).node_addr();
        for generation in 0..MAX_PER_PEER {
            grant.id = format!("{identity}/{generation}");
            routes.accept(&grant).unwrap();
        }
        grant.id = format!("{identity}/overflow");
        assert!(routes.accept(&grant).is_err());
    }
    assert_eq!(routes.stats().outgoing_leases, MAX_LEASES);
    grant.provider = *peer(30).node_addr();
    assert!(routes.accept(&grant).is_err());
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
    paid.id.push('p');
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
    let mut leases = LeaseBook::default();
    let mut grant = offer(1, 2, 9);
    for p in 0..8 {
        for d in 0..16 {
            let key = (NodeAddr::from_bytes([p; 16]), NodeAddr::from_bytes([d; 16]));
            leases.install(key, &grant, 0).unwrap();
        }
    }
    assert_eq!(leases.len(), 128);
    assert!(
        leases
            .install((*peer(1).node_addr(), *peer(9).node_addr()), &grant, 0)
            .is_err()
    );
    let expired = grant.expires_unix;
    grant.expires_unix += 1;
    leases
        .install(
            (*peer(1).node_addr(), *peer(9).node_addr()),
            &grant,
            expired,
        )
        .unwrap();
    assert_eq!(leases.len(), 1);
}

#[test]
fn expired_replacement_history_releases_capacity_without_closing_live_grants() {
    let mut leases = LeaseBook::default();
    let mut grant = offer(1, 2, 9);
    let key = (grant.buyer, *grant.destination.node_addr());
    for generation in 0..MAX_PER_PEER {
        grant.id = generation.to_string();
        grant.expires_unix = if generation + 1 == MAX_PER_PEER {
            20
        } else {
            10
        };
        leases.install(key, &grant, 0).unwrap();
    }
    assert_eq!(leases.len(), MAX_PER_PEER);
    assert!(
        leases
            .get_mut(&key)
            .unwrap()
            .reserve(60, 9, || Some(()))
            .is_some()
    );
    let old = grant.clone();
    grant.id = "replacement-after-expiry".into();
    grant.expires_unix = 30;
    assert!(leases.install(key, &grant, 9).is_err());
    assert_eq!(leases.get(&key).unwrap().offer, old);
    assert_eq!(leases.get(&key).unwrap().used, 60);

    leases.install(key, &grant, 10).unwrap();
    assert_eq!(
        leases.len(),
        2,
        "unexpired superseded grant still occupies a slot"
    );
    assert!(leases.install(key, &old, 10).is_err());
    assert_eq!(leases.get(&key).unwrap().offer, grant);
    let mut expired = old.clone();
    expired.id = "0".into();
    expired.expires_unix = 10;
    assert!(leases.install(key, &expired, 10).is_err());

    let mut fresh = grant.clone();
    fresh.id = "fresh".into();
    fresh.expires_unix = 40;
    leases.install(key, &fresh, 30).unwrap();
    assert_eq!(
        leases.len(),
        1,
        "expired active and retired records are both reclaimed"
    );
}
