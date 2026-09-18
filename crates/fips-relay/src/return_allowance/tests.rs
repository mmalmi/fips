use super::*;
use crate::{
    buyer::{BuyerAuthorizer, PaidForwarder},
    durable::DurableRelay,
    ledger::{BillingBasis, BytePrice, ChannelTerms, Contract, Limits},
};
use fips_core::node::{ForwardingOutcome, ForwardingPolicy};
use fips_core::{Identity, PeerIdentity};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
}
fn request(
    source: u8,
    destination: u8,
    ingress: u8,
    next: u8,
    bytes: &[u8],
) -> ForwardingRequest<'_> {
    ForwardingRequest {
        ingress: peer(ingress),
        next_hop: *peer(next).node_addr(),
        source: *peer(source).node_addr(),
        destination: *peer(destination).node_addr(),
        session_payload: bytes,
    }
}

#[test]
fn only_the_earned_reverse_path_can_spend_credit_and_replies_do_not_refresh_it() {
    let mut allowance = ReturnAllowance::new();
    let now = Instant::now();
    let forward = request(1, 4, 2, 3, &[0; 900]);
    let reverse = request(4, 1, 3, 2, &[0; 200]);
    assert!(!allowance.admit_at(&reverse, now));
    allowance.earn_at(&forward, now);
    for wrong in [
        request(5, 1, 3, 2, &[0]),
        request(4, 5, 3, 2, &[0]),
        request(4, 1, 5, 2, &[0]),
        request(4, 1, 3, 5, &[0]),
        request(4, 1, 3, 2, &[0; MAX_PACKET + 1]),
    ] {
        assert!(!allowance.admit_at(&wrong, now));
    }
    for _ in 0..3 {
        assert!(allowance.admit_at(&reverse, now));
    }
    assert!(!allowance.admit_at(&reverse, now));
    assert_eq!(allowance.flows.len(), 1);
    assert!(
        !allowance.admit_at(&forward, now),
        "replies never buy the opposite direction"
    );
    allowance.earn_at(&forward, now);
    assert!(!allowance.admit_at(&reverse, now + LIFETIME));
    assert_eq!(allowance.stats().traffic.admitted_packets, 3);
}

#[test]
fn credit_caps_and_rate_denials_do_not_consume_other_flows() {
    let mut allowance = ReturnAllowance::new();
    let now = Instant::now();
    let forward = request(1, 4, 2, 3, &[0; 2_048]);
    for _ in 0..100 {
        allowance.earn_at(&forward, now);
    }
    let key = Path::from_request(&forward).reverse();
    assert_eq!(allowance.flows[&key].remaining, MAX_CREDIT);
    let reverse = request(4, 1, 3, 2, &[0; 2_048]);
    assert!(allowance.admit_at(&reverse, now));
    assert!(
        !allowance.admit_at(&reverse, now),
        "per-neighbor burst is bounded"
    );
    assert_eq!(allowance.flows[&key].remaining, 2_048);
    let other = request(5, 6, 2, 7, &[0; 2_048]);
    allowance.earn_at(&other, now);
    assert!(allowance.admit_at(&request(6, 5, 7, 2, &[0; 2_048]), now));
    assert_eq!(allowance.flows[&key].remaining, 2_048);
}

#[test]
fn state_is_bounded_under_claimed_address_and_neighbor_churn() {
    let mut allowance = ReturnAllowance::new();
    let now = Instant::now();
    for destination in 4..=36 {
        allowance.earn_at(&request(1, destination, 2, 3, &[0]), now);
    }
    assert_eq!(allowance.flows.len(), MAX_PER_NEIGHBOR);
    for next in 5..=200 {
        allowance.earn_at(&request(1, 4, 2, next, &[0]), now);
    }
    assert_eq!(allowance.flows.len(), MAX_FLOWS);
    allowance.earn_at(&request(1, 4, 2, 201, &[0]), now + LIFETIME);
    assert_eq!(allowance.flows.len(), 1);
}

#[test]
fn rejected_forwarding_earns_nothing_and_paid_reverse_routes_keep_their_accounting() {
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
    let forwarding =
        PaidForwarder::for_billing(seller.clone(), buyer, BillingBasis::ForwardingData)
            .with_return_allowance()
            .unwrap();
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let open = |source: u8, destination: u8, max_units: u64| {
        let id = format!("{source}-{destination}");
        seller
            .open_channel_verified(
                ChannelTerms {
                    id: id.clone(),
                    buyer: *peer(source).node_addr(),
                    mint_url: "http://test.invalid".into(),
                    expires_unix: expires,
                    capacity_sat: 1,
                    grace_msat: 1_000,
                },
                0,
            )
            .unwrap();
        seller
            .add_contract(Contract {
                id: id.clone(),
                channel_id: id,
                destination: *peer(destination).node_addr(),
                next_hop: *peer(destination).node_addr(),
                expires_unix: expires,
                price: BytePrice {
                    msat: 1,
                    per_bytes: 1,
                },
                max_units,
                billing: BillingBasis::ForwardingData,
            })
            .unwrap();
    };
    assert!(forwarding.admit(&request(1, 3, 1, 3, &[9; 32])).is_none());
    assert_eq!(forwarding.return_stats().unwrap().tracked_paths, 0);
    open(1, 3, 100);
    let token = forwarding
        .admit_classified(&request(1, 3, 1, 3, &[9; 32]))
        .unwrap();
    assert_eq!(token.class, fips_core::node::ForwardingClass::Normal);
    forwarding.complete(token.token, ForwardingOutcome::Submitted);
    let free = forwarding
        .admit_classified(&request(3, 1, 3, 1, &[8; 20]))
        .unwrap();
    assert_eq!(free.token, 0);
    assert_eq!(free.class, fips_core::node::ForwardingClass::Background);
    forwarding.complete(free.token, ForwardingOutcome::Submitted);
    assert_eq!(
        forwarding.return_stats().unwrap().traffic.admitted_packets,
        1
    );
    open(3, 1, 10);
    assert!(
        forwarding.admit(&request(3, 1, 3, 1, &[8; 20])).is_none(),
        "a paid quote's quota must not be bypassed with complimentary credit"
    );
    let paid = forwarding.admit(&request(3, 1, 3, 1, &[8; 10])).unwrap();
    assert_ne!(paid, 0);
    forwarding.complete(paid, ForwardingOutcome::Submitted);
    assert_eq!(seller.channel_usage("3-1").unwrap().submitted_msat, 10);
    assert_eq!(
        forwarding.return_stats().unwrap().traffic.admitted_packets,
        1
    );
}
