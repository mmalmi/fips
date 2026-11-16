use super::*;

#[test]
fn public_seed_honors_live_credit_and_resumes_native_forwarding_after_expiry() {
    use crate::buyer::PaidForwarder;
    use fips_core::node::{
        ForwardingClass, ForwardingDecision, ForwardingOutcome, ForwardingPolicy,
    };

    let root = tempfile::tempdir().unwrap();
    let seller = Arc::new(
        DurableRelay::create(&root.path().join("seller"), Limits::default(), 1_000).unwrap(),
    );
    let buyer = Arc::new(
        BuyerAuthorizer::create(
            &root.path().join("buyer"),
            *peer(2).node_addr(),
            0,
            Limits::default(),
        )
        .unwrap(),
    );
    let mut free = FreeRoutes::for_accounts(seller.clone(), buyer.clone());
    free.set_public_free_transit(true);
    let free = Arc::new(free);
    let incoming = offer(1, 2, 3);
    let outgoing = offer(2, 3, 9);
    free.offer(&incoming).unwrap();
    free.accept(&outgoing).unwrap();
    let packet = request(&[7; 100]);
    assert!(free.admit(&packet));
    assert!(!free.admit(&packet));
    assert!(free.admit_at(&packet, incoming.expires_unix.max(outgoing.expires_unix)));
    assert_eq!(free.remaining_units(&outgoing), Some(0));

    let other = peer(4);
    let mut paid = offer(4, 2, 9);
    paid.bid_msat_per_kib = 8;
    paid.price.msat = 8;
    let channel = ChannelTerms {
        refund_after_unix: None,
        id: "funded".into(),
        buyer: paid.buyer,
        mint_url: paid.mint_url.clone(),
        expires_unix: paid.expires_unix,
        capacity_sat: paid.capacity_sat,
        grace_msat: paid.grace_msat,
    };
    let contract = crate::route_quotes::contract_from_offer(&paid, &channel).unwrap();
    seller.open_channel_verified(channel, 1_000).unwrap();
    seller.add_contract(contract).unwrap();
    let relay = PaidForwarder::with_free_routes(seller, buyer, paid.billing, free);
    let mut packet = request(&[7; 100]);
    packet.ingress = other;
    packet.next_hop = packet.destination;
    let mut bid = 0;
    let admission = relay
        .decide_with_bid(&packet, &mut bid)
        .admission()
        .unwrap();
    assert_eq!((admission.class, bid), (ForwardingClass::Normal, 8));
    relay.complete(admission.token, ForwardingOutcome::Submitted);
    assert_eq!(
        relay.decide_with_bid(&packet, &mut bid),
        ForwardingDecision::Reject
    );
    assert_eq!(bid, 0);
}
