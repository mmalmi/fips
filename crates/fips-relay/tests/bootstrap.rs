use fips_core::{
    Identity, NodeAddr, PeerIdentity,
    node::{
        ForwardingOutcome, ForwardingPolicy, ForwardingRequest, OriginatedSessionObserver,
        OriginatedSessionRequest,
    },
    noise::XK_HANDSHAKE_MSG3_SIZE,
    protocol::SessionMsg3,
};
use fips_relay::{
    buyer::{BuyerAuthorizer, PaidForwarder},
    durable::DurableRelay,
    ledger::{BillingBasis, BytePrice, ChannelTerms, Contract, Limits},
};
use std::sync::Arc;

fn address(n: u8) -> NodeAddr {
    if n == 1 {
        return *peer(1).node_addr();
    }
    NodeAddr::from_bytes([n; 16])
}
fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
}
fn handshake() -> Vec<u8> {
    // Shape validation deliberately cannot prove end-to-end Noise authenticity.
    SessionMsg3::new(vec![0; XK_HANDSHAKE_MSG3_SIZE]).encode()
}

#[test]
fn only_the_explicit_new_tariff_excludes_handshakes_from_both_ledgers() {
    for billing in [
        BillingBasis::UniqueSessionEnvelope,
        BillingBasis::ForwardingAttempt,
        BillingBasis::ForwardingData,
    ] {
        let root = tempfile::tempdir().unwrap();
        let seller_path = root.path().join("seller");
        let buyer_path = root.path().join("buyer");
        let seller = DurableRelay::create(&seller_path, Limits::default(), 1_000).unwrap();
        let buyer =
            BuyerAuthorizer::create(&buyer_path, address(1), 10, Limits::default()).unwrap();
        let terms = ChannelTerms {
            id: "channel".into(),
            buyer: *peer(1).node_addr(),
            mint_url: "http://test.invalid".into(),
            expires_unix: u64::MAX,
            capacity_sat: 10,
            grace_msat: 2_000,
        };
        let quote = Contract {
            id: "route".into(),
            channel_id: terms.id.clone(),
            destination: address(9),
            next_hop: address(9),
            expires_unix: u64::MAX,
            max_units: 10_000,
            price: BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            billing,
        };
        seller.open_channel_verified(terms.clone(), 0).unwrap();
        seller.add_contract(quote.clone()).unwrap();
        buyer.accept_channel(address(2), terms, 0).unwrap();
        buyer.accept_quote(quote).unwrap();
        let packet = handshake();
        let mut malformed = packet.clone();
        malformed.push(0);
        let mut total = 0;
        for payload in [&packet[..], &malformed[..], b"opaque encrypted application"] {
            let seller_token = seller.admit(&ForwardingRequest {
                ingress: peer(1),
                source: address(1),
                destination: address(9),
                next_hop: address(9),
                session_payload: payload,
            });
            let buyer_token = buyer.observe(&OriginatedSessionRequest {
                source: address(1),
                destination: address(9),
                next_hop: address(2),
                session_payload: payload,
            });
            if billing.has_free_handshakes() && payload == packet {
                assert!(seller_token.is_none());
                assert!(buyer_token.is_none());
            } else {
                let seller_token = seller_token.unwrap();
                let buyer_token = buyer_token.unwrap();
                seller.complete(seller_token, ForwardingOutcome::Submitted);
                seller.complete(seller_token, ForwardingOutcome::Submitted);
                buyer.complete(buyer_token, ForwardingOutcome::Submitted);
                buyer.complete(buyer_token, ForwardingOutcome::Submitted);
                total += payload.len() as u64;
            }
        }
        assert_eq!(
            seller.channel_usage("channel").unwrap().submitted_msat,
            total
        );
        assert_eq!(buyer.evidence_msat("channel"), Some(total));
        seller.checkpoint().unwrap();
        buyer.checkpoint().unwrap();
        drop(seller);
        drop(buyer);
        let seller = DurableRelay::load(&seller_path).unwrap();
        let buyer = BuyerAuthorizer::load(&buyer_path).unwrap();
        assert_eq!(
            seller.channel_usage("channel").unwrap().submitted_msat,
            total
        );
        assert_eq!(buyer.evidence_msat("channel"), Some(total));
        assert_eq!(buyer.remaining_budget_sat(), Some(10));
    }
}

#[test]
fn unpaid_handshakes_cannot_create_spending_or_data_authority() {
    let root = tempfile::tempdir().unwrap();
    let seller = Arc::new(
        DurableRelay::create(&root.path().join("seller"), Limits::default(), 1_000).unwrap(),
    );
    let buyer = Arc::new(
        BuyerAuthorizer::create(&root.path().join("buyer"), address(1), 1, Limits::default())
            .unwrap(),
    );
    let old = PaidForwarder::new(seller.clone(), buyer.clone());
    let forwarding =
        PaidForwarder::for_billing(seller.clone(), buyer.clone(), BillingBasis::ForwardingData);
    let packet = handshake();
    let mut request = ForwardingRequest {
        ingress: peer(2),
        source: address(7),
        destination: address(9),
        next_hop: address(3),
        session_payload: &packet,
    };
    assert!(old.admit(&request).is_none());
    assert!(old.bootstrap_stats().is_none());
    let token = forwarding.admit(&request).unwrap();
    assert_eq!(token, 0);
    forwarding.complete(token, ForwardingOutcome::Submitted);
    forwarding.complete(token, ForwardingOutcome::Unconfirmed);
    // Changing unauthenticated end-to-end addresses must not create new buckets.
    for n in 0..=255 {
        request.source = address(n);
        request.destination = address(n.wrapping_add(1));
        if let Some(token) = forwarding.admit(&request) {
            forwarding.complete(token, ForwardingOutcome::Unconfirmed);
        }
    }
    let stats = forwarding.bootstrap_stats().unwrap();
    assert_eq!(stats.tracked_peers, 1);
    assert!(stats.rate_denied > 0);
    request.ingress = peer(3);
    assert_eq!(forwarding.admit(&request), Some(0));
    let mut malformed = packet.clone();
    malformed.push(0);
    for payload in [&malformed[..], b"application bytes"] {
        request.session_payload = payload;
        assert!(forwarding.admit(&request).is_none());
    }
    assert!(seller.checkpoint().unwrap().is_empty());
    assert_eq!(buyer.remaining_budget_sat(), Some(1));
    buyer.checkpoint().unwrap();
}
