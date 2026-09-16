use super::*;

fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
}

#[test]
fn downstream_quotes_cannot_change_identity_price_mint_or_loop_bounds() {
    let (buyer, provider, destination) = (peer(1), peer(2), peer(3));
    let policy = QuotePolicy {
        destination_fees: Default::default(),
        billing: Default::default(),
        mint_url: "http://test.invalid".into(),
        receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
        fee_msat_per_kib: 1_024,
        max_rate_msat_per_kib: 8_192,
        lifetime_secs: 120,
        max_units: 20_000,
        capacity_sat: 32,
        grace_msat: 16_384,
    };
    let request = QuoteRequest {
        destination,
        ancestors: vec![*buyer.node_addr()],
        deadline_unix: 110,
        reuse_unchanged: false,
    };
    let offer = RouteOffer {
        billing: Default::default(),
        id: "quote".into(),
        buyer: *buyer.node_addr(),
        provider: *provider.node_addr(),
        destination,
        next_hop: *destination.node_addr(),
        path: vec![*provider.node_addr(), *destination.node_addr()],
        price: BytePrice {
            msat: 1_024,
            per_bytes: PRICE_BYTES,
        },
        expires_unix: 200,
        max_units: 20_000,
        mint_url: policy.mint_url.clone(),
        receiver_pubkey_hex: policy.receiver_pubkey_hex.clone(),
        capacity_sat: 32,
        grace_msat: 16_384,
    };
    let check = |offer: &RouteOffer| {
        validate_offer(&policy, *buyer.node_addr(), offer, provider, &request, 100)
    };
    check(&offer).unwrap();
    let mutations: Vec<fn(&mut RouteOffer)> = vec![
        |o| o.billing = BillingBasis::ForwardingAttempt,
        |o| o.provider = *peer(4).node_addr(),
        |o| o.buyer = *peer(4).node_addr(),
        |o| o.destination = peer(4),
        |o| o.next_hop = *peer(4).node_addr(),
        |o| o.path.clear(),
        |o| o.path.insert(1, o.provider),
        |o| {
            o.path.insert(1, o.buyer);
            o.next_hop = o.buyer;
        },
        |o| o.price.msat = 8_193,
        |o| o.price.msat = 0,
        |o| o.price.per_bytes = 1_025,
        |o| o.expires_unix = 100,
        |o| o.expires_unix = 3_701,
        |o| o.mint_url = "http://another.invalid".into(),
        |o| o.receiver_pubkey_hex = "invalid".into(),
        |o| o.capacity_sat = u64::MAX,
        |o| o.grace_msat = 32_001,
        |o| o.max_units = 0,
        |o| o.id = "x".repeat(129),
        |o| {
            o.path = (2..=11).map(|n| *peer(n).node_addr()).collect();
            o.path.push(*o.destination.node_addr());
            o.next_hop = o.path[1];
        },
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut invalid = offer.clone();
        mutate(&mut invalid);
        assert!(check(&invalid).is_err(), "invalid downstream quote {index}");
    }
    // Npub serialization is x-only. The authenticated identity is unchanged
    // when a locally known full key had different parity metadata.
    let mut canonical = offer;
    canonical.destination = PeerIdentity::from_npub(&destination.npub()).unwrap();
    check(&canonical).unwrap();
}
