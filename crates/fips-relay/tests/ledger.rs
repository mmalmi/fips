use fips_core::{
    Identity, NodeAddr, PeerIdentity,
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use fips_relay::ledger::{
    BytePrice, ChannelTerms, Contract, LedgerError, Limits, RelayLedger, Snapshot,
};

fn buyer(seed: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(
        Identity::from_secret_bytes(&[seed; 32])
            .unwrap()
            .pubkey_full(),
    )
}
fn channel() -> ChannelTerms {
    ChannelTerms {
        id: "channel-a".into(),
        buyer: *buyer(1).node_addr(),
        mint_url: "http://127.0.0.1:1234".into(),
        expires_unix: 300,
        capacity_sat: 1,
        grace_msat: 0,
    }
}
fn contract() -> Contract {
    Contract {
        billing: Default::default(),
        id: "route-a".into(),
        channel_id: "channel-a".into(),
        destination: NodeAddr::from_bytes([9; 16]),
        next_hop: NodeAddr::from_bytes([2; 16]),
        expires_unix: 200,
        price: BytePrice {
            msat: 1,
            per_bytes: 1,
        },
        max_units: 1_000,
    }
}
fn request(payload: &[u8]) -> ForwardingRequest<'_> {
    let c = contract();
    ForwardingRequest {
        ingress: buyer(1),
        source: NodeAddr::from_bytes([7; 16]),
        destination: c.destination,
        next_hop: c.next_hop,
        session_payload: payload,
    }
}
fn fund(ledger: &RelayLedger, paid_msat: u64) {
    ledger.open_channel_verified(channel(), paid_msat).unwrap();
    ledger.add_contract(contract()).unwrap();
}

#[test]
fn reservations_bound_concurrent_sends_and_renewal_without_a_delivery_receipt() {
    let ledger = RelayLedger::new(Limits::default());
    fund(&ledger, 8);
    let a = ledger.admit_at(&request(b"aaaa"), 100).unwrap();
    let b = ledger.admit_at(&request(b"bbbb"), 100).unwrap();
    assert!(ledger.admit_at(&request(b"c"), 100).is_none());
    assert_eq!(ledger.amount_due_msat("route-a"), Some(0));
    ledger.complete(b, ForwardingOutcome::Submitted);
    ledger.complete(a, ForwardingOutcome::Submitted);
    assert_eq!(ledger.channel_usage("channel-a").unwrap().submitted_msat, 8);
    ledger.apply_verified_balance("channel-a", 9).unwrap();
    assert!(ledger.admit_at(&request(b"c"), 100).is_some());
    assert_eq!(ledger.usage("route-a").unwrap().reserved_units, 9);
}

#[test]
fn wrong_neighbor_destination_or_next_provider_cannot_spend_an_agreement() {
    let ledger = RelayLedger::new(Limits::default());
    fund(&ledger, 100);
    let mut r = request(b"packet");
    r.ingress = buyer(3);
    assert!(ledger.admit_at(&r, 100).is_none());
    r = request(b"packet");
    r.destination = NodeAddr::from_bytes([8; 16]);
    assert!(ledger.admit_at(&r, 100).is_none());
    r = request(b"packet");
    r.next_hop = NodeAddr::from_bytes([3; 16]);
    assert!(ledger.admit_at(&r, 100).is_none());
    assert_eq!(ledger.usage("route-a").unwrap().reserved_units, 0);
    r = request(b"packet");
    r.source = *buyer(4).node_addr();
    assert!(
        ledger.admit_at(&r, 100).is_some(),
        "claimed source does not name a payer"
    );
}

#[test]
fn duplicates_expiry_and_uncertain_sends_never_replenish_credit() {
    let ledger = RelayLedger::new(Limits::default());
    fund(&ledger, 8);
    let a = ledger.admit_at(&request(b"aaaa"), 100).unwrap();
    assert!(ledger.admit_at(&request(b"aaaa"), 100).is_none());
    ledger.complete(a, ForwardingOutcome::Unconfirmed);
    ledger.complete(a, ForwardingOutcome::Submitted);
    assert!(ledger.admit_at(&request(b"aaaa"), 100).is_none());
    assert!(ledger.admit_at(&request(b"bbbbb"), 100).is_none());
    assert_eq!(ledger.usage("route-a").unwrap().unconfirmed_units, 4);
    assert_eq!(ledger.channel_usage("channel-a").unwrap().submitted_msat, 0);
    assert!(ledger.admit_at(&request(b"b"), 200).is_none());
}

#[test]
fn persistent_channel_shares_credit_and_grace_across_destinations_and_quote_changes() {
    let ledger = RelayLedger::new(Limits::default());
    let mut terms = channel();
    terms.grace_msat = 4;
    ledger.open_channel_verified(terms.clone(), 0).unwrap();
    ledger.add_contract(contract()).unwrap();
    let mut second = contract();
    second.id = "route-b".into();
    second.destination = NodeAddr::from_bytes([8; 16]);
    second.price.msat = 2;
    ledger.add_contract(second.clone()).unwrap();
    let a = ledger.admit_at(&request(b"aa"), 100).unwrap();
    ledger.complete(a, ForwardingOutcome::Submitted);
    let mut r = request(b"b");
    r.destination = second.destination;
    let b = ledger.admit_at(&r, 100).unwrap();
    ledger.complete(b, ForwardingOutcome::Submitted);
    assert_eq!(ledger.channel_usage("channel-a").unwrap().submitted_msat, 4);
    assert!(ledger.admit_at(&request(b"new"), 100).is_none());
    ledger.open_channel_verified(terms, 0).unwrap();
    ledger.close_contract("route-a").unwrap();
    let mut replacement = contract();
    replacement.id = "route-a-v2".into();
    replacement.next_hop = NodeAddr::from_bytes([3; 16]);
    ledger.add_contract(replacement.clone()).unwrap();
    let mut changed = request(b"new");
    changed.next_hop = replacement.next_hop;
    assert!(
        ledger.admit_at(&changed, 100).is_none(),
        "new quote cannot reset channel grace"
    );
    ledger.apply_verified_balance("channel-a", 4).unwrap();
    changed.session_payload = b"aa";
    assert!(
        ledger.admit_at(&changed, 100).is_none(),
        "a route change cannot rebill the same ciphertext"
    );
    changed.session_payload = b"new";
    assert!(ledger.admit_at(&changed, 100).is_some());
    assert_eq!(ledger.channel_usage("channel-a").unwrap().reserved_msat, 7);
}

#[test]
fn repeated_opens_and_channel_rollover_cannot_reset_an_unpaid_balance() {
    let ledger = RelayLedger::new(Limits::default());
    let mut c = channel();
    c.grace_msat = 4;
    ledger.open_channel_verified(c.clone(), 0).unwrap();
    ledger.add_contract(contract()).unwrap();
    let token = ledger.admit_at(&request(b"aaaa"), 100).unwrap();
    ledger.complete(token, ForwardingOutcome::Submitted);
    ledger.open_channel_verified(c.clone(), 0).unwrap();
    ledger.add_contract(contract()).unwrap();
    assert!(ledger.admit_at(&request(b"b"), 100).is_none());
    let mut stolen = c.clone();
    stolen.buyer = *buyer(3).node_addr();
    assert_eq!(
        ledger.open_channel_verified(stolen, 0),
        Err(LedgerError::AlreadyBound)
    );
    ledger.close_channel("channel-a").unwrap();
    let mut rollover = c.clone();
    rollover.id = "channel-b".into();
    assert_eq!(
        ledger.open_channel_verified(rollover.clone(), 0),
        Err(LedgerError::UnsettledChannel)
    );
    ledger.apply_verified_balance("channel-a", 4).unwrap();
    assert_eq!(
        ledger.apply_verified_balance("channel-a", 3),
        Err(LedgerError::InvalidPayment)
    );
    assert_eq!(
        ledger.apply_verified_balance("channel-a", 1_001),
        Err(LedgerError::InvalidPayment)
    );
    ledger.open_channel_verified(rollover, 0).unwrap();
    let mut quote = contract();
    quote.id = "route-new-channel".into();
    quote.channel_id = "channel-b".into();
    ledger.add_contract(quote).unwrap();
    assert!(
        ledger.admit_at(&request(b"aaaa"), 100).is_none(),
        "retained replay evidence survives channel rollover"
    );
    assert!(ledger.admit_at(&request(b"new"), 100).is_some());
}

#[test]
fn restart_conserves_pending_usage_and_cannot_reactivate_old_credit() {
    let ledger = RelayLedger::new(Limits::default());
    fund(&ledger, 100);
    let a = ledger.admit_at(&request(b"aaaa"), 100).unwrap();
    ledger.complete(a, ForwardingOutcome::Submitted);
    let b = ledger.admit_at(&request(b"bbbb"), 100).unwrap();
    ledger.complete(b, ForwardingOutcome::Unconfirmed);
    ledger.admit_at(&request(b"cccc"), 100).unwrap();
    let encoded = serde_json::to_vec(&ledger.snapshot()).unwrap();
    let restored = RelayLedger::restore(serde_json::from_slice(&encoded).unwrap()).unwrap();
    let usage = restored.usage("route-a").unwrap();
    assert_eq!(
        (
            usage.reserved_units,
            usage.submitted_units,
            usage.unconfirmed_units
        ),
        (12, 4, 8)
    );
    restored.open_channel_verified(channel(), 100).unwrap();
    restored.add_contract(contract()).unwrap();
    restored.apply_verified_balance("channel-a", 101).unwrap();
    assert!(restored.admit_at(&request(b"new"), 100).is_none());
    assert_eq!(
        restored.channel_usage("channel-a").unwrap().submitted_msat,
        4
    );
    for path in ["reserved_units", "submitted_units", "unconfirmed_units"] {
        let mut malformed = serde_json::to_value(ledger.snapshot()).unwrap();
        malformed["accounts"][0]["usage"][path] = 0.into();
        let s: Snapshot = serde_json::from_value(malformed).unwrap();
        assert!(matches!(
            RelayLedger::restore(s),
            Err(LedgerError::InvalidSnapshot)
        ));
    }
    let mut malformed = serde_json::to_value(ledger.snapshot()).unwrap();
    malformed["channels"][0]["usage"]["reserved_msat"] = 0.into();
    assert!(matches!(
        RelayLedger::restore(serde_json::from_value(malformed).unwrap()),
        Err(LedgerError::InvalidSnapshot)
    ));
}

#[test]
fn memory_and_arithmetic_limits_fail_closed() {
    let ledger = RelayLedger::new(Limits {
        max_channels: 1,
        max_contracts: 1,
        max_packets_per_contract: 2,
        max_pending: 1,
    });
    fund(&ledger, 100);
    let a = ledger.admit_at(&request(b"a"), 100).unwrap();
    assert!(ledger.admit_at(&request(b"b"), 100).is_none());
    ledger.complete(a, ForwardingOutcome::Submitted);
    let b = ledger.admit_at(&request(b"b"), 100).unwrap();
    ledger.complete(b, ForwardingOutcome::Submitted);
    assert!(ledger.admit_at(&request(b"c"), 100).is_none());
    let ledger = RelayLedger::new(Limits::default());
    ledger.open_channel_verified(channel(), 0).unwrap();
    let mut c = contract();
    c.price.msat = u64::MAX;
    assert_eq!(ledger.add_contract(c), Err(LedgerError::InvalidContract));
    assert_eq!(
        BytePrice {
            msat: u64::MAX,
            per_bytes: u64::MAX
        }
        .amount_due_msat(u64::MAX),
        Some(u64::MAX)
    );
}

#[test]
fn channel_capacity_caps_grace_and_prices_accumulate_without_per_packet_rounding() {
    let ledger = RelayLedger::new(Limits::default());
    let mut terms = channel();
    terms.grace_msat = 10;
    ledger.open_channel_verified(terms, 999).unwrap();
    let mut quote = contract();
    quote.max_units = 4_000;
    quote.price = BytePrice {
        msat: 1,
        per_bytes: 3,
    };
    ledger.add_contract(quote).unwrap();
    for packet in [b"a", b"b", b"c"] {
        let token = ledger.admit_at(&request(packet), 100).unwrap();
        ledger.complete(token, ForwardingOutcome::Submitted);
    }
    assert_eq!(ledger.channel_usage("channel-a").unwrap().submitted_msat, 1);
    let fill = vec![42; 2_997];
    let token = ledger.admit_at(&request(&fill), 100).unwrap();
    ledger.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(
        ledger.channel_usage("channel-a").unwrap().submitted_msat,
        1_000
    );
    assert!(
        ledger.admit_at(&request(b"x"), 100).is_none(),
        "grace cannot exceed the redeemable channel capacity"
    );
}

#[test]
fn forwarding_attempt_totals_survive_more_than_the_fingerprint_limit() {
    use fips_relay::ledger::BillingBasis;
    let ledger = RelayLedger::new(Limits {
        max_packets_per_contract: 2,
        max_pending: 2,
        ..Limits::default()
    });
    let mut terms = channel();
    terms.capacity_sat = 100;
    ledger.open_channel_verified(terms, 50_000).unwrap();
    let mut route = contract();
    route.billing = BillingBasis::ForwardingAttempt;
    route.max_units = 100_000;
    ledger.add_contract(route).unwrap();
    for _ in 0..10_000 {
        // These are separate native admissions. Equal inner contents do not
        // imply replay of an authenticated link frame.
        let token = ledger.admit_at(&request(b"four"), 100).unwrap();
        ledger.complete(token, ForwardingOutcome::Submitted);
        ledger.complete(token, ForwardingOutcome::Submitted);
    }
    assert_eq!(ledger.amount_due_msat("route-a"), Some(40_000));
    let before = serde_json::to_value(ledger.snapshot()).unwrap();
    assert!(
        before["accounts"][0]["attempts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(serde_json::to_vec(&before).unwrap().len() < 2_000);
    let a = ledger.admit_at(&request(b"same"), 100).unwrap();
    let b = ledger.admit_at(&request(b"same"), 100).unwrap();
    assert!(ledger.admit_at(&request(b"extra"), 100).is_none());
    ledger.complete(b, ForwardingOutcome::Unconfirmed);
    let saved = ledger.snapshot();
    let recovered = RelayLedger::restore(saved.clone()).unwrap();
    assert_eq!(
        recovered.usage("route-a").unwrap(),
        fips_relay::ledger::Usage {
            reserved_units: 40_008,
            submitted_units: 40_000,
            unconfirmed_units: 8,
        }
    );
    recovered.complete(a, ForwardingOutcome::Submitted);
    assert_eq!(recovered.amount_due_msat("route-a"), Some(40_000));
    let value = serde_json::to_value(recovered.snapshot()).unwrap();
    assert!(
        value["accounts"][0]["attempts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let mut corrupted = serde_json::to_value(saved).unwrap();
    corrupted["accounts"][0]["completed"]["submitted_units"] = 40_001.into();
    assert!(RelayLedger::restore(serde_json::from_value(corrupted).unwrap()).is_err());
}

#[test]
fn legacy_snapshot_keeps_its_original_ciphertext_deduplication() {
    let ledger = RelayLedger::new(Limits::default());
    fund(&ledger, 100);
    let token = ledger.admit_at(&request(b"same"), 100).unwrap();
    ledger.complete(token, ForwardingOutcome::Submitted);
    let mut legacy = serde_json::to_value(ledger.snapshot()).unwrap();
    legacy["version"] = 3.into();
    legacy["accounts"][0]
        .as_object_mut()
        .unwrap()
        .remove("completed");
    let restored = RelayLedger::restore(serde_json::from_value(legacy.clone()).unwrap()).unwrap();
    assert_eq!(restored.amount_due_msat("route-a"), Some(4));
    // Version three must never reinterpret a saved fingerprint table as the
    // new transmission tariff, even if a malformed file adds a billing field.
    legacy["accounts"][0]["contract"]["billing"] = "forwarding_attempt".into();
    assert!(RelayLedger::restore(serde_json::from_value(legacy).unwrap()).is_err());
    assert_eq!(
        restored.contract("route-a").unwrap().billing,
        fips_relay::ledger::BillingBasis::UniqueSessionEnvelope
    );
}
