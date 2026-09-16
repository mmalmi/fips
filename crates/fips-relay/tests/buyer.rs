use cashu_service::{CashuSpilmanPayment, CashuSpilmanPaymentSigner};
use fips_core::{
    Identity, NodeAddr, PeerIdentity,
    node::{
        ForwardingOutcome, ForwardingPolicy, ForwardingRequest, OriginatedSessionObserver,
        OriginatedSessionRequest,
    },
};
use fips_relay::{
    buyer::{BuyerAuthorizer, BuyerError, PaidForwarder},
    durable::DurableRelay,
    ledger::{BytePrice, ChannelTerms, Contract, Limits},
};
use std::sync::{Arc, Mutex};

fn address(n: u8) -> NodeAddr {
    NodeAddr::from_bytes([n; 16])
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn channel(id: &str) -> ChannelTerms {
    ChannelTerms {
        id: id.into(),
        buyer: address(1),
        mint_url: "http://test.invalid".into(),
        expires_unix: now() + 600,
        capacity_sat: 10,
        grace_msat: 1_000,
    }
}

fn quote(id: &str, channel: &ChannelTerms) -> Contract {
    Contract {
        billing: Default::default(),
        id: id.into(),
        channel_id: channel.id.clone(),
        destination: address(9),
        next_hop: address(3),
        expires_unix: channel.expires_unix - 10,
        price: BytePrice {
            msat: 100,
            per_bytes: 1,
        },
        max_units: 1_000,
    }
}

fn observe(buyer: &BuyerAuthorizer, bytes: &[u8]) -> Option<u64> {
    buyer.observe(&OriginatedSessionRequest {
        source: address(1),
        destination: address(9),
        next_hop: address(2),
        session_payload: bytes,
    })
}

// Deliberately fail after recording the request: the authorization must already
// be durable even if a signer produces a signature and then reports an error.
#[derive(Default)]
struct FailingSigner(Mutex<Vec<u64>>);
impl CashuSpilmanPaymentSigner for FailingSigner {
    fn sign_cashu_spilman_payment(
        &self,
        _: &str,
        balance: u64,
        _: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        self.0.lock().unwrap().push(balance);
        Err("injected signer failure".into())
    }
}

fn approve(buyer: &BuyerAuthorizer, terms: &ChannelTerms, id: &str) {
    buyer.accept_channel(address(2), terms.clone(), 0).unwrap();
    buyer.accept_quote(quote(id, terms)).unwrap();
}

#[test]
fn forwarding_attempt_evidence_is_bounded_and_completion_is_idempotent() {
    use fips_relay::ledger::BillingBasis;
    for billing in [
        BillingBasis::ForwardingAttempt,
        BillingBasis::ForwardingData,
    ] {
        compact_evidence_is_bounded(billing);
    }
}

fn compact_evidence_is_bounded(billing: fips_relay::ledger::BillingBasis) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(
        &directory,
        address(1),
        10,
        Limits {
            max_packets_per_contract: 2,
            max_pending: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    let terms = channel("bounded");
    buyer.accept_channel(address(2), terms.clone(), 0).unwrap();
    let mut route = quote("stream", &terms);
    route.billing = billing;
    route.price.msat = 1;
    route.max_units = 20_000;
    buyer.accept_quote(route).unwrap();
    for _ in 0..10_000 {
        let token = observe(&buyer, b"x").unwrap();
        buyer.complete(token, ForwardingOutcome::Submitted);
        buyer.complete(token, ForwardingOutcome::Submitted);
    }
    assert_eq!(buyer.evidence_msat("bounded"), Some(10_000));
    let a = observe(&buyer, b"same").unwrap();
    let b = observe(&buyer, b"same").unwrap();
    assert!(observe(&buyer, b"extra").is_none());
    buyer.complete(a, ForwardingOutcome::Unconfirmed);
    buyer.checkpoint().unwrap();
    assert!(
        std::fs::metadata(directory.join("buyer.json"))
            .unwrap()
            .len()
            < 2_000
    );
    drop(buyer);
    let buyer = BuyerAuthorizer::load(&directory).unwrap();
    buyer.complete(b, ForwardingOutcome::Submitted);
    assert_eq!(buyer.evidence_msat("bounded"), Some(10_000));
    let next = observe(&buyer, b"x").unwrap();
    buyer.complete(next, ForwardingOutcome::Submitted);
    assert_eq!(buyer.evidence_msat("bounded"), Some(10_001));
    buyer.checkpoint().unwrap();
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("buyer.json")).unwrap()).unwrap();
    assert!(
        journal["quotes"]["stream"]["attempts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let signer = FailingSigner::default();
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "bounded", 10_001, now()),
        Err(BuyerError::Budget)
    ));
    assert!(signer.0.lock().unwrap().is_empty());
}

#[test]
fn loading_a_legacy_buyer_does_not_change_its_duplicate_tariff() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(&directory, address(1), 10, Limits::default()).unwrap();
    let terms = channel("legacy");
    approve(&buyer, &terms, "legacy-route");
    let token = observe(&buyer, b"same").unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    buyer.checkpoint().unwrap();
    drop(buyer);
    let path = directory.join("buyer.json");
    let mut journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    journal["version"] = 1.into();
    let quote = journal["quotes"]["legacy-route"].as_object_mut().unwrap();
    quote.remove("completed");
    quote["attempts"].as_array_mut().unwrap()[0]
        .as_object_mut()
        .unwrap()
        .remove("token");
    std::fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let buyer = BuyerAuthorizer::load(&directory).unwrap();
    assert!(observe(&buyer, b"same").is_none());
    assert_eq!(buyer.evidence_msat("legacy"), Some(400));
}

#[test]
fn expired_settlement_can_only_reproduce_the_previously_authorized_balance() {
    let root = tempfile::tempdir().unwrap();
    let buyer = BuyerAuthorizer::create(
        &root.path().join("buyer"),
        address(1),
        10,
        Limits::default(),
    )
    .unwrap();
    let terms = channel("one");
    approve(&buyer, &terms, "quote");
    let first = observe(&buyer, b"abcdefghij").unwrap();
    buyer.complete(first, ForwardingOutcome::Submitted);
    let signer = FailingSigner::default();
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 1_000, now()),
        Err(BuyerError::Signer(_))
    ));
    let second = observe(&buyer, b"0123456789").unwrap();
    buyer.complete(second, ForwardingOutcome::Submitted);
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 2_000, terms.expires_unix),
        Err(BuyerError::Expired)
    ));
    assert!(matches!(
        buyer.reproduce_payment(&signer, address(2), "one", terms.expires_unix),
        Err(BuyerError::Signer(_))
    ));
    assert_eq!(*signer.0.lock().unwrap(), vec![1, 1]);
    assert_eq!(buyer.authorized_sat("one"), Some(1));
}

#[test]
fn signatures_require_accepted_provider_and_unique_local_submitted_bytes() {
    let root = tempfile::tempdir().unwrap();
    let buyer = BuyerAuthorizer::create(
        &root.path().join("buyer"),
        address(1),
        10,
        Limits::default(),
    )
    .unwrap();
    let terms = channel("one");
    approve(&buyer, &terms, "quote");
    let signer = FailingSigner::default();
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 1, now()),
        Err(BuyerError::UnearnedClaim)
    ));
    let first = observe(&buyer, b"abcdefghij").unwrap();
    assert!(observe(&buyer, b"abcdefghij").is_none());
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 1, now()),
        Err(BuyerError::UnearnedClaim)
    ));
    buyer.complete(first, ForwardingOutcome::Submitted);
    buyer.complete(first, ForwardingOutcome::Submitted);
    assert_eq!(buyer.evidence_msat("one"), Some(1_000));
    assert!(matches!(
        buyer.sign_claim(&signer, address(3), "one", 1_000, now()),
        Err(BuyerError::UnknownAgreement)
    ));
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 1_001, now()),
        Err(BuyerError::UnearnedClaim)
    ));
    assert!(signer.0.lock().unwrap().is_empty());
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 1_000, now()),
        Err(BuyerError::Signer(_))
    ));
    assert_eq!(*signer.0.lock().unwrap(), vec![1]);
    let failed = observe(&buyer, b"failed").unwrap();
    buyer.complete(failed, ForwardingOutcome::Unconfirmed);
    assert_eq!(buyer.evidence_msat("one"), Some(1_000));
    assert!(
        buyer
            .observe(&OriginatedSessionRequest {
                source: address(8),
                destination: address(9),
                next_hop: address(2),
                session_payload: b"unsolicited"
            })
            .is_none()
    );
    assert!(
        buyer
            .observe(&OriginatedSessionRequest {
                source: address(1),
                destination: address(8),
                next_hop: address(2),
                session_payload: b"unapproved destination"
            })
            .is_none()
    );
}

#[test]
fn rounding_and_renewal_cannot_reset_durable_spending_cap() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(&directory, address(1), 2, Limits::default()).unwrap();
    let terms = channel("one");
    approve(&buyer, &terms, "first");
    let token = observe(&buyer, b"first").unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    let signer = FailingSigner::default();
    let _ = buyer.sign_claim(&signer, address(2), "one", 100, now());
    let _ = buyer.sign_claim(&signer, address(2), "one", 500, now());
    assert_eq!(*signer.0.lock().unwrap(), vec![1, 1]);
    assert_eq!(buyer.authorized_sat("one"), Some(1));
    buyer.close_channel("one").unwrap();
    let second = channel("two");
    approve(&buyer, &second, "second");
    assert!(
        observe(&buyer, b"first").is_none(),
        "retained ciphertext cannot earn another authorization on rollover"
    );
    let token = observe(&buyer, b"other").unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    let _ = buyer.sign_claim(&signer, address(2), "two", 500, now());
    drop(buyer);
    let buyer = BuyerAuthorizer::load(&directory).unwrap();
    assert_eq!(buyer.authorized_sat("one"), Some(1));
    assert_eq!(buyer.authorized_sat("two"), Some(1));
    let token = observe(&buyer, b"another ten bytes").unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "two", 1_500, now()),
        Err(BuyerError::Budget)
    ));
    assert_eq!(*signer.0.lock().unwrap(), vec![1, 1, 1]);
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 0, now()),
        Err(BuyerError::Signer(_))
    ));
    assert_eq!(
        signer.0.lock().unwrap().last(),
        Some(&1),
        "stale claims never decrease signed balance"
    );
}

#[test]
fn restart_keeps_bindings_and_does_not_turn_pending_sends_into_evidence() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(&directory, address(1), 10, Limits::default()).unwrap();
    let terms = channel("one");
    approve(&buyer, &terms, "first");
    observe(&buyer, b"pending").unwrap();
    buyer.checkpoint().unwrap();
    assert!(
        BuyerAuthorizer::load(&directory).is_err(),
        "exclusive owner"
    );
    drop(buyer);
    let buyer = BuyerAuthorizer::load(&directory).unwrap();
    assert_eq!(buyer.evidence_msat("one"), Some(0));
    assert!(observe(&buyer, b"pending").is_none());
    let mut changed = terms.clone();
    changed.capacity_sat += 1;
    assert!(buyer.accept_channel(address(2), changed, 0).is_err());
    buyer.close_quote("first").unwrap();
    buyer.accept_quote(quote("new-route", &terms)).unwrap();
    assert!(observe(&buyer, b"pending").is_none());
    drop(buyer);
    std::fs::write(directory.join("buyer.json"), b"{}").unwrap();
    assert!(BuyerAuthorizer::load(&directory).is_err());
    assert!(
        BuyerAuthorizer::create(&directory, address(1), 10, Limits::default()).is_err(),
        "corruption is not fresh authorization"
    );
}

#[test]
fn channel_capacity_expiry_and_explicit_advance_are_independent_bounds() {
    let root = tempfile::tempdir().unwrap();
    let buyer = BuyerAuthorizer::create(
        &root.path().join("buyer"),
        address(1),
        30,
        Limits::default(),
    )
    .unwrap();
    let terms = channel("one");
    buyer
        .accept_channel(address(2), terms.clone(), 500)
        .unwrap();
    buyer.accept_quote(quote("first", &terms)).unwrap();
    let signer = FailingSigner::default();
    let _ = buyer.sign_claim(&signer, address(2), "one", 500, now());
    assert_eq!(*signer.0.lock().unwrap(), vec![1]);
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 501, now()),
        Err(BuyerError::UnearnedClaim)
    ));
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 0, terms.expires_unix),
        Err(BuyerError::Expired)
    ));
    let token = observe(&buyer, &[8; 200]).unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 10_001, now()),
        Err(BuyerError::Budget)
    ));
}

#[test]
fn transit_needs_an_approved_upstream_payer_before_it_can_support_onward_payment() {
    let root = tempfile::tempdir().unwrap();
    let buyer = Arc::new(
        BuyerAuthorizer::create(
            &root.path().join("buyer"),
            address(1),
            10,
            Limits::default(),
        )
        .unwrap(),
    );
    let terms = channel("outgoing");
    approve(&buyer, &terms, "outgoing-quote");
    let seller = Arc::new(
        DurableRelay::create(&root.path().join("seller"), Limits::default(), 1_000).unwrap(),
    );
    let ingress = PeerIdentity::from_pubkey_full(
        Identity::from_secret_bytes(&[4; 32]).unwrap().pubkey_full(),
    );
    let mut incoming = channel("incoming");
    incoming.buyer = *ingress.node_addr();
    let mut incoming_quote = quote("incoming-quote", &incoming);
    incoming_quote.next_hop = address(2);
    seller.open_channel_verified(incoming.clone(), 0).unwrap();
    seller.add_contract(incoming_quote).unwrap();
    let forwarding = PaidForwarder::new(seller.clone(), buyer.clone());
    let mut request = ForwardingRequest {
        ingress: PeerIdentity::from_pubkey_full(
            Identity::from_secret_bytes(&[5; 32]).unwrap().pubkey_full(),
        ),
        source: address(7),
        destination: address(9),
        next_hop: address(2),
        session_payload: b"first",
    };
    assert!(forwarding.admit(&request).is_none());
    assert_eq!(buyer.evidence_msat("outgoing"), Some(0));
    request.ingress = ingress;
    let token = forwarding.admit(&request).unwrap();
    assert_eq!(buyer.evidence_msat("outgoing"), Some(0));
    forwarding.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(buyer.evidence_msat("outgoing"), Some(500));
    assert_eq!(
        seller.channel_usage("incoming").unwrap().submitted_msat,
        500
    );
    assert!(forwarding.admit(&request).is_none());
    buyer.close_quote("outgoing-quote").unwrap();
    request.session_payload = b"next";
    assert!(
        forwarding.admit(&request).is_none(),
        "no onward agreement means no authorized resale"
    );
    assert_eq!(
        seller.channel_usage("incoming").unwrap().reserved_msat,
        500,
        "a known unavailable onward contract must be rejected before reserving upstream credit"
    );
    assert_eq!(buyer.evidence_msat("outgoing"), Some(500));
    assert_eq!(
        seller.channel_usage("incoming").unwrap().submitted_msat,
        500
    );
    buyer
        .accept_quote(quote("replacement-quote", &terms))
        .unwrap();
    let resumed = forwarding
        .admit(&request)
        .expect("a never-forwarded packet remains eligible after renewal");
    forwarding.complete(resumed, ForwardingOutcome::Submitted);
    assert_eq!(
        seller.channel_usage("incoming").unwrap().submitted_msat,
        900
    );
}

#[test]
fn failed_persistence_prevents_signing_and_suspends_further_authorization() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(&directory, address(1), 10, Limits::default()).unwrap();
    approve(&buyer, &channel("one"), "quote");
    let token = observe(&buyer, b"bytes").unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    // Keep the last usable journal while making its target unwritable.
    std::fs::rename(
        directory.join("buyer.json"),
        directory.join("previous.json"),
    )
    .unwrap();
    std::fs::create_dir(directory.join("buyer.json")).unwrap();
    let signer = FailingSigner::default();
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 500, now()),
        Err(BuyerError::Journal(_))
    ));
    assert!(signer.0.lock().unwrap().is_empty());
    std::fs::remove_dir(directory.join("buyer.json")).unwrap();
    std::fs::rename(
        directory.join("previous.json"),
        directory.join("buyer.json"),
    )
    .unwrap();
    assert!(matches!(
        buyer.sign_claim(&signer, address(2), "one", 500, now()),
        Err(BuyerError::Journal(_))
    ));
    assert!(signer.0.lock().unwrap().is_empty());
}

#[test]
fn funding_retry_cannot_sign_a_balance_from_failed_persistence() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(&directory, address(1), 10, Limits::default()).unwrap();
    approve(&buyer, &channel("one"), "quote");
    let token = observe(&buyer, b"bytes").unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    std::fs::remove_file(directory.join("buyer.json")).unwrap();
    std::fs::create_dir(directory.join("buyer.json")).unwrap();
    let signer = FailingSigner::default();
    assert!(
        buyer
            .sign_claim(&signer, address(2), "one", 500, now())
            .is_err()
    );
    assert_eq!(
        buyer.authorized_sat("one"),
        Some(1),
        "in-memory intent was changed before persistence failed"
    );
    assert!(
        buyer
            .reproduce_payment(&signer, address(2), "one", now())
            .is_err()
    );
    assert!(signer.0.lock().unwrap().is_empty());
}
