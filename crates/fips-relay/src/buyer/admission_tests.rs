use super::*;
use crate::route_quotes::{RouteOffer, contract_from_offer};
use fips_core::{Identity, PeerIdentity};

fn fixture(root: &Path, max_units: u64, limits: Limits) -> (BuyerAuthorizer, RouteOffer, Contract) {
    let peer = |n| {
        PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
    };
    let offer = RouteOffer {
        trial: true,
        billing: BillingBasis::ForwardingData,
        id: "source-trial".into(),
        buyer: *peer(1).node_addr(),
        provider: *peer(2).node_addr(),
        destination: peer(3),
        next_hop: *peer(3).node_addr(),
        path: vec![*peer(2).node_addr(), *peer(3).node_addr()],
        price: crate::ledger::BytePrice {
            msat: 1,
            per_bytes: 1024,
        },
        expires_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        max_units,
        mint_url: "http://test.invalid".into(),
        receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
        capacity_sat: 64,
        grace_msat: 8_000,
    };
    let buyer = BuyerAuthorizer::create(root, offer.buyer, 64, limits).unwrap();
    let channel = ChannelTerms {
        refund_after_unix: None,
        id: "channel".into(),
        buyer: offer.buyer,
        mint_url: offer.mint_url.clone(),
        expires_unix: offer.expires_unix,
        capacity_sat: 64,
        grace_msat: 8_000,
    };
    buyer
        .accept_channel(offer.provider, channel.clone(), 0)
        .unwrap();
    let contract = contract_from_offer(&offer, &channel).unwrap();
    buyer.accept_quote(contract.clone()).unwrap();
    (buyer, offer, contract)
}

fn intent(offer: &RouteOffer, bytes: usize) -> OriginatedSessionIntent {
    OriginatedSessionIntent {
        source: offer.buyer,
        destination: *offer.destination.node_addr(),
        next_hop: offer.provider,
        session_bytes: bytes,
    }
}

fn submit(buyer: &BuyerAuthorizer, offer: &RouteOffer, bytes: usize) {
    let OriginatedSessionAdmission::Track(token) = buyer.prepare(&intent(offer, bytes)) else {
        panic!("expected real source reservation");
    };
    buyer.complete(token, ForwardingOutcome::Submitted);
}

#[test]
fn renewal_pause_reserves_nothing_and_releases_only_into_current_authority() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let (buyer, offer, contract) = fixture(&directory, 32_768, Limits::default());
    let buyer = Arc::new(buyer);
    let ingress = PeerIdentity::from_pubkey_full(
        Identity::from_secret_bytes(&[4; 32]).unwrap().pubkey_full(),
    );
    let seller = Arc::new(
        crate::durable::DurableRelay::create(&root.path().join("seller"), Limits::default(), 8_000)
            .unwrap(),
    );
    let mut incoming = buyer.state.lock().unwrap().channels[&contract.channel_id]
        .terms
        .clone();
    incoming.id = "incoming".into();
    incoming.buyer = *ingress.node_addr();
    seller.open_channel_verified(incoming.clone(), 0).unwrap();
    seller
        .add_contract(Contract {
            id: "incoming-quote".into(),
            channel_id: incoming.id.clone(),
            buyer: incoming.buyer,
            next_hop: offer.provider,
            ..contract.clone()
        })
        .unwrap();
    let forwarding = PaidForwarder::for_billing(seller.clone(), buyer.clone(), offer.billing);
    let request = ForwardingRequest {
        ingress,
        source: *ingress.node_addr(),
        destination: contract.destination,
        next_hop: offer.provider,
        session_payload: &[7; 200],
    };
    let upstream_before = seller.channel_usage(&incoming.id);
    submit(&buyer, &offer, 100);
    buyer.checkpoint().unwrap();
    let before = std::fs::read(directory.join("buyer.json")).unwrap();
    let pause = buyer.pause_for_renewal([&contract]).unwrap();
    let nested = buyer.pause_for_renewal([&contract]).unwrap();
    let mut mismatched = contract.clone();
    mismatched.max_units += 1;
    assert!(buyer.pause_for_renewal([&contract, &mismatched]).is_err());
    let mut direct = intent(&offer, 200);
    direct.next_hop = direct.destination;
    assert_eq!(buyer.prepare(&direct), OriginatedSessionAdmission::Defer);
    for _ in 0..3 {
        assert_eq!(
            buyer.prepare(&intent(&offer, 200)),
            OriginatedSessionAdmission::Retry
        );
        assert_eq!(
            forwarding.decide(&request),
            fips_core::node::ForwardingDecision::Retry
        );
    }
    assert_eq!(seller.channel_usage(&incoming.id), upstream_before);
    buyer.checkpoint().unwrap();
    assert_eq!(std::fs::read(directory.join("buyer.json")).unwrap(), before);
    drop(nested);
    assert_eq!(
        buyer.prepare(&intent(&offer, 200)),
        OriginatedSessionAdmission::Retry
    );
    buyer.close_channel(&contract.channel_id).unwrap();
    let mut replacement = buyer.state.lock().unwrap().channels[&contract.channel_id]
        .terms
        .clone();
    replacement.id = "replacement".into();
    buyer
        .accept_channel(offer.provider, replacement.clone(), 0)
        .unwrap();
    let replacement_contract = Contract {
        id: "replacement-quote".into(),
        channel_id: replacement.id.clone(),
        ..contract.clone()
    };
    buyer.accept_quote(replacement_contract.clone()).unwrap();
    assert_eq!(
        buyer.prepare(&intent(&offer, 200)),
        OriginatedSessionAdmission::Retry
    );
    assert_eq!(buyer.evidence_msat(&replacement.id), Some(0));
    assert_eq!(
        forwarding.decide(&request),
        fips_core::node::ForwardingDecision::Retry
    );
    let previous_evidence = buyer.evidence_msat(&contract.channel_id);
    drop(pause);
    let admission = forwarding
        .decide(&request)
        .admission()
        .expect("replacement admits held transit");
    forwarding.complete(admission.token, ForwardingOutcome::Submitted);
    submit(&buyer, &offer, 200);
    assert_eq!(buyer.evidence_msat(&contract.channel_id), previous_evidence);
    assert_eq!(
        buyer.state.lock().unwrap().quotes[&replacement_contract.id].submitted_units,
        400
    );
    assert_eq!(buyer.remaining_budget_sat(), Some(64));
    let cancelled = buyer.pause_for_renewal([&replacement_contract]).unwrap();
    buyer.close_channel(&replacement.id).unwrap();
    drop(cancelled);
    assert_eq!(
        buyer.prepare(&intent(&offer, 200)),
        OriginatedSessionAdmission::Reject
    );
    assert_eq!(
        forwarding.decide(&request),
        fips_core::node::ForwardingDecision::Reject
    );
    assert!(buyer.state.lock().unwrap().renewal_pauses.is_empty());
}

#[test]
fn closed_trial_retains_only_exact_unspent_quota_across_reload() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let (buyer, offer, contract) = fixture(&directory, 32_768, Limits::default());
    assert_eq!(buyer.retained_quota(&offer), Ok(Some((true, 32_768))));
    submit(&buyer, &offer, 3_096);
    buyer.close_quote(&contract.id).unwrap();
    buyer.close_channel(&contract.channel_id).unwrap();
    assert_eq!(buyer.retained_quota(&offer), Ok(Some((false, 29_672))));
    let remaining = buyer.remaining_budget_sat();
    drop(buyer);
    let buyer = BuyerAuthorizer::load(&directory).unwrap();
    assert_eq!(buyer.retained_quota(&offer), Ok(Some((false, 29_672))));
    assert_eq!(buyer.remaining_budget_sat(), remaining);
    assert_eq!(
        buyer.prepare(&intent(&offer, 100)),
        OriginatedSessionAdmission::Reject
    );
    for changed in [
        RouteOffer {
            id: "different".into(),
            ..offer.clone()
        },
        RouteOffer {
            buyer: offer.provider,
            ..offer.clone()
        },
        RouteOffer {
            max_units: offer.max_units + 1,
            ..offer.clone()
        },
        RouteOffer {
            provider: offer.buyer,
            ..offer.clone()
        },
    ] {
        assert_eq!(buyer.retained_quota(&changed), Ok(None));
    }
}

#[test]
fn fully_spent_closed_trial_has_no_replacement_quota() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let (buyer, offer, contract) = fixture(&directory, 4_096, Limits::default());
    submit(&buyer, &offer, 4_096);
    buyer.close_quote(&contract.id).unwrap();
    drop(buyer);
    let buyer = BuyerAuthorizer::load(&directory).unwrap();
    assert_eq!(buyer.retained_quota(&offer), Ok(Some((false, 0))));
}

#[test]
fn quota_denial_with_positive_remainder_is_exact_volatile_and_not_a_reservation() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("buyer");
    let (buyer, offer, contract) = fixture(&directory, 32_768, Limits::default());
    assert_eq!(buyer.quota_blocked(&offer), Ok(Some(false)));
    submit(&buyer, &offer, 32_752);
    assert_eq!(buyer.quota_blocked(&offer), Ok(Some(false)));
    let before = serde_json::to_value(buyer.state.lock().unwrap().clone()).unwrap();
    assert_eq!(
        buyer.prepare(&intent(&offer, 260)),
        OriginatedSessionAdmission::Reject
    );
    assert_eq!(buyer.quota_blocked(&offer), Ok(Some(true)));
    assert_eq!(buyer.observed_units(&contract.id), Some(32_752));
    assert_eq!(
        serde_json::to_value(buyer.state.lock().unwrap().clone()).unwrap(),
        before
    );
    for changed in [
        RouteOffer {
            id: "other".into(),
            ..offer.clone()
        },
        RouteOffer {
            max_units: offer.max_units + 1,
            ..offer.clone()
        },
        RouteOffer {
            buyer: offer.provider,
            ..offer.clone()
        },
        RouteOffer {
            provider: offer.buyer,
            ..offer.clone()
        },
        RouteOffer {
            expires_unix: offer.expires_unix - 1,
            ..offer.clone()
        },
    ] {
        assert_eq!(buyer.quota_blocked(&changed), Ok(None));
    }
    buyer.checkpoint().unwrap();
    drop(buyer);
    let buyer = BuyerAuthorizer::load(&directory).unwrap();
    assert_eq!(buyer.observed_units(&contract.id), Some(32_752));
    assert_eq!(buyer.quota_blocked(&offer), Ok(Some(false)));
    assert_eq!(
        buyer.prepare(&intent(&offer, 260)),
        OriginatedSessionAdmission::Reject
    );
    assert_eq!(buyer.quota_blocked(&offer), Ok(Some(true)));
    buyer.close_quote(&contract.id).unwrap();
    assert_eq!(buyer.quota_blocked(&offer), Ok(None));
}

#[test]
fn nonquota_denials_and_transit_do_not_mark_source_trial_blocked() {
    let root = tempfile::tempdir().unwrap();
    let (buyer, offer, _) = fixture(
        &root.path().join("buyer"),
        100,
        Limits {
            max_pending: 1,
            ..Default::default()
        },
    );
    assert_eq!(
        buyer.prepare(&intent(&offer, 0)),
        OriginatedSessionAdmission::Reject
    );
    let OriginatedSessionAdmission::Track(token) = buyer.prepare(&intent(&offer, 10)) else {
        panic!("source reservation");
    };
    assert_eq!(
        buyer.prepare(&intent(&offer, 100)),
        OriginatedSessionAdmission::Reject
    );
    assert_eq!(
        buyer.quota_blocked(&offer),
        Ok(Some(false)),
        "pending capacity is not quota exhaustion"
    );
    buyer.complete(token, ForwardingOutcome::Submitted);
    let request = OriginatedSessionRequest {
        source: offer.provider,
        destination: *offer.destination.node_addr(),
        next_hop: offer.provider,
        session_payload: &[1; 100],
    };
    assert!(buyer.begin_admitted(&request, false, || Some(())).is_none());
    assert_eq!(
        buyer.quota_blocked(&offer),
        Ok(Some(false)),
        "transit does not report a local demand"
    );
    let mut wrong = intent(&offer, 100);
    wrong.source = offer.provider;
    assert_eq!(buyer.prepare(&wrong), OriginatedSessionAdmission::Reject);
    assert_eq!(buyer.quota_blocked(&offer), Ok(Some(false)));
}

#[test]
fn arithmetic_overflow_is_an_actual_quota_denial_and_poison_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    let (buyer, offer, contract) = fixture(&root.path().join("buyer"), u64::MAX, Limits::default());
    submit(&buyer, &offer, 1);
    assert!(
        BuyerAuthorizer::reserve_attempt(
            &mut buyer.state.lock().unwrap(),
            contract.id,
            [0; 32],
            u64::MAX,
            true,
            || Some(()),
        )
        .is_none()
    );
    assert_eq!(buyer.quota_blocked(&offer), Ok(Some(true)));
    let buyer = Arc::new(buyer);
    let poisoned = buyer.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = poisoned.state.lock().unwrap();
            panic!("poison buyer");
        })
        .join()
        .is_err()
    );
    assert!(buyer.quota_blocked(&offer).is_err());
    assert!(buyer.is_local(offer.buyer).is_err());
}
