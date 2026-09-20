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
