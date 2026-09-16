//! Exercise bounded route-history retirement through production accounting APIs.
use cashu_service::{CashuSpilmanPayment, CashuSpilmanPaymentSigner};
use fips_core::{
    Identity, NodeAddr, PeerIdentity,
    node::{
        ForwardingOutcome, ForwardingPolicy, ForwardingRequest, OriginatedSessionObserver,
        OriginatedSessionRequest,
    },
};
use fips_relay::{
    buyer::BuyerAuthorizer,
    durable::DurableRelay,
    ledger::{BillingBasis, BytePrice, ChannelTerms, Contract, Limits},
};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn peer() -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[1; 32]).unwrap().pubkey_full())
}
fn address(n: u8) -> NodeAddr {
    NodeAddr::from_bytes([n; 16])
}
fn terms() -> ChannelTerms {
    ChannelTerms {
        id: "channel".into(),
        buyer: *peer().node_addr(),
        mint_url: "http://test.invalid".into(),
        expires_unix: now() + 10000,
        capacity_sat: 100,
        grace_msat: 4000,
    }
}
fn quote(id: usize, expiry: u64) -> Contract {
    Contract {
        id: format!("quote-{id}"),
        channel_id: "channel".into(),
        destination: address(9),
        next_hop: address(3),
        expires_unix: expiry,
        price: BytePrice {
            msat: 123,
            per_bytes: 100,
        },
        max_units: 10000,
        billing: BillingBasis::ForwardingAttempt,
    }
}
fn limits() -> Limits {
    Limits {
        max_contracts: 1,
        ..Limits::default()
    }
}
fn outgoing() -> OriginatedSessionRequest<'static> {
    OriginatedSessionRequest {
        source: *peer().node_addr(),
        destination: address(9),
        next_hop: address(2),
        session_payload: &[7; 101],
    }
}
fn forwarded() -> ForwardingRequest<'static> {
    ForwardingRequest {
        ingress: peer(),
        source: *peer().node_addr(),
        destination: address(9),
        next_hop: address(3),
        session_payload: &[7; 101],
    }
}
struct InterruptedSigner;
impl CashuSpilmanPaymentSigner for InterruptedSigner {
    fn sign_cashu_spilman_payment(
        &self,
        _: &str,
        _: u64,
        _: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        Err("after durable authorization".into())
    }
}

#[test]
fn buyer_retirement_preserves_rounding_signatures_and_budget_across_restarts() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("buyer");
    let mut buyer = BuyerAuthorizer::create(&path, *peer().node_addr(), 100, limits()).unwrap();
    buyer.accept_channel(address(2), terms(), 0).unwrap();
    let start = now() + 1000;
    // A trusted simulated clock advances expiry without delaying the real
    // packet/signature/storage paths. No network-provided timestamp is trusted.
    for index in 0..64 {
        let route = quote(index, start + index as u64);
        buyer.accept_quote(route.clone()).unwrap();
        let token = buyer.observe(&outgoing()).unwrap();
        buyer.complete(token, ForwardingOutcome::Submitted);
        let expected = 125 * (index as u64 + 1); // ceil(101*123/100), per route
        assert_eq!(buyer.evidence_msat("channel"), Some(expected));
        assert!(
            buyer
                .sign_claim(&InterruptedSigner, address(2), "channel", expected, now())
                .is_err()
        );
        let authorized = buyer.authorized_sat("channel");
        let remaining = buyer.remaining_budget_sat();
        buyer.close_quote(&route.id).unwrap();
        assert_eq!(
            buyer
                .retire_closed_routes("channel", route.expires_unix)
                .unwrap(),
            1
        );
        assert_eq!(
            buyer
                .retire_closed_routes("channel", route.expires_unix)
                .unwrap(),
            0
        );
        assert_eq!(buyer.observed_units(&route.id), None);
        assert!(
            buyer.accept_quote(route.clone()).is_err(),
            "replay cannot reset old quota"
        );
        drop(buyer);
        buyer = BuyerAuthorizer::load(&path).unwrap();
        assert!(
            buyer.accept_quote(route).is_err(),
            "expiry floor survives clock rollback/restart"
        );
        assert_eq!(buyer.evidence_msat("channel"), Some(expected));
        assert_eq!(buyer.authorized_sat("channel"), authorized);
        assert_eq!(buyer.remaining_budget_sat(), remaining);
        assert!(std::fs::metadata(path.join("buyer.json")).unwrap().len() < 4096);
    }
}

#[test]
fn seller_retirement_preserves_credit_and_claims_across_restarts() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("seller");
    let mut seller = DurableRelay::create(&path, limits(), 1000).unwrap();
    seller.open_channel_verified(terms(), 100_000).unwrap();
    let start = now() + 1000;
    for index in 0..64 {
        let route = quote(index, start + index as u64);
        seller.add_contract(route.clone()).unwrap();
        let token = seller.admit(&forwarded()).unwrap();
        seller.complete(token, ForwardingOutcome::Submitted);
        seller.close_contract(&route.id).unwrap();
        let before = seller.channel_usage("channel").unwrap();
        assert_eq!(before.submitted_msat, 125 * (index as u64 + 1));
        assert_eq!(
            seller
                .retire_closed_routes("channel", route.expires_unix)
                .unwrap(),
            1
        );
        assert_eq!(
            seller
                .retire_closed_routes("channel", route.expires_unix)
                .unwrap(),
            0
        );
        assert_eq!(seller.channel_usage("channel"), Some(before));
        assert!(seller.add_contract(route.clone()).is_err());
        assert_eq!(seller.usage(&route.id), None);
        drop(seller);
        seller = DurableRelay::load(&path).unwrap();
        assert_eq!(seller.channel_usage("channel"), Some(before));
        assert!(seller.add_contract(route).is_err());
        assert!(std::fs::metadata(path.join("ledger.json")).unwrap().len() < 4096);
    }
}

#[test]
fn retirement_refuses_live_or_pending_evidence_without_partial_changes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(&path, *peer().node_addr(), 100, limits()).unwrap();
    buyer.accept_channel(address(2), terms(), 0).unwrap();
    let route = quote(0, now() + 1000);
    buyer.accept_quote(route.clone()).unwrap();
    assert!(
        buyer
            .retire_closed_routes("channel", route.expires_unix)
            .is_err()
    );
    let token = buyer.observe(&outgoing()).unwrap();
    buyer.close_quote(&route.id).unwrap();
    assert!(
        buyer
            .retire_closed_routes("channel", route.expires_unix)
            .is_err()
    );
    assert_eq!(buyer.observed_units(&route.id), Some(101));
    buyer.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(
        buyer
            .retire_closed_routes("channel", route.expires_unix - 1)
            .unwrap(),
        0
    );
    assert_eq!(
        buyer
            .retire_closed_routes("channel", route.expires_unix)
            .unwrap(),
        1
    );
    assert_eq!(buyer.evidence_msat("channel"), Some(125));
}

#[test]
fn unresolved_expiry_prefix_is_atomic_for_buyer_and_seller() {
    let root = tempfile::tempdir().unwrap();
    let buyer = BuyerAuthorizer::create(
        &root.path().join("buyer"),
        *peer().node_addr(),
        100,
        Limits::default(),
    )
    .unwrap();
    let seller =
        DurableRelay::create(&root.path().join("seller"), Limits::default(), 1000).unwrap();
    buyer.accept_channel(address(2), terms(), 0).unwrap();
    seller.open_channel_verified(terms(), 0).unwrap();
    let expiry = now() + 1000;
    let first = quote(0, expiry);
    buyer.accept_quote(first.clone()).unwrap();
    seller.add_contract(first.clone()).unwrap();
    let a = buyer.observe(&outgoing()).unwrap();
    let b = seller.admit(&forwarded()).unwrap();
    buyer.complete(a, ForwardingOutcome::Unconfirmed);
    seller.complete(b, ForwardingOutcome::Unconfirmed);
    buyer.close_quote(&first.id).unwrap();
    seller.close_contract(&first.id).unwrap();
    let second = quote(1, expiry);
    buyer.accept_quote(second.clone()).unwrap();
    seller.add_contract(second.clone()).unwrap();
    let a = buyer.observe(&outgoing()).unwrap();
    let b = seller.admit(&forwarded()).unwrap();
    buyer.close_quote(&second.id).unwrap();
    seller.close_contract(&second.id).unwrap();
    let before = seller.channel_usage("channel");
    // The first route can be folded, but the second still has a live completion.
    assert!(buyer.retire_closed_routes("channel", expiry).is_err());
    assert!(seller.retire_closed_routes("channel", expiry).is_err());
    assert_eq!(buyer.observed_units(&first.id), Some(101));
    assert!(seller.usage(&first.id).is_some());
    assert_eq!(
        buyer.retired_route_evidence("channel").unwrap().contracts,
        0
    );
    assert_eq!(
        seller.retired_route_evidence("channel").unwrap().contracts,
        0
    );
    assert_eq!(seller.channel_usage("channel"), before);
    buyer.complete(a, ForwardingOutcome::Submitted);
    seller.complete(b, ForwardingOutcome::Submitted);
    let before = seller.channel_usage("channel");
    assert_eq!(buyer.retire_closed_routes("channel", expiry).unwrap(), 2);
    assert_eq!(seller.retire_closed_routes("channel", expiry).unwrap(), 2);
    let retired = seller.retired_route_evidence("channel").unwrap();
    assert_eq!(retired, buyer.retired_route_evidence("channel").unwrap());
    assert_eq!(retired.reserved_msat, 250);
    assert_eq!(retired.submitted_msat, 125);
    assert_eq!(retired.units.unconfirmed_units, 101);
    assert_eq!(seller.channel_usage("channel"), before);
    // Late duplicate callbacks cannot bill the retired packet again.
    buyer.complete(a, ForwardingOutcome::Submitted);
    seller.complete(b, ForwardingOutcome::Submitted);
    assert_eq!(buyer.evidence_msat("channel"), Some(125));
    assert_eq!(seller.channel_usage("channel"), before);
}

#[test]
fn legacy_ciphertext_fingerprints_cannot_be_retired() {
    let root = tempfile::tempdir().unwrap();
    let buyer = BuyerAuthorizer::create(
        &root.path().join("buyer"),
        *peer().node_addr(),
        100,
        limits(),
    )
    .unwrap();
    let seller = DurableRelay::create(&root.path().join("seller"), limits(), 1000).unwrap();
    buyer.accept_channel(address(2), terms(), 0).unwrap();
    seller.open_channel_verified(terms(), 0).unwrap();
    let mut route = quote(0, now() + 1000);
    route.billing = BillingBasis::UniqueSessionEnvelope;
    buyer.accept_quote(route.clone()).unwrap();
    seller.add_contract(route.clone()).unwrap();
    let a = buyer.observe(&outgoing()).unwrap();
    let b = seller.admit(&forwarded()).unwrap();
    buyer.complete(a, ForwardingOutcome::Submitted);
    seller.complete(b, ForwardingOutcome::Submitted);
    buyer.close_quote(&route.id).unwrap();
    seller.close_contract(&route.id).unwrap();
    assert!(
        buyer
            .retire_closed_routes("channel", route.expires_unix)
            .is_err()
    );
    assert!(
        seller
            .retire_closed_routes("channel", route.expires_unix)
            .is_err()
    );
    assert_eq!(buyer.observed_units(&route.id), Some(101));
    assert!(seller.usage(&route.id).is_some());
}

#[test]
fn modern_journals_require_valid_retired_evidence() {
    for seller_side in [false, true] {
        for mutation in 0..5 {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("state");
            let file = if seller_side {
                let seller = DurableRelay::create(&path, limits(), 1000).unwrap();
                seller.open_channel_verified(terms(), 0).unwrap();
                "ledger.json"
            } else {
                let buyer =
                    BuyerAuthorizer::create(&path, *peer().node_addr(), 100, limits()).unwrap();
                buyer.accept_channel(address(2), terms(), 0).unwrap();
                "buyer.json"
            };
            let file = path.join(file);
            let mut data: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            let channel = if seller_side {
                &mut data["ledger"]["channels"][0]
            } else {
                &mut data["channels"]["channel"]
            };
            match mutation {
                0 => {
                    channel.as_object_mut().unwrap().remove("retired");
                }
                1 => channel["retired"] = serde_json::Value::Null,
                2 => channel["retired"]["units"]["submitted_units"] = 1.into(),
                3 => channel["retired"]["reserved_msat"] = 1.into(),
                _ => channel["retired"]["through_unix"] = 1.into(),
            }
            std::fs::write(&file, serde_json::to_vec(&data).unwrap()).unwrap();
            if seller_side {
                assert!(DurableRelay::load(&path).is_err());
            } else {
                assert!(BuyerAuthorizer::load(&path).is_err());
            }
        }
    }
}

#[test]
fn failed_retirement_write_suspends_and_recovery_keeps_original_records() {
    for seller_side in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        let route = quote(0, now() + 1000);
        let buyer = if seller_side {
            None
        } else {
            let b = BuyerAuthorizer::create(&path, *peer().node_addr(), 100, limits()).unwrap();
            b.accept_channel(address(2), terms(), 0).unwrap();
            b.accept_quote(route.clone()).unwrap();
            b.close_quote(&route.id).unwrap();
            Some(b)
        };
        let seller = if seller_side {
            let s = DurableRelay::create(&path, limits(), 1000).unwrap();
            s.open_channel_verified(terms(), 0).unwrap();
            s.add_contract(route.clone()).unwrap();
            s.close_contract(&route.id).unwrap();
            Some(s)
        } else {
            None
        };
        let name = if seller_side {
            "ledger.json"
        } else {
            "buyer.json"
        };
        let original = path.join(name);
        let saved = path.join("saved.json");
        std::fs::rename(&original, &saved).unwrap();
        std::fs::create_dir(&original).unwrap();
        if let Some(b) = buyer {
            assert!(
                b.retire_closed_routes("channel", route.expires_unix)
                    .is_err()
            );
            assert!(b.checkpoint().is_err());
        }
        if let Some(s) = seller {
            assert!(
                s.retire_closed_routes("channel", route.expires_unix)
                    .is_err()
            );
            assert!(s.checkpoint().is_err());
        }
        std::fs::remove_dir(&original).unwrap();
        std::fs::rename(&saved, &original).unwrap();
        if seller_side {
            let s = DurableRelay::load(&path).unwrap();
            assert!(s.usage(&route.id).is_some());
            assert_eq!(
                s.retire_closed_routes("channel", route.expires_unix)
                    .unwrap(),
                1
            );
        } else {
            let b = BuyerAuthorizer::load(&path).unwrap();
            assert!(b.observed_units(&route.id).is_some());
            assert_eq!(
                b.retire_closed_routes("channel", route.expires_unix)
                    .unwrap(),
                1
            );
        }
    }
}

#[test]
fn retired_routes_cannot_reset_unpaid_grace() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("seller");
    let seller = DurableRelay::create(&path, limits(), 1000).unwrap();
    let mut channel = terms();
    channel.grace_msat = 125;
    seller.open_channel_verified(channel, 0).unwrap();
    let old = quote(0, now() + 1000);
    seller.add_contract(old.clone()).unwrap();
    let token = seller.admit(&forwarded()).unwrap();
    seller.complete(token, ForwardingOutcome::Submitted);
    seller.close_contract(&old.id).unwrap();
    seller
        .retire_closed_routes("channel", old.expires_unix)
        .unwrap();
    drop(seller);
    let seller = DurableRelay::load(&path).unwrap();
    seller.add_contract(quote(1, old.expires_unix + 1)).unwrap();
    assert!(
        seller.admit(&forwarded()).is_none(),
        "old unpaid usage still consumes grace"
    );
    assert_eq!(seller.channel_usage("channel").unwrap().submitted_msat, 125);
    seller.apply_verified_balance("channel", 125).unwrap();
    assert!(seller.admit(&forwarded()).is_some());
}

#[test]
fn older_accounting_schemas_upgrade_with_zero_retired_history() {
    for seller_side in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        let route = quote(0, now() + 1000);
        let file = if seller_side {
            let s = DurableRelay::create(&path, limits(), 1000).unwrap();
            s.open_channel_verified(terms(), 0).unwrap();
            s.add_contract(route.clone()).unwrap();
            let token = s.admit(&forwarded()).unwrap();
            s.complete(token, ForwardingOutcome::Submitted);
            s.close_contract(&route.id).unwrap();
            "ledger.json"
        } else {
            let b = BuyerAuthorizer::create(&path, *peer().node_addr(), 100, limits()).unwrap();
            b.accept_channel(address(2), terms(), 0).unwrap();
            b.accept_quote(route.clone()).unwrap();
            let token = b.observe(&outgoing()).unwrap();
            b.complete(token, ForwardingOutcome::Submitted);
            b.close_quote(&route.id).unwrap();
            "buyer.json"
        };
        let file = path.join(file);
        let mut data: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        if seller_side {
            data["ledger"]["version"] = 4.into();
            data["ledger"]["channels"][0]
                .as_object_mut()
                .unwrap()
                .remove("retired");
        } else {
            data["version"] = 2.into();
            data["channels"]["channel"]
                .as_object_mut()
                .unwrap()
                .remove("retired");
        }
        std::fs::write(&file, serde_json::to_vec(&data).unwrap()).unwrap();
        if seller_side {
            let s = DurableRelay::load(&path).unwrap();
            assert_eq!(s.channel_usage("channel").unwrap().submitted_msat, 125);
            assert_eq!(
                s.retire_closed_routes("channel", route.expires_unix)
                    .unwrap(),
                1
            );
        } else {
            let b = BuyerAuthorizer::load(&path).unwrap();
            assert_eq!(b.evidence_msat("channel"), Some(125));
            assert_eq!(
                b.retire_closed_routes("channel", route.expires_unix)
                    .unwrap(),
                1
            );
        }
    }
}
