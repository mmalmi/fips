use super::*;

pub(super) fn unresolved_journal() -> Journal {
    let local = NodeAddr::from_bytes([1; 16]);
    let policy = ControllerPolicy {
        mint_url: "http://127.0.0.1:1234".into(),
        channel_capacity_sat: 32,
        max_locked_sat: 32,
        channel_lifetime_secs: 600,
        renewal: None,
    };
    let funding = FundingIntent {
        id: "test-1".into(),
        provider: NodeAddr::from_bytes([2; 16]),
        receiver_pubkey_hex: format!("02{}", "11".repeat(32)),
        capacity_sat: 32,
        grace_msat: 8_000,
        created_unix: 100,
        expires_unix: 700,
        funded: None,
    };
    Journal {
        version: 1,
        local,
        policy,
        epoch: "test".into(),
        next_funding: 2,
        selling_stopped: false,
        funding: [(funding.id.clone(), funding)].into(),
        requested: BTreeMap::new(),
        outgoing: BTreeMap::new(),
        incoming: BTreeMap::new(),
        buyer_settlements: BTreeMap::new(),
        seller_settlements: BTreeMap::new(),
        renewals: BTreeMap::new(),
        renewals_paused: false,
        route_changes: BTreeMap::new(),
        watched_routes: BTreeMap::new(),
    }
}

#[test]
fn repurchase_rejects_unfinished_refunds_stale_offers_and_competing_renewal() {
    // Exercise the transition guards directly. The integration suite
    // uses actual funded channels, refunds and a reload of the saved journal.
    let mut journal = unresolved_journal();
    let destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let terms = ChannelTerms {
        id: "closed".into(),
        buyer: journal.local,
        mint_url: journal.policy.mint_url.clone(),
        capacity_sat: 32,
        grace_msat: 8_000,
        expires_unix: now().unwrap() + 600,
    };
    let offer = RouteOffer {
        trial: false,
        billing: Default::default(),
        id: "old-offer".into(),
        buyer: journal.local,
        provider: NodeAddr::from_bytes([2; 16]),
        destination,
        next_hop: *destination.node_addr(),
        path: vec![NodeAddr::from_bytes([2; 16]), *destination.node_addr()],
        price: crate::ledger::BytePrice {
            msat: 1024,
            per_bytes: 1024,
        },
        expires_unix: now().unwrap() + 300,
        max_units: 30_000,
        mint_url: terms.mint_url.clone(),
        receiver_pubkey_hex: format!("02{}", "11".repeat(32)),
        capacity_sat: 32,
        grace_msat: 8_000,
    };
    let old = Outgoing {
        purchase: Purchase {
            provider: offer.provider,
            contract: contract_from_offer(&offer, &terms).unwrap(),
            channel: terms.clone(),
        },
        offer: offer.clone(),
        funding_id: "test-1".into(),
        accepted: true,
        retired: false,
    };
    journal
        .outgoing
        .insert(old.purchase.contract.id.clone(), old.clone());
    journal.requested.insert(offer.id.clone(), offer.clone());
    let mut fresh = offer.clone();
    fresh.id = "fresh-offer".into();
    assert_eq!(
        Controller::reopen_refunded_route(&mut journal, &old, fresh.clone()),
        Err("previous channel refund incomplete".into())
    );
    let provider = serde_json::to_value(&old.purchase).unwrap()["provider"].clone();
    journal.buyer_settlements.insert(
        terms.id.clone(),
        serde_json::from_value(
            serde_json::json!({"provider":provider,"channel":terms,"usage":null,
            "payment":null,"report":null,"refunded":false}),
        )
        .unwrap(),
    );
    assert_eq!(
        Controller::reopen_refunded_route(&mut journal, &old, fresh.clone()),
        Err("previous channel refund incomplete".into())
    );
    journal
        .buyer_settlements
        .get_mut("closed")
        .unwrap()
        .refunded = true;
    for mutation in [0, 1, 2, 3] {
        let mut changed = fresh.clone();
        match mutation {
            0 => changed.id = offer.id.clone(),
            1 => changed.expires_unix = 1,
            2 => changed.price.msat += 1,
            _ => changed.next_hop = NodeAddr::from_bytes([3; 16]),
        }
        assert!(Controller::reopen_refunded_route(&mut journal, &old, changed).is_err());
        assert!(!journal.outgoing[&old.purchase.contract.id].retired);
        assert!(journal.requested.contains_key(&offer.id));
    }
    journal.renewals.insert(
        "closed".into(),
        serde_json::from_value(serde_json::json!({
            "previous":[old], "replacements":null, "completed":false
        }))
        .unwrap(),
    );
    assert_eq!(
        Controller::reopen_refunded_route(&mut journal, &old, fresh),
        Err("channel replacement already in progress".into())
    );
    assert!(!journal.outgoing[&old.purchase.contract.id].retired);
}

#[test]
fn unresolved_funding_survives_storage_and_still_consumes_capital() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("controller");
    let journal = unresolved_journal();
    let mut store = Store {
        _owner: acquire_owner(&directory).unwrap(),
        directory: directory.clone(),
        journal,
        ready: true,
    };
    store.persist().unwrap();
    let result: Result<(), String> = store.change(|j| {
        j.next_funding += 1;
        Err("rejected transition".into())
    });
    assert!(result.is_err());
    assert_eq!(store.journal.next_funding, 2);
    assert!(
        store.ready,
        "rejected mutation preserves the last committed state"
    );
    assert!(acquire_owner(&directory).is_err());
    drop(store);
    let mut journal: Journal =
        serde_json::from_slice(&std::fs::read(directory.join("controller.json")).unwrap()).unwrap();
    Controller::validate_journal(&journal, &journal.policy, journal.local).unwrap();
    assert!(journal.funding["test-1"].funded.is_none());
    let mut second = journal.funding["test-1"].clone();
    second.id = "test-2".into();
    second.provider = NodeAddr::from_bytes([3; 16]);
    journal.next_funding = 3;
    journal.funding.insert(second.id.clone(), second);
    assert_eq!(
        Controller::validate_journal(&journal, &journal.policy, journal.local),
        Err("capital budget exceeded".into()),
        "an unresolved mint operation still locks its whole intended capacity"
    );
}

#[test]
fn reload_rejects_reused_funding_sequence_changed_policy_and_owner() {
    let mut journal = unresolved_journal();
    let mut changed = journal.policy.clone();
    changed.max_locked_sat += 32;
    assert!(Controller::validate_journal(&journal, &changed, journal.local).is_err());
    assert!(
        Controller::validate_journal(&journal, &journal.policy, NodeAddr::from_bytes([4; 16]))
            .is_err()
    );
    journal.next_funding = 1;
    assert_eq!(
        Controller::validate_journal(&journal, &journal.policy, journal.local),
        Err("invalid funding intent".into()),
        "recovery cannot overwrite an earlier idempotent wallet request"
    );
}
