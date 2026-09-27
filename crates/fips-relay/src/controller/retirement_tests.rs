//! Controller/accounting recovery uses real journals and deterministic expiry.
use super::*;
use crate::ledger::{BillingBasis, Limits};

pub(super) fn fixture(root: &Path) -> (Store, Outgoing, BuyerAuthorizer, DurableRelay) {
    let (mut store, mut old) = transition_tests::fixture(&root.join("controller"));
    old.offer.destination = PeerIdentity::from_npub(&old.offer.destination.npub()).unwrap();
    old.offer.expires_unix = now().unwrap() + 100;
    old.offer.billing = BillingBasis::ForwardingAttempt;
    old.purchase.contract = contract_from_offer(&old.offer, &old.purchase.channel).unwrap();
    store.journal.outgoing.clear();
    store.journal.requested.clear();
    store
        .journal
        .outgoing
        .insert(old.purchase.contract.id.clone(), old.clone());
    store
        .journal
        .requested
        .insert(old.offer.id.clone(), old.offer.clone());
    let buyer = BuyerAuthorizer::create(
        &root.join("buyer"),
        store.journal.local,
        1024,
        Limits::default(),
    )
    .unwrap();
    buyer
        .accept_channel(old.purchase.provider, old.purchase.channel.clone(), 0)
        .unwrap();
    buyer.accept_quote(old.purchase.contract.clone()).unwrap();
    let seller = DurableRelay::create(&root.join("seller"), Limits::default(), 1000).unwrap();
    (store, old, buyer, seller)
}

pub(super) fn replace(store: &mut Store, old: &Outgoing, buyer: &BuyerAuthorizer) -> Outgoing {
    let mut next = old.clone();
    next.offer.id = format!("next-{}", old.offer.expires_unix);
    next.offer.expires_unix += 1;
    next.purchase.contract = contract_from_offer(&next.offer, &next.purchase.channel).unwrap();
    let change: RouteChange = serde_json::from_value(serde_json::json!({
        "offer":next.offer,"previous":[old.purchase],"prepared":true,
        "paused":false,"stopped_remotes":[]
    }))
    .unwrap();
    store
        .journal
        .outgoing
        .get_mut(&old.purchase.contract.id)
        .unwrap()
        .retired = true;
    store.journal.requested.remove(&old.offer.id);
    store
        .journal
        .requested
        .insert(next.offer.id.clone(), next.offer.clone());
    store
        .journal
        .route_changes
        .insert(next.offer.id.clone(), change);
    store
        .journal
        .outgoing
        .insert(next.purchase.contract.id.clone(), next.clone());
    buyer.close_quote(&old.purchase.contract.id).unwrap();
    buyer.accept_quote(next.purchase.contract.clone()).unwrap();
    store.persist().unwrap();
    next
}

#[test]
fn completed_settlement_retires_accepted_routes_without_waiting_for_a_replacement() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = fixture(root.path());
    let channel = &old.purchase.channel;
    buyer.close_channel(&channel.id).unwrap();
    let payment = &store.journal.funding[&old.funding_id]
        .funded
        .as_ref()
        .unwrap()
        .opening;
    store.journal.buyer_settlements.insert(channel.id.clone(), serde_json::from_value(serde_json::json!({
        "provider": old.purchase.provider.as_bytes(), "channel": channel,
        "usage": crate::ledger::ChannelUsage::default(), "payment": payment,
        "report": {"channel_id":channel.id, "value_after_stage1_sat":32,"signed_sat":0,"paid_sat":0,"refunded_sat":32,"fee_sat":0},
        "refunded":true,"wallet_refund_sat":32,
    })).unwrap());
    assert!(old.accepted && !old.retired);
    store.persist().unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    assert!(store.journal.outgoing.is_empty());
    assert!(
        store
            .journal
            .history
            .as_ref()
            .unwrap()
            .buyers
            .contains(&channel.id)
    );
    assert_eq!(
        buyer.retired_route_evidence(&channel.id).unwrap().contracts,
        1
    );
    transition_tests::reload(store);
}

#[test]
fn controller_retires_repeated_replacements_without_dropping_channel_or_budget() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, mut old, buyer, seller) = fixture(root.path());
    for n in 1..=64 {
        let next = replace(&mut store, &old, &buyer);
        assert_eq!(
            buyer
                .retirement_plan("channel", old.offer.expires_unix)
                .unwrap()
                .contracts
                .len(),
            1,
            "prefix {n}"
        );
        assert_eq!(
            store
                .retire_routes(&buyer, &seller, old.offer.expires_unix)
                .unwrap(),
            1,
            "round {n}"
        );
        assert_eq!(store.journal.outgoing.len(), 1);
        assert!(store.journal.route_changes.is_empty());
        assert_eq!(
            buyer.retired_route_evidence("channel").unwrap().contracts,
            n
        );
        assert_eq!(store.journal.funding.len(), 1);
        assert_eq!(buyer.remaining_budget_sat(), Some(1024));
        assert!(Controller::check_purchase(&store.journal, &old.offer, None).is_err());
        store = transition_tests::reload(store);
        old = next;
    }
}

fn sale(store: &mut Store, old: &Outgoing, seller: &DurableRelay) -> Incoming {
    let mut channel = old.purchase.channel.clone();
    channel.id = "sale".into();
    channel.buyer = NodeAddr::from_bytes([9; 16]);
    let mut offer = old.offer.clone();
    offer.buyer = channel.buyer;
    offer.provider = store.journal.local;
    offer.path[0] = store.journal.local;
    let contract = contract_from_offer(&offer, &channel).unwrap();
    let incoming = Incoming {
        offer,
        channel: channel.clone(),
        contract: contract.clone(),
        downstream: None,
        verified_paid_msat: 0,
        phase: Phase::Stopped,
        replaces: None,
        replacement_retired: false,
    };
    seller.open_channel_verified(channel, 0).unwrap();
    seller.add_contract(contract.clone()).unwrap();
    seller.close_contract(&contract.id).unwrap();
    store.journal.incoming.insert(contract.id, incoming.clone());
    store.persist().unwrap();
    incoming
}

#[test]
fn recovery_finishes_each_cross_journal_boundary_and_does_not_write_when_idle() {
    for boundary in 0..=2 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old, buyer, seller) = fixture(root.path());
        replace(&mut store, &old, &buyer);
        let incoming = sale(&mut store, &old, &seller);
        store
            .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
            .unwrap();
        assert!(
            store.change(|_| Ok(())).is_err(),
            "intent freezes competing mutations"
        );
        if boundary >= 1 {
            buyer
                .retire_closed_routes("channel", old.offer.expires_unix)
                .unwrap();
        }
        if boundary >= 2 {
            seller
                .retire_closed_routes("sale", old.offer.expires_unix)
                .unwrap();
        }
        store = transition_tests::reload(store);
        drop(buyer);
        drop(seller);
        let buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
        let seller = DurableRelay::load(&root.path().join("seller")).unwrap();
        assert_eq!(store.resume_retirement(&buyer, &seller).unwrap(), 2);
        assert!(store.journal.incoming.is_empty());
        assert_eq!(
            store.journal.history.as_ref().unwrap().sellers["sale"],
            incoming.channel
        );
        let path = store.directory.join("controller.json");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            store
                .retire_routes(&buyer, &seller, old.offer.expires_unix)
                .unwrap(),
            0
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        assert!(buyer.accept_quote(old.purchase.contract).is_err());
        assert!(seller.add_contract(incoming.contract).is_err());
        transition_tests::reload(store);
    }
}

#[test]
fn failed_accounting_write_cannot_be_mistaken_for_durable_completion() {
    for file in ["buyer/buyer.json", "seller/ledger.json"] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old, buyer, seller) = fixture(root.path());
        replace(&mut store, &old, &buyer);
        sale(&mut store, &old, &seller);
        store
            .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
            .unwrap();
        let path = root.path().join(file);
        let backup = root.path().join("accounting.saved");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store.resume_retirement(&buyer, &seller).is_err());
        assert_eq!(
            buyer.retired_route_evidence("channel").unwrap().contracts,
            1
        );
        assert_eq!(
            seller.retired_route_evidence("sale").unwrap().contracts,
            u64::from(file.starts_with("seller"))
        );
        // In-memory totals changed, but the failed writer must never certify them.
        assert!(store.resume_retirement(&buyer, &seller).is_err());
        assert_eq!(store.journal.outgoing.len(), 2);
        assert!(store.change(|_| Ok(())).is_err());
        drop(buyer);
        drop(seller);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        let buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
        let seller = DurableRelay::load(&root.path().join("seller")).unwrap();
        store = transition_tests::reload(store);
        assert_eq!(store.resume_retirement(&buyer, &seller).unwrap(), 2);
        transition_tests::reload(store);
    }
}

#[test]
fn unfinished_replacement_and_pending_submission_block_retirement() {
    use fips_core::node::{ForwardingOutcome, OriginatedSessionObserver, OriginatedSessionRequest};
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = fixture(root.path());
    let request = OriginatedSessionRequest {
        source: store.journal.local,
        destination: old.purchase.contract.destination,
        next_hop: old.purchase.provider,
        session_payload: &[1; 101],
    };
    let token = buyer.observe(&request).unwrap();
    let next = replace(&mut store, &old, &buyer);
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        0
    );
    buyer.complete(token, ForwardingOutcome::Submitted);
    store
        .journal
        .outgoing
        .get_mut(&next.purchase.contract.id)
        .unwrap()
        .accepted = false;
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        0
    );
    store
        .journal
        .outgoing
        .get_mut(&next.purchase.contract.id)
        .unwrap()
        .accepted = true;
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    assert_eq!(buyer.evidence_msat("channel"), Some(101));
    buyer.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(buyer.evidence_msat("channel"), Some(101));
}

#[test]
fn sale_replacement_keeps_wire_identity_and_prepared_acceptance_blocks_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = fixture(root.path());
    let previous = sale(&mut store, &old, &seller);
    let mut next = previous.clone();
    next.offer.id = "sale-next".into();
    next.offer.expires_unix += 1;
    next.contract = contract_from_offer(&next.offer, &next.channel).unwrap();
    next.phase = Phase::Prepared;
    next.replaces = Some(previous.contract.id.clone());
    store
        .journal
        .incoming
        .insert(next.contract.id.clone(), next.clone());
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        0
    );
    seller.add_contract(next.contract.clone()).unwrap();
    store
        .journal
        .incoming
        .get_mut(&next.contract.id)
        .unwrap()
        .phase = Phase::Active;
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    let retained = &store.journal.incoming[&next.contract.id];
    assert_eq!(retained.replaces, next.replaces);
    assert!(retained.replacement_retired);
    transition_tests::reload(store);
}

#[test]
fn malformed_or_missing_retirement_state_fails_before_mutating_accounting() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = fixture(root.path());
    replace(&mut store, &old, &buyer);
    store
        .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
        .unwrap();
    let original = serde_json::to_value(&store.journal).unwrap();
    for corruption in 0..5 {
        let mut changed = original.clone();
        match corruption {
            0 => changed["history"] = serde_json::Value::Null,
            1 => changed["version"] = 2.into(),
            2 => changed["history"]["pending"]["buyer"][0]["after"]["submitted_msat"] = 1.into(),
            3 => changed["history"]["pending"]["buyer"][0]["contracts"][0]["max_units"] = 1.into(),
            _ => {
                let route = changed["history"]["pending"]["buyer"][0]["contracts"][0].clone();
                changed["history"]["pending"]["buyer"][0]["contracts"]
                    .as_array_mut()
                    .unwrap()
                    .push(route);
            }
        }
        store.journal = serde_json::from_value(changed).unwrap();
        let result = Controller::validate_journal(
            &store.journal,
            &store.journal.policy,
            store.journal.local,
        )
        .and_then(|_| store.resume_retirement(&buyer, &seller).map(|_| ()));
        assert!(result.is_err());
        assert_eq!(
            buyer.retired_route_evidence("channel").unwrap().contracts,
            0
        );
    }
    store.journal = serde_json::from_value(original).unwrap();
    assert_eq!(store.resume_retirement(&buyer, &seller).unwrap(), 1);
}

#[test]
fn last_route_can_retire_after_provider_change_without_losing_settlement_identity() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = fixture(root.path());
    let mut replacement = old.clone();
    replacement.offer.id = "new-provider".into();
    replacement.offer.expires_unix += 1;
    replacement.offer.provider = NodeAddr::from_bytes([3; 16]);
    replacement.offer.path[0] = replacement.offer.provider;
    replacement.purchase.provider = replacement.offer.provider;
    replacement.purchase.channel.id = "second-channel".into();
    replacement.purchase.contract =
        contract_from_offer(&replacement.offer, &replacement.purchase.channel).unwrap();
    replacement.funding_id = "test-2".into();
    let mut funding = store.journal.funding["test-1"].clone();
    funding.id = replacement.funding_id.clone();
    funding.funded.as_mut().unwrap().wallet_operation_id = "fixture-operation-2".into();
    funding.provider = replacement.purchase.provider;
    funding.funded.as_mut().unwrap().terms = replacement.purchase.channel.clone();
    funding.funded.as_mut().unwrap().opening.channel_id = replacement.purchase.channel.id.clone();
    store.journal.funding.insert(funding.id.clone(), funding);
    store.journal.next_funding = 3;
    store.journal.policy.max_locked_sat = 64;
    store
        .journal
        .outgoing
        .get_mut(&old.purchase.contract.id)
        .unwrap()
        .retired = true;
    store.journal.outgoing.insert(
        replacement.purchase.contract.id.clone(),
        replacement.clone(),
    );
    store
        .journal
        .requested
        .insert(replacement.offer.id.clone(), replacement.offer.clone());
    let change: RouteChange = serde_json::from_value(serde_json::json!({
        "offer":replacement.offer,"previous":[old.purchase],"prepared":true,
        "paused":false,"stopped_remotes":[]
    }))
    .unwrap();
    store.journal.requested.remove(&old.offer.id);
    store
        .journal
        .route_changes
        .insert(replacement.offer.id.clone(), change);
    buyer.close_quote(&old.purchase.contract.id).unwrap();
    buyer
        .accept_channel(
            replacement.purchase.provider,
            replacement.purchase.channel.clone(),
            0,
        )
        .unwrap();
    buyer
        .accept_quote(replacement.purchase.contract.clone())
        .unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    assert!(
        store
            .journal
            .outgoing
            .values()
            .all(|o| o.purchase.channel.id != "channel")
    );
    assert_eq!(
        Controller::settlement_terms(&store.journal, "channel").unwrap(),
        (old.purchase.provider, old.purchase.channel)
    );
    assert_eq!(Controller::settlement_channels(&store.journal).len(), 2);
    transition_tests::reload(store);
}

#[test]
fn failed_controller_writes_keep_the_intent_and_never_double_count_accounting() {
    for prepared in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old, buyer, seller) = fixture(root.path());
        replace(&mut store, &old, &buyer);
        if prepared {
            store
                .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
                .unwrap();
        }
        let saved = std::fs::read(store.directory.join("controller.json")).unwrap();
        let path = store.directory.join("controller.json");
        let backup = store.directory.join("controller.saved");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(
            store
                .retire_routes(&buyer, &seller, old.offer.expires_unix)
                .is_err()
        );
        assert!(store.resume_retirement(&buyer, &seller).is_err());
        assert_eq!(
            buyer.retired_route_evidence("channel").unwrap().contracts,
            u64::from(prepared)
        );
        let directory = store.directory.clone();
        drop(store);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        let journal: Journal = serde_json::from_slice(&saved).unwrap();
        let mut store = Store {
            _owner: acquire_owner(&directory).unwrap(),
            directory,
            control_obligations: ControlObligations::from_journal(&journal).unwrap(),
            journal,
            ready: true,
        };
        assert_eq!(
            store
                .retire_routes(&buyer, &seller, old.offer.expires_unix)
                .unwrap(),
            1
        );
        assert_eq!(
            buyer.retired_route_evidence("channel").unwrap().contracts,
            1
        );
        transition_tests::reload(store);
    }
}

#[test]
fn completed_renewal_retires_route_references_but_keeps_refund_and_capital_evidence() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = fixture(root.path());
    let mut next = old.clone();
    next.offer.id = "renewed-offer".into();
    next.offer.expires_unix += 1;
    next.purchase.channel.id = "renewed-channel".into();
    next.purchase.contract = contract_from_offer(&next.offer, &next.purchase.channel).unwrap();
    next.funding_id = "test-2".into();
    let mut funding = store.journal.funding["test-1"].clone();
    funding.id = next.funding_id.clone();
    funding.funded.as_mut().unwrap().wallet_operation_id = "fixture-operation-2".into();
    funding.funded.as_mut().unwrap().terms = next.purchase.channel.clone();
    funding.funded.as_mut().unwrap().opening.channel_id = next.purchase.channel.id.clone();
    store.journal.funding.insert(funding.id.clone(), funding);
    store.journal.next_funding = 3;
    let provider = serde_json::to_value(&old.purchase).unwrap()["provider"].clone();
    let settlement: BuyerSettlement = serde_json::from_value(serde_json::json!({
        "provider":provider,"channel":old.purchase.channel,
        "usage":{"paid_msat":0,"reserved_msat":0,"submitted_msat":0,"lost_msat":0},
        "payment":{"channel_id":"channel","balance":0,"signature":"fixture","params":null,"funding_proofs":null},
        "report":{"channel_id":"channel","value_after_stage1_sat":32,"signed_sat":0,"paid_sat":0,"refunded_sat":32,"fee_sat":0},
        "refunded":true,"wallet_refund_sat":32
    })).unwrap();
    store
        .journal
        .buyer_settlements
        .insert("channel".into(), settlement);
    let renewal: Renewal = serde_json::from_value(serde_json::json!({
        "previous":[old],"replacements":[next.offer],"completed":true
    }))
    .unwrap();
    store.journal.renewals.insert("channel".into(), renewal);
    store
        .journal
        .outgoing
        .get_mut(&old.purchase.contract.id)
        .unwrap()
        .retired = true;
    store.journal.requested.remove(&old.offer.id);
    store
        .journal
        .requested
        .insert(next.offer.id.clone(), next.offer.clone());
    store
        .journal
        .outgoing
        .insert(next.purchase.contract.id.clone(), next.clone());
    buyer.close_channel("channel").unwrap();
    buyer
        .accept_channel(next.purchase.provider, next.purchase.channel, 0)
        .unwrap();
    buyer.accept_quote(next.purchase.contract).unwrap();
    Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
        .unwrap();
    let before = Controller::capital(&store.journal).unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    assert!(store.journal.renewals.is_empty());
    assert_eq!(store.journal.funding.len(), 2);
    assert!(store.journal.buyer_settlements["channel"].refunded);
    assert_eq!(Controller::capital(&store.journal).unwrap(), before);
    transition_tests::reload(store);
}
