//! Deterministic interleavings around an interrupted source purchase.
use super::*;
use crate::controller::transition_tests::{fixture, reload};

fn watch(j: &mut Journal, offer: &RouteOffer) -> WatchedRoute {
    let watch = WatchedRoute {
        billing: offer.billing,
        destination: offer.destination.npub(),
        max_rate_msat_per_kib: offer.price.msat,
        paused: false,
        pending: Some(offer.clone()),
        selected_trial: None,
    };
    j.watched_routes
        .insert(watch.destination.clone(), watch.clone());
    watch
}

#[test]
fn withdrawn_reservation_retains_exact_capital_and_fences_stale_funding() {
    for funded in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        store.journal.outgoing.clear();
        if !funded {
            store
                .journal
                .funding
                .get_mut(&old.funding_id)
                .unwrap()
                .funded = None;
        }
        let captured = watch(&mut store.journal, &old.offer);
        let funding = serde_json::to_value(&store.journal.funding).unwrap();
        let budget = Controller::capital(&store.journal).unwrap();
        store
            .change(|j| Controller::withdraw_watched_purchase(j, &captured))
            .unwrap();
        let mut store = reload(store);
        assert_ne!(store.journal.version & journal::RECOVERY_ONLY_VERSION, 0);
        assert!(store.journal.recovery_only.contains(&old.offer.id));
        assert!(
            store.journal.watched_routes[&captured.destination]
                .pending
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(&store.journal.funding).unwrap(),
            funding
        );
        assert_eq!(Controller::capital(&store.journal).unwrap(), budget);
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            store
                .change(|j| Controller::reserve_purchase(j, old.offer.clone()))
                .is_err()
        );
        assert!(
            store
                .change(|j| Controller::record_purchase(j, old.clone()))
                .is_err()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        let mut next = old.offer.clone();
        next.id = "independent-provider".into();
        next.provider = NodeAddr::from_bytes([9; 16]);
        next.path[0] = next.provider;
        store
            .change(|j| Controller::reserve_purchase(j, next))
            .unwrap();
        reload(store);
    }
}

#[test]
fn late_acceptance_records_knowledge_without_reviving_withdrawn_routing() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, mut old) = fixture(&root.path().join("controller"));
    old.accepted = false;
    store
        .journal
        .outgoing
        .insert(old.purchase.contract.id.clone(), old.clone());
    let captured = watch(&mut store.journal, &old.offer);
    store
        .change(|j| Controller::withdraw_watched_purchase(j, &captured))
        .unwrap();
    let mut store = reload(store);
    assert!(
        !store
            .change(|j| Controller::finish_acceptance(j, &old.purchase.contract.id))
            .unwrap()
    );
    let saved = &store.journal.outgoing[&old.purchase.contract.id];
    assert!(
        saved.accepted,
        "a real late success remains financial knowledge"
    );
    assert!(!Controller::routing_eligible(&store.journal, saved));
    assert!(!saved.retired);
    assert!(store.journal.buyer_settlements.is_empty());
    reload(store);
}

#[test]
fn changed_or_paused_watch_cannot_be_withdrawn_by_a_stale_observer() {
    for pause in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let captured = watch(&mut store.journal, &old.offer);
        let current = store
            .journal
            .watched_routes
            .get_mut(&captured.destination)
            .unwrap();
        if pause {
            current.paused = true;
        } else {
            current.pending = None;
        }
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            !store
                .change(|j| Controller::withdraw_watched_purchase(j, &captured))
                .unwrap()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        reload(store);
    }
}

#[test]
fn recovery_closure_rechecks_shared_channel_and_new_reservations() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let captured = watch(&mut store.journal, &old.offer);
    store
        .change(|j| Controller::withdraw_watched_purchase(j, &captured))
        .unwrap();
    Controller::check_recovery_settlement(&store.journal, &old.purchase.channel.id).unwrap();
    let mut other = old.clone();
    other.offer.id = "still-serving".into();
    other.offer.destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    other.offer.next_hop = *other.offer.destination.node_addr();
    other.offer.path[1] = other.offer.next_hop;
    other.purchase.contract = contract_from_offer(&other.offer, &other.purchase.channel).unwrap();
    store
        .change(|j| Controller::reserve_purchase(j, other.offer.clone()))
        .unwrap();
    assert!(
        Controller::check_recovery_settlement(&store.journal, &old.purchase.channel.id).is_err()
    );
    store
        .change(|j| Controller::record_purchase(j, other))
        .unwrap();
    assert!(
        Controller::check_recovery_settlement(&store.journal, &old.purchase.channel.id).is_err()
    );
    assert!(store.journal.buyer_settlements.is_empty());
    reload(store);
}

#[test]
fn committed_funding_attaches_after_withdrawal_without_restoring_authority() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    store.journal.outgoing.clear();
    let funded = store
        .journal
        .funding
        .get_mut(&old.funding_id)
        .unwrap()
        .funded
        .take()
        .unwrap();
    let intent = store.journal.funding[&old.funding_id].clone();
    let captured = watch(&mut store.journal, &old.offer);
    store
        .change(|j| Controller::withdraw_watched_purchase(j, &captured))
        .unwrap();
    let mut store = reload(store);
    store
        .change(|j| Controller::record_funding(j, intent.clone(), funded.clone()))
        .unwrap();
    store
        .change(|j| Controller::record_funding(j, intent, funded.clone()))
        .unwrap();
    assert_eq!(store.journal.funding.len(), 1);
    assert_eq!(
        store.journal.funding[&old.funding_id]
            .funded
            .as_ref()
            .unwrap()
            .wallet_operation_id,
        funded.wallet_operation_id
    );
    let budget = Controller::capital(&store.journal).unwrap();
    assert_eq!(
        (
            budget.wallet_debited_sat,
            budget.locked_sat,
            budget.wallet_refunded_sat
        ),
        (32, 32, 0)
    );
    assert!(
        store
            .change(|j| Controller::record_purchase(j, old))
            .is_err()
    );
    reload(store);
}

#[test]
fn withdrawal_and_quote_installation_have_one_durable_order() {
    for install_first in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(&root.path().join("controller"));
        let buyer = BuyerAuthorizer::create(
            &root.path().join("buyer"),
            store.journal.local,
            64,
            crate::ledger::Limits::default(),
        )
        .unwrap();
        let captured = watch(&mut store.journal, &old.offer);
        if install_first {
            store
                .change(|j| Controller::install_buyer_purchase(j, &buyer, &old.purchase))
                .unwrap();
            assert!(buyer.has_active_route(
                old.purchase.provider,
                old.purchase.contract.destination,
                now().unwrap()
            ));
        }
        store
            .change(|j| {
                Controller::withdraw_watched_purchase(j, &captured)?;
                Controller::reconcile_withdrawn_routes(j, &buyer)
            })
            .unwrap();
        let mut store = reload(store);
        assert!(
            store
                .change(|j| Controller::install_buyer_purchase(j, &buyer, &old.purchase))
                .is_err()
        );
        assert!(!buyer.has_active_route(
            old.purchase.provider,
            old.purchase.contract.destination,
            now().unwrap()
        ));
        assert_eq!(buyer.remaining_budget_sat(), Some(64));
    }
}

#[test]
fn verified_retirement_prunes_the_marker_and_keeps_an_expiry_replay_fence() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, mut old) = fixture(&root.path().join("controller"));
    old.offer.billing = crate::ledger::BillingBasis::ForwardingData;
    old.offer.expires_unix = now().unwrap() + 100;
    old.purchase.contract = contract_from_offer(&old.offer, &old.purchase.channel).unwrap();
    old.accepted = false;
    store.journal.outgoing = [(old.purchase.contract.id.clone(), old.clone())].into();
    store.journal.requested = [(old.offer.id.clone(), old.offer.clone())].into();
    let buyer = BuyerAuthorizer::create(
        &root.path().join("buyer"),
        store.journal.local,
        64,
        crate::ledger::Limits::default(),
    )
    .unwrap();
    Controller::install_buyer_purchase(&store.journal, &buyer, &old.purchase).unwrap();
    let seller = DurableRelay::create(
        &root.path().join("seller"),
        crate::ledger::Limits::default(),
        1000,
    )
    .unwrap();
    let captured = watch(&mut store.journal, &old.offer);
    store
        .change(|j| {
            Controller::withdraw_watched_purchase(j, &captured)?;
            Controller::reconcile_withdrawn_routes(j, &buyer)
        })
        .unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        0
    );
    assert!(store.journal.recovery_only.contains(&old.offer.id));
    let channel = &old.purchase.channel;
    let opening = store.journal.funding[&old.funding_id]
        .funded
        .as_ref()
        .unwrap()
        .opening
        .clone();
    store.change(|j| {
        j.buyer_settlements.insert(channel.id.clone(), serde_json::from_value(serde_json::json!({
            "provider":old.purchase.provider.as_bytes(), "channel":channel,
            "usage":crate::ledger::ChannelUsage::default(), "payment":opening,
            "report":{"channel_id":channel.id,"value_after_stage1_sat":32,"signed_sat":0,"paid_sat":0,"refunded_sat":32,"fee_sat":0},
            "refunded":true,"wallet_refund_sat":32
        })).unwrap());
        Controller::retire_refunded_purchases(j, &channel.id)
    }).unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, old.offer.expires_unix)
            .unwrap(),
        1
    );
    let mut store = reload(store);
    assert!(store.journal.recovery_only.is_empty());
    assert_ne!(store.journal.version & journal::RECOVERY_ONLY_VERSION, 0);
    assert!(
        store
            .change(|j| Controller::reserve_purchase(j, old.offer))
            .is_err()
    );
    assert_eq!(
        Controller::capital(&store.journal)
            .unwrap()
            .wallet_refunded_sat,
        32
    );
}

#[test]
fn disposition_format_preserves_required_history_and_rejects_unknown_versions() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let captured = watch(&mut store.journal, &old.offer);
    store
        .change(|j| Controller::withdraw_watched_purchase(j, &captured))
        .unwrap();
    let mut saved = store.journal.clone();
    assert!(
        !matches!(saved.version, 2..=6),
        "older readers must fail closed"
    );
    saved.advance_history_version(4);
    assert_eq!(saved.history_version(), 4);
    assert_ne!(saved.version & journal::RECOVERY_ONLY_VERSION, 0);
    assert_eq!(
        Controller::validate_channel_history(&saved),
        Err("missing channel history".into())
    );
    saved.advance_history_version(7);
    assert_eq!(
        Controller::validate_journal(&saved, &saved.policy, saved.local),
        Err("invalid controller journal bindings".into())
    );
    saved = store.journal.clone();
    saved.version = saved.history_version();
    assert!(Controller::validate_recovery_only(&saved).is_err());
    saved = store.journal.clone();
    saved.recovery_only.insert("unknown-reservation".into());
    assert!(Controller::validate_recovery_only(&saved).is_err());
    reload(store);
}

#[test]
fn failed_withdrawal_persistence_never_closes_local_authority() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("controller");
    let (mut store, old) = fixture(&directory);
    let captured = watch(&mut store.journal, &old.offer);
    store.persist().unwrap();
    let original = std::fs::read(directory.join("controller.json")).unwrap();
    let moved = root.path().join("retained-controller");
    std::fs::rename(&directory, &moved).unwrap();
    std::fs::write(&directory, b"block persistence").unwrap();
    let mut reconciled = false;
    assert!(
        store
            .withdraw_purchase(&captured, |_| {
                reconciled = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!reconciled);
    assert!(!store.ready);
    assert_eq!(
        std::fs::read(moved.join("controller.json")).unwrap(),
        original
    );
    std::fs::remove_file(&directory).unwrap();
    std::fs::rename(moved, &directory).unwrap();
}

#[test]
fn a_failed_buyer_checkpoint_still_fences_every_marked_quote() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(&root.path().join("controller"));
    let buyer_dir = root.path().join("buyer");
    let buyer = BuyerAuthorizer::create(
        &buyer_dir,
        store.journal.local,
        64,
        crate::ledger::Limits::default(),
    )
    .unwrap();
    Controller::install_buyer_purchase(&store.journal, &buyer, &old.purchase).unwrap();
    let mut second = old.clone();
    second.offer.id = "second-withdrawn".into();
    second.offer.destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    second.offer.next_hop = *second.offer.destination.node_addr();
    second.offer.path[1] = second.offer.next_hop;
    second.purchase.contract =
        contract_from_offer(&second.offer, &second.purchase.channel).unwrap();
    store
        .change(|j| {
            Controller::reserve_purchase(j, second.offer.clone())?;
            Controller::record_purchase(j, second.clone())?;
            Controller::install_buyer_purchase(j, &buyer, &second.purchase)
        })
        .unwrap();
    let first_watch = watch(&mut store.journal, &old.offer);
    let second_watch = watch(&mut store.journal, &second.offer);
    store
        .change(|j| Controller::withdraw_watched_purchase(j, &first_watch))
        .unwrap();
    let moved = root.path().join("retained-buyer");
    std::fs::rename(&buyer_dir, &moved).unwrap();
    std::fs::write(&buyer_dir, b"block checkpoint").unwrap();
    let path = store.directory.join("controller.json");
    assert!(
        store
            .withdraw_purchase(&second_watch, |j| {
                let durable: Journal =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                assert_eq!(
                    durable.recovery_only, j.recovery_only,
                    "both fences precede external effects"
                );
                Controller::reconcile_withdrawn_routes(j, &buyer)
            })
            .is_err()
    );
    assert!(!store.ready);
    assert!(store.ensure_ready().is_err());
    for outgoing in [&old, &second] {
        assert!(!buyer.has_active_route(
            outgoing.purchase.provider,
            outgoing.purchase.contract.destination,
            now().unwrap()
        ));
    }
    assert_eq!(buyer.remaining_budget_sat(), Some(64));
    std::fs::remove_file(&buyer_dir).unwrap();
    std::fs::rename(moved, buyer_dir).unwrap();
}

#[tokio::test]
async fn controller_load_closes_authority_after_crash_between_journals() {
    let root = tempfile::tempdir().unwrap();
    let controller = crate::controller::refresh::tests::disconnected_controller(root.path()).await;
    let services = controller.services.clone();
    let policy = controller.policy.clone();
    let (fixture, mut old) = fixture(&root.path().join("fixture"));
    let mut journal = fixture.journal.clone();
    journal.local = *services.endpoint.node_addr();
    old.offer.buyer = journal.local;
    old.purchase.channel.buyer = journal.local;
    old.purchase.contract = contract_from_offer(&old.offer, &old.purchase.channel).unwrap();
    journal
        .funding
        .get_mut(&old.funding_id)
        .unwrap()
        .funded
        .as_mut()
        .unwrap()
        .terms = old.purchase.channel.clone();
    journal.requested = [(old.offer.id.clone(), old.offer.clone())].into();
    journal.outgoing = [(old.purchase.contract.id.clone(), old.clone())].into();
    let captured = watch(&mut journal, &old.offer);
    controller
        .change(move |j| {
            *j = journal;
            Ok(())
        })
        .await
        .unwrap();
    controller
        .ensure_buyer_purchase(&old.purchase)
        .await
        .unwrap();
    let budget = controller.funding_budget().await.unwrap();
    let directory = root.path().join("controller");
    {
        let mut store = controller.store.lock().unwrap();
        assert!(
            store
                .withdraw_purchase(&captured, |j| {
                    let disk: Journal = serde_json::from_slice(
                        &std::fs::read(directory.join("controller.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(disk.recovery_only, j.recovery_only);
                    Err("simulate process exit before local close".into())
                })
                .is_err()
        );
    }
    assert!(services.buyer.has_active_route(
        old.purchase.provider,
        old.purchase.contract.destination,
        now().unwrap()
    ));
    assert!(
        controller
            .ensure_buyer_purchase(&old.purchase)
            .await
            .is_err()
    );
    drop(controller);
    let loaded = Controller::load(&directory, policy, services.clone()).unwrap();
    assert!(!services.buyer.has_active_route(
        old.purchase.provider,
        old.purchase.contract.destination,
        now().unwrap()
    ));
    assert_eq!(loaded.funding_budget().await.unwrap(), budget);
    assert!(loaded.purchases().await.unwrap().is_empty());
    assert!(
        loaded
            .snapshot()
            .await
            .unwrap()
            .recovery_only
            .contains(&old.offer.id)
    );
}
