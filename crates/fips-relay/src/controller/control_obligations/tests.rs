use super::*;
use crate::ledger::BillingBasis;

fn fixture(root: &Path) -> (Store, Outgoing) {
    super::super::transition_tests::fixture(&root.join("controller"))
}

fn sale(store: &Store, old: &Outgoing, phase: Phase) -> Incoming {
    let mut offer = old.offer.clone();
    offer.id = "sale-offer".into();
    offer.buyer = NodeAddr::from_bytes([3; 16]);
    offer.provider = store.journal.local;
    offer.path = vec![offer.provider, *offer.destination.node_addr()];
    offer.billing = BillingBasis::ForwardingAttempt;
    let mut channel = old.purchase.channel.clone();
    channel.id = "sale-channel".into();
    channel.buyer = offer.buyer;
    Incoming {
        contract: contract_from_offer(&offer, &channel).unwrap(),
        offer,
        channel,
        downstream: None,
        verified_paid_msat: 0,
        phase,
        replaces: None,
        replacement_retired: false,
    }
}

#[test]
fn unverified_funding_requested_quotes_and_free_watches_do_not_protect_peers() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(root.path());
    store.journal.outgoing.clear();
    store.journal.funding.get_mut("test-1").unwrap().funded = None;
    let mut free = old.offer;
    free.price.msat = 0;
    free.billing = BillingBasis::ForwardingData;
    let destination = free.destination.npub();
    store.journal.watched_routes.insert(
        destination.clone(),
        WatchedRoute {
            destination,
            billing: free.billing,
            max_rate_msat_per_kib: 0,
            paused: false,
            pending: Some(free),
        },
    );
    Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
        .unwrap();
    store.persist().unwrap();
    assert!(store.control_obligations.snapshot().is_empty());
}

#[test]
fn funded_obligations_survive_withdrawal_expiry_and_validated_reload() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(root.path());
    let provider = old.purchase.provider;
    let handle = store.control_obligations.clone();
    assert_eq!(handle.local(), store.journal.local);
    assert_eq!(handle.snapshot(), vec![provider]);
    assert!(!handle.contains(store.journal.local));
    store.journal.outgoing.clear();
    store.journal.requested.clear();
    // No active route or installed buyer account is required to retain funding.
    let funding = store.journal.funding.get_mut("test-1").unwrap();
    funding.created_unix = 1;
    funding.expires_unix = 1 + store.journal.policy.channel_lifetime_secs;
    funding.funded.as_mut().unwrap().terms.expires_unix = funding.expires_unix;
    Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
        .unwrap();
    store.persist().unwrap();
    assert_eq!(handle.snapshot(), vec![provider]);
    let store = super::super::transition_tests::reload(store);
    assert_eq!(store.control_obligations.snapshot(), vec![provider]);
}

#[test]
fn completed_refund_and_released_report_keep_protection_until_record_retirement() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) = fixture(root.path());
    let handle = store.control_obligations.clone();
    let channel = old.purchase.channel;
    store.journal.outgoing.clear();
    store.journal.requested.clear();
    let settlement = BuyerSettlement {
        kind: SettlementKind::Cooperative,
        provider: old.purchase.provider,
        channel: channel.clone(),
        usage: Some(crate::ledger::ChannelUsage::default()),
        payment: Some(
            store.journal.funding["test-1"]
                .funded
                .as_ref()
                .unwrap()
                .opening
                .clone(),
        ),
        report: Some(SettlementReport {
            channel_id: channel.id.clone(),
            value_after_stage1_sat: channel.capacity_sat,
            paid_sat: 0,
            receiver_fee_reserve_sat: 0,
            refunded_sat: channel.capacity_sat,
            fee_sat: 0,
        }),
        refunded: true,
        wallet_refund_sat: Some(channel.capacity_sat),
        released: false,
    };
    store
        .journal
        .buyer_settlements
        .insert(channel.id.clone(), settlement);
    for released in [false, true] {
        store
            .journal
            .buyer_settlements
            .get_mut(&channel.id)
            .unwrap()
            .released = released;
        Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
            .unwrap();
        store.persist().unwrap();
        assert!(handle.contains(old.purchase.provider));
    }
}

#[test]
fn prepared_stopped_and_retired_sales_retain_the_original_buyer() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = super::super::retirement_tests::fixture(root.path());
    let mut incoming = sale(&store, &old, Phase::Prepared);
    let customer = incoming.channel.buyer;
    let handle = store.control_obligations.clone();
    for phase in [Phase::Prepared, Phase::Active, Phase::Stopped] {
        incoming.phase = phase;
        store
            .journal
            .incoming
            .insert(incoming.contract.id.clone(), incoming.clone());
        Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
            .unwrap();
        store.persist().unwrap();
        assert!(handle.contains(customer));
        assert!(!handle.contains(*incoming.offer.destination.node_addr()));
    }
    seller
        .open_channel_verified(incoming.channel.clone(), 0)
        .unwrap();
    seller.add_contract(incoming.contract.clone()).unwrap();
    seller.close_contract(&incoming.contract.id).unwrap();
    assert_eq!(
        store
            .retire_routes(&buyer, &seller, incoming.offer.expires_unix)
            .unwrap(),
        1
    );
    assert!(store.journal.incoming.is_empty());
    assert_eq!(
        store.journal.history.as_ref().unwrap().sellers[&incoming.channel.id],
        incoming.channel
    );
    assert!(handle.contains(customer));
    let mut store = super::super::transition_tests::reload(store);
    let handle = store.control_obligations.clone();
    assert!(handle.contains(customer));
    // The financial retirement coordinator removes these retained terms only
    // after the completed settlement. Publication must remove their priority too.
    store.journal.history.as_mut().unwrap().sellers.clear();
    Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
        .unwrap();
    store.persist().unwrap();
    assert!(!handle.contains(customer));
    assert!(handle.contains(old.purchase.provider));
}

#[test]
fn failed_persistence_publishes_neither_new_nor_removed_obligations() {
    for remove in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) = fixture(root.path());
        let handle = store.control_obligations.clone();
        let incoming = sale(&store, &old, Phase::Prepared);
        let customer = incoming.channel.buyer;
        let path = store.directory.join("controller.json");
        let backup = store.directory.join("controller.saved");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        if remove {
            store.journal.outgoing.clear();
            store.journal.requested.clear();
            store.journal.funding.clear();
        } else {
            store
                .journal
                .incoming
                .insert(incoming.contract.id.clone(), incoming);
        }
        assert!(store.persist().is_err());
        assert!(!store.ready);
        assert_eq!(handle.snapshot(), vec![old.purchase.provider]);
        assert!(!handle.contains(customer));
    }
}

#[test]
fn oversized_or_foreign_projections_leave_published_membership_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let (store, old) = fixture(root.path());
    let handle = store.control_obligations.clone();
    let mut journal = store.journal.clone();
    journal.local = old.purchase.provider;
    assert!(handle.prepare(&journal).is_err());
    let mut journal = store.journal.clone();
    let incoming = sale(&store, &old, Phase::Prepared);
    for n in 0..=MAX_ROUTES {
        journal
            .incoming
            .insert(format!("sale-{n}"), incoming.clone());
    }
    assert!(handle.prepare(&journal).is_err());
    assert_eq!(handle.snapshot(), vec![old.purchase.provider]);
}

#[test]
fn poisoned_projection_fails_closed() {
    let peer = NodeAddr::from_bytes([2; 16]);
    let handle = ControlObligations::for_test(NodeAddr::from_bytes([1; 16]), [peer]);
    let poisoned = handle.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = poisoned.peers.write().unwrap();
            panic!("poison the read-only projection");
        })
        .join()
        .is_err()
    );
    assert!(!handle.contains(peer));
    assert!(handle.snapshot().is_empty());
}

#[tokio::test]
async fn reload_reuses_services_and_rebuilds_the_obligation_handle() {
    let root = tempfile::tempdir().unwrap();
    let controller = super::super::refresh::tests::disconnected_controller(root.path()).await;
    let before = controller.control_obligations();
    let services = controller.services.clone();
    let policy = controller.policy.clone();
    let local = before.local();
    let admissions = [
        services.quotes.control_admission().clone(),
        services.acceptance.control_admission().clone(),
        services.payments.control_admission().clone(),
    ];
    drop(controller);
    let controller = Controller::load(&root.path().join("controller"), policy, services).unwrap();
    let after = controller.control_obligations();
    assert_eq!(after.local(), local);
    assert!(!Arc::ptr_eq(&before.peers, &after.peers));
    assert!(after.snapshot().is_empty());
    for admission in admissions {
        assert!(admission.owns_endpoint(&controller.services.endpoint));
    }
    controller.services.endpoint.shutdown().await.unwrap();
}

#[tokio::test]
async fn foreign_service_endpoint_is_rejected_before_binding() {
    let root = tempfile::tempdir().unwrap();
    let controller =
        super::super::refresh::tests::disconnected_controller(&root.path().join("one")).await;
    let other =
        super::super::refresh::tests::disconnected_controller(&root.path().join("two")).await;
    let mut services = controller.services.clone();
    services.payments = other.services.payments.clone();
    assert!(bind_services(&services, &controller.control_obligations()).is_err());
    controller.services.endpoint.shutdown().await.unwrap();
    other.services.endpoint.shutdown().await.unwrap();
}
