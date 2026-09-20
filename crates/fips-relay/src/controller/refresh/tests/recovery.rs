//! A withdrawn offer must not pin an authorized native watch to a reusable quote.
use super::*;
use crate::route_quotes::QuoteRequest;

fn due(controller: &Controller, id: &str) {
    controller
        .refresh_checks
        .lock()
        .unwrap()
        .get_mut(id)
        .unwrap()
        .checked = tokio::time::Instant::now() - Duration::from_secs(REFRESH_SECONDS);
}

#[tokio::test]
async fn fenced_native_refresh_requotes_once_at_the_existing_deadline() {
    let root = tempfile::tempdir().unwrap();
    let provider_identity = Identity::generate();
    let controller = controller_with_neighbors(
        root.path(),
        crate::controller::tests::unresolved_journal().policy,
        vec![PeerIdentity::from_pubkey_full(
            provider_identity.pubkey_full(),
        )],
    )
    .await;
    let provider =
        coalescing::provider_with_identity(&controller.services.endpoint, provider_identity).await;
    let destination = coalescing::provider(&provider).await;
    let destination_peer = PeerIdentity::from_npub(destination.npub()).unwrap();
    let (fixture, old) = crate::controller::transition_tests::fixture(&root.path().join("fixture"));
    let (transport, mut incoming) = ControlTransport::start(
        provider.clone(),
        44_741,
        vec![PeerIdentity::from_npub(controller.services.endpoint.npub()).unwrap()],
        4,
    )
    .await
    .unwrap();
    let quotes = Arc::new(
        RouteQuotes::new(
            provider.clone(),
            Arc::new(transport),
            QuotePolicy {
                destination_fees: Default::default(),
                billing: BillingBasis::ForwardingData,
                mint_url: controller.policy.mint_url.clone(),
                receiver_pubkey_hex: old.offer.receiver_pubkey_hex.clone(),
                fee_msat_per_kib: 1024,
                max_rate_msat_per_kib: 8192,
                lifetime_secs: 300,
                max_units: 30_000,
                capacity_sat: 32,
                grace_msat: 8000,
            },
        )
        .unwrap(),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let served = quotes.clone();
    let server = tokio::spawn(async move {
        while let Some(request) = incoming.recv().await {
            let quote: QuoteRequest = serde_json::from_slice(&request.body).unwrap();
            observed.lock().unwrap().push(quote.reuse_unchanged);
            let response = served.handle(request.peer, &request.body).await;
            let _ = request.respond.send(serde_json::to_vec(&response).unwrap());
        }
    });
    let offer = controller
        .services
        .quotes
        .request_route(destination_peer)
        .await
        .unwrap();
    let mut journal = fixture.journal.clone();
    journal.local = *controller.services.endpoint.node_addr();
    journal.outgoing.clear();
    journal.requested = [(offer.id.clone(), offer.clone())].into();
    let funding = journal.funding.get_mut(&old.funding_id).unwrap();
    funding.provider = offer.provider;
    funding.funded.as_mut().unwrap().terms.buyer = journal.local;
    let mut watch = authorized_watch(&offer);
    watch.pending = Some(offer.clone());
    let id = watch.destination.clone();
    journal.watched_routes.insert(id.clone(), watch.clone());
    Controller::withdraw_watched_purchase(&mut journal, &watch).unwrap();
    Controller::validate_journal(&journal, &journal.policy, journal.local).unwrap();
    controller
        .change(move |j| {
            *j = journal;
            Ok(())
        })
        .await
        .unwrap();
    let before = controller.snapshot().await.unwrap();
    let funding = serde_json::to_value(&before.funding).unwrap();
    let capital = Controller::capital(&before).unwrap();
    // Existing fixture funding avoids mint work; stop only at the signer, after
    // the real refresh, quote, reservation and retained-channel selection paths.
    std::fs::write(root.path().join("wallet"), b"signer unavailable").unwrap();
    // Match native withdrawal's cache invalidation without changing the
    // provider's still-reusable offer.
    controller
        .services
        .quotes
        .invalidate_price(offer.provider, *destination_peer.node_addr());
    assert_eq!(
        controller.refresh_watched_routes().await.unwrap_err(),
        "route change paused"
    );
    assert_eq!(*requests.lock().unwrap(), vec![false, true]);
    assert_eq!(
        serde_json::to_value(controller.snapshot().await.unwrap()).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
    for _ in 0..3 {
        controller.refresh_watched_routes().await.unwrap();
    }
    assert_eq!(
        *requests.lock().unwrap(),
        vec![false, true],
        "no same-round fresh request or early retry"
    );
    let policy = controller.policy.clone();
    let services = controller.services.clone();
    drop(controller);
    let controller = Controller::load(&root.path().join("controller"), policy, services).unwrap();
    assert!(controller.refresh_checks.lock().unwrap().is_empty());
    assert_eq!(
        controller.refresh_watched_routes().await.unwrap_err(),
        "route change paused",
        "reload re-detects the durable fence without restoring transient retry state"
    );
    assert_eq!(*requests.lock().unwrap(), vec![false, true, true]);
    controller.refresh_watched_routes().await.unwrap();
    assert_eq!(*requests.lock().unwrap(), vec![false, true, true]);
    due(&controller, &id);
    assert!(
        controller.refresh_watched_routes().await.is_err(),
        "fixture signer stops acceptance"
    );
    assert_eq!(*requests.lock().unwrap(), vec![false, true, true, false]);
    let after = controller.snapshot().await.unwrap();
    let fresh = after.watched_routes[&id]
        .pending
        .as_ref()
        .expect("a fresh offer reached durable reservation");
    assert_ne!(
        fresh.id, offer.id,
        "the reusable fenced quote cannot keep the watch stuck"
    );
    assert_eq!(fresh.price, offer.price);
    assert_eq!(fresh.max_units, offer.max_units);
    assert!(!fresh.trial);
    assert!(after.recovery_only.contains(&offer.id));
    assert_eq!(after.requested[&offer.id], offer);
    assert_eq!(after.funding.len(), before.funding.len());
    assert_eq!(serde_json::to_value(&after.funding).unwrap(), funding);
    assert_eq!(Controller::capital(&after).unwrap(), capital);
    assert_eq!(
        after.watched_routes[&id].max_rate_msat_per_kib,
        watch.max_rate_msat_per_kib
    );
    assert!(
        controller.refresh_checks.lock().unwrap()[&id]
            .replace_fenced
            .is_none()
    );
    server.abort();
    let _ = server.await;
    destination.shutdown().await.unwrap();
    provider.shutdown().await.unwrap();
    controller.services.endpoint.shutdown().await.unwrap();
}

#[test]
fn replacement_rechecks_authority_and_does_not_reset_trial_selection() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old) =
        crate::controller::transition_tests::fixture(&root.path().join("fixture"));
    let offer = old.offer;
    let watch = authorized_watch(&offer);
    store
        .journal
        .watched_routes
        .insert(watch.destination.clone(), watch.clone());
    store.journal.recovery_only.insert(offer.id.clone());
    let before = serde_json::to_value(&store.journal).unwrap();
    assert!(Controller::replace_fenced_refresh(
        &store.journal,
        &watch,
        &offer,
        false,
        now().unwrap()
    ));
    for condition in [
        "selector", "trial", "free", "unfenced", "paused", "pending", "price", "changed",
        "retired", "expired", "terms",
    ] {
        let mut journal = store.journal.clone();
        let mut offered = offer.clone();
        let mut expected = watch.clone();
        let mut selection = false;
        match condition {
            "selector" => selection = true,
            "trial" => offered.trial = true,
            "free" => offered.price.msat = 0,
            "unfenced" => {
                journal.recovery_only.clear();
            }
            "paused" => {
                journal
                    .watched_routes
                    .get_mut(&watch.destination)
                    .unwrap()
                    .paused = true
            }
            "pending" => {
                journal
                    .watched_routes
                    .get_mut(&watch.destination)
                    .unwrap()
                    .pending = Some(offer.clone())
            }
            "price" => {
                expected.max_rate_msat_per_kib = 0;
                journal
                    .watched_routes
                    .insert(expected.destination.clone(), expected.clone());
            }
            "changed" => {
                let mut change = crate::controller::transition_tests::change(
                    store.journal.outgoing.values().next().unwrap(),
                );
                change.offer = offer.clone();
                change.paused = true;
                journal.route_changes.insert(offer.id.clone(), change);
            }
            "retired" => {
                let mut history = History::default();
                history.through_unix = offer.expires_unix;
                journal.history = Some(history);
            }
            "expired" => offered.expires_unix = 0,
            "terms" => offered.max_units += 1,
            _ => unreachable!(),
        }
        if matches!(condition, "trial" | "free" | "expired") {
            journal
                .requested
                .insert(offered.id.clone(), offered.clone());
        }
        assert!(
            !Controller::replace_fenced_refresh(
                &journal,
                &expected,
                &offered,
                selection,
                now().unwrap()
            ),
            "{condition}"
        );
    }
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
}
