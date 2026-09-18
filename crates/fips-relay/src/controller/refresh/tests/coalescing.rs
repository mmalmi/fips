//! Distinct source/transit quotes can name the same retained paid agreement.
use super::*;

async fn provider(endpoint: &Arc<FipsEndpoint>) -> Arc<FipsEndpoint> {
    let mut config = Config::new();
    config.node.control.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    config.peers.push(fips_core::config::PeerConfig::new(
        endpoint.npub(),
        "udp",
        endpoint.bound_udp_listen_addrs().await.unwrap()[0].to_string(),
    ));
    let peer = Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if endpoint
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.npub == peer.npub())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("real native provider adjacency");
    peer
}

async fn exercise(accepted: Option<bool>) {
    let root = tempfile::tempdir().unwrap();
    let controller = disconnected_controller(root.path()).await;
    let peer = provider(&controller.services.endpoint).await;
    let (fixture, mut old) =
        crate::controller::transition_tests::fixture(&root.path().join("fixture"));
    let mut journal = fixture.journal.clone();
    journal.local = *controller.services.endpoint.node_addr();
    old.offer.buyer = journal.local;
    old.offer.provider = *peer.node_addr();
    old.offer.path[0] = old.offer.provider;
    old.offer.billing = BillingBasis::ForwardingData;
    old.offer.trial = false;
    old.purchase.provider = old.offer.provider;
    old.purchase.channel.buyer = journal.local;
    old.purchase.contract = contract_from_offer(&old.offer, &old.purchase.channel).unwrap();
    old.accepted = accepted.unwrap_or(false);
    let funding = journal.funding.get_mut(&old.funding_id).unwrap();
    funding.provider = old.offer.provider;
    funding.funded.as_mut().unwrap().terms = old.purchase.channel.clone();
    journal.requested = [(old.offer.id.clone(), old.offer.clone())].into();
    journal.outgoing = accepted
        .map(|_| (old.purchase.contract.id.clone(), old.clone()))
        .into_iter()
        .collect();
    let watch = authorized_watch(&old.offer);
    let id = watch.destination.clone();
    journal.watched_routes.insert(id.clone(), watch);
    Controller::validate_journal(&journal, &journal.policy, journal.local).unwrap();
    controller
        .change(move |j| {
            *j = journal;
            Ok(())
        })
        .await
        .unwrap();
    let before = controller.funding_budget().await.unwrap();
    let funding = serde_json::to_value(controller.snapshot().await.unwrap().funding).unwrap();
    // No test tokens: the existing journal fixture bypasses wallet funding.
    // A file at the signer-directory path stops opening_payment after purchase
    // reservation, without dispatching an Accept or inventing a signed payment.
    std::fs::write(root.path().join("wallet"), b"signer unavailable").unwrap();
    let mut offered = old.offer.clone();
    offered.id = "new-source-quote-for-retained-service".into();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        controller.accept_watched_offer(&id, offered),
    )
    .await
    .expect("bounded coalesced purchase");
    let snapshot = controller.snapshot().await.unwrap();
    if accepted == Some(true) {
        let RouteAccess::Paid(purchase) =
            result.expect("coalesced accepted purchase must clear its actual watch binding")
        else {
            panic!("paid agreement expected");
        };
        assert_eq!(purchase, old.purchase);
        assert!(snapshot.watched_routes[&id].pending.is_none());
    } else {
        assert!(
            result.is_err(),
            "signer boundary must retain the unacknowledged purchase"
        );
        assert!(
            snapshot.outgoing.values().any(|o| o.offer == old.offer),
            "the production path must reach local purchase retention"
        );
        assert_eq!(
            snapshot.watched_routes[&id].pending,
            Some(old.offer.clone()),
            "the watch must bind the actual retained offer, not the equivalent incoming quote"
        );
        let pending = snapshot.watched_routes[&id].clone();
        assert!(
            controller
                .change(move |j| Controller::withdraw_watched_purchase(j, &pending))
                .await
                .unwrap()
        );
        assert!(
            controller
                .snapshot()
                .await
                .unwrap()
                .recovery_only
                .contains(&old.offer.id)
        );
    }
    assert_eq!(controller.funding_budget().await.unwrap(), before);
    assert_eq!(
        serde_json::to_value(controller.snapshot().await.unwrap().funding).unwrap(),
        funding
    );
    peer.shutdown().await.unwrap();
    controller.services.endpoint.shutdown().await.unwrap();
}

#[tokio::test]
async fn coalesced_requested_offer_binds_its_retained_identity() {
    exercise(None).await;
}

#[tokio::test]
async fn coalesced_unacknowledged_purchase_binds_its_retained_identity() {
    exercise(Some(false)).await;
}

#[tokio::test]
async fn coalesced_accepted_purchase_clears_its_retained_binding() {
    exercise(Some(true)).await;
}
