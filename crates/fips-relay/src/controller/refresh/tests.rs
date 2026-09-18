mod coalescing;

use super::*;
use crate::ledger::{BillingBasis, Limits};
use crate::route_quotes::QuotePolicy;
use cashu_service::FileSpilmanPaymentReceiverConfig;
use fips_core::Config;
use fips_core::config::{TransportInstances, UdpConfig};

pub(in crate::controller) async fn disconnected_controller(root: &Path) -> Controller {
    disconnected_controller_with_policy(root, super::super::tests::unresolved_journal().policy)
        .await
}

pub(in crate::controller) async fn disconnected_controller_with_policy(
    root: &Path,
    policy: ControllerPolicy,
) -> Controller {
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
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    let seller =
        Arc::new(DurableRelay::create(&root.join("seller"), Limits::default(), 1000).unwrap());
    let buyer = Arc::new(
        BuyerAuthorizer::create(
            &root.join("buyer"),
            *endpoint.node_addr(),
            64,
            Limits::default(),
        )
        .unwrap(),
    );
    let receiver = FileSpilmanPaymentReceiver::load(
        &root.join("receiver"),
        FileSpilmanPaymentReceiverConfig::new([policy.mint_url.clone()]),
    )
    .unwrap();
    let (transport, _) = ControlTransport::start(endpoint.clone(), 44_741, vec![], 1)
        .await
        .unwrap();
    let quotes = Arc::new(
        RouteQuotes::new(
            endpoint.clone(),
            Arc::new(transport),
            QuotePolicy {
                destination_fees: Default::default(),
                billing: BillingBasis::ForwardingData,
                mint_url: policy.mint_url.clone(),
                receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
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
    let (acceptance, _) = ControlTransport::start(endpoint.clone(), 44_742, vec![], 2)
        .await
        .unwrap();
    let (payments, _) = ControlTransport::start(endpoint.clone(), 44_743, vec![], 3)
        .await
        .unwrap();
    Controller::create(
        &root.join("controller"),
        policy,
        ControllerServices {
            endpoint,
            quotes,
            acceptance: Arc::new(acceptance),
            payments: Arc::new(payments),
            payment_control: Arc::new(
                PaymentControl::new(receiver, seller.clone(), vec![]).unwrap(),
            ),
            seller,
            buyer,
            wallet_directory: root.join("wallet"),
        },
    )
    .unwrap()
}

#[tokio::test]
async fn disconnected_offer_does_not_pin_a_watch_before_purchase_reservation() {
    assert_disconnected_watch(false).await;
}

#[tokio::test]
async fn disconnected_restored_pending_offer_retains_its_exact_intent() {
    assert_disconnected_watch(true).await;
}

async fn assert_disconnected_watch(restored: bool) {
    let root = tempfile::tempdir().unwrap();
    let controller = disconnected_controller(root.path()).await;
    let (_, mut old) = super::super::transition_tests::fixture(&root.path().join("fixture"));
    old.offer.buyer = *controller.services.endpoint.node_addr();
    old.offer.billing = BillingBasis::ForwardingData;
    let offer = old.offer;
    let id = offer.destination.npub();
    let watch = WatchedRoute {
        billing: offer.billing,
        destination: id.clone(),
        max_rate_msat_per_kib: 8192,
        paused: false,
        pending: restored.then(|| offer.clone()),
    };
    let key = id.clone();
    controller
        .change(move |j| {
            j.watched_routes.insert(key, watch);
            Ok(())
        })
        .await
        .unwrap();
    let before = serde_json::to_value(controller.snapshot().await.unwrap()).unwrap();
    let saved = std::fs::read(root.path().join("controller/controller.json")).unwrap();
    let result = controller.accept_watched_offer(&id, offer).await;
    assert_eq!(
        result.unwrap_err(),
        "provider is not a connected native neighbor"
    );
    let after = controller.snapshot().await.unwrap();
    assert_eq!(
        after.watched_routes[&id].pending.is_some(),
        restored,
        "only previously reserved work should remain pending after neighbor rejection"
    );
    assert_eq!(serde_json::to_value(after).unwrap(), before);
    assert_eq!(
        std::fs::read(root.path().join("controller/controller.json")).unwrap(),
        saved
    );
    assert!(
        !root.path().join("wallet").exists(),
        "no wallet operation ran"
    );
    let policy = controller.policy.clone();
    let services = controller.services.clone();
    drop(controller);
    let reloaded = Controller::load(&root.path().join("controller"), policy, services).unwrap();
    assert_eq!(
        serde_json::to_value(reloaded.snapshot().await.unwrap()).unwrap(),
        before
    );
    reloaded.services.endpoint.shutdown().await.unwrap();
}

fn reservation_offer(old: &Outgoing, replacement: bool) -> RouteOffer {
    let mut offer = old.offer.clone();
    offer.id = "watched-reservation".into();
    if replacement {
        offer.price.msat += 1;
    } else {
        offer.destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
        offer.next_hop = *offer.destination.node_addr();
        offer.path = vec![offer.provider, offer.next_hop];
    }
    // Match the public identity retained by the offer's wire/journal encoding.
    offer.destination = PeerIdentity::from_npub(&offer.destination.npub()).unwrap();
    offer
}

fn reserve(
    j: &mut Journal,
    old: &Outgoing,
    offer: &RouteOffer,
    replacement: bool,
) -> Result<(), String> {
    if replacement {
        let mut change = super::super::transition_tests::change(old);
        change.offer = offer.clone();
        Controller::reserve_route_change(j, change)
    } else {
        Controller::reserve_purchase(j, offer.clone()).map(|_| ())
    }
}

fn authorized_watch(offer: &RouteOffer) -> WatchedRoute {
    WatchedRoute {
        billing: offer.billing,
        destination: offer.destination.npub(),
        max_rate_msat_per_kib: 8192,
        paused: false,
        pending: None,
    }
}

#[test]
fn watched_intent_is_atomic_with_initial_and_replacement_reservations() {
    for replacement in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old) =
            super::super::transition_tests::fixture(&root.path().join("controller"));
        let offer = reservation_offer(&old, replacement);
        let watch = authorized_watch(&offer);
        store
            .change(|j| {
                j.watched_routes
                    .insert(watch.destination.clone(), watch.clone());
                Ok(())
            })
            .unwrap();
        let funding = serde_json::to_value(&store.journal.funding).unwrap();
        store
            .change(|j| {
                reserve(j, &old, &offer, replacement)?;
                Controller::reserve_watched_offer(j, Some(&watch), &offer)
            })
            .unwrap();
        let mut store = super::super::transition_tests::reload(store);
        assert_eq!(
            store.journal.watched_routes[&watch.destination].pending,
            Some(offer.clone())
        );
        assert_eq!(
            serde_json::to_value(&store.journal.funding).unwrap(),
            funding
        );
        assert_eq!(
            store.journal.outgoing[&old.purchase.contract.id].retired,
            old.retired
        );
        if replacement {
            assert_eq!(store.journal.route_changes[&offer.id].offer, offer);
        } else {
            assert_eq!(store.journal.requested[&offer.id], offer);
        }
        // A prepared replacement reaches the next reservation with the same
        // captured watch. Binding its exact intent remains idempotent.
        store
            .change(|j| Controller::reserve_watched_offer(j, Some(&watch), &offer))
            .unwrap();
        super::super::transition_tests::reload(store);
    }
}

#[test]
fn changed_watch_rejects_stale_reservations_without_partial_writes() {
    for replacement in [false, true] {
        for change in [
            "paused", "ceiling", "billing", "pending", "missing", "cleared",
        ] {
            let root = tempfile::tempdir().unwrap();
            let (mut store, old) =
                super::super::transition_tests::fixture(&root.path().join("controller"));
            let offer = reservation_offer(&old, replacement);
            let mut expected = authorized_watch(&offer);
            if change == "cleared" {
                expected.pending = Some(offer.clone());
            }
            store
                .change(|j| {
                    let mut current = expected.clone();
                    match change {
                        "paused" => current.paused = true,
                        "ceiling" => current.max_rate_msat_per_kib -= 1,
                        "billing" => current.billing = BillingBasis::ForwardingData,
                        "pending" => {
                            let mut competing = offer.clone();
                            competing.id = "competing-pending".into();
                            current.pending = Some(competing);
                        }
                        "cleared" => current.pending = None,
                        "missing" => return Ok(()),
                        _ => unreachable!(),
                    }
                    j.watched_routes
                        .insert(current.destination.clone(), current);
                    Ok(())
                })
                .unwrap();
            let before = serde_json::to_value(&store.journal).unwrap();
            let saved = std::fs::read(store.directory.join("controller.json")).unwrap();
            assert!(
                store
                    .change(|j| {
                        reserve(j, &old, &offer, replacement)?;
                        Controller::reserve_watched_offer(j, Some(&expected), &offer)
                    })
                    .is_err(),
                "{change}, replacement={replacement}"
            );
            assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
            assert_eq!(
                std::fs::read(store.directory.join("controller.json")).unwrap(),
                saved
            );
            super::super::transition_tests::reload(store);
        }
    }
}
