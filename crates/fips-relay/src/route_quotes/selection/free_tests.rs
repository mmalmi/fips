use super::{
    tests::{offer, working},
    *,
};
use fips_core::{
    Config,
    config::{PeerConfig, TransportInstances, UdpConfig},
    node::ForwardingRequest,
};

fn unknown_trial() -> (Destination, RouteOffer) {
    let selected = offer(2, 0);
    let mut active = selected.clone();
    active.id = "trial".into();
    active.trial = true;
    active.max_units = 4_096;
    active.expires_unix = 1;
    (
        Destination {
            active: Some(active),
            ..Default::default()
        },
        selected,
    )
}

#[test]
fn expired_unknown_free_trial_carries_only_exact_remaining_quota() {
    let (state, selected) = unknown_trial();
    let policy = PriceSelectionPolicy::default();
    for remaining in [None, Some(0)] {
        assert!(
            state
                .selection_step(&selected, &policy, true, |queried| {
                    assert_eq!(Some(queried), state.active.as_ref());
                    remaining
                })
                .is_err(),
            "missing or exhausted trial cannot receive a new allowance"
        );
    }
    for remaining in [1, 1_234, 4_096] {
        assert!(matches!(
            state
                .selection_step(&selected, &policy, true, |queried| {
                    assert_eq!(Some(queried), state.active.as_ref());
                    Some(remaining)
                })
                .unwrap(),
            SelectionStep::Request {
                max_units: Some(limit),
                reuse_unchanged: false,
            } if limit == remaining
        ));
    }
}

#[test]
fn unexpired_unknown_free_trial_is_retained_even_when_exhausted() {
    let (mut state, selected) = unknown_trial();
    state.active.as_mut().unwrap().expires_unix = unix_now().unwrap() + 60;
    let result = state
        .selection_step(&selected, &PriceSelectionPolicy::default(), true, |_| {
            panic!("a live unknown trial must not negotiate replacement quota")
        })
        .unwrap();
    let SelectionStep::Retain(retained) = result else {
        panic!("expected the unchanged trial");
    };
    assert_eq!(Some(retained.as_ref()), state.active.as_ref());
}

#[test]
fn measured_free_trial_promotion_requires_a_fresh_current_grant() {
    let (mut state, selected) = unknown_trial();
    let policy = PriceSelectionPolicy::default();
    let active = state.active.as_ref().unwrap().clone();
    state
        .observe(&working(&active, 0.0), &policy, Instant::now())
        .unwrap();
    assert!(matches!(
        state
            .selection_step(&selected, &policy, true, |_| None)
            .unwrap(),
        SelectionStep::Request {
            max_units: None,
            reuse_unchanged: false,
        }
    ));
    assert!(matches!(
        state
            .selection_step(&selected, &policy, true, |_| Some(100))
            .unwrap(),
        SelectionStep::Accept
    ));
}

#[test]
fn explicit_or_failed_provider_retry_retains_fresh_trial_policy() {
    let (mut state, selected) = unknown_trial();
    let policy = PriceSelectionPolicy::default();
    for explicit in [true, false] {
        if !explicit {
            state.failed.insert(selected.provider, Instant::now());
        }
        assert!(matches!(
            state.selection_step(&selected, &policy, !explicit, |_| None).unwrap(),
            SelectionStep::Request {
                max_units: Some(limit),
                reuse_unchanged: false,
            } if limit == policy.trial_max_units
        ));
    }
}

#[test]
fn paid_trial_expiry_and_promotion_keep_existing_selection_rules() {
    let (mut state, mut selected) = unknown_trial();
    selected.price.msat = 1_024;
    state.active.as_mut().unwrap().price = selected.price;
    let policy = PriceSelectionPolicy::default();
    assert!(matches!(
        state
            .selection_step(&selected, &policy, true, |_| panic!("paid quota"))
            .unwrap(),
        SelectionStep::Request {
            max_units: Some(4_096),
            reuse_unchanged: true,
        }
    ));
    let active = state.active.as_ref().unwrap().clone();
    state
        .observe(&working(&active, 0.0), &policy, Instant::now())
        .unwrap();
    assert!(matches!(
        state
            .selection_step(&selected, &policy, true, |_| panic!("paid quota"))
            .unwrap(),
        SelectionStep::Accept
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_quote_promotion_with_injected_quality_installs_current_free_grant() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut nodes = Vec::new();
        let mut addresses = Vec::new();
        for _ in 0..3 {
            let mut config = Config::new();
            config.node.control.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.local.enabled = false;
            config.transports.udp = TransportInstances::Single(UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                advertise_on_nostr: Some(false),
                ..Default::default()
            });
            let node = Arc::new(
                FipsEndpoint::builder()
                    .config(config)
                    .without_system_tun()
                    .bind()
                    .await
                    .unwrap(),
            );
            addresses.push(node.bound_udp_listen_addrs().await.unwrap()[0]);
            nodes.push(node);
        }
        let peers: Vec<_> = nodes
            .iter()
            .map(|node| PeerIdentity::from_npub(node.npub()).unwrap())
            .collect();
        for (i, node) in nodes.iter().enumerate() {
            node.update_peers(
                peers
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| i.abs_diff(*j) == 1)
                    .map(|(j, peer)| PeerConfig::new(peer.npub(), "udp", addresses[j].to_string()))
                    .collect(),
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut connected = 0;
                for node in &nodes {
                    connected += node
                        .peers()
                        .await
                        .unwrap()
                        .iter()
                        .filter(|p| p.connected)
                        .count();
                }
                if connected == 4 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let mut quotes = Vec::new();
        let mut servers = Vec::new();
        let mut statistics = Vec::new();
        for (i, node) in nodes.iter().take(2).enumerate() {
            let (control, incoming) = ControlTransport::start(
                node.clone(),
                44_731,
                peers
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| i.abs_diff(*j) == 1)
                    .map(|(_, peer)| *peer)
                    .collect(),
                80 + i as u64,
            )
            .await
            .unwrap();
            statistics.push(control.statistics());
            let mut service = RouteQuotes::new(
                node.clone(),
                Arc::new(control),
                QuotePolicy {
                    destination_fees: Default::default(),
                    billing: BillingBasis::ForwardingData,
                    mint_url: "http://test.invalid".into(),
                    receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
                    fee_msat_per_kib: 0,
                    max_rate_msat_per_kib: 0,
                    lifetime_secs: 120,
                    max_units: 65_536,
                    capacity_sat: 32,
                    grace_msat: 8_000,
                },
            )
            .unwrap();
            if i == 0 {
                service = service
                    .with_price_selection(PriceSelectionPolicy {
                        trial_max_units: 4_096,
                        ..Default::default()
                    })
                    .unwrap();
            }
            let service = Arc::new(service);
            servers.push(QuoteServer::start(service.clone(), incoming));
            quotes.push(service);
        }
        let source = &quotes[0];
        let provider = &quotes[1];
        let destination = peers[2];
        let trial = source.request_route(destination).await.unwrap();
        assert!(trial.trial);
        assert_eq!(trial.max_units, 4_096);
        source.activate_source_route(&trial).await.unwrap();
        let cached = source
            .client
            .request(
                peers[1],
                &QuoteRequest {
                    destination,
                    ancestors: vec![*peers[0].node_addr()],
                    deadline_unix: unix_now().unwrap() + QUOTE_SECONDS,
                    reuse_unchanged: true,
                    requested_max_units: None,
                },
            )
            .await
            .unwrap();
        assert!(!cached.trial);
        assert_ne!(cached.id, trial.id);
        assert_eq!(source.free.remaining_units(&cached), None);
        assert!(!provider.free.can_reuse_offer(&cached));
        assert!(provider.free.can_reuse_offer(&trial));
        assert_eq!(
            source
                .free
                .prepare_onward(trial.provider, *destination.node_addr(), 1_000),
            Some(true)
        );

        let payload = vec![0; 4_097];
        let packet = ForwardingRequest {
            ingress: peers[0],
            source: *peers[0].node_addr(),
            destination: *destination.node_addr(),
            next_hop: *destination.node_addr(),
            session_payload: &payload,
        };
        assert!(
            !provider.free.admit(&packet),
            "the old trial cannot admit this packet"
        );

        // Quotes cross real authenticated TCP/FIPS control. Delivery feedback is
        // injected here; data checks below exercise production quota admission.
        let selection = source.selection.as_ref().unwrap();
        let promoted = {
            let _work = selection.work.lock().await;
            source
                .select_with_quality(destination, selection, true, &working(&trial, 0.0))
                .await
                .unwrap()
        };
        assert_ne!(promoted.id, cached.id);
        assert_ne!(promoted.id, trial.id);
        assert!(!promoted.trial);
        assert_eq!(promoted.max_units, 65_536);
        assert!(provider.free.can_reuse_offer(&promoted));
        assert!(!provider.free.can_reuse_offer(&trial));
        assert_eq!(source.free.remaining_units(&trial), None);
        assert_eq!(source.free.remaining_units(&promoted), Some(65_536));
        assert_eq!(
            source
                .free
                .prepare_onward(promoted.provider, *destination.node_addr(), payload.len()),
            Some(true)
        );
        assert!(
            provider.free.admit(&packet),
            "both peers must use the fresh full grant"
        );
        source.activate_source_route(&promoted).await.unwrap();
        let requests = statistics[0].snapshot().requests_started;
        let repeated = {
            let _work = selection.work.lock().await;
            source
                .select_with_quality(destination, selection, true, &working(&promoted, 0.0))
                .await
                .unwrap()
        };
        assert_eq!(repeated, promoted);
        assert_eq!(source.free.remaining_units(&repeated), Some(65_536 - 4_097));
        assert_eq!(statistics[0].snapshot().requests_started, requests);
        for server in servers {
            server.stop().await;
        }
        drop(quotes);
        for node in nodes {
            node.shutdown().await.unwrap();
        }
    })
    .await
    .expect("bounded real quote promotion");
}
