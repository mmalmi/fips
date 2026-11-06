//! Opt-in process fixture. The caller executes a previously qualified test
//! binary, supplies one ephemeral JS public identity, and owns the JS peer.
//! This tests routed FSP with a UDP adapter, not browser transport behavior.
use super::*;
use crate::config::{NostrDiscoveryConfig, NostrPeerfindingSource, PeerConfig};
use crate::discovery::nostr::{BootstrapEvent, MeshTraversalSignal, NostrDiscovery};
use crate::node::tests::spanning_tree::{initiate_handshake, make_test_node};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Write,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    schema: u8,
    target_npub: String,
    ready_path: PathBuf,
    result_path: PathBuf,
    stop_path: PathBuf,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Outcome {
    schema: u8,
    passed: u8,
    cleanup_closed: u8,
    error_code: u8,
    attempts: usize,
    offers: usize,
    retransmissions: usize,
    matching_rejections: usize,
    failures: usize,
    cooldown_ms_remaining: u64,
    application_deliveries: usize,
    application_replies_sent: usize,
}

fn publish(path: &Path, value: &impl Serialize) {
    let pending = pending_path(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .unwrap();
    serde_json::to_writer(&mut file, value).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
    // Linking a complete private file provides atomic, no-replacement publication.
    std::fs::hard_link(&pending, path).unwrap();
    std::fs::remove_file(pending).unwrap();
}

fn pending_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".pending");
    path.with_file_name(name)
}

fn input() -> Input {
    let path = PathBuf::from(
        std::env::var_os("FIPS_TRAVERSAL_INTEROP_CONFIG").expect("explicit test config required"),
    );
    assert!(path.is_absolute() && std::fs::metadata(&path).unwrap().len() <= 4096);
    let config: Input = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(config.schema, 1);
    assert!(config.target_npub.starts_with("npub1") && config.target_npub.len() == 63);
    let outputs = [&config.ready_path, &config.result_path, &config.stop_path];
    for output in outputs {
        assert!(output.is_absolute() && output.parent() == path.parent() && !output.exists());
        assert_ne!(output, &path);
    }
    assert_ne!(config.ready_path, config.result_path);
    assert_ne!(config.ready_path, config.stop_path);
    assert_ne!(config.result_path, config.stop_path);
    for destination in [&config.ready_path, &config.result_path] {
        let pending = pending_path(destination);
        assert!(!pending.exists() && pending != path);
        assert!(!outputs.contains(&&pending));
    }
    config
}

#[test]
#[ignore = "explicit private config and external JS process required; never launches Cargo"]
fn native_js_unsupported_process() {
    let config = input();
    run_large_stack_async_test("native-js-unsupported", move || async move {
        let mut nodes = Vec::new();
        let mut outcome = Outcome {
            schema: 1,
            ..Default::default()
        };
        let execution = AssertUnwindSafe(async {
            tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(120), exercise(&config, &mut nodes, &mut outcome)) => {
                    if result.is_err() { return 2; }
                    0
                }
                () = async {
                    while !config.stop_path.exists() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                } => 3,
            }
        }).catch_unwind().await;
        outcome.error_code = execution.unwrap_or(1);
        let cleanup = AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(10), async {
            let mut closed = true;
            for node in &mut nodes {
                if let Some(discovery) = node.node.nostr_discovery.take() {
                    closed &= discovery.shutdown().await.is_ok();
                }
                node.node.drain_deferred_session_forwards().await;
                for transport in node.node.transports.values_mut() {
                    closed &= transport.stop().await.is_ok();
                }
            }
            closed
        }))
        .catch_unwind()
        .await;
        outcome.cleanup_closed = u8::from(matches!(cleanup, Ok(Ok(true))));
        outcome.passed = u8::from(outcome.error_code == 0 && outcome.cleanup_closed == 1);
        publish(&config.result_path, &outcome);
        assert_eq!(
            outcome.passed, 1,
            "mixed fixture failed; inspect numeric private result"
        );
    });
}

async fn exercise(config: &Input, nodes: &mut Vec<TestNode>, outcome: &mut Outcome) {
    let target = PeerIdentity::from_npub(&config.target_npub).unwrap();
    nodes.push(make_test_node().await);
    nodes.push(make_test_node().await);
    initiate_handshake(nodes, 0, 1).await;
    let ready_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        poll_available_packets(nodes).await;
        if nodes.iter().all(|n| n.node.peer_count() == 1)
            && nodes[0].node.tree_state().my_coords().root_id()
                == nodes[1].node.tree_state().my_coords().root_id()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < ready_deadline,
            "native relay startup deadline"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    populate_all_coord_caches(nodes);
    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut peer_config = PeerConfig::new(target.npub(), "udp", "nat");
    peer_config.auto_reconnect = false;
    nodes[0].node.config.peers.push(peer_config.clone());
    nodes[0].node.configured_peers =
        crate::node::ConfiguredPeerLookup::from_config(&nodes[0].node.config);
    let error = nodes[0]
        .node
        .initiate_peer_connection(&peer_config)
        .await
        .expect_err("no discovery during cold setup");
    nodes[0]
        .node
        .schedule_retry_after_error(*target.node_addr(), Node::now_ms(), &error);
    assert!(nodes[0].node.retry_pending.contains_key(target.node_addr()));
    let mut application = nodes[0].node.attach_endpoint_data_io(16).unwrap();
    let relay_address = nodes[1]
        .addr
        .as_str()
        .unwrap()
        .parse::<std::net::SocketAddr>()
        .unwrap();
    assert!(relay_address.ip().is_loopback());
    publish(
        &config.ready_path,
        &serde_json::json!({
            "schema": 1, "senderNpub": nodes[0].node.npub(), "relayNpub": nodes[1].node.npub(),
            "relayAddress": relay_address.to_string(),
        }),
    );

    let discovery_config = NostrDiscoveryConfig {
        enabled: true,
        advertise: false,
        stun_servers: Vec::new(),
        advert_relays: Vec::new(),
        share_local_candidates: false,
        peerfinding_source: NostrPeerfindingSource::External,
        ..Default::default()
    };
    let discovery = Arc::new(NostrDiscovery::new_for_test_with_identity_and_config(
        nodes[0].node.identity(),
        discovery_config.clone(),
    ));
    // Install only after setup: no relay client, STUN query, or candidate data.
    nodes[0].node.config.node.discovery.nostr = discovery_config;
    nodes[0].node.nostr_discovery = Some(discovery.clone());
    let mut stage = 0;
    let mut offers = BTreeMap::<String, usize>::new();
    let app_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        poll_available_packets(nodes).await;
        while let Ok(event) = application.event_rx.try_recv() {
            application.event_rx.release_messages(event.messages.len());
            for message in event.messages {
                assert_eq!(message.source_peer, target, "application source binding");
                let payload = message.payload.as_slice();
                match stage {
                    0 => {
                        assert_eq!(payload, b"traversal-interop-warm");
                        send_endpoint_data_via_dataplane(
                            &mut nodes[0].node,
                            target,
                            b"traversal-interop-warm-ack".to_vec(),
                        )
                        .await
                        .unwrap();
                        outcome.application_replies_sent += 1;
                        stage = 1;
                    }
                    1 => {
                        assert_eq!(payload, b"traversal-interop-go");
                        assert!(
                            !nodes[0].node.peers.contains_key(target.node_addr()),
                            "target stays routed"
                        );
                        assert!(nodes[0].node.request_nostr_bootstrap(&peer_config).await);
                        stage = 2;
                    }
                    3 => {
                        assert_eq!(payload, b"traversal-interop-finished-ack");
                        outcome.application_deliveries += 1;
                        assert_eq!(outcome.application_deliveries, 3);
                        assert_eq!(outcome.application_replies_sent, 2);
                        return;
                    }
                    _ => panic!("unexpected application marker stage"),
                }
                outcome.application_deliveries += 1;
            }
        }
        if stage < 2 {
            assert!(
                tokio::time::Instant::now() < app_deadline,
                "JS warm-up deadline"
            );
        }
        if stage == 2 {
            for signal in discovery.drain_mesh_signals().await {
                if let MeshTraversalSignal::Offer { offer, .. } = &signal {
                    *offers.entry(offer.session_id.clone()).or_default() += 1;
                    outcome.offers += 1;
                    outcome.attempts = offers.len();
                    outcome.retransmissions = outcome.offers - outcome.attempts;
                } else {
                    panic!("initiator fixture cannot emit answers");
                }
                nodes[0].node.send_nostr_mesh_signal(signal).await;
            }
            for event in discovery.drain_events().await {
                if let BootstrapEvent::Failed { reason, .. } = &event {
                    outcome.failures += 1;
                    // connect_peer emits this only after the real decrypted
                    // reply passes session/nonce/identity/freshness checks.
                    outcome.matching_rejections +=
                        usize::from(reason == "protocol error: traversal-unsupported");
                } else {
                    panic!("unsupported destination cannot establish traversal");
                }
                discovery.push_event_for_test(event);
            }
            nodes[0]
                .node
                .poll_nostr_discovery_event_turn(Duration::from_millis(20))
                .await;
            nodes[0].node.process_pending_retries(Node::now_ms()).await;
            if outcome.failures == 5 {
                assert_eq!(
                    (
                        outcome.attempts,
                        outcome.offers,
                        outcome.retransmissions,
                        outcome.matching_rejections
                    ),
                    (5, 5, 0, 5)
                );
                let state = discovery.failure_state_snapshot();
                let state = state.iter().find(|s| s.npub == target.npub()).unwrap();
                assert_eq!(state.consecutive_failures, 5);
                let until = state.cooldown_until_ms.unwrap();
                outcome.cooldown_ms_remaining = until.saturating_sub(Node::now_ms());
                assert!((1_799_000..=1_800_000).contains(&outcome.cooldown_ms_remaining));
                assert!(
                    nodes[0]
                        .node
                        .retry_pending
                        .get(target.node_addr())
                        .unwrap()
                        .retry_after_ms
                        >= until
                );
                assert!(!nodes[0].node.request_nostr_bootstrap(&peer_config).await);
                assert!(discovery.drain_mesh_signals().await.is_empty());
                send_endpoint_data_via_dataplane(
                    &mut nodes[0].node,
                    target,
                    b"traversal-interop-finished".to_vec(),
                )
                .await
                .unwrap();
                outcome.application_replies_sent += 1;
                stage = 3;
            }
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}
