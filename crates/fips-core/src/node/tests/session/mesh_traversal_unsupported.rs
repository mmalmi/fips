//! A routed, authenticated peer may support application traffic without NAT discovery.
use super::*;
use crate::SessionMessageType;
use crate::config::{NostrDiscoveryConfig, NostrPeerfindingSource, PeerConfig};
use crate::discovery::nostr::{
    BootstrapEvent, MeshTraversalSignal, NostrDiscovery, TraversalAnswer, TraversalOffer,
};
use crate::node::tests::spanning_tree::process_node_packets;
use futures::FutureExt;
use std::{collections::BTreeMap, panic::AssertUnwindSafe, sync::Arc};

fn authorize(node: &mut Node, peer: PeerIdentity) -> PeerConfig {
    let mut config = PeerConfig::new(peer.npub(), "udp", "nat");
    config.auto_reconnect = false;
    node.config.peers.push(config.clone());
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    config
}

fn identities(nodes: &[TestNode]) -> Vec<PeerIdentity> {
    nodes
        .iter()
        .map(|n| PeerIdentity::from_pubkey_full(n.node.identity().pubkey_full()))
        .collect()
}

fn offer(peers: &[PeerIdentity]) -> TraversalOffer {
    let now = Node::now_ms();
    TraversalOffer {
        message_type: "offer".into(),
        session_id: "unsupported-session".into(),
        issued_at: now,
        expires_at: now + 120_000,
        nonce: "unsupported-nonce".into(),
        sender_npub: peers[0].npub(),
        recipient_npub: peers[2].npub(),
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
    }
}

async fn send_offer(nodes: &mut [TestNode], destination: PeerIdentity, body: &[u8]) {
    nodes[0]
        .node
        .send_session_msg(
            destination.node_addr(),
            SessionMessageType::TraversalOffer.to_byte(),
            body,
        )
        .await
        .unwrap();
}

async fn answers_for(nodes: &mut [TestNode], duration: Duration) -> Vec<TraversalAnswer> {
    let deadline = tokio::time::Instant::now() + duration;
    let mut answers = Vec::new();
    while tokio::time::Instant::now() < deadline {
        for node in &mut nodes[1..] {
            process_node_packets(&mut node.node, &mut node.packet_rx).await;
        }
        let mut turn = super::mesh_signal_replay::native_turn(&mut nodes[0]).await;
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty(), "reply must authenticate");
        let (_, _, sessions) = turn.take_fsp_authenticated_ingress().into_parts();
        for ingress in sessions {
            let (source, peer, _, _, _, _, kind, _, plaintext) = ingress.into_parts();
            if kind == SessionMessageType::TraversalAnswer.to_byte() {
                assert_eq!(source, *nodes[2].node.node_addr());
                assert_eq!(source, *peer.node_addr());
                let (_, parsed_kind, _, body) =
                    crate::node::session_wire::fsp_strip_inner_header(plaintext.as_slice())
                        .unwrap();
                assert_eq!(parsed_kind, kind);
                assert!(body.len() <= 1024, "bounded rejection body");
                answers.push(serde_json::from_slice(body).unwrap());
            }
        }
        nodes[0]
            .node
            .process_dataplane_control_ingress(&mut turn)
            .await;
        nodes[0].node.drain_deferred_dataplane_control_turns().await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    answers
}

#[test]
fn unsupported_mesh_offer_rejects_only_authorized_valid_encrypted_requests() {
    run_large_stack_async_test("unsupported-mesh-validation", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        let result = AssertUnwindSafe(async {
            populate_all_coord_caches(&mut nodes);
            let peers = identities(&nodes);
            let mut sender = nodes[0].node.attach_endpoint_data_io(8).unwrap();
            let mut receiver = nodes[2].node.attach_endpoint_data_io(8).unwrap();
            send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[2], b"warm".to_vec())
                .await
                .unwrap();
            let event = recv_endpoint_event_while_draining(
                &mut nodes,
                &mut receiver.event_rx,
                Duration::from_secs(5),
                "warm routed session",
            )
            .await;
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                b"warm"
            );
            drain_to_quiescence(&mut nodes).await;
            assert!(nodes[2].node.nostr_discovery.is_none());
            assert!(!nodes[2].node.peers.contains_key(peers[0].node_addr()));
            let valid = offer(&peers);
            send_offer(&mut nodes, peers[2], &serde_json::to_vec(&valid).unwrap()).await;
            assert!(
                answers_for(&mut nodes, Duration::from_millis(150))
                    .await
                    .is_empty(),
                "a routed session alone does not authorize traversal"
            );
            authorize(&mut nodes[2].node, peers[0]);

            let mut invalid = vec![b"{malformed".to_vec()];
            for change in 0..9 {
                let mut bad = valid.clone();
                match change {
                    0 => bad.message_type = "answer".into(),
                    1 => bad.sender_npub = peers[1].npub(),
                    2 => bad.recipient_npub = peers[1].npub(),
                    3 => {
                        bad.issued_at -= 300_000;
                        bad.expires_at -= 300_000;
                    }
                    4 => {
                        bad.issued_at += 120_000;
                        bad.expires_at += 120_000;
                    }
                    5 => bad.session_id.clear(),
                    6 => bad.nonce.clear(),
                    7 => bad.session_id = "s".repeat(129),
                    8 => bad.nonce = "n".repeat(129),
                    _ => unreachable!(),
                }
                invalid.push(serde_json::to_vec(&bad).unwrap());
            }
            for body in invalid {
                send_offer(&mut nodes, peers[2], &body).await;
                assert!(
                    answers_for(&mut nodes, Duration::from_millis(50))
                        .await
                        .is_empty(),
                    "invalid offer must stay silent"
                );
            }
            for _ in 0..2 {
                send_offer(&mut nodes, peers[2], &serde_json::to_vec(&valid).unwrap()).await;
                let replies = answers_for(&mut nodes, Duration::from_millis(200)).await;
                assert_eq!(
                    replies.len(),
                    1,
                    "one authenticated rejection, including after lost-answer offer retry"
                );
                let answer = &replies[0];
                assert!(!answer.accepted);
                assert_eq!(answer.reason.as_deref(), Some("traversal-unsupported"));
                assert_eq!(answer.session_id, valid.session_id);
                assert_eq!(answer.in_reply_to, valid.nonce);
                assert_eq!(answer.sender_npub, peers[2].npub());
                assert_eq!(answer.recipient_npub, peers[0].npub());
                assert!(answer.reflexive_address.is_none() && answer.local_addresses.is_empty());
                assert!(answer.stun_server.is_none() && answer.punch.is_none());
            }
            send_endpoint_data_via_dataplane(
                &mut nodes[2].node,
                peers[0],
                b"still-delivers".to_vec(),
            )
            .await
            .unwrap();
            let event = recv_endpoint_event_while_draining(
                &mut nodes,
                &mut sender.event_rx,
                Duration::from_secs(5),
                "application reply after rejection",
            )
            .await;
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                b"still-delivers"
            );
            assert!(nodes[2].node.nostr_discovery.is_none());
        })
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[test]
fn unsupported_mesh_default_attempts_stop_repeating_and_reach_existing_cooldown() {
    run_large_stack_async_test("unsupported-mesh-cooldown", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        let peers = identities(&nodes);
        let config = NostrDiscoveryConfig {
            enabled: true,
            advertise: false,
            stun_servers: Vec::new(),
            advert_relays: Vec::new(),
            share_local_candidates: false,
            peerfinding_source: NostrPeerfindingSource::External,
            ..Default::default()
        };
        assert_eq!(
            (
                config.attempt_timeout_secs,
                config.failure_streak_threshold,
                config.extended_cooldown_secs
            ),
            (10, 5, 1800)
        );
        let discovery = Arc::new(NostrDiscovery::new_for_test_with_identity_and_config(
            nodes[0].node.identity(),
            config.clone(),
        ));
        let result = AssertUnwindSafe(async {
            populate_all_coord_caches(&mut nodes);
            let mut sender = nodes[0].node.attach_endpoint_data_io(8).unwrap();
            let mut receiver = nodes[2].node.attach_endpoint_data_io(8).unwrap();
            let peer_config = authorize(&mut nodes[0].node, peers[2]);
            authorize(&mut nodes[2].node, peers[0]);
            // Seed retry state through the ordinary cold-start failure path,
            // before a routed application session exists. A manual request
            // made only after warming does not create that startup state.
            let error = nodes[0].node.initiate_peer_connection(&peer_config).await
                .expect_err("discovery has not started yet");
            nodes[0].node.schedule_retry_after_error(*peers[2].node_addr(), Node::now_ms(), &error);
            assert!(nodes[0].node.retry_pending.contains_key(peers[2].node_addr()));
            send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[2], b"before-attempts".to_vec()).await.unwrap();
            let _ = recv_endpoint_event_while_draining(&mut nodes, &mut receiver.event_rx, Duration::from_secs(5), "routed application before attempts").await;
            drain_to_quiescence(&mut nodes).await;
            let links: Vec<_> = nodes.iter().map(|n| n.node.links.len()).collect();
            nodes[0].node.config.node.discovery.nostr = config;
            nodes[0].node.nostr_discovery = Some(discovery.clone());
            assert!(nodes[0].node.request_nostr_bootstrap(&peer_config).await);
            let start = tokio::time::Instant::now();
            let mut offers = BTreeMap::<String, usize>::new();
            let mut failures = 0;
            let mut unsupported = 0;
            while failures < 5 && start.elapsed() < Duration::from_secs(80) {
                for signal in discovery.drain_mesh_signals().await {
                    if let MeshTraversalSignal::Offer { offer, .. } = &signal {
                        *offers.entry(offer.session_id.clone()).or_default() += 1;
                    }
                    nodes[0].node.send_nostr_mesh_signal(signal).await;
                }
                process_available_packets(&mut nodes).await;
                for event in discovery.drain_events().await {
                    if let BootstrapEvent::Failed { reason, .. } = &event {
                        failures += 1;
                        unsupported += usize::from(reason.contains("traversal-unsupported"));
                    } else { panic!("unsupported receiver cannot establish traversal"); }
                    discovery.push_event_for_test(event);
                }
                // Run the actual failure and retry handlers; neither policy nor clock is changed.
                nodes[0].node.poll_nostr_discovery_event_turn(Duration::from_millis(20)).await;
                nodes[0].node.process_pending_retries(Node::now_ms()).await;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let submitted: usize = offers.values().sum();
            println!("unsupported_mesh_counts attempts={} offers={} retransmissions={} failures={} unsupported={} elapsed_ms={}", offers.len(), submitted, submitted.saturating_sub(offers.len()), failures, unsupported, start.elapsed().as_millis());
            assert_eq!(failures, 5);
            let state = discovery.failure_state_snapshot();
            let state = state.iter().find(|s| s.npub == peers[2].npub()).unwrap();
            assert_eq!(state.consecutive_failures, 5);
            let now = Node::now_ms();
            let until = state.cooldown_until_ms.expect("ordinary five-failure cooldown");
            assert!((1_799_000..=1_800_000).contains(&until.saturating_sub(now)));
            assert!(nodes[0].node.retry_pending.get(peers[2].node_addr()).unwrap().retry_after_ms >= until);
            assert!(!nodes[0].node.request_nostr_bootstrap(&peer_config).await);
            assert!(discovery.drain_mesh_signals().await.is_empty());
            send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[2], b"after-cooldown".to_vec()).await.unwrap();
            let event = recv_endpoint_event_while_draining(&mut nodes, &mut receiver.event_rx, Duration::from_secs(5), "application during traversal cooldown").await;
            assert_eq!(expect_single_endpoint_data_event(event).payload.as_slice(), b"after-cooldown");
            send_endpoint_data_via_dataplane(&mut nodes[2].node, peers[0], b"reply-during-cooldown".to_vec()).await.unwrap();
            let event = recv_endpoint_event_while_draining(&mut nodes, &mut sender.event_rx, Duration::from_secs(5), "application reply during traversal cooldown").await;
            assert_eq!(expect_single_endpoint_data_event(event).payload.as_slice(), b"reply-during-cooldown");
            assert_eq!(links, nodes.iter().map(|n| n.node.links.len()).collect::<Vec<_>>());
            assert_eq!(offers.len(), 5);
            assert_eq!(submitted, 5, "one offer per rejected attempt, no one-second retransmissions");
            assert_eq!(unsupported, 5);
        }).catch_unwind().await;
        discovery.shutdown().await.unwrap();
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}
