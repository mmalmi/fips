//! One discovery retry for an outgoing attempt displaced by reciprocal admission.
use super::*;
use crate::config::SimTransportConfig;
use crate::node::wire::{Msg1Header, build_msg2};
use crate::transport::sim::SimTransport;
use crate::transport::{PacketRx, TransportHandle, packet_channel};
use crate::{SimNetwork, register_sim_network, unregister_sim_network};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    RetryOnce,
    DemandRetryOnce,
    MissingTarget,
    PreparationExpires,
    HandshakeExpires,
    RetryCannotMature,
    RetryCannotPace,
}

#[test]
fn transferred_outgoing_gets_one_discovery_retry_with_promotion_anchored_deadline() {
    run(Case::RetryOnce);
}

#[test]
fn interrupted_demand_retry_preserves_the_owed_exploration_turn() {
    run(Case::DemandRetryOnce);
}

#[test]
fn missing_interrupted_target_does_not_block_other_discovery() {
    run(Case::MissingTarget);
}

#[test]
fn retried_hostname_preparation_expires_at_earned_deadline() {
    run(Case::PreparationExpires);
}

#[test]
fn retried_noise_expires_at_earned_deadline_after_timeout_increase() {
    run(Case::HandshakeExpires);
}

#[test]
fn interrupted_retry_that_cannot_mature_yields_to_another_discovered_peer() {
    run(Case::RetryCannotMature);
}

#[test]
fn interrupted_retry_that_cannot_meet_replacement_interval_yields_to_another_peer() {
    run(Case::RetryCannotPace);
}

fn run(case: Case) {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-interrupted-retry",
        move || async move {
            let _guard = super::super::super::super::spanning_tree::lock_large_network_test().await;
            let mut node = make_test_node().await;
            let result = AssertUnwindSafe(exercise(&mut node, case))
                .catch_unwind()
                .await;
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        },
    );
}

async fn exercise(node: &mut TestNode, case: Case) {
    let old = make_node();
    let first = make_node();
    let second = make_node();
    let mut target = make_node();
    let mut competitor = make_node();
    // Assign the required ordinary discovery order without changing policy or clocks.
    if (node.node.neighbor_rotation_order(*target.node_addr())
        > node.node.neighbor_rotation_order(*competitor.node_addr()))
        != (case == Case::DemandRetryOnce)
    {
        std::mem::swap(&mut target, &mut competitor);
    }
    let (_old_socket, old_source) = local_path().await;
    let (target_socket, target_source) = local_path().await;
    let (_first_socket, first_source) = local_path().await;
    let (_second_socket, second_source) = local_path().await;
    let mut old_owner = incumbent(node, &old, &old_source, 601, 0).await;
    enable(node, 1);
    node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: if case == Case::RetryCannotMature {
            2
        } else {
            1
        },
        interval_secs: if case == Case::RetryCannotPace { 2 } else { 1 },
    });
    node.node.config.node.rate_limit.handshake_timeout_secs = 6;
    node.node.config.node.rekey.enabled = false;
    tokio::time::sleep(Duration::from_millis(1_050)).await;

    if case == Case::DemandRetryOnce {
        crate::node::tests::session::send_endpoint_data_via_dataplane(
            &mut node.node,
            identity(&target),
            b"waiting for this discovered destination".to_vec(),
        )
        .await
        .unwrap();
        assert!(
            node.node
                .pending_session_traffic
                .has_traffic_for(target.node_addr())
        );
    }

    let wall_start = tokio::time::Instant::now();
    node.node
        .initiate_connection(node.transport_id, target_source.clone(), identity(&target))
        .await
        .unwrap();
    let original = receive_wire(&target_socket).await;
    let original_header = Msg1Header::parse(&original).expect("actual original Noise Msg1");
    let pending = node.node.peers.connection_values().next().unwrap();
    let original_link = pending.link_id();
    let original_index = pending.our_index().unwrap();
    let original_start = node
        .node
        .neighbor_rotation_started_at(target.node_addr())
        .unwrap();
    let original_cursor = node.node.neighbor_rotation_order(*competitor.node_addr());
    assert!(!original_cursor.0);
    assert_eq!(resources(node), (1, 1, 2, 2));
    // An actual valid reply is retained locally until after the old owner is gone.
    let mut responder = HandshakeState::new_responder(target.identity.keypair());
    responder.set_local_epoch(target.startup_epoch);
    responder
        .read_message_1(original_header.noise_msg1(&original))
        .unwrap();
    let stale_reply = build_msg2(
        SessionIndex::new(602),
        original_header.sender_idx,
        &responder.write_message_2().unwrap(),
    );

    let short_retry = matches!(case, Case::RetryCannotMature | Case::RetryCannotPace);
    let transfer_ms = if short_retry { 2_050 } else { 1_050 };
    tokio::time::sleep_until(wall_start + Duration::from_millis(transfer_ms)).await;
    let mut first_owner = connect(node, &first, &first_source, 603).await;
    assert_eq!(
        node.node.neighbor_rotation_started_at(first.node_addr()),
        Some(original_start)
    );
    assert!(node.node.get_connection(&original_link).is_none());
    assert!(!node.node.index_allocator.is_allocated(original_index));
    assert_eq!(resources(node), (1, 1, 2, 2));
    assert_eq!(
        node.node.get_peer(old.node_addr()).unwrap().link_id(),
        old_owner.link
    );
    assert_eq!(heartbeat(node, &old, &mut old_owner, 2).await, 2);
    if short_retry {
        // A late but valid proof earns a window from its actual promotion.
        tokio::time::sleep_until(wall_start + Duration::from_millis(4_500)).await;
    }
    if case == Case::PreparationExpires {
        // The grant must use the original duration, even if configuration
        // changed while the incoming replacement was still pending.
        node.node.config.node.rate_limit.handshake_timeout_secs = 60;
    }
    let promotion_before = Node::now_ms();
    let first_proof = promote(node, &first, &mut first_owner).await;
    let promotion_after = Node::now_ms();
    assert_eq!(
        node.node.neighbor_rotation_order(*competitor.node_addr()),
        original_cursor
    );

    tokio::time::sleep_until(wall_start + Duration::from_millis(2_150)).await;
    if case == Case::PreparationExpires {
        let port = target_socket.local_addr().unwrap().port();
        node.node
            .initiate_connection(
                node.transport_id,
                TransportAddr::from_string(&format!("localhost:{port}")),
                identity(&target),
            )
            .await
            .unwrap();
        assert_eq!(node.node.pending_connects.len(), 1);
        assert_eq!(node.node.connection_count(), 0);
        let earned_start = node
            .node
            .neighbor_rotation_started_at(target.node_addr())
            .unwrap();
        assert!((promotion_before..=promotion_after).contains(&earned_start));
        assert_eq!(
            node.node.neighbor_rotation_deadline(target.node_addr()),
            Some(earned_start + 6_000)
        );
        sleep_until_ms(earned_start + 6_100).await;
        node.node.poll_pending_connects().await;
        assert!(node.node.pending_connects.is_empty());
        assert_eq!(resources(node), (1, 0, 1, 1));
        assert_eq!(heartbeat(node, &first, &mut first_owner, 2).await, 2);
        assert!(
            target_socket.try_recv(&mut [0; 512]).is_err(),
            "expired preparation must not dispatch a fresh Noise request"
        );
        return;
    }

    if short_retry {
        // An unrelated incoming exchange near the earned deadline creates a
        // genuinely young incumbent. Its proof must not renew the old grant.
        sleep_until_ms(promotion_after + 3_500).await;
        let mut second_owner = connect(node, &second, &second_source, 605).await;
        sleep_until_ms(promotion_after + 4_500).await;
        promote(node, &second, &mut second_owner).await;
        // Both attempt cooldowns have elapsed, but the grant is still live.
        sleep_until_ms(promotion_after + 5_600).await;
        assert!(
            !node
                .node
                .neighbor_rotation_discovery_order(*target.node_addr(), Node::now_ms())
                .0
        );
    }
    let mut discovery = Discovery::new(node, &target, &competitor, case).await;
    node.node.poll_transport_discovery().await;
    let expected = if case == Case::MissingTarget || short_retry {
        &competitor
    } else {
        &target
    };
    let pending = node
        .node
        .peers
        .connection_values()
        .next()
        .expect("fresh discovery dial");
    assert_eq!(
        pending.expected_identity().unwrap().node_addr(),
        expected.node_addr(),
        "discovery must select an eligible candidate without blocking on an unusable preference"
    );
    assert_eq!(resources(node), (1, 1, 2, 2));
    if short_retry {
        let admitted = node
            .node
            .get_peer(second.node_addr())
            .unwrap()
            .authenticated_at();
        let policy = node.node.config.node.neighbor_rotation.as_ref().unwrap();
        let earliest_deadline = promotion_before + 6_000;
        let latest_deadline = promotion_after + 6_000;
        let age_ready = admitted + policy.idle_secs * 1000;
        let pacing_ready = admitted + policy.interval_secs * 1000;
        // Establish each premise across the entire promotion-time bracket.
        if case == Case::RetryCannotMature {
            assert!(age_ready >= latest_deadline);
            assert!(pacing_ready < earliest_deadline);
        } else {
            assert!(pacing_ready >= latest_deadline);
            assert!(age_ready < earliest_deadline);
        }
        assert!(Node::now_ms() < promotion_before + 6_000);
        assert!(
            node.node
                .neighbor_rotation_started_at(competitor.node_addr())
                .unwrap()
                > promotion_after,
            "the other peer gets its own ordinary attempt, not a renewed interrupted retry"
        );
        assert!(
            discovery.target_rx.try_recv().is_err(),
            "no unusable retry is sent"
        );
        return;
    }
    if case == Case::MissingTarget {
        return;
    }

    let retry_link = pending.link_id();
    let retry_index = pending.our_index().unwrap();
    let earned_start = node
        .node
        .neighbor_rotation_started_at(target.node_addr())
        .unwrap();
    assert_ne!(retry_link, original_link);
    assert!((promotion_before..=promotion_after).contains(&earned_start));
    assert_eq!(pending.last_activity(), earned_start);
    assert_eq!(
        node.node.neighbor_rotation_deadline(target.node_addr()),
        Some(earned_start + 6_000)
    );
    assert_eq!(
        node.node.neighbor_rotation_order(*competitor.node_addr()),
        original_cursor
    );
    let retry = tokio::time::timeout(Duration::from_secs(1), discovery.target_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let retry_header = Msg1Header::parse(retry.data.as_slice()).expect("actual fresh retry Msg1");
    assert_ne!(retry_header.sender_idx, original_header.sender_idx);
    assert_ne!(retry.data.as_slice(), original.as_slice());
    assert_eq!(
        pending.source_addr(),
        Some(&TransportAddr::from_string("target")),
        "retry uses the newly discovered carrier, never the incoming source address"
    );
    node.node
        .handle_msg2(packet(node, &target_source, stale_reply))
        .await;
    assert_eq!(
        node.node.get_connection(&retry_link).unwrap().our_index(),
        Some(retry_index)
    );
    assert!(node.node.get_peer(target.node_addr()).is_none());
    // Already-active proof is handed to the normal replay-checking owner;
    // recognizing that owner does not perform a second promotion.
    assert!(node.node.confirm_pending_handshake(first_proof).await);
    process_available_packets(std::slice::from_mut(node)).await;
    assert_eq!(
        node.node.neighbor_rotation_deadline(target.node_addr()),
        Some(earned_start + 6_000),
        "replayed successful proof cannot renew the already consumed grant"
    );

    tokio::time::sleep_until(wall_start + Duration::from_millis(3_250)).await;
    let _second_request = request(node, &second, &second_source, 604).await;
    let retained = node
        .node
        .get_connection(&retry_link)
        .expect("the one earned outgoing retry must survive another requester");
    assert_eq!(retained.our_index(), Some(retry_index));
    assert_eq!(retained.last_activity(), earned_start);
    assert_eq!(
        node.node.neighbor_rotation_deadline(target.node_addr()),
        Some(earned_start + 6_000)
    );
    assert_eq!(
        node.node.neighbor_rotation_order(*competitor.node_addr()),
        original_cursor
    );
    assert_eq!(resources(node), (1, 1, 2, 2));
    assert_eq!(heartbeat(node, &first, &mut first_owner, 2).await, 2);

    if matches!(case, Case::HandshakeExpires | Case::DemandRetryOnce) {
        if case == Case::HandshakeExpires {
            node.node.config.node.rate_limit.handshake_timeout_secs = 60;
        }
        sleep_until_ms(earned_start + 6_100).await;
        node.node.check_timeouts().await;
        assert_eq!(resources(node), (1, 0, 1, 1));
        assert!(!node.node.index_allocator.is_allocated(retry_index));
        assert!(node.node.pending_outbound.is_empty());
        assert_eq!(heartbeat(node, &first, &mut first_owner, 3).await, 3);
        if case == Case::DemandRetryOnce {
            assert!(
                node.node
                    .pending_session_traffic
                    .has_traffic_for(target.node_addr())
            );
            node.node.poll_transport_discovery().await;
            let next = node.node.peers.connection_values().next().unwrap();
            assert_eq!(
                next.expected_identity().unwrap().node_addr(),
                competitor.node_addr(),
                "an expired demand retry must give the next actual discovery turn to exploration"
            );
            assert_eq!(resources(node), (1, 1, 2, 2));
        } else {
            let mut next = connect(node, &second, &second_source, 605).await;
            promote(node, &second, &mut next).await;
        }
        return;
    }

    finish_retry(
        node,
        &mut discovery,
        &target,
        &retry,
        retry_link,
        retry_index,
    )
    .await;
    assert_eq!(resources(node), (1, 0, 1, 1));
    assert_eq!(
        node.node.get_peer(target.node_addr()).unwrap().link_id(),
        retry_link
    );
    assert_eq!(
        node.node.get_peer(target.node_addr()).unwrap().our_index(),
        Some(retry_index)
    );
    assert!(node.node.get_peer(second.node_addr()).is_none());
    assert!(
        node.node
            .neighbor_rotation_discovery_order(*target.node_addr(), Node::now_ms())
            .0
    );
    assert_eq!(
        node.node.neighbor_rotation_order(*competitor.node_addr()),
        original_cursor
    );
}

async fn finish_retry(
    node: &mut TestNode,
    discovery: &mut Discovery,
    target: &Node,
    request: &ReceivedPacket,
    link: LinkId,
    index: SessionIndex,
) {
    let header = Msg1Header::parse(request.data.as_slice()).unwrap();
    let mut responder = HandshakeState::new_responder(target.identity.keypair());
    responder.set_local_epoch(target.startup_epoch);
    responder
        .read_message_1(header.noise_msg1(request.data.as_slice()))
        .unwrap();
    let reply = build_msg2(
        SessionIndex::new(607),
        header.sender_idx,
        &responder.write_message_2().unwrap(),
    );
    let source = TransportAddr::from_string("source");
    discovery._target.send_async(&source, &reply).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(1), discovery._source_rx.recv())
        .await
        .unwrap()
        .unwrap();
    crate::node::tests::spanning_tree::process_dataplane_packet(node, reply).await;
    let ready = tokio::time::timeout(Duration::from_secs(1), discovery.target_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let header = crate::dataplane::FmpWireHeader::parse_encrypted(ready.data.as_slice()).unwrap();
    assert_eq!(header.receiver_idx(), 607);
    let offset = usize::from(header.ciphertext_offset());
    let mut session = responder.into_session().unwrap();
    session
        .decrypt_with_replay_check_and_aad(
            &ready.data.as_slice()[offset..],
            header.counter(),
            &ready.data.as_slice()[..offset],
        )
        .expect("target authenticates the retry's real readiness frame");
    let mut owner = Candidate {
        link,
        index,
        session,
        source: TransportAddr::from_string("target"),
    };
    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    let proof = owner.frame(TransportId::new(2), &heartbeat);
    discovery
        ._target
        .send_async(&source, proof.data.as_slice())
        .await
        .unwrap();
    let proof = tokio::time::timeout(Duration::from_secs(1), discovery._source_rx.recv())
        .await
        .unwrap()
        .unwrap();
    crate::node::tests::spanning_tree::process_dataplane_packet(node, proof).await;
    assert_eq!(await_heartbeat(node, target, 1).await, 1);
}

fn identity(node: &Node) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(node.identity.pubkey_full())
}

async fn receive_wire(socket: &tokio::net::UdpSocket) -> Vec<u8> {
    let mut wire = vec![0; 512];
    let length = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut wire))
        .await
        .unwrap()
        .unwrap();
    wire.truncate(length);
    wire
}

async fn sleep_until_ms(at_ms: u64) {
    tokio::time::sleep(Duration::from_millis(at_ms.saturating_sub(Node::now_ms()))).await;
}

async fn promote(node: &mut TestNode, remote: &Node, candidate: &mut Candidate) -> ReceivedPacket {
    let proof = candidate.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    assert!(node.node.confirm_pending_handshake(proof.clone()).await);
    assert_eq!(await_heartbeat(node, remote, 1).await, 1);
    assert_eq!(resources(node), (1, 0, 1, 1));
    proof
}

struct Discovery {
    name: String,
    _target: SimTransport,
    _competitor: SimTransport,
    _source_rx: PacketRx,
    target_rx: PacketRx,
    _competitor_rx: PacketRx,
}

impl Discovery {
    async fn new(node: &mut TestNode, target: &Node, competitor: &Node, case: Case) -> Self {
        let name = format!("rotation-retry-{}-{case:?}", std::process::id());
        let network = SimNetwork::new(191);
        register_sim_network(name.clone(), network.clone());
        let (source, source_rx) = sim(&name, "source", &node.node, true).await;
        let (target_transport, target_rx) = sim(&name, "target", target, false).await;
        let (competitor_transport, competitor_rx) =
            sim(&name, "competitor", competitor, false).await;
        if case == Case::MissingTarget {
            network.set_link_up("source", "target", false);
        }
        node.node
            .transports
            .insert(TransportId::new(2), TransportHandle::Sim(source));
        Self {
            name,
            _target: target_transport,
            _competitor: competitor_transport,
            _source_rx: source_rx,
            target_rx,
            _competitor_rx: competitor_rx,
        }
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        unregister_sim_network(&self.name);
    }
}

async fn sim(
    network: &str,
    address: &str,
    node: &Node,
    automatic: bool,
) -> (SimTransport, PacketRx) {
    let (tx, rx) = packet_channel(16);
    let mut transport = SimTransport::new(
        TransportId::new(2),
        None,
        SimTransportConfig {
            network: Some(network.to_owned()),
            addr: Some(address.to_owned()),
            auto_connect: Some(automatic),
            ..Default::default()
        },
        tx,
    );
    transport.set_local_pubkey(node.identity.pubkey());
    transport.start_async().await.unwrap();
    (transport, rx)
}
