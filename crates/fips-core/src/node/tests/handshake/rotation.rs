use super::*;
use crate::config::{NeighborRotationConfig, PeerConfig};

#[cfg(feature = "sim-transport")]
#[path = "candidates/rotation/rendezvous.rs"]
mod rendezvous;

#[path = "rotation_carrier.rs"]
mod rotation_carrier;

#[path = "rotation_success_carrier.rs"]
mod rotation_success_carrier;

#[path = "rotation_prepared.rs"]
mod rotation_prepared;

#[path = "rotation_starvation.rs"]
mod rotation_starvation;

#[path = "rotation_overlap.rs"]
mod rotation_overlap;

#[path = "rotation_transfer.rs"]
mod rotation_transfer;

fn enable(node: &mut TestNode, peers: usize) {
    node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 60,
    });
    node.node.max_peers = peers;
    node.node.max_connections = 1;
    node.node.max_links = peers + 1;
}

fn resources(node: &TestNode) -> (usize, usize, usize, usize) {
    (
        node.node.peer_count(),
        node.node.connection_count(),
        node.node.link_count(),
        node.node.index_allocator.count(),
    )
}

fn packet(node: &TestNode, source: &TransportAddr, wire: Vec<u8>) -> ReceivedPacket {
    ReceivedPacket::with_timestamp(
        node.transport_id,
        source.clone(),
        PacketBuffer::new(wire),
        Node::now_ms(),
    )
}

async fn heartbeat(node: &mut TestNode, remote: &Node, owner: &mut Candidate) -> u64 {
    let frame = owner.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    super::super::super::spanning_tree::process_dataplane_packet(node, frame).await;
    node.node
        .dataplane_fmp_link_metrics(remote.node_addr(), Instant::now())
        .unwrap()
        .rx_packets
}

// Only the captured Msg1 arrival is aged. Keys, Msg2 and installed ownership
// still come from the real Noise handlers; no peer/session is synthesized.
async fn incumbent(
    node: &mut TestNode,
    remote: &Node,
    source: &TransportAddr,
    index: u32,
    age_ms: u64,
) -> Candidate {
    let mut handshake =
        HandshakeState::new_initiator(remote.identity.keypair(), node.node.identity.pubkey_full());
    handshake.set_local_epoch(remote.startup_epoch);
    let wire = build_msg1(
        SessionIndex::new(index),
        &handshake.write_message_1().unwrap(),
    );
    let mut request = packet(node, source, wire);
    request.timestamp_ms -= age_ms;
    node.node.handle_msg1(request).await;
    let peer = node.node.get_peer(remote.node_addr()).unwrap();
    let msg2 = peer.handshake_msg2().unwrap();
    let header = Msg2Header::parse(msg2).unwrap();
    handshake.read_message_2(header.noise_msg2(msg2)).unwrap();
    let mut owner = Candidate {
        link: peer.link_id(),
        index: header.sender_idx,
        session: handshake.into_session().unwrap(),
        source: source.clone(),
    };
    assert_eq!(heartbeat(node, remote, &mut owner).await, 1);
    assert!(
        Node::now_ms()
            - node
                .node
                .get_peer(remote.node_addr())
                .unwrap()
                .authenticated_at()
            >= age_ms
    );
    owner
}

#[test]
fn fresh_confirmation_replaces_only_idle_neighbor_and_preserves_active_session() {
    super::super::super::session::run_large_stack_async_test("rotation-confirmed", || async {
        let mut node = make_test_node().await;
        let old = make_node();
        let active = make_node();
        let newcomer = make_node();
        let (_old_socket, old_source) = local_path().await;
        let (_active_socket, active_source) = local_path().await;
        let (_new_socket, new_source) = local_path().await;
        let old_owner = incumbent(&mut node, &old, &old_source, 10, 60_000).await;
        let mut active_owner = incumbent(&mut node, &active, &active_source, 11, 50_000).await;
        node.node.pending_session_traffic.push_tun_packet(
            *active.node_addr(),
            vec![1],
            8,
            8,
            Some(1),
        );
        let epoch = node.node.startup_epoch;
        let generation = node
            .node
            .get_peer(active.node_addr())
            .unwrap()
            .session_generation();
        enable(&mut node, 2);

        let mut candidate = connect(&mut node, &newcomer, &new_source, 12).await;
        assert_eq!(resources(&node), (2, 1, 3, 3));
        assert!(node.node.get_peer(newcomer.node_addr()).is_none());
        assert_eq!(
            node.node.get_peer(old.node_addr()).unwrap().our_index(),
            Some(old_owner.index)
        );
        assert_eq!(heartbeat(&mut node, &active, &mut active_owner).await, 2);

        let proof = candidate.frame(
            node.transport_id,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
        );
        assert!(node.node.confirm_inbound_handshake(proof).await);
        process_available_packets(std::slice::from_mut(&mut node)).await;
        assert_eq!(resources(&node), (2, 0, 2, 2));
        assert_eq!(
            (
                node.node.max_peers,
                node.node.max_connections,
                node.node.max_links
            ),
            (2, 1, 3)
        );
        assert!(node.node.get_peer(old.node_addr()).is_none());
        assert!(!node.node.index_allocator.is_allocated(old_owner.index));
        assert_eq!(
            node.node
                .get_peer(newcomer.node_addr())
                .unwrap()
                .our_index(),
            Some(candidate.index)
        );
        let retained = node.node.get_peer(active.node_addr()).unwrap();
        assert_eq!(retained.link_id(), active_owner.link);
        assert_eq!(retained.our_index(), Some(active_owner.index));
        assert_eq!(retained.remote_epoch(), Some(active.startup_epoch));
        assert_eq!(retained.session_generation(), generation);
        assert_eq!(node.node.startup_epoch, epoch);
        assert_eq!(heartbeat(&mut node, &active, &mut active_owner).await, 3);
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
    });
}

#[test]
fn msg1_replay_bad_proof_and_retired_confirmation_never_evict() {
    super::super::super::session::run_large_stack_async_test("rotation-replay", || async {
        let mut node = make_test_node().await;
        let old = make_node();
        let newcomer = make_node();
        let (_old_socket, old_source) = local_path().await;
        let (_new_socket, new_source) = local_path().await;
        let (_wrong_socket, wrong_source) = local_path().await;
        let mut owner = incumbent(&mut node, &old, &old_source, 20, 60_000).await;
        enable(&mut node, 1);
        let mut candidate = connect(&mut node, &newcomer, &new_source, 21).await;
        let msg1 = node
            .node
            .get_connection(&candidate.link)
            .unwrap()
            .handshake_msg1()
            .unwrap()
            .to_vec();
        node.node
            .handle_msg1(packet(&node, &new_source, msg1))
            .await;
        assert_eq!(resources(&node), (1, 1, 2, 2));
        assert_eq!(
            node.node.get_peer(old.node_addr()).unwrap().our_index(),
            Some(owner.index)
        );

        let proof = candidate.frame(
            node.transport_id,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
        );
        let original = proof.data.as_slice().to_vec();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            !node
                .node
                .confirm_inbound_handshake(packet(&node, &new_source, corrupt))
                .await
        );
        assert!(
            !node
                .node
                .confirm_inbound_handshake(packet(&node, &wrong_source, original.clone()))
                .await
        );
        assert_eq!(resources(&node), (1, 1, 2, 2));
        assert!(node.node.get_peer(newcomer.node_addr()).is_none());
        assert_eq!(heartbeat(&mut node, &old, &mut owner).await, 2);

        node.node
            .cleanup_stale_connection(candidate.link, Node::now_ms())
            .await;
        assert!(
            !node
                .node
                .confirm_inbound_handshake(packet(&node, &new_source, original))
                .await
        );
        assert_eq!(resources(&node), (1, 0, 1, 1));
        assert_eq!(
            node.node.get_peer(old.node_addr()).unwrap().remote_epoch(),
            Some(old.startup_epoch)
        );
        assert_eq!(heartbeat(&mut node, &old, &mut owner).await, 3);
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
    });
}

#[test]
fn application_demand_arriving_before_confirmation_cancels_replacement() {
    super::super::super::session::run_large_stack_async_test("rotation-demand-race", || async {
        let mut node = make_test_node().await;
        let old = make_node();
        let newcomer = make_node();
        let (_old_socket, old_source) = local_path().await;
        let (_new_socket, new_source) = local_path().await;
        let mut owner = incumbent(&mut node, &old, &old_source, 30, 60_000).await;
        enable(&mut node, 1);
        let mut candidate = connect(&mut node, &newcomer, &new_source, 31).await;
        assert_eq!(resources(&node), (1, 1, 2, 2));
        node.node.pending_session_traffic.push_tun_packet(
            *old.node_addr(),
            vec![1, 2, 3],
            8,
            8,
            Some(1),
        );
        let proof = candidate.frame(
            node.transport_id,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
        );
        assert!(!node.node.confirm_inbound_handshake(proof).await);
        assert_eq!(resources(&node), (1, 0, 1, 1));
        assert!(node.node.get_peer(newcomer.node_addr()).is_none());
        assert_eq!(
            node.node.get_peer(old.node_addr()).unwrap().our_index(),
            Some(owner.index)
        );
        assert_eq!(heartbeat(&mut node, &old, &mut owner).await, 2);
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
    });
}

#[test]
fn configured_incumbent_is_protected_while_an_idle_learned_neighbor_can_rotate() {
    super::super::super::session::run_large_stack_async_test("rotation-configured", || async {
        let mut node = make_test_node().await;
        let configured = make_node();
        let learned = make_node();
        let newcomer = make_node();
        let (_configured_socket, configured_source) = local_path().await;
        let (_learned_socket, learned_source) = local_path().await;
        let (_new_socket, new_source) = local_path().await;
        let mut owner = incumbent(&mut node, &configured, &configured_source, 40, 60_000).await;
        node.node.config.peers.push(PeerConfig::new(
            configured.identity.npub(),
            "udp",
            "127.0.0.1:1",
        ));
        node.node.configured_peers =
            crate::node::ConfiguredPeerLookup::from_config(&node.node.config);
        enable(&mut node, 1);
        request(&mut node, &newcomer, &new_source, 41).await;
        assert_eq!(resources(&node), (1, 0, 1, 1));

        // Even though the configured peer is older, only the learned one is
        // eligible when a second roster slot has subsequently been filled.
        node.node.max_peers = 2;
        incumbent(&mut node, &learned, &learned_source, 42, 50_000).await;
        enable(&mut node, 2);
        let mut candidate = connect(&mut node, &newcomer, &new_source, 43).await;
        let proof = candidate.frame(
            node.transport_id,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
        );
        assert!(node.node.confirm_inbound_handshake(proof).await);
        assert_eq!(resources(&node), (2, 0, 2, 2));
        assert!(node.node.get_peer(learned.node_addr()).is_none());
        assert_eq!(
            node.node
                .get_peer(configured.node_addr())
                .unwrap()
                .our_index(),
            Some(owner.index)
        );
        assert_eq!(heartbeat(&mut node, &configured, &mut owner).await, 2);
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
    });
}

#[test]
fn attempt_and_replacement_cooldowns_apply_across_candidate_identities() {
    super::super::super::session::run_large_stack_async_test(
        "rotation-global-cooldown",
        || async {
            for promote in [false, true] {
                let mut node = make_test_node().await;
                let first = make_node();
                let second = make_node();
                let newcomer = make_node();
                let (_first_socket, first_source) = local_path().await;
                let (_second_socket, second_source) = local_path().await;
                let (_new_socket, new_source) = local_path().await;
                incumbent(&mut node, &first, &first_source, 50, 60_000).await;
                let mut retained = incumbent(&mut node, &second, &second_source, 51, 50_000).await;
                enable(&mut node, 2);
                let mut candidate = connect(&mut node, &newcomer, &new_source, 52).await;
                // A distinct identity cannot create a second concurrent attempt.
                let other = make_node();
                let (_other_socket, other_source) = local_path().await;
                request(&mut node, &other, &other_source, 53).await;
                assert_eq!(resources(&node), (2, 1, 3, 3));
                if promote {
                    let proof = candidate.frame(
                        node.transport_id,
                        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                    );
                    assert!(node.node.confirm_inbound_handshake(proof).await);
                } else {
                    node.node
                        .cleanup_stale_connection(candidate.link, Node::now_ms())
                        .await;
                }
                for index in 54..57 {
                    let another = make_node();
                    let (_socket, source) = local_path().await;
                    request(&mut node, &another, &source, index).await;
                    assert!(node.node.get_peer(another.node_addr()).is_none());
                    assert_eq!(resources(&node), (2, 0, 2, 2));
                }
                // This old, idle learned peer is still eligible by age; new
                // identities must not bypass the node-wide attempt/replacement gap.
                assert_eq!(
                    node.node.get_peer(second.node_addr()).unwrap().our_index(),
                    Some(retained.index)
                );
                assert_eq!(heartbeat(&mut node, &second, &mut retained).await, 2);
                cleanup_nodes(std::slice::from_mut(&mut node)).await;
            }
        },
    );
}

#[test]
fn rotation_does_not_increase_link_or_handshake_caps_and_default_stays_closed() {
    super::super::super::session::run_large_stack_async_test("rotation-resource-caps", || async {
        for mode in 0..3 {
            let mut node = make_test_node().await;
            let old = make_node();
            let newcomer = make_node();
            let (_old_socket, old_source) = local_path().await;
            let (_new_socket, new_source) = local_path().await;
            let mut owner = incumbent(&mut node, &old, &old_source, 60, 60_000).await;
            enable(&mut node, 1);
            if mode == 0 {
                node.node.config.node.neighbor_rotation = None;
            } else if mode == 1 {
                node.node.max_links = 1;
            } else {
                // Refresh a different incumbent so the first remains an
                // eligible victim. Only the handshake cap can block admission.
                node.node.max_peers = 2;
                let other = make_node();
                let (_other_socket, other_source) = local_path().await;
                incumbent(&mut node, &other, &other_source, 61, 50_000).await;
                enable(&mut node, 2);
                let (_refresh_socket, refresh_source) = local_path().await;
                let refresh = connect(&mut node, &other, &refresh_source, 62).await;
                node.node.max_links = 4;
                assert!(node.node.get_connection(&refresh.link).is_some());
                assert!(node.node.has_neighbor_rotation_opportunity(Node::now_ms()));
            }
            let before = resources(&node);
            let caps = (
                node.node.max_peers,
                node.node.max_connections,
                node.node.max_links,
            );
            request(&mut node, &newcomer, &new_source, 63).await;
            assert_eq!(resources(&node), before);
            assert_eq!(
                (
                    node.node.max_peers,
                    node.node.max_connections,
                    node.node.max_links
                ),
                caps
            );
            assert!(node.node.get_peer(newcomer.node_addr()).is_none());
            assert_eq!(
                node.node.get_peer(old.node_addr()).unwrap().our_index(),
                Some(owner.index)
            );
            assert_eq!(heartbeat(&mut node, &old, &mut owner).await, 2);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        }
    });
}

#[test]
fn symmetric_rotation_completes_with_one_spare_link_and_handshake_slot() {
    super::super::super::session::run_large_stack_async_test("rotation-symmetric", || async {
        use crate::node::wire::{Msg1Header, build_msg2};

        let mut nodes = [make_test_node().await, make_test_node().await];
        let old = [make_node(), make_node()];
        let paths = [local_path().await, local_path().await];
        let mut old_indices = Vec::new();
        for i in 0..2 {
            let owner = incumbent(&mut nodes[i], &old[i], &paths[i].1, 70, 60_000).await;
            old_indices.push(owner.index);
            enable(&mut nodes[i], 1);
        }
        for (from, to) in [(0, 1), (1, 0)] {
            let identity = PeerIdentity::from_pubkey_full(nodes[to].node.identity.pubkey_full());
            let address = nodes[to].addr.clone();
            let local = &mut nodes[from];
            local
                .node
                .initiate_connection(local.transport_id, address, identity)
                .await
                .unwrap();
            assert_eq!(resources(local), (1, 1, 2, 2));
        }

        let smaller = usize::from(nodes[0].node.node_addr() > nodes[1].node.node_addr());
        let larger = 1 - smaller;
        let mut late_reply = None;
        // Both Msg1s are already on the wire before either node can choose the
        // winning direction. Neither replayable Msg1 may remove an incumbent.
        for i in 0..2 {
            let incoming = tokio::time::timeout(Duration::from_secs(1), nodes[i].packet_rx.recv())
                .await
                .unwrap()
                .unwrap();
            if i == smaller {
                // Retain a genuine Noise response for the losing outbound
                // half, as if that response were delayed past convergence.
                let header = Msg1Header::parse(incoming.data.as_slice()).unwrap();
                let mut responder = HandshakeState::new_responder(nodes[i].node.identity.keypair());
                responder.set_local_epoch(nodes[i].node.startup_epoch);
                responder
                    .read_message_1(header.noise_msg1(incoming.data.as_slice()))
                    .unwrap();
                late_reply = Some(build_msg2(
                    SessionIndex::new(u32::MAX - 1),
                    header.sender_idx,
                    &responder.write_message_2().unwrap(),
                ));
            }
            nodes[i].node.handle_msg1(incoming).await;
            assert_eq!(resources(&nodes[i]), (1, 1, 2, 2));
            assert_eq!(
                nodes[i]
                    .node
                    .get_peer(old[i].node_addr())
                    .unwrap()
                    .our_index(),
                Some(old_indices[i])
            );
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                for node in &mut nodes {
                    process_available_packets(std::slice::from_mut(node)).await;
                    assert_eq!(node.node.peer_count(), 1);
                    assert!(node.node.connection_count() <= 1);
                    assert!(node.node.link_count() <= 2);
                    assert!(node.node.index_allocator.count() <= 2);
                    assert_eq!(
                        (
                            node.node.max_peers,
                            node.node.max_connections,
                            node.node.max_links
                        ),
                        (1, 1, 2)
                    );
                }
                if nodes.iter().enumerate().all(|(i, node)| {
                    node.node.get_peer(nodes[1 - i].node.node_addr()).is_some()
                        && node.node.connection_count() == 0
                        && node.node.pending_outbound.is_empty()
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("symmetric full-roster dials must converge without extra slots");

        for i in 0..2 {
            assert_eq!(resources(&nodes[i]), (1, 0, 1, 1));
            assert!(nodes[i].node.get_peer(old[i].node_addr()).is_none());
            assert!(!nodes[i].node.index_allocator.is_allocated(old_indices[i]));
            let owner = nodes[i]
                .node
                .get_peer(nodes[1 - i].node.node_addr())
                .unwrap();
            let opposite = nodes[1 - i]
                .node
                .get_peer(nodes[i].node.node_addr())
                .unwrap();
            assert!(owner.has_session() && owner.can_send());
            assert_eq!(owner.their_index(), opposite.our_index());
            assert_eq!(owner.remote_epoch(), Some(nodes[1 - i].node.startup_epoch));
            assert!(owner.previous_our_index().is_none());
        }
        let remote_addr = *nodes[smaller].node.node_addr();
        let source = nodes[smaller].addr.clone();
        let before = nodes[larger].node.get_peer(&remote_addr).unwrap();
        let identity = (
            before.link_id(),
            before.our_index(),
            before.session_generation(),
            before.remote_epoch(),
        );
        let delayed = packet(&nodes[larger], &source, late_reply.unwrap());
        nodes[larger].node.handle_msg2(delayed).await;
        assert_eq!(resources(&nodes[larger]), (1, 0, 1, 1));
        let retained = nodes[larger].node.get_peer(&remote_addr).unwrap();
        assert_eq!(
            (
                retained.link_id(),
                retained.our_index(),
                retained.session_generation(),
                retained.remote_epoch()
            ),
            identity
        );
        cleanup_nodes(&mut nodes).await;
    });
}
