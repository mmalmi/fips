//! Elective adjacency loss must distinguish a retained FSP from a restarted peer.

use super::*;
use crate::node::wire::{Msg1Header, Msg2Header};
use crate::transport::{PacketBuffer, ReceivedPacket};

#[test]
fn rotation_restart_outbound_promotion_discards_stale_fsp() {
    run_large_stack_async_test("rotation-restart-outbound", || async {
        restart_then_rejoin(0).await;
    });
}

#[test]
fn rotation_restart_inbound_promotion_discards_stale_fsp() {
    run_large_stack_async_test("rotation-restart-inbound", || async {
        restart_then_rejoin(1).await;
    });
}

#[test]
fn rotation_restart_unchanged_epoch_preserves_fsp_in_both_directions() {
    run_large_stack_async_test("rotation-unchanged-epoch", || async {
        let mut nodes = established_pair().await;
        let old_hash = session_hash(&nodes);
        for initiator in [0, 1] {
            rotate_both_out(&mut nodes);
            rejoin(&mut nodes, initiator).await;
            assert_eq!(session_hash(&nodes), old_hash);
            assert_matching_fsp(&nodes);
            deliver(&mut nodes, b"same-process-rejoin").await;
        }
        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn rotation_restart_simultaneous_rejoin_preserves_fsp_with_one_connection_slot() {
    run_large_stack_async_test("rotation-simultaneous-rejoin", || {
        simultaneous_rejoin(false)
    });
}

#[test]
fn rotation_restart_third_source_cannot_add_another_crossed_half() {
    run_large_stack_async_test("rotation-third-source-replay", || simultaneous_rejoin(true));
}

async fn simultaneous_rejoin(replay_third_source: bool) {
    let mut nodes = established_pair().await;
    let retained_hash = session_hash(&nodes);
    let addresses = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    rotate_both_out(&mut nodes);
    for node in &mut nodes {
        node.node.max_peers = 1;
        node.node.max_connections = 1;
        node.node.max_links = 2;
    }
    // Both Msg1 flights leave before either is processed. The existing
    // same-identity crossed-dial allowance permits a temporary extra half;
    // max_connections=1 must not deadlock the new confirmation requirement.
    for source in [0, 1] {
        let target = &nodes[1 - source];
        let identity = PeerIdentity::from_pubkey_full(target.node.identity().pubkey_full());
        let address = target.addr.clone();
        let node = &mut nodes[source];
        node.node
            .initiate_connection(node.transport_id, address, identity)
            .await
            .unwrap();
        assert_eq!(node.node.connection_count(), 1);
        assert_eq!(node.node.link_count(), 1);
    }
    for (index, node) in nodes.iter_mut().enumerate() {
        let packet = tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
            .await
            .expect("both initial crossed UDP requests should arrive")
            .unwrap();
        assert!(Msg1Header::parse(packet.data.as_slice()).is_some());
        let captured = packet.data.as_slice().to_vec();
        node.node.handle_msg1(packet).await;
        assert!(node.node.connection_count() <= 2);
        assert!(node.node.link_count() <= 2);
        assert_eq!(node.node.index_allocator.count(), 2);
        if replay_third_source && index == 0 {
            reject_third_source_replay(node, &captured).await;
        }
    }
    assert_eq!(session_hash(&nodes), retained_hash);
    assert_matching_fsp(&nodes);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            process_available_packets(&mut nodes).await;
            for node in &nodes {
                assert!(node.node.peer_count() <= 1);
                assert!(node.node.connection_count() <= 2);
                assert!(node.node.link_count() <= 2);
            }
            if let (Some(a), Some(b)) = (
                nodes[0].node.get_peer(&addresses[1]),
                nodes[1].node.get_peer(&addresses[0]),
            ) && a.can_send()
                && b.can_send()
                && a.our_index() == b.their_index()
                && a.their_index() == b.our_index()
                && nodes.iter().all(|node| {
                    node.node.connection_count() == 0 && node.node.pending_outbound.is_empty()
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("crossed rejoin must authenticate reciprocal owners and retire both losing halves");
    drain_to_quiescence(&mut nodes).await;
    for (index, node) in nodes.iter().enumerate() {
        let remote = addresses[1 - index];
        let peer = node.node.get_peer(&remote).unwrap();
        assert_eq!(peer.fmp_mmp_is_initiator(), addresses[index] < remote);
        assert_eq!(node.node.connection_count(), 0);
        assert_eq!(node.node.link_count(), 1);
        // A previous receive epoch belongs to the ordinary FMP drain;
        // it is not an orphan pending handshake or an extra active link.
        assert_eq!(
            node.node.index_allocator.count(),
            1 + usize::from(peer.previous_our_index().is_some())
        );
    }
    populate_all_coord_caches(&mut nodes);
    assert_eq!(session_hash(&nodes), retained_hash);
    assert_matching_fsp(&nodes);
    deliver(&mut nodes, b"simultaneous-same-epoch-rejoin").await;
    cleanup_nodes(&mut nodes).await;
}

async fn reject_third_source_replay(node: &mut TestNode, captured: &[u8]) {
    let owners = node
        .node
        .peers
        .connection_values()
        .map(|conn| {
            (
                conn.link_id(),
                conn.our_index(),
                conn.their_index(),
                conn.is_outbound(),
                conn.source_addr().cloned(),
                conn.last_activity(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(owners.len(), 2);
    assert_eq!(owners.iter().filter(|owner| owner.3).count(), 1);
    assert_eq!(node.node.peer_count(), 0);
    let outgoing = node
        .node
        .peers
        .connection_values()
        .filter(|conn| conn.is_outbound())
        .map(|conn| {
            let key = (
                conn.transport_id().unwrap(),
                conn.our_index().unwrap().as_u32(),
            );
            let link = *node.node.pending_outbound.get(&key).unwrap();
            assert_eq!(link, conn.link_id());
            (key, link)
        })
        .collect::<Vec<_>>();
    assert_eq!(outgoing.len(), 1);
    let replay_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let third_source = TransportAddr::from_string(&replay_socket.local_addr().unwrap().to_string());
    // The other node has not yet handled our initial Msg1, so no genuine Msg2
    // is queued here. Replay its actual request over a third UDP source first.
    replay_socket
        .send_to(captured, node.addr.as_str().unwrap())
        .await
        .unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
        .await
        .expect("third-source UDP replay should arrive")
        .unwrap();
    assert_eq!(packet.remote_addr, third_source);
    assert_eq!(packet.data.as_slice(), captured);
    node.node.handle_msg1(packet).await;
    assert_eq!(
        (
            node.node.connection_count(),
            node.node.link_count(),
            node.node.index_allocator.count()
        ),
        (2, 2, 2),
        "one crossed-dial allowance cannot admit another inbound half from a third source"
    );
    assert_eq!(node.node.peer_count(), 0);
    for (key, link) in outgoing {
        assert_eq!(node.node.pending_outbound.get(&key), Some(&link));
    }
    for (link, ours, theirs, outbound, source, last_activity) in owners {
        let retained = node
            .node
            .get_connection(&link)
            .expect("original candidate must remain");
        assert_eq!(retained.our_index(), ours);
        assert_eq!(retained.their_index(), theirs);
        assert_eq!(retained.is_outbound(), outbound);
        assert_eq!(retained.source_addr(), source.as_ref());
        assert_eq!(retained.last_activity(), last_activity);
        assert!(node.node.links.get(&link).is_some());
    }
}

#[test]
fn rotation_restart_replayed_older_epoch_msg1_cannot_clear_retained_fsp() {
    run_large_stack_async_test("rotation-old-epoch-replay", || async {
        replay_requires_fresh_confirmation(true, false).await;
    });
}

#[test]
fn rotation_restart_replayed_same_epoch_msg1_cannot_redirect_retained_fsp() {
    run_large_stack_async_test("rotation-same-epoch-replay", || async {
        replay_requires_fresh_confirmation(false, false).await;
    });
}

#[test]
fn rotation_restart_final_fsp_drains_ready_work_without_a_new_wakeup() {
    run_large_stack_async_test("rotation-retained-readiness", || async {
        replay_requires_fresh_confirmation(true, true).await;
    });
}

async fn replay_requires_fresh_confirmation(advance_epoch: bool, hold_final_wakeup: bool) {
    let mut nodes = established_pair().await;
    let remote = *nodes[1].node.node_addr();
    let captured_epoch = nodes[1].node.startup_epoch;
    rotate_both_out(&mut nodes);

    // Capture a real UDP request produced by the remote's normal outbound
    // path. No replacement keys or synthetic Noise response are installed.
    let local_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let local_address = nodes[0].addr.clone();
    let remote_node = &mut nodes[1];
    remote_node
        .node
        .initiate_connection(remote_node.transport_id, local_address, local_identity)
        .await
        .unwrap();
    let original = tokio::time::timeout(Duration::from_secs(1), nodes[0].packet_rx.recv())
        .await
        .expect("capture original UDP Msg1")
        .unwrap();
    assert_eq!(original.remote_addr, nodes[1].addr);
    assert!(Msg1Header::parse(original.data.as_slice()).is_some());
    let captured = original.data.as_slice().to_vec();

    if advance_epoch {
        restart_remote_node(&mut nodes[1]);
        assert_ne!(nodes[1].node.startup_epoch, captured_epoch);
        rejoin(&mut nodes, 0).await;
        establish_fsp(&mut nodes).await;
        assert_matching_fsp(&nodes);
        deliver(&mut nodes, b"newer-epoch-before-captured-replay").await;
        rotate_both_out(&mut nodes);
    }
    let retained_hash = session_hash(&nodes);
    let retained_epoch = nodes[1].node.startup_epoch;
    let source = nodes[1].addr.clone();
    let local = &mut nodes[0];
    local.node.max_peers = 1;
    local.node.max_connections = 1;
    local.node.max_links = 1;
    local.node.config.node.rate_limit.handshake_timeout_secs = 1;
    assert_eq!(local.node.peer_count(), 0, "roster has spare capacity");
    assert_eq!(local.node.connection_count(), 0);

    let replay = |transport_id| {
        ReceivedPacket::with_timestamp(
            transport_id,
            source.clone(),
            PacketBuffer::new(captured.clone()),
            Node::now_ms(),
        )
    };
    local.node.handle_msg1(replay(local.transport_id)).await;
    assert_eq!(
        local
            .node
            .get_session(&remote)
            .and_then(|s| s.handshake_hash())
            .copied(),
        Some(retained_hash),
        "replayable Msg1 cannot clear a retained FSP without fresh encrypted proof"
    );
    assert!(local.node.dataplane_has_fsp_owner(&remote));
    assert!(
        local.node.get_peer(&remote).is_none(),
        "replayable Msg1 cannot install direct egress for a retained FSP"
    );
    let pending = local.node.peers.connection_values().next().unwrap();
    assert!(!pending.is_outbound() && pending.has_session());
    assert_eq!(pending.remote_epoch(), Some(captured_epoch));
    let link = pending.link_id();
    let index = pending.our_index().unwrap();
    let last_activity = pending.last_activity();
    let response = pending.handshake_msg2().unwrap().to_vec();
    assert_eq!(
        (
            local.node.connection_count(),
            local.node.link_count(),
            local.node.index_allocator.count()
        ),
        (1, 1, 1)
    );

    // Do not consume the response at the remote: a captured request supplies
    // no knowledge of this fresh responder key. Exact replay neither grows
    // state nor refreshes its deadline or responder key.
    local.node.handle_msg1(replay(local.transport_id)).await;
    let pending = local.node.get_connection(&link).unwrap();
    assert_eq!(pending.our_index(), Some(index));
    assert_eq!(pending.last_activity(), last_activity);
    assert_eq!(pending.handshake_msg2(), Some(response.as_slice()));
    assert_eq!(local.node.connection_count(), 1);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    local.node.check_timeouts().await;
    assert_eq!(
        (
            local.node.peer_count(),
            local.node.connection_count(),
            local.node.link_count(),
            local.node.index_allocator.count()
        ),
        (0, 0, 0, 0)
    );
    let retained = local.node.get_session(&remote).unwrap();
    assert_eq!(retained.handshake_hash(), Some(&retained_hash));
    assert!(retained.established_remote_epoch_matches(Some(retained_epoch)));
    assert!(local.node.dataplane_has_fsp_owner(&remote));

    // Model lost replies explicitly; never feed either response into the old
    // initiator or carry a queued old-process response across the next restart.
    for _ in 0..2 {
        let discarded = tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
            .await
            .expect("each replay should receive its unchanged Msg2")
            .unwrap();
        assert!(Msg2Header::parse(discarded.data.as_slice()).is_some());
        assert_eq!(discarded.data.as_slice(), response.as_slice());
    }

    // A fresh process can still finish the ordinary real Noise proof exchange.
    // Its new epoch clears obsolete FSP only after that handshake progresses.
    restart_remote_node(&mut nodes[1]);
    rejoin(&mut nodes, 1).await;
    assert!(nodes[0].node.get_session(&remote).is_none());
    // Readiness is advisory, not a fence for a particular crypto operation.
    // Retain the next responder notification in an already registered observer:
    // the ordinary completion queue must still make progress without a new wake.
    let notify = nodes[1].node.dataplane.readiness_notify();
    let mut retained_wakeup = hold_final_wakeup.then(|| Box::pin(notify.notified()));
    if let Some(wakeup) = &mut retained_wakeup {
        while wakeup.as_mut().enable() {
            *wakeup = Box::pin(notify.notified());
        }
    }
    establish_fsp(&mut nodes).await;
    if let Some(wakeup) = &mut retained_wakeup {
        assert!(
            wakeup.as_mut().enable(),
            "control must retain a real readiness wake"
        );
    }
    assert_matching_fsp(&nodes);
    deliver(&mut nodes, b"fresh-proof-after-replay-timeout").await;
    cleanup_nodes(&mut nodes).await;
}

async fn established_pair() -> Vec<TestNode> {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    for node in &mut nodes {
        // Neither automatic rekey nor idle eviction may rescue obsolete keys.
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.session.idle_timeout_secs = 0;
    }
    populate_all_coord_caches(&mut nodes);
    establish_fsp(&mut nodes).await;
    assert_matching_fsp(&nodes);
    deliver(&mut nodes, b"before-elective-removal").await;
    nodes
}

async fn restart_then_rejoin(initiator: usize) {
    let mut nodes = established_pair().await;
    let remote = *nodes[1].node.node_addr();
    let old_epoch = nodes[1].node.startup_epoch;
    let old_hash = session_hash(&nodes);

    nodes[0].node.remove_neighbor_for_rotation(&remote);
    assert!(nodes[0].node.get_peer(&remote).is_none());
    assert!(!nodes[0].node.dataplane_has_fmp_owner(&remote));
    assert_eq!(session_hash(&nodes), old_hash);
    assert!(nodes[0].node.dataplane_has_fsp_owner(&remote));

    restart_remote_node(&mut nodes[1]);
    assert_eq!(*nodes[1].node.node_addr(), remote);
    assert_ne!(nodes[1].node.startup_epoch, old_epoch);
    assert_eq!(nodes[1].node.peer_count(), 0);
    assert_eq!(nodes[1].node.session_count(), 0);
    rejoin(&mut nodes, initiator).await;

    // Both real Noise directions enter normal promotion: no old ActivePeer
    // remains to carry the old remote epoch. The retained FSP has that evidence.
    assert_eq!(
        nodes[0].node.get_peer(&remote).unwrap().remote_epoch(),
        Some(nodes[1].node.startup_epoch)
    );
    assert!(
        nodes[0].node.get_session(&remote).is_none(),
        "authenticated new process epoch must remove retained obsolete FSP before automatic recovery"
    );
    assert!(!nodes[0].node.dataplane_has_fsp_owner(&remote));

    establish_fsp(&mut nodes).await;
    let recovered_hash = session_hash(&nodes);
    assert_ne!(recovered_hash, old_hash);
    assert_matching_fsp(&nodes);
    deliver(&mut nodes, b"after-authenticated-restart").await;

    // A subsequent same-process normal promotion must retain the FSP which
    // already recovered to this epoch, including both matching crypto owners.
    rotate_both_out(&mut nodes);
    rejoin(&mut nodes, initiator).await;
    assert_eq!(session_hash(&nodes), recovered_hash);
    assert_matching_fsp(&nodes);
    deliver(&mut nodes, b"already-recovered-session-rejoin").await;
    cleanup_nodes(&mut nodes).await;
}

fn restart_remote_node(remote: &mut TestNode) {
    let mut config = remote.node.config.clone();
    config.node.identity.replace_nsec(Some(crate::encode_nsec(
        &remote.node.identity().keypair().secret_key(),
    )));
    let mut fresh = Node::new(config).expect("restart with the same persistent identity");
    // Keep only the fixture's UDP socket and TUN input plumbing. Every protocol
    // owner, replay index, session key and startup epoch comes from a fresh Node.
    fresh.transports = std::mem::take(&mut remote.node.transports);
    fresh.tun_outbound_rx = remote.node.tun_outbound_rx.take();
    remote.node = fresh;
}

fn rotate_both_out(nodes: &mut [TestNode]) {
    let addresses = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    for (index, node) in nodes.iter_mut().enumerate() {
        node.node
            .remove_neighbor_for_rotation(&addresses[1 - index]);
        assert_eq!(node.node.peer_count(), 0);
        assert_eq!(node.node.connection_count(), 0);
        assert_eq!(node.node.session_count(), 1);
    }
}

async fn rejoin(nodes: &mut [TestNode], initiator: usize) {
    let responder = 1 - initiator;
    let identity = PeerIdentity::from_pubkey_full(nodes[responder].node.identity().pubkey_full());
    let address = nodes[responder].addr.clone();
    let node = &mut nodes[initiator];
    node.node
        .initiate_connection(node.transport_id, address, identity)
        .await
        .expect("real UDP rejoin should initiate");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            process_available_packets(nodes).await;
            if nodes.iter().all(|node| node.node.peer_count() == 1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("real Noise rejoin should promote both ends");
    drain_to_quiescence(nodes).await;
    let addresses = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    for (index, node) in nodes.iter().enumerate() {
        let peer = node.node.get_peer(&addresses[1 - index]).unwrap();
        let counterpart = nodes[1 - index].node.get_peer(&addresses[index]).unwrap();
        assert_eq!(peer.fmp_mmp_is_initiator(), index == initiator);
        assert_eq!(peer.our_index(), counterpart.their_index());
        assert_eq!(peer.their_index(), counterpart.our_index());
        assert_eq!(
            peer.remote_epoch(),
            Some(nodes[1 - index].node.startup_epoch)
        );
        assert!(!node.node.config.node.rekey.enabled);
        assert_eq!(node.node.config.node.session.idle_timeout_secs, 0);
    }
    populate_all_coord_caches(nodes);
}

async fn establish_fsp(nodes: &mut [TestNode]) {
    let addresses = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    let remote_key = nodes[1].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(addresses[1], remote_key)
        .await
        .expect("fresh end-to-end handshake should start");
    for index in [0, 1] {
        wait_for_session_established(
            nodes,
            index,
            &addresses[1 - index],
            Duration::from_secs(5),
            "rotation/restart FSP",
        )
        .await;
    }
    drain_to_quiescence(nodes).await;
}

fn session_hash(nodes: &[TestNode]) -> [u8; 32] {
    *nodes[0]
        .node
        .get_session(nodes[1].node.node_addr())
        .and_then(|session| session.handshake_hash())
        .expect("established survivor session hash")
}

fn assert_matching_fsp(nodes: &[TestNode]) {
    let expected = session_hash(nodes);
    for (index, node) in nodes.iter().enumerate() {
        let remote = &nodes[1 - index].node;
        let session = node.node.get_session(remote.node_addr()).unwrap();
        assert!(session.is_established());
        assert_eq!(session.handshake_hash(), Some(&expected));
        assert!(session.established_remote_epoch_matches(Some(remote.startup_epoch)));
        assert!(node.node.dataplane_has_fsp_owner(remote.node_addr()));
    }
}

async fn deliver(nodes: &mut [TestNode], payload: &[u8]) {
    let mut receiver = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    let remote = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    send_endpoint_data_via_dataplane(&mut nodes[0].node, remote, payload.to_vec())
        .await
        .unwrap();
    let event = recv_endpoint_event_while_draining(
        nodes,
        &mut receiver.event_rx,
        Duration::from_secs(3),
        "rotation/restart payload delivery",
    )
    .await;
    receiver.event_rx.release_messages(event.messages.len());
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        payload
    );
    drain_to_quiescence(nodes).await;
}
