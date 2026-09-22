use super::*;

mod displaced;
mod stale;
use crate::dataplane::FmpWireHeader;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, make_test_node, process_available_packets,
    process_dataplane_completions, process_dataplane_packet,
};
use crate::node::wire::{Msg1Header, Msg2Header};
use crate::transport::ReceivedPacket;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::time::Instant;

#[test]
fn asymmetric_quiet_same_path_refresh_accepts_fresh_proof() {
    run_large_stack_async_test("asymmetric-quiet-fmp-refresh", || run(true, false));
}

#[test]
fn healthy_same_path_duplicate_preserves_authenticated_owner_without_rekey() {
    run_large_stack_async_test("healthy-same-path-duplicate", || run(false, false));
}

#[test]
fn reverse_quiet_same_path_refresh_accepts_fresh_proof() {
    run_large_stack_async_test("reverse-quiet-fmp-refresh", || run(true, true));
}

#[test]
fn reverse_healthy_same_path_duplicate_preserves_authenticated_owner() {
    run_large_stack_async_test("reverse-healthy-fmp-refresh", || run(false, true));
}

async fn run(quiet: bool, reverse: bool) {
    let mut nodes = [make_test_node().await, make_test_node().await];
    // A's fresh outbound would lose the crossed-dial rule against smaller B.
    if reverse && nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        nodes.swap(0, 1);
    }
    let result = AssertUnwindSafe(exercise(&mut nodes, quiet, reverse))
        .catch_unwind()
        .await;
    cleanup_nodes(&mut nodes).await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Owner {
    link: LinkId,
    our: SessionIndex,
    their: SessionIndex,
    epoch: Option<[u8; 8]>,
    generation: u64,
    authenticated_at: u64,
    handshake_hash: [u8; 32],
}

fn owner(node: &TestNode, peer: &NodeAddr) -> Owner {
    let active = node.node.get_peer(peer).unwrap();
    assert!(active.is_healthy() && active.can_send());
    Owner {
        link: active.link_id(),
        our: active.our_index().unwrap(),
        their: active.their_index().unwrap(),
        epoch: active.remote_epoch(),
        generation: active.session_generation(),
        authenticated_at: active.authenticated_at(),
        handshake_hash: *active.noise_session().unwrap().handshake_hash(),
    }
}

fn resources(node: &TestNode) -> (usize, usize, usize, usize) {
    (
        node.node.peer_count(),
        node.node.connection_count(),
        node.node.link_count(),
        node.node.index_allocator.count(),
    )
}

async fn dial(nodes: &mut [TestNode; 2]) {
    let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity.pubkey_full());
    let remote = nodes[1].addr.clone();
    let transport = nodes[0].transport_id;
    nodes[0]
        .node
        .initiate_connection(transport, remote, identity)
        .await
        .unwrap();
}

async fn next_matching(
    node: &mut TestNode,
    matches: impl Fn(&ReceivedPacket) -> bool,
) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = node.packet_rx.recv().await.expect("live UDP receiver");
            if matches(&packet) {
                return packet;
            }
            // This fixture controls loss at the receiving socket. In the
            // quiet phase, old B->A frames must not repair A's observation.
        }
    })
    .await
    .expect("expected real UDP frame must arrive")
}

async fn send_wire(nodes: &[TestNode; 2], source: usize, wire: &[u8]) {
    nodes[source]
        .node
        .transports
        .get(&nodes[source].transport_id)
        .unwrap()
        .send(&nodes[1 - source].addr, wire)
        .await
        .unwrap();
}

async fn heartbeat(nodes: &mut [TestNode; 2], source: usize) {
    let destination = *nodes[1 - source].node.node_addr();
    nodes[source]
        .node
        .send_dataplane_fmp_link_plaintext(
            &destination,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            false,
        )
        .await
        .unwrap();
}

async fn observed_heartbeat(nodes: &mut [TestNode; 2], source: usize) -> ReceivedPacket {
    let destination = 1 - source;
    let sender = *nodes[source].node.node_addr();
    let receiver_index = owner(&nodes[destination], &sender).our;
    let before = received(&nodes[destination], &sender);
    heartbeat(nodes, source).await;
    let packet = next_matching(&mut nodes[destination], |packet| {
        FmpWireHeader::parse_encrypted(packet.data.as_slice())
            .is_ok_and(|header| header.receiver_idx() == receiver_index.as_u32())
    })
    .await;
    process_dataplane_packet(&mut nodes[destination], packet.clone()).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while received(&nodes[destination], &sender) == before {
            process_dataplane_completions(&mut nodes[destination].node).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver must authenticate the actual encrypted Heartbeat");
    assert_eq!(received(&nodes[destination], &sender), before + 1);
    packet
}

async fn quiesce(nodes: &mut [TestNode; 2]) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut empty = 0;
        while empty < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            empty = if process_available_packets(nodes).await == 0 {
                empty + 1
            } else {
                0
            };
        }
    })
    .await
    .expect("event-only packet/completion drain must settle");
}

async fn settle_completions(node: &mut TestNode) {
    for _ in 0..8 {
        process_dataplane_completions(&mut node.node).await;
        tokio::task::yield_now().await;
    }
}

fn received(node: &TestNode, peer: &NodeAddr) -> u64 {
    node.node
        .dataplane_fmp_link_metrics(peer, Instant::now())
        .unwrap()
        .rx_packets
}

fn assert_pair(nodes: &[TestNode; 2]) {
    for (local, remote) in [(0, 1), (1, 0)] {
        let peer = nodes[remote].node.node_addr();
        let active = nodes[local].node.get_peer(peer).unwrap();
        let reverse = nodes[remote]
            .node
            .get_peer(nodes[local].node.node_addr())
            .unwrap();
        assert_eq!(active.our_index(), reverse.their_index());
        assert_eq!(active.their_index(), reverse.our_index());
        assert_eq!(
            active.remote_epoch(),
            Some(nodes[remote].node.startup_epoch)
        );
        assert_eq!(active.current_addr(), Some(&nodes[remote].addr));
        assert_eq!(active.transport_id(), Some(nodes[local].transport_id));
        assert!(active.is_healthy() && active.can_send());
        assert!(
            nodes[local]
                .node
                .dataplane_fmp_link_metrics(peer, Instant::now())
                .unwrap()
                .current_epoch_authenticated
        );
    }
}

async fn exercise(nodes: &mut [TestNode; 2], quiet: bool, reverse: bool) {
    for node in nodes.iter_mut() {
        // Explicit supported mode: exercise full same-path handshakes, not
        // ActivePeer rekey classification. Both tests use this same setting.
        // Liveness, admission, degradation and handshake expiry stay enabled.
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.heartbeat_interval_secs = 1;
    }
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    if reverse {
        nodes.swap(0, 1);
    }
    dial(nodes).await;
    if reverse {
        nodes.swap(0, 1);
    }
    quiesce(nodes).await;
    heartbeat(nodes, 0).await;
    heartbeat(nodes, 1).await;
    quiesce(nodes).await;
    assert_pair(nodes);
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
    assert_eq!(resources(&nodes[1]), (1, 0, 1, 1));
    let old_a = owner(&nodes[0], &b);
    let old_b = owner(&nodes[1], &a);

    if quiet {
        // A's inbound observation really ages; B will receive a fresh old-key
        // Heartbeat below. No clock, peer-health or key state is fabricated.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
    }
    let old_frame = observed_heartbeat(nodes, 0).await;
    assert_eq!(nodes[0].node.active_peer_needs_same_path_refresh(&b), quiet);
    assert!(!nodes[1].node.active_peer_needs_same_path_refresh(&a));
    assert_eq!(owner(&nodes[0], &b), old_a);
    assert_eq!(owner(&nodes[1], &a), old_b);
    for (node, remote) in [(0, b), (1, a)] {
        assert!(nodes[node].node.get_session(&remote).is_none());
        assert!(
            !nodes[node]
                .node
                .same_epoch_msg1_is_direct_path_recovery(&remote, Node::now_ms())
        );
    }

    dial(nodes).await;
    let request = next_matching(&mut nodes[1], |p| {
        Msg1Header::parse(p.data.as_slice()).is_some()
    })
    .await;
    nodes[1].node.handle_msg1(request.clone()).await;
    let response = next_matching(&mut nodes[0], |p| {
        Msg2Header::parse(p.data.as_slice()).is_some()
    })
    .await;
    let pending = nodes[1].node.peers.connection_values().next().unwrap();
    assert!(pending.is_inbound() && pending.is_complete());
    let candidate = pending.link_id();
    let candidate_index = pending.our_index().unwrap();
    let deadline_origin = pending.last_activity();
    assert_ne!(candidate_index, old_b.our);
    assert_eq!(owner(&nodes[1], &a), old_b, "Msg1 alone cannot replace B");
    assert_eq!(resources(&nodes[1]), (1, 1, 2, 2));

    // Both replays use the actual UDP source and original authenticated bytes.
    // Exact Msg1 retries retain the response/index/deadline; original-session
    // traffic cannot supply the fresh candidate's confirmation.
    send_wire(nodes, 0, request.data.as_slice()).await;
    let repeated = next_matching(&mut nodes[1], |p| {
        Msg1Header::parse(p.data.as_slice()).is_some()
    })
    .await;
    nodes[1].node.handle_msg1(repeated).await;
    let duplicate_response = next_matching(&mut nodes[0], |p| {
        Msg2Header::parse(p.data.as_slice()).is_some()
    })
    .await;
    assert_eq!(duplicate_response.data.as_slice(), response.data.as_slice());
    send_wire(nodes, 0, old_frame.data.as_slice()).await;
    let replay = next_matching(&mut nodes[1], |p| {
        p.data.as_slice() == old_frame.data.as_slice()
    })
    .await;
    let before_replay = received(&nodes[1], &a);
    process_dataplane_packet(&mut nodes[1], replay).await;
    settle_completions(&mut nodes[1]).await;
    assert_eq!(received(&nodes[1], &a), before_replay);
    assert_eq!(owner(&nodes[1], &a), old_b);
    let pending = nodes[1].node.get_connection(&candidate).unwrap();
    assert_eq!(pending.our_index(), Some(candidate_index));
    assert_eq!(pending.last_activity(), deadline_origin);
    assert!(pending.handshake_confirmation().is_none());
    assert_eq!(resources(&nodes[1]), (1, 1, 2, 2));

    // Keep the receiver demonstrably responsive at the decision boundary,
    // including if packet dispatch took longer than the usual local case.
    observed_heartbeat(nodes, 0).await;
    if !quiet {
        observed_heartbeat(nodes, 1).await;
    }
    assert_eq!(nodes[0].node.active_peer_needs_same_path_refresh(&b), quiet);
    assert!(!nodes[1].node.active_peer_needs_same_path_refresh(&a));
    assert_eq!(owner(&nodes[0], &b), old_a);
    assert_eq!(owner(&nodes[1], &a), old_b);
    nodes[0].node.handle_msg2(response).await;
    if quiet {
        assert_ne!(
            owner(&nodes[0], &b).our,
            old_a.our,
            "quiet A selected fresh keys"
        );
        assert_eq!(
            nodes[0].node.get_peer(&b).unwrap().their_index(),
            Some(candidate_index)
        );
        let proof = next_matching(&mut nodes[1], |packet| {
            FmpWireHeader::parse_encrypted(packet.data.as_slice())
                .is_ok_and(|header| header.receiver_idx() == candidate_index.as_u32())
        })
        .await;
        let header = FmpWireHeader::parse_encrypted(proof.data.as_slice()).unwrap();
        let offset = usize::from(header.ciphertext_offset());
        assert!(
            nodes[1]
                .node
                .get_connection(&candidate)
                .unwrap()
                .session()
                .unwrap()
                .authenticate_with_counter_and_aad(
                    &proof.data.as_slice()[offset..],
                    header.counter(),
                    &proof.data.as_slice()[..offset]
                )
                .is_ok(),
            "the actual initiator confirmation authenticates under B's retained candidate"
        );
        process_dataplane_packet(&mut nodes[1], proof).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while nodes[1].node.get_connection(&candidate).is_some() {
                process_dataplane_completions(&mut nodes[1].node).await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fresh candidate proof reaches the promotion decision");
        assert_eq!(
            nodes[1].node.get_peer(&a).unwrap().our_index(),
            Some(candidate_index),
            "fresh same-path proof must align B with the quiet initiator's chosen keys; B's old carrier being locally responsive is not proof that A retained it"
        );
    } else {
        assert_eq!(
            owner(&nodes[0], &b),
            old_a,
            "a healthy duplicate cannot select fresh keys"
        );
        assert_eq!(owner(&nodes[1], &a), old_b);
    }

    // Authentication of both actual FMP directions is necessary: direct FSP
    // payload alone can otherwise hide mismatched link keys.
    quiesce(nodes).await;
    heartbeat(nodes, 0).await;
    heartbeat(nodes, 1).await;
    quiesce(nodes).await;
    assert_pair(nodes);
    if quiet {
        // Full replacement keeps the old receive epoch for its drain window.
        assert_eq!(resources(&nodes[0]), (1, 0, 1, 2));
        assert_eq!(resources(&nodes[1]), (1, 0, 1, 2));
    } else {
        assert_eq!(owner(&nodes[0], &b), old_a);
        assert_eq!(owner(&nodes[1], &a), old_b);
        assert!(nodes[1].node.get_connection(&candidate).is_some());
    }
    deliver_both_directions(nodes).await;
    if quiet {
        // Disabling new periodic rekeys must not disable retirement of old
        // keys from a completed full-handshake replacement.
        let deadline = Duration::from_secs(12); // Normal ten-second FMP drain plus margin.
        tokio::time::timeout(deadline, async {
            while resources(&nodes[0]).3 > 1 || resources(&nodes[1]).3 > 1 {
                for node in nodes.iter_mut() {
                    node.node.check_rekey().await;
                }
                heartbeat(nodes, 0).await;
                heartbeat(nodes, 1).await;
                quiesce(nodes).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("ordinary maintenance must retire both old receive indices");
        assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
        assert_eq!(resources(&nodes[1]), (1, 0, 1, 1));
        assert!(!nodes[0].node.index_allocator.is_allocated(old_a.our));
        assert!(!nodes[1].node.index_allocator.is_allocated(old_b.our));
        assert_pair(nodes);
        deliver_both_directions(nodes).await;
    }
}

async fn deliver_both_directions(nodes: &mut [TestNode; 2]) {
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.node.attach_endpoint_data_io(8).unwrap())
        .collect();
    for (source, destination, payload) in [
        (0, 1, b"same-path-out".as_slice()),
        (1, 0, b"same-path-back".as_slice()),
    ] {
        let peer = PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
        send_endpoint_data_via_dataplane(&mut nodes[source].node, peer, payload.to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoints[destination].event_rx,
            Duration::from_secs(2),
            "same-path bidirectional payload",
        )
        .await;
        endpoints[destination]
            .event_rx
            .release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            payload
        );
    }
    quiesce(nodes).await;
    for endpoint in &mut endpoints {
        assert!(matches!(
            endpoint.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}
