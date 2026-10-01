//! Crossed full-roster dials must meet within their existing retry budgets.
//! Withholding real received packets models a lost winning request. Only the
//! crossed-request handler runs during the prompt-response observation window.
use super::*;
use crate::node::acl::{PeerAclContext, PeerAclReloader};
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use crate::node::wire::Msg1Header;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[path = "rotation_crossed_resend_control.rs"]
mod readiness_control;

#[derive(Clone, Copy)]
enum ResendBudget {
    Available,
    BeyondDeadline,
    EarlierScheduled,
    Exhausted,
    RejectedBeforeValid,
    Expired,
}

#[test]
fn crossed_full_roster_msg1_prompts_one_bounded_owned_resend_after_backoff() {
    run_crossed_resend(ResendBudget::Available);
}

#[test]
fn crossed_full_roster_msg1_uses_remaining_credit_before_backoff_outlives_attempt() {
    run_crossed_resend(ResendBudget::BeyondDeadline);
}

#[test]
fn crossed_full_roster_early_resend_preserves_the_earlier_scheduled_retry() {
    run_crossed_resend(ResendBudget::EarlierScheduled);
}

#[test]
fn crossed_full_roster_msg1_cannot_exceed_existing_resend_limit() {
    run_crossed_resend(ResendBudget::Exhausted);
}

#[test]
fn crossed_full_roster_invalid_and_denied_requests_preserve_one_use_resend() {
    run_crossed_resend(ResendBudget::RejectedBeforeValid);
}

#[test]
fn crossed_full_roster_expired_attempt_cannot_emit_or_renew_after_timeout_increase() {
    run_crossed_resend(ResendBudget::Expired);
}

fn run_crossed_resend(budget: ResendBudget) {
    run_large_stack_async_test("rotation-crossed-reactive-resend", move || async move {
        let mut nodes = [make_test_node().await, make_test_node().await];
        // Select the ordinary deterministic winner; no identity search.
        if nodes[0].node.node_addr() > nodes[1].node.node_addr() {
            nodes.swap(0, 1);
        }
        let result = AssertUnwindSafe(exercise_crossed_resend(&mut nodes, budget))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

struct FrozenAttempt {
    link: LinkId,
    index: SessionIndex,
    started: u64,
    activity: u64,
    attempt: u64,
    deadline: u64,
}

impl FrozenAttempt {
    fn capture(node: &TestNode, remote: &NodeAddr) -> Self {
        let conn = node.node.peers.connection_values().next().unwrap();
        assert!(conn.is_outbound());
        assert_eq!(conn.expected_identity().unwrap().node_addr(), remote);
        assert_eq!(
            conn.handshake_state(),
            crate::peer::HandshakeState::SentMsg1
        );
        Self {
            link: conn.link_id(),
            index: conn.our_index().unwrap(),
            started: conn.started_at(),
            activity: conn.last_activity(),
            attempt: node.node.neighbor_rotation_started_at(remote).unwrap(),
            deadline: node.node.neighbor_rotation_deadline(remote).unwrap(),
        }
    }

    fn assert_unchanged(&self, node: &TestNode, remote: &NodeAddr) {
        self.assert_owned(node, remote);
        assert!(Node::now_ms() < self.deadline);
    }

    fn assert_owned(&self, node: &TestNode, remote: &NodeAddr) {
        let conn = node.node.get_connection(&self.link).unwrap();
        assert!(conn.is_outbound());
        assert_eq!(conn.expected_identity().unwrap().node_addr(), remote);
        assert_eq!(conn.our_index(), Some(self.index));
        assert_eq!(conn.started_at(), self.started);
        assert_eq!(conn.last_activity(), self.activity);
        assert_eq!(
            conn.handshake_state(),
            crate::peer::HandshakeState::SentMsg1
        );
        assert_eq!(
            node.node.neighbor_rotation_started_at(remote),
            Some(self.attempt)
        );
        assert_eq!(
            node.node.neighbor_rotation_deadline(remote),
            Some(self.deadline)
        );
        assert!(node.node.index_allocator.is_allocated(self.index));
        assert!(
            node.node
                .pending_outbound
                .contains_key(&(node.transport_id, self.index.as_u32()))
        );
        assert_eq!(resources(node), (1, 1, 2, 2));
    }
}

async fn native_dial(nodes: &mut [TestNode; 2], source: usize, destination: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
    let address = nodes[destination].addr.clone();
    let node = &mut nodes[source];
    node.node
        .initiate_connection(node.transport_id, address, identity)
        .await
        .unwrap();
}

async fn receive_request(node: &mut TestNode, timeout: Duration) -> ReceivedPacket {
    let packet = tokio::time::timeout(timeout, node.packet_rx.recv())
        .await
        .expect("an actual owned Noise Msg1 must arrive before scheduled retry")
        .unwrap();
    assert!(Msg1Header::parse(packet.data.as_slice()).is_some());
    packet
}

async fn wait_for_ms(deadline: u64) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while Node::now_ms() < deadline {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the configured resend timer must become due in real time");
}

async fn assert_no_spent_resend(
    nodes: &mut [TestNode; 2],
    winner: &FrozenAttempt,
    remote: &NodeAddr,
    next_due: u64,
) {
    assert!(
        tokio::time::timeout(Duration::from_millis(100), nodes[1].packet_rx.recv())
            .await
            .is_err(),
        "rejected requests must not emit an owned Msg1 or a new Msg2"
    );
    winner.assert_owned(&nodes[0], remote);
    let conn = nodes[0].node.get_connection(&winner.link).unwrap();
    assert_eq!(
        conn.resend_count(),
        1,
        "only the scheduled resend was spent"
    );
    assert_eq!(conn.next_resend_at_ms(), next_due);
}

// Promotion finishes Noise ownership before the first encrypted receive completes.
fn crossed_peers_authenticated(nodes: &[TestNode; 2], ids: &[NodeAddr; 2]) -> bool {
    nodes.iter().enumerate().all(|(i, node)| {
        node.node.get_peer(&ids[1 - i]).is_some()
            && node.node.connection_count() == 0
            && node
                .node
                .dataplane_fmp_link_metrics(&ids[1 - i], Instant::now())
                .is_some_and(|metrics| metrics.current_epoch_authenticated)
    })
}

async fn exercise_crossed_resend(nodes: &mut [TestNode; 2], budget: ResendBudget) {
    let old = [make_node(), make_node()];
    let paths = [local_path().await, local_path().await];
    let mut old_owners = Vec::new();
    for i in 0..2 {
        old_owners.push(incumbent(&mut nodes[i], &old[i], &paths[i].1, 801, 0).await);
        enable(&mut nodes[i], 1);
        let config = &mut nodes[i].node.config.node;
        config.neighbor_rotation = Some(NeighborRotationConfig {
            idle_secs: 1,
            interval_secs: 1,
        });
        config.rekey.enabled = false;
        config.rate_limit.handshake_timeout_secs = if matches!(budget, ResendBudget::Expired) {
            3
        } else {
            6
        };
        config.rate_limit.handshake_resend_interval_ms = 400;
        config.rate_limit.handshake_resend_backoff = 4.0;
        config.rate_limit.handshake_max_resends = match budget {
            ResendBudget::Exhausted => 1,
            _ => 4,
        };
    }
    // All incumbent sessions and ages come from real Noise and elapsed time.
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    let ids = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    assert!(crate::peer::cross_connection_winner(&ids[0], &ids[1], true));

    native_dial(nodes, 0, 1).await;
    let first = receive_request(&mut nodes[1], Duration::from_secs(1)).await;
    let winner = FrozenAttempt::capture(&nodes[0], &ids[1]);
    assert_eq!(
        Msg1Header::parse(first.data.as_slice()).unwrap().sender_idx,
        winner.index
    );
    let first_due = nodes[0]
        .node
        .get_connection(&winner.link)
        .unwrap()
        .next_resend_at_ms();
    wait_for_ms(first_due).await;
    nodes[0]
        .node
        .resend_pending_handshakes(Node::now_ms())
        .await;
    let scheduled = receive_request(&mut nodes[1], Duration::from_secs(1)).await;
    assert_eq!(scheduled.data.as_slice(), first.data.as_slice());
    let mut scheduled_at = tokio::time::Instant::now();
    let conn = nodes[0].node.get_connection(&winner.link).unwrap();
    assert_eq!(
        conn.resend_count(),
        1,
        "consume a genuine scheduled resend first"
    );
    let mut next_due = conn.next_resend_at_ms();
    let resends_before = if matches!(budget, ResendBudget::BeyondDeadline) {
        wait_for_ms(next_due).await;
        nodes[0]
            .node
            .resend_pending_handshakes(Node::now_ms())
            .await;
        let scheduled = receive_request(&mut nodes[1], Duration::from_secs(1)).await;
        assert_eq!(scheduled.data.as_slice(), first.data.as_slice());
        scheduled_at = tokio::time::Instant::now();
        let conn = nodes[0].node.get_connection(&winner.link).unwrap();
        assert_eq!(conn.resend_count(), 2);
        next_due = conn.next_resend_at_ms();
        assert!(
            next_due > winner.deadline,
            "ordinary backoff now outlives the attempt"
        );
        2
    } else {
        1
    };
    winner.assert_unchanged(&nodes[0], &ids[1]);

    // Neither real winning request reaches its handler. Allow more than the
    // base resend interval to pass, while the exponential retry is still far
    // away; no timestamp or scheduling field is changed by this fixture.
    tokio::time::sleep_until(scheduled_at + Duration::from_millis(450)).await;
    native_dial(nodes, 1, 0).await;
    let crossed = receive_request(&mut nodes[0], Duration::from_secs(1)).await;
    let loser = FrozenAttempt::capture(&nodes[1], &ids[0]);
    assert_eq!(crossed.remote_addr, nodes[1].addr);
    assert_eq!(
        Msg1Header::parse(crossed.data.as_slice())
            .unwrap()
            .sender_idx,
        loser.index
    );
    assert!(
        next_due.saturating_sub(Node::now_ms()) > 700,
        "the prompt response must be distinguishable from the scheduled retry"
    );
    if matches!(budget, ResendBudget::RejectedBeforeValid) {
        // Keep the actual header/source/index, but corrupt the authenticated
        // Noise body. The original valid request remains available below.
        let mut invalid = crossed.clone();
        let mut wire = invalid.data.as_slice().to_vec();
        *wire.last_mut().unwrap() ^= 1;
        invalid.data = PacketBuffer::new(wire);
        nodes[0].node.handle_msg1(invalid).await;
        assert_no_spent_resend(nodes, &winner, &ids[1], next_due).await;

        // Use the real ACL boundary after cryptographic authentication. A
        // rejected request must not silently consume the reactive allowance.
        let acl = tempfile::tempdir().unwrap();
        let allow = acl.path().join("peers.allow");
        let deny = acl.path().join("peers.deny");
        std::fs::write(&allow, "").unwrap();
        std::fs::write(&deny, nodes[1].node.identity.npub()).unwrap();
        nodes[0].node.peer_acl = PeerAclReloader::with_paths(allow.clone(), deny.clone());
        let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity.pubkey_full());
        assert!(
            nodes[0]
                .node
                .authorize_peer(
                    &identity,
                    PeerAclContext::InboundHandshake,
                    crossed.transport_id,
                    &crossed.remote_addr,
                )
                .is_err()
        );
        nodes[0].node.handle_msg1(crossed.clone()).await;
        assert_no_spent_resend(nodes, &winner, &ids[1], next_due).await;

        // Reload supported ACL files explicitly; filesystem polling latency is
        // not part of this handshake test. All peers are now permitted.
        std::fs::write(&deny, "").unwrap();
        nodes[0].node.peer_acl = PeerAclReloader::with_paths(allow, deny);
        assert!(
            nodes[0]
                .node
                .authorize_peer(
                    &identity,
                    PeerAclContext::InboundHandshake,
                    crossed.transport_id,
                    &crossed.remote_addr,
                )
                .is_ok()
        );
        // Continue the same successful wire/index/payload assertions as the
        // positive case: either premature consumption now makes it fail.
    }

    if matches!(budget, ResendBudget::Expired) {
        // Existing attempts keep their original deadline when live config
        // changes. Leave timeout cleanup unpolled until the crossed handler
        // itself has rejected this valid request at the frozen deadline.
        nodes[0].node.config.node.rate_limit.handshake_timeout_secs = 60;
        wait_for_ms(winner.deadline + 25).await;
        assert!(Node::now_ms() >= winner.deadline);
        nodes[0].node.handle_msg1(crossed).await;
        assert_no_spent_resend(nodes, &winner, &ids[1], next_due).await;
        nodes[0].node.check_timeouts().await;
        assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
        assert!(!nodes[0].node.index_allocator.is_allocated(winner.index));
        assert!(nodes[0].node.pending_outbound.is_empty());
        assert_eq!(
            nodes[0]
                .node
                .get_peer(old[0].node_addr())
                .unwrap()
                .our_index(),
            Some(old_owners[0].index)
        );
        assert_eq!(
            heartbeat(&mut nodes[0], &old[0], &mut old_owners[0], 2).await,
            2
        );
        return;
    }

    let replay = crossed.clone();
    nodes[0].node.handle_msg1(crossed).await;
    winner.assert_unchanged(&nodes[0], &ids[1]);
    loser.assert_unchanged(&nodes[1], &ids[0]);

    if matches!(budget, ResendBudget::Exhausted) {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), nodes[1].packet_rx.recv())
                .await
                .is_err(),
            "a crossed request cannot create another resend after the shared budget is exhausted"
        );
        assert_eq!(
            nodes[0]
                .node
                .get_connection(&winner.link)
                .unwrap()
                .resend_count(),
            1
        );
        winner.assert_unchanged(&nodes[0], &ids[1]);
        for i in 0..2 {
            assert_eq!(
                heartbeat(&mut nodes[i], &old[i], &mut old_owners[i], 2).await,
                2
            );
        }
        return;
    }

    // No scheduled retry is polled here; only the crossed request can prompt
    // the still-owned message before its ordinary backoff expires.
    let prompt = receive_request(&mut nodes[1], Duration::from_millis(200)).await;
    assert_eq!(prompt.remote_addr, nodes[0].addr);
    assert_eq!(prompt.transport_id, nodes[1].transport_id);
    assert_eq!(
        prompt.data.as_slice(),
        first.data.as_slice(),
        "reactive response must reuse the exact owned request/index/Noise state"
    );
    assert_eq!(
        nodes[0]
            .node
            .get_connection(&winner.link)
            .unwrap()
            .resend_count(),
        resends_before + 1
    );
    winner.assert_unchanged(&nodes[0], &ids[1]);

    for _ in 0..16 {
        nodes[0].node.handle_msg1(replay.clone()).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), nodes[1].packet_rx.recv())
            .await
            .is_err(),
        "replayed crossed requests must not drain the remaining resend budget in a burst"
    );
    assert_eq!(
        nodes[0]
            .node
            .get_connection(&winner.link)
            .unwrap()
            .resend_count(),
        resends_before + 1
    );
    winner.assert_unchanged(&nodes[0], &ids[1]);
    loser.assert_unchanged(&nodes[1], &ids[0]);

    // One-use is stronger than a short rate limit: another replay after the
    // base interval must not earn a second early response either.
    tokio::time::sleep(Duration::from_millis(450)).await;
    nodes[0].node.handle_msg1(replay).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), nodes[1].packet_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        nodes[0]
            .node
            .get_connection(&winner.link)
            .unwrap()
            .resend_count(),
        resends_before + 1
    );
    winner.assert_unchanged(&nodes[0], &ids[1]);
    loser.assert_unchanged(&nodes[1], &ids[0]);

    let prompt = if matches!(budget, ResendBudget::EarlierScheduled) {
        // Lose the early packet. Ordinary maintenance must still use the
        // already-scheduled opportunity, without granting another retry credit.
        wait_for_ms(next_due).await;
        nodes[0]
            .node
            .resend_pending_handshakes(Node::now_ms())
            .await;
        let scheduled = receive_request(&mut nodes[1], Duration::from_millis(200)).await;
        assert_eq!(scheduled.data.as_slice(), prompt.data.as_slice());
        assert_eq!(
            nodes[0]
                .node
                .get_connection(&winner.link)
                .unwrap()
                .resend_count(),
            3
        );
        winner.assert_unchanged(&nodes[0], &ids[1]);
        scheduled
    } else {
        prompt
    };

    // The delayed peer now gets the still-owned request, resolves its losing
    // half normally, and responds. No incumbent is removed by Msg1 alone.
    nodes[1].node.handle_msg1(prompt).await;
    assert!(!nodes[1].node.index_allocator.is_allocated(loser.index));
    assert_eq!(
        nodes[1].node.neighbor_rotation_deadline(&ids[0]),
        Some(loser.deadline)
    );
    for i in 0..2 {
        assert_eq!(
            nodes[i]
                .node
                .get_peer(old[i].node_addr())
                .unwrap()
                .our_index(),
            Some(old_owners[i].index)
        );
        assert_eq!(resources(&nodes[i]), (1, 1, 2, 2));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            process_available_packets(nodes).await;
            for node in nodes.iter_mut() {
                assert_eq!(node.node.peer_count(), 1);
                assert!(node.node.connection_count() <= 1);
                assert!(node.node.link_count() <= 2);
                assert!(node.node.index_allocator.count() <= 2);
            }
            if crossed_peers_authenticated(nodes, &ids) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("crossed peers must authenticate without waiting for another scheduled Msg1");
    for i in 0..2 {
        assert_eq!(resources(&nodes[i]), (1, 0, 1, 1));
        assert!(nodes[i].node.get_peer(old[i].node_addr()).is_none());
        assert!(
            !nodes[i]
                .node
                .index_allocator
                .is_allocated(old_owners[i].index)
        );
        assert!(nodes[i].node.pending_outbound.is_empty());
        let peer = nodes[i].node.get_peer(&ids[1 - i]).unwrap();
        let other = nodes[1 - i].node.get_peer(&ids[i]).unwrap();
        assert_eq!(peer.our_index(), other.their_index());
        assert_eq!(peer.their_index(), other.our_index());
        assert_eq!(peer.remote_epoch(), Some(nodes[1 - i].node.startup_epoch));
        assert!(
            nodes[i]
                .node
                .dataplane_fmp_link_metrics(&ids[1 - i], Instant::now())
                .unwrap()
                .current_epoch_authenticated
        );
    }
    assert_eq!(
        nodes[0].node.get_peer(&ids[1]).unwrap().our_index(),
        Some(winner.index)
    );

    let mut endpoints = [
        nodes[0].node.attach_endpoint_data_io(8).unwrap(),
        nodes[1].node.attach_endpoint_data_io(8).unwrap(),
    ];
    for (source, destination) in [(0, 1), (1, 0)] {
        let identity =
            PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
        let payload = vec![91 + source as u8; 64];
        send_endpoint_data_via_dataplane(&mut nodes[source].node, identity, payload.clone())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoints[destination].event_rx,
            Duration::from_secs(2),
            "payload after bounded crossed-request response",
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
}
