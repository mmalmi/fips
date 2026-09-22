//! Fresh demand may recover an incomplete probe budget without reviving expiry.
use super::wire_tap::WireTap;
use super::*;
use crate::protocol::{FilterAnnounce, LinkMessageType};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

const PARENT: usize = 0;
const SOURCE: usize = 1;
const TARGET: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    LateReplyLoss,
    Offline,
    Unanswered,
}

#[test]
fn fresh_payload_recovers_after_one_late_lookup_reply_is_lost() {
    run(Case::LateReplyLoss);
}

#[test]
fn absent_target_keeps_backoff_after_an_unsent_ladder() {
    run(Case::Offline);
}

#[test]
fn fully_sent_unanswered_ladder_keeps_backoff_for_fresh_demand() {
    run(Case::Unanswered);
}

fn run(case: Case) {
    run_large_stack_async_test("late-lookup-reply-loss", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..3 {
            nodes.push(make_test_node().await);
        }
        // P remains root; S cannot learn sibling T's coordinates from ancestry.
        nodes.sort_by_key(|test| *test.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes, case))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[derive(Debug, Default)]
struct Witness {
    requests: Vec<(u64, u64)>,
    replies: Vec<(u64, u64, bool)>,
    target_filters: usize,
}

fn taps(nodes: &mut [TestNode], case: Case, witness: &Arc<Mutex<Witness>>) -> [WireTap; 2] {
    let target = PeerIdentity::from_pubkey_full(nodes[TARGET].node.identity().pubkey_full());
    let source = *nodes[SOURCE].node.node_addr();
    let root = *nodes[PARENT].node.node_addr();
    let observed = witness.clone();
    let requests = WireTap::start(nodes, PARENT, SOURCE, move |message, received_ms| {
        if message[0] == LinkMessageType::LookupRequest.to_byte() {
            let request = LookupRequest::decode(&message[1..]).unwrap();
            assert_eq!(request.origin, source);
            assert_eq!(request.target, *target.node_addr());
            let mut witness = observed.lock().unwrap();
            assert!(
                witness.requests.len() < 8,
                "two four-request lookups bound the trace"
            );
            witness.requests.push((request.request_id, received_ms));
        }
        true
    });
    let observed = witness.clone();
    let replies = WireTap::start(nodes, SOURCE, PARENT, move |message, received_ms| {
        let mut witness = observed.lock().unwrap();
        if message[0] == LinkMessageType::LookupResponse.to_byte() {
            let response = LookupResponse::decode(&message[1..]).unwrap();
            assert_eq!(response.target, *target.node_addr());
            assert_eq!(*response.target_coords.root_id(), root);
            let proof = LookupResponse::proof_bytes(
                response.request_id,
                &response.target,
                &response.target_coords,
            );
            assert!(
                target.verify(&proof, &response.proof),
                "genuine target-signed reply"
            );
            assert!(
                witness
                    .requests
                    .iter()
                    .any(|(id, _)| *id == response.request_id)
            );
            let drop = case == Case::Unanswered || witness.replies.is_empty();
            assert!(witness.replies.len() < 8, "bounded complete reply trace");
            witness
                .replies
                .push((response.request_id, received_ms, drop));
            return !drop;
        }
        if message[0] == LinkMessageType::FilterAnnounce.to_byte()
            && FilterAnnounce::decode(&message[1..])
                .unwrap()
                .filter
                .contains(target.node_addr())
        {
            witness.target_filters += 1;
        }
        true
    });
    [requests, replies]
}

async fn dial(nodes: &mut [TestNode], child: usize, remote: TransportAddr, identity: PeerIdentity) {
    let child = &mut nodes[child];
    child
        .node
        .initiate_connection(child.transport_id, remote, identity)
        .await
        .unwrap();
}

fn owners(nodes: &[TestNode]) -> Vec<PeerOwner> {
    [(SOURCE, PARENT), (PARENT, SOURCE)]
        .into_iter()
        .map(|(local, remote)| {
            let peer = nodes[local]
                .node
                .get_peer(nodes[remote].node.node_addr())
                .unwrap();
            assert!(peer.is_healthy() && peer.can_send());
            (
                *peer.node_addr(),
                peer.link_id(),
                peer.our_index(),
                peer.session_generation(),
            )
        })
        .collect()
}

async fn exercise(nodes: &mut [TestNode], case: Case) {
    let defaults = Config::new();
    for test in nodes.iter_mut() {
        test.node.config.node.rate_limit = defaults.node.rate_limit.clone();
        test.node.config.node.bloom = defaults.node.bloom.clone();
        test.node
            .bloom_state
            .set_update_debounce_ms(defaults.node.bloom.update_debounce_ms);
        test.node.config.node.discovery.lan.enabled = false;
        assert_eq!(
            test.node.config.node.discovery.attempt_timeouts_secs,
            [1, 2, 4, 8]
        );
        assert_eq!(test.node.config.node.discovery.forward_min_interval_secs, 2);
        assert_eq!(test.node.config.node.tree.announce_min_interval_ms, 500);
        assert_eq!(test.node.config.node.session.pending_max_destinations, 256);
    }
    let parent = PeerIdentity::from_pubkey_full(nodes[PARENT].node.identity().pubkey_full());
    let remote = nodes[PARENT].addr.clone();
    let target = *nodes[TARGET].node.node_addr();
    dial(nodes, SOURCE, remote.clone(), parent).await;
    if case == Case::Unanswered {
        dial(nodes, TARGET, remote.clone(), parent).await;
    }
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        turn(nodes).await;
        let ready = nodes[SOURCE]
            .node
            .get_peer(parent.node_addr())
            .is_some_and(|peer| {
                peer.filter_sequence() > 0 && peer.may_reach(&target) == (case == Case::Unanswered)
            });
        if ready
            && nodes[SOURCE].node.tree_state().root() == parent.node_addr()
            && nodes[PARENT]
                .node
                .is_tree_peer(nodes[SOURCE].node.node_addr())
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "real source-parent tree/filter setup"
        );
    }
    let original_owners = owners(nodes);
    let witness = Arc::new(Mutex::new(Witness::default()));
    let taps = taps(nodes, case, &witness);
    let actor = rx_loop::Transit::start(&mut nodes[PARENT]).await;
    let result = AssertUnwindSafe(traffic(nodes, case, parent, remote, &witness))
        .catch_unwind()
        .await;
    actor.restore(&mut nodes[PARENT]).await;
    for tap in taps {
        tap.restore(nodes).await;
    }
    assert_eq!(
        owners(nodes),
        original_owners,
        "original carrier ownership survives"
    );
    eprintln!(
        "late reply loss: case={case:?}, witness={:?}",
        witness.lock().unwrap()
    );
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn traffic(
    nodes: &mut [TestNode],
    case: Case,
    parent: PeerIdentity,
    remote: TransportAddr,
    witness: &Arc<Mutex<Witness>>,
) {
    let destination = PeerIdentity::from_pubkey_full(nodes[TARGET].node.identity().pubkey_full());
    let target = *destination.node_addr();
    let _source_io = nodes[SOURCE].node.attach_endpoint_data_io(8).unwrap();
    let mut target_io = nodes[TARGET].node.attach_endpoint_data_io(8).unwrap();
    send_endpoint_data_via_dataplane(
        &mut nodes[SOURCE].node,
        destination,
        b"original expires before fresh demand".to_vec(),
    )
    .await
    .unwrap();
    let initiated = nodes[SOURCE]
        .node
        .pending_lookups
        .get(&target)
        .unwrap()
        .initiated_ms;
    let mut attempts = Vec::new();
    let mut final_phase = None;
    let mut joined = false;
    while let Some(entry) = nodes[SOURCE].node.pending_lookups.get(&target) {
        assert_eq!(entry.initiated_ms, initiated);
        if attempts
            .last()
            .is_none_or(|(attempt, _)| *attempt != entry.attempt)
        {
            attempts.push((entry.attempt, entry.last_sent_ms));
        }
        if entry.attempt == 4 {
            let state = (entry.last_sent_ms, entry.deadline_ms(&[1, 2, 4, 8]));
            assert_eq!(
                *final_phase.get_or_insert(state),
                state,
                "original expiry never moves"
            );
            if case == Case::LateReplyLoss && !joined && Node::now_ms() >= state.1 - 2_000 {
                assert!(entry.awaiting_first_request());
                joined = true;
                dial(nodes, TARGET, remote.clone(), parent).await;
            }
        }
        assert!(
            Node::now_ms() < initiated + 16_000,
            "original ladder remains bounded"
        );
        turn(nodes).await;
        assert!(
            target_io.event_rx.try_recv().is_err(),
            "original is never delivered"
        );
        assert_eq!(nodes[SOURCE].node.tree_state().root(), parent.node_addr());
    }
    assert_eq!(
        attempts
            .iter()
            .map(|(attempt, _)| *attempt)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    for (pair, delay) in attempts.windows(2).zip([1_000, 2_000, 4_000]) {
        assert!(pair[1].1 >= pair[0].1 + delay, "normal retry phase spacing");
    }
    let (_, expiry) = final_phase.unwrap();
    assert!(Node::now_ms() >= expiry);
    assert_eq!(nodes[SOURCE].node.stats().discovery.resp_timed_out, 1);
    assert!(
        !nodes[SOURCE]
            .node
            .pending_session_traffic
            .has_traffic_for(&target)
    );
    assert!(nodes[SOURCE].node.get_session(&target).is_none());
    assert!(nodes[SOURCE].node.discovery_backoff.is_suppressed(&target));
    assert_eq!(
        nodes[SOURCE].node.discovery_backoff.failure_count(&target),
        1
    );
    let sent = witness.lock().unwrap().requests.len();
    let expected = match case {
        Case::LateReplyLoss => 1,
        Case::Offline => 0,
        Case::Unanswered => 4,
    };
    assert_eq!(
        sent, expected,
        "actual wire requests differ from timer-only phases"
    );
    {
        let trace = witness.lock().unwrap();
        assert_eq!(
            trace
                .requests
                .iter()
                .map(|(id, _)| *id)
                .collect::<HashSet<_>>()
                .len(),
            sent
        );
        assert_eq!(trace.replies.len(), sent);
        assert!(trace.replies.iter().all(|(_, _, dropped)| *dropped));
        if case == Case::LateReplyLoss {
            assert!(trace.requests[0].1 >= expiry - 2_000);
            assert!(
                trace.replies[0].1 < expiry,
                "first genuine signed reply was lost before expiry"
            );
        }
    }
    let filters = witness.lock().unwrap().target_filters;
    let until = Instant::now() + Duration::from_secs(7);
    loop {
        turn(nodes).await;
        assert!(nodes[SOURCE].node.pending_lookups.get(&target).is_none());
        assert!(
            !nodes[SOURCE]
                .node
                .pending_session_traffic
                .has_traffic_for(&target)
        );
        assert_eq!(
            witness.lock().unwrap().requests.len(),
            sent,
            "hints alone cannot restart discovery"
        );
        assert!(target_io.event_rx.try_recv().is_err());
        if case != Case::LateReplyLoss || witness.lock().unwrap().target_filters > filters {
            break;
        }
        assert!(
            Instant::now() < until,
            "ordinary periodic reachability refresh arrives"
        );
    }
    let fresh = b"fresh payload owns a distinct bounded lookup";
    send_endpoint_data_via_dataplane(&mut nodes[SOURCE].node, destination, fresh.to_vec())
        .await
        .unwrap();
    if case != Case::LateReplyLoss {
        assert!(
            nodes[SOURCE].node.pending_lookups.get(&target).is_none(),
            "offline or fully tried target stays suppressed"
        );
        let until = Instant::now() + Duration::from_millis(1_100);
        while Instant::now() < until {
            turn(nodes).await;
        }
        assert_eq!(witness.lock().unwrap().requests.len(), sent);
        assert!(target_io.event_rx.try_recv().is_err());
        assert_eq!(
            nodes[SOURCE].node.discovery_backoff.failure_count(&target),
            1
        );
        return;
    }
    let pending =
        nodes[SOURCE].node.pending_lookups.get(&target).expect(
            "fresh demand retries an incomplete wire budget without waiting thirty seconds",
        );
    assert!(pending.initiated_ms > expiry);
    assert_eq!(pending.attempt, 1);
    assert_eq!(
        nodes[SOURCE].node.discovery_backoff.failure_count(&target),
        1,
        "mere retry admission does not erase failure history"
    );
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        turn(nodes).await;
        if let Ok(event) = target_io.event_rx.try_recv() {
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                fresh
            );
            break;
        }
        assert!(
            Instant::now() < until,
            "fresh request recovers over the original carriers"
        );
    }
    {
        let trace = witness.lock().unwrap();
        assert!(
            (1..=4).contains(&(trace.requests.len() - sent)),
            "new lookup retains its own wire budget"
        );
        assert_eq!(
            trace
                .requests
                .iter()
                .map(|(id, _)| *id)
                .collect::<HashSet<_>>()
                .len(),
            trace.requests.len(),
            "fresh demand cannot reuse an expired request ID"
        );
        assert!(trace.replies.iter().skip(1).any(|(_, _, dropped)| !dropped));
    }
    assert_eq!(
        nodes[SOURCE].node.discovery_backoff.failure_count(&target),
        0
    );
    let until = Instant::now() + Duration::from_millis(250);
    while Instant::now() < until {
        turn(nodes).await;
        assert!(
            target_io.event_rx.try_recv().is_err(),
            "old or duplicate originals remain absent"
        );
    }
}
