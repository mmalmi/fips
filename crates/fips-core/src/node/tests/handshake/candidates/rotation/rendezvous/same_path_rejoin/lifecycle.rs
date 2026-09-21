//! Real queued traffic survives elective removal, but normal idle expiry still owns it.
use super::*;

pub(super) const IDLE_SECS: u64 = 4;
const QUEUED_SEQUENCE: u8 = u8::MAX;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Scenario {
    RejoinWithHistory,
    RejoinIdle,
    QueuedRecovery,
    QueuedExpiry,
}

#[test]
fn queued_original_delivers_once_after_real_rotation_and_rejoin() {
    run(Scenario::QueuedRecovery);
}

#[test]
fn retained_session_and_real_queued_payload_expire_while_useful_peer_progresses() {
    run(Scenario::QueuedExpiry);
}

pub(super) struct QueuedPayload {
    pub(super) allow_delivery: bool,
    delivered_at: Option<tokio::time::Instant>,
}

impl Pump {
    /// Preserve the ordinary round's strict checks while independently observing
    /// the single payload offered before rejoin. Useful traffic never resends it.
    pub(super) fn receive(
        &mut self,
        endpoints: &mut [EndpointDataIo],
        ids: &[PeerIdentity],
        sequence: u8,
        flows: &[(usize, usize)],
        received: &mut Vec<(usize, usize)>,
    ) {
        assert_ne!(sequence, QUEUED_SEQUENCE);
        for (destination, endpoint) in endpoints.iter_mut().enumerate() {
            while let Ok(event) = endpoint.event_rx.try_recv() {
                let count = event.message_count();
                for message in event.messages {
                    let payload = message.payload.as_slice();
                    assert_eq!(payload.len(), 3);
                    if payload[0] == QUEUED_SEQUENCE {
                        assert_eq!(payload, &[QUEUED_SEQUENCE, 0, 1]);
                        assert_eq!(destination, 1);
                        assert_eq!(message.source_peer.node_addr(), ids[0].node_addr());
                        let queued = self
                            .queued
                            .as_mut()
                            .expect("only the offered queued original");
                        assert!(
                            queued.allow_delivery,
                            "queued original delivered before rejoin"
                        );
                        assert!(
                            queued.delivered_at.is_none(),
                            "queued original must arrive exactly once"
                        );
                        queued.delivered_at = Some(tokio::time::Instant::now());
                    } else {
                        assert_eq!(
                            payload[0], sequence,
                            "late packet from a prior observation turn"
                        );
                        let source = usize::from(payload[1]);
                        assert_eq!(usize::from(payload[2]), destination);
                        assert_eq!(message.source_peer.node_addr(), ids[source].node_addr());
                        assert!(flows.contains(&(source, destination)));
                        assert!(
                            !received.contains(&(source, destination)),
                            "no duplicate progress"
                        );
                        received.push((source, destination));
                    }
                }
                endpoint.event_rx.release_messages(count);
            }
        }
    }
}

pub(super) async fn queue_original(pump: &mut Pump, nodes: &mut [TestNode], ids: &[PeerIdentity]) {
    let before = fsp_history(nodes, ids);
    assert!(nodes[0].node.get_peer(ids[1].node_addr()).is_none());
    assert!(
        !nodes[0].node.has_application_next_hop(ids[1].node_addr()),
        "queue premise: actual rotation must leave application routing unavailable"
    );
    assert!(nodes[0].node.dataplane_has_fsp_owner(ids[1].node_addr()));
    assert!(
        !nodes[0]
            .node
            .pending_session_traffic
            .has_traffic_for(ids[1].node_addr())
    );
    pump.queued = Some(QueuedPayload {
        allow_delivery: false,
        delivered_at: None,
    });
    send_endpoint_data_via_dataplane(&mut nodes[0].node, ids[1], vec![QUEUED_SEQUENCE, 0, 1])
        .await
        .unwrap();
    assert_queued(nodes, ids);
    assert_fsp_history(nodes, ids, &before);
    for (at, current) in fsp_history(nodes, ids).iter().enumerate() {
        assert_eq!(
            current.counters, before[at].counters,
            "queueing is not carrier delivery"
        );
    }
}

pub(super) fn assert_queued(nodes: &[TestNode], ids: &[PeerIdentity]) {
    let node = &nodes[0].node;
    let remote = ids[1].node_addr();
    assert!(node.get_peer(remote).is_none());
    assert!(
        node.get_session(remote)
            .is_some_and(|session| session.is_established())
    );
    assert!(node.dataplane_has_fsp_owner(remote));
    assert!(!node.dataplane_application_route_ready(remote));
    assert_eq!(
        node.pending_session_traffic
            .endpoint_data_for(remote)
            .map_or(0, |q| q.len()),
        1
    );
}

pub(super) async fn await_queued_delivery(
    pump: &mut Pump,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u8,
) {
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(2);
    loop {
        let observed = pump.queued.as_ref().unwrap().delivered_at;
        if let Some(at) = observed
            && at <= deadline
        {
            eprintln!(
                "queued original recovery: {}",
                json!({
                    "observed_before_wait":at < started,
                    "delivery_after_wait_started_ms":at.saturating_duration_since(started).as_millis(),
                    "budget_ms":2000,
                })
            );
            break;
        }
        if observed.is_some() || tokio::time::Instant::now() >= deadline {
            eprintln!(
                "queued original recovery timeout: {}",
                json!({
                    "wait_elapsed_ms":started.elapsed().as_millis(),
                    "delivery_observed":observed.is_some(),
                    "delivery_after_wait_started_ms":observed.map(|at|at.saturating_duration_since(started).as_millis()),
                    "budget_ms":2000,
                })
            );
            delivery_snapshot(nodes, ids, "queued-recovery-timeout");
            panic!("original queued payload must be observed within the 2s recovery window");
        }
        // Each round completes its useful traffic before another round starts;
        // only normal maintenance/discovery/promotion may flush the queued item.
        round(pump, nodes, endpoints, ids, *sequence, &USEFUL).await;
        *sequence += 1;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !nodes[0]
            .node
            .pending_session_traffic
            .has_traffic_for(ids[1].node_addr())
    );
}

pub(super) async fn await_idle_expiry(
    pump: &mut Pump,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u8,
    protected: (LinkId, SessionIndex, u64),
) {
    let source = &nodes[0].node;
    let remote = ids[1].node_addr();
    let before_sessions = source.session_count();
    let before_peers = source.peer_count();
    let activity = source.dataplane.fsp_owner_activity(remote).unwrap();
    assert!(activity.has_recent_session_activity(Node::now_ms(), IDLE_SECS * 1000));
    assert!(!activity.has_stale_outbound_only_activity(Node::now_ms(), IDLE_SECS * 1000));
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(IDLE_SECS + 2);
    loop {
        round(pump, nodes, endpoints, ids, *sequence, &USEFUL).await;
        *sequence += 1;
        assert_eq!(owner(nodes, ids, 0, 2), protected);
        assert_eq!(nodes[0].node.peer_count(), before_peers);
        assert!(nodes[0].node.get_peer(remote).is_none());
        assert!(pump.queued.as_ref().unwrap().delivered_at.is_none());
        assert!(
            tokio::time::Instant::now() < deadline,
            "ordinary idle maintenance must retire retained session"
        );
        if nodes[0].node.get_session(remote).is_none() {
            break;
        }
        assert_queued(nodes, ids);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!nodes[0].node.dataplane_has_fsp_owner(remote));
    assert!(
        !nodes[0]
            .node
            .pending_session_traffic
            .has_traffic_for(remote)
    );
    assert_eq!(nodes[0].node.session_count() + 1, before_sessions);
    assert!(
        nodes[0]
            .node
            .get_session(ids[2].node_addr())
            .is_some_and(|s| s.is_established())
    );
    assert!(nodes[0].node.dataplane_has_fsp_owner(ids[2].node_addr()));
    // One further actual useful round also checks no late delivery survived expiry.
    round(pump, nodes, endpoints, ids, *sequence, &USEFUL).await;
    assert_eq!(owner(nodes, ids, 0, 2), protected);
    assert!(pump.queued.as_ref().unwrap().delivered_at.is_none());
    eprintln!(
        "retained FSP idle expiry: configured_secs={IDLE_SECS}, observed_after_queue_ms={}",
        started.elapsed().as_millis()
    );
}

#[derive(Clone, Copy)]
pub(super) struct FspHistory {
    created_ms: u64,
    epoch: (u64, bool, bool),
    pub(super) counters: (u64, u64, u64, u64),
}

pub(super) fn fsp_history(nodes: &[TestNode], ids: &[PeerIdentity]) -> [FspHistory; 2] {
    std::array::from_fn(|at| {
        let node = &nodes[at].node;
        let remote = ids[1 - at].node_addr();
        FspHistory {
            created_ms: node.get_session(remote).unwrap().created_at(),
            epoch: node.session_dataplane_epoch(remote).unwrap(),
            counters: node.session_dataplane_counters(remote),
        }
    })
}

pub(super) fn assert_fsp_history(
    nodes: &[TestNode],
    ids: &[PeerIdentity],
    original: &[FspHistory; 2],
) {
    for (at, current) in fsp_history(nodes, ids).iter().enumerate() {
        assert_eq!(current.created_ms, original[at].created_ms);
        assert_eq!(
            current.epoch, original[at].epoch,
            "rotation must not reset FSP keys/epoch"
        );
        let (tx, rx, tx_bytes, rx_bytes) = current.counters;
        let (old_tx, old_rx, old_tx_bytes, old_rx_bytes) = original[at].counters;
        assert!(
            tx >= old_tx && rx >= old_rx && tx_bytes >= old_tx_bytes && rx_bytes >= old_rx_bytes,
            "retained FSP accounting must not reset"
        );
    }
}
