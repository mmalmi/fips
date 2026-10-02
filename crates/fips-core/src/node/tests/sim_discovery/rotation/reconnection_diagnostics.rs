//! Bounded observations printed only if the replacement ownership guard fails.
use super::*;

pub(super) fn maintenance_snapshot(
    node: &Node,
    peer: &NodeAddr,
    candidate: &NodeAddr,
    cut_at: Option<Instant>,
) -> serde_json::Value {
    let now_ms = Node::now_ms();
    let active = node.get_peer(peer);
    let pending = node.peers.connection_values().find(|connection| {
        connection
            .expected_identity()
            .is_some_and(|id| id.node_addr() == candidate)
    });
    serde_json::json!({
        "observed_ms": now_ms,
        "cut_elapsed_ms": cut_at.map(|at| at.elapsed().as_millis()),
        "link_dead_ms": node.config.node.link_dead_timeout_secs * 1000,
        "owner": active.map(|p| (p.link_id().as_u64(), p.our_index().map(|i| i.as_u32()),
            p.their_index().map(|i| i.as_u32()), p.session_generation())),
        "peer_idle_ms": active.map(|p| p.idle_time(now_ms)),
        "link_rx_age_ms": node.dataplane_fmp_link_metrics(peer, Instant::now())
            .and_then(|metrics| metrics.last_recv_age_ms),
        "fsp_rx_age_ms": node.dataplane.min_fsp_rx_age_for_next_hop(peer, now_ms),
        "fsp_data_rx_age_ms": node.dataplane.min_fsp_data_rx_age_for_next_hop(peer, now_ms),
        "candidate_admitted": node.get_peer(candidate).is_some(),
        "candidate_deadline_ms": node.neighbor_rotation_deadline(candidate),
        "candidate": pending.map(|p| serde_json::json!({
            "link": p.link_id().as_u64(), "outbound": p.is_outbound(),
            "has_session": p.has_session(), "complete": p.is_complete(),
            "started_ms": p.started_at(), "idle_ms": p.idle_time(now_ms)
        }))
    })
}

pub(super) fn assert_owner(
    node: &Node,
    peer: &NodeAddr,
    expected: Owner,
    candidate: &NodeAddr,
    cut_at: Option<Instant>,
    phase: &str,
    before: &serde_json::Value,
) {
    let actual = node.get_peer(peer).map(|p| {
        (
            p.link_id(),
            p.our_index(),
            p.their_index(),
            p.session_generation(),
        )
    });
    if actual != Some(expected) {
        let after = maintenance_snapshot(node, peer, candidate, cut_at);
        panic!(
            "timeout maintenance must retain the original replacement victim; \
             phase={phase}; before={before}; after={after}; expected={expected:?}; actual={actual:?}"
        );
    }
}
