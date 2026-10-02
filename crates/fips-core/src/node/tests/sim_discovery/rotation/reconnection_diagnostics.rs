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

// These are observations of existing state, not a claim that empty raw queues
// or no runnable shards mean every async operation has completed.
pub(super) fn demand_snapshot(nodes: &[TestNode]) -> serde_json::Value {
    let now_ms = Node::now_ms();
    let boundary = &nodes[A].node;
    let peers: Vec<_> = [S, R].into_iter().map(|index| {
        let addr = nodes[index].node.node_addr();
        serde_json::json!({
            "peer": NAMES[index],
            "recent_transit": boundary.get_peer(addr)
                .map(|peer| peer.has_recent_transit_demand(now_ms, 1_000)),
            "deferred_transit": boundary.deferred_session_forwards.has_demand_for(addr),
            "recent_local_data": boundary.peer_has_recent_local_application_data(addr, now_ms, 1_000),
            "queued_local_data": boundary.peer_has_queued_application_demand(addr),
            "application_demand": boundary.peer_has_application_demand(addr, now_ms, 1_000)
        })
    }).collect();
    let sessions: Vec<_> = [(S, R), (R, S)].into_iter().map(|(local, remote)| {
        let node = &nodes[local].node;
        let target = nodes[remote].node.node_addr();
        let entry = node.get_session(target);
        let activity = node.dataplane.fsp_owner_activity(target);
        serde_json::json!({
            "node": NAMES[local], "target": NAMES[remote],
            "raw_queued": nodes[local].packet_rx.queued_packets_for_test(),
            "runnable": node.dataplane.has_runnable_work(),
            "established": entry.map(|e| e.is_established()),
            "handshake_payload": entry.map(|e| e.handshake_payload().is_some()),
            "handshake_resends": entry.map(|e| e.resend_count()),
            "handshake_next_ms": entry.map(|e| e.next_resend_at_ms()),
            "rekey": entry.map(|e| e.has_rekey_in_progress()),
            "epoch_confirmed": activity.map(|a| a.current_epoch_confirmed()),
            "send_counter": activity.map(|a| a.send_counter()),
            "last_rx_age_ms": activity.and_then(|a| a.last_rx_age_ms(now_ms)),
            "data_counters": activity.map(|a| a.traffic_counters()),
            "mmp": node.dataplane.fsp_mmp_snapshot(target).map(|m| serde_json::json!({
                "mode": format!("{:?}", m.mode), "tx_packets": m.tx_packets,
                "rx_packets": m.rx_packets, "send_mtu": m.send_mtu, "observed_mtu": m.observed_mtu
            }))
        })
    }).collect();
    serde_json::json!({
        "observed_ms": now_ms,
        "preparation_opportunity": boundary.has_neighbor_preparation_opportunity(now_ms),
        "peers": peers, "sessions": sessions
    })
}
