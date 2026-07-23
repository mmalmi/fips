//! Sans-IO lookup peer selection.
//!
//! Discovery lookup handlers still decode wire messages and perform encrypted
//! async sends. This module owns the deterministic peer-selection part so the
//! lookup routing policy can be tested without sockets, tasks, or mutable node
//! state.

use crate::NodeAddr;
use crate::config::RoutingMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LookupPeerCandidate {
    pub(crate) addr: NodeAddr,
    pub(crate) can_send: bool,
    pub(crate) is_healthy: bool,
    pub(crate) is_tree_peer: bool,
    pub(crate) may_reach_target: bool,
    pub(crate) reply_learned_fallback_allowed: bool,
    pub(crate) configured_reply_learned_fallback_transit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LookupPeerPlan {
    pub(crate) peers: Vec<NodeAddr>,
    pub(crate) tree_match_count: usize,
    pub(crate) used_fallback: bool,
}

pub(crate) fn plan_forward_peers(
    from: NodeAddr,
    origin: NodeAddr,
    target: NodeAddr,
    routing_mode: RoutingMode,
    reply_learned_fallback_enabled: bool,
    candidates: &[LookupPeerCandidate],
    extra_peer_budget: usize,
) -> LookupPeerPlan {
    let mut peers: Vec<NodeAddr> = candidates
        .iter()
        .filter(|candidate| {
            candidate.addr != from
                && candidate.is_tree_peer
                && candidate.can_send
                && candidate.may_reach_target
                && (routing_mode != RoutingMode::ReplyLearned
                    || candidate.addr != target
                    || candidate.is_healthy)
        })
        .map(|candidate| candidate.addr)
        .collect();
    let tree_match_count = peers.len();

    if routing_mode == RoutingMode::ReplyLearned && reply_learned_fallback_enabled {
        let fallback_budget = extra_peer_budget.saturating_sub(peers.len());
        let mut fallback_candidates = candidates
            .iter()
            .filter(|candidate| {
                candidate.addr != from
                    && candidate.addr != origin
                    && candidate.can_send
                    && (candidate.addr != target || candidate.is_healthy)
                    && candidate.reply_learned_fallback_allowed
            })
            .filter(|candidate| !peers.contains(&candidate.addr))
            .collect::<Vec<_>>();
        fallback_candidates
            .sort_by_key(|candidate| !candidate.configured_reply_learned_fallback_transit);
        let extra_peers: Vec<NodeAddr> = fallback_candidates
            .into_iter()
            .map(|candidate| candidate.addr)
            .take(fallback_budget)
            .collect();
        peers.extend(extra_peers);
    } else if peers.is_empty() {
        peers = candidates
            .iter()
            .filter(|candidate| {
                candidate.addr != from
                    && !candidate.is_tree_peer
                    && candidate.can_send
                    && candidate.may_reach_target
            })
            .map(|candidate| candidate.addr)
            .collect();
    }

    let used_fallback = !peers.is_empty()
        && ((routing_mode == RoutingMode::ReplyLearned && peers.len() > tree_match_count)
            || (routing_mode != RoutingMode::ReplyLearned && tree_match_count == 0));

    LookupPeerPlan {
        peers,
        tree_match_count,
        used_fallback,
    }
}

pub(crate) fn plan_initiate_peers(
    routing_mode: RoutingMode,
    reply_learned_fallback_enabled: bool,
    candidates: &[LookupPeerCandidate],
    extra_peer_budget: usize,
) -> LookupPeerPlan {
    let mut peers: Vec<NodeAddr> = candidates
        .iter()
        .filter(|candidate| {
            candidate.is_tree_peer && candidate.can_send && candidate.may_reach_target
        })
        .map(|candidate| candidate.addr)
        .collect();
    let tree_match_count = peers.len();

    if routing_mode == RoutingMode::ReplyLearned && reply_learned_fallback_enabled {
        let fallback_budget = extra_peer_budget.saturating_sub(peers.len());
        let mut fallback_candidates = candidates
            .iter()
            .filter(|candidate| candidate.can_send && candidate.reply_learned_fallback_allowed)
            .filter(|candidate| !peers.contains(&candidate.addr))
            .collect::<Vec<_>>();
        fallback_candidates
            .sort_by_key(|candidate| !candidate.configured_reply_learned_fallback_transit);
        let extra_peers: Vec<NodeAddr> = fallback_candidates
            .into_iter()
            .map(|candidate| candidate.addr)
            .take(fallback_budget)
            .collect();
        peers.extend(extra_peers);
    }

    let used_fallback = routing_mode == RoutingMode::ReplyLearned && peers.len() > tree_match_count;

    LookupPeerPlan {
        peers,
        tree_match_count,
        used_fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn candidate(
        val: u8,
        can_send: bool,
        is_healthy: bool,
        is_tree_peer: bool,
        may_reach_target: bool,
        reply_learned_fallback_allowed: bool,
    ) -> LookupPeerCandidate {
        LookupPeerCandidate {
            addr: addr(val),
            can_send,
            is_healthy,
            is_tree_peer,
            may_reach_target,
            reply_learned_fallback_allowed,
            configured_reply_learned_fallback_transit: false,
        }
    }

    #[test]
    fn forward_prefers_sendable_tree_bloom_matches() {
        let from = addr(1);
        let origin = addr(9);
        let candidates = vec![
            candidate(1, true, true, true, true, true),
            candidate(2, true, true, true, true, false),
            candidate(3, false, false, true, true, false),
            candidate(4, true, true, false, true, true),
            candidate(5, true, true, true, false, true),
        ];

        let plan = plan_forward_peers(
            from,
            origin,
            addr(42),
            RoutingMode::Tree,
            false,
            &candidates,
            16,
        );

        assert_eq!(plan.peers, vec![addr(2)]);
        assert_eq!(plan.tree_match_count, 1);
        assert!(!plan.used_fallback);
    }

    #[test]
    fn forward_tree_mode_falls_back_to_non_tree_bloom_matches() {
        let candidates = vec![
            candidate(2, true, true, true, false, false),
            candidate(3, true, true, false, true, false),
            candidate(4, true, true, false, true, false),
        ];

        let plan = plan_forward_peers(
            addr(1),
            addr(9),
            addr(42),
            RoutingMode::Tree,
            false,
            &candidates,
            16,
        );

        assert_eq!(plan.peers, vec![addr(3), addr(4)]);
        assert_eq!(plan.tree_match_count, 0);
        assert!(plan.used_fallback);
    }

    #[test]
    fn forward_reply_learned_adds_allowed_live_neighbors_with_budget() {
        let candidates = vec![
            candidate(2, true, true, true, true, false),
            candidate(3, true, true, false, false, true),
            candidate(4, true, true, false, false, true),
            candidate(5, true, true, false, false, true),
            candidate(9, true, true, false, false, true),
        ];

        let plan = plan_forward_peers(
            addr(1),
            addr(9),
            addr(42),
            RoutingMode::ReplyLearned,
            true,
            &candidates,
            3,
        );

        assert_eq!(plan.peers, vec![addr(2), addr(3), addr(4)]);
        assert_eq!(plan.tree_match_count, 1);
        assert!(plan.used_fallback);
    }

    #[test]
    fn forward_reply_learned_excludes_stale_target_when_fallback_exists() {
        let candidates = vec![
            candidate(42, true, false, true, true, true),
            candidate(3, true, true, false, false, true),
        ];

        let plan = plan_forward_peers(
            addr(1),
            addr(9),
            addr(42),
            RoutingMode::ReplyLearned,
            true,
            &candidates,
            16,
        );

        assert_eq!(plan.peers, vec![addr(3)]);
        assert_eq!(plan.tree_match_count, 0);
        assert!(plan.used_fallback);
    }

    #[test]
    fn forward_reply_learned_leaves_stale_target_for_shell_probe_when_alone() {
        let candidates = vec![candidate(42, true, false, false, false, true)];

        let plan = plan_forward_peers(
            addr(1),
            addr(9),
            addr(42),
            RoutingMode::ReplyLearned,
            true,
            &candidates,
            16,
        );

        assert!(plan.peers.is_empty());
        assert_eq!(plan.tree_match_count, 0);
        assert!(!plan.used_fallback);
    }

    #[test]
    fn initiate_reply_learned_extends_tree_matches() {
        let candidates = vec![
            candidate(2, true, true, true, true, false),
            candidate(3, true, true, false, false, true),
            candidate(4, false, false, false, false, true),
        ];

        let plan = plan_initiate_peers(RoutingMode::ReplyLearned, true, &candidates, 16);

        assert_eq!(plan.peers, vec![addr(2), addr(3)]);
        assert_eq!(plan.tree_match_count, 1);
        assert!(plan.used_fallback);
    }

    #[test]
    fn initiate_reply_learned_keeps_configured_transit_inside_fanout_budget() {
        let mut candidates = (1..=20)
            .map(|val| candidate(val, true, true, false, false, true))
            .collect::<Vec<_>>();
        candidates.push(LookupPeerCandidate {
            configured_reply_learned_fallback_transit: true,
            ..candidate(42, true, true, false, false, true)
        });

        let plan = plan_initiate_peers(RoutingMode::ReplyLearned, true, &candidates, 16);

        assert_eq!(plan.peers.len(), 16);
        assert!(
            plan.peers.contains(&addr(42)),
            "configured transit peer was excluded by opportunistic peers"
        );
    }

    #[test]
    fn forward_reply_learned_keeps_configured_transit_inside_fanout_budget() {
        let mut candidates = (2..=21)
            .map(|val| candidate(val, true, true, false, false, true))
            .collect::<Vec<_>>();
        candidates.push(LookupPeerCandidate {
            configured_reply_learned_fallback_transit: true,
            ..candidate(42, true, true, false, false, true)
        });

        let plan = plan_forward_peers(
            addr(1),
            addr(99),
            addr(100),
            RoutingMode::ReplyLearned,
            true,
            &candidates,
            16,
        );

        assert_eq!(plan.peers.len(), 16);
        assert!(
            plan.peers.contains(&addr(42)),
            "configured transit peer was excluded by opportunistic peers"
        );
    }
}
