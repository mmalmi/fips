//! Bounded exploration at a full neighbor roster, without a wire extension.

use super::{LinkId, Node, NodeAddr, TransportAddr, TransportId};

mod carrier;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod benchmark;

#[derive(Default)]
pub(super) struct NeighborRotation {
    attempt: Option<Attempt>,
    next_attempt_ms: u64,
    last_replacement_ms: Option<u64>,
    displaced: Option<(NodeAddr, u64)>,
    cursor: Option<NodeAddr>,
}

struct Attempt {
    peer: NodeAddr,
    started_ms: u64,
    confirmed_inbound: Option<LinkId>,
}

/// An admission decision owned by one uninterrupted promotion operation.
pub(in crate::node) struct PreparedNeighborRotation {
    candidate: NodeAddr,
    candidate_link: LinkId,
    victim: NodeAddr,
    victim_link: LinkId,
    victim_index: Option<crate::utils::index::SessionIndex>,
    victim_generation: u64,
    decided_ms: u64,
}

impl Node {
    pub(in crate::node) fn neighbor_roster_full(&self) -> bool {
        self.max_peers > 0 && self.peers.len() >= self.max_peers
    }

    fn rotation_victim(&self, now_ms: u64) -> Option<NodeAddr> {
        let config = self.config.node.neighbor_rotation.as_ref()?;
        if self.max_peers == 0 || self.peers.len() != self.max_peers {
            return None;
        }
        let idle_ms = config.idle_secs.saturating_mul(1000);
        let mut candidates: Vec<_> = self
            .peers
            .values()
            .filter(|peer| {
                !self.is_configured_peer_identity(peer.identity())
                    && now_ms.saturating_sub(peer.authenticated_at()) >= idle_ms
                    && !peer.has_recent_transit_demand(now_ms, idle_ms)
            })
            .collect();
        candidates.sort_unstable_by_key(|peer| (peer.authenticated_at(), *peer.node_addr()));
        // Inspect demand in victim order. Once the oldest eligible peer is
        // found, younger peers cannot change this decision.
        candidates
            .into_iter()
            .find(|peer| {
                let addr = peer.node_addr();
                !self.peer_has_application_demand(addr, now_ms, idle_ms)
                    && !self.peers.connection_values().any(|conn| {
                        conn.expected_identity()
                            .is_some_and(|id| id.node_addr() == addr)
                    })
                    && !self
                        .pending_connects
                        .iter()
                        .any(|p| p.peer_identity.node_addr() == addr)
            })
            .map(|peer| *peer.node_addr())
    }

    fn rotation_attempt_is_fresh(&self, attempt: &Attempt, now_ms: u64) -> bool {
        now_ms.saturating_sub(attempt.started_ms)
            < self
                .config
                .node
                .rate_limit
                .handshake_timeout_secs
                .saturating_mul(1000)
    }

    fn rotation_has_pending_candidate(&self) -> bool {
        self.peers.connection_values().any(|conn| {
            conn.expected_identity()
                .is_some_and(|id| !self.peers.contains_key(id.node_addr()))
        }) || self
            .pending_connects
            .iter()
            .any(|pending| !self.peers.contains_key(pending.peer_identity.node_addr()))
    }

    pub(in crate::node) fn has_neighbor_rotation_opportunity(&self, now_ms: u64) -> bool {
        self.neighbor_roster_full()
            && now_ms >= self.neighbor_rotation.next_attempt_ms
            && !self.rotation_has_pending_candidate()
            && self.rotation_victim(now_ms).is_some()
    }

    /// At most one candidate identity, with one handshake in each direction
    /// for simultaneous dials. Active-peer path refresh keeps its own limits.
    pub(in crate::node) fn can_attempt_neighbor_rotation(
        &self,
        peer: &NodeAddr,
        outbound: bool,
        now_ms: u64,
    ) -> bool {
        let Some(config) = self.config.node.neighbor_rotation.as_ref() else {
            return false;
        };
        if !self.neighbor_roster_full()
            || self.peers.contains_key(peer)
            || peer == self.node_addr()
            || self.neighbor_rotation.displaced.is_some_and(|(old, at)| {
                old == *peer && now_ms.saturating_sub(at) < config.idle_secs.saturating_mul(1000)
            })
        {
            return false;
        }
        if self.rotation_has_pending_candidate() {
            let Some(attempt) = &self.neighbor_rotation.attempt else {
                return false;
            };
            if attempt.peer != *peer
                || !self.rotation_attempt_is_fresh(attempt, now_ms)
                || self.peers.connection_values().any(|conn| {
                    conn.expected_identity().is_some_and(|id| {
                        !self.peers.contains_key(id.node_addr())
                            && (id.node_addr() != peer || conn.is_outbound() == outbound)
                    })
                })
                || self.pending_connects.iter().any(|pending| {
                    !self.peers.contains_key(pending.peer_identity.node_addr())
                        && (pending.peer_identity.node_addr() != peer || outbound)
                })
            {
                return false;
            }
        } else if now_ms < self.neighbor_rotation.next_attempt_ms {
            return false;
        }
        // Cooldown and candidate ownership can reject without walking every
        // neighbor's session activity. Demand is still fresh on allowed paths.
        self.rotation_victim(now_ms).is_some()
    }

    pub(in crate::node) fn begin_neighbor_rotation(
        &mut self,
        peer: NodeAddr,
        outbound: bool,
        now_ms: u64,
    ) -> bool {
        if !self.can_attempt_neighbor_rotation(&peer, outbound, now_ms) {
            return false;
        }
        if !self.rotation_has_pending_candidate() {
            let interval_ms = self
                .config
                .node
                .neighbor_rotation
                .as_ref()
                .unwrap()
                .interval_secs
                .saturating_mul(1000);
            self.neighbor_rotation.attempt = Some(Attempt {
                peer,
                started_ms: now_ms,
                confirmed_inbound: None,
            });
            self.neighbor_rotation.next_attempt_ms = now_ms.saturating_add(interval_ms);
            self.neighbor_rotation.cursor = Some(peer);
        }
        true
    }

    pub(in crate::node) fn neighbor_rotation_awaits_confirmation(&self, peer: &NodeAddr) -> bool {
        self.neighbor_rotation
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.peer == *peer)
            && self.neighbor_roster_full()
            && !self.peers.contains_key(peer)
    }

    /// Resolve a crossed exploratory dial within the existing transient slots.
    /// Only the losing pending handshake retires; no active peer is displaced.
    pub(in crate::node) async fn reclaim_crossed_rotation_dial(
        &mut self,
        peer: &NodeAddr,
        transport: TransportId,
        remote: &TransportAddr,
    ) {
        if !self.neighbor_rotation_awaits_confirmation(peer)
            || !crate::peer::cross_connection_winner(self.node_addr(), peer, false)
            || (self.outbound_handshake_slots() > 0 && self.outbound_link_slots() > 0)
        {
            return;
        }
        let loser = self.peers.connection_iter().find_map(|(link, conn)| {
            (conn.is_outbound()
                && conn
                    .expected_identity()
                    .is_some_and(|id| id.node_addr() == peer))
            .then_some(*link)
        });
        if let Some(link) = loser {
            self.retire_connection_candidate(link, Some((transport, remote.clone())))
                .await;
        }
    }

    /// Called only after an encrypted response to this fresh Msg2 authenticates
    /// and the inbound ACL is rechecked. Msg1 by itself is replayable.
    pub(in crate::node) fn confirm_neighbor_rotation_candidate(
        &mut self,
        peer: &NodeAddr,
        link: LinkId,
    ) {
        if let Some(attempt) = &mut self.neighbor_rotation.attempt
            && attempt.peer == *peer
        {
            attempt.confirmed_inbound = Some(link);
        }
    }

    fn rotation_promotion_victim(
        &self,
        peer: &NodeAddr,
        link: LinkId,
        outbound: bool,
        now_ms: u64,
    ) -> Option<NodeAddr> {
        let config = self.config.node.neighbor_rotation.as_ref()?;
        let attempt = self.neighbor_rotation.attempt.as_ref()?;
        let interval_ms = config.interval_secs.saturating_mul(1000);
        if attempt.peer != *peer
            || !self.rotation_attempt_is_fresh(attempt, now_ms)
            || (!outbound && attempt.confirmed_inbound != Some(link))
            || self
                .neighbor_rotation
                .last_replacement_ms
                .is_some_and(|at| now_ms.saturating_sub(at) < interval_ms)
        {
            return None;
        }
        self.rotation_victim(now_ms)
    }

    pub(in crate::node) fn commit_neighbor_rotation(
        &mut self,
        peer: &NodeAddr,
        link: LinkId,
        prepared: Option<PreparedNeighborRotation>,
    ) -> bool {
        let Some(prepared) = prepared else {
            return false;
        };
        if prepared.candidate != *peer
            || prepared.candidate_link != link
            || !self.peers.get(&prepared.victim).is_some_and(|victim| {
                victim.link_id() == prepared.victim_link
                    && victim.our_index() == prepared.victim_index
                    && victim.session_generation() == prepared.victim_generation
            })
        {
            return false;
        }
        // The actor holds exclusive native state from the decision through
        // carrier cleanup. Never reselect a different victim or expire the
        // authenticated decision after its carrier has already been closed.
        let victim = prepared.victim;
        let now_ms = Self::now_ms().max(prepared.decided_ms);
        let interval_ms = self
            .config
            .node
            .neighbor_rotation
            .as_ref()
            .unwrap()
            .interval_secs
            .saturating_mul(1000);
        self.remove_active_peer(&victim);
        self.neighbor_rotation.displaced = Some((victim, now_ms));
        self.neighbor_rotation.last_replacement_ms = Some(now_ms);
        self.neighbor_rotation.next_attempt_ms = now_ms.saturating_add(interval_ms);
        self.neighbor_rotation.attempt = None;
        tracing::info!(
            node = %self.node_addr(),
            previous_peer = %self.peer_display_name(&victim),
            candidate = %self.peer_display_name(peer),
            "Replacing idle learned neighbor after fresh authentication"
        );
        true
    }

    /// Continue after the last attempted identity rather than retrying the
    /// first discovery result forever. This stores no untrusted identity list.
    pub(in crate::node) fn neighbor_rotation_order(&self, peer: NodeAddr) -> (bool, NodeAddr) {
        (
            self.neighbor_rotation
                .cursor
                .is_some_and(|cursor| peer <= cursor),
            peer,
        )
    }
}
