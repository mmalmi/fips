//! Bounded exploration at a full neighbor roster, without a wire extension.

use super::{LinkId, Node, NodeAddr, TransportAddr, TransportId};

mod carrier;
mod incoming;
mod outgoing;
mod reconnection;

#[cfg(test)]
mod demand_tests;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod benchmark;

#[derive(Default)]
pub(super) struct NeighborRotation {
    attempt: Option<Attempt>,
    next_attempt_ms: u64,
    last_replacement_ms: Option<u64>,
    displaced: Option<(NodeAddr, u64)>,
    cursor: Option<NodeAddr>,
    exploration_due: bool,
    outbound_turn_until_ms: u64,
    interrupted_outgoing: Option<InterruptedOutgoing>,
    lost_transit: std::collections::HashMap<NodeAddr, u64>,
}

struct Attempt {
    peer: NodeAddr,
    started_ms: u64,
    deadline_ms: u64,
    is_retry: bool,
    confirmed_inbound: Option<LinkId>,
}

/// A transferred outgoing attempt may earn one fresh discovery window when
/// its exact incoming replacement promotes. No address or Noise state survives.
struct InterruptedOutgoing {
    peer: NodeAddr,
    started_ms: u64,
    deadline_ms: u64,
    transferred_to: Option<NodeAddr>,
}

/// An admission decision owned by one uninterrupted promotion operation.
pub(in crate::node) struct PreparedNeighborRotation {
    candidate: NodeAddr,
    candidate_link: LinkId,
    outbound: bool,
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
        self.rotation_victim_by(now_ms, Some(now_ms))
    }

    fn rotation_victim_by(&self, now_ms: u64, eligible_by_ms: Option<u64>) -> Option<NodeAddr> {
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
                    && eligible_by_ms
                        .is_none_or(|at| at.saturating_sub(peer.authenticated_at()) >= idle_ms)
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
        now_ms < attempt.deadline_ms
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
        self.has_neighbor_rotation_opportunity_with_age(now_ms, true)
    }

    pub(in crate::node) fn has_neighbor_preparation_opportunity(&self, now_ms: u64) -> bool {
        self.has_neighbor_rotation_opportunity_with_age(now_ms, false)
    }

    fn has_neighbor_rotation_opportunity_with_age(&self, now_ms: u64, require_age: bool) -> bool {
        self.neighbor_roster_full()
            && now_ms >= self.neighbor_rotation.next_attempt_ms
            && !self.rotation_has_pending_candidate()
            && self
                .rotation_victim_by(now_ms, require_age.then_some(now_ms))
                .is_some()
    }

    /// Keep discovery from refreshing the idle peer that can make room for
    /// exploration, including while that candidate's handshake is pending.
    pub(in crate::node) fn discovery_rotation_victim(&self, now_ms: u64) -> Option<NodeAddr> {
        if self.rotation_has_pending_candidate() {
            let attempt = self.neighbor_rotation.attempt.as_ref()?;
            if !self.rotation_attempt_is_fresh(attempt, now_ms)
                || self.peers.contains_key(&attempt.peer)
                || !(self.peers.connection_values().any(|conn| {
                    conn.expected_identity()
                        .is_some_and(|id| id.node_addr() == &attempt.peer)
                }) || self
                    .pending_connects
                    .iter()
                    .any(|pending| pending.peer_identity.node_addr() == &attempt.peer))
            {
                return None;
            }
        } else if !self.neighbor_rotation_discovery_turn_reserved(now_ms)
            && now_ms < self.neighbor_rotation.next_attempt_ms
        {
            return None;
        }
        // Both directions may prepare while the incumbent ages. Ordinary
        // discovery refresh must not keep postponing that maturity window.
        self.rotation_victim_by(now_ms, None)
    }

    /// At most one candidate identity, with one handshake in each direction
    /// for simultaneous dials. Active-peer path refresh keeps its own limits.
    pub(in crate::node) fn can_attempt_neighbor_rotation(
        &self,
        peer: &NodeAddr,
        outbound: bool,
        now_ms: u64,
    ) -> bool {
        let rejection = self.neighbor_rotation_rejection(peer, outbound, now_ms, None);
        if let Some(reason) = rejection {
            self.observe_neighbor_rotation_rejection(peer, outbound, now_ms, reason);
        }
        rejection.is_none()
    }

    fn neighbor_rotation_rejection(
        &self,
        peer: &NodeAddr,
        outbound: bool,
        now_ms: u64,
        replacing: Option<LinkId>,
    ) -> Option<&'static str> {
        if let Some(reason) = self.rotation_new_peer_rejection(peer, now_ms) {
            return Some(reason);
        }
        let pending_candidate = self.rotation_has_pending_candidate();
        if pending_candidate {
            let Some(attempt) = &self.neighbor_rotation.attempt else {
                return Some("pending candidate without rotation ownership");
            };
            if attempt.peer != *peer {
                return Some("another candidate owns the attempt");
            }
            if !self.rotation_attempt_is_fresh(attempt, now_ms) {
                return Some("candidate attempt expired");
            }
            if self.peers.connection_iter().any(|(link, conn)| {
                Some(*link) != replacing
                    && conn.expected_identity().is_some_and(|id| {
                        !self.peers.contains_key(id.node_addr())
                            && (id.node_addr() != peer || conn.is_outbound() == outbound)
                    })
            }) {
                return Some("conflicting pending handshake");
            }
            if self.pending_connects.iter().any(|pending| {
                !self.peers.contains_key(pending.peer_identity.node_addr())
                    && (pending.peer_identity.node_addr() != peer || outbound)
            }) {
                return Some("conflicting pending transport connection");
            }
        } else if now_ms < self.neighbor_rotation.next_attempt_ms {
            return Some("rotation cooldown");
        } else if !outbound && self.neighbor_rotation_discovery_turn_reserved(now_ms) {
            return Some("local discovery turn reserved");
        }
        // An interrupted retry keeps its frozen deadline. Do not spend a
        // discovery turn on it if this roster cannot become eligible in time.
        // This does not predict later disconnects. A rejected candidate keeps
        // its original deadline and one-use preference.
        let mut eligible_by_ms = None;
        let retry_ineligible = "interrupted retry cannot become eligible before expiry";
        if outbound
            && !pending_candidate
            && let Some(retry) = self.neighbor_rotation.interrupted_outgoing.as_ref()
            && retry.peer == *peer
            && now_ms < retry.deadline_ms
        {
            let interval_ms = self
                .config
                .node
                .neighbor_rotation
                .as_ref()
                .unwrap()
                .interval_secs
                .saturating_mul(1000);
            if self
                .neighbor_rotation
                .last_replacement_ms
                .is_some_and(|at| at.saturating_add(interval_ms) >= retry.deadline_ms)
            {
                return Some(retry_ineligible);
            }
            eligible_by_ms = Some(retry.deadline_ms - 1);
        }
        // Cooldown and candidate ownership can reject without walking every
        // neighbor's session activity. Demand is still fresh on allowed paths.
        // Either direction may prepare one candidate before minimum age.
        // Promotion still requires fresh mature eligibility and peer proof.
        self.rotation_victim_by(now_ms, eligible_by_ms)
            .is_none()
            .then_some(if eligible_by_ms.is_some() {
                retry_ineligible
            } else {
                "no eligible idle neighbor"
            })
    }

    fn rotation_new_peer_rejection(&self, peer: &NodeAddr, now_ms: u64) -> Option<&'static str> {
        let Some(config) = self.config.node.neighbor_rotation.as_ref() else {
            return Some("rotation disabled");
        };
        if !self.neighbor_roster_full() || self.peers.contains_key(peer) || peer == self.node_addr()
        {
            return Some("not a new full-roster neighbor");
        }
        self.neighbor_rotation
            .displaced
            .is_some_and(|(old, at)| {
                old == *peer && now_ms.saturating_sub(at) < config.idle_secs.saturating_mul(1000)
            })
            .then_some("recently displaced neighbor")
    }

    fn observe_neighbor_rotation_rejection(
        &self,
        peer: &NodeAddr,
        outbound: bool,
        now_ms: u64,
        reason: &'static str,
    ) {
        if !tracing::enabled!(target: "fips_core::node::neighbor_rotation", tracing::Level::DEBUG) {
            return;
        }
        let attempt = self.neighbor_rotation.attempt.as_ref();
        tracing::debug!(
            target: "fips_core::node::neighbor_rotation",
            node = %self.node_addr(),
            peer = %peer,
            outbound,
            reason,
            peers = self.peers.len(),
            max_peers = self.max_peers,
            attempt_peer = ?attempt.map(|attempt| attempt.peer),
            attempt_age_ms = ?attempt.map(|attempt| now_ms.saturating_sub(attempt.started_ms)),
            cooldown_remaining_ms = self.neighbor_rotation.next_attempt_ms.saturating_sub(now_ms),
            "Neighbor rotation rejected"
        );
        if reason != "no eligible idle neighbor" {
            return;
        }
        let idle_ms = self
            .config
            .node
            .neighbor_rotation
            .as_ref()
            .map_or(0, |config| config.idle_secs.saturating_mul(1000));
        for neighbor in self.peers.values() {
            let addr = neighbor.node_addr();
            tracing::debug!(
                target: "fips_core::node::neighbor_rotation",
                node = %self.node_addr(),
                candidate = %peer,
                neighbor = %addr,
                authenticated_age_ms = now_ms.saturating_sub(neighbor.authenticated_at()),
                idle_ms,
                configured = self.is_configured_peer_identity(neighbor.identity()),
                transit_demand = neighbor.has_recent_transit_demand(now_ms, idle_ms),
                application_demand = self.peer_has_application_demand(addr, now_ms, idle_ms),
                pending_handshake = self.peers.connection_values().any(|conn| {
                    conn.expected_identity().is_some_and(|identity| identity.node_addr() == addr)
                }),
                pending_transport = self.pending_connects.iter().any(|pending| {
                    pending.peer_identity.node_addr() == addr
                }),
                "Observed protected neighbor at rotation rejection"
            );
        }
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
            // Consume even a missing/ineligible preference when another outgoing
            // candidate wins. It cannot block discovery or re-arm after transfer.
            let retry = outbound
                .then(|| self.neighbor_rotation.interrupted_outgoing.take())
                .flatten()
                .filter(|retry| retry.peer == peer && now_ms < retry.deadline_ms);
            let is_retry = retry.is_some();
            let started_ms = retry.as_ref().map_or(now_ms, |retry| retry.started_ms);
            let deadline_ms = retry.map_or_else(
                || {
                    now_ms.saturating_add(
                        self.config
                            .node
                            .rate_limit
                            .handshake_timeout_secs
                            .saturating_mul(1000),
                    )
                },
                |retry| retry.deadline_ms,
            );
            self.neighbor_rotation.attempt = Some(Attempt {
                peer,
                started_ms,
                deadline_ms,
                is_retry,
                confirmed_inbound: None,
            });
            self.neighbor_rotation.next_attempt_ms = now_ms.saturating_add(interval_ms);
            if outbound {
                self.neighbor_rotation.outbound_turn_until_ms = 0;
            }
            if outbound && !is_retry {
                // Spend a demand turn when it starts, even if no reply arrives.
                // Only ordinary exploration advances the cursor.
                let demand = self.neighbor_rotation_prefers_demand(peer, now_ms);
                self.neighbor_rotation.exploration_due = demand;
                if !demand {
                    self.neighbor_rotation.cursor = Some(peer);
                }
            } else if !outbound && self.neighbor_rotation.cursor.is_none() {
                // Only the first inbound attempt can seed ordinary exploration.
                self.neighbor_rotation.cursor = Some(peer);
            }
            if outbound {
                self.forget_neighbor_reconnection(&peer);
            }
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
        let attempt = self.neighbor_rotation.attempt.as_ref()?;
        if !self.rotation_replacement_ready(peer, now_ms)
            || (!outbound && attempt.confirmed_inbound != Some(link))
        {
            return None;
        }
        self.rotation_victim(now_ms)
    }

    fn rotation_replacement_ready(&self, peer: &NodeAddr, now_ms: u64) -> bool {
        let Some(config) = self.config.node.neighbor_rotation.as_ref() else {
            return false;
        };
        self.neighbor_rotation
            .attempt
            .as_ref()
            .is_some_and(|attempt| {
                attempt.peer == *peer && self.rotation_attempt_is_fresh(attempt, now_ms)
            })
            && self.neighbor_rotation.last_replacement_ms.is_none_or(|at| {
                now_ms.saturating_sub(at) >= config.interval_secs.saturating_mul(1000)
            })
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
        if !prepared.outbound {
            self.grant_interrupted_retry_after_promotion(peer, now_ms);
        }
        let config = self.config.node.neighbor_rotation.as_ref().unwrap();
        let interval_ms = config.interval_secs.saturating_mul(1000);
        if !prepared.outbound
            && (self
                .transports
                .values()
                .any(|transport| transport.auto_connect())
                || self.lan_discovery.is_some()
                || self.nostr_discovery.is_some())
        {
            // An incoming winner must not monopolize every maturity window.
            // Reserve one local turn, with a finite fallback for incoming-only
            // peers or discovery that is unavailable.
            self.neighbor_rotation.outbound_turn_until_ms = now_ms
                .saturating_add(config.idle_secs.saturating_mul(1000).max(interval_ms))
                .saturating_add(
                    self.config
                        .node
                        .rate_limit
                        .handshake_timeout_secs
                        .saturating_mul(1000),
                );
        }
        self.remove_neighbor_for_rotation(&victim);
        self.neighbor_rotation.displaced = Some((victim, now_ms));
        self.neighbor_rotation.last_replacement_ms = Some(now_ms);
        // begin_neighbor_rotation already spaces attempts. Replacement pacing
        // is checked against last_replacement_ms, independently of preparation.
        self.neighbor_rotation.attempt = None;
        tracing::info!(
            node = %self.node_addr(),
            previous_peer = %self.peer_display_name(&victim),
            candidate = %self.peer_display_name(peer),
            "Replacing idle learned neighbor after fresh authentication"
        );
        true
    }

    pub(in crate::node) fn yield_empty_neighbor_discovery_turn(&mut self, now_ms: u64) {
        if self.neighbor_rotation_discovery_turn_reserved(now_ms)
            && self.has_neighbor_rotation_opportunity(now_ms)
        {
            self.neighbor_rotation.outbound_turn_until_ms = 0;
        }
    }

    pub(in crate::node) fn neighbor_rotation_discovery_turn_reserved(&self, now_ms: u64) -> bool {
        now_ms < self.neighbor_rotation.outbound_turn_until_ms
    }

    pub(in crate::node) fn pending_rotation_discovery_victim(
        &self,
        now_ms: u64,
    ) -> Option<NodeAddr> {
        if self.neighbor_rotation_discovery_turn_reserved(now_ms)
            || self.rotation_has_pending_candidate()
        {
            self.discovery_rotation_victim(now_ms)
        } else {
            None
        }
    }

    /// Frozen admission deadline, including time spent preparing its carrier.
    pub(in crate::node) fn neighbor_rotation_deadline(&self, peer: &NodeAddr) -> Option<u64> {
        self.neighbor_rotation
            .attempt
            .as_ref()
            .filter(|attempt| attempt.peer == *peer && !self.peers.contains_key(peer))
            .map(|attempt| attempt.deadline_ms)
    }

    fn neighbor_rotation_prefers_demand(&self, peer: NodeAddr, now_ms: u64) -> bool {
        !self.neighbor_rotation.exploration_due
            && (self.peer_has_queued_application_demand(&peer)
                || self
                    .neighbor_rotation
                    .lost_transit
                    .get(&peer)
                    .is_some_and(|deadline| now_ms < *deadline))
    }

    /// Retry a presently offered interrupted attempt first, then alternate
    /// current local demand or recently lost transit with ordinary exploration.
    pub(in crate::node) fn neighbor_rotation_discovery_order(
        &self,
        peer: NodeAddr,
        now_ms: u64,
    ) -> (bool, bool, (bool, [u8; 16])) {
        let preferred = self
            .neighbor_rotation
            .interrupted_outgoing
            .as_ref()
            .is_some_and(|retry| retry.peer == peer && now_ms < retry.deadline_ms);
        (
            !preferred,
            !self.neighbor_rotation_prefers_demand(peer, now_ms),
            self.neighbor_rotation_order(peer),
        )
    }

    /// Both endpoints give an edge the same score. Continue cyclically after
    /// the last ordinary attempt; demand and retries leave that cursor intact.
    pub(in crate::node) fn neighbor_rotation_order(&self, peer: NodeAddr) -> (bool, [u8; 16]) {
        let score = self.neighbor_rotation_edge_score(peer);
        (
            self.neighbor_rotation
                .cursor
                .is_some_and(|cursor| score <= self.neighbor_rotation_edge_score(cursor)),
            score,
        )
    }

    fn neighbor_rotation_edge_score(&self, peer: NodeAddr) -> [u8; 16] {
        std::array::from_fn(|index| self.node_addr().as_bytes()[index] ^ peer.as_bytes()[index])
    }
}
