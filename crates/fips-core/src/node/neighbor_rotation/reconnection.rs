//! One discovery preference for a recently used application neighbor after link loss.
use super::*;
use std::time::Duration;

impl Node {
    pub(in crate::node) fn remove_link_dead_discovered_peer(
        &mut self,
        peer: &NodeAddr,
        now_ms: u64,
        dead_timeout: Duration,
    ) {
        let qualified = self.max_peers > 0
            && self
                .config
                .node
                .neighbor_rotation
                .as_ref()
                .is_some_and(|rotation| {
                    let dead_ms = u64::try_from(dead_timeout.as_millis()).unwrap_or(u64::MAX);
                    let lookback_ms =
                        dead_ms.saturating_add(rotation.idle_secs.saturating_mul(1000));
                    self.peers.get(peer).is_some_and(|active| {
                        !self.is_configured_peer_identity(active.identity())
                            && (active.has_recent_transit_demand(now_ms, lookback_ms)
                                || now_ms
                                    .checked_sub(active.authenticated_at())
                                    .and_then(|age| age.checked_sub(1))
                                    .is_some_and(|age| {
                                        // Retained FSP history must be newer than this
                                        // adjacency's admission, including at millisecond
                                        // boundaries. It does not prove wire delivery.
                                        self.peer_has_recent_local_application_data(
                                            peer,
                                            now_ms,
                                            lookback_ms.min(age),
                                        )
                                    }))
                    })
                });
        // Normal cleanup removes any old preference and all link authority.
        // Only this physical-failure path can remember recently admitted application use.
        self.remove_active_peer(peer);
        if !qualified {
            return;
        }
        // Freeze one existing handshake window. Advertisements, later config
        // changes and failed attempts cannot extend it. No address is retained.
        let deadline = now_ms.saturating_add(
            self.config
                .node
                .rate_limit
                .handshake_timeout_secs
                .saturating_mul(1000),
        );
        self.neighbor_rotation
            .lost_neighbors
            .insert(*peer, deadline);
        self.prune_neighbor_reconnections(now_ms);
    }

    pub(in crate::node) fn forget_neighbor_reconnection(&mut self, peer: &NodeAddr) {
        self.neighbor_rotation.lost_neighbors.remove(peer);
    }

    pub(in crate::node) fn prune_neighbor_reconnections(&mut self, now_ms: u64) {
        let history = &mut self.neighbor_rotation.lost_neighbors;
        history.retain(|_, deadline| now_ms < *deadline);
        while history.len() > self.max_peers {
            let oldest = *history
                .iter()
                .min_by_key(|(identity, deadline)| (**deadline, **identity))
                .unwrap()
                .0;
            history.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests;
