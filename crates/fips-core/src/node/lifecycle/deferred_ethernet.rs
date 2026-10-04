use super::*;
use std::time::Instant;

/// A beacon is an unauthenticated retry hint, never proof of a new session.
pub(in crate::node) struct DeferredEthernetHint {
    link_id: LinkId,
    generation: u64,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    last_seen_ms: u64,
    received_packets: Option<u64>,
    observed_at: Instant,
    retry_delay: Duration,
    lifetime: Duration,
}

impl Node {
    pub(super) fn deferred_ethernet_hint(
        &self,
        node_addr: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<DeferredEthernetHint> {
        let peer = self.peers.get(node_addr)?;
        if peer.transport_id() != Some(transport_id) || peer.current_addr() != Some(remote_addr) {
            return None;
        }
        // Leave the next scheduled heartbeat one maintenance tick to arrive.
        // The ordinary freshness threshold alone races healthy heartbeat jitter.
        let retry_delay = Duration::from_secs(
            self.config
                .node
                .heartbeat_interval_secs
                .max(1)
                .saturating_add(self.config.node.tick_interval_secs.max(1)),
        );
        let now = Instant::now();
        Some(DeferredEthernetHint {
            link_id: peer.link_id(),
            generation: peer.session_generation(),
            transport_id,
            remote_addr: remote_addr.clone(),
            last_seen_ms: peer.last_seen(),
            received_packets: self
                .dataplane
                .fmp_link_metrics(node_addr, now)
                .map(|m| m.rx_packets),
            observed_at: now,
            retry_delay,
            lifetime: Duration::from_secs(self.config.node.link_dead_timeout_secs),
        })
    }

    fn deferred_ethernet_hint_is_current(
        &self,
        node_addr: &NodeAddr,
        hint: &DeferredEthernetHint,
        now: Instant,
    ) -> bool {
        now.duration_since(hint.observed_at) < hint.lifetime
            // Authenticated link activity after the observation disproves this
            // retry hint; it must not trigger on an unrelated later quiet spell.
            && self.dataplane.fmp_link_metrics(node_addr, now).map(|m| m.rx_packets)
                == hint.received_packets
            && self.peers.get(node_addr).is_some_and(|peer| {
                peer.link_id() == hint.link_id
                    && peer.session_generation() == hint.generation
                    && peer.transport_id() == Some(hint.transport_id)
                    && peer.current_addr() == Some(&hint.remote_addr)
                    && peer.last_seen() == hint.last_seen_ms
            })
            && self
                .transports
                .get(&hint.transport_id)
                .is_some_and(|transport| transport.is_operational() && transport.auto_connect())
    }

    pub(super) fn prune_deferred_ethernet_hints(&mut self) {
        let now = Instant::now();
        let mut hints = std::mem::take(&mut self.deferred_ethernet_hints);
        hints
            .retain(|node_addr, hint| self.deferred_ethernet_hint_is_current(node_addr, hint, now));
        self.deferred_ethernet_hints = hints;
    }

    pub(super) fn take_deferred_ethernet_refreshes(
        &mut self,
        budget: usize,
        scheduled: &HashSet<NodeAddr>,
        allow_rotation_refresh: bool,
    ) -> Vec<(TransportId, TransportAddr, PeerIdentity)> {
        let now_ms = Self::now_ms();
        let rotation_victim = self.discovery_rotation_victim(now_ms);
        let now = Instant::now();
        let mut ready = Vec::new();
        let mut hints = std::mem::take(&mut self.deferred_ethernet_hints);
        hints.retain(|node_addr, hint| {
            if scheduled.contains(node_addr) {
                return false;
            }
            let peer = self
                .peers
                .get(node_addr)
                .expect("hints pruned before discovery");
            if now.duration_since(hint.observed_at) < hint.retry_delay
                || ready.len() == budget
                || (rotation_victim == Some(*node_addr) && !allow_rotation_refresh)
                || (peer.is_healthy() && !self.active_peer_needs_same_path_refresh(node_addr))
                || self.path_candidate_attempt_budget(node_addr) == 0
                || self.is_connecting_to_peer_on_path(
                    node_addr,
                    hint.transport_id,
                    &hint.remote_addr,
                )
            {
                return true;
            }
            if self
                .authorize_peer(
                    peer.identity(),
                    PeerAclContext::OutboundConnect,
                    hint.transport_id,
                    &hint.remote_addr,
                )
                .is_ok()
            {
                ready.push((
                    hint.transport_id,
                    hint.remote_addr.clone(),
                    *peer.identity(),
                ));
            }
            false
        });
        self.deferred_ethernet_hints = hints;
        ready
    }
}
