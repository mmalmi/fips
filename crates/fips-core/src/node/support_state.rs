use super::*;

#[derive(Debug, Default)]
pub(in crate::node) struct LocalSendFailures {
    failures: HashMap<NodeAddr, std::time::Instant>,
}

impl LocalSendFailures {
    pub(in crate::node) fn note_send_outcome(
        &mut self,
        node_addr: &NodeAddr,
        result: &Result<usize, TransportError>,
        now: std::time::Instant,
    ) {
        match result {
            Ok(_) => {
                self.failures.remove(node_addr);
            }
            Err(error) if error.is_local_route_unavailable() => {
                self.record_failure(*node_addr, now);
            }
            Err(_) => {}
        }
    }

    pub(in crate::node) fn record_failure(&mut self, node_addr: NodeAddr, at: std::time::Instant) {
        self.failures.insert(node_addr, at);
    }

    pub(in crate::node) fn dead_timeout_for_peer(
        &self,
        node_addr: &NodeAddr,
        now: std::time::Instant,
        dead_timeout: std::time::Duration,
        fast_dead_timeout: std::time::Duration,
    ) -> std::time::Duration {
        match self.failures.get(node_addr).copied() {
            Some(t) if now.duration_since(t) <= LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW => {
                fast_dead_timeout.min(dead_timeout)
            }
            None => dead_timeout,
            Some(_) => dead_timeout,
        }
    }

    pub(in crate::node) fn purge_expired(&mut self, now: std::time::Instant) {
        self.failures
            .retain(|_, at| now.duration_since(*at) <= LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW);
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.failures.contains_key(node_addr)
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct SessionDirectDegradation {
    degraded_until_ms: HashMap<NodeAddr, u64>,
}

impl SessionDirectDegradation {
    pub(in crate::node) fn is_degraded_at(&self, dest: &NodeAddr, now_ms: u64) -> bool {
        self.degraded_until_ms
            .get(dest)
            .is_some_and(|until_ms| *until_ms > now_ms)
    }

    pub(in crate::node) fn is_degraded(&self, dest: &NodeAddr, now_ms: u64) -> bool {
        self.is_degraded_at(dest, now_ms)
    }

    pub(in crate::node) fn has_pending_validation(&self, dest: &NodeAddr) -> bool {
        self.degraded_until_ms.contains_key(dest)
    }

    pub(in crate::node) fn release_hold_for_validation(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        let Some(until_ms) = self.degraded_until_ms.get_mut(dest) else {
            return false;
        };
        *until_ms = now_ms;
        true
    }

    pub(in crate::node) fn mark_degraded(
        &mut self,
        dest: NodeAddr,
        now_ms: u64,
        hold_ms: u64,
    ) -> bool {
        let until_ms = now_ms.saturating_add(hold_ms);
        let entry = self.degraded_until_ms.entry(dest).or_insert(0);
        let was_degraded = *entry > now_ms;
        *entry = (*entry).max(until_ms);
        !was_degraded
    }

    pub(in crate::node) fn clear(&mut self, dest: &NodeAddr) -> bool {
        self.degraded_until_ms.remove(dest).is_some()
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct DiscoveryFallbackTransit {
    blocked_peers: HashSet<NodeAddr>,
}

impl DiscoveryFallbackTransit {
    pub(in crate::node) fn set_allowed(&mut self, peer_addr: NodeAddr, allowed: bool) {
        if allowed {
            self.blocked_peers.remove(&peer_addr);
        } else {
            self.blocked_peers.insert(peer_addr);
        }
    }

    pub(in crate::node) fn allows_lookup_fallback_peer<F>(
        &self,
        peer_addr: &NodeAddr,
        target: &NodeAddr,
        transport_id: Option<TransportId>,
        mut is_bootstrap_transport: F,
    ) -> bool
    where
        F: FnMut(TransportId) -> bool,
    {
        if peer_addr == target {
            return true;
        }

        if self.blocked_peers.contains(peer_addr) {
            return false;
        }

        match transport_id {
            Some(transport_id) => !is_bootstrap_transport(transport_id),
            None => true,
        }
    }

    #[cfg(test)]
    pub(in crate::node) fn is_blocked(&self, peer_addr: &NodeAddr) -> bool {
        self.blocked_peers.contains(peer_addr)
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct BootstrapTransports {
    transport_ids: HashSet<TransportId>,
    peer_npubs: HashMap<TransportId, String>,
}

impl BootstrapTransports {
    pub(in crate::node) fn register(&mut self, transport_id: TransportId, peer_npub: String) {
        self.transport_ids.insert(transport_id);
        self.peer_npubs.insert(transport_id, peer_npub);
    }

    #[cfg(test)]
    pub(in crate::node) fn mark(&mut self, transport_id: TransportId) {
        self.transport_ids.insert(transport_id);
    }

    pub(in crate::node) fn remove(&mut self, transport_id: &TransportId) {
        self.transport_ids.remove(transport_id);
        self.peer_npubs.remove(transport_id);
    }

    pub(in crate::node) fn contains(&self, transport_id: &TransportId) -> bool {
        self.transport_ids.contains(transport_id)
    }

    pub(in crate::node) fn peer_npub(&self, transport_id: &TransportId) -> Option<&str> {
        self.peer_npubs.get(transport_id).map(String::as_str)
    }
}
