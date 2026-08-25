use crate::NodeAddr;
use std::collections::{HashMap, VecDeque};

/// Recent request tracking for dedup and reverse-path forwarding.
///
/// When a LookupRequest is forwarded through a node, the node stores the
/// request_id and which peer sent it. When the corresponding LookupResponse
/// arrives, it's forwarded back to that peer (reverse-path forwarding).
/// The `response_forwarded` flag prevents response routing loops.
#[derive(Clone, Debug)]
pub(crate) struct RecentRequest {
    /// The peer who sent this request to us.
    pub(crate) from_peer: NodeAddr,
    /// Target named by the authenticated request carrying this ID.
    pub(crate) target: NodeAddr,
    /// When we received this request (Unix milliseconds).
    pub(crate) timestamp_ms: u64,
    /// Whether we've already forwarded a response for this request.
    /// Prevents response routing loops when convergent request paths
    /// create bidirectional entries in recent_requests.
    pub(crate) response_forwarded: bool,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, target: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            from_peer,
            target,
            timestamp_ms,
            response_forwarded: false,
        }
    }

    /// Check if this entry has expired (older than expiry_ms).
    pub(crate) fn is_expired(&self, current_time_ms: u64, expiry_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.timestamp_ms) > expiry_ms
    }
}

/// Admission result for recent discovery request tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecentDiscoveryRequestAdmission {
    accepted: bool,
    deduplicated: bool,
    evicted: bool,
}

/// Resource bounds used when admitting one reverse-path lookup record.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecentDiscoveryRequestLimits {
    pub(crate) max_entries: usize,
    pub(crate) peer_count: usize,
    pub(crate) min_per_peer: usize,
}

impl RecentDiscoveryRequestLimits {
    pub(crate) const fn new(max_entries: usize, peer_count: usize, min_per_peer: usize) -> Self {
        Self {
            max_entries,
            peer_count,
            min_per_peer,
        }
    }
}

impl RecentDiscoveryRequestAdmission {
    pub(crate) fn accepted(&self) -> bool {
        self.accepted
    }

    pub(crate) fn deduplicated(&self) -> bool {
        self.deduplicated
    }

    pub(crate) fn evicted(&self) -> bool {
        self.evicted
    }
}

/// Reverse-path forwarding decision for a LookupResponse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecentResponseForward {
    Missing,
    AlreadyForwarded,
    Forward { from_peer: NodeAddr },
}

/// Recent discovery requests used for dedup and reverse-path forwarding.
#[derive(Debug, Default)]
pub(crate) struct RecentDiscoveryRequests {
    entries: HashMap<u64, RecentRequest>,
    /// Arrival order partitioned by authenticated ingress peer. This lets a
    /// heavy peer pay for its own admission instead of evicting a light
    /// peer's response path.
    by_peer: HashMap<NodeAddr, VecDeque<u64>>,
}

impl RecentDiscoveryRequests {
    pub(crate) fn record_request(
        &mut self,
        request_id: u64,
        from_peer: NodeAddr,
        target: NodeAddr,
        now_ms: u64,
        limits: RecentDiscoveryRequestLimits,
    ) -> RecentDiscoveryRequestAdmission {
        if self.entries.contains_key(&request_id) {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: true,
                evicted: false,
            };
        }

        if limits.max_entries == 0 {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: false,
                evicted: false,
            };
        }

        let share = (limits.max_entries / limits.peer_count.max(1)).max(limits.min_per_peer);
        let over_share = self
            .by_peer
            .get(&from_peer)
            .is_some_and(|ids| ids.len() >= share);
        let victim = if over_share {
            Some(from_peer)
        } else if self.entries.len() >= limits.max_entries {
            self.by_peer
                .iter()
                .max_by_key(|(_, ids)| ids.len())
                .map(|(peer, _)| *peer)
        } else {
            None
        };
        let evicted = victim.is_some_and(|peer| self.evict_oldest(peer));

        self.entries
            .insert(request_id, RecentRequest::new(from_peer, target, now_ms));
        self.by_peer
            .entry(from_peer)
            .or_default()
            .push_back(request_id);
        RecentDiscoveryRequestAdmission {
            accepted: true,
            deduplicated: false,
            evicted,
        }
    }

    fn evict_oldest(&mut self, peer: NodeAddr) -> bool {
        let (request_id, remove_queue) = {
            let Some(ids) = self.by_peer.get_mut(&peer) else {
                return false;
            };
            let Some(request_id) = ids.pop_front() else {
                return false;
            };
            (request_id, ids.is_empty())
        };
        if remove_queue {
            self.by_peer.remove(&peer);
        }
        self.entries.remove(&request_id).is_some()
    }

    pub(crate) fn claim_response_forward(
        &mut self,
        request_id: u64,
        target: NodeAddr,
    ) -> RecentResponseForward {
        let Some(recent) = self.entries.get_mut(&request_id) else {
            return RecentResponseForward::Missing;
        };

        if recent.target != target {
            return RecentResponseForward::Missing;
        }

        if recent.response_forwarded {
            return RecentResponseForward::AlreadyForwarded;
        }

        recent.response_forwarded = true;
        RecentResponseForward::Forward {
            from_peer: recent.from_peer,
        }
    }

    /// Remove a reverse-path entry and its per-peer admission index.
    pub(crate) fn remove(&mut self, request_id: u64) -> Option<RecentRequest> {
        let removed = self.entries.remove(&request_id)?;
        let from_peer = removed.from_peer;
        let remove_peer_index = self.by_peer.get_mut(&from_peer).is_some_and(|ids| {
            ids.retain(|candidate| *candidate != request_id);
            ids.is_empty()
        });
        if remove_peer_index {
            self.by_peer.remove(&from_peer);
        }
        Some(removed)
    }

    pub(crate) fn purge_expired(&mut self, current_time_ms: u64, expiry_ms: u64) {
        self.entries
            .retain(|_, entry| !entry.is_expired(current_time_ms, expiry_ms));
        let entries = &self.entries;
        self.by_peer.retain(|_, ids| {
            ids.retain(|request_id| entries.contains_key(request_id));
            !ids.is_empty()
        });
    }

    #[cfg(test)]
    pub(crate) fn insert(
        &mut self,
        request_id: u64,
        request: RecentRequest,
    ) -> Option<RecentRequest> {
        let from_peer = request.from_peer;
        let previous = self.entries.insert(request_id, request);
        if previous.is_none() {
            self.by_peer
                .entry(from_peer)
                .or_default()
                .push_back(request_id);
        }
        previous
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, request_id: &u64) -> bool {
        self.entries.contains_key(request_id)
    }

    pub(crate) fn get(&self, request_id: &u64) -> Option<&RecentRequest> {
        self.entries.get(request_id)
    }

    #[cfg(test)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &RecentRequest> {
        self.entries.values()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn indexed_len(&self) -> usize {
        self.by_peer.values().map(VecDeque::len).sum()
    }
}
