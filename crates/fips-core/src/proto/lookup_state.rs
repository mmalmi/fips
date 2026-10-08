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
    /// Unique admission within this node lifetime, including same-ms ID reuse.
    pub(crate) admission_generation: u64,
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
    /// Admitted sends and deferred waiters own their return path until a
    /// response is claimed or the original record expires.
    protected: bool,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, target: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            admission_generation: 0,
            from_peer,
            target,
            timestamp_ms,
            response_forwarded: false,
            protected: false,
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
    // Conservative lower bound; removing the oldest entry may leave it stale,
    // which permits an extra scan but can never delay expiry.
    oldest_timestamp_ms: Option<u64>,
    last_admission_generation: u64,
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

        let Some(generation) = self.last_admission_generation.checked_add(1) else {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: false,
                evicted: false,
            };
        };
        let share = (limits.max_entries / limits.peer_count.max(1)).max(limits.min_per_peer);
        let over_share = self
            .by_peer
            .get(&from_peer)
            .is_some_and(|ids| ids.len() >= share);
        let at_capacity = self.entries.len() >= limits.max_entries;
        let victim = if over_share {
            Some(from_peer)
        } else if at_capacity {
            self.by_peer
                .iter()
                .filter(|(_, ids)| ids.iter().any(|id| !self.entries[id].protected))
                .max_by_key(|(_, ids)| ids.len())
                .map(|(peer, _)| *peer)
        } else {
            None
        };
        let evicted = victim.is_some_and(|peer| self.evict_oldest(peer));
        if (over_share || at_capacity) && !evicted {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: false,
                evicted: false,
            };
        }

        self.last_admission_generation = generation;
        let mut request = RecentRequest::new(from_peer, target, now_ms);
        request.admission_generation = generation;
        self.entries.insert(request_id, request);
        self.note_timestamp(now_ms);
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
            let Some(index) = ids.iter().position(|id| !self.entries[id].protected) else {
                return false;
            };
            let request_id = ids.remove(index).expect("selected admission index");
            (request_id, ids.is_empty())
        };
        if remove_queue {
            self.by_peer.remove(&peer);
        }
        self.entries.remove(&request_id).is_some()
    }

    /// Call only after forwarding admission or successful waiter admission,
    /// before the first transport await. Cancellation keeps the bounded path
    /// alive for any work that may already have been queued.
    pub(crate) fn protect(&mut self, request_id: u64) {
        if let Some(recent) = self.entries.get_mut(&request_id)
            && !recent.response_forwarded
        {
            recent.protected = true;
        }
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
        recent.protected = false;
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
        if self
            .oldest_timestamp_ms
            .is_none_or(|oldest| current_time_ms.saturating_sub(oldest) <= expiry_ms)
        {
            return;
        }
        let previous_len = self.entries.len();
        let mut oldest = None;
        self.entries.retain(|_, entry| {
            if entry.is_expired(current_time_ms, expiry_ms) {
                return false;
            }
            oldest = Some(oldest.map_or(entry.timestamp_ms, |value: u64| {
                value.min(entry.timestamp_ms)
            }));
            true
        });
        self.oldest_timestamp_ms = oldest;
        if self.entries.len() == previous_len {
            return;
        }
        let entries = &self.entries;
        self.by_peer.retain(|_, ids| {
            ids.retain(|request_id| entries.contains_key(request_id));
            !ids.is_empty()
        });
    }

    fn note_timestamp(&mut self, timestamp_ms: u64) {
        self.oldest_timestamp_ms = Some(
            self.oldest_timestamp_ms
                .map_or(timestamp_ms, |oldest| oldest.min(timestamp_ms)),
        );
    }

    #[cfg(test)]
    pub(crate) fn insert(
        &mut self,
        request_id: u64,
        mut request: RecentRequest,
    ) -> Option<RecentRequest> {
        self.last_admission_generation = self
            .last_admission_generation
            .checked_add(1)
            .expect("test request admission generation exhausted");
        request.admission_generation = self.last_admission_generation;
        let from_peer = request.from_peer;
        self.note_timestamp(request.timestamp_ms);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_hint_preserves_boundaries_clock_rollback_and_removed_oldest() {
        let mut recent = RecentDiscoveryRequests::default();
        let peer = NodeAddr::from_bytes([1; 16]);
        let target = NodeAddr::from_bytes([2; 16]);
        let limits = RecentDiscoveryRequestLimits::new(10, 1, 1);
        assert!(
            recent
                .record_request(1, peer, target, 100, limits)
                .accepted()
        );
        assert!(
            recent
                .record_request(2, peer, target, 200, limits)
                .accepted()
        );
        recent.protect(2);
        recent.remove(1);
        recent.purge_expired(151, 50);
        assert!(recent.contains_key(&2));
        assert_eq!(recent.oldest_timestamp_ms, Some(200));
        assert!(
            recent
                .record_request(3, peer, target, 50, limits)
                .accepted()
        );
        recent.purge_expired(40, 0);
        assert_eq!(recent.len(), 2);
        recent.purge_expired(100, 50);
        assert!(recent.contains_key(&3), "exact expiry boundary is retained");
        recent.purge_expired(101, 50);
        assert!(!recent.contains_key(&3));
        recent.purge_expired(250, 50);
        assert!(recent.contains_key(&2));
        recent.purge_expired(251, 50);
        assert!(recent.is_empty(), "protected paths still expire on time");
        assert_eq!(recent.indexed_len(), 0);
        assert_eq!(recent.oldest_timestamp_ms, None);
        recent.insert(4, RecentRequest::new(peer, target, u64::MAX));
        recent.purge_expired(u64::MAX, 0);
        assert!(recent.contains_key(&4));
        recent.insert(4, RecentRequest::new(peer, target, 0));
        recent.purge_expired(u64::MAX, u64::MAX);
        assert!(recent.contains_key(&4));
        recent.purge_expired(u64::MAX, u64::MAX - 1);
        assert!(recent.is_empty());
        assert_eq!(recent.indexed_len(), 0);
    }

    #[test]
    fn protected_paths_keep_their_ingress_share_without_displacing_other_peers() {
        let mut recent = RecentDiscoveryRequests::default();
        let heavy = NodeAddr::from_bytes([1; 16]);
        let light = NodeAddr::from_bytes([2; 16]);
        let target = NodeAddr::from_bytes([3; 16]);
        let limits = RecentDiscoveryRequestLimits::new(4, 2, 1);
        assert!(
            recent
                .record_request(100, light, target, 1, limits)
                .accepted()
        );
        recent.protect(100);
        assert!(
            recent
                .record_request(1, heavy, target, 1, limits)
                .accepted()
        );
        recent.protect(1);
        assert!(
            recent
                .record_request(2, heavy, target, 2, limits)
                .accepted()
        );
        assert!(recent.record_request(3, heavy, target, 3, limits).evicted());
        assert!(recent.contains_key(&1));
        assert!(!recent.contains_key(&2));
        recent.protect(3);
        let rejected = recent.record_request(4, heavy, target, 4, limits);
        assert!(!rejected.accepted() && !rejected.evicted());
        assert!(recent.contains_key(&100));
        assert!(recent.contains_key(&1));
        assert!(recent.contains_key(&3));
        assert!(
            recent
                .record_request(101, light, target, 5, limits)
                .accepted()
        );
        assert_eq!(recent.len(), 4);
        assert_eq!(recent.indexed_len(), 4);
    }

    #[test]
    fn global_capacity_evicts_only_unprotected_records_then_rejects() {
        let mut recent = RecentDiscoveryRequests::default();
        let target = NodeAddr::from_bytes([9; 16]);
        let limits = RecentDiscoveryRequestLimits::new(3, 1, 1);
        for id in 1..=3 {
            let peer = NodeAddr::from_bytes([id as u8; 16]);
            assert!(
                recent
                    .record_request(id, peer, target, id, limits)
                    .accepted()
            );
            if id != 2 {
                recent.protect(id);
            }
        }
        let newcomer = NodeAddr::from_bytes([4; 16]);
        assert!(
            recent
                .record_request(4, newcomer, target, 4, limits)
                .evicted()
        );
        assert!(!recent.contains_key(&2));
        recent.protect(4);
        let rejected = recent.record_request(5, newcomer, target, 5, limits);
        assert!(!rejected.accepted() && !rejected.evicted());
        assert!(
            recent
                .record_request(1, newcomer, target, 5, limits)
                .deduplicated()
        );
        for id in [1, 3, 4] {
            assert!(recent.contains_key(&id));
        }
        assert_eq!(recent.len(), 3);
        assert_eq!(recent.indexed_len(), 3);
    }

    #[test]
    fn only_matching_response_releases_protection_without_resetting_dedup() {
        let mut recent = RecentDiscoveryRequests::default();
        let peer = NodeAddr::from_bytes([1; 16]);
        let target = NodeAddr::from_bytes([2; 16]);
        let limits = RecentDiscoveryRequestLimits::new(1, 1, 1);
        assert!(recent.record_request(1, peer, target, 1, limits).accepted());
        recent.protect(1);
        assert_eq!(
            recent.claim_response_forward(1, peer),
            RecentResponseForward::Missing
        );
        assert!(!recent.record_request(2, peer, target, 2, limits).accepted());
        assert_eq!(
            recent.claim_response_forward(1, target),
            RecentResponseForward::Forward { from_peer: peer }
        );
        assert!(
            recent
                .record_request(1, peer, target, 3, limits)
                .deduplicated()
        );
        recent.protect(1);
        assert_eq!(
            recent.claim_response_forward(1, target),
            RecentResponseForward::AlreadyForwarded
        );
        assert!(recent.record_request(2, peer, target, 4, limits).evicted());
        assert_eq!(recent.len(), 1);
        assert_eq!(recent.indexed_len(), 1);
    }

    #[test]
    fn abandoned_work_expires_at_the_original_deadline() {
        let mut recent = RecentDiscoveryRequests::default();
        let peer = NodeAddr::from_bytes([1; 16]);
        let target = NodeAddr::from_bytes([2; 16]);
        let limits = RecentDiscoveryRequestLimits::new(1, 1, 1);
        assert!(
            recent
                .record_request(1, peer, target, 100, limits)
                .accepted()
        );
        recent.protect(1);
        recent.protect(1);
        recent.purge_expired(10_100, 10_000);
        assert!(
            !recent
                .record_request(2, peer, target, 10_100, limits)
                .accepted()
        );
        recent.purge_expired(10_101, 10_000);
        assert!(recent.is_empty());
        assert_eq!(recent.indexed_len(), 0);
        assert!(
            recent
                .record_request(2, peer, target, 10_101, limits)
                .accepted()
        );
    }

    #[test]
    fn same_millisecond_id_readmission_has_a_new_owner() {
        let mut recent = RecentDiscoveryRequests::default();
        let peer = NodeAddr::from_bytes([1; 16]);
        let target = NodeAddr::from_bytes([2; 16]);
        let limits = RecentDiscoveryRequestLimits::new(1, 1, 1);
        assert!(
            recent
                .record_request(10, peer, target, 7, limits)
                .accepted()
        );
        let owner = recent.get(&10).unwrap().admission_generation;
        assert!(
            recent
                .record_request(10, peer, target, 7, limits)
                .deduplicated()
        );
        assert_eq!(recent.get(&10).unwrap().admission_generation, owner);
        assert!(recent.record_request(11, peer, target, 7, limits).evicted());
        assert!(recent.record_request(10, peer, target, 7, limits).evicted());
        let replacement = recent.get(&10).unwrap();
        assert_eq!(
            (
                replacement.from_peer,
                replacement.target,
                replacement.timestamp_ms
            ),
            (peer, target, 7)
        );
        assert_ne!(replacement.admission_generation, owner);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn admission_generation_cannot_wrap_or_evict_on_exhaustion() {
        let mut recent = RecentDiscoveryRequests::default();
        let peer = NodeAddr::from_bytes([1; 16]);
        let target = NodeAddr::from_bytes([2; 16]);
        let limits = RecentDiscoveryRequestLimits::new(1, 1, 1);
        recent.last_admission_generation = u64::MAX - 1;
        assert!(
            recent
                .record_request(10, peer, target, 7, limits)
                .accepted()
        );
        assert!(
            !recent
                .record_request(11, peer, target, 7, limits)
                .accepted()
        );
        assert_eq!(recent.get(&10).unwrap().admission_generation, u64::MAX);
        assert_eq!(recent.len(), 1);
    }
}
