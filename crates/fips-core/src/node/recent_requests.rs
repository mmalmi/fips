use super::*;

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
    /// When we received this request (Unix milliseconds).
    pub(crate) timestamp_ms: u64,
    /// Whether we've already forwarded a response for this request.
    /// Prevents response routing loops when convergent request paths
    /// create bidirectional entries in recent_requests.
    pub(crate) response_forwarded: bool,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            from_peer,
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
    cache_full: bool,
}

impl RecentDiscoveryRequestAdmission {
    pub(crate) fn accepted(&self) -> bool {
        self.accepted
    }

    pub(crate) fn deduplicated(&self) -> bool {
        self.deduplicated
    }

    pub(crate) fn cache_full(&self) -> bool {
        self.cache_full
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
}

impl RecentDiscoveryRequests {
    pub(crate) fn record_request(
        &mut self,
        request_id: u64,
        from_peer: NodeAddr,
        now_ms: u64,
        max_entries: usize,
    ) -> RecentDiscoveryRequestAdmission {
        if self.entries.contains_key(&request_id) {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: true,
                cache_full: false,
            };
        }

        if self.entries.len() >= max_entries {
            return RecentDiscoveryRequestAdmission {
                accepted: false,
                deduplicated: false,
                cache_full: true,
            };
        }

        self.entries
            .insert(request_id, RecentRequest::new(from_peer, now_ms));
        RecentDiscoveryRequestAdmission {
            accepted: true,
            deduplicated: false,
            cache_full: false,
        }
    }

    pub(crate) fn claim_response_forward(&mut self, request_id: u64) -> RecentResponseForward {
        let Some(recent) = self.entries.get_mut(&request_id) else {
            return RecentResponseForward::Missing;
        };

        if recent.response_forwarded {
            return RecentResponseForward::AlreadyForwarded;
        }

        recent.response_forwarded = true;
        RecentResponseForward::Forward {
            from_peer: recent.from_peer,
        }
    }

    pub(crate) fn purge_expired(&mut self, current_time_ms: u64, expiry_ms: u64) {
        self.entries
            .retain(|_, entry| !entry.is_expired(current_time_ms, expiry_ms));
    }

    #[cfg(test)]
    pub(crate) fn insert(
        &mut self,
        request_id: u64,
        request: RecentRequest,
    ) -> Option<RecentRequest> {
        self.entries.insert(request_id, request)
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
}
