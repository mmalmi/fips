use crate::NodeAddr;
use std::collections::HashMap;

/// Tracks a pending discovery lookup with retry state.
#[derive(Clone, Debug)]
pub struct PendingLookup {
    /// When the lookup was first initiated.
    pub initiated_ms: u64,
    /// When the last attempt was sent.
    pub last_sent_ms: u64,
    /// Current attempt number (1 = initial, 2 = first retry, ...).
    pub attempt: u8,
    origin_request_ids: Vec<u64>,
}

impl PendingLookup {
    pub fn new(now_ms: u64) -> Self {
        Self {
            initiated_ms: now_ms,
            last_sent_ms: now_ms,
            attempt: 1,
            origin_request_ids: Vec::new(),
        }
    }

    fn record_origin_request(&mut self, request_id: u64) {
        self.origin_request_ids.push(request_id);
    }

    fn matches_origin_request(&self, request_id: u64) -> bool {
        self.origin_request_ids.contains(&request_id)
    }

    #[cfg(test)]
    fn last_origin_request_id(&self) -> Option<u64> {
        self.origin_request_ids.last().copied()
    }
}

/// Admission result for the pending discovery lookup queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingDiscoveryLookupAdmission {
    accepted: bool,
    deduplicated: bool,
    queue_full: bool,
}

impl PendingDiscoveryLookupAdmission {
    pub(crate) fn accepted(&self) -> bool {
        self.accepted
    }

    pub(crate) fn deduplicated(&self) -> bool {
        self.deduplicated
    }

    pub(crate) fn queue_full(&self) -> bool {
        self.queue_full
    }
}

/// In-flight discovery lookups keyed by target node address.
#[derive(Debug, Default)]
pub(crate) struct PendingDiscoveryLookups {
    entries: HashMap<NodeAddr, PendingLookup>,
}

impl PendingDiscoveryLookups {
    pub(crate) fn admission_for(
        &self,
        dest: &NodeAddr,
        max_pending: usize,
    ) -> PendingDiscoveryLookupAdmission {
        if self.entries.contains_key(dest) {
            return PendingDiscoveryLookupAdmission {
                accepted: false,
                deduplicated: true,
                queue_full: false,
            };
        }

        if self.entries.len() >= max_pending {
            return PendingDiscoveryLookupAdmission {
                accepted: false,
                deduplicated: false,
                queue_full: true,
            };
        }

        PendingDiscoveryLookupAdmission {
            accepted: true,
            deduplicated: false,
            queue_full: false,
        }
    }

    pub(crate) fn insert_new(&mut self, dest: NodeAddr, now_ms: u64) -> Option<PendingLookup> {
        self.entries.insert(dest, PendingLookup::new(now_ms))
    }

    #[cfg(test)]
    pub(crate) fn insert(
        &mut self,
        dest: NodeAddr,
        lookup: PendingLookup,
    ) -> Option<PendingLookup> {
        self.entries.insert(dest, lookup)
    }

    pub(crate) fn remove(&mut self, dest: &NodeAddr) -> Option<PendingLookup> {
        self.entries.remove(dest)
    }

    pub(crate) fn contains_key(&self, dest: &NodeAddr) -> bool {
        self.entries.contains_key(dest)
    }

    pub(crate) fn record_origin_request(&mut self, dest: &NodeAddr, request_id: u64) {
        if let Some(entry) = self.entries.get_mut(dest) {
            entry.record_origin_request(request_id);
        }
    }

    pub(crate) fn matches_origin_request(&self, dest: &NodeAddr, request_id: u64) -> bool {
        self.entries
            .get(dest)
            .is_some_and(|entry| entry.matches_origin_request(request_id))
    }

    #[cfg(test)]
    pub(crate) fn get(&self, dest: &NodeAddr) -> Option<&PendingLookup> {
        self.entries.get(dest)
    }

    #[cfg(test)]
    pub(crate) fn last_origin_request_id(&self, dest: &NodeAddr) -> Option<u64> {
        self.entries
            .get(dest)
            .and_then(PendingLookup::last_origin_request_id)
    }

    pub(crate) fn get_mut(&mut self, dest: &NodeAddr) -> Option<&mut PendingLookup> {
        self.entries.get_mut(dest)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &PendingLookup)> {
        self.entries.iter()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}
