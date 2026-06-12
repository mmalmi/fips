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
}

impl PendingLookup {
    pub fn new(now_ms: u64) -> Self {
        Self {
            initiated_ms: now_ms,
            last_sent_ms: now_ms,
            attempt: 1,
        }
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

    #[cfg(test)]
    pub(crate) fn contains_key(&self, dest: &NodeAddr) -> bool {
        self.entries.contains_key(dest)
    }

    #[cfg(test)]
    pub(crate) fn get(&self, dest: &NodeAddr) -> Option<&PendingLookup> {
        self.entries.get(dest)
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
