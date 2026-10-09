//! FIPS-specific Bloom filter announcement state management.

use std::collections::{BTreeSet, HashMap, HashSet, hash_map::Entry};

use super::BloomFilter;
use crate::NodeAddr;

/// One immutable input view for a recipient fanout. Shared bits survive the
/// exclusion of any one peer, including overlap with our local identities.
pub(crate) struct OutgoingBloomFilters<'a> {
    peers: &'a HashMap<NodeAddr, BloomFilter>,
    combined: Vec<u8>,
    shared: Vec<u8>,
    hash_count: u8,
}

impl OutgoingBloomFilters<'_> {
    fn excluded(&self, peer: &NodeAddr) -> Option<&BloomFilter> {
        self.peers
            .get(peer)
            .filter(|filter| filter.num_bytes() == self.combined.len())
    }

    pub(crate) fn for_peer(&self, peer: &NodeAddr) -> BloomFilter {
        let mut bytes = self.combined.clone();
        if let Some(excluded) = self.excluded(peer) {
            for ((byte, shared), excluded) in
                bytes.iter_mut().zip(&self.shared).zip(excluded.as_bytes())
            {
                *byte &= !*excluded | *shared;
            }
        }
        BloomFilter::from_bytes(bytes, self.hash_count).expect("valid base filter parameters")
    }

    fn matches(&self, peer: &NodeAddr, last: &BloomFilter) -> bool {
        if last.num_bytes() != self.combined.len() || last.hash_count() != self.hash_count {
            return false;
        }
        match self.excluded(peer) {
            Some(excluded) => last
                .as_bytes()
                .iter()
                .zip(&self.combined)
                .zip(&self.shared)
                .zip(excluded.as_bytes())
                .all(|(((last, all), shared), excluded)| *last == *all & (!*excluded | *shared)),
            None => last.as_bytes() == self.combined,
        }
    }
}

/// State for managing Bloom filter announcements.
///
/// Tracks local filter state and what needs to be sent to peers.
#[derive(Clone, Debug)]
pub struct BloomState {
    /// This node's NodeAddr (always included in outgoing filters).
    own_node_addr: NodeAddr,
    /// Leaf-only nodes we speak for (included in our filter).
    leaf_dependents: HashSet<NodeAddr>,
    /// Whether this node operates in leaf-only mode.
    is_leaf_only: bool,
    /// Rate limiting: minimum interval between outgoing updates (milliseconds).
    update_debounce_ms: u64,
    /// Timestamp of last update sent (per peer, in milliseconds).
    last_update_sent: HashMap<NodeAddr, u64>,
    /// Pending peers and their fast-dispatch retry floors. Periodic maintenance
    /// still uses only the successful-send debounce.
    pending_updates: HashMap<NodeAddr, u64>,
    /// One effective deadline per pending peer, ordered for incremental updates.
    pending_update_deadlines: BTreeSet<(u64, NodeAddr)>,
    /// Cached earliest pending deadline; idle RX turns never scan peer state.
    pending_update_deadline_ms: Option<u64>,
    /// Current sequence number for outgoing filters.
    sequence: u64,
    /// Last outgoing filter sent to each peer (for change detection).
    last_sent_filters: HashMap<NodeAddr, BloomFilter>,
}

impl BloomState {
    /// Create new Bloom state for a node.
    pub fn new(own_node_addr: NodeAddr) -> Self {
        Self {
            own_node_addr,
            leaf_dependents: HashSet::new(),
            is_leaf_only: false,
            update_debounce_ms: 500,
            last_update_sent: HashMap::new(),
            pending_updates: HashMap::new(),
            pending_update_deadlines: BTreeSet::new(),
            pending_update_deadline_ms: None,
            sequence: 0,
            last_sent_filters: HashMap::new(),
        }
    }

    /// Create state for a leaf-only node.
    pub fn leaf_only(own_node_addr: NodeAddr) -> Self {
        let mut state = Self::new(own_node_addr);
        state.is_leaf_only = true;
        state
    }

    /// Get the node's own ID.
    pub fn own_node_addr(&self) -> &NodeAddr {
        &self.own_node_addr
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
    }

    /// Get the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Increment and return the next sequence number.
    pub fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Get the update debounce interval in milliseconds.
    pub fn update_debounce_ms(&self) -> u64 {
        self.update_debounce_ms
    }

    /// Set the update debounce interval.
    pub fn set_update_debounce_ms(&mut self, ms: u64) {
        self.update_debounce_ms = ms;
        self.refresh_pending_deadline();
    }

    /// Add a leaf dependent that we'll include in our filter.
    pub fn add_leaf_dependent(&mut self, node_addr: NodeAddr) {
        self.leaf_dependents.insert(node_addr);
    }

    /// Remove a leaf dependent.
    pub fn remove_leaf_dependent(&mut self, node_addr: &NodeAddr) -> bool {
        self.leaf_dependents.remove(node_addr)
    }

    /// Get the set of leaf dependents.
    pub fn leaf_dependents(&self) -> &HashSet<NodeAddr> {
        &self.leaf_dependents
    }

    /// Number of leaf dependents.
    pub fn leaf_dependent_count(&self) -> usize {
        self.leaf_dependents.len()
    }

    /// Mark that a peer needs an update.
    pub fn mark_update_needed(&mut self, peer_id: NodeAddr) {
        match self.pending_updates.entry(peer_id) {
            Entry::Occupied(_) => return,
            Entry::Vacant(entry) => entry.insert(0),
        };
        self.update_pending_deadline(peer_id, None);
    }

    /// Mark all peers as needing updates.
    pub fn mark_all_updates_needed(&mut self, peer_ids: impl IntoIterator<Item = NodeAddr>) {
        for peer in peer_ids {
            self.mark_update_needed(peer);
        }
    }

    /// Check if a peer needs an update.
    pub fn needs_update(&self, peer_id: &NodeAddr) -> bool {
        self.pending_updates.contains_key(peer_id)
    }

    /// Check if we should send an update to a peer (respecting debounce).
    pub fn should_send_update(&self, peer_id: &NodeAddr, current_time_ms: u64) -> bool {
        if !self.needs_update(peer_id) {
            return false;
        }

        match self.last_update_sent.get(peer_id) {
            Some(&last_time) => {
                current_time_ms >= last_time.saturating_add(self.update_debounce_ms)
            }
            None => true,
        }
    }

    pub(crate) fn pending_update_deadline_ms(&self) -> Option<u64> {
        self.pending_update_deadline_ms
    }

    pub(crate) fn pending_peer_deadline_ms(&self, peer: &NodeAddr) -> Option<u64> {
        let retry = *self.pending_updates.get(peer)?;
        let debounce = self
            .last_update_sent
            .get(peer)
            .map_or(0, |last| last.saturating_add(self.update_debounce_ms));
        Some(retry.max(debounce))
    }

    pub(crate) fn pending_peers_due(&self, now_ms: u64) -> Vec<NodeAddr> {
        self.pending_updates
            .keys()
            .filter(|peer| {
                self.pending_peer_deadline_ms(peer)
                    .is_some_and(|due| due <= now_ms)
            })
            .copied()
            .collect()
    }

    pub(crate) fn defer_update_retry(&mut self, peer: &NodeAddr, retry_at_ms: u64) {
        let previous = self.pending_peer_deadline_ms(peer);
        if let Some(floor) = self.pending_updates.get_mut(peer) {
            if *floor >= retry_at_ms {
                return;
            }
            *floor = (*floor).max(retry_at_ms);
            self.update_pending_deadline(*peer, previous);
        }
    }

    pub(crate) fn defer_pending_retries(&mut self, retry_at_ms: u64) {
        for floor in self.pending_updates.values_mut() {
            *floor = (*floor).max(retry_at_ms);
        }
        self.refresh_pending_deadline();
    }

    fn refresh_pending_deadline(&mut self) {
        self.pending_update_deadlines = self
            .pending_updates
            .keys()
            .filter_map(|peer| self.pending_peer_deadline_ms(peer).map(|due| (due, *peer)))
            .collect();
        self.pending_update_deadline_ms =
            self.pending_update_deadlines.first().map(|(due, _)| *due);
    }

    fn update_pending_deadline(&mut self, peer: NodeAddr, previous: Option<u64>) {
        if let Some(due) = previous {
            self.pending_update_deadlines.remove(&(due, peer));
        }
        if let Some(due) = self.pending_peer_deadline_ms(&peer) {
            self.pending_update_deadlines.insert((due, peer));
        }
        self.pending_update_deadline_ms =
            self.pending_update_deadlines.first().map(|(due, _)| *due);
    }

    /// Whether a previously sent filter needs periodic loss repair. Content
    /// changes and initial announcements remain independently pending/debounced.
    pub(crate) fn refresh_due(&self, peer_id: &NodeAddr, now_ms: u64, interval_ms: u64) -> bool {
        interval_ms > 0
            && self
                .last_update_sent
                .get(peer_id)
                .is_some_and(|last| now_ms.saturating_sub(*last) >= interval_ms)
    }

    /// Record that we sent an update to a peer.
    pub fn record_update_sent(&mut self, peer_id: NodeAddr, current_time_ms: u64) {
        let previous = self.pending_peer_deadline_ms(&peer_id);
        self.last_update_sent.insert(peer_id, current_time_ms);
        self.pending_updates.remove(&peer_id);
        self.update_pending_deadline(peer_id, previous);
    }

    /// Clear all pending updates.
    pub fn clear_pending_updates(&mut self) {
        self.pending_updates.clear();
        self.pending_update_deadlines.clear();
        self.pending_update_deadline_ms = None;
    }

    /// Record the outgoing filter that was sent to a peer.
    pub fn record_sent_filter(&mut self, peer_id: NodeAddr, filter: BloomFilter) {
        self.last_sent_filters.insert(peer_id, filter);
    }

    /// Remove stored filter state for a peer that was removed.
    pub fn remove_peer_state(&mut self, peer_id: &NodeAddr) {
        let previous = self.pending_peer_deadline_ms(peer_id);
        self.last_sent_filters.remove(peer_id);
        self.last_update_sent.remove(peer_id);
        self.pending_updates.remove(peer_id);
        self.update_pending_deadline(*peer_id, previous);
    }

    /// Mark only peers whose outgoing filter has actually changed.
    ///
    /// Compare each outgoing filter against what was last sent. Aggregate the
    /// current inputs once; bits contributed more than once survive any single
    /// peer's exclusion. This avoids remerging every tree filter (and rehashing
    /// local identities) for every recipient, without caching mutable inputs.
    pub fn mark_changed_peers(
        &mut self,
        exclude_from: &NodeAddr,
        peer_addrs: &[NodeAddr],
        peer_filters: &HashMap<NodeAddr, BloomFilter>,
    ) {
        let filters = self.prepare_outgoing_filters(peer_filters);

        for peer_addr in peer_addrs {
            if peer_addr == exclude_from {
                continue;
            }
            let changed = self
                .last_sent_filters
                .get(peer_addr)
                .is_none_or(|last| !filters.matches(peer_addr, last));
            if changed {
                self.mark_update_needed(*peer_addr);
            }
        }
    }

    pub(crate) fn prepare_outgoing_filters<'a>(
        &self,
        peer_filters: &'a HashMap<NodeAddr, BloomFilter>,
    ) -> OutgoingBloomFilters<'a> {
        let base = self.base_filter();
        let mut combined = base.as_bytes().to_vec();
        let mut shared = vec![0; combined.len()];
        for filter in peer_filters
            .values()
            .filter(|filter| filter.num_bits() == base.num_bits())
        {
            for ((all, shared), incoming) in
                combined.iter_mut().zip(&mut shared).zip(filter.as_bytes())
            {
                *shared |= *all & incoming;
                *all |= incoming;
            }
        }
        OutgoingBloomFilters {
            peers: peer_filters,
            combined,
            shared,
            hash_count: base.hash_count(),
        }
    }

    /// Compute the outgoing filter for a specific peer.
    ///
    /// The filter includes:
    /// - This node's own ID
    /// - All leaf dependents
    /// - Entries from other peers' inbound filters (excluding the destination peer)
    ///
    /// The `peer_filters` map contains inbound filters from each peer.
    /// The filter for `exclude_peer` is excluded to prevent routing loops.
    pub fn compute_outgoing_filter(
        &self,
        exclude_peer: &NodeAddr,
        peer_filters: &HashMap<NodeAddr, BloomFilter>,
    ) -> BloomFilter {
        let mut filter = BloomFilter::new();

        // Always include ourselves
        filter.insert(&self.own_node_addr);

        // Include leaf dependents
        for dep in &self.leaf_dependents {
            filter.insert(dep);
        }

        // Merge filters from other peers
        for (peer_id, peer_filter) in peer_filters {
            if peer_id != exclude_peer {
                // Ignore merge errors (size mismatches) - just skip that filter
                let _ = filter.merge(peer_filter);
            }
        }

        filter
    }

    /// Create a base filter containing just this node and its dependents.
    pub fn base_filter(&self) -> BloomFilter {
        let mut filter = BloomFilter::new();
        filter.insert(&self.own_node_addr);
        for dep in &self.leaf_dependents {
            filter.insert(dep);
        }
        filter
    }
}
