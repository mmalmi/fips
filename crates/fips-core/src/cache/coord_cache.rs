//! Coordinate cache for routing decisions.
//!
//! Maps node addresses to their tree coordinates, enabling data packets
//! to be routed without carrying coordinates in every packet. Populated
//! by SessionSetup packets.

use std::collections::HashMap;

use super::CacheStats;
use super::entry::CacheEntry;
use crate::NodeAddr;
use crate::tree::TreeCoordinate;

/// Default maximum entries in coordinate cache.
pub const DEFAULT_COORD_CACHE_SIZE: usize = 50_000;

/// Default TTL for coordinate cache entries (5 minutes in milliseconds).
pub const DEFAULT_COORD_CACHE_TTL_MS: u64 = 300_000;

/// Result of attempting to write an unauthenticated coordinate hint.
///
/// Callers must observe this because a live verified entry can refuse the
/// write, and treating that refusal as a successful warm would make routing
/// state and observability disagree.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintOutcome {
    Inserted,
    Changed,
    Unchanged,
    Rejected,
}

/// Coordinate cache for routing decisions.
///
/// Maps node addresses to their tree coordinates, enabling data packets
/// to be routed without carrying coordinates in every packet. Populated
/// by SessionSetup packets.
#[derive(Clone, Debug)]
pub struct CoordCache {
    /// NodeAddr -> coordinates mapping.
    entries: HashMap<NodeAddr, CacheEntry>,
    /// Maximum number of entries.
    max_entries: usize,
    /// Default TTL for entries (milliseconds).
    default_ttl_ms: u64,
}

impl CoordCache {
    /// Create a new coordinate cache.
    pub fn new(max_entries: usize, default_ttl_ms: u64) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(1000)),
            max_entries,
            default_ttl_ms,
        }
    }

    /// Create a cache with default parameters.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_COORD_CACHE_SIZE, DEFAULT_COORD_CACHE_TTL_MS)
    }

    /// Get the maximum capacity.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Get the default TTL.
    pub fn default_ttl_ms(&self) -> u64 {
        self.default_ttl_ms
    }

    /// Set the default TTL.
    pub fn set_default_ttl_ms(&mut self, ttl_ms: u64) {
        self.default_ttl_ms = ttl_ms;
    }

    /// Insert or update a cache entry from an unauthenticated hint.
    ///
    /// This compatibility entry point retains the original `()` return type.
    /// Internal callers that must distinguish an accepted hint from a rejected
    /// overwrite use [`Self::insert_checked`].
    pub fn insert(&mut self, addr: NodeAddr, coords: TreeCoordinate, current_time_ms: u64) {
        let _ = self.insert_checked(addr, coords, current_time_ms);
    }

    /// Insert or update an unauthenticated hint and report the outcome.
    pub fn insert_checked(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) -> HintOutcome {
        self.insert_hint_with_ttl(addr, coords, current_time_ms, self.default_ttl_ms)
    }

    fn insert_hint_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) -> HintOutcome {
        if let Some(entry) = self.entries.get_mut(&addr) {
            if entry.is_verified(current_time_ms) {
                return HintOutcome::Rejected;
            }
            let changed = entry.coords() != &coords;
            entry.update(coords, current_time_ms, ttl_ms);
            return if changed {
                HintOutcome::Changed
            } else {
                HintOutcome::Unchanged
            };
        }

        if self.entries.len() >= self.max_entries {
            self.evict_hint_victim(current_time_ms);
        }
        if self.entries.len() >= self.max_entries {
            return HintOutcome::Rejected;
        }

        let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
        self.entries.insert(addr, entry);
        HintOutcome::Inserted
    }

    /// Insert or update an unauthenticated hint with path MTU information.
    ///
    /// This compatibility entry point retains the original `()` return type.
    /// Use [`Self::insert_with_path_mtu_checked`] when rejection matters.
    ///
    /// Used by discovery response handling to store the discovered path MTU
    /// alongside the target's coordinates. Updates keep the tighter MTU so a
    /// later response cannot loosen an established clamp.
    pub fn insert_with_path_mtu(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        path_mtu: u16,
    ) {
        let _ = self.insert_with_path_mtu_checked(addr, coords, current_time_ms, path_mtu);
    }

    /// Insert a hint with path-MTU information and report the outcome.
    pub fn insert_with_path_mtu_checked(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        path_mtu: u16,
    ) -> HintOutcome {
        if let Some(entry) = self.entries.get_mut(&addr) {
            if entry.is_verified(current_time_ms) {
                return HintOutcome::Rejected;
            }
            let changed = entry.coords() != &coords;
            entry.update(coords, current_time_ms, self.default_ttl_ms);
            let path_mtu = entry
                .path_mtu()
                .map_or(path_mtu, |existing| existing.min(path_mtu));
            entry.set_path_mtu(path_mtu);
            return if changed {
                HintOutcome::Changed
            } else {
                HintOutcome::Unchanged
            };
        }

        if self.entries.len() >= self.max_entries {
            self.evict_hint_victim(current_time_ms);
        }
        if self.entries.len() >= self.max_entries {
            return HintOutcome::Rejected;
        }

        let mut entry = CacheEntry::new(coords, current_time_ms, self.default_ttl_ms);
        entry.set_path_mtu(path_mtu);
        self.entries.insert(addr, entry);
        HintOutcome::Inserted
    }

    /// Insert a hint only when its key and root agree with the local routing
    /// context. This is the write-site guard used by plaintext session headers,
    /// including the optimized pre-decryption coordinate-warm path.
    pub fn insert_current_root_hint(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_root: &NodeAddr,
        current_time_ms: u64,
    ) -> Option<HintOutcome> {
        if coords.node_addr() != &addr || coords.root_id() != current_root {
            return None;
        }
        Some(self.insert_checked(addr, coords, current_time_ms))
    }

    /// Insert or update coordinates established by a proof-verified lookup.
    pub fn insert_verified(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) {
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.update_verified(coords, current_time_ms, self.default_ttl_ms);
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_verified_victim(current_time_ms);
        }
        if self.entries.len() >= self.max_entries {
            return;
        }

        let entry = CacheEntry::new_verified(coords, current_time_ms, self.default_ttl_ms);
        self.entries.insert(addr, entry);
    }

    /// Insert or update proof-verified coordinates with their discovered MTU.
    ///
    /// A verified response replaces MTU state that arrived with a hint. For two
    /// still-verified responses, retain the fork's existing never-loosen rule.
    pub fn insert_verified_with_path_mtu(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        path_mtu: u16,
    ) {
        if let Some(entry) = self.entries.get_mut(&addr) {
            let keep_tighter = entry.is_verified(current_time_ms);
            let previous_path_mtu = entry.path_mtu();
            entry.update_verified(coords, current_time_ms, self.default_ttl_ms);
            let path_mtu = if keep_tighter {
                previous_path_mtu.map_or(path_mtu, |existing| existing.min(path_mtu))
            } else {
                path_mtu
            };
            entry.set_path_mtu(path_mtu);
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_verified_victim(current_time_ms);
        }
        if self.entries.len() >= self.max_entries {
            return;
        }

        let mut entry = CacheEntry::new_verified(coords, current_time_ms, self.default_ttl_ms);
        entry.set_path_mtu(path_mtu);
        self.entries.insert(addr, entry);
    }

    /// Insert with a custom TTL.
    ///
    /// This compatibility entry point retains the original `()` return type.
    /// Use [`Self::insert_with_ttl_checked`] when rejection matters.
    pub fn insert_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) {
        let _ = self.insert_with_ttl_checked(addr, coords, current_time_ms, ttl_ms);
    }

    /// Insert a hint with a custom TTL and report the outcome.
    pub fn insert_with_ttl_checked(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) -> HintOutcome {
        self.insert_hint_with_ttl(addr, coords, current_time_ms, ttl_ms)
    }

    /// Look up coordinates for an address (without touching).
    pub fn get(&self, addr: &NodeAddr, current_time_ms: u64) -> Option<&TreeCoordinate> {
        self.entries.get(addr).and_then(|entry| {
            if entry.is_expired(current_time_ms) {
                None
            } else {
                Some(entry.coords())
            }
        })
    }

    /// Look up coordinates and refresh (update last_used and extend TTL).
    pub fn get_and_touch(
        &mut self,
        addr: &NodeAddr,
        current_time_ms: u64,
    ) -> Option<&TreeCoordinate> {
        // Check and remove if expired
        if let Some(entry) = self.entries.get(addr)
            && entry.is_expired(current_time_ms)
        {
            self.entries.remove(addr);
            return None;
        }

        // Refresh TTL and return
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.refresh(current_time_ms, self.default_ttl_ms);
            Some(entry.coords())
        } else {
            None
        }
    }

    /// Get the full cache entry.
    pub fn get_entry(&self, addr: &NodeAddr) -> Option<&CacheEntry> {
        self.entries.get(addr)
    }

    /// Remove an entry.
    pub fn remove(&mut self, addr: &NodeAddr) -> Option<CacheEntry> {
        self.entries.remove(addr)
    }

    /// Check if an address is cached (and not expired).
    pub fn contains(&self, addr: &NodeAddr, current_time_ms: u64) -> bool {
        self.get(addr, current_time_ms).is_some()
    }

    /// Number of entries (including expired).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over non-expired entries.
    pub fn iter(&self, current_time_ms: u64) -> impl Iterator<Item = (&NodeAddr, &CacheEntry)> {
        self.entries
            .iter()
            .filter(move |(_, entry)| !entry.is_expired(current_time_ms))
    }

    /// Remove all expired entries.
    pub fn purge_expired(&mut self, current_time_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| !entry.is_expired(current_time_ms));
        before - self.entries.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drop entries whose cached destination ancestry contains `node_addr`.
    ///
    /// When this node changes position in the tree, destinations downstream of
    /// its old coordinate prefix must be re-learned. Unrelated same-root entries
    /// remain usable and are retained.
    pub fn invalidate_via_node(&mut self, node_addr: &NodeAddr) -> usize {
        let len_before = self.entries.len();
        self.entries
            .retain(|_, entry| !entry.coords().contains(node_addr));
        len_before - self.entries.len()
    }

    /// Drop entries whose cached root differs from `current_root`.
    ///
    /// Entries from a stale root cannot route after a root change; removing them
    /// prevents active traffic from keeping those stale entries alive forever by
    /// refreshing their TTL.
    pub fn invalidate_other_roots(&mut self, current_root: &NodeAddr) -> usize {
        let len_before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.coords().root_id() == current_root);
        len_before - self.entries.len()
    }

    fn evict_expired(&mut self, current_time_ms: u64) -> bool {
        let expired_key = self
            .entries
            .iter()
            .find(|(_, e)| e.is_expired(current_time_ms))
            .map(|(k, _)| *k);

        if let Some(key) = expired_key {
            self.entries.remove(&key);
            return true;
        }
        false
    }

    /// Make room for a hint without evicting a live verified entry.
    fn evict_hint_victim(&mut self, current_time_ms: u64) {
        if self.evict_expired(current_time_ms) {
            return;
        }

        let lru_key = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.is_verified(current_time_ms))
            .max_by_key(|(_, e)| e.idle_time(current_time_ms))
            .map(|(k, _)| *k);

        if let Some(key) = lru_key {
            self.entries.remove(&key);
        }
    }

    /// A verified insertion may replace the least-recent verified entry when
    /// necessary; unlike hints, it cannot be used to grow past the hard cap.
    fn evict_verified_victim(&mut self, current_time_ms: u64) {
        if self.evict_expired(current_time_ms) {
            return;
        }
        let lru_key = self
            .entries
            .iter()
            .max_by_key(|(_, entry)| entry.idle_time(current_time_ms))
            .map(|(key, _)| *key);
        if let Some(key) = lru_key {
            self.entries.remove(&key);
        }
    }

    /// Get cache statistics.
    pub fn stats(&self, current_time_ms: u64) -> CacheStats {
        let mut expired = 0;
        let mut total_age = 0u64;

        for entry in self.entries.values() {
            if entry.is_expired(current_time_ms) {
                expired += 1;
            }
            total_age += entry.age(current_time_ms);
        }

        CacheStats {
            entries: self.entries.len(),
            max_entries: self.max_entries,
            expired,
            avg_age_ms: if self.entries.is_empty() {
                0
            } else {
                total_age / self.entries.len() as u64
            },
        }
    }
}

impl Default for CoordCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CoordSource, VERIFIED_TTL_MS};

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

    #[test]
    fn test_coord_cache_basic() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(addr, coords.clone(), 0);

        assert!(cache.contains(&addr, 0));
        assert_eq!(cache.get(&addr, 0), Some(&coords));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_coord_cache_expiry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(addr, coords, 0);

        assert!(cache.contains(&addr, 500));
        assert!(!cache.contains(&addr, 1500));
    }

    #[test]
    fn test_coord_cache_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert(addr, make_coords(&[1, 0]), 0);
        cache.insert(addr, make_coords(&[1, 2, 0]), 500);

        assert_eq!(cache.len(), 1);
        let coords = cache.get(&addr, 500).unwrap();
        assert_eq!(coords.depth(), 2);
    }

    #[test]
    fn test_coord_cache_eviction() {
        let mut cache = CoordCache::new(2, 10000);

        let addr1 = make_node_addr(1);
        let addr2 = make_node_addr(2);
        let addr3 = make_node_addr(3);

        cache.insert(addr1, make_coords(&[1, 0]), 0);
        cache.insert(addr2, make_coords(&[2, 0]), 100);

        // Touch addr2 to make it more recent
        let _ = cache.get_and_touch(&addr2, 200);

        // Insert addr3, should evict addr1 (LRU)
        cache.insert(addr3, make_coords(&[3, 0]), 300);

        assert!(!cache.contains(&addr1, 300));
        assert!(cache.contains(&addr2, 300));
        assert!(cache.contains(&addr3, 300));
    }

    #[test]
    fn test_coord_cache_evict_expired_first() {
        let mut cache = CoordCache::new(2, 100);

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

        // At time 150, addr1 is expired, addr2 is not
        cache.insert(make_node_addr(3), make_coords(&[3, 0]), 150);

        // addr1 should be evicted (expired), not addr2 (LRU but not expired)
        assert!(!cache.contains(&make_node_addr(1), 150));
        assert!(cache.contains(&make_node_addr(2), 150));
        assert!(cache.contains(&make_node_addr(3), 150));
    }

    #[test]
    fn test_coord_cache_purge_expired() {
        let mut cache = CoordCache::new(100, 100);

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0); // expires at 100
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50); // expires at 150
        cache.insert(make_node_addr(3), make_coords(&[3, 0]), 200); // expires at 300

        assert_eq!(cache.len(), 3);

        let purged = cache.purge_expired(151); // both addr1 and addr2 expired

        // Entry 1 and 2 expired, entry 3 still valid
        assert_eq!(purged, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&make_node_addr(3), 151));
    }

    #[test]
    fn test_coord_cache_stats() {
        let mut cache = CoordCache::new(100, 100);

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

        let stats = cache.stats(150);

        assert_eq!(stats.entries, 2);
        assert_eq!(stats.max_entries, 100);
        assert_eq!(stats.expired, 1); // addr1 expired
        assert!(stats.avg_age_ms > 0);
    }

    #[test]
    fn test_coord_cache_insert_with_ttl() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);

        // Should expire at 200, not the default 1000
        assert!(cache.contains(&addr, 100));
        assert!(!cache.contains(&addr, 201));
    }

    #[test]
    fn test_coord_cache_insert_with_ttl_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);
        cache.insert_with_ttl(addr, make_coords(&[1, 2, 0]), 100, 300);

        assert_eq!(cache.len(), 1);
        let coords = cache.get(&addr, 100).unwrap();
        assert_eq!(coords.depth(), 2);
        // New TTL: 100 + 300 = 400
        assert!(cache.contains(&addr, 399));
        assert!(!cache.contains(&addr, 401));
    }

    #[test]
    fn test_coord_cache_get_and_touch_removes_expired() {
        let mut cache = CoordCache::new(100, 100);
        let addr = make_node_addr(1);

        cache.insert(addr, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        // Entry expired at time 200
        let result = cache.get_and_touch(&addr, 200);
        assert!(result.is_none());
        // Entry should be removed from the map
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_coord_cache_get_entry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert(addr, make_coords(&[1, 0]), 500);

        let entry = cache.get_entry(&addr).unwrap();
        assert_eq!(entry.created_at(), 500);
        assert_eq!(entry.expires_at(), 1500);

        assert!(cache.get_entry(&make_node_addr(99)).is_none());
    }

    #[test]
    fn test_coord_cache_remove() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert(addr, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        let removed = cache.remove(&addr);
        assert!(removed.is_some());
        assert_eq!(cache.len(), 0);

        // Removing again returns None
        assert!(cache.remove(&addr).is_none());
    }

    #[test]
    fn test_coord_cache_clear_and_is_empty() {
        let mut cache = CoordCache::new(100, 1000);

        assert!(cache.is_empty());

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_coord_cache_invalidate_via_node_is_surgical() {
        let mut cache = CoordCache::new(100, 1000);
        let node = make_node_addr(1);
        let downstream = make_node_addr(2);
        let sibling = make_node_addr(3);

        cache.insert(downstream, make_coords(&[2, 1, 0]), 0);
        cache.insert(sibling, make_coords(&[3, 4, 0]), 0);

        assert_eq!(cache.invalidate_via_node(&node), 1);
        assert!(!cache.contains(&downstream, 0));
        assert!(cache.contains(&sibling, 0));
    }

    #[test]
    fn test_coord_cache_invalidate_other_roots_keeps_current_root() {
        let mut cache = CoordCache::new(100, 1000);
        let current_root = make_node_addr(0);
        let current = make_node_addr(2);
        let stale = make_node_addr(3);

        cache.insert(current, make_coords(&[2, 1, 0]), 0);
        cache.insert(stale, make_coords(&[3, 4, 9]), 0);

        assert_eq!(cache.invalidate_other_roots(&current_root), 1);
        assert!(cache.contains(&current, 0));
        assert!(!cache.contains(&stale, 0));
    }

    #[test]
    fn test_coord_cache_default() {
        let cache = CoordCache::default();

        assert_eq!(cache.max_entries(), DEFAULT_COORD_CACHE_SIZE);
        assert_eq!(cache.default_ttl_ms(), DEFAULT_COORD_CACHE_TTL_MS);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_coord_cache_set_default_ttl() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.set_default_ttl_ms(200);
        assert_eq!(cache.default_ttl_ms(), 200);

        cache.insert(addr, make_coords(&[1, 0]), 0);
        // New TTL applies: expires at 200
        assert!(cache.contains(&addr, 100));
        assert!(!cache.contains(&addr, 201));
    }

    #[test]
    fn test_coord_cache_stats_empty() {
        let cache = CoordCache::new(100, 1000);
        let stats = cache.stats(0);

        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, 100);
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.avg_age_ms, 0);
    }

    #[test]
    fn hint_does_not_displace_live_verified_entry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let verified = make_coords(&[1, 0]);
        let forged = make_coords(&[1, 2, 0]);

        cache.insert_verified(addr, verified.clone(), 0);
        assert_eq!(
            cache.insert_checked(addr, forged, 10),
            HintOutcome::Rejected
        );
        assert_eq!(cache.get(&addr, 10), Some(&verified));
        assert_eq!(
            cache.get_entry(&addr).unwrap().source(),
            CoordSource::Verified
        );
    }

    #[test]
    fn legacy_unit_returning_insert_preserves_verified_hint_guard() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let verified = make_coords(&[1, 0]);
        let forged = make_coords(&[1, 2, 0]);
        cache.insert_verified(addr, verified.clone(), 0);

        let result: () = cache.insert(addr, forged, 10);

        assert_eq!(result, ());
        assert_eq!(cache.get(&addr, 10), Some(&verified));
    }

    #[test]
    fn legacy_insert_method_signatures_remain_unit_returning() {
        let _: fn(&mut CoordCache, NodeAddr, TreeCoordinate, u64) = CoordCache::insert;
        let _: fn(&mut CoordCache, NodeAddr, TreeCoordinate, u64, u16) =
            CoordCache::insert_with_path_mtu;
        let _: fn(&mut CoordCache, NodeAddr, TreeCoordinate, u64, u64) =
            CoordCache::insert_with_ttl;
    }

    #[test]
    fn verified_write_displaces_hint_and_its_path_mtu() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let hint = make_coords(&[1, 2, 0]);
        let verified = make_coords(&[1, 0]);

        assert_eq!(
            cache.insert_with_path_mtu_checked(addr, hint, 0, 256),
            HintOutcome::Inserted
        );
        cache.insert_verified_with_path_mtu(addr, verified.clone(), 10, 1280);

        let entry = cache.get_entry(&addr).unwrap();
        assert_eq!(entry.coords(), &verified);
        assert_eq!(entry.path_mtu(), Some(1280));
        assert_eq!(entry.source(), CoordSource::Verified);
    }

    #[test]
    fn verification_ages_out_independently_of_entry_activity() {
        let mut cache = CoordCache::new(100, VERIFIED_TTL_MS * 2);
        let addr = make_node_addr(1);
        let original = make_coords(&[1, 0]);
        let moved = make_coords(&[1, 3, 0]);

        cache.insert_verified(addr, original, 0);
        for now_ms in [100, 1_000, 100_000, VERIFIED_TTL_MS] {
            let _ = cache.get_and_touch(&addr, now_ms);
        }

        assert_eq!(
            cache.insert_checked(addr, moved.clone(), VERIFIED_TTL_MS + 1),
            HintOutcome::Changed
        );
        assert_eq!(cache.get(&addr, VERIFIED_TTL_MS + 1), Some(&moved));
        assert_eq!(cache.get_entry(&addr).unwrap().source(), CoordSource::Hint);
    }

    #[test]
    fn hint_eviction_preserves_live_verified_entries() {
        let mut cache = CoordCache::new(2, 1_000_000);
        let verified = make_node_addr(1);
        let hint = make_node_addr(2);
        let newcomer = make_node_addr(3);

        cache.insert_verified(verified, make_coords(&[1, 0]), 0);
        assert_eq!(
            cache.insert_checked(hint, make_coords(&[2, 0]), 100),
            HintOutcome::Inserted
        );
        assert_eq!(
            cache.insert_checked(newcomer, make_coords(&[3, 0]), 200),
            HintOutcome::Inserted
        );

        assert!(cache.contains(&verified, 200));
        assert!(!cache.contains(&hint, 200));
        assert!(cache.contains(&newcomer, 200));
    }

    #[test]
    fn full_verified_cache_refuses_hint() {
        let mut cache = CoordCache::new(2, 1_000_000);
        cache.insert_verified(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert_verified(make_node_addr(2), make_coords(&[2, 0]), 0);

        assert_eq!(
            cache.insert_checked(make_node_addr(3), make_coords(&[3, 0]), 10),
            HintOutcome::Rejected
        );
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&make_node_addr(1), 10));
        assert!(cache.contains(&make_node_addr(2), 10));
    }
}
