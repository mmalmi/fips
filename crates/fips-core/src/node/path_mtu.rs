//! Private provenance for the public per-destination path-MTU lookup.
//!
//! `PathMtuLookup` intentionally remains the original public
//! `HashMap<FipsAddress, u16>` API consumed by TUN readers. The node is the
//! sole writer and keeps expiry and transport provenance beside that map so
//! security and roaming decisions do not leak into its public value type.

use super::Node;
use crate::FipsAddress;
use crate::transport::TransportId;
use tracing::warn;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::node) struct PathMtuProvenance {
    learned_ms: Option<u64>,
    seeded_by: Option<TransportId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) struct PathMtuEntry {
    pub(in crate::node) mtu: u16,
    pub(in crate::node) learned_ms: Option<u64>,
    seeded_by: Option<TransportId>,
}

impl PathMtuEntry {
    fn held(mtu: u16, seeded_by: Option<TransportId>) -> Self {
        Self {
            mtu,
            learned_ms: None,
            seeded_by,
        }
    }

    fn learned(mtu: u16, learned_ms: u64, seeded_by: Option<TransportId>) -> Self {
        Self {
            mtu,
            learned_ms: Some(learned_ms),
            seeded_by,
        }
    }

    pub(in crate::node) fn seeded_by(self) -> Option<TransportId> {
        self.seeded_by
    }

    fn provenance(self) -> PathMtuProvenance {
        PathMtuProvenance {
            learned_ms: self.learned_ms,
            seeded_by: self.seeded_by,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum PathMtuUpdate {
    Unavailable,
    Kept {
        current: PathMtuEntry,
    },
    Updated {
        prior: Option<PathMtuEntry>,
        current: PathMtuEntry,
        relinked: bool,
    },
}

impl Node {
    #[cfg(test)]
    fn path_mtu_entry_with_value(&self, addr: &FipsAddress, mtu: u16) -> PathMtuEntry {
        let provenance = self
            .path_mtu_provenance
            .get(addr)
            .copied()
            .unwrap_or_default();
        PathMtuEntry {
            mtu,
            learned_ms: provenance.learned_ms,
            seeded_by: provenance.seeded_by,
        }
    }

    #[cfg(test)]
    pub(in crate::node) fn path_mtu_entry(&self, addr: &FipsAddress) -> Option<PathMtuEntry> {
        let mtu = self
            .path_mtu_lookup
            .read()
            .ok()
            .and_then(|lookup| lookup.get(addr).copied())?;
        Some(self.path_mtu_entry_with_value(addr, mtu))
    }

    /// Tighten a discovery-carried clamp while recording when it may expire.
    pub(in crate::node) fn record_discovery_path_mtu(
        &mut self,
        addr: FipsAddress,
        mtu: u16,
        learned_ms: u64,
    ) -> PathMtuUpdate {
        let provenance = self
            .path_mtu_provenance
            .get(&addr)
            .copied()
            .unwrap_or_default();
        let Ok(mut lookup) = self.path_mtu_lookup.write() else {
            warn!(%addr, "path-MTU lookup write lock poisoned");
            return PathMtuUpdate::Unavailable;
        };
        let prior = lookup.get(&addr).copied().map(|mtu| PathMtuEntry {
            mtu,
            learned_ms: provenance.learned_ms,
            seeded_by: provenance.seeded_by,
        });
        if let Some(current) = prior
            && current.mtu <= mtu
        {
            return PathMtuUpdate::Kept { current };
        }

        let current =
            PathMtuEntry::learned(mtu, learned_ms, prior.and_then(PathMtuEntry::seeded_by));
        lookup.insert(addr, mtu);
        drop(lookup);
        self.path_mtu_provenance.insert(addr, current.provenance());
        PathMtuUpdate::Updated {
            prior,
            current,
            relinked: false,
        }
    }

    /// Tighten a locally measured or authenticated-session-held clamp.
    pub(in crate::node) fn record_held_path_mtu(
        &mut self,
        addr: FipsAddress,
        mtu: u16,
    ) -> PathMtuUpdate {
        let provenance = self
            .path_mtu_provenance
            .get(&addr)
            .copied()
            .unwrap_or_default();
        let Ok(mut lookup) = self.path_mtu_lookup.write() else {
            warn!(%addr, "path-MTU lookup write lock poisoned");
            return PathMtuUpdate::Unavailable;
        };
        let prior = lookup.get(&addr).copied().map(|mtu| PathMtuEntry {
            mtu,
            learned_ms: provenance.learned_ms,
            seeded_by: provenance.seeded_by,
        });
        if let Some(current) = prior
            && current.mtu <= mtu
        {
            return PathMtuUpdate::Kept { current };
        }

        let current = PathMtuEntry::held(mtu, prior.and_then(PathMtuEntry::seeded_by));
        lookup.insert(addr, mtu);
        drop(lookup);
        self.path_mtu_provenance.insert(addr, current.provenance());
        PathMtuUpdate::Updated {
            prior,
            current,
            relinked: false,
        }
    }

    /// Seed a direct path and replace an obsolete clamp after transport roam.
    pub(in crate::node) fn record_seeded_path_mtu(
        &mut self,
        addr: FipsAddress,
        mtu: u16,
        transport_id: TransportId,
    ) -> PathMtuUpdate {
        let provenance = self
            .path_mtu_provenance
            .get(&addr)
            .copied()
            .unwrap_or_default();
        let Ok(mut lookup) = self.path_mtu_lookup.write() else {
            warn!(%addr, "path-MTU lookup write lock poisoned");
            return PathMtuUpdate::Unavailable;
        };
        let prior = lookup.get(&addr).copied().map(|mtu| PathMtuEntry {
            mtu,
            learned_ms: provenance.learned_ms,
            seeded_by: provenance.seeded_by,
        });
        let prior_seed = prior.and_then(PathMtuEntry::seeded_by);
        let relinked = prior_seed.is_some_and(|prior| prior != transport_id);

        if let Some(existing) = prior
            && !relinked
            && existing.mtu <= mtu
        {
            let current = PathMtuEntry {
                seeded_by: Some(transport_id),
                ..existing
            };
            drop(lookup);
            self.path_mtu_provenance.insert(addr, current.provenance());
            return PathMtuUpdate::Kept { current };
        }

        let current = PathMtuEntry::held(mtu, Some(transport_id));
        lookup.insert(addr, mtu);
        drop(lookup);
        self.path_mtu_provenance.insert(addr, current.provenance());
        PathMtuUpdate::Updated {
            prior,
            current,
            relinked,
        }
    }

    /// Remove only discovery-carried clamps whose independent TTL elapsed.
    pub(in crate::node) fn remove_expired_discovery_path_mtus(
        &mut self,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Vec<FipsAddress> {
        let expired = self
            .path_mtu_provenance
            .iter()
            .filter_map(|(addr, provenance)| {
                provenance
                    .learned_ms
                    .is_some_and(|learned_ms| now_ms.saturating_sub(learned_ms) >= ttl_ms)
                    .then_some(*addr)
            })
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return Vec::new();
        }

        let Ok(mut lookup) = self.path_mtu_lookup.write() else {
            warn!("path-MTU lookup write lock poisoned; expiry skipped");
            return Vec::new();
        };
        let removed = expired
            .into_iter()
            .filter(|addr| lookup.remove(addr).is_some())
            .collect::<Vec<_>>();
        drop(lookup);
        for addr in &removed {
            self.path_mtu_provenance.remove(addr);
        }
        removed
    }
}
