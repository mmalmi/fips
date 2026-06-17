use super::*;

/// Key for reverse address dispatch.
pub(in crate::node) type AddrKey = (TransportId, TransportAddr);

/// Reverse index from `(transport, remote address)` to active/pending link.
#[derive(Debug, Default)]
pub(in crate::node) struct LinkAddressIndex {
    entries: HashMap<AddrKey, LinkId>,
}

impl LinkAddressIndex {
    pub(in crate::node) fn insert(&mut self, key: AddrKey, link_id: LinkId) -> Option<LinkId> {
        self.entries.insert(key, link_id)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove(&mut self, key: &AddrKey) -> Option<LinkId> {
        self.entries.remove(key)
    }

    pub(in crate::node) fn remove_if_points_to(&mut self, key: &AddrKey, link_id: &LinkId) -> bool {
        if self.entries.get(key) == Some(link_id) {
            self.entries.remove(key);
            true
        } else {
            false
        }
    }

    pub(in crate::node) fn lookup(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.entries.get(&(transport_id, addr.clone())).copied()
    }

    #[cfg(test)]
    pub(in crate::node) fn get(&self, key: &AddrKey) -> Option<&LinkId> {
        self.entries.get(key)
    }

    pub(in crate::node) fn contains_key(&self, key: &AddrKey) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Link storage plus reverse dispatch index.
#[derive(Debug, Default)]
pub(in crate::node) struct LinkRegistry {
    links: HashMap<LinkId, Link>,
    by_addr: LinkAddressIndex,
}

impl LinkRegistry {
    pub(in crate::node) fn insert(&mut self, link_id: LinkId, link: Link) -> Option<Link> {
        debug_assert_eq!(link_id, link.link_id());
        let previous = self.links.insert(link_id, link);
        if let Some(previous) = &previous {
            let previous_key = (previous.transport_id(), previous.remote_addr().clone());
            self.by_addr.remove_if_points_to(&previous_key, &link_id);
        }

        let link = self
            .links
            .get(&link_id)
            .expect("link inserted above should be present");
        self.by_addr
            .insert((link.transport_id(), link.remote_addr().clone()), link_id);
        previous
    }

    pub(in crate::node) fn insert_addr(&mut self, key: AddrKey, link_id: LinkId) -> Option<LinkId> {
        self.by_addr.insert(key, link_id)
    }

    pub(in crate::node) fn remove(&mut self, link_id: &LinkId) -> Option<Link> {
        let link = self.links.remove(link_id)?;
        let key = (link.transport_id(), link.remote_addr().clone());
        self.by_addr.remove_if_points_to(&key, link_id);
        Some(link)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove_addr(&mut self, key: &AddrKey) -> Option<LinkId> {
        self.by_addr.remove(key)
    }

    pub(in crate::node) fn lookup_addr(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.by_addr.lookup(transport_id, addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn get_addr(&self, key: &AddrKey) -> Option<&LinkId> {
        self.by_addr.get(key)
    }

    pub(in crate::node) fn contains_addr(&self, key: &AddrKey) -> bool {
        self.by_addr.contains_key(key)
    }

    pub(in crate::node) fn get(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    pub(in crate::node) fn get_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, link_id: &LinkId) -> bool {
        self.links.contains_key(link_id)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.links.len()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    #[cfg(test)]
    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&LinkId, &Link)> {
        self.links.iter()
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
}

/// Per-transport kernel drop tracking for congestion detection.
///
/// Sampled every tick (1s). The `dropping` flag indicates whether new
/// kernel drops were observed since the previous sample.
#[derive(Debug, Default)]
struct TransportDropState {
    /// Previous `recv_drops` sample (cumulative counter).
    prev_drops: u64,
    /// True if drops increased since the last sample.
    dropping: bool,
}

#[derive(Debug, Default)]
pub(in crate::node) struct TransportDropTracker {
    states: HashMap<TransportId, TransportDropState>,
}

impl TransportDropTracker {
    pub(in crate::node) fn any_dropping(&self) -> bool {
        self.states.values().any(|state| state.dropping)
    }

    pub(in crate::node) fn sample(
        &mut self,
        transport_id: TransportId,
        recv_drops: Option<u64>,
    ) -> Option<u64> {
        let state = self.states.entry(transport_id).or_default();
        let Some(current) = recv_drops else {
            return None;
        };

        let dropped = current.saturating_sub(state.prev_drops);
        let new_drops = dropped > 0;
        state.dropping = new_drops;
        state.prev_drops = current;
        new_drops.then_some(dropped)
    }

    pub(in crate::node) fn remove(&mut self, transport_id: &TransportId) {
        self.states.remove(transport_id);
    }

    #[cfg(test)]
    pub(in crate::node) fn set_for_test(
        &mut self,
        transport_id: TransportId,
        prev_drops: u64,
        dropping: bool,
    ) {
        self.states.insert(
            transport_id,
            TransportDropState {
                prev_drops,
                dropping,
            },
        );
    }
}

/// State for a link waiting for transport-level connection establishment.
///
/// For connection-oriented transports (TCP, Tor), the transport connect runs
/// asynchronously. This struct holds the data needed to complete the handshake
/// once the connection is ready.
pub(in crate::node) struct PendingConnect {
    /// The link that was created for this connection.
    pub(in crate::node) link_id: LinkId,
    /// Which transport is being used.
    pub(in crate::node) transport_id: TransportId,
    /// The remote address being connected to.
    pub(in crate::node) remote_addr: TransportAddr,
    /// The peer identity (for handshake initiation).
    pub(in crate::node) peer_identity: PeerIdentity,
}
