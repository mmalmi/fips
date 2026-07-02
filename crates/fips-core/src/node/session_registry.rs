use super::*;

/// End-to-end FSP session storage keyed by remote node address.
#[derive(Default)]
pub(in crate::node) struct SessionRegistry {
    sessions: HashMap<NodeAddr, SessionEntry>,
}

impl SessionRegistry {
    pub(in crate::node) fn insert(
        &mut self,
        node_addr: NodeAddr,
        entry: SessionEntry,
    ) -> Option<SessionEntry> {
        self.sessions.insert(node_addr, entry)
    }

    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr) -> Option<SessionEntry> {
        self.sessions.remove(node_addr)
    }

    pub(in crate::node) fn get(&self, node_addr: &NodeAddr) -> Option<&SessionEntry> {
        self.sessions.get(node_addr)
    }

    pub(in crate::node) fn get_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut SessionEntry> {
        self.sessions.get_mut(node_addr)
    }

    pub(in crate::node) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.sessions.len()
    }

    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &SessionEntry)> {
        self.sessions.iter()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &SessionEntry> {
        self.sessions.values()
    }
}

impl<'a> IntoIterator for &'a SessionRegistry {
    type Item = (&'a NodeAddr, &'a SessionEntry);
    type IntoIter = std::collections::hash_map::Iter<'a, NodeAddr, SessionEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.sessions.iter()
    }
}

/// Configured peer lookup cache derived from the peer roster.
#[derive(Debug, Default)]
pub(in crate::node) struct ConfiguredPeerSendWeights {
    peer_configs: HashMap<NodeAddr, PeerConfig>,
    peer_addrs_by_npub: HashMap<String, NodeAddr>,
}

impl ConfiguredPeerSendWeights {
    pub(in crate::node) fn from_config(config: &Config) -> Self {
        let mut peer_configs = HashMap::with_capacity(config.peers().len());
        let mut peer_addrs_by_npub = HashMap::with_capacity(config.peers().len());
        for peer in config.peers() {
            let Ok(identity) = PeerIdentity::from_npub(&peer.npub) else {
                continue;
            };
            let node_addr = *identity.node_addr();
            peer_addrs_by_npub.insert(peer.npub.clone(), node_addr);
            peer_configs.insert(node_addr, peer.clone());
        }
        Self {
            peer_configs,
            peer_addrs_by_npub,
        }
    }

    pub(in crate::node) fn peer_config(&self, peer_addr: &NodeAddr) -> Option<&PeerConfig> {
        self.peer_configs.get(peer_addr)
    }

    pub(in crate::node) fn peer_addr_for_npub(&self, npub: &str) -> Option<NodeAddr> {
        self.peer_addrs_by_npub.get(npub).copied()
    }

    pub(in crate::node) fn auto_connect_peer_configs(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &PeerConfig)> {
        self.peer_configs
            .iter()
            .filter(|(_, peer)| peer.is_auto_connect())
    }
}

/// Pending outbound FMP handshakes keyed by `(transport_id, our_index)`.
#[derive(Debug, Default)]
pub(in crate::node) struct PendingOutboundHandshakes {
    entries: HashMap<(TransportId, u32), LinkId>,
}

impl PendingOutboundHandshakes {
    pub(in crate::node) fn insert(
        &mut self,
        key: (TransportId, u32),
        link_id: LinkId,
    ) -> Option<LinkId> {
        self.entries.insert(key, link_id)
    }

    pub(in crate::node) fn remove(&mut self, key: &(TransportId, u32)) -> Option<LinkId> {
        self.entries.remove(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn get(&self, key: &(TransportId, u32)) -> Option<&LinkId> {
        self.entries.get(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, key: &(TransportId, u32)) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(in crate::node) fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&(TransportId, u32), &mut LinkId) -> bool,
    {
        self.entries.retain(f);
    }

    pub(in crate::node) fn match_msg2(
        &self,
        transport_id: TransportId,
        receiver_idx: u32,
    ) -> Option<((TransportId, u32), LinkId)> {
        let exact_key = (transport_id, receiver_idx);
        if let Some(link_id) = self.entries.get(&exact_key).copied() {
            return Some((exact_key, link_id));
        }

        let mut matches = self
            .entries
            .iter()
            .filter(|((_, idx), _)| *idx == receiver_idx);
        match (matches.next(), matches.next()) {
            (Some((fallback_key, link_id)), None) => Some((*fallback_key, *link_id)),
            _ => None,
        }
    }
}
