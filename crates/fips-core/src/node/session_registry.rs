use super::*;

/// End-to-end FSP session storage keyed by remote node address.
#[derive(Default)]
pub(in crate::node) struct SessionRegistry {
    sessions: HashMap<NodeAddr, SessionEntry>,
    worker_registrations: DecryptSessionRegistrations,
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

    #[cfg(test)]
    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.sessions.contains_key(node_addr)
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

    pub(in crate::node) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&NodeAddr, &mut SessionEntry)> {
        self.sessions.iter_mut()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &SessionEntry> {
        self.sessions.values()
    }

    pub(in crate::node) fn record_fsp_send_bookkeeping(
        &mut self,
        node_addr: &NodeAddr,
        input: FspSendBookkeepingInput,
    ) -> Option<FspSendBookkeeping> {
        let entry = self.sessions.get_mut(node_addr)?;
        let mut result = FspSendBookkeeping {
            data_recorded: false,
            mmp_recorded: false,
            touched: false,
            next_hop_recorded: false,
        };

        if let Some(next_hop) = input.next_hop {
            entry.record_outbound_next_hop(next_hop);
            result.next_hop_recorded = true;
        }
        if let Some(data_bytes) = input.data_bytes {
            entry.record_sent(data_bytes);
            result.data_recorded = true;
        }
        if let Some(mmp) = entry.mmp_mut() {
            mmp.sender
                .record_sent(input.counter, input.timestamp, input.frame_bytes);
            result.mmp_recorded = true;
        }
        if let Some(touch_ms) = input.touch_ms {
            entry.touch(touch_ms);
            result.touched = true;
        }

        Some(result)
    }

    pub(in crate::node) fn record_fsp_send_bookkeeping_batch<I>(
        &mut self,
        node_addr: &NodeAddr,
        inputs: I,
    ) -> Option<usize>
    where
        I: IntoIterator<Item = FspSendBookkeepingInput>,
    {
        let entry = self.sessions.get_mut(node_addr)?;
        let mut data_packets = 0usize;
        let mut data_bytes = 0usize;
        let mut last_touch_ms = None;
        let mut last_next_hop = None;

        for input in inputs {
            if let Some(next_hop) = input.next_hop {
                last_next_hop = Some(next_hop);
            }
            if let Some(bytes) = input.data_bytes {
                data_packets += 1;
                data_bytes += bytes;
            }
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender
                    .record_sent(input.counter, input.timestamp, input.frame_bytes);
            }
            if input.touch_ms.is_some() {
                last_touch_ms = input.touch_ms;
            }
        }

        if let Some(next_hop) = last_next_hop {
            entry.record_outbound_next_hop(next_hop);
        }
        if data_packets > 0 {
            entry.record_sent_batch(data_packets, data_bytes);
        }
        if let Some(touch_ms) = last_touch_ms {
            entry.touch(touch_ms);
        }

        Some(data_packets)
    }

    #[cfg(unix)]
    pub(in crate::node) fn seed_endpoint_data_fsp_path_mtu_batch<I>(
        &mut self,
        node_addr: &NodeAddr,
        path_mtus: I,
    ) -> Option<()>
    where
        I: IntoIterator<Item = u16>,
    {
        let entry = self.sessions.get_mut(node_addr)?;
        if let Some(mmp) = entry.mmp_mut() {
            for path_mtu in path_mtus {
                mmp.path_mtu.seed_source_mtu(path_mtu);
            }
        }
        Some(())
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_endpoint_data_fsp_worker_send(
        &mut self,
        node_addr: &NodeAddr,
        input: FspWorkerSendReservationInput,
    ) -> Result<Option<FspSendReservation>, FspWorkerSendReservationError> {
        let entry = self
            .sessions
            .get_mut(node_addr)
            .ok_or(FspWorkerSendReservationError::MissingSession)?;
        if let Some(mmp) = entry.mmp_mut() {
            mmp.path_mtu.seed_source_mtu(input.path_mtu);
        }
        if !entry.is_established() {
            return Err(FspWorkerSendReservationError::NotEstablished);
        }
        entry
            .reserve_fsp_worker_send(input.flags, input.payload_len)
            .map_err(|_| FspWorkerSendReservationError::CounterReservationFailed)
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_endpoint_data_fsp_worker_send_batch(
        &mut self,
        node_addr: &NodeAddr,
        inputs: &[FspWorkerSendReservationInput],
    ) -> Result<Option<Vec<FspSendReservation>>, FspWorkerSendReservationError> {
        let entry = self
            .sessions
            .get_mut(node_addr)
            .ok_or(FspWorkerSendReservationError::MissingSession)?;
        if let Some(mmp) = entry.mmp_mut() {
            for input in inputs {
                mmp.path_mtu.seed_source_mtu(input.path_mtu);
            }
        }
        if !entry.is_established() {
            return Err(FspWorkerSendReservationError::NotEstablished);
        }
        entry
            .reserve_fsp_worker_send_batch(
                inputs.iter().map(|input| (input.flags, input.payload_len)),
            )
            .map_err(|_| FspWorkerSendReservationError::CounterReservationFailed)
    }

    pub(in crate::node) fn record_worker_registration(
        &mut self,
        session_key: DecryptSessionKey,
        accepted: bool,
    ) -> bool {
        self.worker_registrations
            .record_worker_registration(session_key, accepted)
    }

    pub(in crate::node) fn unregister_worker_session_if_registered(
        &mut self,
        session_key: &DecryptSessionKey,
    ) -> bool {
        self.worker_registrations
            .unregister_if_registered(session_key)
    }

    pub(in crate::node) fn is_worker_registered(&self, session_key: &DecryptSessionKey) -> bool {
        self.worker_registrations.is_registered(session_key)
    }

    #[cfg(test)]
    pub(in crate::node) fn worker_registration_is_empty(&self) -> bool {
        self.worker_registrations.is_empty()
    }
}

impl<'a> IntoIterator for &'a SessionRegistry {
    type Item = (&'a NodeAddr, &'a SessionEntry);
    type IntoIter = std::collections::hash_map::Iter<'a, NodeAddr, SessionEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.sessions.iter()
    }
}

/// Rx-loop mirror of sessions accepted by decrypt-worker shards.
#[derive(Debug, Default)]
pub(in crate::node) struct DecryptSessionRegistrations {
    sessions: HashSet<DecryptSessionKey>,
}

impl DecryptSessionRegistrations {
    pub(in crate::node) fn record_worker_registration(
        &mut self,
        session_key: DecryptSessionKey,
        accepted: bool,
    ) -> bool {
        if !accepted {
            return false;
        }
        self.sessions.insert(session_key);
        true
    }

    pub(in crate::node) fn unregister_if_registered(
        &mut self,
        session_key: &DecryptSessionKey,
    ) -> bool {
        self.sessions.remove(session_key)
    }

    pub(in crate::node) fn is_registered(&self, session_key: &DecryptSessionKey) -> bool {
        self.sessions.contains(session_key)
    }

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Binary-indexed runtime view of the configured peer roster.
#[derive(Debug, Default)]
pub(in crate::node) struct ConfiguredPeerIndex {
    peers_by_addr: HashMap<NodeAddr, ConfiguredPeerEntry>,
    addrs_by_npub: HashMap<String, NodeAddr>,
}

#[derive(Debug)]
struct ConfiguredPeerEntry {
    identity: PeerIdentity,
    config: PeerConfig,
}

impl ConfiguredPeerIndex {
    pub(in crate::node) fn from_config(config: &Config) -> Self {
        Self::from_parsed_peers(config.peers().iter().filter_map(|peer| {
            PeerIdentity::from_npub(&peer.npub)
                .ok()
                .map(|identity| (identity, peer.clone()))
        }))
    }

    pub(in crate::node) fn from_parsed_peers(
        peers: impl IntoIterator<Item = (PeerIdentity, PeerConfig)>,
    ) -> Self {
        let peers = peers.into_iter();
        let mut peers_by_addr = HashMap::with_capacity(peers.size_hint().0);
        for (identity, config) in peers {
            peers_by_addr.insert(
                *identity.node_addr(),
                ConfiguredPeerEntry { identity, config },
            );
        }
        let mut addrs_by_npub = HashMap::with_capacity(peers_by_addr.len());
        for (peer_addr, entry) in &peers_by_addr {
            addrs_by_npub.insert(entry.config.npub.clone(), *peer_addr);
        }
        Self {
            peers_by_addr,
            addrs_by_npub,
        }
    }

    pub(in crate::node) fn get(&self, peer_addr: &NodeAddr) -> Option<&PeerConfig> {
        self.peers_by_addr.get(peer_addr).map(|entry| &entry.config)
    }

    pub(in crate::node) fn identity(&self, peer_addr: &NodeAddr) -> Option<&PeerIdentity> {
        self.peers_by_addr
            .get(peer_addr)
            .map(|entry| &entry.identity)
    }

    pub(in crate::node) fn identity_for_npub(&self, npub: &str) -> Option<&PeerIdentity> {
        let peer_addr = self.addrs_by_npub.get(npub)?;
        self.identity(peer_addr)
    }

    pub(in crate::node) fn auto_connect(&self, peer_addr: &NodeAddr) -> Option<&PeerConfig> {
        self.get(peer_addr)
            .filter(|peer_config| peer_config.is_auto_connect())
    }

    pub(in crate::node) fn auto_connect_with_identity(
        &self,
        peer_addr: &NodeAddr,
    ) -> Option<(&PeerConfig, &PeerIdentity)> {
        let entry = self.peers_by_addr.get(peer_addr)?;
        entry
            .config
            .is_auto_connect()
            .then_some((&entry.config, &entry.identity))
    }

    pub(in crate::node) fn contains(&self, peer_addr: &NodeAddr) -> bool {
        self.peers_by_addr.contains_key(peer_addr)
    }

    pub(in crate::node) fn weight_for(&self, peer_addr: &NodeAddr) -> u8 {
        if self.contains(peer_addr) {
            encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT
        } else {
            encrypt_worker::DEFAULT_SEND_WEIGHT
        }
    }

    pub(in crate::node) fn entries(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &PeerIdentity, &PeerConfig)> {
        self.peers_by_addr
            .iter()
            .map(|(addr, entry)| (addr, &entry.identity, &entry.config))
    }

    #[cfg(test)]
    pub(in crate::node) fn len(&self) -> usize {
        self.peers_by_addr.len()
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
