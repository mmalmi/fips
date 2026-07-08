use super::*;

/// Active peer storage plus receiver-index dispatch.
#[derive(Debug, Default)]
pub(in crate::node) struct ActivePeerRegistry {
    peers: HashMap<NodeAddr, ActivePeer>,
    by_session_index: SessionIndexRegistry,
}

impl ActivePeerRegistry {
    pub(in crate::node) fn insert(
        &mut self,
        node_addr: NodeAddr,
        peer: ActivePeer,
    ) -> Option<ActivePeer> {
        debug_assert_eq!(&node_addr, peer.node_addr());
        self.peers.insert(node_addr, peer)
    }

    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.peers.remove(node_addr)
    }

    pub(in crate::node) fn get(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.peers.get(node_addr)
    }

    pub(in crate::node) fn get_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_addr)
    }

    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.peers.contains_key(node_addr)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.peers.len()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    pub(in crate::node) fn values_mut(&mut self) -> impl Iterator<Item = &mut ActivePeer> {
        self.peers.values_mut()
    }

    pub(in crate::node) fn keys(&self) -> impl Iterator<Item = &NodeAddr> {
        self.peers.keys()
    }

    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &ActivePeer)> {
        self.peers.iter()
    }

    pub(in crate::node) fn insert_session_index(
        &mut self,
        key: (TransportId, u32),
        node_addr: NodeAddr,
    ) -> Option<NodeAddr> {
        self.by_session_index.insert(key, node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove_session_index(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<NodeAddr> {
        self.by_session_index.remove(key)
    }

    pub(in crate::node) fn remove_session_index_with_owner_state(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<RemovedSessionIndex> {
        self.by_session_index.remove_with_owner_state(key)
    }

    pub(in crate::node) fn lookup_session_index(
        &self,
        key: (TransportId, u32),
    ) -> Option<NodeAddr> {
        self.by_session_index.lookup(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn peer_has_any_session_index(&self, node_addr: &NodeAddr) -> bool {
        self.by_session_index.peer_has_any_index(node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn get_session_index(&self, key: &(TransportId, u32)) -> Option<&NodeAddr> {
        self.by_session_index.get(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_session_index(&self, key: &(TransportId, u32)) -> bool {
        self.by_session_index.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn session_index_is_empty(&self) -> bool {
        self.by_session_index.is_empty()
    }
}

impl<'a> IntoIterator for &'a ActivePeerRegistry {
    type Item = (&'a NodeAddr, &'a ActivePeer);
    type IntoIter = std::collections::hash_map::Iter<'a, NodeAddr, ActivePeer>;

    fn into_iter(self) -> Self::IntoIter {
        self.peers.iter()
    }
}

/// Peer lifecycle storage for handshake and active phases.
#[derive(Debug, Default)]
pub(in crate::node) struct PeerLifecycleRegistry {
    connections: HashMap<LinkId, PeerConnection>,
    pub(in crate::node) active: ActivePeerRegistry,
}

impl PeerLifecycleRegistry {
    fn active_peer_current_session_index(peer: &ActivePeer) -> Option<PeerSessionIndex> {
        let transport_id = peer.transport_id()?;
        let index = peer.our_index()?;
        Some(PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: (transport_id, index.as_u32()),
            index,
        })
    }

    fn active_peer_session_indices(peer: &ActivePeer) -> Vec<PeerSessionIndex> {
        let Some(transport_id) = peer.transport_id() else {
            return Vec::new();
        };

        let mut indices = Vec::with_capacity(4);
        if let Some(current) = Self::active_peer_current_session_index(peer) {
            indices.push(current);
        }
        let mut push_index = |kind: PeerSessionIndexKind, index: Option<SessionIndex>| {
            let Some(index) = index else {
                return;
            };
            let key = (transport_id, index.as_u32());
            if indices
                .iter()
                .any(|existing: &PeerSessionIndex| existing.key == key)
            {
                return;
            }
            indices.push(PeerSessionIndex { kind, key, index });
        };

        push_index(PeerSessionIndexKind::Rekey, peer.rekey_our_index());
        push_index(PeerSessionIndexKind::Pending, peer.pending_our_index());
        push_index(PeerSessionIndexKind::Previous, peer.previous_our_index());
        indices
    }

    pub(in crate::node) fn insert_connection(
        &mut self,
        link_id: LinkId,
        connection: PeerConnection,
    ) -> Option<PeerConnection> {
        debug_assert_eq!(link_id, connection.link_id());
        self.connections.insert(link_id, connection)
    }

    pub(in crate::node) fn remove_connection(
        &mut self,
        link_id: &LinkId,
    ) -> Option<PeerConnection> {
        self.connections.remove(link_id)
    }

    pub(in crate::node) fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.connections.get(link_id)
    }

    pub(in crate::node) fn get_connection_mut(
        &mut self,
        link_id: &LinkId,
    ) -> Option<&mut PeerConnection> {
        self.connections.get_mut(link_id)
    }

    pub(in crate::node) fn contains_connection(&self, link_id: &LinkId) -> bool {
        self.connections.contains_key(link_id)
    }

    pub(in crate::node) fn connection_len(&self) -> usize {
        self.connections.len()
    }

    pub(in crate::node) fn connection_is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    pub(in crate::node) fn connection_values(&self) -> impl Iterator<Item = &PeerConnection> {
        self.connections.values()
    }

    pub(in crate::node) fn connection_iter(
        &self,
    ) -> impl Iterator<Item = (&LinkId, &PeerConnection)> {
        self.connections.iter()
    }

    #[cfg(test)]
    pub(in crate::node) fn connection_keys(&self) -> impl Iterator<Item = &LinkId> {
        self.connections.keys()
    }

    #[cfg(test)]
    pub(in crate::node) fn insert(
        &mut self,
        node_addr: NodeAddr,
        peer: ActivePeer,
    ) -> Option<ActivePeer> {
        self.active.insert(node_addr, peer)
    }

    pub(in crate::node) fn insert_with_current_session_index(
        &mut self,
        node_addr: NodeAddr,
        peer: ActivePeer,
    ) -> InsertedActivePeer {
        let current_session_index = Self::active_peer_current_session_index(&peer);
        let previous_peer = self.active.insert(node_addr, peer);
        let current_session_index = current_session_index.map(|session_index| {
            let previous_owner = self
                .active
                .insert_session_index(session_index.key, node_addr);
            RegisteredPeerSessionIndex {
                session_index,
                previous_owner,
            }
        });
        InsertedActivePeer {
            previous_peer,
            current_session_index,
        }
    }

    pub(in crate::node) fn ensure_current_session_index_registered(
        &mut self,
        node_addr: &NodeAddr,
    ) -> CurrentSessionIndexRegistration {
        let Some(peer) = self.active.get(node_addr) else {
            return CurrentSessionIndexRegistration::MissingActivePeer;
        };
        let Some(transport_id) = peer.transport_id() else {
            return CurrentSessionIndexRegistration::MissingTransportId;
        };
        let Some(our_index) = peer.our_index() else {
            return CurrentSessionIndexRegistration::MissingLocalIndex;
        };
        let session_index = PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: (transport_id, our_index.as_u32()),
            index: our_index,
        };

        match self.active.lookup_session_index(session_index.key) {
            Some(existing) if existing == *node_addr => {
                CurrentSessionIndexRegistration::AlreadyRegistered(session_index)
            }
            expected_previous_owner => {
                let previous_owner = self
                    .active
                    .insert_session_index(session_index.key, *node_addr);
                debug_assert_eq!(previous_owner, expected_previous_owner);
                CurrentSessionIndexRegistration::Repaired(RegisteredPeerSessionIndex {
                    session_index,
                    previous_owner,
                })
            }
        }
    }

    pub(in crate::node) fn replace_current_session_and_path(
        &mut self,
        node_addr: &NodeAddr,
        replacement: ActivePeerCurrentSessionReplacement<'_>,
    ) -> Option<ReplacedActivePeerCurrentSession> {
        let ActivePeerCurrentSessionReplacement {
            session,
            our_index,
            their_index,
            link_id,
            transport_id,
            addr,
            is_initiator,
            remote_epoch_update,
            connected_at_ms,
        } = replacement;
        let new_session_index = PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: (transport_id, our_index.as_u32()),
            index: our_index,
        };
        let (old_link_id, old_session_index, replay_suppressed_count) = {
            let peer = self.active.get_mut(node_addr)?;
            let previous_current_index = Self::active_peer_current_session_index(peer);
            let old_link_id = peer.link_id();
            let replay_suppressed_count = peer.replay_suppressed_count();
            let replaced_our_index = peer.replace_session(session, our_index, their_index);
            debug_assert_eq!(
                previous_current_index.map(|old| old.index),
                replaced_our_index
            );
            peer.set_link_id(link_id);
            peer.set_current_addr(transport_id, addr);
            peer.set_fmp_mmp_is_initiator(is_initiator);
            if remote_epoch_update.is_some() {
                peer.set_remote_epoch(remote_epoch_update);
            }
            peer.mark_connected(connected_at_ms);
            (
                old_link_id,
                previous_current_index.filter(|old| old.key != new_session_index.key),
                replay_suppressed_count,
            )
        };

        let previous_owner = self
            .active
            .insert_session_index(new_session_index.key, *node_addr);
        Some(ReplacedActivePeerCurrentSession {
            old_link_id,
            old_session_index,
            new_session_index: RegisteredPeerSessionIndex {
                session_index: new_session_index,
                previous_owner,
            },
            replay_suppressed_count,
        })
    }

    pub(in crate::node) fn install_pending_rekey_session_and_index(
        &mut self,
        node_addr: &NodeAddr,
        pending_session: crate::noise::NoiseSession,
        pending_our_index: SessionIndex,
        pending_their_index: SessionIndex,
        initiated_by_local: bool,
        remote_epoch: Option<[u8; 8]>,
    ) -> Option<RegisteredPeerSessionIndex> {
        let pending_session_index = {
            let peer = self.active.get_mut(node_addr)?;
            let transport_id = peer.transport_id()?;
            let session_index = PeerSessionIndex {
                kind: PeerSessionIndexKind::Pending,
                key: (transport_id, pending_our_index.as_u32()),
                index: pending_our_index,
            };
            if remote_epoch.is_some() {
                peer.set_remote_epoch(remote_epoch);
            }
            peer.set_pending_session(
                pending_session,
                pending_our_index,
                pending_their_index,
                initiated_by_local,
            );
            if !initiated_by_local {
                peer.record_peer_rekey();
            }
            session_index
        };

        let previous_owner = self
            .active
            .insert_session_index(pending_session_index.key, *node_addr);
        Some(RegisteredPeerSessionIndex {
            session_index: pending_session_index,
            previous_owner,
        })
    }

    pub(in crate::node) fn record_authenticated_fmp_receive(
        &mut self,
        fmp: AuthenticatedFmpReceiveFacts<'_>,
        liveness_bookkeeping_allowed: bool,
        path_bookkeeping_allowed: bool,
    ) -> Option<AuthenticatedFmpReceiveBookkeeping> {
        let node_addr = fmp.source_node_addr();
        let peer = self.active.get_mut(node_addr)?;
        peer.reset_decrypt_failures();

        let mut result = AuthenticatedFmpReceiveBookkeeping {
            address_changed: false,
            path_bookkeeping_recorded: false,
            liveness_bookkeeping_recorded: false,
        };
        if path_bookkeeping_allowed {
            result.address_changed = peer.set_current_addr(fmp.transport_id, fmp.remote_addr);
            result.path_bookkeeping_recorded = true;
        }
        if liveness_bookkeeping_allowed {
            result.liveness_bookkeeping_recorded = true;
            peer.link_stats_mut()
                .record_recv(fmp.packet_len, fmp.packet_timestamp_ms);
            peer.touch(fmp.packet_timestamp_ms);
        }

        Some(result)
    }

    pub(in crate::node) fn record_fmp_send_bookkeeping(
        &mut self,
        node_addr: &NodeAddr,
        bytes_sent: usize,
    ) -> bool {
        let Some(peer) = self.active.get_mut(node_addr) else {
            return false;
        };
        peer.link_stats_mut().record_sent(bytes_sent);

        true
    }

    pub(in crate::node) fn mark_link_dead_direct_path(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Option<LinkDeadDirectPathDegradation> {
        let peer = self.active.get_mut(node_addr)?;
        let link_id = peer.link_id();
        peer.mark_stale();

        Some(LinkDeadDirectPathDegradation { link_id })
    }

    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.active.remove(node_addr)
    }

    pub(in crate::node) fn remove_with_session_indices(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Option<RemovedActivePeer> {
        let peer = self.active.remove(node_addr)?;
        let session_indices = Self::active_peer_session_indices(&peer);
        Some(RemovedActivePeer {
            peer,
            session_indices,
        })
    }

    pub(in crate::node) fn get(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.active.get(node_addr)
    }

    pub(in crate::node) fn get_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.active.get_mut(node_addr)
    }

    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.active.contains_key(node_addr)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.active.len()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &ActivePeer> {
        self.active.values()
    }

    pub(in crate::node) fn values_mut(&mut self) -> impl Iterator<Item = &mut ActivePeer> {
        self.active.values_mut()
    }

    pub(in crate::node) fn keys(&self) -> impl Iterator<Item = &NodeAddr> {
        self.active.keys()
    }

    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &ActivePeer)> {
        self.active.iter()
    }

    #[cfg(test)]
    pub(in crate::node) fn insert_session_index(
        &mut self,
        key: (TransportId, u32),
        node_addr: NodeAddr,
    ) -> Option<NodeAddr> {
        self.active.insert_session_index(key, node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove_session_index(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<NodeAddr> {
        self.active.remove_session_index(key)
    }

    pub(in crate::node) fn remove_session_index_with_owner_state(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<RemovedSessionIndex> {
        self.active.remove_session_index_with_owner_state(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn lookup_session_index(
        &self,
        key: (TransportId, u32),
    ) -> Option<NodeAddr> {
        self.active.lookup_session_index(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn get_session_index(&self, key: &(TransportId, u32)) -> Option<&NodeAddr> {
        self.active.get_session_index(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn contains_session_index(&self, key: &(TransportId, u32)) -> bool {
        self.active.contains_session_index(key)
    }

    #[cfg(test)]
    pub(in crate::node) fn session_index_is_empty(&self) -> bool {
        self.active.session_index_is_empty()
    }
}

impl<'a> IntoIterator for &'a PeerLifecycleRegistry {
    type Item = (&'a NodeAddr, &'a ActivePeer);
    type IntoIter = std::collections::hash_map::Iter<'a, NodeAddr, ActivePeer>;

    fn into_iter(self) -> Self::IntoIter {
        self.active.peers.iter()
    }
}
