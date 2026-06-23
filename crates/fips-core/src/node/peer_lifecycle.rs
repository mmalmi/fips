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

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.peers.is_empty()
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

    pub(in crate::node) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&NodeAddr, &mut ActivePeer)> {
        self.peers.iter_mut()
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn connected_udp_activation_candidate(peer: &ActivePeer) -> bool {
        peer.is_healthy()
            && peer.noise_session().is_some()
            && peer.transport_id().is_some()
            && peer.current_addr().is_some()
            && peer.connected_udp().is_none()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn connected_udp_activation_order(mut candidates: Vec<(NodeAddr, bool)>) -> Vec<NodeAddr> {
        candidates.sort_by_key(|(addr, is_configured)| (!*is_configured, *addr));
        candidates.into_iter().map(|(addr, _)| addr).collect()
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

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn replace_current_session_and_path(
        &mut self,
        node_addr: &NodeAddr,
        new_session: crate::noise::NoiseSession,
        new_our_index: SessionIndex,
        new_their_index: SessionIndex,
        new_link_id: LinkId,
        new_transport_id: TransportId,
        new_addr: &TransportAddr,
        new_remote_epoch: Option<[u8; 8]>,
        connected_at_ms: u64,
    ) -> Option<ReplacedActivePeerCurrentSession> {
        let new_session_index = PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: (new_transport_id, new_our_index.as_u32()),
            index: new_our_index,
        };
        let (old_link_id, old_session_index, replay_suppressed_count) = {
            let peer = self.active.get_mut(node_addr)?;
            let previous_current_index = Self::active_peer_current_session_index(peer);
            let old_link_id = peer.link_id();
            let replay_suppressed_count = peer.replay_suppressed_count();
            let replaced_our_index =
                peer.replace_session(new_session, new_our_index, new_their_index);
            debug_assert_eq!(
                previous_current_index.map(|old| old.index),
                replaced_our_index
            );
            peer.set_link_id(new_link_id);
            peer.set_current_addr(new_transport_id, new_addr);
            if new_remote_epoch.is_some() {
                peer.set_remote_epoch(new_remote_epoch);
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

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn record_authenticated_fmp_receive(
        &mut self,
        node_addr: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        inner_timestamp_ms: u32,
        ce_flag: bool,
        sp_flag: bool,
        now: std::time::Instant,
        path_bookkeeping_allowed: bool,
    ) -> Option<AuthenticatedFmpReceiveBookkeeping> {
        let peer = self.active.get_mut(node_addr)?;
        peer.reset_decrypt_failures();

        let mut result = AuthenticatedFmpReceiveBookkeeping {
            address_changed: false,
            path_bookkeeping_recorded: false,
            mmp_recorded: false,
            spin_rtt: None,
        };
        if path_bookkeeping_allowed {
            result.address_changed = peer.set_current_addr(transport_id, remote_addr);
            result.path_bookkeeping_recorded = true;
            peer.link_stats_mut()
                .record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver
                    .record_recv(fmp_counter, inner_timestamp_ms, packet_len, ce_flag, now);
                result.spin_rtt = mmp.spin_bit.rx_observe(sp_flag, fmp_counter, now);
                result.mmp_recorded = true;
            }
        }

        Some(result)
    }

    pub(in crate::node) fn record_fmp_send_bookkeeping(
        &mut self,
        node_addr: &NodeAddr,
        fmp_counter: u64,
        timestamp_ms: u32,
        bytes_sent: usize,
    ) -> Option<FmpSendBookkeeping> {
        let peer = self.active.get_mut(node_addr)?;
        peer.link_stats_mut().record_sent(bytes_sent);

        let mut result = FmpSendBookkeeping {
            mmp_recorded: false,
        };
        if let Some(mmp) = peer.mmp_mut() {
            mmp.sender
                .record_sent(fmp_counter, timestamp_ms, bytes_sent);
            result.mmp_recorded = true;
        }
        Some(result)
    }

    pub(in crate::node) fn record_fmp_send_bookkeeping_batch<I>(
        &mut self,
        node_addr: &NodeAddr,
        records: I,
    ) -> Option<usize>
    where
        I: IntoIterator<Item = (u64, u32, usize)>,
    {
        let peer = self.active.get_mut(node_addr)?;
        let mut packets = 0usize;
        let mut bytes = 0usize;

        {
            let mut mmp = peer.mmp_mut();
            for (fmp_counter, timestamp_ms, bytes_sent) in records {
                packets += 1;
                bytes += bytes_sent;
                if let Some(mmp) = mmp.as_mut() {
                    mmp.sender
                        .record_sent(fmp_counter, timestamp_ms, bytes_sent);
                }
            }
        }

        if packets > 0 {
            peer.link_stats_mut().record_sent_batch(packets, bytes);
        }
        Some(packets)
    }

    pub(in crate::node) fn prepare_fmp_send(
        &self,
        node_addr: &NodeAddr,
        ce_flag: bool,
        payload_len: u16,
    ) -> Result<FmpSendPreparation, FmpSendPreparationError> {
        let peer = self
            .active
            .get(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        Self::fmp_send_preparation_from_peer(peer, ce_flag, payload_len)
    }

    fn fmp_send_preparation_from_peer(
        peer: &ActivePeer,
        ce_flag: bool,
        payload_len: u16,
    ) -> Result<FmpSendPreparation, FmpSendPreparationError> {
        let snapshot = Self::peer_runtime_route_snapshot_from_peer(*peer.node_addr(), peer)?
            .prepare_send_snapshot(ce_flag, payload_len);
        Ok(snapshot.fmp_prepared().clone())
    }

    fn peer_runtime_route_snapshot_from_peer(
        node_addr: NodeAddr,
        peer: &ActivePeer,
    ) -> Result<PeerRuntimeRouteSnapshot, FmpSendPreparationError> {
        let their_index = peer
            .their_index()
            .ok_or(FmpSendPreparationError::MissingTheirIndex)?;
        let transport_id = peer
            .transport_id()
            .ok_or(FmpSendPreparationError::MissingTransportId)?;
        let remote_addr = peer
            .current_addr()
            .cloned()
            .ok_or(FmpSendPreparationError::MissingCurrentAddr)?;
        let noise_session = peer
            .noise_session()
            .ok_or(FmpSendPreparationError::MissingNoiseSession)?;

        let timestamp_ms = peer.session_elapsed_ms();
        let sp_flag = peer.mmp().map(|mmp| mmp.spin_bit.tx_bit()).unwrap_or(false);
        let mut base_flags = if sp_flag { FLAG_SP } else { 0 };
        if peer.current_k_bit() {
            base_flags |= FLAG_KEY_EPOCH;
        }

        Ok(PeerRuntimeRouteSnapshot::new(
            node_addr,
            their_index,
            transport_id,
            remote_addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            peer.connected_udp(),
            timestamp_ms,
            base_flags,
            noise_session.has_send_cipher(),
        ))
    }

    #[cfg(unix)]
    pub(in crate::node) fn prepare_peer_runtime_route_snapshot(
        &self,
        node_addr: &NodeAddr,
    ) -> Result<PeerRuntimeRouteSnapshot, FmpSendPreparationError> {
        let peer = self
            .active
            .get(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        Self::peer_runtime_route_snapshot_from_peer(*node_addr, peer)
    }

    #[cfg(unix)]
    pub(in crate::node) fn endpoint_bulk_fmp_lease(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<EndpointBulkSendFmpLease> {
        let peer = self.active.get(node_addr)?;
        let session = peer.noise_session()?;
        let mut base_flags = if peer.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()) {
            FLAG_SP
        } else {
            0
        };
        if peer.current_k_bit() {
            base_flags |= FLAG_KEY_EPOCH;
        }

        Some(EndpointBulkSendFmpLease {
            cipher: session.send_cipher_clone()?,
            counter_authority: session.send_counter_authority(),
            their_index: peer.their_index()?,
            session_start: peer.session_start(),
            base_flags,
        })
    }

    #[cfg(all(unix, test))]
    pub(in crate::node) fn prepare_peer_runtime_send_snapshot(
        &self,
        node_addr: &NodeAddr,
        ce_flag: bool,
        payload_len: u16,
    ) -> Result<PeerRuntimeSendSnapshot, FmpSendPreparationError> {
        Ok(self
            .prepare_peer_runtime_route_snapshot(node_addr)?
            .prepare_send_snapshot(ce_flag, payload_len))
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_prepared_fmp_worker_send(
        &mut self,
        node_addr: &NodeAddr,
        prepared: &FmpSendPreparation,
    ) -> Result<Option<PreparedFmpWorkerReservation>, FmpSendPreparationError> {
        let peer = self
            .active
            .get_mut(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        let session = peer
            .noise_session_mut()
            .ok_or(FmpSendPreparationError::MissingNoiseSession)?;
        let reservation = reserve_fmp_worker_send(
            session,
            prepared.their_index,
            prepared.flags,
            prepared.payload_len,
        )
        .map_err(|_| FmpSendPreparationError::CounterReservationFailed)?;

        Ok(reservation.map(|reservation| {
            let predicted_bytes =
                ESTABLISHED_HEADER_SIZE + prepared.payload_len as usize + crate::noise::TAG_SIZE;
            PreparedFmpWorkerReservation {
                counter: reservation.counter,
                header: reservation.header,
                cipher: reservation.cipher,
                predicted_bytes,
            }
        }))
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_prepared_fmp_worker_send_batch<'a, I>(
        &mut self,
        node_addr: &NodeAddr,
        prepared: I,
    ) -> Result<Option<Vec<PreparedFmpWorkerReservation>>, FmpSendPreparationError>
    where
        I: IntoIterator<Item = &'a FmpSendPreparation>,
    {
        let peer = self
            .active
            .get_mut(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        let session = peer
            .noise_session_mut()
            .ok_or(FmpSendPreparationError::MissingNoiseSession)?;
        let Some(cipher) = session.send_cipher_clone() else {
            return Ok(None);
        };
        let counter_authority = session.send_counter_authority();

        let prepared = prepared.into_iter().collect::<Vec<_>>();
        let counters = counter_authority
            .reserve_range(prepared.len())
            .map_err(|_| FmpSendPreparationError::CounterReservationFailed)?;
        let mut reservations = Vec::with_capacity(prepared.len());
        for (prepared, counter) in prepared.into_iter().zip(counters) {
            let header = build_established_header(
                prepared.their_index,
                counter,
                prepared.flags,
                prepared.payload_len,
            );
            let predicted_bytes =
                ESTABLISHED_HEADER_SIZE + prepared.payload_len as usize + crate::noise::TAG_SIZE;
            reservations.push(PreparedFmpWorkerReservation {
                counter,
                header,
                cipher: cipher.clone(),
                predicted_bytes,
            });
        }

        Ok(Some(reservations))
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_peer_runtime_fmp_worker_send(
        &mut self,
        snapshot: &PeerRuntimeSendSnapshot,
    ) -> Result<Option<PreparedFmpWorkerReservation>, FmpSendPreparationError> {
        self.reserve_prepared_fmp_worker_send(&snapshot.node_addr(), snapshot.fmp_prepared())
    }

    #[cfg(unix)]
    pub(in crate::node) fn reserve_peer_runtime_fmp_worker_send_batch<'a, I>(
        &mut self,
        node_addr: &NodeAddr,
        snapshots: I,
    ) -> Result<Option<Vec<PreparedFmpWorkerReservation>>, FmpSendPreparationError>
    where
        I: IntoIterator<Item = &'a PeerRuntimeSendSnapshot>,
    {
        self.reserve_prepared_fmp_worker_send_batch(
            node_addr,
            snapshots.into_iter().map(|snapshot| {
                debug_assert_eq!(snapshot.node_addr(), *node_addr);
                snapshot.fmp_prepared()
            }),
        )
    }

    #[cfg(unix)]
    pub(in crate::node) fn prepare_fmp_worker_send(
        &mut self,
        node_addr: &NodeAddr,
        prepared: &FmpSendPreparation,
        plaintext: &[u8],
    ) -> Result<Option<PreparedFmpWorkerSend>, FmpSendPreparationError> {
        const INNER_TS_LEN: usize = 4;
        let expected_payload_len = INNER_TS_LEN + plaintext.len();
        if prepared.payload_len as usize != expected_payload_len {
            return Err(FmpSendPreparationError::PayloadLengthMismatch);
        }

        Ok(self
            .reserve_prepared_fmp_worker_send(node_addr, prepared)?
            .map(|reservation| {
                let header = reservation.header;
                let wire_len = ESTABLISHED_HEADER_SIZE + prepared.payload_len as usize;
                let mut wire_buf = Vec::with_capacity(reservation.predicted_bytes);
                wire_buf.extend_from_slice(&header);
                wire_buf.extend_from_slice(&prepared.timestamp_ms.to_le_bytes());
                wire_buf.extend_from_slice(plaintext);
                debug_assert_eq!(wire_buf.len(), wire_len);

                PreparedFmpWorkerSend {
                    counter: reservation.counter,
                    #[cfg(test)]
                    header,
                    cipher: reservation.cipher,
                    wire_buf,
                    predicted_bytes: reservation.predicted_bytes,
                }
            }))
    }

    pub(in crate::node) fn seal_prepared_fmp_inline_send(
        &mut self,
        node_addr: &NodeAddr,
        prepared: &FmpSendPreparation,
        inner_plaintext: &[u8],
    ) -> Result<PreparedFmpInlineSend, FmpSendPreparationError> {
        let peer = self
            .active
            .get_mut(node_addr)
            .ok_or(FmpSendPreparationError::MissingPeer)?;
        let session = peer
            .noise_session_mut()
            .ok_or(FmpSendPreparationError::MissingNoiseSession)?;
        let counter = session.current_send_counter();
        let header = build_established_header(
            prepared.their_index,
            counter,
            prepared.flags,
            prepared.payload_len,
        );
        let ciphertext = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);
            session
                .encrypt_with_aad(inner_plaintext, &header)
                .map_err(|_| FmpSendPreparationError::EncryptionFailed)?
        };
        let wire_packet = build_encrypted(&header, &ciphertext);
        Ok(PreparedFmpInlineSend {
            counter,
            #[cfg(test)]
            header,
            wire_packet,
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn connected_udp_activation_plan(
        &self,
        configured_peers: &ConfiguredPeerCache,
    ) -> ConnectedUdpActivationPlan {
        let candidates = self
            .active
            .iter()
            .filter_map(|(addr, peer)| {
                Self::connected_udp_activation_candidate(peer)
                    .then_some((*addr, configured_peers.contains(addr)))
            })
            .collect();
        let candidates = Self::connected_udp_activation_order(candidates);
        let installed_count = self
            .active
            .values()
            .filter(|peer| peer.connected_udp().is_some())
            .count();

        ConnectedUdpActivationPlan {
            candidates,
            installed_count,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn install_connected_udp_if_eligible(
        &mut self,
        node_addr: &NodeAddr,
        socket: std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
        drain: crate::transport::udp::peer_drain::PeerRecvDrain,
    ) -> ConnectedUdpInstallResult {
        let Some(peer) = self.active.get_mut(node_addr) else {
            return ConnectedUdpInstallResult::MissingPeer;
        };
        if !Self::connected_udp_activation_candidate(peer) {
            return ConnectedUdpInstallResult::NotEligible;
        }
        peer.set_connected_udp(socket, drain);
        ConnectedUdpInstallResult::Installed
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn clear_connected_udp_for_peer(
        &mut self,
        node_addr: &NodeAddr,
    ) -> ConnectedUdpClearResult {
        let Some(peer) = self.active.get_mut(node_addr) else {
            return ConnectedUdpClearResult::MissingPeer;
        };
        if peer.connected_udp().is_none() {
            return ConnectedUdpClearResult::AlreadyClear;
        }
        peer.clear_connected_udp();
        ConnectedUdpClearResult::Cleared
    }

    pub(in crate::node) fn mark_link_dead_direct_path(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Option<LinkDeadDirectPathDegradation> {
        let peer = self.active.get_mut(node_addr)?;
        let link_id = peer.link_id();
        peer.mark_stale();
        let connected_udp_cleared = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let had_connected_udp = peer.connected_udp().is_some();
                peer.clear_connected_udp();
                had_connected_udp
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                false
            }
        };

        Some(LinkDeadDirectPathDegradation {
            link_id,
            connected_udp_cleared,
        })
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

    #[cfg(test)]
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.active.is_empty()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FspSendBookkeepingInput {
    pub(in crate::node) data_bytes: Option<usize>,
    pub(in crate::node) counter: u64,
    pub(in crate::node) timestamp: u32,
    pub(in crate::node) frame_bytes: usize,
    pub(in crate::node) touch_ms: Option<u64>,
    pub(in crate::node) next_hop: Option<NodeAddr>,
}

impl FspSendBookkeepingInput {
    pub(in crate::node) fn data(
        data_bytes: usize,
        counter: u64,
        timestamp: u32,
        frame_bytes: usize,
        touch_ms: u64,
    ) -> Self {
        Self {
            data_bytes: Some(data_bytes),
            counter,
            timestamp,
            frame_bytes,
            touch_ms: Some(touch_ms),
            next_hop: None,
        }
    }

    pub(in crate::node) fn control(counter: u64, timestamp: u32, frame_bytes: usize) -> Self {
        Self {
            data_bytes: None,
            counter,
            timestamp,
            frame_bytes,
            touch_ms: None,
            next_hop: None,
        }
    }

    pub(in crate::node) fn with_next_hop(mut self, next_hop: NodeAddr) -> Self {
        self.next_hop = Some(next_hop);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FspSendBookkeeping {
    pub(in crate::node) data_recorded: bool,
    pub(in crate::node) mmp_recorded: bool,
    pub(in crate::node) touched: bool,
    pub(in crate::node) next_hop_recorded: bool,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FspWorkerSendReservationInput {
    pub(in crate::node) flags: u8,
    pub(in crate::node) payload_len: u16,
    pub(in crate::node) path_mtu: u16,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum FspWorkerSendReservationError {
    MissingSession,
    NotEstablished,
    CounterReservationFailed,
}
