use super::*;

/// Active FMP receiver-index registry keyed by `(transport_id, our_index)`.
#[derive(Debug, Default)]
pub(in crate::node) struct SessionIndexRegistry {
    entries: HashMap<(TransportId, u32), NodeAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct RemovedSessionIndex {
    pub(in crate::node) owner: NodeAddr,
    pub(in crate::node) owner_has_remaining_index: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum PeerSessionIndexKind {
    Current,
    Rekey,
    Pending,
    Previous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct PeerSessionIndex {
    pub(in crate::node) kind: PeerSessionIndexKind,
    pub(in crate::node) key: (TransportId, u32),
    pub(in crate::node) index: SessionIndex,
}

#[derive(Debug)]
pub(in crate::node) struct RemovedActivePeer {
    pub(in crate::node) peer: ActivePeer,
    pub(in crate::node) session_indices: Vec<PeerSessionIndex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct RegisteredPeerSessionIndex {
    pub(in crate::node) session_index: PeerSessionIndex,
    pub(in crate::node) previous_owner: Option<NodeAddr>,
}

#[derive(Debug)]
pub(in crate::node) struct InsertedActivePeer {
    pub(in crate::node) previous_peer: Option<ActivePeer>,
    pub(in crate::node) current_session_index: Option<RegisteredPeerSessionIndex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum CurrentSessionIndexRegistration {
    MissingActivePeer,
    MissingTransportId,
    MissingLocalIndex,
    AlreadyRegistered(PeerSessionIndex),
    Repaired(RegisteredPeerSessionIndex),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct ReplacedActivePeerCurrentSession {
    pub(in crate::node) old_link_id: LinkId,
    pub(in crate::node) old_session_index: Option<PeerSessionIndex>,
    pub(in crate::node) new_session_index: RegisteredPeerSessionIndex,
    pub(in crate::node) replay_suppressed_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct AuthenticatedFmpReceiveBookkeeping {
    pub(in crate::node) address_changed: bool,
    pub(in crate::node) path_bookkeeping_recorded: bool,
    pub(in crate::node) mmp_recorded: bool,
    pub(in crate::node) spin_rtt: Option<std::time::Duration>,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::node) struct AuthenticatedFmpReceiveFacts<'a> {
    pub(in crate::node) source_peer: PeerIdentity,
    pub(in crate::node) transport_id: TransportId,
    pub(in crate::node) remote_addr: &'a TransportAddr,
    pub(in crate::node) packet_timestamp_ms: u64,
    pub(in crate::node) packet_len: usize,
    pub(in crate::node) fmp_counter: u64,
    pub(in crate::node) inner_timestamp_ms: u32,
    pub(in crate::node) fmp_flags: u8,
}

pub(in crate::node) struct AuthenticatedLinkMessage<'a> {
    source_peer: PeerIdentity,
    msg_type: u8,
    payload: &'a [u8],
    ce_flag: bool,
}

pub(in crate::node) struct AuthenticatedSessionDatagram<'a> {
    previous_hop_peer: PeerIdentity,
    payload: &'a [u8],
    ce_flag: bool,
}

pub(in crate::node) struct LocalSessionPayload<'a> {
    source_addr: NodeAddr,
    payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FmpSendBookkeeping {
    pub(in crate::node) mmp_recorded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(all(test, unix))]
pub(in crate::node) enum FmpSendPreparationError {
    MissingPeer,
    MissingTheirIndex,
    MissingTransportId,
    MissingCurrentAddr,
    MissingNoiseSession,
    CounterReservationFailed,
}

#[cfg(all(test, unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum PeerRuntimeRouteDecisionError {
    NoRoute {
        dest_addr: NodeAddr,
    },
    FmpPreparation {
        next_hop_addr: NodeAddr,
        error: FmpSendPreparationError,
    },
}

#[derive(Clone)]
#[cfg(all(test, unix))]
pub(in crate::node) struct FmpSendPreparation {
    pub(in crate::node) their_index: SessionIndex,
    pub(in crate::node) transport_id: TransportId,
    pub(in crate::node) remote_addr: TransportAddr,
    pub(in crate::node) flags: u8,
    pub(in crate::node) payload_len: u16,
}

#[derive(Clone)]
#[cfg(all(test, unix))]
pub(in crate::node) struct PeerRuntimeRouteSnapshot {
    node_addr: NodeAddr,
    their_index: SessionIndex,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    base_flags: u8,
    fmp_worker_send_available: bool,
}

#[cfg(all(test, unix))]
pub(in crate::node) struct PeerRuntimeRouteDecision {
    next_hop_addr: NodeAddr,
    peer_snapshot: PeerRuntimeRouteSnapshot,
    scheduling_weight: u8,
    direct_path_blocks_direct_payload: bool,
}

impl<'a> AuthenticatedFmpReceiveFacts<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn new(
        source_peer: PeerIdentity,
        transport_id: TransportId,
        remote_addr: &'a TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        inner_timestamp_ms: u32,
        fmp_flags: u8,
    ) -> Self {
        Self {
            source_peer,
            transport_id,
            remote_addr,
            packet_timestamp_ms,
            packet_len,
            fmp_counter,
            inner_timestamp_ms,
            fmp_flags,
        }
    }

    pub(in crate::node) fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }
}

impl<'a> AuthenticatedLinkMessage<'a> {
    pub(in crate::node) fn new(
        source_peer: PeerIdentity,
        msg_type: u8,
        payload: &'a [u8],
        ce_flag: bool,
    ) -> Self {
        Self {
            source_peer,
            msg_type,
            payload,
            ce_flag,
        }
    }

    pub(in crate::node) fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    pub(in crate::node) fn msg_type(&self) -> u8 {
        self.msg_type
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(in crate::node) fn into_session_datagram(self) -> AuthenticatedSessionDatagram<'a> {
        debug_assert_eq!(self.msg_type, LinkMessageType::SessionDatagram.to_byte());
        AuthenticatedSessionDatagram::new(self.source_peer, self.payload, self.ce_flag)
    }
}

impl<'a> AuthenticatedSessionDatagram<'a> {
    pub(in crate::node) fn new(
        previous_hop_peer: PeerIdentity,
        payload: &'a [u8],
        ce_flag: bool,
    ) -> Self {
        Self {
            previous_hop_peer,
            payload,
            ce_flag,
        }
    }

    pub(in crate::node) fn previous_hop_addr(&self) -> &NodeAddr {
        self.previous_hop_peer.node_addr()
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(in crate::node) fn local_session_payload(
        &self,
        source_addr: NodeAddr,
        payload: &'a [u8],
    ) -> LocalSessionPayload<'a> {
        LocalSessionPayload::new(source_addr, payload)
    }
}

impl<'a> LocalSessionPayload<'a> {
    pub(in crate::node) fn new(source_addr: NodeAddr, payload: &'a [u8]) -> Self {
        Self {
            source_addr,
            payload,
        }
    }

    pub(in crate::node) fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[cfg(all(test, unix))]
impl PeerRuntimeRouteSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn new(
        node_addr: NodeAddr,
        their_index: SessionIndex,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        base_flags: u8,
        fmp_worker_send_available: bool,
    ) -> Self {
        Self {
            node_addr,
            their_index,
            transport_id,
            remote_addr,
            base_flags,
            fmp_worker_send_available,
        }
    }

    pub(in crate::node) fn node_addr(&self) -> NodeAddr {
        self.node_addr
    }

    pub(in crate::node) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    #[cfg(test)]
    pub(in crate::node) fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    pub(in crate::node) fn path_mtu(&self, transport: &TransportHandle) -> u16 {
        debug_assert_eq!(transport.transport_id(), self.transport_id);
        transport.link_mtu(&self.remote_addr)
    }

    pub(in crate::node) fn prepare_send_snapshot(
        &self,
        ce_flag: bool,
        payload_len: u16,
    ) -> PeerRuntimeSendSnapshot {
        let mut flags = self.base_flags;
        if ce_flag {
            flags |= FLAG_CE;
        }

        PeerRuntimeSendSnapshot::new(
            self.node_addr,
            FmpSendPreparation {
                their_index: self.their_index,
                transport_id: self.transport_id,
                remote_addr: self.remote_addr.clone(),
                flags,
                payload_len,
            },
            self.fmp_worker_send_available,
        )
    }
}

#[cfg(all(test, unix))]
impl PeerRuntimeRouteDecision {
    pub(in crate::node) fn new(
        next_hop_addr: NodeAddr,
        peer_snapshot: PeerRuntimeRouteSnapshot,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
    ) -> Self {
        debug_assert_eq!(next_hop_addr, peer_snapshot.node_addr());
        Self {
            next_hop_addr,
            peer_snapshot,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        }
    }

    #[cfg(test)]
    pub(in crate::node) fn next_hop_addr(&self) -> NodeAddr {
        self.next_hop_addr
    }

    #[cfg(test)]
    pub(in crate::node) fn peer_snapshot(&self) -> &PeerRuntimeRouteSnapshot {
        &self.peer_snapshot
    }

    #[cfg(test)]
    pub(in crate::node) fn scheduling_weight(&self) -> u8 {
        self.scheduling_weight
    }

    #[cfg(test)]
    pub(in crate::node) fn direct_path_blocks_direct_payload(&self) -> bool {
        self.direct_path_blocks_direct_payload
    }
}

#[cfg(all(test, unix))]
pub(in crate::node) struct PeerRuntimeSendSnapshot {
    node_addr: NodeAddr,
    fmp_prepared: FmpSendPreparation,
    fmp_worker_send_available: bool,
}

#[cfg(all(test, unix))]
impl PeerRuntimeSendSnapshot {
    pub(in crate::node) fn new(
        node_addr: NodeAddr,
        fmp_prepared: FmpSendPreparation,
        fmp_worker_send_available: bool,
    ) -> Self {
        Self {
            node_addr,
            fmp_prepared,
            fmp_worker_send_available,
        }
    }

    pub(in crate::node) fn node_addr(&self) -> NodeAddr {
        self.node_addr
    }

    pub(in crate::node) fn fmp_prepared(&self) -> &FmpSendPreparation {
        &self.fmp_prepared
    }

    pub(in crate::node) fn fmp_worker_send_available(&self) -> bool {
        self.fmp_worker_send_available
    }
}

#[cfg(all(test, unix))]
pub(in crate::node) struct PreparedFmpWorkerReservation {
    pub(in crate::node) counter: u64,
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) predicted_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct LinkDeadDirectPathDegradation {
    pub(in crate::node) link_id: LinkId,
}

impl SessionIndexRegistry {
    pub(in crate::node) fn insert(
        &mut self,
        key: (TransportId, u32),
        node_addr: NodeAddr,
    ) -> Option<NodeAddr> {
        self.entries.insert(key, node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn remove(&mut self, key: &(TransportId, u32)) -> Option<NodeAddr> {
        self.entries.remove(key)
    }

    pub(in crate::node) fn remove_with_owner_state(
        &mut self,
        key: &(TransportId, u32),
    ) -> Option<RemovedSessionIndex> {
        let owner = self.entries.remove(key)?;
        let owner_has_remaining_index = self.peer_has_any_index(&owner);
        Some(RemovedSessionIndex {
            owner,
            owner_has_remaining_index,
        })
    }

    pub(in crate::node) fn lookup(&self, key: (TransportId, u32)) -> Option<NodeAddr> {
        self.entries.get(&key).copied()
    }

    pub(in crate::node) fn peer_has_any_index(&self, node_addr: &NodeAddr) -> bool {
        self.entries.values().any(|other| other == node_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn get(&self, key: &(TransportId, u32)) -> Option<&NodeAddr> {
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
}
