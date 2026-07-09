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

pub(in crate::node) struct ActivePeerCurrentSessionReplacement<'a> {
    pub(in crate::node) session: crate::noise::NoiseSession,
    pub(in crate::node) our_index: SessionIndex,
    pub(in crate::node) their_index: SessionIndex,
    pub(in crate::node) link_id: LinkId,
    pub(in crate::node) transport_id: TransportId,
    pub(in crate::node) addr: &'a TransportAddr,
    pub(in crate::node) is_initiator: bool,
    pub(in crate::node) remote_epoch_update: Option<[u8; 8]>,
    pub(in crate::node) connected_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct AuthenticatedFmpReceiveBookkeeping {
    pub(in crate::node) address_changed: bool,
    pub(in crate::node) path_bookkeeping_recorded: bool,
    pub(in crate::node) liveness_bookkeeping_recorded: bool,
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
    pub(in crate::node) source_peer: PeerIdentity,
    pub(in crate::node) msg_type: u8,
    pub(in crate::node) payload: &'a [u8],
    pub(in crate::node) ce_flag: bool,
}

pub(in crate::node) struct AuthenticatedSessionDatagram<'a> {
    pub(in crate::node) previous_hop_peer: PeerIdentity,
    pub(in crate::node) payload: &'a [u8],
    pub(in crate::node) ce_flag: bool,
}

pub(in crate::node) struct LocalSessionPayload<'a> {
    source_addr: NodeAddr,
    payload: &'a [u8],
}

impl<'a> AuthenticatedFmpReceiveFacts<'a> {
    pub(in crate::node) fn from_dataplane_receipt(
        receipt: &'a crate::dataplane::DataplaneFmpIngressReceipt,
    ) -> Self {
        Self {
            source_peer: receipt.source_peer(),
            transport_id: receipt.transport_id(),
            remote_addr: receipt.remote_addr(),
            packet_timestamp_ms: receipt.packet_timestamp_ms(),
            packet_len: receipt.packet_len(),
            fmp_counter: receipt.fmp_counter(),
            inner_timestamp_ms: receipt.inner_timestamp_ms(),
            fmp_flags: receipt.fmp_flags(),
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
