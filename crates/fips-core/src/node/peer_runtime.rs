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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum PeerRuntimeReceiveError {
    MissingInnerTimestamp,
}

pub(in crate::node) struct AuthenticatedFmpPlaintext<'a> {
    source_peer: PeerIdentity,
    transport_id: TransportId,
    remote_addr: &'a TransportAddr,
    packet_timestamp_ms: u64,
    packet_len: usize,
    fmp_counter: u64,
    fmp_flags: u8,
    plaintext: &'a [u8],
}

pub(in crate::node) struct PeerRuntimeReceive<'a> {
    source_peer: PeerIdentity,
    transport_id: TransportId,
    remote_addr: &'a TransportAddr,
    packet_timestamp_ms: u64,
    packet_len: usize,
    fmp_counter: u64,
    inner_timestamp_ms: u32,
    ce_flag: bool,
    sp_flag: bool,
    link_message: &'a [u8],
}

pub(in crate::node) struct PeerRuntimeReceiveDispatch<'a> {
    source_peer: PeerIdentity,
    ce_flag: bool,
    link_message: &'a [u8],
    bookkeeping: Option<AuthenticatedFmpReceiveBookkeeping>,
}

pub(in crate::node) struct PeerRuntimeReceiveAction<'a> {
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    source_peer: PeerIdentity,
    address_changed: bool,
    link_message: Option<AuthenticatedLinkMessage<'a>>,
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
    previous_hop_peer: PeerIdentity,
    payload: &'a [u8],
    path_mtu: u16,
    ce_flag: bool,
}

pub(in crate::node) struct EncryptedSessionPayload<'a> {
    source_addr: NodeAddr,
    previous_hop_peer: PeerIdentity,
    payload: &'a [u8],
    path_mtu: u16,
    ce_flag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct FmpSendBookkeeping {
    pub(in crate::node) mmp_recorded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum FmpSendPreparationError {
    MissingPeer,
    MissingTheirIndex,
    MissingTransportId,
    MissingCurrentAddr,
    MissingNoiseSession,
    PayloadLengthMismatch,
    CounterReservationFailed,
    EncryptionFailed,
}

#[cfg(unix)]
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
pub(in crate::node) struct FmpSendPreparation {
    pub(in crate::node) their_index: SessionIndex,
    pub(in crate::node) transport_id: TransportId,
    pub(in crate::node) remote_addr: TransportAddr,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) connected_socket:
        Option<Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
    pub(in crate::node) timestamp_ms: u32,
    pub(in crate::node) flags: u8,
    pub(in crate::node) payload_len: u16,
}

#[derive(Clone)]
pub(in crate::node) struct PeerRuntimeRouteSnapshot {
    node_addr: NodeAddr,
    their_index: SessionIndex,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_socket: Option<Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
    timestamp_ms: u32,
    base_flags: u8,
    fmp_worker_send_available: bool,
}

#[cfg(unix)]
pub(in crate::node) struct PeerRuntimeRouteDecision {
    next_hop_addr: NodeAddr,
    peer_snapshot: PeerRuntimeRouteSnapshot,
    scheduling_weight: u8,
    direct_path_blocks_direct_payload: bool,
}

impl<'a> AuthenticatedFmpPlaintext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn new(
        source_peer: PeerIdentity,
        transport_id: TransportId,
        remote_addr: &'a TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        fmp_flags: u8,
        plaintext: &'a [u8],
    ) -> Self {
        Self {
            source_peer,
            transport_id,
            remote_addr,
            packet_timestamp_ms,
            packet_len,
            fmp_counter,
            fmp_flags,
            plaintext,
        }
    }

    pub(in crate::node) fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    pub(in crate::node) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    pub(in crate::node) fn remote_addr(&self) -> &'a TransportAddr {
        self.remote_addr
    }

    pub(in crate::node) fn packet_timestamp_ms(&self) -> u64 {
        self.packet_timestamp_ms
    }
}

impl<'a> PeerRuntimeReceive<'a> {
    const INNER_TIMESTAMP_LEN: usize = 4;

    pub(in crate::node) fn from_authenticated_fmp_plaintext(
        receive: AuthenticatedFmpPlaintext<'a>,
    ) -> Result<Self, PeerRuntimeReceiveError> {
        let AuthenticatedFmpPlaintext {
            source_peer,
            transport_id,
            remote_addr,
            packet_timestamp_ms,
            packet_len,
            fmp_counter,
            fmp_flags,
            plaintext,
        } = receive;

        if plaintext.len() < Self::INNER_TIMESTAMP_LEN {
            return Err(PeerRuntimeReceiveError::MissingInnerTimestamp);
        }

        let inner_timestamp_ms =
            u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        let link_message = &plaintext[Self::INNER_TIMESTAMP_LEN..];

        Ok(Self {
            source_peer,
            transport_id,
            remote_addr,
            packet_timestamp_ms,
            packet_len,
            fmp_counter,
            inner_timestamp_ms,
            ce_flag: fmp_flags & FLAG_CE != 0,
            sp_flag: fmp_flags & FLAG_SP != 0,
            link_message,
        })
    }

    pub(in crate::node) fn record_bookkeeping(
        &self,
        peers: &mut PeerLifecycleRegistry,
        now: std::time::Instant,
        path_bookkeeping_allowed: bool,
    ) -> PeerRuntimeReceiveDispatch<'a> {
        let node_addr = self.source_peer.node_addr();
        let bookkeeping = peers.record_authenticated_fmp_receive(
            node_addr,
            self.transport_id,
            self.remote_addr,
            self.packet_timestamp_ms,
            self.packet_len,
            self.fmp_counter,
            self.inner_timestamp_ms,
            self.ce_flag,
            self.sp_flag,
            now,
            path_bookkeeping_allowed,
        );

        PeerRuntimeReceiveDispatch {
            source_peer: self.source_peer,
            ce_flag: self.ce_flag,
            link_message: self.link_message,
            bookkeeping,
        }
    }
}

impl<'a> PeerRuntimeReceiveDispatch<'a> {
    #[cfg(test)]
    pub(in crate::node) fn source_peer(&self) -> PeerIdentity {
        self.source_peer
    }

    #[cfg(test)]
    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    #[cfg(test)]
    pub(in crate::node) fn link_message(&self) -> &'a [u8] {
        self.link_message
    }

    #[cfg(test)]
    pub(in crate::node) fn bookkeeping(&self) -> Option<AuthenticatedFmpReceiveBookkeeping> {
        self.bookkeeping
    }

    pub(in crate::node) fn into_action(self) -> PeerRuntimeReceiveAction<'a> {
        let link_message =
            self.link_message
                .split_first()
                .map(|(&msg_type, payload)| AuthenticatedLinkMessage {
                    source_peer: self.source_peer,
                    msg_type,
                    payload,
                    ce_flag: self.ce_flag,
                });
        PeerRuntimeReceiveAction {
            #[cfg(any(test, target_os = "linux", target_os = "macos"))]
            source_peer: self.source_peer,
            address_changed: self
                .bookkeeping
                .is_some_and(|update| update.address_changed),
            link_message,
        }
    }
}

impl<'a> PeerRuntimeReceiveAction<'a> {
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    pub(in crate::node) fn address_changed(&self) -> bool {
        self.address_changed
    }

    #[cfg(test)]
    pub(in crate::node) fn link_message(&self) -> Option<&AuthenticatedLinkMessage<'a>> {
        self.link_message.as_ref()
    }

    pub(in crate::node) fn into_link_message(self) -> Option<AuthenticatedLinkMessage<'a>> {
        self.link_message
    }
}

impl<'a> AuthenticatedLinkMessage<'a> {
    pub(in crate::node) fn source_peer(&self) -> PeerIdentity {
        self.source_peer
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

    #[cfg(test)]
    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
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
        path_mtu: u16,
    ) -> LocalSessionPayload<'a> {
        LocalSessionPayload::new(
            source_addr,
            self.previous_hop_peer,
            payload,
            path_mtu,
            self.ce_flag,
        )
    }
}

impl<'a> LocalSessionPayload<'a> {
    pub(in crate::node) fn new(
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        payload: &'a [u8],
        path_mtu: u16,
        ce_flag: bool,
    ) -> Self {
        Self {
            source_addr,
            previous_hop_peer,
            payload,
            path_mtu,
            ce_flag,
        }
    }

    pub(in crate::node) fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    #[cfg(test)]
    pub(in crate::node) fn previous_hop_addr(&self) -> &NodeAddr {
        self.previous_hop_peer.node_addr()
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(in crate::node) fn into_encrypted(self) -> EncryptedSessionPayload<'a> {
        EncryptedSessionPayload {
            source_addr: self.source_addr,
            previous_hop_peer: self.previous_hop_peer,
            payload: self.payload,
            path_mtu: self.path_mtu,
            ce_flag: self.ce_flag,
        }
    }
}

impl<'a> EncryptedSessionPayload<'a> {
    pub(in crate::node) fn source_addr(&self) -> &NodeAddr {
        &self.source_addr
    }

    pub(in crate::node) fn previous_hop_addr(&self) -> &NodeAddr {
        self.previous_hop_peer.node_addr()
    }

    pub(in crate::node) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(in crate::node) fn path_mtu(&self) -> u16 {
        self.path_mtu
    }

    pub(in crate::node) fn ce_flag(&self) -> bool {
        self.ce_flag
    }
}

impl PeerRuntimeRouteSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn new(
        node_addr: NodeAddr,
        their_index: SessionIndex,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        #[cfg(any(target_os = "linux", target_os = "macos"))] connected_socket: Option<
            Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
        >,
        timestamp_ms: u32,
        base_flags: u8,
        fmp_worker_send_available: bool,
    ) -> Self {
        Self {
            node_addr,
            their_index,
            transport_id,
            remote_addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket,
            timestamp_ms,
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
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                connected_socket: self.connected_socket.clone(),
                timestamp_ms: self.timestamp_ms,
                flags,
                payload_len,
            },
            self.fmp_worker_send_available,
        )
    }
}

#[cfg(unix)]
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

    pub(in crate::node) fn into_parts(self) -> (PeerRuntimeRouteSnapshot, u8, bool) {
        let Self {
            next_hop_addr,
            peer_snapshot,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        } = self;
        debug_assert_eq!(next_hop_addr, peer_snapshot.node_addr());
        (
            peer_snapshot,
            scheduling_weight,
            direct_path_blocks_direct_payload,
        )
    }
}

pub(in crate::node) struct PeerRuntimeSendSnapshot {
    node_addr: NodeAddr,
    fmp_prepared: FmpSendPreparation,
    fmp_worker_send_available: bool,
}

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

pub(in crate::node) struct PreparedFmpInlineSend {
    pub(in crate::node) counter: u64,
    #[cfg(test)]
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) wire_packet: Vec<u8>,
}

#[cfg(unix)]
pub(in crate::node) struct PreparedFmpWorkerReservation {
    pub(in crate::node) counter: u64,
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) cipher: Arc<ring::aead::LessSafeKey>,
    pub(in crate::node) predicted_bytes: usize,
}

#[cfg(unix)]
pub(in crate::node) struct PreparedFmpWorkerSend {
    pub(in crate::node) counter: u64,
    #[cfg(test)]
    pub(in crate::node) header: [u8; ESTABLISHED_HEADER_SIZE],
    pub(in crate::node) cipher: Arc<ring::aead::LessSafeKey>,
    pub(in crate::node) wire_buf: Vec<u8>,
    pub(in crate::node) predicted_bytes: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone)]
pub(crate) struct ConnectedUdpDecryptFastPath {
    session_key: decrypt_worker::DecryptSessionKey,
    local_node_addr: NodeAddr,
    workers: decrypt_worker::DecryptWorkerPool,
    fallback_tx: decrypt_worker::DecryptWorkerFallbackSender,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ConnectedUdpDecryptFastPathBatcher {
    fast_path: ConnectedUdpDecryptFastPath,
    jobs: decrypt_worker::DecryptJobBatcher,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ConnectedUdpDecryptFastPathBatcher {
    fn new(fast_path: ConnectedUdpDecryptFastPath) -> Self {
        Self {
            fast_path,
            jobs: decrypt_worker::DecryptJobBatcher::new(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ConnectedUdpDecryptFastPath {
    pub(in crate::node) fn new(
        session_key: decrypt_worker::DecryptSessionKey,
        local_node_addr: NodeAddr,
        workers: decrypt_worker::DecryptWorkerPool,
        fallback_tx: decrypt_worker::DecryptWorkerFallbackSender,
    ) -> Self {
        Self {
            session_key,
            local_node_addr,
            workers,
            fallback_tx,
        }
    }

    pub(in crate::node) fn prepare_job(
        &self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        packet_data: Vec<u8>,
        timestamp_ms: u64,
    ) -> Result<decrypt_worker::DecryptJob, Vec<u8>> {
        let Some(header) = wire::EncryptedHeader::parse(&packet_data) else {
            return Err(packet_data);
        };
        let packet_session_key =
            decrypt_worker::DecryptSessionKey::new(transport_id, header.receiver_idx.as_u32());
        if packet_session_key != self.session_key {
            return Err(packet_data);
        }

        Ok(decrypt_worker::DecryptJob::new(
            packet_data,
            self.session_key,
            transport_id,
            remote_addr,
            self.local_node_addr,
            timestamp_ms,
            header.counter,
            header.flags,
            header.header_bytes,
            header.ciphertext_offset(),
            self.fallback_tx.clone(),
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl crate::transport::udp::peer_drain::ConnectedUdpPacketFastPath for ConnectedUdpDecryptFastPath {
    fn batcher(
        &self,
    ) -> Box<dyn crate::transport::udp::peer_drain::ConnectedUdpPacketFastPathBatcher> {
        Box::new(ConnectedUdpDecryptFastPathBatcher::new(self.clone()))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl crate::transport::udp::peer_drain::ConnectedUdpPacketFastPathBatcher
    for ConnectedUdpDecryptFastPathBatcher
{
    fn try_dispatch(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        packet_data: Vec<u8>,
        timestamp_ms: u64,
    ) -> Result<(), Vec<u8>> {
        match self
            .fast_path
            .prepare_job(transport_id, remote_addr, packet_data, timestamp_ms)
        {
            Ok(job) => {
                self.jobs.push(&self.fast_path.workers, job);
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::ConnectedUdpDirectDecrypt,
                );
                Ok(())
            }
            Err(packet_data) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::ConnectedUdpDirectDecryptMiss,
                );
                Err(packet_data)
            }
        }
    }

    fn flush(&mut self) {
        self.jobs.flush(&self.fast_path.workers);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::node) struct ConnectedUdpActivationPlan {
    pub(in crate::node) candidates: Vec<NodeAddr>,
    pub(in crate::node) installed_count: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum ConnectedUdpInstallResult {
    MissingPeer,
    NotEligible,
    Installed,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum ConnectedUdpClearResult {
    MissingPeer,
    AlreadyClear,
    Cleared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct LinkDeadDirectPathDegradation {
    pub(in crate::node) link_id: LinkId,
    pub(in crate::node) connected_udp_cleared: bool,
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
