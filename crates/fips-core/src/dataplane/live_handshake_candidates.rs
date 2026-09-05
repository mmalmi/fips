type DataplaneFmpHandshakeCandidates = Arc<HashMap<(TransportId, u32), TransportAddr>>;

fn is_fmp_handshake_candidate(
    candidates: &DataplaneFmpHandshakeCandidates,
    packet: &ReceivedPacket,
) -> bool {
    !candidates.is_empty()
        && FmpWireHeader::parse(packet.data.as_slice())
            .ok()
            .is_some_and(|header| {
                candidates.get(&(packet.transport_id, header.receiver_idx()))
                    == Some(&packet.remote_addr)
            })
}

impl DataplaneLiveNode {
    /// Divert a newly allocated receiver index to handshake confirmation.
    /// The candidate has no active owner route until the node promotes it.
    pub(crate) fn register_fmp_handshake_candidate(
        &mut self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        receiver_idx: u32,
    ) {
        Arc::make_mut(&mut self.fmp_handshake_candidates)
            .insert((transport_id, receiver_idx), remote_addr.clone());
    }

    pub(crate) fn remove_fmp_handshake_candidate(
        &mut self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        receiver_idx: u32,
    ) {
        let key = (transport_id, receiver_idx);
        if self.fmp_handshake_candidates.get(&key) == Some(remote_addr) {
            Arc::make_mut(&mut self.fmp_handshake_candidates).remove(&key);
        }
    }

    /// Reenter normal admission after promotion, retaining the original frame
    /// so the active owner authenticates, accounts for, and dispatches it once.
    pub(crate) fn defer_fmp_handshake_proof(&mut self, packet: ReceivedPacket) {
        self.deferred_raw_ingress.push_back((
            DataplaneRawIngress::from_live_received(PacketProtocol::Fmp, packet),
            crate::time::now_ms(),
        ));
        self.readiness_notify().notify_one();
    }
}
