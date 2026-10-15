impl Node {
    async fn send_session_confirmation(&mut self, destination: &NodeAddr, previous_hop: &NodeAddr) {
        let Some(proof) = self
            .sessions
            .get(destination)
            .and_then(SessionEntry::rekey_confirmation)
        else {
            return;
        };
        if !self.coords_response_rate_limiter.should_send(destination)
            || !self
                .setup_rate_limiter
                .try_admit(previous_hop, Msg1Class::EstablishedLink)
        {
            return;
        }
        let mut datagram =
            SessionDatagram::new(*self.node_addr(), *destination, proof.as_bytes().to_vec())
                .with_ttl(self.config.node.session.default_ttl);
        if let Err(error) = self.send_session_datagram(&mut datagram).await {
            debug!(dest = %self.peer_display_name(destination), %error, "Session confirmation send failed");
        }
    }

    fn handle_session_confirmation(
        &mut self,
        source: &NodeAddr,
        previous_hop: &NodeAddr,
        payload: &[u8],
    ) {
        let Some(proof) = SessionConfirm::decode(payload) else {
            return;
        };
        let Some(entry) = self.sessions.get(source) else {
            return;
        };
        if !entry.pending_rekey_initiator() || entry.pending_new_session().is_none() {
            return;
        }
        let next_k_bit = !entry.current_k_bit();
        if !self
            .setup_rate_limiter
            .try_admit(previous_hop, Msg1Class::EstablishedLink)
            || !self
                .dataplane
                .authenticate_fsp_owner_confirmation(source, &proof, next_k_bit)
        {
            return;
        }
        if self.promote_dataplane_authenticated_pending_fsp_epoch(source, next_k_bit) {
            debug!(src = %self.peer_display_name(source), "FSP rekey cutover confirmed by responder");
        }
    }
}
