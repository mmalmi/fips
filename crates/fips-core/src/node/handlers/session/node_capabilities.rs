use crate::node::session::capabilities::{
    DIRECT_FSP, SESSION_CAPABILITY_PORT, SessionCapabilities,
};

impl Node {
    /// Optional negotiation never changes whether the standard session works.
    /// Before a positive advertisement, this takes the ordinary FMP route.
    async fn send_session_capabilities(&mut self, dest_addr: &NodeAddr, request: bool) {
        let mut body = [0u8; 16];
        body[..2].copy_from_slice(&SESSION_CAPABILITY_PORT.to_le_bytes());
        body[2..4].copy_from_slice(&SESSION_CAPABILITY_PORT.to_le_bytes());
        body[4..].copy_from_slice(&SessionCapabilities::local(request).encode());
        if let Err(error) = Box::pin(self.send_dataplane_fsp_session_msg(
            dest_addr,
            SessionMessageType::DataPacket.to_byte(),
            &body,
        ))
        .await
        {
            debug!(peer = %self.peer_display_name(dest_addr), %error, "Optional session capabilities not sent");
        }
    }

    /// Called only after FSP authentication/replay admission, never for the
    /// cleartext handshake or an application-injected service datagram.
    async fn handle_session_capabilities(
        &mut self,
        source_addr: &NodeAddr,
        source_port: u16,
        payload: &[u8],
    ) {
        if source_port != SESSION_CAPABILITY_PORT {
            return;
        }
        let Some(capabilities) = SessionCapabilities::decode(payload) else {
            return;
        };
        if !self
            .sessions
            .get(source_addr)
            .is_some_and(SessionEntry::is_established)
        {
            return;
        }
        // The authenticated record proves possession of this epoch's keys,
        // independently of whether it carries application or route evidence.
        clear_dataplane_confirmed_retransmits_for(self, source_addr);
        // Send the first response using the standard carrier before enabling
        // the optimization. Response messages never elicit another response.
        if capabilities.request {
            self.send_session_capabilities(source_addr, false).await;
        }
        if capabilities.bits & DIRECT_FSP != 0 {
            if let Some(entry) = self.sessions.get_mut(source_addr) {
                entry.set_remote_supports_direct_fsp_transport(true);
            }
            // The capability changes framing, not path preference. A routed
            // session will use it if a later routing decision selects direct.
            if self.dataplane.fsp_owner_next_hop(source_addr) == Some(*source_addr) {
                self.refresh_dataplane_fsp_owner_routes_retaining_current(source_addr);
            }
        }
    }
}
