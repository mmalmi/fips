use super::*;

impl Node {
    // === Sending ===

    /// Encrypt and send a link-layer message to an authenticated peer.
    ///
    /// The plaintext should include the message type byte followed by the
    /// message-specific payload (e.g., `[0x50, reason]` for Disconnect).
    ///
    /// The send path prepends a 4-byte session-relative timestamp (inner
    /// header) before encryption. The full 16-byte outer header is used
    /// as AAD for the AEAD construction.
    ///
    /// This is the standard path for sending any link-layer control message
    /// to a peer over their encrypted Noise session.
    pub(super) async fn send_encrypted_link_message(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        self.send_encrypted_link_message_with_ce(node_addr, plaintext, false)
            .await
    }

    /// Like `send_encrypted_link_message` but allows setting the FMP CE flag.
    ///
    /// Used by the forwarding path to relay congestion signals hop-by-hop.
    pub(super) async fn send_encrypted_link_message_with_ce(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        self.send_packet_mover2_fmp_link_plaintext(node_addr, plaintext, ce_flag)
            .await
    }
}
