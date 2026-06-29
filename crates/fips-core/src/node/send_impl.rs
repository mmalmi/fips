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

    pub(super) fn map_fmp_send_preparation_error(
        node_addr: NodeAddr,
        error: FmpSendPreparationError,
    ) -> NodeError {
        match error {
            FmpSendPreparationError::MissingPeer => NodeError::PeerNotFound(node_addr),
            FmpSendPreparationError::MissingTheirIndex => NodeError::SendFailed {
                node_addr,
                reason: "no their_index".into(),
            },
            FmpSendPreparationError::MissingTransportId => NodeError::SendFailed {
                node_addr,
                reason: "no transport_id".into(),
            },
            FmpSendPreparationError::MissingCurrentAddr => NodeError::SendFailed {
                node_addr,
                reason: "no current_addr".into(),
            },
            FmpSendPreparationError::MissingNoiseSession => NodeError::SendFailed {
                node_addr,
                reason: "no noise session".into(),
            },
            FmpSendPreparationError::PayloadLengthMismatch => NodeError::SendFailed {
                node_addr,
                reason: "payload length mismatch".into(),
            },
            FmpSendPreparationError::CounterReservationFailed => NodeError::SendFailed {
                node_addr,
                reason: "counter reservation failed".into(),
            },
            FmpSendPreparationError::EncryptionFailed => NodeError::SendFailed {
                node_addr,
                reason: "encryption failed".into(),
            },
        }
    }

    #[cfg(unix)]
    pub(super) fn map_fsp_worker_send_reservation_error(
        node_addr: NodeAddr,
        error: FspWorkerSendReservationError,
    ) -> NodeError {
        match error {
            FspWorkerSendReservationError::MissingSession => NodeError::SendFailed {
                node_addr,
                reason: "no session".into(),
            },
            FspWorkerSendReservationError::NotEstablished => NodeError::SendFailed {
                node_addr,
                reason: "session not established".into(),
            },
            FspWorkerSendReservationError::CounterReservationFailed => NodeError::SendFailed {
                node_addr,
                reason: "session counter reservation failed".into(),
            },
        }
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
