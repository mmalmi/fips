use super::WebRtcSignal;
use crate::NodeAddr;
use crate::transport::TransportError;
use crate::transport::link_negotiation::OutboundLinkNegotiation;
use nostr::prelude::PublicKey;
use tokio::sync::mpsc;
use tracing::debug;

/// WebRTC has no relay client of its own. Its SDP negotiation is ordinary
/// encrypted FIPS session traffic, which also lets any bootstrap transport
/// (including the Nostr relay fallback) negotiate a better data path.
#[derive(Clone)]
pub(super) struct FipsSignalSender {
    tx: mpsc::UnboundedSender<OutboundLinkNegotiation>,
}

impl FipsSignalSender {
    pub(super) fn new(tx: mpsc::UnboundedSender<OutboundLinkNegotiation>) -> Self {
        Self { tx }
    }

    pub(super) fn send_signal(
        &self,
        receiver: PublicKey,
        signal: &WebRtcSignal,
    ) -> Result<(), TransportError> {
        let xonly = secp256k1::XOnlyPublicKey::from_slice(receiver.as_bytes())
            .map_err(|error| TransportError::InvalidAddress(error.to_string()))?;
        let recipient = NodeAddr::from_pubkey(&xonly);
        let payload = serde_json::to_vec(signal)
            .map_err(|error| TransportError::SendFailed(error.to_string()))?;
        self.tx
            .send(OutboundLinkNegotiation { recipient, payload })
            .map_err(|_| TransportError::SendFailed("FIPS WebRTC signaling queue closed".into()))?;
        debug!(
            receiver = %receiver,
            kind = ?signal.kind,
            negotiation = %signal.negotiation_id,
            "WebRTC signal queued on FIPS session"
        );
        Ok(())
    }
}
