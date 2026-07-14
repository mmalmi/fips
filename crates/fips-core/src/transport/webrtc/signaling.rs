use super::WebRtcSignal;
use crate::NodeAddr;
use crate::transport::TransportError;
use nostr::prelude::PublicKey;
use tokio::sync::mpsc;
use tracing::debug;

/// A WebRTC negotiation message waiting to be carried by an authenticated
/// end-to-end FIPS session.
pub(crate) struct OutboundWebRtcSignal {
    pub(crate) recipient: NodeAddr,
    pub(crate) payload: Vec<u8>,
}

/// WebRTC has no relay client of its own. Its SDP negotiation is ordinary
/// encrypted FIPS session traffic, which also lets any bootstrap transport
/// (including the Nostr relay fallback) negotiate a better data path.
#[derive(Clone)]
pub(super) struct FipsSignalSender {
    tx: mpsc::UnboundedSender<OutboundWebRtcSignal>,
}

impl FipsSignalSender {
    pub(super) fn new(tx: mpsc::UnboundedSender<OutboundWebRtcSignal>) -> Self {
        Self { tx }
    }

    pub(super) async fn send_signal(
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
            .send(OutboundWebRtcSignal { recipient, payload })
            .map_err(|_| TransportError::SendFailed("FIPS WebRTC signaling queue closed".into()))?;
        debug!(
            receiver = %receiver,
            kind = ?signal.kind,
            session = %signal.session_id,
            "WebRTC signal queued on FIPS session"
        );
        Ok(())
    }
}
