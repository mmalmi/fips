use tokio::sync::{mpsc, oneshot};

use super::{ENDPOINT_OPERATION_TIMEOUT, FipsEndpointError};
use crate::node::NodeEndpointControlCommand;

/// Application-side control handle for a [`crate::Node`]'s Nostr relay
/// transport.
///
/// This lets the standalone daemon or another direct `Node` embedder bridge
/// relay events without moving relay URLs or relay connections into
/// `fips-core`.
#[derive(Clone)]
pub struct NostrRelayIo {
    npub: String,
    control_tx: mpsc::Sender<NodeEndpointControlCommand>,
}

impl NostrRelayIo {
    pub(crate) fn new(npub: String, control_tx: mpsc::Sender<NodeEndpointControlCommand>) -> Self {
        Self { npub, control_tx }
    }

    /// Local FIPS identity used as the relay event recipient.
    pub fn npub(&self) -> &str {
        &self.npub
    }

    async fn control<T>(
        &self,
        operation: &'static str,
        command: NodeEndpointControlCommand,
        response_rx: oneshot::Receiver<T>,
    ) -> Result<T, FipsEndpointError> {
        tokio::time::timeout(ENDPOINT_OPERATION_TIMEOUT, async {
            self.control_tx
                .send(command)
                .await
                .map_err(|_| FipsEndpointError::Closed)?;
            response_rx.await.map_err(|_| FipsEndpointError::Closed)
        })
        .await
        .map_err(|_| FipsEndpointError::Timeout { operation })?
    }

    /// Feed one externally received relay event into the transport.
    pub async fn ingest_event(&self, event: nostr::Event) -> Result<bool, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "Nostr relay event ingest",
            NodeEndpointControlCommand::IngestNostrEvent { event, response_tx },
            response_rx,
        )
        .await
    }

    /// Drain signed relay events for publication by the embedding application.
    pub async fn drain_events(&self, limit: usize) -> Result<Vec<nostr::Event>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "Nostr relay event drain",
            NodeEndpointControlCommand::DrainNostrRelayEvents {
                limit: limit.max(1),
                response_tx,
            },
            response_rx,
        )
        .await
    }
}
