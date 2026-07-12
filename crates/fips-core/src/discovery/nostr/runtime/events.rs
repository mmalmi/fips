use super::*;

impl NostrDiscovery {
    pub async fn drain_events(&self) -> Vec<BootstrapEvent> {
        let mut out = Vec::new();
        let mut rx = self.event_rx.lock().await;
        while let Ok(event) = rx.try_recv() {
            out.push(event);
        }
        out
    }

    pub(crate) async fn drain_mesh_signals(&self) -> Vec<MeshTraversalSignal> {
        let mut out = Vec::new();
        let mut rx = self.mesh_signal_rx.lock().await;
        while let Ok(signal) = rx.try_recv() {
            out.push(signal);
        }
        out
    }

    pub(super) async fn emit_event(&self, event: BootstrapEvent) {
        let (kind, peer_npub) = match &event {
            BootstrapEvent::Established { traversal } => {
                ("established", traversal.peer_npub.clone())
            }
            BootstrapEvent::Failed { peer_config, .. } => ("failed", peer_config.npub.clone()),
        };
        if self.event_tx.send(event).await.is_err() {
            debug!(
                kind,
                peer = %short_npub(&peer_npub),
                "dropping Nostr traversal event because node event receiver is closed"
            );
        }
    }

    pub(super) async fn emit_mesh_signal(&self, signal: MeshTraversalSignal) -> bool {
        let (kind, peer_npub) = match &signal {
            MeshTraversalSignal::Offer { peer_npub, .. } => ("offer", peer_npub.clone()),
            MeshTraversalSignal::Answer { peer_npub, .. } => ("answer", peer_npub.clone()),
        };
        if self.mesh_signal_tx.send(signal).await.is_err() {
            debug!(
                kind,
                peer = %short_npub(&peer_npub),
                "dropping mesh traversal signal because node signal channel is closed"
            );
            return false;
        }
        true
    }
}
