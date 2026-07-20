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

    pub(crate) async fn drain_external_signal_events(&self) -> Vec<Event> {
        let mut out = Vec::new();
        let mut rx = self.external_signal_rx.lock().await;
        while let Ok(event) = rx.try_recv() {
            out.push(event);
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

    pub(super) async fn emit_traversal_signal(&self, signal: MeshTraversalSignal) -> bool {
        let (kind, peer_npub) = match &signal {
            MeshTraversalSignal::Offer { peer_npub, .. } => ("offer", peer_npub.clone()),
            MeshTraversalSignal::Answer { peer_npub, .. } => ("answer", peer_npub.clone()),
        };
        if self.config.peerfinding_source == crate::config::NostrPeerfindingSource::External {
            let receiver = match PublicKey::parse(&peer_npub) {
                Ok(receiver) => receiver,
                Err(error) => {
                    debug!(kind, peer = %short_npub(&peer_npub), %error, "cannot encrypt traversal signal for invalid peer identity");
                    return false;
                }
            };
            let payload = match &signal {
                MeshTraversalSignal::Offer { offer, .. } => serde_json::to_string(offer),
                MeshTraversalSignal::Answer { answer, .. } => serde_json::to_string(answer),
            };
            let payload = match payload {
                Ok(payload) => payload,
                Err(error) => {
                    debug!(kind, peer = %short_npub(&peer_npub), %error, "cannot encode traversal signal");
                    return false;
                }
            };
            let rumor = EventBuilder::private_msg_rumor(receiver, payload).build(self.pubkey);
            let expiration = Timestamp::from(
                (now_ms().saturating_add(self.config.signal_ttl_secs.saturating_mul(1_000)))
                    / 1_000,
            );
            let event = match build_signal_event(&self.keys, receiver, rumor, expiration).await {
                Ok(event) => event,
                Err(error) => {
                    debug!(kind, peer = %short_npub(&peer_npub), %error, "cannot encrypt traversal signal");
                    return false;
                }
            };
            if self.external_signal_tx.send(event).await.is_err() {
                debug!(kind, peer = %short_npub(&peer_npub), "dropping external traversal signal because provider channel is closed");
                return false;
            }
            return true;
        }
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
