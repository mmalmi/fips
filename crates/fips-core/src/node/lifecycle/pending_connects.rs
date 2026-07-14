use super::*;

impl Node {
    /// Poll pending transport connects and initiate handshakes for ready ones.
    ///
    /// Called from the tick handler. For each pending connect, queries the
    /// transport's connection state. When a connection is established,
    /// marks the link as Connected and starts the Noise handshake.
    /// Failed connections are cleaned up and scheduled for retry.
    pub(in crate::node) async fn poll_pending_connects(&mut self) {
        if self.pending_connects.is_empty() {
            return;
        }

        let mut completed = Vec::new();

        for (i, pending) in self.pending_connects.iter().enumerate() {
            let state = if let Some(transport) = self.transports.get(&pending.transport_id) {
                transport.connection_state(&pending.remote_addr)
            } else {
                crate::transport::ConnectionState::Failed("transport removed".into())
            };

            match state {
                crate::transport::ConnectionState::Connected => {
                    completed.push((i, true, None));
                }
                crate::transport::ConnectionState::Failed(reason) => {
                    completed.push((i, false, Some(reason)));
                }
                crate::transport::ConnectionState::Connecting => {
                    // Still in progress, check on next tick
                }
                crate::transport::ConnectionState::None => {
                    // Shouldn't happen — treat as failure
                    completed.push((i, false, Some("no connection attempt found".into())));
                }
            }
        }

        // Process completions in reverse order to preserve indices
        for (i, success, reason) in completed.into_iter().rev() {
            let pending = self.pending_connects.remove(i);

            if success {
                // Mark link as Connected
                if let Some(link) = self.links.get_mut(&pending.link_id) {
                    link.set_connected();
                }

                debug!(
                    peer = %self.peer_display_name(pending.peer_identity.node_addr()),
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %pending.link_id,
                    "Transport connected, starting handshake"
                );

                // Start the handshake now that the transport is connected
                if let Err(e) = self
                    .start_handshake(
                        pending.link_id,
                        pending.transport_id,
                        pending.remote_addr.clone(),
                        pending.peer_identity,
                    )
                    .await
                {
                    warn!(
                        link_id = %pending.link_id,
                        error = %e,
                        "Failed to start handshake after transport connect"
                    );
                    // Clean up link on handshake failure
                    self.remove_link(&pending.link_id);
                }
            } else {
                let reason = reason.unwrap_or_default();
                warn!(
                    peer = %self.peer_display_name(pending.peer_identity.node_addr()),
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %pending.link_id,
                    reason = %reason,
                    "Transport connect failed"
                );

                // Clean up link and schedule retry
                self.remove_link(&pending.link_id);
                self.links.remove(&pending.link_id);
                self.schedule_retry(*pending.peer_identity.node_addr(), Self::now_ms());
            }
        }
    }
}
