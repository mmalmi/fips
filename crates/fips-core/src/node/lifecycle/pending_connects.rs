use super::*;
use futures::FutureExt;

impl Node {
    /// Poll pending transport connects and initiate handshakes for ready ones.
    ///
    /// Called from the tick handler. For each pending connect, queries the
    /// transport's connection state. When a connection is established,
    /// marks the link as Connected and starts the Noise handshake.
    /// Failed connections are cleaned up and scheduled for retry.
    pub(in crate::node) async fn poll_pending_connects(&mut self) {
        // Remove each completed preparation before awaiting its handshake.
        // Cancellation must not leave an already-completed DNS future to poll
        // again next tick. Reverse order keeps remaining indices stable.
        let mut i = self.pending_connects.len();
        while i > 0 {
            i -= 1;
            let pending = &mut self.pending_connects[i];
            let state = if !self.transports.contains_key(&pending.transport_id) {
                crate::transport::ConnectionState::Failed("transport removed".into())
            } else if let Some(resolution) = pending.address_resolution.as_mut() {
                match resolution.as_mut().now_or_never() {
                    None => crate::transport::ConnectionState::Connecting,
                    Some(Err(error)) => {
                        crate::transport::ConnectionState::Failed(error.to_string())
                    }
                    Some(Ok(addr)) => {
                        let hostname = std::mem::replace(&mut pending.remote_addr, addr);
                        pending.address_resolution = None;
                        self.links.insert(
                            pending.link_id,
                            Link::connectionless(
                                pending.link_id,
                                pending.transport_id,
                                pending.remote_addr.clone(),
                                LinkDirection::Outbound,
                                Duration::from_millis(self.config.node.base_rtt_ms),
                            ),
                        );
                        // Keep configured hostname matching until this link is
                        // removed, while all Noise sends use its numeric path.
                        self.links
                            .insert_addr((pending.transport_id, hostname), pending.link_id);
                        crate::transport::ConnectionState::Connected
                    }
                }
            } else if let Some(transport) = self.transports.get(&pending.transport_id) {
                transport.connection_state(&pending.remote_addr)
            } else {
                crate::transport::ConnectionState::Failed("transport removed".into())
            };

            let reason = match state {
                crate::transport::ConnectionState::Connected => None,
                crate::transport::ConnectionState::Failed(reason) => Some(reason),
                crate::transport::ConnectionState::Connecting => continue,
                crate::transport::ConnectionState::None => {
                    Some("no connection attempt found".into())
                }
            };
            let pending = self.pending_connects.remove(i);

            if reason.is_none() {
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
                    self.schedule_retry_after_error(
                        *pending.peer_identity.node_addr(),
                        Self::now_ms(),
                        &e,
                    );
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
                self.schedule_retry(*pending.peer_identity.node_addr(), Self::now_ms());
            }
        }
    }
}
