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
        // Retain preparation through any awaited rejection close. A successful
        // preflight removes it immediately before Noise installs its owner.
        // Completed DNS futures are cleared before any await; reverse order
        // keeps the remaining preparation indices stable.
        let mut i = self.pending_connects.len();
        while i > 0 {
            i -= 1;
            let pending = &self.pending_connects[i];
            if self
                .neighbor_rotation_deadline(pending.peer_identity.node_addr())
                .is_some_and(|deadline| Self::now_ms() >= deadline)
            {
                // Keep the preparation/link owned across physical close.
                self.retire_connection_preparation(pending.link_id).await;
                continue;
            }
            let pending = &mut self.pending_connects[i];
            let mut resolved_hostname = None;
            let state = if !self.transports.contains_key(&pending.transport_id) {
                crate::transport::ConnectionState::Failed("transport removed".into())
            } else if let Some(resolution) = pending.address_resolution.as_mut() {
                match resolution.as_mut().now_or_never() {
                    None => crate::transport::ConnectionState::Connecting,
                    Some(Err(error)) => {
                        pending.address_resolution = None;
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
                            .insert_addr((pending.transport_id, hostname.clone()), pending.link_id);
                        resolved_hostname = Some(hostname);
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
            let pending = &self.pending_connects[i];
            if let Some(reason) = reason {
                let link = pending.link_id;
                let peer = *pending.peer_identity.node_addr();
                warn!(
                    peer = %self.peer_display_name(&peer),
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %link,
                    %reason,
                    "Transport connect failed"
                );
                // Keep ownership until transport cleanup completes, just as
                // for a rejected ready carrier. Shared paths remain owned.
                self.retire_connection_preparation(link).await;
                self.schedule_retry(peer, Self::now_ms());
                continue;
            }
            // DNS can reveal that this preparation duplicates an existing
            // rekey. Coalesce now: replaying it after local cutover could still
            // retire the responder's keys before its first new-epoch frame.
            if resolved_hostname.is_some()
                && self.fmp_rekey_owns_path(
                    pending.peer_identity.node_addr(),
                    pending.transport_id,
                    &pending.remote_addr,
                )
            {
                let peer = self.peers.get(pending.peer_identity.node_addr()).unwrap();
                let active_link = peer.link_id();
                let current_addr = peer.current_addr().cloned();
                let pending = self.pending_connects.remove(i);
                self.remove_link(&pending.link_id);
                self.restore_link_address(active_link);
                if let Some(addr) = current_addr {
                    self.links
                        .insert_addr((pending.transport_id, addr), active_link);
                }
                if let Some(hostname) = resolved_hostname {
                    self.links
                        .insert_addr((pending.transport_id, hostname), active_link);
                }
                // Only the temporary link is gone; its active carrier stays open.
                continue;
            }
            if let Err(error) = self.preflight_connection_handshake(
                &pending.peer_identity,
                pending.transport_id,
                &pending.remote_addr,
            ) {
                let link = pending.link_id;
                let peer = *pending.peer_identity.node_addr();
                self.retire_connection_preparation(link).await;
                warn!(link_id = %link, %error, "Rejected prepared handshake before Noise allocation");
                self.schedule_retry_after_error(peer, Self::now_ms(), &error);
                continue;
            }
            let pending = self.pending_connects.remove(i);

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
                // start_handshake already retires failed Noise/link state.
                self.schedule_retry_after_error(
                    *pending.peer_identity.node_addr(),
                    Self::now_ms(),
                    &e,
                );
            }
        }
    }

    pub(in crate::node) async fn retire_connection_preparation(&mut self, link: LinkId) {
        let Some(owner) = self.links.get(&link) else {
            return;
        };
        let transport = owner.transport_id();
        let remote = owner.remote_addr().clone();
        let winner = self
            .links
            .values()
            .find(|other| {
                other.link_id() != link
                    && other.transport_id() == transport
                    && other.remote_addr() == &remote
            })
            .map(|other| other.link_id())
            .or_else(|| self.active_link_for_carrier(transport, &remote));
        self.close_cross_connection_loser_physical_path(link, winner)
            .await;
        // Physical close can yield; release both logical records only after
        // it completes, so a cancelled close remains discoverable next turn.
        self.pending_connects
            .retain(|pending| pending.link_id != link);
        self.remove_link(&link);
        if let Some(winner) = winner {
            self.restore_link_address(winner);
        }
        self.cleanup_bootstrap_transport_if_unused(transport);
    }
}
