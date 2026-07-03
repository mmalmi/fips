//! Link message dispatch and peer removal.

use crate::NodeAddr;
use crate::node::{AuthenticatedLinkMessage, Node, PeerSessionIndexKind};
use tracing::{debug, info, trace};

impl Node {
    /// Dispatch a decrypted link message to the appropriate handler.
    ///
    /// Link messages are protocol messages exchanged between authenticated peers.
    pub(in crate::node) async fn dispatch_link_message(
        &mut self,
        message: AuthenticatedLinkMessage<'_>,
    ) {
        let msg_type = message.msg_type();

        match msg_type {
            0x00 => {
                // SessionDatagram
                self.handle_session_datagram(message.into_session_datagram())
                    .await;
            }
            0x01 => {
                // SenderReport
                self.handle_sender_report(message.source_node_addr(), message.payload());
            }
            0x02 => {
                // ReceiverReport
                self.handle_receiver_report(message.source_node_addr(), message.payload())
                    .await;
            }
            0x10 => {
                // TreeAnnounce
                self.handle_tree_announce(message.source_node_addr(), message.payload())
                    .await;
            }
            0x20 => {
                // FilterAnnounce
                self.handle_filter_announce(message.source_node_addr(), message.payload())
                    .await;
            }
            0x30 => {
                // LookupRequest
                self.handle_lookup_request(message.source_node_addr(), message.payload())
                    .await;
            }
            0x31 => {
                // LookupResponse
                self.handle_lookup_response(message.source_node_addr(), message.payload())
                    .await;
            }
            0x50 => {
                // Disconnect
                self.handle_disconnect(message.source_node_addr(), message.payload());
            }
            0x51 => {
                // Heartbeat — no-op, last_recv_time already updated by record_recv()
                trace!(peer = %self.peer_display_name(message.source_node_addr()), "Received heartbeat");
            }
            _ => {
                debug!(msg_type = msg_type, "Unknown link message type");
            }
        }
    }

    /// Handle a Disconnect notification from a peer.
    ///
    /// The peer is signaling an orderly departure. We immediately remove
    /// them from all state rather than waiting for timeout detection, and
    /// schedule a reconnect if the peer is configured as auto-connect.
    /// Without this, a graceful upstream shutdown orphans auto-connect
    /// entries — other removal paths (link-dead, decrypt failure, peer
    /// restart) all schedule reconnect.
    pub(in crate::node) fn handle_disconnect(&mut self, from: &NodeAddr, payload: &[u8]) {
        let disconnect = match crate::protocol::Disconnect::decode(payload) {
            Ok(msg) => msg,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed disconnect message");
                return;
            }
        };

        info!(
            peer = %self.peer_display_name(from),
            reason = %disconnect.reason,
            "Peer sent disconnect notification"
        );

        let addr = *from;
        self.remove_active_peer(from);
        let now_ms = Self::now_ms();
        self.schedule_reconnect(addr, now_ms);
    }

    /// Remove an active peer and clean up all associated state.
    ///
    /// Frees session index, removes link and address mappings. Used for
    /// both graceful disconnect and timeout-based eviction.
    ///
    /// Also handles tree state cleanup: if the removed peer was our parent,
    /// selects an alternative or becomes root, and marks remaining peers
    /// for pending tree announce (delivered on next tick).
    pub(in crate::node) fn remove_active_peer(&mut self, node_addr: &NodeAddr) {
        self.remove_active_peer_inner(node_addr, false);
    }

    /// Degrade a dead direct path while preserving peer/session continuity.
    ///
    /// A link-dead timeout proves that one authenticated transport path has
    /// stopped producing inbound traffic. It does not prove that the remote
    /// endpoint identity is gone. Keep the authenticated FMP peer sendable so
    /// it can still be probed, let a late authenticated packet revive the
    /// path immediately, and keep the end-to-end FSP session so user traffic
    /// can move over an existing graph/fallback route without a cold
    /// re-handshake.
    pub(in crate::node) fn remove_link_dead_peer(&mut self, node_addr: &NodeAddr) {
        self.mark_link_dead_peer_inner(node_addr, true);
    }

    fn mark_link_dead_peer_inner(&mut self, node_addr: &NodeAddr, preserve_queued_packets: bool) {
        let peer_name = self.peer_display_name(node_addr);
        let degraded = match self.peers.mark_link_dead_direct_path(node_addr) {
            Some(degraded) => degraded,
            None => {
                debug!(peer = %peer_name, "Peer already removed");
                return;
            }
        };

        self.mark_session_direct_path_degraded(*node_addr, Self::now_ms());

        if !preserve_queued_packets {
            self.pending_session_traffic.remove_destination(node_addr);
        }

        info!(
            peer = %peer_name,
            link_id = %degraded.link_id,
            preserve_queued_packets,
            "Peer direct path marked stale after link-dead timeout"
        );
    }

    fn remove_active_peer_inner(&mut self, node_addr: &NodeAddr, preserve_queued_packets: bool) {
        let removed_peer = match self.peers.remove_with_session_indices(node_addr) {
            Some(removed) => removed,
            None => {
                debug!(peer = %self.peer_display_name(node_addr), "Peer already removed");
                return;
            }
        };
        let peer = removed_peer.peer;
        let link_mmp = self
            .dataplane
            .fmp_link_metrics(node_addr, std::time::Instant::now());
        self.remove_dataplane_fmp_owner(node_addr);

        // Log suppressed replay detection summary before teardown
        let suppressed = peer.replay_suppressed_count();
        if suppressed > 0 {
            debug!(
                peer = %self.peer_display_name(node_addr),
                count = suppressed,
                "Suppressed replay detections during link transition"
            );
        }

        // MMP teardown log (before we drop the peer)
        let peer_name = self
            .peer_aliases
            .get(node_addr)
            .cloned()
            .unwrap_or_else(|| peer.identity().short_npub());
        if let Some(mmp) = link_mmp {
            Self::log_mmp_teardown(&peer_name, &mmp);
        }

        // Remove any end-to-end session associated with this peer.
        //
        // Sessions are tracked separately from peers (self.sessions vs
        // self.peers). Leaving a stale session alive after link removal causes:
        //   1. check_session_mmp_reports() keeps logging stale
        //      "MMP session metrics" with frozen counters until
        //      purge_idle_sessions() eventually fires.
        //   2. initiate_session() finds is_established() == true on the stale
        //      entry and silently returns Ok(()), preventing a new session over
        //      fallback or a recovered direct link.
        let session_mmp = self.session_mmp_snapshot(node_addr);
        self.remove_dataplane_fsp_owner(node_addr);
        if self.sessions.remove(node_addr).is_some()
            && let Some(mmp) = session_mmp
        {
            Self::log_session_mmp_teardown(&peer_name, &mmp);
        }

        if !preserve_queued_packets {
            self.pending_session_traffic.remove_destination(node_addr);
        }

        let link_id = peer.link_id();
        let transport_id = peer.transport_id();

        // Free session indices (current, rekey, pending, previous)
        for session_index in removed_peer.session_indices {
            if session_index.kind == PeerSessionIndexKind::Rekey {
                self.pending_outbound.remove(&session_index.key);
            }
            self.deregister_session_index(session_index.key);
            let _ = self.index_allocator.free(session_index.index);
        }

        // Remove link and address mapping
        self.remove_link(&link_id);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }

        // Tree state cleanup
        let tree_changed = self.handle_peer_removal_tree_cleanup(node_addr);
        if tree_changed {
            // Mark all remaining peers for pending tree announce.
            // These will be sent on the next tick via check_tree_state().
            for peer in self.peers.values_mut() {
                peer.mark_tree_announce_pending();
            }
        }

        // Bloom filter cleanup: clear state for removed peer, mark all remaining peers
        self.bloom_state.remove_peer_state(node_addr);
        let remaining_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
        self.bloom_state.mark_all_updates_needed(remaining_peers);

        info!(
            peer = %self.peer_display_name(node_addr),
            link_id = %link_id,
            tree_changed = tree_changed,
            preserve_queued_packets,
            "Peer removed and state cleaned up"
        );
    }
}
