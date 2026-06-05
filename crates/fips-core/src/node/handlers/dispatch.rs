//! Link message dispatch and peer removal.

use crate::NodeAddr;
use crate::node::Node;
use tracing::{debug, info, trace};

impl Node {
    /// Dispatch a decrypted link message to the appropriate handler.
    ///
    /// Link messages are protocol messages exchanged between authenticated peers.
    pub(in crate::node) async fn dispatch_link_message(
        &mut self,
        from: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) {
        if plaintext.is_empty() {
            return;
        }

        let msg_type = plaintext[0];
        let payload = &plaintext[1..];

        match msg_type {
            0x00 => {
                // SessionDatagram
                self.handle_session_datagram(from, payload, ce_flag).await;
            }
            0x01 => {
                // SenderReport
                self.handle_sender_report(from, payload);
            }
            0x02 => {
                // ReceiverReport
                self.handle_receiver_report(from, payload).await;
            }
            0x10 => {
                // TreeAnnounce
                self.handle_tree_announce(from, payload).await;
            }
            0x20 => {
                // FilterAnnounce
                self.handle_filter_announce(from, payload).await;
            }
            0x30 => {
                // LookupRequest
                self.handle_lookup_request(from, payload).await;
            }
            0x31 => {
                // LookupResponse
                self.handle_lookup_response(from, payload).await;
            }
            0x50 => {
                // Disconnect
                self.handle_disconnect(from, payload);
            }
            0x51 => {
                // Heartbeat — no-op, last_recv_time already updated by record_recv()
                trace!(peer = %self.peer_display_name(from), "Received heartbeat");
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
        if !self.peers.contains_key(node_addr) {
            debug!(peer = %peer_name, "Peer already removed");
            return;
        }

        self.mark_session_direct_path_degraded(*node_addr, Self::now_ms());
        let peer = self
            .peers
            .get_mut(node_addr)
            .expect("peer existence checked before link-dead degradation");

        let link_id = peer.link_id();
        peer.mark_stale();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        peer.clear_connected_udp();

        if !preserve_queued_packets {
            self.pending_tun_packets.remove(node_addr);
            self.pending_endpoint_data.remove(node_addr);
        }

        info!(
            peer = %peer_name,
            link_id = %link_id,
            preserve_queued_packets,
            "Peer direct path marked stale after link-dead timeout"
        );
    }

    fn remove_active_peer_inner(&mut self, node_addr: &NodeAddr, preserve_queued_packets: bool) {
        let peer = match self.peers.remove(node_addr) {
            Some(p) => p,
            None => {
                debug!(peer = %self.peer_display_name(node_addr), "Peer already removed");
                return;
            }
        };

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
        if let Some(mmp) = peer.mmp() {
            Self::log_mmp_teardown(&peer_name, mmp);
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
        if let Some(session_entry) = self.sessions.remove(node_addr)
            && let Some(mmp) = session_entry.mmp()
        {
            Self::log_session_mmp_teardown(&peer_name, mmp);
        }

        if !preserve_queued_packets {
            self.pending_tun_packets.remove(node_addr);
            self.pending_endpoint_data.remove(node_addr);
        }

        let link_id = peer.link_id();
        let transport_id = peer.transport_id();

        // Free session indices (current, rekey, pending, previous)
        if let Some(tid) = transport_id {
            if let Some(idx) = peer.our_index() {
                self.deregister_session_index((tid, idx.as_u32()));
                let _ = self.index_allocator.free(idx);
            }
            if let Some(idx) = peer.rekey_our_index() {
                self.pending_outbound.remove(&(tid, idx.as_u32()));
                self.deregister_session_index((tid, idx.as_u32()));
                let _ = self.index_allocator.free(idx);
            }
            if let Some(idx) = peer.pending_our_index() {
                self.deregister_session_index((tid, idx.as_u32()));
                let _ = self.index_allocator.free(idx);
            }
            if let Some(idx) = peer.previous_our_index() {
                self.deregister_session_index((tid, idx.as_u32()));
                let _ = self.index_allocator.free(idx);
            }
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
