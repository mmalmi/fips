//! Link message dispatch and peer removal.

use crate::NodeAddr;
use crate::node::{
    AuthenticatedLinkMessage, AuthenticatedSessionDatagram, Node, PeerSessionIndexKind,
};
use tracing::{debug, info, trace};

impl Node {
    /// Dispatch a decrypted link message to the appropriate handler.
    ///
    /// Link messages are protocol messages exchanged between authenticated peers.
    pub(in crate::node) async fn dispatch_link_message(
        &mut self,
        message: AuthenticatedLinkMessage<'_>,
    ) {
        let AuthenticatedLinkMessage {
            source_peer,
            msg_type,
            payload,
            ce_flag,
        } = message;
        let source_addr = *source_peer.node_addr();

        match msg_type {
            0x00 => {
                // SessionDatagram
                self.handle_session_datagram(AuthenticatedSessionDatagram::new(
                    source_peer,
                    payload,
                    ce_flag,
                ))
                .await;
            }
            0x01 => {
                // SenderReport
                self.handle_sender_report(&source_addr, payload);
            }
            0x02 => {
                // ReceiverReport
                self.handle_receiver_report(&source_addr, payload).await;
            }
            0x10 => {
                // TreeAnnounce
                self.handle_tree_announce(&source_addr, payload).await;
            }
            0x20 => {
                // FilterAnnounce
                self.handle_filter_announce(&source_addr, payload).await;
            }
            0x30 => {
                // LookupRequest
                self.handle_lookup_request(&source_addr, payload).await;
            }
            0x31 => {
                // LookupResponse
                self.handle_lookup_response(&source_addr, payload).await;
            }
            0x50 => {
                // Disconnect
                self.handle_disconnect(&source_addr, payload);
            }
            0x51 => {
                // Heartbeat — no-op, last_recv_time already updated by record_recv()
                trace!(peer = %self.peer_display_name(&source_addr), "Received heartbeat");
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
    /// for pending tree announce (delivered within the per-peer rate limit).
    pub(in crate::node) fn remove_active_peer(&mut self, node_addr: &NodeAddr) {
        self.remove_active_peer_inner(node_addr, false);
    }

    /// Free an elective neighbor slot without resetting its end-to-end session.
    /// The remote still owns those FSP keys; ordinary route and idle-session
    /// handling govern the retained session and its bounded pending traffic.
    pub(in crate::node) fn remove_neighbor_for_rotation(&mut self, node_addr: &NodeAddr) {
        self.remove_active_peer_inner(node_addr, true);
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

        // Preserve the authenticated destination coordinate before removing
        // the dead edge from the live tree. The coordinate identifies the
        // destination in the current tree and can still route through another
        // healthy neighbor; discarding it here leaves reply-learned mode with
        // no loop-free fallback until a new discovery lookup succeeds.
        let now_ms = Self::now_ms();
        let stale_peer_coords = self.tree_state.peer_coords(node_addr).cloned();

        // The authenticated peer/session stays available for direct probes,
        // but a dead physical edge must leave the live routing graph. If the
        // stale peer remains our tree parent, its old coordinate prefix can
        // hide an otherwise healthy two-hop path and FSP payload never reaches
        // the fallback carrier. A later authenticated TreeAnnounce restores
        // the edge after direct recovery.
        let tree_changed = self.handle_peer_removal_tree_cleanup(node_addr);
        if tree_changed {
            self.mark_all_tree_announces_pending();
        }
        self.bloom_state.remove_peer_state(node_addr);
        let remaining_peers = self.peers.keys().copied().collect::<Vec<_>>();
        self.bloom_state.mark_all_updates_needed(remaining_peers);
        if let Some(coords) = stale_peer_coords {
            self.cache_current_root_coords(*node_addr, coords, now_ms);
        }

        self.mark_session_direct_path_degraded(*node_addr, now_ms);

        if !preserve_queued_packets {
            self.pending_session_traffic.remove_destination(node_addr);
        }

        info!(
            peer = %peer_name,
            link_id = %degraded.link_id,
            tree_changed,
            preserve_queued_packets,
            "Peer direct path marked stale after link-dead timeout"
        );
    }

    fn remove_active_peer_inner(&mut self, node_addr: &NodeAddr, preserve_end_to_end: bool) {
        self.forget_neighbor_reconnection(node_addr);
        let removed_peer = match self.peers.remove_with_session_indices(node_addr) {
            Some(removed) => removed,
            None => {
                debug!(peer = %self.peer_display_name(node_addr), "Peer already removed");
                return;
            }
        };
        self.mark_dataplane_direct_fsp_sources_dirty();
        let peer = removed_peer.peer;
        let link_mmp = self
            .dataplane
            .fmp_link_metrics(node_addr, std::time::Instant::now());
        self.remove_dataplane_fmp_owner(node_addr);
        self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(node_addr);

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

        // Generic removal still discards stale end-to-end state. Elective
        // rotation only removes adjacency: the remote has not reset its FSP
        // session, and the same keys can survive a route change or rejoin.
        if !preserve_end_to_end {
            let session_mmp = self.session_mmp_snapshot(node_addr);
            self.remove_dataplane_fsp_owner(node_addr);
            if self.sessions.remove(node_addr).is_some()
                && let Some(mmp) = session_mmp
            {
                Self::log_session_mmp_teardown(&peer_name, &mmp);
            }
            self.pending_session_traffic.remove_destination(node_addr);
        }

        // Promotion seeded this peer's direct-link MTU. The path is gone, so
        // release both the public clamp and its provenance before a future
        // link (possibly wider but on the same transport instance) returns.
        self.release_path_mtu(crate::FipsAddress::from_node_addr(node_addr));

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

        // Remove this link before closing its physical carrier. A shared
        // active or pending owner must retain the connection.
        if let Some(link) = self.remove_link(&link_id)
            && !self.handshake_carrier_is_owned(link.transport_id(), link.remote_addr())
            && let Some(transport) = self.transports.get(&link.transport_id())
        {
            transport.close_connection_detached(link.remote_addr());
        }
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }

        // Tree state cleanup
        let tree_changed = self.handle_peer_removal_tree_cleanup(node_addr);
        if tree_changed {
            // Mark all remaining peers for pending tree announce.
            self.mark_all_tree_announces_pending();
        }

        // Bloom filter cleanup: clear state for removed peer, mark all remaining peers
        self.bloom_state.remove_peer_state(node_addr);
        let remaining_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
        self.bloom_state.mark_all_updates_needed(remaining_peers);

        if preserve_end_to_end {
            // Rebuild after tree changes and release of the old direct MTU.
            // Retain authenticated FSP ingress, but leave application egress
            // absent when no authorized, usable carrier remains.
            self.refresh_dataplane_fsp_owner_routes(node_addr);
        }

        info!(
            peer = %self.peer_display_name(node_addr),
            link_id = %link_id,
            tree_changed = tree_changed,
            preserve_end_to_end,
            "Peer removed and state cleaned up"
        );
    }
}
