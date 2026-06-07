//! Periodic rekey (key rotation) for FMP link sessions.
//!
//! Checks all active peers on each tick for:
//! 1. Rekey trigger (time elapsed or send counter exceeded)
//! 2. Drain window expiry (clean up previous session after cutover)
//! 3. Initiator-side cutover (first send after handshake completion)

use crate::NodeAddr;
use crate::node::Node;
use crate::node::wire::build_msg1;
use crate::noise::HandshakeState;
use crate::protocol::{SessionDatagram, SessionSetup};
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Keep previous session alive for this long after cutover.
const DRAIN_WINDOW_SECS: u64 = 10;

/// Suppress local rekey initiation for this long after receiving
/// a peer's rekey msg1.
const REKEY_DAMPENING_SECS: u64 = 30;

/// Delay FMP initiator cutover after receiving msg2. The responder keeps the
/// pending session until it authenticates the peer's K-bit flip.
const FMP_CUTOVER_DELAY_MS: u64 = 250;

/// Delay FSP initiator cutover after handshake completion to allow
/// XK msg3 to reach the responder before K-bit-flipped data arrives.
const FSP_CUTOVER_DELAY_MS: u64 = 2000;

impl Node {
    /// Periodic rekey check. Called from the tick loop.
    ///
    /// For each active peer with a session:
    /// - If the initiator has a pending session, perform K-bit cutover
    /// - If the drain window has expired, clean up the previous session
    /// - If the rekey timer/counter fires, initiate a new handshake
    pub(in crate::node) async fn check_rekey(&mut self) {
        if !self.config.node.rekey.enabled {
            return;
        }

        let rekey_after_secs = self.config.node.rekey.after_secs;
        let rekey_after_messages = self.config.node.rekey.after_messages;

        // Collect peers that need action (to avoid borrow conflicts)
        let mut peers_to_cutover: Vec<NodeAddr> = Vec::new();
        let mut peers_to_drain: Vec<NodeAddr> = Vec::new();
        let mut peers_to_rekey: Vec<NodeAddr> = Vec::new();

        for (node_addr, peer) in &self.peers {
            if !peer.has_session() || !peer.is_healthy() {
                continue;
            }

            // 1. Initiator-side cutover: we completed a rekey and have a
            //    pending session ready. Responders wait for the peer's K-bit.
            if peer.pending_new_session().is_some()
                && !peer.rekey_in_progress()
                && peer.pending_rekey_cutover_due(Duration::from_millis(FMP_CUTOVER_DELAY_MS))
            {
                peers_to_cutover.push(*node_addr);
                continue;
            }

            // 2. Drain window expiry
            if peer.is_draining() && peer.drain_expired(DRAIN_WINDOW_SECS) {
                peers_to_drain.push(*node_addr);
            }

            // 3. Rekey trigger
            if peer.rekey_in_progress() {
                continue;
            }
            if peer.is_rekey_dampened(REKEY_DAMPENING_SECS) {
                continue;
            }

            let elapsed = peer.session_established_at().elapsed().as_secs();
            let counter = peer
                .noise_session()
                .map(|s| s.current_send_counter())
                .unwrap_or(0);

            let effective_after_secs =
                rekey_after_secs.saturating_add_signed(peer.rekey_jitter_secs());
            if elapsed >= effective_after_secs || counter >= rekey_after_messages {
                peers_to_rekey.push(*node_addr);
            }
        }

        // Execute cutover for initiator side
        for node_addr in peers_to_cutover {
            let did_cutover = {
                if let Some(peer) = self.peers.get_mut(&node_addr)
                    && let Some(_old_our_index) = peer.cutover_to_new_session()
                {
                    debug!(
                        peer = %self.peer_display_name(&node_addr),
                        "Rekey cutover complete (initiator), K-bit flipped"
                    );
                    true
                } else {
                    false
                }
            };
            // Re-register the (now-current) FMP session with the
            // decrypt worker shard. Without this, the worker's
            // owned cipher + replay state stays pinned to the
            // pre-rekey session and post-cutover packets miss the
            // worker entirely. See the matching comment in
            // `handle_encrypted_frame`'s K-bit-flip branch.
            if did_cutover {
                self.ensure_current_session_index_registered(&node_addr, "initiator rekey cutover");
                self.register_decrypt_worker_session(&node_addr);
            }
        }

        // Execute drain completion
        for node_addr in peers_to_drain {
            let drained = if let Some(peer) = self.peers.get_mut(&node_addr)
                && let Some(old_our_index) = peer.complete_drain()
            {
                let transport_id = peer.transport_id();
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    old_index = %old_our_index,
                    "Drain complete, previous session erased"
                );
                Some((transport_id, old_our_index))
            } else {
                None
            };
            // Drop the old session index through `deregister_session_
            // index` rather than `peers_by_index.remove` directly so
            // the decrypt worker also evicts the old session's owned
            // cipher + replay state. Pre-fix the worker held onto
            // the old entry forever, wasting a HashMap slot per
            // rekey for the peer's lifetime.
            if let Some((Some(transport_id), old_our_index)) = drained {
                self.deregister_session_index((transport_id, old_our_index.as_u32()));
                let _ = self.index_allocator.free(old_our_index);
            }
        }

        // Initiate new rekeys
        for node_addr in peers_to_rekey {
            let _ = self.initiate_rekey(&node_addr).await;
        }
    }

    /// Initiate an outbound rekey to a peer.
    ///
    /// Creates a new IK handshake as initiator, sends msg1 over the existing
    /// link (same transport, same remote address), and stores the handshake
    /// state on the ActivePeer. No new Link or PeerConnection is created.
    pub(in crate::node) async fn initiate_rekey(&mut self, node_addr: &NodeAddr) -> bool {
        let peer = match self.peers.get(node_addr) {
            Some(p) => p,
            None => return false,
        };

        let transport_id = match peer.transport_id() {
            Some(t) => t,
            None => return false,
        };
        let remote_addr = match peer.current_addr() {
            Some(a) => a.clone(),
            None => return false,
        };
        let link_id = peer.link_id();
        let peer_pubkey = peer.identity().pubkey_full();

        // Allocate a new session index for the rekey
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to allocate index for rekey"
                );
                return false;
            }
        };

        // Create IK initiator handshake directly (no PeerConnection)
        let our_keypair = self.identity.keypair();
        let mut hs = HandshakeState::new_initiator(our_keypair, peer_pubkey);
        hs.set_local_epoch(self.startup_epoch);

        let noise_msg1 = match hs.write_message_1() {
            Ok(msg) => msg,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to generate rekey msg1"
                );
                let _ = self.index_allocator.free(our_index);
                return false;
            }
        };

        let wire_msg1 = build_msg1(our_index, &noise_msg1);

        // Send msg1 on the existing link (same transport + address)
        let Some(transport) = self.transports.get(&transport_id) else {
            let _ = self.index_allocator.free(our_index);
            return false;
        };
        match transport.send(&remote_addr, &wire_msg1).await {
            Ok(_) => {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    our_index = %our_index,
                    "Rekey initiated, sent msg1 on existing link"
                );
            }
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to send rekey msg1"
                );
                let _ = self.index_allocator.free(our_index);
                return false;
            }
        }

        // Store handshake state on the ActivePeer (not a separate PeerConnection)
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let now_ms = Self::now_ms();
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.set_rekey_state(hs, our_index, wire_msg1, now_ms + resend_interval);
        } else {
            let _ = self.index_allocator.free(our_index);
            return false;
        }

        // Register in pending_outbound for msg2 dispatch (maps to existing link)
        self.pending_outbound
            .insert((transport_id, our_index.as_u32()), link_id);
        true
    }

    /// Resend pending rekey msg1s and abandon timed-out rekeys.
    ///
    /// Called from the tick loop. Uses the same resend interval and max
    /// resend count as initial handshakes.
    pub(in crate::node) async fn resend_pending_rekeys(&mut self, now_ms: u64) {
        if !self.config.node.rekey.enabled {
            return;
        }

        let interval_ms = self.config.node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config.node.rate_limit.handshake_resend_backoff;
        let max_resends = self.config.node.rate_limit.handshake_max_resends;

        // Collect peers needing action
        let mut to_resend: Vec<(NodeAddr, Vec<u8>)> = Vec::new();
        let mut to_abandon: Vec<NodeAddr> = Vec::new();

        for (node_addr, peer) in &self.peers {
            if !peer.rekey_in_progress() || peer.rekey_msg1().is_none() {
                continue;
            }
            if peer.rekey_msg1_resend_count() >= max_resends {
                to_abandon.push(*node_addr);
                continue;
            }
            if peer.needs_msg1_resend(now_ms) {
                to_resend.push((*node_addr, peer.rekey_msg1().unwrap().to_vec()));
            }
        }

        for node_addr in to_abandon {
            let abandoned = if let Some(peer) = self.peers.get_mut(&node_addr) {
                let transport_id = peer.transport_id();
                peer.abandon_rekey().map(|idx| (transport_id, idx))
            } else {
                None
            };
            if let Some((transport_id, idx)) = abandoned {
                if let Some(tid) = transport_id {
                    self.pending_outbound.remove(&(tid, idx.as_u32()));
                    self.deregister_session_index((tid, idx.as_u32()));
                }
                let _ = self.index_allocator.free(idx);
            }
            warn!(
                peer = %self.peer_display_name(&node_addr),
                "FMP rekey aborted: msg1 unconfirmed after max retransmissions"
            );
        }

        for (node_addr, msg1_bytes) in to_resend {
            let (transport_id, remote_addr) = match self.peers.get(&node_addr) {
                Some(p) => match (p.transport_id(), p.current_addr()) {
                    (Some(tid), Some(addr)) => (tid, addr.clone()),
                    _ => continue,
                },
                None => continue,
            };

            let sent = if let Some(transport) = self.transports.get(&transport_id) {
                transport.send(&remote_addr, &msg1_bytes).await.is_ok()
            } else {
                false
            };

            if sent && let Some(peer) = self.peers.get_mut(&node_addr) {
                let count = peer.rekey_msg1_resend_count() + 1;
                let next = now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
                peer.record_rekey_msg1_resend(next);
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    resend = count,
                    "Resent rekey msg1"
                );
            }
        }
    }

    /// Retransmit FSP rekey msg3 until the responder is confirmed on the new epoch.
    pub(in crate::node) async fn resend_pending_session_msg3(&mut self, now_ms: u64) {
        if !self.config.node.rekey.enabled || self.sessions.is_empty() {
            return;
        }

        let interval_ms = self.config.node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config.node.rate_limit.handshake_resend_backoff;
        let max_resends = self.config.node.rate_limit.handshake_max_resends;
        let ttl = self.config.node.session.default_ttl;
        let my_addr = *self.node_addr();

        let mut to_resend: Vec<(NodeAddr, Vec<u8>)> = Vec::new();
        let mut to_abandon: Vec<NodeAddr> = Vec::new();

        for (node_addr, entry) in &self.sessions {
            let payload = match entry.rekey_msg3_payload() {
                Some(payload) => payload,
                None => continue,
            };
            if entry.rekey_msg3_next_resend_ms() == 0 || now_ms < entry.rekey_msg3_next_resend_ms()
            {
                continue;
            }
            if entry.rekey_msg3_resend_count() >= max_resends {
                to_abandon.push(*node_addr);
                continue;
            }
            to_resend.push((*node_addr, payload.to_vec()));
        }

        for node_addr in to_abandon {
            if let Some(entry) = self.sessions.get_mut(&node_addr) {
                entry.abandon_rekey();
            }
            warn!(
                peer = %self.peer_display_name(&node_addr),
                "FSP rekey aborted: msg3 unconfirmed after max retransmissions"
            );
        }

        for (node_addr, payload) in to_resend {
            let mut datagram = SessionDatagram::new(my_addr, node_addr, payload).with_ttl(ttl);
            let sent = match self.send_session_datagram(&mut datagram).await {
                Ok(_) => true,
                Err(error) => {
                    debug!(
                        peer = %self.peer_display_name(&node_addr),
                        error = %error,
                        "FSP rekey msg3 retransmission failed"
                    );
                    false
                }
            };

            if sent && let Some(entry) = self.sessions.get_mut(&node_addr) {
                let count = entry.rekey_msg3_resend_count() + 1;
                let next = now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
                entry.record_rekey_msg3_resend(next);
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    resend = count,
                    "Resent FSP rekey msg3"
                );
            }
        }
    }

    /// Periodic session (FSP) rekey check. Called from the tick loop.
    ///
    /// For each established session:
    /// - If the initiator has a pending session past the liveness timer,
    ///   perform K-bit cutover
    /// - If the drain window has expired, clean up the previous session
    /// - If the rekey timer/counter fires, initiate a new XK handshake
    pub(in crate::node) async fn check_session_rekey(&mut self) {
        if !self.config.node.rekey.enabled {
            return;
        }

        let rekey_after_secs = self.config.node.rekey.after_secs;
        let rekey_after_messages = self.config.node.rekey.after_messages;
        let now_ms = Self::now_ms();
        let drain_ms = DRAIN_WINDOW_SECS * 1000;
        let dampening_ms = REKEY_DAMPENING_SECS * 1000;

        let mut sessions_to_cutover: Vec<NodeAddr> = Vec::new();
        let mut sessions_to_drain: Vec<NodeAddr> = Vec::new();
        let mut sessions_to_rekey: Vec<NodeAddr> = Vec::new();

        for (node_addr, entry) in &self.sessions {
            if !entry.is_established() {
                continue;
            }

            // 1. Initiator-side cutover: completed rekey, pending session ready.
            //    Defer cutover until msg3 has had time to reach the responder.
            //    Without this delay, K-bit-flipped data can arrive before
            //    msg3, causing decryption failures on the responder.
            if entry.pending_new_session().is_some()
                && !entry.has_rekey_in_progress()
                && entry.is_rekey_initiator()
                && now_ms.saturating_sub(entry.rekey_completed_ms()) >= FSP_CUTOVER_DELAY_MS
            {
                sessions_to_cutover.push(*node_addr);
                continue;
            }

            // 2. Drain window expiry
            if entry.is_draining() && entry.drain_expired(now_ms, drain_ms) {
                sessions_to_drain.push(*node_addr);
            }

            // 3. Rekey trigger
            if entry.has_rekey_in_progress() {
                continue;
            }
            if entry.pending_new_session().is_some() {
                continue; // Pending session present, awaiting cutover
            }
            if entry.rekey_msg3_payload().is_some() {
                continue; // Current rekey still awaits peer confirmation.
            }
            if entry.is_rekey_dampened(now_ms, dampening_ms) {
                continue;
            }

            let elapsed_secs = now_ms.saturating_sub(entry.session_start_ms()) / 1000;
            let counter = entry.send_counter();

            let effective_after_secs =
                rekey_after_secs.saturating_add_signed(entry.rekey_jitter_secs());
            if elapsed_secs >= effective_after_secs || counter >= rekey_after_messages {
                sessions_to_rekey.push(*node_addr);
            }
        }

        // Execute cutover for initiator side
        for node_addr in sessions_to_cutover {
            if let Some(entry) = self.sessions.get_mut(&node_addr)
                && entry.cutover_to_new_session(now_ms)
            {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP rekey cutover complete (initiator), K-bit flipped"
                );
            }
        }

        // Execute drain completion
        for node_addr in sessions_to_drain {
            if let Some(entry) = self.sessions.get_mut(&node_addr) {
                entry.complete_drain();
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP drain complete, previous session erased"
                );
            }
        }

        // Initiate new rekeys
        for node_addr in sessions_to_rekey {
            let _ = self.initiate_session_rekey(&node_addr).await;
        }
    }

    /// Initiate an FSP session rekey.
    ///
    /// Creates a new XK handshake as initiator, sends SessionSetup msg1
    /// through the mesh, and stores the handshake state on the existing entry.
    pub(in crate::node) async fn initiate_session_rekey(&mut self, dest_addr: &NodeAddr) -> bool {
        // Check route availability before paying crypto cost
        if self.find_next_hop(dest_addr).is_none() {
            trace!(
                peer = %self.peer_display_name(dest_addr),
                "FSP rekey skipped: no route to destination"
            );
            return false;
        }

        let entry = match self.sessions.get(dest_addr) {
            Some(e) => e,
            None => return false,
        };
        if !entry.is_established() {
            trace!(
                peer = %self.peer_display_name(dest_addr),
                "FSP rekey skipped: session is not established"
            );
            return false;
        }
        if entry.has_rekey_in_progress() || entry.pending_new_session().is_some() {
            trace!(
                peer = %self.peer_display_name(dest_addr),
                "FSP rekey skipped: rekey already in progress"
            );
            return false;
        }
        let dest_pubkey = *entry.remote_pubkey();

        // Create Noise XK initiator handshake
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_initiator(our_keypair, dest_pubkey);
        handshake.set_local_epoch(self.startup_epoch);

        let msg1 = match handshake.write_xk_message_1() {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(dest_addr),
                    error = %e,
                    "Failed to generate FSP rekey XK msg1"
                );
                return false;
            }
        };

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
        let setup_payload = setup.encode();

        // Send through the mesh
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, setup_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(
                peer = %self.peer_display_name(dest_addr),
                error = %e,
                "Failed to send FSP rekey SessionSetup"
            );
            return false;
        }

        // Store rekey state on the existing session entry
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.set_rekey_state(handshake, true);
            let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
            entry.set_handshake_payload(setup_payload, Self::now_ms() + resend_interval);
            entry.reset_decrypt_failures();
        } else {
            return false;
        }

        debug!(
            peer = %self.peer_display_name(dest_addr),
            "FSP rekey initiated, sent SessionSetup"
        );
        true
    }
}
