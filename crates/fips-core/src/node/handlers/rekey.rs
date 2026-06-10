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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionRekeyMsg3Resend {
    dest_addr: NodeAddr,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExhaustedSessionRekeyMsg3 {
    dest_addr: NodeAddr,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SessionRekeyTickPlan {
    cutover: Vec<NodeAddr>,
    drain: Vec<NodeAddr>,
    initiate: Vec<NodeAddr>,
}

impl crate::node::SessionRegistry {
    fn plan_session_rekey_tick(
        &self,
        now_ms: u64,
        rekey_after_secs: u64,
        rekey_after_messages: u64,
        drain_ms: u64,
        dampening_ms: u64,
        cutover_delay_ms: u64,
    ) -> SessionRekeyTickPlan {
        let mut plan = SessionRekeyTickPlan::default();

        for (node_addr, entry) in self.iter() {
            if !entry.is_established() {
                continue;
            }

            if entry.pending_new_session().is_some()
                && !entry.has_rekey_in_progress()
                && entry.is_rekey_initiator()
                && now_ms.saturating_sub(entry.rekey_completed_ms()) >= cutover_delay_ms
            {
                plan.cutover.push(*node_addr);
                continue;
            }

            if entry.is_draining() && entry.drain_expired(now_ms, drain_ms) {
                plan.drain.push(*node_addr);
            }

            if entry.has_rekey_in_progress()
                || entry.pending_new_session().is_some()
                || entry.rekey_msg3_payload().is_some()
                || entry.is_rekey_dampened(now_ms, dampening_ms)
            {
                continue;
            }

            let elapsed_secs = now_ms.saturating_sub(entry.session_start_ms()) / 1000;
            let effective_after_secs =
                rekey_after_secs.saturating_add_signed(entry.rekey_jitter_secs());
            if elapsed_secs >= effective_after_secs || entry.send_counter() >= rekey_after_messages
            {
                plan.initiate.push(*node_addr);
            }
        }

        plan
    }

    fn cutover_due_session_rekey(
        &mut self,
        dest_addr: &NodeAddr,
        now_ms: u64,
        cutover_delay_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        if entry.pending_new_session().is_none()
            || entry.has_rekey_in_progress()
            || !entry.is_rekey_initiator()
            || now_ms.saturating_sub(entry.rekey_completed_ms()) < cutover_delay_ms
        {
            return false;
        }
        entry.cutover_to_new_session(now_ms)
    }

    fn complete_due_session_rekey_drain(
        &mut self,
        dest_addr: &NodeAddr,
        now_ms: u64,
        drain_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        if !entry.is_draining() || !entry.drain_expired(now_ms, drain_ms) {
            return false;
        }
        entry.complete_drain();
        true
    }

    fn exhaust_due_rekey_msg3_resend_budgets(
        &mut self,
        now_ms: u64,
        max_resends: u32,
    ) -> Vec<ExhaustedSessionRekeyMsg3> {
        let exhausted: Vec<NodeAddr> = self
            .iter()
            .filter(|(_, entry)| {
                entry.rekey_msg3_payload().is_some()
                    && entry.rekey_msg3_next_resend_ms() > 0
                    && now_ms >= entry.rekey_msg3_next_resend_ms()
                    && entry.rekey_msg3_resend_count() >= max_resends
            })
            .map(|(addr, _)| *addr)
            .collect();

        exhausted
            .into_iter()
            .filter_map(|dest_addr| {
                let entry = self.get_mut(&dest_addr)?;
                entry.abandon_rekey();
                Some(ExhaustedSessionRekeyMsg3 { dest_addr })
            })
            .collect()
    }

    fn due_rekey_msg3_resends(&self, now_ms: u64, max_resends: u32) -> Vec<SessionRekeyMsg3Resend> {
        self.iter()
            .filter(|(_, entry)| {
                entry.rekey_msg3_payload().is_some()
                    && entry.rekey_msg3_next_resend_ms() > 0
                    && now_ms >= entry.rekey_msg3_next_resend_ms()
                    && entry.rekey_msg3_resend_count() < max_resends
            })
            .filter_map(|(dest_addr, entry)| {
                entry
                    .rekey_msg3_payload()
                    .map(|payload| SessionRekeyMsg3Resend {
                        dest_addr: *dest_addr,
                        payload: payload.to_vec(),
                    })
            })
            .collect()
    }

    fn record_scheduled_rekey_msg3_resend(
        &mut self,
        dest_addr: &NodeAddr,
        now_ms: u64,
        interval_ms: u64,
        backoff: f64,
    ) -> Option<u32> {
        let entry = self.get_mut(dest_addr)?;
        let count = entry.rekey_msg3_resend_count() + 1;
        let next = now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
        entry.record_rekey_msg3_resend(next);
        Some(count)
    }
}

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
            // index` rather than registry removal directly so
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

        for exhausted in self
            .sessions
            .exhaust_due_rekey_msg3_resend_budgets(now_ms, max_resends)
        {
            warn!(
                peer = %self.peer_display_name(&exhausted.dest_addr),
                "FSP rekey aborted: msg3 unconfirmed after max retransmissions"
            );
        }

        for candidate in self.sessions.due_rekey_msg3_resends(now_ms, max_resends) {
            let mut datagram =
                SessionDatagram::new(my_addr, candidate.dest_addr, candidate.payload).with_ttl(ttl);
            let sent = match self.send_session_datagram(&mut datagram).await {
                Ok(_) => true,
                Err(error) => {
                    debug!(
                        peer = %self.peer_display_name(&candidate.dest_addr),
                        error = %error,
                        "FSP rekey msg3 retransmission failed"
                    );
                    false
                }
            };

            if sent
                && let Some(count) = self.sessions.record_scheduled_rekey_msg3_resend(
                    &candidate.dest_addr,
                    now_ms,
                    interval_ms,
                    backoff,
                )
            {
                trace!(
                    peer = %self.peer_display_name(&candidate.dest_addr),
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

        let plan = self.sessions.plan_session_rekey_tick(
            now_ms,
            rekey_after_secs,
            rekey_after_messages,
            drain_ms,
            dampening_ms,
            FSP_CUTOVER_DELAY_MS,
        );

        // Execute cutover for initiator side
        for node_addr in plan.cutover {
            if self
                .sessions
                .cutover_due_session_rekey(&node_addr, now_ms, FSP_CUTOVER_DELAY_MS)
            {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP rekey cutover complete (initiator), K-bit flipped"
                );
            }
        }

        // Execute drain completion
        for node_addr in plan.drain {
            if self
                .sessions
                .complete_due_session_rekey_drain(&node_addr, now_ms, drain_ms)
            {
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP drain complete, previous session erased"
                );
            }
        }

        // Initiate new rekeys
        for node_addr in plan.initiate {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseSession};
    use crate::{Identity, NodeAddr};

    fn node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_xk_session_pair(
        initiator: &Identity,
        responder: &Identity,
    ) -> (NoiseSession, NoiseSession) {
        let mut initiator_hs =
            NoiseHandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
        let mut responder_hs = NoiseHandshakeState::new_xk_responder(responder.keypair());
        initiator_hs.set_local_epoch([1u8; 8]);
        responder_hs.set_local_epoch([2u8; 8]);

        let msg1 = initiator_hs.write_xk_message_1().unwrap();
        responder_hs.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder_hs.write_xk_message_2().unwrap();
        initiator_hs.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator_hs.write_xk_message_3().unwrap();
        responder_hs.read_xk_message_3(&msg3).unwrap();

        (
            initiator_hs.into_session().unwrap(),
            responder_hs.into_session().unwrap(),
        )
    }

    fn established_entry(local: &Identity, peer: &Identity, now_ms: u64) -> SessionEntry {
        let (session, _) = make_xk_session_pair(local, peer);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(session),
            now_ms,
            true,
        );
        entry.mark_established(now_ms);
        entry
    }

    fn arm_completed_initiator_rekey(
        entry: &mut SessionEntry,
        local: &Identity,
        peer: &Identity,
        completed_ms: u64,
    ) {
        entry.set_rekey_state(
            NoiseHandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full()),
            true,
        );
        let (pending_session, _) = make_xk_session_pair(local, peer);
        entry.set_pending_session(pending_session);
        entry.set_rekey_completed_ms(completed_ms);
    }

    #[test]
    fn session_registry_owns_rekey_tick_selection() {
        let local = Identity::generate();
        let cutover_peer = Identity::generate();
        let early_cutover_peer = Identity::generate();
        let drain_peer = Identity::generate();
        let drain_and_rekey_peer = Identity::generate();
        let rekey_peer = Identity::generate();
        let under_age_peer = Identity::generate();
        let dampened_peer = Identity::generate();
        let msg3_peer = Identity::generate();

        let now_ms = 20_000_000;
        let rekey_after_secs = 10_000;
        let drain_ms = DRAIN_WINDOW_SECS * 1000;
        let dampening_ms = REKEY_DAMPENING_SECS * 1000;

        let mut cutover = established_entry(&local, &cutover_peer, 1_000);
        arm_completed_initiator_rekey(&mut cutover, &local, &cutover_peer, now_ms - 2_500);

        let mut early_cutover = established_entry(&local, &early_cutover_peer, 1_000);
        arm_completed_initiator_rekey(
            &mut early_cutover,
            &local,
            &early_cutover_peer,
            now_ms - 1_000,
        );

        let mut drain = established_entry(&local, &drain_peer, now_ms - 11_000);
        arm_completed_initiator_rekey(&mut drain, &local, &drain_peer, now_ms - 11_000);
        assert!(drain.cutover_to_new_session(now_ms - 11_000));

        let mut drain_and_rekey = established_entry(&local, &drain_and_rekey_peer, 1_000);
        arm_completed_initiator_rekey(&mut drain_and_rekey, &local, &drain_and_rekey_peer, 1_000);
        assert!(drain_and_rekey.cutover_to_new_session(1_000));

        let rekey = established_entry(&local, &rekey_peer, 1_000);
        let under_age = established_entry(&local, &under_age_peer, now_ms - 1_000);

        let mut dampened = established_entry(&local, &dampened_peer, 1_000);
        dampened.record_peer_rekey(now_ms - 1_000);

        let mut msg3 = established_entry(&local, &msg3_peer, 1_000);
        msg3.set_rekey_msg3_payload(vec![0x90], now_ms);

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*cutover_peer.node_addr(), cutover);
        sessions.insert(*early_cutover_peer.node_addr(), early_cutover);
        sessions.insert(*drain_peer.node_addr(), drain);
        sessions.insert(*drain_and_rekey_peer.node_addr(), drain_and_rekey);
        sessions.insert(*rekey_peer.node_addr(), rekey);
        sessions.insert(*under_age_peer.node_addr(), under_age);
        sessions.insert(*dampened_peer.node_addr(), dampened);
        sessions.insert(*msg3_peer.node_addr(), msg3);

        let mut plan = sessions.plan_session_rekey_tick(
            now_ms,
            rekey_after_secs,
            u64::MAX,
            drain_ms,
            dampening_ms,
            FSP_CUTOVER_DELAY_MS,
        );
        plan.cutover.sort();
        plan.drain.sort();
        plan.initiate.sort();

        let mut expected_cutover = vec![*cutover_peer.node_addr()];
        expected_cutover.sort();
        assert_eq!(plan.cutover, expected_cutover);

        let mut expected_drain = vec![*drain_peer.node_addr(), *drain_and_rekey_peer.node_addr()];
        expected_drain.sort();
        assert_eq!(plan.drain, expected_drain);

        let mut expected_initiate =
            vec![*drain_and_rekey_peer.node_addr(), *rekey_peer.node_addr()];
        expected_initiate.sort();
        assert_eq!(plan.initiate, expected_initiate);
    }

    #[test]
    fn session_registry_owns_rekey_tick_cutover_and_drain_mutation() {
        let local = Identity::generate();
        let cutover_peer = Identity::generate();
        let early_cutover_peer = Identity::generate();
        let drain_peer = Identity::generate();
        let early_drain_peer = Identity::generate();

        let now_ms = 20_000;
        let drain_ms = DRAIN_WINDOW_SECS * 1000;

        let mut cutover = established_entry(&local, &cutover_peer, 1_000);
        arm_completed_initiator_rekey(&mut cutover, &local, &cutover_peer, now_ms - 2_500);

        let mut early_cutover = established_entry(&local, &early_cutover_peer, 1_000);
        arm_completed_initiator_rekey(
            &mut early_cutover,
            &local,
            &early_cutover_peer,
            now_ms - 1_000,
        );

        let mut drain = established_entry(&local, &drain_peer, 1_000);
        arm_completed_initiator_rekey(&mut drain, &local, &drain_peer, 1_000);
        assert!(drain.cutover_to_new_session(1_000));

        let mut early_drain = established_entry(&local, &early_drain_peer, now_ms - 1_000);
        arm_completed_initiator_rekey(&mut early_drain, &local, &early_drain_peer, now_ms - 1_000);
        assert!(early_drain.cutover_to_new_session(now_ms - 1_000));

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*cutover_peer.node_addr(), cutover);
        sessions.insert(*early_cutover_peer.node_addr(), early_cutover);
        sessions.insert(*drain_peer.node_addr(), drain);
        sessions.insert(*early_drain_peer.node_addr(), early_drain);

        assert!(sessions.cutover_due_session_rekey(
            cutover_peer.node_addr(),
            now_ms,
            FSP_CUTOVER_DELAY_MS
        ));
        let cutover = sessions
            .get(cutover_peer.node_addr())
            .expect("cutover session should remain");
        assert!(cutover.pending_new_session().is_none());
        assert!(cutover.is_draining());
        assert_eq!(cutover.rekey_completed_ms(), 0);

        assert!(!sessions.cutover_due_session_rekey(
            early_cutover_peer.node_addr(),
            now_ms,
            FSP_CUTOVER_DELAY_MS
        ));
        assert!(
            sessions
                .get(early_cutover_peer.node_addr())
                .expect("early cutover session should remain")
                .pending_new_session()
                .is_some()
        );

        assert!(sessions.complete_due_session_rekey_drain(
            drain_peer.node_addr(),
            now_ms,
            drain_ms
        ));
        assert!(
            !sessions
                .get(drain_peer.node_addr())
                .expect("drained session should remain")
                .is_draining()
        );

        assert!(!sessions.complete_due_session_rekey_drain(
            early_drain_peer.node_addr(),
            now_ms,
            drain_ms
        ));
        assert!(
            sessions
                .get(early_drain_peer.node_addr())
                .expect("early drain session should remain")
                .is_draining()
        );
    }

    #[test]
    fn session_registry_owns_rekey_msg3_resend_selection_and_accounting() {
        let local = Identity::generate();
        let due_peer = Identity::generate();
        let future_peer = Identity::generate();
        let no_payload_peer = Identity::generate();

        let mut due = established_entry(&local, &due_peer, 1_000);
        due.set_rekey_msg3_payload(vec![0x30, 0x31], 1_500);

        let mut future = established_entry(&local, &future_peer, 1_000);
        future.set_rekey_msg3_payload(vec![0x40], 2_500);

        let no_payload = established_entry(&local, &no_payload_peer, 1_000);

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*due_peer.node_addr(), due);
        sessions.insert(*future_peer.node_addr(), future);
        sessions.insert(*no_payload_peer.node_addr(), no_payload);

        assert_eq!(
            sessions.due_rekey_msg3_resends(1_499, 3),
            Vec::<SessionRekeyMsg3Resend>::new()
        );
        assert_eq!(
            sessions.due_rekey_msg3_resends(1_500, 3),
            vec![SessionRekeyMsg3Resend {
                dest_addr: *due_peer.node_addr(),
                payload: vec![0x30, 0x31],
            }]
        );

        let count = sessions
            .record_scheduled_rekey_msg3_resend(due_peer.node_addr(), 1_500, 1_000, 2.0)
            .expect("due rekey msg3 session should exist");
        assert_eq!(count, 1);
        let due = sessions
            .get(due_peer.node_addr())
            .expect("due session should remain");
        assert_eq!(due.rekey_msg3_resend_count(), 1);
        assert_eq!(due.rekey_msg3_next_resend_ms(), 3_500);
        assert_eq!(due.rekey_msg3_payload(), Some(&[0x30, 0x31][..]));

        assert!(
            sessions
                .record_scheduled_rekey_msg3_resend(&node_addr(0x77), 1_500, 1_000, 2.0)
                .is_none()
        );
    }

    #[test]
    fn session_registry_owns_exhausted_rekey_msg3_cleanup() {
        let local = Identity::generate();
        let exhausted_peer = Identity::generate();
        let future_exhausted_peer = Identity::generate();
        let under_budget_peer = Identity::generate();
        let pending_peer = Identity::generate();

        let mut exhausted = established_entry(&local, &exhausted_peer, 1_000);
        exhausted.set_rekey_completed_ms(1_000);
        exhausted.set_rekey_msg3_payload(vec![0x50], 1_500);
        exhausted.record_rekey_msg3_resend(1_500);

        let mut future_exhausted = established_entry(&local, &future_exhausted_peer, 1_000);
        future_exhausted.set_rekey_msg3_payload(vec![0x60], 2_500);
        future_exhausted.record_rekey_msg3_resend(2_500);

        let mut under_budget = established_entry(&local, &under_budget_peer, 1_000);
        under_budget.set_rekey_msg3_payload(vec![0x70], 1_500);

        let (pending_session, _) = make_xk_session_pair(&local, &pending_peer);
        let mut pending = established_entry(&local, &pending_peer, 1_000);
        pending.set_pending_session(pending_session);
        pending.set_rekey_completed_ms(1_000);
        pending.set_rekey_msg3_payload(vec![0x80], 1_500);
        pending.record_rekey_msg3_resend(1_500);

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*exhausted_peer.node_addr(), exhausted);
        sessions.insert(*future_exhausted_peer.node_addr(), future_exhausted);
        sessions.insert(*under_budget_peer.node_addr(), under_budget);
        sessions.insert(*pending_peer.node_addr(), pending);

        let mut exhausted = sessions.exhaust_due_rekey_msg3_resend_budgets(1_500, 1);
        exhausted.sort_by_key(|item| item.dest_addr);
        let mut expected = vec![
            ExhaustedSessionRekeyMsg3 {
                dest_addr: *exhausted_peer.node_addr(),
            },
            ExhaustedSessionRekeyMsg3 {
                dest_addr: *pending_peer.node_addr(),
            },
        ];
        expected.sort_by_key(|item| item.dest_addr);
        assert_eq!(exhausted, expected);

        let exhausted = sessions
            .get(exhausted_peer.node_addr())
            .expect("exhausted session should remain");
        assert!(exhausted.rekey_msg3_payload().is_none());
        assert_eq!(exhausted.rekey_msg3_resend_count(), 0);
        assert_eq!(exhausted.rekey_msg3_next_resend_ms(), 0);
        assert_eq!(exhausted.rekey_completed_ms(), 0);

        let pending = sessions
            .get(pending_peer.node_addr())
            .expect("pending session should remain");
        assert!(pending.pending_new_session().is_none());
        assert!(pending.rekey_msg3_payload().is_none());
        assert_eq!(pending.rekey_completed_ms(), 0);

        let future_exhausted = sessions
            .get(future_exhausted_peer.node_addr())
            .expect("future-exhausted session should remain");
        assert_eq!(future_exhausted.rekey_msg3_payload(), Some(&[0x60][..]));
        assert_eq!(future_exhausted.rekey_msg3_resend_count(), 1);

        let under_budget = sessions
            .get(under_budget_peer.node_addr())
            .expect("under-budget session should remain");
        assert_eq!(under_budget.rekey_msg3_payload(), Some(&[0x70][..]));
        assert_eq!(under_budget.rekey_msg3_resend_count(), 0);
    }
}
