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
use crate::protocol::{SessionDatagram, SessionFlags, SessionSetup};
use secp256k1::PublicKey;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Keep the post-cutover stale-epoch FMP drain window open for this long.
const FMP_DRAIN_WINDOW_SECS: u64 = 10;

/// Keep the post-cutover stale-epoch FSP drain window open long enough for
/// delayed direct-lane packet bursts to clear after explicit rekey tests.
const FSP_DRAIN_WINDOW_SECS: u64 = 45;

/// Suppress local rekey initiation for this long after receiving
/// a peer's rekey msg1.
const REKEY_DAMPENING_SECS: u64 = 30;

/// Delay FMP initiator cutover after receiving msg2. The responder keeps the
/// pending session until it authenticates the peer's K-bit flip.
const FMP_CUTOVER_DELAY_MS: u64 = 250;

/// Delay FSP initiator cutover after handshake completion to allow the initial
/// XK msg3 plus the exponential resend burst to reach the responder before
/// K-bit-flipped data arrives.
const FSP_CUTOVER_DELAY_MS: u64 = 35_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionRekeyMsg3Resend {
    dest_addr: NodeAddr,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExhaustedSessionRekeyMsg3 {
    dest_addr: NodeAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FmpRekeyMsg1Resend {
    node_addr: NodeAddr,
    transport_id: crate::transport::TransportId,
    remote_addr: crate::transport::TransportAddr,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FmpRekeyIndexCleanup {
    transport_id: Option<crate::transport::TransportId>,
    rekey_our_index: crate::utils::index::SessionIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExhaustedFmpRekeyMsg1 {
    node_addr: NodeAddr,
    cleanup: Option<FmpRekeyIndexCleanup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FmpRekeyInitiation {
    transport_id: crate::transport::TransportId,
    remote_addr: crate::transport::TransportAddr,
    link_id: crate::transport::LinkId,
    peer_pubkey: PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FmpRekeyInitiationSkip {
    Peer,
    Transport,
    Address,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SessionRekeyTickPlan {
    cutover: Vec<NodeAddr>,
    drain: Vec<NodeAddr>,
    initiate: Vec<NodeAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionRekeyTickConfig {
    now_ms: u64,
    rekey_after_secs: u64,
    rekey_after_messages: u64,
    drain_ms: u64,
    dampening_ms: u64,
    cutover_delay_ms: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FmpRekeyTickPlan {
    cutover: Vec<NodeAddr>,
    drain: Vec<NodeAddr>,
    initiate: Vec<NodeAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FmpRekeyDrainCompletion {
    transport_id: Option<crate::transport::TransportId>,
    old_our_index: crate::utils::index::SessionIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionRekeyInitiation {
    dest_pubkey: PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionRekeyInitiationSkip {
    MissingSession,
    NotEstablished,
    RekeyInProgress,
}

impl crate::node::PeerLifecycleRegistry {
    fn prepare_fmp_rekey_initiation(
        &self,
        node_addr: &NodeAddr,
    ) -> Result<FmpRekeyInitiation, FmpRekeyInitiationSkip> {
        let peer = self
            .active
            .get(node_addr)
            .ok_or(FmpRekeyInitiationSkip::Peer)?;
        let transport_id = peer
            .transport_id()
            .ok_or(FmpRekeyInitiationSkip::Transport)?;
        let remote_addr = peer
            .current_addr()
            .cloned()
            .ok_or(FmpRekeyInitiationSkip::Address)?;

        Ok(FmpRekeyInitiation {
            transport_id,
            remote_addr,
            link_id: peer.link_id(),
            peer_pubkey: peer.identity().pubkey_full(),
        })
    }

    fn record_fmp_rekey_initiated(
        &mut self,
        node_addr: &NodeAddr,
        handshake: HandshakeState,
        our_index: crate::utils::index::SessionIndex,
        wire_msg1: Vec<u8>,
        next_resend_ms: u64,
    ) -> bool {
        let Some(peer) = self.active.get_mut(node_addr) else {
            return false;
        };
        peer.set_rekey_state(handshake, our_index, wire_msg1, next_resend_ms);
        true
    }

    fn exhaust_fmp_rekey_msg1_resend_budgets(
        &mut self,
        max_resends: u32,
    ) -> Vec<ExhaustedFmpRekeyMsg1> {
        let exhausted: Vec<NodeAddr> = self
            .active
            .iter()
            .filter(|(_, peer)| {
                peer.rekey_in_progress()
                    && peer.rekey_msg1().is_some()
                    && peer.rekey_msg1_resend_count() >= max_resends
            })
            .map(|(addr, _)| *addr)
            .collect();

        exhausted
            .into_iter()
            .filter_map(|node_addr| {
                let peer = self.active.get_mut(&node_addr)?;
                let transport_id = peer.transport_id();
                let cleanup = peer
                    .abandon_rekey()
                    .map(|rekey_our_index| FmpRekeyIndexCleanup {
                        transport_id,
                        rekey_our_index,
                    });
                Some(ExhaustedFmpRekeyMsg1 { node_addr, cleanup })
            })
            .collect()
    }

    fn due_fmp_rekey_msg1_resends(&self, now_ms: u64, max_resends: u32) -> Vec<FmpRekeyMsg1Resend> {
        self.active
            .iter()
            .filter(|(_, peer)| {
                peer.rekey_in_progress()
                    && peer.rekey_msg1().is_some()
                    && peer.rekey_msg1_resend_count() < max_resends
                    && peer.needs_msg1_resend(now_ms)
            })
            .filter_map(|(node_addr, peer)| {
                let transport_id = peer.transport_id()?;
                let remote_addr = peer.current_addr()?.clone();
                let payload = peer.rekey_msg1()?.to_vec();
                Some(FmpRekeyMsg1Resend {
                    node_addr: *node_addr,
                    transport_id,
                    remote_addr,
                    payload,
                })
            })
            .collect()
    }

    fn record_scheduled_fmp_rekey_msg1_resend(
        &mut self,
        node_addr: &NodeAddr,
        now_ms: u64,
        interval_ms: u64,
        backoff: f64,
    ) -> Option<u32> {
        let peer = self.active.get_mut(node_addr)?;
        let count = peer.rekey_msg1_resend_count() + 1;
        let next = now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
        peer.record_rekey_msg1_resend(next);
        Some(count)
    }

    fn plan_fmp_rekey_tick(
        &self,
        rekey_after_secs: u64,
        rekey_after_messages: u64,
        cutover_delay: Duration,
        drain_secs: u64,
        dampening_secs: u64,
    ) -> FmpRekeyTickPlan {
        let mut plan = FmpRekeyTickPlan::default();

        for (node_addr, peer) in &self.active {
            if !peer.has_session() || !peer.is_healthy() {
                continue;
            }

            if peer.pending_new_session().is_some()
                && !peer.rekey_in_progress()
                && peer.pending_rekey_cutover_due(cutover_delay)
            {
                plan.cutover.push(*node_addr);
                continue;
            }

            if peer.is_draining() && peer.drain_expired(drain_secs) {
                plan.drain.push(*node_addr);
            }

            if peer.rekey_in_progress() || peer.is_rekey_dampened(dampening_secs) {
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
                plan.initiate.push(*node_addr);
            }
        }

        plan
    }

    fn cutover_due_fmp_rekey(&mut self, node_addr: &NodeAddr, cutover_delay: Duration) -> bool {
        let Some(peer) = self.active.get_mut(node_addr) else {
            return false;
        };
        if peer.pending_new_session().is_none()
            || peer.rekey_in_progress()
            || !peer.pending_rekey_cutover_due(cutover_delay)
        {
            return false;
        }
        peer.cutover_to_new_session().is_some()
    }

    fn complete_due_fmp_rekey_drain(
        &mut self,
        node_addr: &NodeAddr,
        drain_secs: u64,
    ) -> Option<FmpRekeyDrainCompletion> {
        let peer = self.active.get_mut(node_addr)?;
        if !peer.is_draining() || !peer.drain_expired(drain_secs) {
            return None;
        }
        let transport_id = peer.previous_transport_id().or_else(|| peer.transport_id());
        let old_our_index = peer.complete_drain()?;
        Some(FmpRekeyDrainCompletion {
            transport_id,
            old_our_index,
        })
    }
}

impl crate::node::SessionRegistry {
    fn prepare_session_rekey_initiation(
        &self,
        dest_addr: &NodeAddr,
    ) -> Result<SessionRekeyInitiation, SessionRekeyInitiationSkip> {
        let entry = self
            .get(dest_addr)
            .ok_or(SessionRekeyInitiationSkip::MissingSession)?;
        if !entry.is_established() {
            return Err(SessionRekeyInitiationSkip::NotEstablished);
        }
        if entry.has_rekey_in_progress() || entry.pending_new_session().is_some() {
            return Err(SessionRekeyInitiationSkip::RekeyInProgress);
        }
        Ok(SessionRekeyInitiation {
            dest_pubkey: *entry.remote_pubkey(),
        })
    }

    fn record_session_rekey_initiated(
        &mut self,
        dest_addr: &NodeAddr,
        handshake: HandshakeState,
        setup_payload: Vec<u8>,
        next_resend_at_ms: u64,
    ) -> bool {
        let Some(entry) = self.get_mut(dest_addr) else {
            return false;
        };
        entry.set_rekey_state(handshake, true);
        entry.set_handshake_payload(setup_payload, next_resend_at_ms);
        true
    }

    fn plan_session_rekey_tick<F>(
        &self,
        tick: SessionRekeyTickConfig,
        mut send_counter_for: F,
    ) -> SessionRekeyTickPlan
    where
        F: FnMut(&NodeAddr) -> u64,
    {
        let mut plan = SessionRekeyTickPlan::default();

        for (node_addr, entry) in self.iter() {
            if !entry.is_established() {
                continue;
            }

            if entry.pending_new_session().is_some()
                && !entry.has_rekey_in_progress()
                && entry.is_rekey_initiator()
                && tick.now_ms.saturating_sub(entry.rekey_completed_ms()) >= tick.cutover_delay_ms
            {
                plan.cutover.push(*node_addr);
                continue;
            }

            if entry.is_draining() && entry.drain_expired(tick.now_ms, tick.drain_ms) {
                plan.drain.push(*node_addr);
            }

            if entry.has_rekey_in_progress()
                || entry.pending_new_session().is_some()
                || entry.rekey_msg3_payload().is_some()
                || entry.is_rekey_dampened(tick.now_ms, tick.dampening_ms)
            {
                continue;
            }

            let elapsed_secs = tick.now_ms.saturating_sub(entry.session_start_ms()) / 1000;
            let effective_after_secs = tick
                .rekey_after_secs
                .saturating_add_signed(entry.rekey_jitter_secs());
            if elapsed_secs >= effective_after_secs
                || send_counter_for(node_addr) >= tick.rekey_after_messages
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
                entry.stop_rekey_msg3_retransmit();
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
    pub(in crate::node) fn abandon_fmp_rekey_for_peer(
        &mut self,
        node_addr: &NodeAddr,
        reason: &'static str,
    ) -> bool {
        let peer_name = self.peer_display_name(node_addr);
        let cleanup = self.peers.get_mut(node_addr).and_then(|peer| {
            let transport_id = peer.transport_id();
            peer.clear_handshake_msg2();
            peer.abandon_rekey().map(|idx| (transport_id, idx))
        });

        let Some((transport_id, idx)) = cleanup else {
            return false;
        };

        if let Some(tid) = transport_id {
            self.pending_outbound.remove(&(tid, idx.as_u32()));
            self.deregister_session_index((tid, idx.as_u32()));
        }
        let _ = self.index_allocator.free(idx);
        let _ = self.clear_dataplane_fmp_pending_receive_epoch(node_addr);
        let _ = self.sync_dataplane_fmp_owner(node_addr);
        debug!(
            peer = %peer_name,
            reason,
            "Abandoned FMP rekey state"
        );
        true
    }

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

        let plan = self.peers.plan_fmp_rekey_tick(
            rekey_after_secs,
            rekey_after_messages,
            Duration::from_millis(FMP_CUTOVER_DELAY_MS),
            FMP_DRAIN_WINDOW_SECS,
            REKEY_DAMPENING_SECS,
        );

        // Execute cutover for initiator side
        for node_addr in plan.cutover {
            // Refresh the dataplane FMP owner with the now-current
            // session so owner crypto/replay state follows the cutover.
            if self
                .peers
                .cutover_due_fmp_rekey(&node_addr, Duration::from_millis(FMP_CUTOVER_DELAY_MS))
            {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "Rekey cutover complete (initiator), K-bit flipped"
                );
                self.ensure_current_session_index_registered(&node_addr, "initiator rekey cutover");
                self.sync_dataplane_fmp_owner(&node_addr);
                self.complete_authenticated_direct_path_refresh_after_rekey(&node_addr);
            }
        }

        // Execute drain completion
        for node_addr in plan.drain {
            let drained = self
                .peers
                .complete_due_fmp_rekey_drain(&node_addr, FMP_DRAIN_WINDOW_SECS);
            if let Some(drained) = drained {
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    old_index = %drained.old_our_index,
                    "Drain complete, previous session erased"
                );
                // Drop the old session index through `deregister_session_
                // index` rather than registry removal directly so stale
                // receive indexes are retired consistently after drain.
                if let Some(transport_id) = drained.transport_id {
                    self.deregister_session_index((transport_id, drained.old_our_index.as_u32()));
                    let _ = self.index_allocator.free(drained.old_our_index);
                }
                self.sync_dataplane_fmp_owner(&node_addr);
            }
        }

        // Initiate new rekeys
        for node_addr in plan.initiate {
            let _ = self.initiate_rekey(&node_addr).await;
        }
    }

    /// Initiate an outbound rekey to a peer.
    ///
    /// Creates a new IK handshake as initiator, sends msg1 over the existing
    /// link (same transport, same remote address), and stores the handshake
    /// state on the ActivePeer. No new Link or PeerConnection is created.
    pub(in crate::node) async fn initiate_rekey(&mut self, node_addr: &NodeAddr) -> bool {
        let initiation = match self.peers.prepare_fmp_rekey_initiation(node_addr) {
            Ok(initiation) => initiation,
            Err(FmpRekeyInitiationSkip::Peer) => return false,
            Err(FmpRekeyInitiationSkip::Transport) => return false,
            Err(FmpRekeyInitiationSkip::Address) => return false,
        };

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
        let mut hs = HandshakeState::new_initiator(our_keypair, initiation.peer_pubkey);
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

        // Stage handshake dispatch before advertising our receiver index. A
        // fast Msg2 must always resolve to this in-progress rekey.
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let now_ms = Self::now_ms();
        if !self.peers.record_fmp_rekey_initiated(
            node_addr,
            hs,
            our_index,
            wire_msg1.clone(),
            now_ms + resend_interval,
        ) {
            let _ = self.index_allocator.free(our_index);
            return false;
        }
        self.pending_outbound.insert(
            (initiation.transport_id, our_index.as_u32()),
            initiation.link_id,
        );

        // Send msg1 on the existing link (same transport + address). Roll
        // back every staged owner on failure so no unadvertised index leaks.
        let send_result = match self.transports.get(&initiation.transport_id) {
            Some(transport) => transport.send(&initiation.remote_addr, &wire_msg1).await,
            None => Err(crate::transport::TransportError::NotStarted),
        };
        match send_result {
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
                self.abandon_fmp_rekey_for_peer(node_addr, "initial Msg1 send failed");
                return false;
            }
        }
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

        for exhausted in self
            .peers
            .exhaust_fmp_rekey_msg1_resend_budgets(max_resends)
        {
            if let Some(cleanup) = exhausted.cleanup {
                if let Some(transport_id) = cleanup.transport_id {
                    self.pending_outbound
                        .remove(&(transport_id, cleanup.rekey_our_index.as_u32()));
                    self.deregister_session_index((transport_id, cleanup.rekey_our_index.as_u32()));
                }
                let _ = self.index_allocator.free(cleanup.rekey_our_index);
            }
            debug!(
                peer = %self.peer_display_name(&exhausted.node_addr),
                "FMP rekey aborted: msg1 unconfirmed after max retransmissions"
            );
        }

        for resend in self.peers.due_fmp_rekey_msg1_resends(now_ms, max_resends) {
            let sent = if let Some(transport) = self.transports.get(&resend.transport_id) {
                transport
                    .send(&resend.remote_addr, &resend.payload)
                    .await
                    .is_ok()
            } else {
                false
            };

            if sent
                && let Some(count) = self.peers.record_scheduled_fmp_rekey_msg1_resend(
                    &resend.node_addr,
                    now_ms,
                    interval_ms,
                    backoff,
                )
            {
                trace!(
                    peer = %self.peer_display_name(&resend.node_addr),
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
            debug!(
                peer = %self.peer_display_name(&exhausted.dest_addr),
                "FSP rekey msg3 retransmit stopped after max retransmissions"
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
    /// - If the drain window has expired, clear stale-epoch metadata
    /// - If the rekey timer/counter fires, initiate a new XK handshake
    pub(in crate::node) async fn check_session_rekey(&mut self) {
        if !self.config.node.rekey.enabled {
            return;
        }

        let tick = SessionRekeyTickConfig {
            now_ms: Self::now_ms(),
            rekey_after_secs: self.config.node.rekey.after_secs,
            rekey_after_messages: self.config.node.rekey.after_messages,
            drain_ms: FSP_DRAIN_WINDOW_SECS * 1000,
            dampening_ms: REKEY_DAMPENING_SECS * 1000,
            cutover_delay_ms: FSP_CUTOVER_DELAY_MS,
        };

        let dataplane = &self.dataplane;
        let plan = self.sessions.plan_session_rekey_tick(tick, |addr| {
            dataplane
                .fsp_owner_activity(addr)
                .map_or(0, |activity| activity.send_counter())
        });

        // Execute cutover for initiator side
        for node_addr in plan.cutover {
            if self.sessions.cutover_due_session_rekey(
                &node_addr,
                tick.now_ms,
                tick.cutover_delay_ms,
            ) {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP rekey cutover complete (initiator), K-bit flipped"
                );
                self.sync_dataplane_fsp_owner_from_current_session(&node_addr, 0);
            }
        }

        // Execute drain completion
        for node_addr in plan.drain {
            if self.sessions.complete_due_session_rekey_drain(
                &node_addr,
                tick.now_ms,
                tick.drain_ms,
            ) {
                let epoch = self
                    .sessions
                    .get(&node_addr)
                    .map(Self::dataplane_fsp_owner_epoch);
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP drain complete, stale epoch retired"
                );
                if let Some((current_k_bit, previous_draining_k_bit)) = epoch {
                    self.set_dataplane_fsp_owner_epoch(
                        &node_addr,
                        current_k_bit,
                        previous_draining_k_bit,
                    );
                }
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

        let initiation = match self.sessions.prepare_session_rekey_initiation(dest_addr) {
            Ok(initiation) => initiation,
            Err(SessionRekeyInitiationSkip::MissingSession) => return false,
            Err(SessionRekeyInitiationSkip::NotEstablished) => {
                trace!(
                    peer = %self.peer_display_name(dest_addr),
                    "FSP rekey skipped: session is not established"
                );
                return false;
            }
            Err(SessionRekeyInitiationSkip::RekeyInProgress) => {
                trace!(
                    peer = %self.peer_display_name(dest_addr),
                    "FSP rekey skipped: rekey already in progress"
                );
                return false;
            }
        };

        // Create Noise XK initiator handshake
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_initiator(our_keypair, initiation.dest_pubkey);
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
        let setup = SessionSetup::new(our_coords, dest_coords)
            .with_flags(SessionFlags::new().with_direct_fsp_transport())
            .with_handshake(msg1);
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

        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        if !self.sessions.record_session_rekey_initiated(
            dest_addr,
            handshake,
            setup_payload,
            Self::now_ms() + resend_interval,
        ) {
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
mod tests;
