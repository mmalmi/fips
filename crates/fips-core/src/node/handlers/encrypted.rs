//! Encrypted frame handling (hot path).
//!
//! Every authentic packet on an established session is dispatched to
//! the decrypt-worker shard pool — there is **no in-line decrypt
//! path** in this handler anymore. Sessions are registered with the
//! worker at FMP-establishment (see `register_decrypt_worker_session`,
//! invoked from `handlers/handshake.rs::promote_connection`), so the
//! shard owns the recv-side state from the moment a peer becomes
//! reachable.
//!
//! The rx_loop's decrypt-worker return arms apply the compact receive
//! bookkeeping or authenticated FMP plaintext that still needs link dispatch.
//! Peer receive bookkeeping then goes through `PeerLifecycleRegistry`, keeping
//! liveness, link stats, path rotation, and MMP receive metrics in one
//! lifecycle owner.

use crate::node::decrypt_worker::{DecryptFailureReport, DecryptJob, DecryptSessionKey};
use crate::node::wire::{EncryptedHeader, FLAG_KEY_EPOCH};
use crate::node::{AuthenticatedFmpPlaintext, Node, PeerRuntimeReceive, PeerRuntimeReceiveError};
use crate::transport::ReceivedPacket;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Start link-session recovery after this many consecutive FMP AEAD failures.
const DECRYPT_FAILURE_THRESHOLD: u32 = 4;
/// Newly established worker-owned FMP sessions can briefly receive encrypted
/// packets from the peer's previous link session after restart, rekey, roaming,
/// or NAT traversal handoff. Until one packet authenticates on the new replay
/// window, treat those first failures as stale drain noise instead of starting
/// another recovery rekey.
const DECRYPT_FAILURE_FRESH_SESSION_GRACE_SECS: u64 = 30;
/// After the first authenticated packet on a fresh worker-owned session, a
/// smaller stale-ciphertext tail can still arrive from packets already queued
/// against the old epoch/index. Do not let that tail immediately start another
/// recovery rekey.
const DECRYPT_FAILURE_POST_AUTH_GRACE_SECS: u64 = 10;

enum DecryptFailureAction {
    None,
    StartRecoveryRekey { consecutive_failures: u32 },
    AwaitRecovery { consecutive_failures: u32 },
    RemovePeer { consecutive_failures: u32 },
}

pub(in crate::node) enum EncryptedFrameFastPath {
    Dispatch(DecryptJob),
    Dropped,
    RekeyTrial(ReceivedPacket),
}

impl Node {
    pub(in crate::node) fn decrypt_worker_count(default: usize) -> usize {
        std::env::var("FIPS_DECRYPT_WORKERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default.max(1))
            .max(1)
    }

    pub(in crate::node) fn ensure_decrypt_worker_pool(
        &mut self,
        default_workers: usize,
    ) -> crate::node::decrypt_worker::DecryptWorkerPool {
        if self.decrypt_workers.is_none() {
            let worker_count = Self::decrypt_worker_count(default_workers);
            let direct_delivery_sink = self.decrypt_direct_session_delivery_sink();
            self.decrypt_workers = Some(
                crate::node::decrypt_worker::DecryptWorkerPool::spawn_with_direct_delivery_sink(
                    worker_count,
                    direct_delivery_sink,
                ),
            );
            info!(
                workers = worker_count,
                "Spawned FMP+FSP-decrypt worker pool"
            );
        }
        self.decrypt_workers
            .as_ref()
            .expect("decrypt worker pool was just ensured")
            .clone()
    }

    pub(in crate::node) fn try_prepare_encrypted_frame_for_worker(
        &mut self,
        packet: ReceivedPacket,
    ) -> EncryptedFrameFastPath {
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return EncryptedFrameFastPath::Dropped,
        };

        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let node_addr = match self.peers.lookup_session_index(key) {
            Some(id) => id,
            None => {
                trace!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "Unknown session index, dropping"
                );
                return EncryptedFrameFastPath::Dropped;
            }
        };

        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;
        let need_kbit_flip = match self.peers.get(&node_addr) {
            Some(peer) => {
                received_k_bit != peer.current_k_bit() && peer.pending_new_session().is_some()
            }
            None => {
                self.deregister_session_index(key);
                return EncryptedFrameFastPath::Dropped;
            }
        };
        if need_kbit_flip {
            return EncryptedFrameFastPath::RekeyTrial(packet);
        }

        let session_key = DecryptSessionKey::new(packet.transport_id, header.receiver_idx.as_u32());
        if self.decrypt_workers.is_none() {
            self.record_decrypt_worker_unowned_packet_drop(
                &node_addr,
                &packet,
                "missing-worker-pool",
                header.counter,
            );
            return EncryptedFrameFastPath::Dropped;
        }
        if !self.sessions.is_worker_registered(&session_key) {
            self.record_decrypt_worker_unowned_packet_drop(
                &node_addr,
                &packet,
                "unregistered-session",
                header.counter,
            );
            return EncryptedFrameFastPath::Dropped;
        }

        let job = super::super::decrypt_worker::DecryptJob::new(
            packet.data,
            session_key,
            packet.transport_id,
            packet.remote_addr,
            *self.node_addr(),
            packet.timestamp_ms,
            header.counter,
            header.flags,
            header.header_bytes,
            header.ciphertext_offset(),
            self.decrypt_fallback_tx.clone(),
        );
        EncryptedFrameFastPath::Dispatch(job)
    }

    /// Handle an encrypted frame (phase 0x0).
    ///
    /// This is the hot path for established sessions. We use O(1)
    /// index-based lookup to find the session, then decrypt.
    ///
    /// K-bit handling: when the peer flips the K-bit after a rekey,
    /// we promote the pending new session to current and demote the old
    /// session to previous for a drain window. During drain, we try the
    /// current session first, then fall back to the previous session.
    #[cfg(test)]
    pub(in crate::node) async fn handle_encrypted_frame(&mut self, packet: ReceivedPacket) {
        match self.try_prepare_encrypted_frame_for_worker(packet) {
            EncryptedFrameFastPath::Dispatch(job) => {
                if let Some(workers) = self.decrypt_workers.as_ref() {
                    workers.dispatch_job(job);
                    self.drain_decrypt_worker_test_return().await;
                }
            }
            EncryptedFrameFastPath::Dropped => (),
            EncryptedFrameFastPath::RekeyTrial(packet) => {
                self.handle_encrypted_frame_rekey_trial(packet).await;
                self.drain_decrypt_worker_test_return().await;
            }
        }
    }

    #[cfg(test)]
    async fn drain_decrypt_worker_test_return(&mut self) {
        let Some(mut rx) = self.decrypt_fallback_rx.take() else {
            return;
        };

        for _ in 0..100 {
            if !rx.priority.is_empty() || !rx.authenticated_bulk.is_empty() || !rx.bulk.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }

        self.drain_decrypt_fallback(&mut rx, None, None, None, 64)
            .await;
        self.decrypt_fallback_rx = Some(rx);
    }

    pub(in crate::node) async fn handle_encrypted_frame_rekey_trial(
        &mut self,
        packet: ReceivedPacket,
    ) {
        // Parse header (fail fast)
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return, // Malformed, drop silently
        };

        // O(1) session lookup by our receiver index
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let node_addr = match self.peers.lookup_session_index(key) {
            Some(id) => id,
            None => {
                trace!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "Unknown session index, dropping"
                );
                return;
            }
        };

        // K-bit flip detection: peer may have cut over to the new session.
        // The bit alone is only a hint: authenticate the frame against the
        // pending session before promotion. The decrypt worker owns the
        // current FMP recv state in production, so failed pending trials fall
        // through to the normal worker/inline current-session path.
        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;
        let need_kbit_flip = match self.peers.get(&node_addr) {
            Some(peer) => {
                received_k_bit != peer.current_k_bit() && peer.pending_new_session().is_some()
            }
            None => {
                // Stale index entry; drop the index and let next handshake repopulate.
                self.deregister_session_index(key);
                return;
            }
        };
        if need_kbit_flip {
            let ciphertext = &packet.data[header.ciphertext_offset()..];
            let pending_plaintext = {
                let Some(peer) = self.peers.get_mut(&node_addr) else {
                    self.deregister_session_index(key);
                    return;
                };
                peer.trial_decrypt_pending_new_session(
                    ciphertext,
                    header.counter,
                    &header.header_bytes,
                )
            };

            if let Some(plaintext) = pending_plaintext {
                let display_name = self.peer_display_name(&node_addr);
                info!(
                    peer = %display_name,
                    "Peer new-epoch frame authenticated, promoting new session"
                );
                let did_flip = {
                    let Some(peer) = self.peers.get_mut(&node_addr) else {
                        self.deregister_session_index(key);
                        return;
                    };
                    peer.handle_peer_kbit_flip().is_some()
                };
                // After cutover the *new* FMP session is the one the
                // decrypt worker must own. Pre-fix: the worker still
                // had the OLD session's cipher + replay state, so every
                // post-flip packet missed the worker's HashMap lookup
                // (cache_key now points at the new index) and either
                // dropped silently in `handle_job` or, if the worker
                // had never been registered for this peer at all, fell
                // through to the in-line legacy path on rx_loop for
                // the lifetime of the new session. Re-register here so
                // the worker observes the rekey and the bulk receive
                // path keeps using it.
                if did_flip {
                    self.ensure_current_session_index_registered(&node_addr, "peer K-bit flip");
                    self.register_decrypt_worker_session(&node_addr);
                }
                let Some(source_peer) = self.peers.get(&node_addr).map(|peer| *peer.identity())
                else {
                    self.deregister_session_index(key);
                    return;
                };
                self.process_authentic_fmp_plaintext(AuthenticatedFmpPlaintext::new(
                    source_peer,
                    packet.transport_id,
                    &packet.remote_addr,
                    packet.timestamp_ms,
                    packet.data.len(),
                    header.counter,
                    header.flags,
                    &plaintext,
                ))
                .await;
                return;
            }

            trace!(
                peer = %self.peer_display_name(&node_addr),
                counter = header.counter,
                "Peer K-bit flip did not authenticate against pending session"
            );
            // Do not promote. The frame may be stale/mismatched, or it may
            // still authenticate against the current worker-owned session.
            // Fall through to the normal decrypt path.
        }

        // Pending-session trial did not authenticate. Fall back only to the
        // owner worker for the current session; missing ownership is a drop,
        // not an in-node decrypt bypass.
        let session_key = DecryptSessionKey::new(packet.transport_id, header.receiver_idx.as_u32());
        if let Some(workers) = self.decrypt_workers.as_ref()
            && self.sessions.is_worker_registered(&session_key)
        {
            let job = super::super::decrypt_worker::DecryptJob::new(
                packet.data,
                session_key,
                packet.transport_id,
                packet.remote_addr,
                *self.node_addr(),
                packet.timestamp_ms,
                header.counter,
                header.flags,
                header.header_bytes,
                header.ciphertext_offset(),
                self.decrypt_fallback_tx.clone(),
            );
            workers.dispatch_job(job);
            return;
        }

        self.record_decrypt_worker_unowned_packet_drop(
            &node_addr,
            &packet,
            "rekey-trial-unregistered-session",
            header.counter,
        );
    }

    /// Single canonical site for "the FMP layer authenticated and
    /// accepted this packet" side-effects. Called from the worker-bounce arm
    /// in rx_loop and the bounded pending-rekey trial above.
    ///
    /// Performs the per-peer bookkeeping (last-seen, MMP receiver,
    /// link stats, address-rotation) and then dispatches the
    /// link-layer message body to `dispatch_link_message`. The
    /// caller is responsible for ensuring the FMP AEAD already
    /// verified the bytes — this function trusts `fmp_plaintext` as
    /// authentic.
    ///
    /// `fmp_plaintext` is the post-FMP-decrypt buffer with the
    /// 4-byte inner timestamp still at the front (i.e. the same
    /// layout the legacy `strip_inner_header` consumed).
    pub(in crate::node) async fn process_authentic_fmp_plaintext(
        &mut self,
        receive: AuthenticatedFmpPlaintext<'_>,
    ) {
        let source_node_addr = *receive.source_node_addr();
        let transport_id = receive.transport_id();
        let packet_timestamp_ms = receive.packet_timestamp_ms();
        let now = Instant::now();
        let path_bookkeeping_allowed = self.authenticated_packet_path_allows_bookkeeping(
            &source_node_addr,
            transport_id,
            receive.remote_addr(),
            packet_timestamp_ms,
        );
        let runtime_receive = match PeerRuntimeReceive::from_authenticated_fmp_plaintext(receive) {
            Ok(receive) => receive,
            Err(PeerRuntimeReceiveError::MissingInnerTimestamp) => return,
        };
        let dispatch =
            runtime_receive.record_bookkeeping(&mut self.peers, now, path_bookkeeping_allowed);
        let action = dispatch.into_action();
        let _ = action.address_changed();
        let Some(link_message) = action.into_link_message() else {
            return;
        };
        self.dispatch_link_message(link_message).await;
    }

    /// Register a peer's recv state with the decrypt-worker shard
    /// **eagerly at FSP-session establishment**. After this call the
    /// worker becomes the sole replay-window writer for the session
    /// and rx_loop's legacy in-line decrypt is no longer used for
    /// this peer.
    ///
    /// Called from the FSP-session-established sites in
    /// `handlers/session.rs` (both initiator and responder). No-op if
    /// the session state can't be built yet (peer gone, FSP not yet
    /// promoted to Established) — the caller can retry on a later
    /// event. Idempotent: re-registering the same cache_key
    /// overwrites the worker's entry, which is the correct behaviour
    /// for rekey.
    pub(in crate::node) fn register_decrypt_worker_session(&mut self, node_addr: &crate::NodeAddr) {
        let workers = self.ensure_decrypt_worker_pool(1);
        let (session_key, state) = {
            let Some(peer) = self.peers.get(node_addr) else {
                return;
            };
            let Some(transport_id) = peer.transport_id() else {
                return;
            };
            let Some(our_index) = peer.our_index() else {
                return;
            };
            let session_key = DecryptSessionKey::new(transport_id, our_index.as_u32());
            let Some(state) = self.build_owned_session_state(node_addr) else {
                return;
            };
            (session_key, state)
        };
        // Only mark as registered if the worker actually accepted the
        // registration message. If the control lane is full, packets for this
        // session are explicit worker-drop accounting until a later session
        // event retries registration.
        let accepted = workers.register_session(session_key, state);
        self.sessions
            .record_worker_registration(session_key, accepted);
    }

    pub(in crate::node) fn register_decrypt_worker_fsp_session(
        &mut self,
        node_addr: &crate::NodeAddr,
    ) {
        self.sync_packet_mover2_fsp_owner(node_addr);

        let workers = self.ensure_decrypt_worker_pool(1);
        let Some(snapshot) = self
            .sessions
            .get(node_addr)
            .and_then(|entry| entry.fsp_recv_snapshot())
        else {
            return;
        };
        let _accepted = workers.register_fsp_session(*node_addr, snapshot);
    }

    pub(in crate::node) fn unregister_decrypt_worker_fsp_session(
        &mut self,
        node_addr: &crate::NodeAddr,
    ) {
        self.remove_packet_mover2_fsp_owner(node_addr);

        if let Some(workers) = self.decrypt_workers.as_ref() {
            let _ = workers.unregister_fsp_session(*node_addr);
        }
    }

    /// Build the **owned FMP recv state** handed off to the decrypt
    /// shard worker. Returns `None` if the peer is gone or the FMP
    /// session isn't ready. After registration the worker is the
    /// sole FMP replay-window writer for this session.
    ///
    /// Note: only FMP state is captured here. Established FSP receive
    /// snapshots are registered separately, keyed by end-to-end source, after
    /// the session handshake/rekey reaches an FSP-ready state. This lets FMP
    /// registration happen as soon as the link Noise handshake completes
    /// without pretending the end-to-end receive state is available yet.
    fn build_owned_session_state(
        &self,
        node_addr: &crate::NodeAddr,
    ) -> Option<crate::node::decrypt_worker::OwnedSessionState> {
        let peer = self.peers.get(node_addr)?;
        let fmp_session = peer.noise_session()?;
        let fmp_cipher = fmp_session.recv_cipher_clone()?;
        let fmp_replay = fmp_session.recv_replay_snapshot_owned();
        let source_peer = *peer.identity();
        Some(crate::node::decrypt_worker::OwnedSessionState::new(
            fmp_cipher,
            fmp_replay,
            source_peer,
        ))
    }

    fn record_decrypt_worker_unowned_packet_drop(
        &self,
        node_addr: &crate::NodeAddr,
        packet: &ReceivedPacket,
        reason: &'static str,
        counter: u64,
    ) {
        crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerQueueFull);
        crate::perf_profile::record_event(if packet.is_priority_sized() {
            crate::perf_profile::Event::DecryptWorkerPriorityDropped
        } else {
            crate::perf_profile::Event::DecryptWorkerBulkDropped
        });
        debug!(
            peer = %self.peer_display_name(node_addr),
            transport_id = %packet.transport_id,
            remote_addr = %packet.remote_addr,
            bytes = packet.data.len(),
            counter,
            reason,
            "Dropping established FMP packet without decrypt-worker ownership"
        );
    }

    /// Increment decrypt failure counter and recover stale FMP sessions.
    ///
    /// Stale encrypted packets can arrive after sleep/wake, network roaming,
    /// rekey races, or peer restart. Removing the peer immediately causes a
    /// visible traffic drop even when the existing link is healthy enough to
    /// carry a replacement handshake. Prefer an in-place rekey and keep the
    /// old session alive while that recovery handshake completes; only evict
    /// when recovery cannot be started.
    pub(in crate::node) async fn handle_decrypt_failure(&mut self, node_addr: &crate::NodeAddr) {
        let rekey_enabled = self.config.node.rekey.enabled;
        let action = {
            let Some(peer) = self.peers.get_mut(node_addr) else {
                return;
            };
            let count = peer.increment_decrypt_failures();
            if count < DECRYPT_FAILURE_THRESHOLD {
                DecryptFailureAction::None
            } else if rekey_enabled && peer.has_session() {
                if !peer.rekey_in_progress() && peer.pending_new_session().is_none() {
                    DecryptFailureAction::StartRecoveryRekey {
                        consecutive_failures: count,
                    }
                } else {
                    DecryptFailureAction::AwaitRecovery {
                        consecutive_failures: count,
                    }
                }
            } else {
                DecryptFailureAction::RemovePeer {
                    consecutive_failures: count,
                }
            }
        };

        match action {
            DecryptFailureAction::None => {}
            DecryptFailureAction::StartRecoveryRekey {
                consecutive_failures,
            } => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures,
                    "FMP AEAD failures exceeded threshold; starting recovery rekey"
                );
                if self.initiate_rekey(node_addr).await {
                    if let Some(peer) = self.peers.get_mut(node_addr) {
                        peer.reset_decrypt_failures();
                    }
                } else {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        consecutive_failures,
                        "Failed to start FMP recovery rekey; removing peer"
                    );
                    let addr = *node_addr;
                    self.remove_active_peer(node_addr);
                    let now_ms = Self::now_ms();
                    self.schedule_reconnect(addr, now_ms);
                }
            }
            DecryptFailureAction::AwaitRecovery {
                consecutive_failures,
            } => {
                if consecutive_failures == DECRYPT_FAILURE_THRESHOLD
                    || consecutive_failures.is_multiple_of(1000)
                {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        consecutive_failures,
                        "FMP AEAD failures continuing while recovery rekey is pending"
                    );
                }
            }
            DecryptFailureAction::RemovePeer {
                consecutive_failures,
            } => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures,
                    "FMP AEAD failures exceeded threshold and recovery is unavailable; removing peer"
                );
                let addr = *node_addr;
                self.remove_active_peer(node_addr);
                let now_ms = Self::now_ms();
                self.schedule_reconnect(addr, now_ms);
            }
        }
    }

    /// Handle an AEAD failure reported by the worker-owned FMP decrypt path.
    ///
    /// The worker owns the replay window for production traffic, so it can tell
    /// us whether the current session has authenticated anything yet. That lets
    /// us ignore a bounded startup drain of stale ciphertext after peer restart
    /// or rekey while keeping the normal recovery path for established sessions.
    pub(in crate::node) async fn handle_decrypt_failure_report(
        &mut self,
        report: &DecryptFailureReport,
    ) {
        let source_node_addr = report.source_peer.node_addr();
        let Some(peer) = self.peers.get(source_node_addr) else {
            return;
        };
        let session_age = peer.session_established_at().elapsed();
        let grace_secs = if report.fmp_replay_highest == 0 {
            DECRYPT_FAILURE_FRESH_SESSION_GRACE_SECS
        } else {
            DECRYPT_FAILURE_POST_AUTH_GRACE_SECS
        };
        if session_age.as_secs() < grace_secs {
            trace!(
                peer = %self.peer_display_name(source_node_addr),
                counter = report.fmp_counter,
                replay_highest = report.fmp_replay_highest,
                session_age_ms = session_age.as_millis(),
                grace_secs,
                "Ignoring likely stale FMP AEAD failure during fresh-session drain window"
            );
            return;
        }

        self.handle_decrypt_failure(source_node_addr).await;
    }
}
