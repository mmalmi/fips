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
use crate::noise::NoiseError;
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
    Slow(ReceivedPacket),
}

impl Node {
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
            return EncryptedFrameFastPath::Slow(packet);
        }

        let session_key = DecryptSessionKey::new(packet.transport_id, header.receiver_idx.as_u32());
        if self.decrypt_workers.is_none() {
            return EncryptedFrameFastPath::Slow(packet);
        }
        if !self.sessions.is_worker_registered(&session_key) {
            return EncryptedFrameFastPath::Slow(packet);
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
                }
            }
            EncryptedFrameFastPath::Dropped => (),
            EncryptedFrameFastPath::Slow(packet) => self.handle_encrypted_frame_slow(packet).await,
        }
    }

    pub(in crate::node) async fn handle_encrypted_frame_slow(&mut self, packet: ReceivedPacket) {
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

        // **Worker dispatch is the production path.** Sessions are
        // registered with the decrypt worker at FMP-establishment
        // (see `register_decrypt_worker_session` invoked from
        // `promote_connection`), so in production every
        // `handle_encrypted_frame` for an established session
        // dispatches the packet to the worker and returns. All
        // per-peer bookkeeping runs through
        // `PeerLifecycleRegistry::record_authenticated_fmp_receive`
        // after the worker returns compact receive metadata or an
        // authenticated FMP plaintext fallback.
        //
        // The in-line decrypt below this is the **synchronous test-
        // mode path**: unit tests construct `Node` instances directly
        // (bypassing `lifecycle::start_async`) and step the event
        // loop by hand, so they need a synchronous decrypt that
        // updates `Node` state before the test code returns. In
        // production `self.decrypt_workers` is always `Some` (spawned
        // at lifecycle start with `num_cpus` workers), so this branch
        // is taken and the legacy block below never runs.
        let session_key = DecryptSessionKey::new(packet.transport_id, header.receiver_idx.as_u32());
        // **Worker is the production decrypt path.** The previous
        // version of this gate also required `endpoint_event_tx` to
        // be `Some`, but that field is only populated when a caller
        // attaches the endpoint-data API (`endpoint_data_io()`) — in
        // pure TUN mode (the common iperf-bench shape) the field is
        // `None`, so the gate silently bounced every packet to the
        // legacy in-line decrypt path. The worker can now decode direct
        // local FSP data when the needed sinks exist, so the only
        // remaining requirements are: a worker pool exists, and this
        // session has been handed off
        // to it.
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

        // === Test-mode synchronous decrypt ===
        // Production never reaches here. See module-level docs. Does
        // the FMP AEAD in place against the noise session's own
        // cipher + replay window (which is the authoritative state
        // when no worker is registered), then hands the FMP plaintext
        // to the canonical `process_authentic_fmp_plaintext` — same
        // path the worker-bounce arm in rx_loop takes, so post-
        // decrypt bookkeeping + link-layer dispatch don't fork.
        let ciphertext_offset = header.ciphertext_offset();
        let counter = header.counter;
        let header_bytes = header.header_bytes;
        let packet_len = packet.data.len();
        let packet_timestamp_ms = packet.timestamp_ms;
        let packet_transport_id = packet.transport_id;
        let packet_remote_addr = packet.remote_addr.clone();
        let mut packet_data = packet.data;

        let Some(peer) = self.peers.get_mut(&node_addr) else {
            self.deregister_session_index(key);
            return;
        };
        let source_peer = *peer.identity();
        let Some(session) = peer.noise_session_mut() else {
            warn!(
                peer = %self.peer_display_name(&node_addr),
                "Peer in index map has no session"
            );
            return;
        };
        let decrypt_result = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);
            session.decrypt_with_replay_check_and_aad_in_place(
                &mut packet_data[ciphertext_offset..],
                counter,
                &header_bytes,
            )
        };
        let plaintext_len = match decrypt_result {
            Ok(len) => len,
            Err(e) => {
                self.log_decrypt_failure(&node_addr, &header, &e);
                self.handle_decrypt_failure(&node_addr).await;
                return;
            }
        };
        // The FMP plaintext (4-byte ts + link msg) lives at
        // packet_data[ciphertext_offset..ciphertext_offset + plaintext_len].
        // Slice + own a copy to hand to the shared helper. The copy
        // is cheap (test-mode path; not the hot bench path).
        let fmp_plaintext: Vec<u8> =
            packet_data[ciphertext_offset..ciphertext_offset + plaintext_len].to_vec();
        self.process_authentic_fmp_plaintext(AuthenticatedFmpPlaintext::new(
            source_peer,
            packet_transport_id,
            &packet_remote_addr,
            packet_timestamp_ms,
            packet_len,
            counter,
            header.flags,
            &fmp_plaintext,
        ))
        .await;
    }

    /// Single canonical site for "the FMP layer authenticated and
    /// accepted this packet" side-effects. Called both from the
    /// worker-bounce arm in rx_loop (production fast path) and from
    /// the in-line synchronous decrypt below (test-mode path).
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
        // Address rotation invalidates the per-peer connected UDP
        // socket: it's `connect(2)`-ed to the old kernel 5-tuple
        // (cached route + neighbour entry), and continuing to
        // `sendmsg(.., msg_name=NULL)` on it would push outbound
        // packets at the now-stale address. Drop the connected socket
        // + paired drain thread; the wildcard listen socket takes
        // over until the peer's new 5-tuple is observed long enough
        // to re-`connect()`. Done after the `peer.get_mut` block so
        // the borrow on `self.peers` is released — `clear_connected_
        // udp_for_peer` may need to traverse other peer state.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if action.address_changed() {
            self.clear_connected_udp_for_peer(action.node_addr());
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = action.address_changed();
        }
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
        let Some(workers) = self.decrypt_workers.as_ref().cloned() else {
            return;
        };
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
        // **Only mark as registered if the worker actually accepted
        // the registration message.** When the per-worker channel is
        // full (sustained ingress + registration burst on the same
        // shard), `try_send` returns `Full` and the cipher + replay
        // state are dropped on the floor. If we still inserted into
        // the session registry's worker-registration mirror, every subsequent
        // packet for this session would be `dispatch_job`'d to the worker,
        // miss the unregistered HashMap entry, and silently drop —
        // permanent black hole until the session rotates. Gating
        // the local "is registered" set on the dispatch result
        // means we keep using the legacy in-line decrypt path
        // until a later `register_decrypt_worker_session` succeeds
        // (the FSP-established / rekey callers retry naturally).
        let accepted = workers.register_session(session_key, state);
        self.sessions
            .record_worker_registration(session_key, accepted);
    }

    pub(in crate::node) fn register_decrypt_worker_fsp_session(
        &mut self,
        node_addr: &crate::NodeAddr,
    ) {
        let Some(workers) = self.decrypt_workers.as_ref().cloned() else {
            return;
        };
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
        Some(crate::node::decrypt_worker::OwnedSessionState {
            fmp_cipher,
            fmp_replay,
            source_peer,
        })
    }

    /// Log a decryption failure with replay suppression.
    fn log_decrypt_failure(
        &mut self,
        node_addr: &crate::NodeAddr,
        header: &EncryptedHeader,
        error: &NoiseError,
    ) {
        if matches!(error, NoiseError::ReplayDetected(_)) {
            if let Some(peer) = self.peers.get_mut(node_addr) {
                let count = peer.increment_replay_suppressed();
                if count <= 3 {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        counter = header.counter,
                        error = %error,
                        "Decryption failed"
                    );
                } else if count == 4 {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        "Suppressing further replay detection messages"
                    );
                }
            } else {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    counter = header.counter,
                    error = %error,
                    "Decryption failed"
                );
            }
        } else {
            debug!(
                peer = %self.peer_display_name(node_addr),
                counter = header.counter,
                error = %error,
                "Decryption failed"
            );
        }
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
