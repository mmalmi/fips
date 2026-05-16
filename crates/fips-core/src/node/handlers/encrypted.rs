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
//! Per-peer bookkeeping (`peer.touch`, `link_stats.record_recv`,
//! `mmp.receiver.record_recv`, `set_current_addr`) happens in the
//! rx_loop's `decrypt_fallback_rx` arm after the worker bounces the
//! FMP plaintext back; that arm is the single canonical site for
//! "this packet was successfully received and authenticated" side-
//! effects under the shard architecture.

use crate::node::Node;
use crate::node::decrypt_worker::DecryptFailureReport;
use crate::node::wire::{EncryptedHeader, FLAG_KEY_EPOCH};
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

enum DecryptFailureAction {
    None,
    StartRecoveryRekey { consecutive_failures: u32 },
    AwaitRecovery { consecutive_failures: u32 },
    RemovePeer { consecutive_failures: u32 },
}

impl Node {
    /// Handle an encrypted frame (phase 0x0).
    ///
    /// This is the hot path for established sessions. We use O(1)
    /// index-based lookup to find the session, then decrypt.
    ///
    /// K-bit handling: when the peer flips the K-bit after a rekey,
    /// we promote the pending new session to current and demote the old
    /// session to previous for a drain window. During drain, we try the
    /// current session first, then fall back to the previous session.
    pub(in crate::node) async fn handle_encrypted_frame(&mut self, packet: ReceivedPacket) {
        // Parse header (fail fast)
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return, // Malformed, drop silently
        };

        // O(1) session lookup by our receiver index
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let node_addr = match self.peers_by_index.get(&key) {
            Some(id) => *id,
            None => {
                trace!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "Unknown session index, dropping"
                );
                return;
            }
        };

        // K-bit flip detection: peer has cut over to the new session. This
        // is rare (only at rekey), so we do it as a separate borrow rather
        // than baking it into the fast-path block below — keeping the fast
        // path's `peers.get_mut` straight-line.
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
            let display_name = self.peer_display_name(&node_addr);
            info!(
                peer = %display_name,
                "Peer K-bit flip detected, promoting new session"
            );
            let did_flip = {
                let peer = self.peers.get_mut(&node_addr).unwrap();
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
        }

        // **Worker dispatch is the production path.** Sessions are
        // registered with the decrypt worker at FMP-establishment
        // (see `register_decrypt_worker_session` invoked from
        // `promote_connection`), so in production every
        // `handle_encrypted_frame` for an established session
        // dispatches the packet to the worker and returns. All
        // per-peer bookkeeping (`peer.touch`, `link_stats.record_recv`,
        // `mmp.receiver.record_recv`, `set_current_addr`) runs in the
        // rx_loop's `decrypt_fallback_rx` arm after the worker bounces
        // the FMP plaintext back.
        //
        // The in-line decrypt below this is the **synchronous test-
        // mode path**: unit tests construct `Node` instances directly
        // (bypassing `lifecycle::start_async`) and step the event
        // loop by hand, so they need a synchronous decrypt that
        // updates `Node` state before the test code returns. In
        // production `self.decrypt_workers` is always `Some` (spawned
        // at lifecycle start with `num_cpus` workers), so this branch
        // is taken and the legacy block below never runs.
        let cache_key = (packet.transport_id, header.receiver_idx.as_u32());
        // **Worker is the production decrypt path.** The previous
        // version of this gate also required `endpoint_event_tx` to
        // be `Some`, but that field is only populated when a caller
        // attaches the endpoint-data API (`endpoint_data_io()`) — in
        // pure TUN mode (the common iperf-bench shape) the field is
        // `None`, so the gate silently bounced every packet to the
        // legacy in-line decrypt path. The worker doesn't actually
        // use the endpoint sender after the FMP-only refactor (all
        // link messages bounce back through `fallback_tx` for FSP
        // decrypt on rx_loop), so it was a redundant predicate
        // hiding the bug. The only remaining requirements are: a
        // worker pool exists, and this session has been handed off
        // to it.
        if let Some(workers) = self.decrypt_workers.as_ref().cloned()
            && self.decrypt_registered_sessions.contains(&cache_key)
        {
            let job = super::super::decrypt_worker::DecryptJob {
                packet_data: packet.data,
                cache_key,
                _transport_id: packet.transport_id,
                _remote_addr: packet.remote_addr,
                timestamp_ms: packet.timestamp_ms,
                source_node_addr: node_addr,
                fmp_counter: header.counter,
                fmp_flags: header.flags,
                fmp_header: header.header_bytes,
                fmp_ciphertext_offset: header.ciphertext_offset(),
                fallback_tx: self.decrypt_fallback_tx.clone(),
            };
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
        let ce_flag = header.flags & crate::node::wire::FLAG_CE != 0;
        let sp_flag = header.flags & crate::node::wire::FLAG_SP != 0;
        let packet_len = packet.data.len();
        let packet_timestamp_ms = packet.timestamp_ms;
        let packet_transport_id = packet.transport_id;
        let packet_remote_addr = packet.remote_addr.clone();
        let mut packet_data = packet.data;

        let Some(peer) = self.peers.get_mut(&node_addr) else {
            self.deregister_session_index(key);
            return;
        };
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
        self.process_authentic_fmp_plaintext(
            &node_addr,
            packet_transport_id,
            &packet_remote_addr,
            packet_timestamp_ms,
            packet_len,
            counter,
            ce_flag,
            sp_flag,
            &fmp_plaintext,
        )
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
    #[allow(clippy::too_many_arguments)] // single canonical post-decrypt hook;
    // grouping these into a struct just shifts the
    // boilerplate around without simplifying anything.
    pub(in crate::node) async fn process_authentic_fmp_plaintext(
        &mut self,
        node_addr: &crate::NodeAddr,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        ce_flag: bool,
        sp_flag: bool,
        fmp_plaintext: &[u8],
    ) {
        const INNER_TIMESTAMP_LEN: usize = 4;
        let inner_ts = if fmp_plaintext.len() >= INNER_TIMESTAMP_LEN {
            u32::from_le_bytes([
                fmp_plaintext[0],
                fmp_plaintext[1],
                fmp_plaintext[2],
                fmp_plaintext[3],
            ])
        } else {
            return;
        };
        let now = Instant::now();
        let mut address_changed = false;
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.reset_decrypt_failures();
            address_changed = peer.set_current_addr(transport_id, remote_addr);
            peer.link_stats_mut()
                .record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver
                    .record_recv(fmp_counter, inner_ts, packet_len, ce_flag, now);
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, fmp_counter, now);
            }
        }
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
        if address_changed {
            self.clear_connected_udp_for_peer(node_addr);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = address_changed;
        }
        let link_message = &fmp_plaintext[INNER_TIMESTAMP_LEN..];
        self.dispatch_link_message(node_addr, link_message, ce_flag)
            .await;
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
        let (cache_key, state) = {
            let Some(peer) = self.peers.get(node_addr) else {
                return;
            };
            let Some(transport_id) = peer.transport_id() else {
                return;
            };
            let Some(our_index) = peer.our_index() else {
                return;
            };
            let cache_key = (transport_id, our_index.as_u32());
            let Some(state) = self.build_owned_session_state(node_addr) else {
                return;
            };
            (cache_key, state)
        };
        // **Only mark as registered if the worker actually accepted
        // the registration message.** When the per-worker channel is
        // full (sustained ingress + registration burst on the same
        // shard), `try_send` returns `Full` and the cipher + replay
        // state are dropped on the floor. If we still inserted into
        // `decrypt_registered_sessions`, every subsequent packet for
        // this session would be `dispatch_job`'d to the worker,
        // miss the unregistered HashMap entry, and silently drop —
        // permanent black hole until the session rotates. Gating
        // the local "is registered" set on the dispatch result
        // means we keep using the legacy in-line decrypt path
        // until a later `register_decrypt_worker_session` succeeds
        // (the FSP-established / rekey callers retry naturally).
        if workers.register_session(cache_key, state) {
            self.decrypt_registered_sessions.insert(cache_key);
        }
    }

    /// Build the **owned FMP recv state** handed off to the decrypt
    /// shard worker. Returns `None` if the peer is gone or the FMP
    /// session isn't ready. After registration the worker is the
    /// sole FMP replay-window writer for this session.
    ///
    /// Note: only FMP state is captured. The worker bounces all
    /// link-layer messages back to rx_loop for FSP dispatch, so the
    /// FSP cipher / replay window don't need to live worker-side.
    /// This lets us register at FMP establishment (i.e. as soon as
    /// the Noise handshake completes), eliminating the legacy
    /// in-line decrypt path that used to handle the FMP-established-
    /// but-FSP-not-yet window.
    fn build_owned_session_state(
        &self,
        node_addr: &crate::NodeAddr,
    ) -> Option<crate::node::decrypt_worker::OwnedSessionState> {
        let peer = self.peers.get(node_addr)?;
        let fmp_session = peer.noise_session()?;
        let fmp_cipher = fmp_session.recv_cipher_clone()?;
        let fmp_replay = fmp_session.recv_replay_snapshot_owned();
        let source_npub = self.npub_for_node_addr(node_addr);
        Some(crate::node::decrypt_worker::OwnedSessionState {
            fmp_cipher,
            fmp_replay,
            source_npub,
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
        let Some(peer) = self.peers.get(&report.source_node_addr) else {
            return;
        };
        let session_age = peer.session_established_at().elapsed();
        if report.fmp_replay_highest == 0
            && session_age.as_secs() < DECRYPT_FAILURE_FRESH_SESSION_GRACE_SECS
        {
            trace!(
                peer = %self.peer_display_name(&report.source_node_addr),
                counter = report.fmp_counter,
                session_age_ms = session_age.as_millis(),
                "Ignoring likely stale FMP AEAD failure during fresh-session drain window"
            );
            return;
        }

        self.handle_decrypt_failure(&report.source_node_addr).await;
    }
}
