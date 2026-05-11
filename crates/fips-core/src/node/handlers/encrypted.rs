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
use crate::node::wire::{EncryptedHeader, FLAG_KEY_EPOCH};
use crate::noise::NoiseError;
use crate::transport::ReceivedPacket;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Force-remove a peer after this many consecutive decryption failures.
const DECRYPT_FAILURE_THRESHOLD: u32 = 20;

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
            let peer = self.peers.get_mut(&node_addr).unwrap();
            if let Some(_old_our_index) = peer.handle_peer_kbit_flip() {
                // New index was pre-registered in peers_by_index during
                // msg1 handling (handshake.rs). Verify, don't duplicate.
                debug_assert!(
                    peer.transport_id().is_some()
                        && peer.our_index().is_some()
                        && self.peers_by_index.contains_key(&(
                            peer.transport_id().unwrap(),
                            peer.our_index().unwrap().as_u32()
                        )),
                    "peers_by_index should contain pre-registered new index after K-bit flip"
                );
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
        if let Some(workers) = self.decrypt_workers.as_ref().cloned()
            && let Some(endpoint_event_tx_ref) = self.endpoint_event_tx.as_ref()
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
                fmp_header: header.header_bytes,
                fmp_ciphertext_offset: header.ciphertext_offset(),
                endpoint_event_tx: endpoint_event_tx_ref.clone(),
                fallback_tx: self.decrypt_fallback_tx.clone(),
            };
            workers.dispatch_job(job);
            return;
        }

        // === Test-mode synchronous decrypt ===
        // Production never reaches here. See module-level docs.
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
            let _t = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::FmpDecrypt,
            );
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
                self.handle_decrypt_failure(&node_addr);
                return;
            }
        };
        let plaintext_slice =
            &packet_data[ciphertext_offset..ciphertext_offset + plaintext_len];
        let timestamp = match crate::node::wire::strip_inner_header(plaintext_slice) {
            Some((ts, _link)) => ts,
            None => {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    len = plaintext_len,
                    "Decrypted payload too short for inner header"
                );
                return;
            }
        };
        let peer = self.peers.get_mut(&node_addr).unwrap();
        peer.reset_decrypt_failures();
        let now = Instant::now();
        if let Some(mmp) = peer.mmp_mut() {
            mmp.receiver
                .record_recv(counter, timestamp, packet_len, ce_flag, now);
            let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, counter, now);
        }
        peer.set_current_addr(packet_transport_id, &packet_remote_addr);
        peer.link_stats_mut()
            .record_recv(packet_len, packet_timestamp_ms);
        peer.touch(packet_timestamp_ms);

        const INNER_TIMESTAMP_LEN: usize = 4;
        let link_message = &packet_data
            [ciphertext_offset + INNER_TIMESTAMP_LEN..ciphertext_offset + plaintext_len];
        let link_message_owned: Vec<u8> = link_message.to_vec();
        self.dispatch_link_message(&node_addr, &link_message_owned, ce_flag)
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
    pub(in crate::node) fn register_decrypt_worker_session(
        &mut self,
        node_addr: &crate::NodeAddr,
    ) {
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
        workers.register_session(cache_key, state);
        self.decrypt_registered_sessions.insert(cache_key);
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

    /// Increment decrypt failure counter and force-remove peer if threshold exceeded.
    pub(in crate::node) fn handle_decrypt_failure(&mut self, node_addr: &crate::NodeAddr) {
        if let Some(peer) = self.peers.get_mut(node_addr) {
            let count = peer.increment_decrypt_failures();
            if count >= DECRYPT_FAILURE_THRESHOLD {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures = count,
                    "Excessive decryption failures, removing peer"
                );
                let addr = *node_addr;
                self.remove_active_peer(node_addr);
                let now_ms = Self::now_ms();
                self.schedule_reconnect(addr, now_ms);
            }
        }
    }
}
