//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::wire::{EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, strip_inner_header};

/// Width of the inner-header timestamp prefix (mirrors `strip_inner_header`'s
/// `&plaintext[4..]` slice). Local to this module to keep the FMP fast path
/// self-contained.
const INNER_TIMESTAMP_LEN: usize = 4;
use crate::noise::NoiseError;
use crate::transport::ReceivedPacket;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Force-remove a peer after this many consecutive decryption failures.
const DECRYPT_FAILURE_THRESHOLD: u32 = 20;

/// Outcome of the inner peer-mut block in `handle_encrypted_frame`.
///
/// All fast-path work that needs `&mut peer` (decrypt, MMP record, link
/// stats, touch) is performed inside one `peers.get_mut` borrow. The caller
/// then drops the borrow, looks at this enum, and runs whatever needs
/// `&mut self` (decrypt-failure logging, dispatch).
enum FmpFrameOutcome {
    /// Fast path: in-place AEAD decrypt landed the plaintext directly
    /// inside `packet.data`. `plaintext_len` is the number of bytes of
    /// plaintext (excluding the 16-byte AEAD tag) starting at
    /// `packet.data[ciphertext_offset..]`. The link-message body
    /// (after stripping the 4-byte inner timestamp) is at
    /// `packet.data[ciphertext_offset + INNER_TIMESTAMP_LEN ..
    /// ciphertext_offset + plaintext_len]`.
    ///
    /// Used when there is no previous (drain-window) session, which is
    /// the steady state — rekey transitions are rare. Avoids the
    /// ~1.4 KB heap alloc + memcpy per packet that the legacy
    /// `Authentic { plaintext: Vec<u8> }` path required.
    AuthenticInPlace { plaintext_len: usize },
    /// Slow path: packet decrypted via the by-value AEAD path because
    /// a previous session was present (drain-window after rekey). In
    /// that case `open_in_place` would corrupt the ciphertext on a
    /// failed current-session attempt, so we keep the legacy
    /// allocate-and-copy decrypt to preserve the original bytes for a
    /// previous-session retry. Same plaintext layout as the in-place
    /// variant.
    Authentic { plaintext: Vec<u8> },
    /// Plaintext was too short for the inner header. Drop quietly.
    InnerHeaderTooShort { plaintext_len: usize },
    /// Both current and previous (drain-window) sessions failed to
    /// authenticate the frame. `error` is the failure on the *current*
    /// session — that's what gets logged and counted.
    DecryptFailed { error: NoiseError },
    /// `peers_by_index` mapped to a peer that has no live session. Treat
    /// the same as the legacy warning path.
    NoSession,
    /// `peers_by_index` mapped to a peer that has been removed. Stale
    /// entry; drop and let the next handshake repopulate.
    PeerGone,
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
                self.peers_by_index.remove(&key);
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

        // Single-borrow fast path: decrypt, parse inner header, and update
        // all per-peer counters (MMP, link stats, last-seen) inside one
        // `peers.get_mut` lookup. Hands the plaintext back to the caller
        // via `FmpFrameOutcome::Authentic{,InPlace}` so dispatch (which
        // needs `&mut self`) can run after the peer borrow is dropped.
        let ciphertext_offset = header.ciphertext_offset();
        let counter = header.counter;
        let header_bytes = header.header_bytes;
        let ce_flag = header.flags & FLAG_CE != 0;
        let sp_flag = header.flags & FLAG_SP != 0;
        let packet_len = packet.data.len();
        let packet_timestamp_ms = packet.timestamp_ms;
        let packet_transport_id = packet.transport_id;
        // Borrow rather than clone. `set_current_addr` short-circuits
        // when the address hasn't changed (the common case at line
        // rate), and otherwise it clones internally — so eagerly
        // cloning here was a wasted Vec alloc + memcpy per packet on
        // the steady-state hot path.
        let packet_remote_addr = packet.remote_addr.clone();

        // Off-task decrypt fast path: when a decrypt worker pool is
        // configured AND we've cached recv state for this session
        // AND an embedded endpoint is attached (so the worker has
        // somewhere to deliver), dispatch the whole AEAD + delivery
        // pipeline to a worker thread and return. First-packet path
        // falls through to the legacy in-place decrypt below, which
        // also populates the cache so subsequent packets take the
        // worker path.
        let cache_key = (packet.transport_id, header.receiver_idx.as_u32());
        // Off-task fast path: build a slim `DecryptJob` (no replay /
        // cipher fields — those are owned by the worker itself in its
        // shard-local `HashMap`, keyed by `cache_key`) and dispatch.
        // If the worker hasn't received `RegisterSession` for this
        // session yet (very first packet), it will drop the job and
        // we'll register on the legacy path below — subsequent packets
        // take the fast path.
        if let (Some(workers), Some(endpoint_event_tx_ref)) =
            (self.decrypt_workers.as_ref().cloned(), self.endpoint_event_tx.as_ref())
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

        // `packet` is owned by this function; take ownership of its data
        // so we can take a `&mut [u8]` to the ciphertext tail for the
        // in-place decrypt path. Wrap in `Some` so it can be optionally
        // consumed by branches that drop it.
        let mut packet_data = packet.data;

        let outcome: FmpFrameOutcome = 'outcome: {
            let Some(peer) = self.peers.get_mut(&node_addr) else {
                // Race vs. K-bit block: peer was removed between checks.
                break 'outcome FmpFrameOutcome::PeerGone;
            };

            // Fast path: in-place AEAD decrypt on `packet_data` when no
            // previous (drain-window) session is present. The vast
            // majority of inbound packets land here in steady state —
            // rekey transitions are infrequent. Saves the ~1.4 KB Vec
            // alloc + memcpy that `decrypt_with_replay_check_and_aad`'s
            // internal `ciphertext.to_vec()` would do.
            //
            // Slow path: when a previous session exists, we keep the
            // legacy by-value decrypt because in-place open() would
            // corrupt the ciphertext on a failed current-session attempt
            // and leave nothing for the previous-session retry. The
            // drain window is short and rare so the slow path
            // is not on the steady-state hot path.
            let has_previous = peer.previous_session_mut().is_some();

            if !has_previous {
                let Some(session) = peer.noise_session_mut() else {
                    break 'outcome FmpFrameOutcome::NoSession;
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
                        break 'outcome FmpFrameOutcome::DecryptFailed { error: e };
                    }
                };

                // strip_inner_header reads the 4-byte timestamp prefix
                // and validates length. plaintext lives inside
                // packet_data[ciphertext_offset..ciphertext_offset+plaintext_len].
                let plaintext_slice =
                    &packet_data[ciphertext_offset..ciphertext_offset + plaintext_len];
                let timestamp = match strip_inner_header(plaintext_slice) {
                    Some((ts, _link)) => ts,
                    None => {
                        break 'outcome FmpFrameOutcome::InnerHeaderTooShort {
                            plaintext_len,
                        };
                    }
                };

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

                break 'outcome FmpFrameOutcome::AuthenticInPlace { plaintext_len };
            }

            // Slow path with by-value decrypt + drain-window fallback.
            let ciphertext = &packet_data[ciphertext_offset..];
            let current_attempt = {
                let _t = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::FmpDecrypt,
                );
                peer.noise_session_mut().map(|s| {
                    s.decrypt_with_replay_check_and_aad(ciphertext, counter, &header_bytes)
                })
            };

            let plaintext = match current_attempt {
                Some(Ok(p)) => p,
                Some(Err(e)) => {
                    let prev_attempt = peer.previous_session_mut().map(|s| {
                        s.decrypt_with_replay_check_and_aad(ciphertext, counter, &header_bytes)
                    });
                    match prev_attempt {
                        Some(Ok(p)) => p,
                        _ => break 'outcome FmpFrameOutcome::DecryptFailed { error: e },
                    }
                }
                None => break 'outcome FmpFrameOutcome::NoSession,
            };

            let timestamp = match strip_inner_header(&plaintext) {
                Some((ts, _link)) => ts,
                None => {
                    break 'outcome FmpFrameOutcome::InnerHeaderTooShort {
                        plaintext_len: plaintext.len(),
                    };
                }
            };

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

            FmpFrameOutcome::Authentic { plaintext }
        };

        // After the legacy path runs once successfully, hand
        // ownership of the session's recv state to the assigned
        // shard worker. One-way transition: the worker becomes the
        // sole replay-window writer after this point.
        let authentic_first_time =
            matches!(outcome, FmpFrameOutcome::AuthenticInPlace { .. } | FmpFrameOutcome::Authentic { .. });
        if authentic_first_time
            && let Some(workers) = self.decrypt_workers.as_ref().cloned()
            && !self.decrypt_registered_sessions.contains(&cache_key)
            && let Some(state) = self.build_owned_session_state(&node_addr)
        {
            workers.register_session(cache_key, state);
            self.decrypt_registered_sessions.insert(cache_key);
        }

        match outcome {
            FmpFrameOutcome::AuthenticInPlace { plaintext_len } => {
                // Fast path: plaintext lives inside `packet_data`. Slice
                // the link-message body out and dispatch — no Vec
                // allocation involved.
                let link_message = &packet_data
                    [ciphertext_offset + INNER_TIMESTAMP_LEN..ciphertext_offset + plaintext_len];
                self.dispatch_link_message(&node_addr, link_message, ce_flag)
                    .await;
            }
            FmpFrameOutcome::Authentic { plaintext } => {
                // === PACKET IS AUTHENTIC ===
                // Slow path: plaintext is its own Vec (legacy decrypt
                // path used for drain-window fallback). Same dispatch
                // shape — re-slice past the inner-timestamp prefix.
                let link_message = &plaintext[INNER_TIMESTAMP_LEN..];
                self.dispatch_link_message(&node_addr, link_message, ce_flag)
                    .await;
            }
            FmpFrameOutcome::InnerHeaderTooShort { plaintext_len } => {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    len = plaintext_len,
                    "Decrypted payload too short for inner header"
                );
            }
            FmpFrameOutcome::DecryptFailed { error } => {
                self.log_decrypt_failure(&node_addr, &header, &error);
                self.handle_decrypt_failure(&node_addr);
            }
            FmpFrameOutcome::NoSession => {
                warn!(
                    peer = %self.peer_display_name(&node_addr),
                    "Peer in index map has no session"
                );
            }
            FmpFrameOutcome::PeerGone => {
                self.peers_by_index.remove(&key);
            }
        }
    }

    /// Build the **owned** recv state handed off to the decrypt
    /// shard worker on first authentic packet. Returns `None` if the
    /// peer is gone, the session isn't established yet, or the FSP
    /// session for this peer hasn't been brought up (FSP runs over
    /// FMP after a separate handshake). After this call the worker
    /// is the sole replay-window writer for the session.
    fn build_owned_session_state(
        &self,
        node_addr: &crate::NodeAddr,
    ) -> Option<crate::node::decrypt_worker::OwnedSessionState> {
        let peer = self.peers.get(node_addr)?;
        let fmp_session = peer.noise_session()?;
        let fmp_cipher = fmp_session.recv_cipher_clone()?;
        let fmp_replay = fmp_session.recv_replay_snapshot_owned();
        let session_entry = self.sessions.get(node_addr)?;
        let fsp_session = match session_entry.state() {
            crate::node::session::EndToEndState::Established(s) => s,
            _ => return None,
        };
        let fsp_cipher = fsp_session.recv_cipher_clone()?;
        let fsp_replay = fsp_session.recv_replay_snapshot_owned();
        let source_npub = self.npub_for_node_addr(node_addr);
        Some(crate::node::decrypt_worker::OwnedSessionState {
            fmp_cipher,
            fmp_replay,
            fsp_cipher,
            fsp_replay,
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
