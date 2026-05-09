//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::aead_pool::{AeadInboundElem, DecryptedElem};
use crate::node::wire::{EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, strip_inner_header};

/// Width of the inner-header timestamp prefix (mirrors `strip_inner_header`'s
/// `&plaintext[4..]` slice). Local to this module to keep the FMP fast path
/// self-contained.
const INNER_TIMESTAMP_LEN: usize = 4;
use crate::noise::NoiseError;
use crate::transport::ReceivedPacket;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Outcome of `classify_inbound_packet` for the parallel-decrypt path.
pub(in crate::node) enum InboundClassify {
    /// Packet is a PHASE_ESTABLISHED frame on a known live session and
    /// passes the cheap pre-decrypt replay-window check. The
    /// `AeadInboundElem` is ready to ship to the AEAD pool.
    Aead(AeadInboundElem),
    /// Packet should run through the legacy inline path: handshake
    /// (PHASE_MSG1/2), unknown phase, unknown session, peer removed,
    /// K-bit-flip required, or session not yet keyed. The original
    /// packet is returned so the rx_loop can call `process_packet` on
    /// it as before.
    Inline(ReceivedPacket),
    /// Pre-decrypt replay-window check rejected the counter; drop
    /// silently without spending a worker slot. (Replays are common
    /// under loss + retransmits and we don't want to wedge the pool's
    /// queue with garbage.)
    Replay,
}

/// Force-remove a peer after this many consecutive decryption failures.
const DECRYPT_FAILURE_THRESHOLD: u32 = 20;

/// Outcome of the inner peer-mut block in `handle_encrypted_frame`.
///
/// All fast-path work that needs `&mut peer` (decrypt, MMP record, link
/// stats, touch) is performed inside one `peers.get_mut` borrow. The caller
/// then drops the borrow, looks at this enum, and runs whatever needs
/// `&mut self` (decrypt-failure logging, dispatch).
enum FmpFrameOutcome {
    /// Packet decrypted successfully. `plaintext` still includes the
    /// 4-byte inner timestamp prefix — the link-layer message body starts
    /// at `plaintext[INNER_TIMESTAMP_LEN..]`. The timestamp itself is
    /// consumed for MMP stats inside the same borrow that decrypted the
    /// frame, so it doesn't need to escape.
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
        // via `FmpFrameOutcome::Authentic` so dispatch (which needs
        // `&mut self`) can run after the peer borrow is dropped.
        let ciphertext_offset = header.ciphertext_offset();
        let counter = header.counter;
        let header_bytes = header.header_bytes;
        let ce_flag = header.flags & FLAG_CE != 0;
        let sp_flag = header.flags & FLAG_SP != 0;
        let packet_len = packet.data.len();
        let packet_timestamp_ms = packet.timestamp_ms;
        let packet_transport_id = packet.transport_id;
        let packet_remote_addr = packet.remote_addr.clone();
        let ciphertext = &packet.data[ciphertext_offset..];

        let outcome: FmpFrameOutcome = 'outcome: {
            let Some(peer) = self.peers.get_mut(&node_addr) else {
                // Race vs. K-bit block: peer was removed between checks.
                break 'outcome FmpFrameOutcome::PeerGone;
            };

            // Try current session first. We extract `Result<Vec<u8>, _>` so
            // the `&mut NoiseSession` borrow ends before we touch peer
            // again (for the previous-session fallback or for stats).
            let current_attempt = peer
                .noise_session_mut()
                .map(|s| s.decrypt_with_replay_check_and_aad(ciphertext, counter, &header_bytes));

            let plaintext = match current_attempt {
                Some(Ok(p)) => p,
                Some(Err(e)) => {
                    // Drain-window fallback: previous session.
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

            // Inner header is 4-byte timestamp + at least one msg_type byte
            // (total min INNER_HEADER_SIZE = 5). `strip_inner_header`
            // borrows from `plaintext`; we only need the timestamp here,
            // because the link-message slice is computed after the borrow
            // releases.
            let timestamp = match strip_inner_header(&plaintext) {
                Some((ts, _link)) => ts,
                None => {
                    break 'outcome FmpFrameOutcome::InnerHeaderTooShort {
                        plaintext_len: plaintext.len(),
                    };
                }
            };

            // Stats inline — same borrow.
            peer.reset_decrypt_failures();
            let now = Instant::now();
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver
                    .record_recv(counter, timestamp, packet_len, ce_flag, now);
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, counter, now);
            }
            peer.set_current_addr(packet_transport_id, packet_remote_addr);
            peer.link_stats_mut()
                .record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);

            FmpFrameOutcome::Authentic { plaintext }
        };

        match outcome {
            FmpFrameOutcome::Authentic { plaintext } => {
                // === PACKET IS AUTHENTIC ===
                // The link message is plaintext minus the 4-byte timestamp
                // (mirrors what `strip_inner_header` returned). We re-slice
                // here because plaintext is owned by us at this point.
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

    // ========================================================================
    // Parallel-decrypt path
    // ========================================================================

    /// Classify an inbound packet for the parallel-decrypt pool.
    ///
    /// Called by `rx_loop` when `aead_pool` is enabled. Performs the
    /// cheap pre-decrypt work that needs `&mut self` (header parse,
    /// peers_by_index lookup, K-bit detection, replay check, recv-cipher
    /// clone) and either packages the work for the pool or punts back
    /// to inline `process_packet`. Counter assignment / replay-window
    /// updates happen in `apply_decrypted_elem` after the worker reports
    /// success — workers themselves never touch session state.
    ///
    /// We deliberately punt the K-bit-flip case (rare) and any
    /// "session not yet keyed" / "peer removed" / "unknown session"
    /// cases to the inline path so this function has no failure modes
    /// other than "dispatch via pool" or "punt to inline" or "drop on
    /// replay" — keeping the rx_loop's drain loop simple.
    pub(in crate::node) fn classify_inbound_packet(
        &mut self,
        packet: ReceivedPacket,
    ) -> InboundClassify {
        // Need at least the encrypted-frame header to consider the pool;
        // anything shorter or with non-ESTABLISHED phase goes inline.
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return InboundClassify::Inline(packet),
        };

        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let node_addr = match self.peers_by_index.get(&key) {
            Some(id) => *id,
            None => return InboundClassify::Inline(packet),
        };

        // K-bit flip detection: rare, and the flip mutation lives on the
        // inline path. Fall back to inline if a flip is needed so we
        // don't have to duplicate the K-bit-flip code on this path too.
        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;
        let peer = match self.peers.get(&node_addr) {
            Some(p) => p,
            None => return InboundClassify::Inline(packet),
        };
        let need_kbit_flip =
            received_k_bit != peer.current_k_bit() && peer.pending_new_session().is_some();
        if need_kbit_flip {
            return InboundClassify::Inline(packet);
        }

        let session = match peer.noise_session() {
            Some(s) => s,
            None => return InboundClassify::Inline(packet),
        };

        // Cheap pre-decrypt replay check. We don't ADVANCE the window
        // here — that happens in `apply_decrypted_elem` once the worker
        // confirms a valid AEAD tag. Pre-checking lets us drop replays
        // before consuming a pool slot.
        if session.check_replay(header.counter).is_err() {
            return InboundClassify::Replay;
        }

        let key_current = match session.recv_cipher_clone() {
            Some(k) => Arc::new(k),
            None => return InboundClassify::Inline(packet),
        };
        let key_previous = peer
            .previous_session()
            .and_then(|s| s.recv_cipher_clone())
            .map(Arc::new);

        let counter = header.counter;
        let aad = header.header_bytes;
        let ciphertext_offset = header.ciphertext_offset();

        InboundClassify::Aead(AeadInboundElem {
            packet,
            header,
            counter,
            aad,
            ciphertext_offset,
            key_current,
            key_previous,
            node_addr,
        })
    }

    /// Apply a decrypted elem produced by the AEAD pool: advance the
    /// peer's replay window, run the same per-peer counter updates that
    /// the inline `handle_encrypted_frame` does (MMP record, link stats,
    /// touch), then dispatch the link message.
    ///
    /// On AEAD-failure outcomes we mirror the inline path's logging and
    /// failure-count handling; on success we honour the
    /// `used_previous_session` flag for replay-window placement.
    pub(in crate::node) async fn apply_decrypted_elem(&mut self, elem: DecryptedElem) {
        let DecryptedElem {
            packet,
            header,
            node_addr,
            result,
            used_previous_session,
        } = elem;

        let plaintext = match result {
            Ok(pt) => pt,
            Err(error) => {
                self.log_decrypt_failure(&node_addr, &header, &error);
                self.handle_decrypt_failure(&node_addr);
                return;
            }
        };

        let counter = header.counter;
        let ce_flag = header.flags & FLAG_CE != 0;
        let sp_flag = header.flags & FLAG_SP != 0;
        let packet_len = packet.data.len();
        let packet_timestamp_ms = packet.timestamp_ms;
        let packet_transport_id = packet.transport_id;
        let packet_remote_addr = packet.remote_addr.clone();

        // Inner-header parse must succeed: workers don't gate on this,
        // so a corrupted plaintext (post-AEAD) gets dropped here. AEAD
        // makes this near-impossible, but the check is cheap.
        let timestamp = match strip_inner_header(&plaintext) {
            Some((ts, _)) => ts,
            None => {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    len = plaintext.len(),
                    "Decrypted payload too short for inner header (pool path)"
                );
                return;
            }
        };

        // Single-borrow update of peer state, mirroring the inline path.
        // The replay-window accept happens here; pre-decrypt classify
        // only checked, didn't advance.
        if let Some(peer) = self.peers.get_mut(&node_addr) {
            if used_previous_session {
                if let Some(prev) = peer.previous_session_mut() {
                    prev.accept_replay(counter);
                }
            } else if let Some(s) = peer.noise_session_mut() {
                s.accept_replay(counter);
            }

            peer.reset_decrypt_failures();
            let now = Instant::now();
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver
                    .record_recv(counter, timestamp, packet_len, ce_flag, now);
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, counter, now);
            }
            peer.set_current_addr(packet_transport_id, packet_remote_addr);
            peer.link_stats_mut()
                .record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);
        } else {
            // Peer was removed between classify-time and completion.
            // Drop the plaintext silently — the link layer doesn't have
            // anywhere to put it.
            return;
        }

        // === PACKET IS AUTHENTIC ===
        let link_message = &plaintext[INNER_TIMESTAMP_LEN..];
        self.dispatch_link_message(&node_addr, link_message, ce_flag)
            .await;
    }
}
