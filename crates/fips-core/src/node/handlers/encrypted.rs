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
    /// Packet decrypted successfully. `plaintext` still includes the
    /// 4-byte inner timestamp prefix — the link-layer message body
    /// starts at `plaintext[INNER_TIMESTAMP_LEN..]`. `used_previous`
    /// tells the actor / inline post-decrypt path which session's
    /// replay window to advance (current vs drain-window).
    /// `inner_timestamp` is the parsed value from the 4-byte prefix.
    Authentic {
        plaintext: Vec<u8>,
        used_previous: bool,
        inner_timestamp: u32,
    },
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
            Some(slot) => {
                let peer = slot;
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
            let Some(slot) = self.peers.get(&node_addr) else {
                // Race vs. K-bit block: peer was removed between checks.
                break 'outcome FmpFrameOutcome::PeerGone;
            };
            let peer = slot;

            // Try current session first. After step 2, NoiseSession's
            // decrypt_with_replay_check_and_aad takes `&self`, so the
            // shared `peer_read` guard suffices. Note: this version
            // does NOT advance the replay window — the actor / inline
            // post-decrypt path does, once we know which session
            // succeeded.
            let try_current = peer.noise_session().and_then(|s| {
                if s.check_replay(counter).is_err() {
                    return None;
                }
                s.decrypt_with_replay_check_and_aad(ciphertext, counter, &header_bytes)
                    .ok()
                    .map(|pt| (pt, false))
            });

            let (plaintext, used_previous) = match try_current {
                Some(out) => out,
                None => {
                    // Try previous (drain-window) session.
                    let try_prev = peer.previous_session().and_then(|s| {
                        s.decrypt_with_replay_check_and_aad(ciphertext, counter, &header_bytes)
                            .ok()
                            .map(|pt| (pt, true))
                    });
                    match try_prev {
                        Some(out) => out,
                        None => {
                            // Both failed (or no current session at all).
                            // Distinguish "no session" from "decrypt fail".
                            break 'outcome if peer.noise_session().is_some() {
                                FmpFrameOutcome::DecryptFailed {
                                    error: NoiseError::DecryptionFailed,
                                }
                            } else {
                                FmpFrameOutcome::NoSession
                            };
                        }
                    }
                }
            };

            // Inner header parse — needed for timestamp.
            let timestamp = match strip_inner_header(&plaintext) {
                Some((ts, _link)) => ts,
                None => {
                    break 'outcome FmpFrameOutcome::InnerHeaderTooShort {
                        plaintext_len: plaintext.len(),
                    };
                }
            };

            FmpFrameOutcome::Authentic {
                plaintext,
                used_previous,
                inner_timestamp: timestamp,
            }
        };

        match outcome {
            FmpFrameOutcome::Authentic {
                plaintext,
                used_previous,
                inner_timestamp,
            } => {
                // Per-peer state mutations always run on rx_loop (the
                // owner of `Node.peers`). After step 7d there's no
                // peer-actor cohabitation — the actor handles only
                // session work, not ActivePeer mutations.
                if let Some(slot) = self.peers.get(&node_addr) {
                    let peer = slot;
                    if used_previous {
                        if let Some(prev) = peer.previous_session() {
                            prev.accept_replay(counter);
                        }
                    } else if let Some(s) = peer.noise_session() {
                        s.accept_replay(counter);
                    }
                    peer.reset_decrypt_failures();
                    let now = Instant::now();
                    if let Some(mut mmp) = peer.mmp_mut() {
                        mmp.receiver.record_recv(
                            counter,
                            inner_timestamp,
                            packet_len,
                            ce_flag,
                            now,
                        );
                        let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, counter, now);
                    }
                    peer.set_current_addr(packet_transport_id, packet_remote_addr);
                    peer.link_stats()
                        .record_recv(packet_len, packet_timestamp_ms);
                    peer.touch(packet_timestamp_ms);
                }

                // After per-peer mutations, hand off to actor (for FSP
                // fast path on owned session) or dispatch_link_message
                // (legacy / non-direct sessions).
                let actor_handle = self
                    .peers
                    .get(&node_addr)
                    .and_then(|slot| slot.actor().cloned());

                if let Some(actor) = actor_handle {
                    let job = crate::peer::actor::DecryptedJob {
                        plaintext,
                        ce_flag,
                    };
                    let _ = actor
                        .dispatch(crate::peer::actor::PeerInboundJob::Decrypted(Box::new(
                            job,
                        )))
                        .await;
                } else {
                    let link_message = &plaintext[INNER_TIMESTAMP_LEN..];
                    self.dispatch_link_message(&node_addr, link_message, ce_flag)
                        .await;
                }
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
            if let Some(slot) = self.peers.get(node_addr) {
                let count = slot.increment_replay_suppressed();
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
        if let Some(slot) = self.peers.get(node_addr) {
            let count = slot.increment_decrypt_failures();
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
