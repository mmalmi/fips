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

        // Pre-extract everything off `packet` so we can move data into
        // the single `&mut peer` borrow below without aliasing.
        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;
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

        // Single `&mut peer` borrow for everything: K-bit cutover (rare,
        // free if not needed), FMP decrypt+replay-accept (advances replay
        // window inline post-step-7d-cleanup), inner-header parse, and all
        // per-peer mutations (MMP record, link_stats, set_current_addr,
        // touch). One HashMap lookup per packet, no redundant
        // accept_replay calls.
        let outcome: FmpFrameOutcome = 'outcome: {
            let Some(peer) = self.peers.get_mut(&node_addr) else {
                self.peers_by_index.remove(&key);
                return;
            };

            // K-bit flip — once per rekey, branch-free in steady state.
            if received_k_bit != peer.current_k_bit() && peer.pending_new_session().is_some() {
                let _ = peer.handle_peer_kbit_flip();
                // Index was pre-registered during msg1 handling.
            }

            // FMP decrypt: try current, then drain-window. Each call
            // already advances its replay window on success (post 7d
            // replay_window-Mutex revert) so no separate accept_replay.
            let try_current = if let Some(s) = peer.noise_session_mut() {
                if s.check_replay(counter).is_err() {
                    None
                } else {
                    s.decrypt_with_replay_check_and_aad(ciphertext, counter, &header_bytes)
                        .ok()
                        .map(|pt| (pt, false))
                }
            } else {
                None
            };
            let (plaintext, _used_previous) = match try_current {
                Some(out) => out,
                None => {
                    let try_prev = peer.previous_session_mut().and_then(|s| {
                        s.decrypt_with_replay_check_and_aad(ciphertext, counter, &header_bytes)
                            .ok()
                            .map(|pt| (pt, true))
                    });
                    match try_prev {
                        Some(out) => out,
                        None => {
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

            let timestamp = match strip_inner_header(&plaintext) {
                Some((ts, _link)) => ts,
                None => {
                    break 'outcome FmpFrameOutcome::InnerHeaderTooShort {
                        plaintext_len: plaintext.len(),
                    };
                }
            };

            // Per-peer mutations under the same `&mut peer` borrow.
            peer.reset_decrypt_failures();
            let now = Instant::now();
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver
                    .record_recv(counter, timestamp, packet_len, ce_flag, now);
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, counter, now);
            }
            peer.set_current_addr(packet_transport_id, packet_remote_addr);
            peer.link_stats().record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);

            FmpFrameOutcome::Authentic {
                plaintext,
                used_previous: false, // unused post-cleanup
                inner_timestamp: timestamp,
            }
        };

        match outcome {
            FmpFrameOutcome::Authentic {
                plaintext,
                used_previous: _,
                inner_timestamp: _,
            } => {
                // Hand off to actor (for FSP fast path on owned session)
                // or dispatch_link_message inline (legacy / non-direct).
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
