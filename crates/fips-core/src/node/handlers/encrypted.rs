//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::wire::{EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP};
use crate::peer::{InboundFrame, InboundFrameOutcome};

/// Width of the inner-header timestamp prefix (mirrors `strip_inner_header`'s
/// `&plaintext[4..]` slice). Local to this module to keep the FMP fast path
/// self-contained.
const INNER_TIMESTAMP_LEN: usize = 4;
use crate::noise::NoiseError;
use crate::transport::ReceivedPacket;
use tracing::{debug, trace, warn};

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

        // Pre-extract everything off `packet` so we can move data into
        // the single `&mut peer` borrow below without aliasing.
        let ce_flag = header.flags & FLAG_CE != 0;
        let frame = InboundFrame {
            ciphertext: &packet.data[header.ciphertext_offset()..],
            counter: header.counter,
            header_bytes: &header.header_bytes,
            received_k_bit: header.flags & FLAG_KEY_EPOCH != 0,
            ce_flag,
            sp_flag: header.flags & FLAG_SP != 0,
            packet_len: packet.data.len(),
            packet_timestamp_ms: packet.timestamp_ms,
            packet_transport_id: packet.transport_id,
            packet_remote_addr: packet.remote_addr.clone(),
        };

        // Single `&mut peer` borrow for everything: K-bit cutover, FMP
        // decrypt + replay-accept (inline), inner-header parse, and all
        // per-peer mutations (MMP record, link_stats, set_current_addr,
        // touch). One HashMap lookup per packet. The same method runs on
        // the per-peer actor task post ActivePeer-to-actor migration.
        let outcome = {
            let Some(peer) = self.peers.get_mut(&node_addr) else {
                self.peers_by_index.remove(&key);
                return;
            };
            peer.process_inbound_fmp_frame(frame)
        };

        match outcome {
            InboundFrameOutcome::Authentic {
                plaintext,
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
            InboundFrameOutcome::InnerHeaderTooShort { plaintext_len } => {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    len = plaintext_len,
                    "Decrypted payload too short for inner header"
                );
            }
            InboundFrameOutcome::DecryptFailed { error } => {
                self.log_decrypt_failure(&node_addr, &header, &error);
                self.handle_decrypt_failure(&node_addr);
            }
            InboundFrameOutcome::NoSession => {
                warn!(
                    peer = %self.peer_display_name(&node_addr),
                    "Peer in index map has no session"
                );
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
