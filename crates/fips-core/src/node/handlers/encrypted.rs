//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::aead_pool::{AeadInboundElem, DecryptedElem};
use crate::node::wire::{EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, strip_inner_header};
use crate::peer::{InboundFrame, InboundFrameOutcome};

/// Width of the inner-header timestamp prefix (mirrors `strip_inner_header`'s
/// `&plaintext[4..]` slice). Local to this module to keep the FMP fast path
/// self-contained.
const INNER_TIMESTAMP_LEN: usize = 4;
use crate::noise::NoiseError;
use crate::transport::ReceivedPacket;
use std::time::Instant;
use tracing::{debug, trace, warn};

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
    /// silently without spending a worker slot.
    Replay,
}

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

        // Actor-owned-peer fast path: when `node.actor_owns_peer` is
        // enabled, the peer's `ActivePeer` lives inside the per-peer
        // actor task. Ship the raw packet there (best-effort sync
        // try_send) and return — the actor handles header re-parse,
        // FMP decrypt, per-peer mutations, and link dispatch on its
        // own task. This thins rx_loop to just header parse + lookup
        // + enqueue, freeing it for concurrent peers.
        if let Some(actor) = self.peer_actors.get(&node_addr) {
            if !actor.try_dispatch_packet(Box::new(packet)) {
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    "Per-peer actor queue full / closed — dropping packet"
                );
            }
            return;
        }

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
    pub(in crate::node) fn classify_inbound_packet(
        &mut self,
        packet: ReceivedPacket,
    ) -> InboundClassify {
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return InboundClassify::Inline(packet),
        };
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let node_addr = match self.peers_by_index.get(&key) {
            Some(id) => *id,
            None => return InboundClassify::Inline(packet),
        };
        // K-bit flip: rare, lives on inline path.
        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;
        let peer = match self.peers.get(&node_addr) {
            Some(p) => p,
            None => return InboundClassify::Inline(packet),
        };
        if received_k_bit != peer.current_k_bit() && peer.pending_new_session().is_some() {
            return InboundClassify::Inline(packet);
        }
        let session = match peer.noise_session() {
            Some(s) => s,
            None => return InboundClassify::Inline(packet),
        };
        // Pre-decrypt replay check (don't ADVANCE the window — that
        // happens in apply_decrypted_elem after the worker confirms
        // a valid AEAD tag).
        if session.check_replay(header.counter).is_err() {
            return InboundClassify::Replay;
        }
        let key_current = match session.recv_cipher_clone() {
            Some(k) => k,
            None => return InboundClassify::Inline(packet),
        };
        let key_previous = peer.previous_session().and_then(|s| s.recv_cipher_clone());

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

    /// Apply a worker-decrypted element to the FMP receive pipeline.
    /// Called from `rx_loop` when the AEAD pool's completion arm fires.
    /// Mirrors the inline path's per-peer mutations + dispatch but
    /// against an already-decrypted plaintext.
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
            peer.link_stats()
                .record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);
        } else {
            return;
        }

        let link_message = &plaintext[INNER_TIMESTAMP_LEN..];
        self.dispatch_link_message(&node_addr, link_message, ce_flag)
            .await;
    }
}
