//! End-to-end session message handlers.
//!
//! Handles locally-delivered session payloads from SessionDatagram envelopes.
//! Dispatches based on FSP common prefix phase to specific handlers for
//! SessionSetup (Noise XK msg1), SessionAck (msg2), SessionMsg3 (msg3),
//! encrypted data, and error signals (CoordsRequired, PathBroken).

use crate::NodeAddr;
use crate::mmp::report::ReceiverReport;
use crate::mmp::{MAX_SESSION_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS};
use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::session_wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_FLAG_CP, FSP_FLAG_K, FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE,
    FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3, FSP_PORT_HEADER_SIZE,
    FSP_PORT_IPV6_SHIM, FspCommonPrefix, FspEncryptedHeader, build_fsp_header,
    fsp_prepend_inner_header, fsp_strip_inner_header, parse_encrypted_coords,
};
use crate::node::{Node, NodeEndpointCommand, NodeEndpointEvent, NodeEndpointPeer, NodeError};
use crate::noise::{
    HandshakeState, XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE, XK_HANDSHAKE_MSG3_SIZE,
};
use crate::protocol::{
    CoordsRequired, FspInnerFlags, MtuExceeded, PathBroken, PathMtuNotification, SessionAck,
    SessionDatagram, SessionMessageType, SessionMsg3, SessionReceiverReport, SessionSenderReport,
    SessionSetup,
};
use crate::protocol::{coords_wire_size, encode_coords};
use crate::upper::icmp::FIPS_OVERHEAD;
use secp256k1::PublicKey;
use tracing::{debug, info, trace, warn};

/// Output of the single-borrow steady-state block in
/// [`Node::handle_encrypted_session_msg`]. Carries the small amount of
/// state the post-borrow path needs (the decrypted plaintext +
/// inner-header fields), or which slow path (UnknownSession,
/// NotEstablished, BadInnerHeader, DecryptFailed) to take after the
/// `&mut entry` borrow on `self.sessions` drops. Lets the steady-state
/// AEAD + MMP + path-MTU work all run under one `get_mut(src_addr)`
/// instead of seven `self.sessions` operations per packet.
enum FspFrameOutcome {
    /// FSP frame decrypted successfully; ready to dispatch by msg_type.
    /// `plaintext` is the full inner-decoded payload — the per-msg_type
    /// payload starts at offset `FSP_INNER_HEADER_SIZE`.
    Authentic {
        plaintext: Vec<u8>,
        msg_type: u8,
        inner_flags_byte: u8,
        timestamp: u32,
    },
    /// `self.sessions` had no entry for the source address.
    UnknownSession,
    /// Session entry exists but the XK handshake hasn't completed yet.
    NotEstablished,
    /// Decrypted payload was shorter than `FSP_INNER_HEADER_SIZE`.
    BadInnerHeader,
    /// Both current and previous (drain-window) AEAD attempts failed.
    /// `consecutive` tracks the post-failure counter; if it crossed the
    /// threshold, `reinit_pubkey` is `Some(remote_pubkey)` so the
    /// post-borrow path can drop the stale session and start a fresh
    /// XK handshake against the same peer.
    DecryptFailed {
        error: crate::noise::NoiseError,
        counter: u64,
        consecutive: u32,
        reinit_pubkey: Option<PublicKey>,
    },
}

/// Drop the end-to-end session and start a fresh XK handshake after this
/// many consecutive AEAD decryption failures from a peer. Recovers from
/// stale session state on either side (e.g. peer restarted with new keys
/// but our entry still holds the old keys, or vice versa) without
/// requiring a manual daemon restart.
const DECRYPT_FAILURE_REINIT_THRESHOLD: u32 = 32;
/// After a new FSP session is established, stale packets encrypted under the
/// previous session can still be in flight through the mesh. Do not let those
/// packets immediately trip the reinit threshold for the fresh session.
const DECRYPT_FAILURE_REINIT_GRACE_MS: u64 = 5_000;

fn pending_rekey_wins_tiebreak(
    our_addr: &NodeAddr,
    peer_addr: &NodeAddr,
    existing: &SessionEntry,
) -> bool {
    existing.pending_new_session().is_some()
        && existing.is_rekey_initiator()
        && our_addr < peer_addr
}

fn session_decrypt_failure_in_grace(entry: &SessionEntry, now_ms: u64) -> bool {
    let session_start_ms = entry.session_start_ms();
    session_start_ms != 0
        && now_ms.saturating_sub(session_start_ms) < DECRYPT_FAILURE_REINIT_GRACE_MS
}

impl Node {
    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches based on the 4-byte FSP common prefix:
    ///
    /// - Phase 0x1 → SessionSetup (handshake msg1)
    /// - Phase 0x2 → SessionAck (handshake msg2)
    /// - Phase 0x3 → SessionMsg3 (XK handshake msg3)
    /// - Phase 0x0 + U flag → plaintext error signal (CoordsRequired/PathBroken)
    /// - Phase 0x0 + !U → encrypted session message (data, reports, etc.)
    pub(in crate::node) async fn handle_session_payload(
        &mut self,
        src_addr: &NodeAddr,
        payload: &[u8],
        path_mtu: u16,
        ce_flag: bool,
        previous_hop: Option<NodeAddr>,
    ) {
        let prefix = match FspCommonPrefix::parse(payload) {
            Some(p) => p,
            None => {
                debug!(
                    len = payload.len(),
                    "Session payload too short for FSP prefix"
                );
                return;
            }
        };

        let inner = &payload[FSP_COMMON_PREFIX_SIZE..];

        match prefix.phase {
            FSP_PHASE_MSG1 => {
                self.handle_session_setup(src_addr, inner).await;
            }
            FSP_PHASE_MSG2 => {
                self.handle_session_ack(src_addr, inner).await;
            }
            FSP_PHASE_MSG3 => {
                self.handle_session_msg3(src_addr, inner).await;
            }
            FSP_PHASE_ESTABLISHED if prefix.is_unencrypted() => {
                // Plaintext error signals: read msg_type from first byte after prefix
                if inner.is_empty() {
                    debug!("Empty plaintext error signal");
                    return;
                }
                let error_type = inner[0];
                let error_body = &inner[1..];
                match SessionMessageType::from_byte(error_type) {
                    Some(SessionMessageType::CoordsRequired) => {
                        self.handle_coords_required(error_body).await;
                    }
                    Some(SessionMessageType::PathBroken) => {
                        self.handle_path_broken(error_body).await;
                    }
                    Some(SessionMessageType::MtuExceeded) => {
                        self.handle_mtu_exceeded(error_body).await;
                    }
                    _ => {
                        debug!(error_type, "Unknown plaintext error signal type");
                    }
                }
            }
            FSP_PHASE_ESTABLISHED => {
                self.handle_encrypted_session_msg(
                    src_addr,
                    payload,
                    path_mtu,
                    ce_flag,
                    previous_hop,
                )
                .await;
            }
            _ => {
                debug!(phase = prefix.phase, "Unknown FSP phase");
            }
        }
    }

    /// Handle an encrypted session message (phase 0x0, U flag clear).
    ///
    /// Full FSP receive pipeline:
    /// 1. Parse FspEncryptedHeader (12 bytes) → counter, flags, header_bytes
    /// 2. If CP flag: parse cleartext coords, cache them
    /// 3. Session lookup (must be Established)
    /// 4. AEAD decrypt with AAD = header_bytes
    /// 5. Strip FSP inner header → timestamp, msg_type, inner_flags
    /// 6. Dispatch by msg_type
    async fn handle_encrypted_session_msg(
        &mut self,
        src_addr: &NodeAddr,
        payload: &[u8],
        path_mtu: u16,
        ce_flag: bool,
        previous_hop: Option<NodeAddr>,
    ) {
        let _t_fsp_handle =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspHandle);
        // Parse the 12-byte encrypted header (includes the 4-byte prefix)
        let header = match FspEncryptedHeader::parse(payload) {
            Some(h) => h,
            None => {
                debug!(
                    len = payload.len(),
                    "Encrypted session message too short for FSP header"
                );
                return;
            }
        };

        // Determine where ciphertext starts (after header, optionally after coords)
        let mut ciphertext_offset = FSP_HEADER_SIZE;

        // If CP flag set, parse cleartext coords between header and ciphertext
        if header.has_coords() {
            let coord_data = &payload[FSP_HEADER_SIZE..];
            match parse_encrypted_coords(coord_data) {
                Ok((src_coords, dest_coords, bytes_consumed)) => {
                    let now_ms = Self::now_ms();
                    if let Some(coords) = src_coords {
                        self.coord_cache.insert(*src_addr, coords, now_ms);
                    }
                    if let Some(coords) = dest_coords {
                        self.coord_cache.insert(*self.node_addr(), coords, now_ms);
                    }
                    ciphertext_offset += bytes_consumed;
                }
                Err(e) => {
                    debug!(error = %e, "Failed to parse coords from encrypted session message");
                    return;
                }
            }
        }

        let ciphertext = &payload[ciphertext_offset..];
        let received_k_bit = header.flags & FSP_FLAG_K != 0;

        // Single &mut sessions[src_addr] borrow for is_established,
        // K-bit detect+handle, AEAD decrypt, drain-window fallback,
        // failure-counter bookkeeping (rehandshake threshold), inner-
        // header strip, MMP receive, and path-MTU observation. Down
        // from 7 `self.sessions` operations per packet
        // (get + get + get_mut + remove + insert + get_mut + get_mut)
        // to a single `get_mut`. Slow-path operations that need
        // `&mut self` (decrypt-failure logging, msg_type dispatch into
        // sub-handlers, session re-initiation after threshold) run
        // after the borrow drops, communicated via `FspFrameOutcome`.
        let outcome: FspFrameOutcome = 'outcome: {
            let entry = match self.sessions.get_mut(src_addr) {
                Some(e) => e,
                None => break 'outcome FspFrameOutcome::UnknownSession,
            };
            if !entry.is_established() {
                break 'outcome FspFrameOutcome::NotEstablished;
            }

            // K-bit flip detection. Read + cutover share the borrow.
            // Logging uses `src_addr` (a NodeAddr) directly because
            // `self.peer_display_name` would conflict with the &mut
            // borrow on `self.sessions`. K-bit flips are rare so a
            // less-friendly log identifier on this line is acceptable.
            if received_k_bit != entry.current_k_bit() && entry.pending_new_session().is_some() {
                info!(
                    src = %src_addr,
                    "Peer FSP K-bit flip detected, promoting new session"
                );
                let now_ms = Self::now_ms();
                entry.handle_peer_kbit_flip(now_ms);
            }

            let session = match entry.state_mut() {
                EndToEndState::Established(s) => s,
                _ => break 'outcome FspFrameOutcome::NotEstablished,
            };

            let primary = {
                let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
                session.decrypt_with_replay_check_and_aad(
                    ciphertext,
                    header.counter,
                    &header.header_bytes,
                )
            };
            let plaintext = match primary {
                Ok(pt) => pt,
                Err(primary_err) => {
                    // Drain-window fallback on the same &mut entry borrow.
                    let drain = entry.previous_noise_session_mut().and_then(|prev| {
                        prev.decrypt_with_replay_check_and_aad(
                            ciphertext,
                            header.counter,
                            &header.header_bytes,
                        )
                        .ok()
                    });
                    match drain {
                        Some(pt) => pt,
                        None => {
                            // Both current and previous failed. During
                            // post-establish grace we treat this as stale
                            // old-session traffic; after that, bump the
                            // consecutive-failure counter and surface a
                            // re-handshake hint if the threshold is crossed.
                            let now_ms = Self::now_ms();
                            let (consecutive, reinit_pubkey) =
                                if session_decrypt_failure_in_grace(entry, now_ms) {
                                    (0, None)
                                } else {
                                    let consecutive = entry.record_decrypt_failure();
                                    let reinit_pubkey =
                                        if consecutive >= DECRYPT_FAILURE_REINIT_THRESHOLD {
                                            Some(*entry.remote_pubkey())
                                        } else {
                                            None
                                        };
                                    (consecutive, reinit_pubkey)
                                };
                            break 'outcome FspFrameOutcome::DecryptFailed {
                                error: primary_err,
                                counter: header.counter,
                                consecutive,
                                reinit_pubkey,
                            };
                        }
                    }
                }
            };

            // Successful decrypt — reset the per-session failure
            // counter so a single bad packet doesn't carry forward
            // toward the threshold.
            entry.reset_decrypt_failures();

            // Strip FSP inner header (6 bytes) for the timestamp +
            // msg_type + inner_flags fields. The rest of the buffer
            // (the per-msg_type payload) is re-derived as
            // `&plaintext[FSP_INNER_HEADER_SIZE..]` outside the borrow
            // scope, since `rest` would otherwise borrow from
            // `plaintext` and prevent us from returning owned
            // `plaintext` from the labeled block.
            let (timestamp, msg_type, inner_flags_byte) = match fsp_strip_inner_header(&plaintext) {
                Some((ts, mt, inf, _rest)) => (ts, mt, inf),
                None => break 'outcome FspFrameOutcome::BadInnerHeader,
            };

            // MMP receive bookkeeping + path-MTU observation. Same
            // &mut entry borrow — collapses the two consecutive
            // `self.sessions.get_mut(src_addr) + entry.mmp_mut()`
            // blocks (and the matching pair of `Instant::now()`
            // calls) from the original implementation into one.
            if let Some(mmp) = entry.mmp_mut() {
                let now = std::time::Instant::now();
                mmp.receiver
                    .record_recv(header.counter, timestamp, plaintext.len(), ce_flag, now);
                // Spin bit: advance state machine for correct TX
                // reflection. RTT samples not fed into SRTT —
                // timestamp-echo provides accurate RTT; spin bit
                // includes variable inter-frame delays.
                let inner_flags = FspInnerFlags::from_byte(inner_flags_byte);
                let _spin_rtt = mmp
                    .spin_bit
                    .rx_observe(inner_flags.spin_bit, header.counter, now);
                // Feed path_mtu from datagram envelope to MMP path
                // MTU tracking. Done for ALL session messages, not
                // just DataPackets, so the destination learns the
                // path MTU even when only reports flow.
                mmp.path_mtu.observe_incoming_mtu(path_mtu);
            }

            FspFrameOutcome::Authentic {
                plaintext,
                msg_type,
                inner_flags_byte,
                timestamp,
            }
        };

        // The &mut entry borrow on self.sessions has dropped. Handle
        // slow-path outcomes and dispatch by msg_type (which calls
        // other &mut self handlers).
        let (plaintext, msg_type, _inner_flags_byte, _timestamp) = match outcome {
            FspFrameOutcome::Authentic {
                plaintext,
                msg_type,
                inner_flags_byte,
                timestamp,
            } => (plaintext, msg_type, inner_flags_byte, timestamp),
            FspFrameOutcome::UnknownSession => {
                debug!(src = %self.peer_display_name(src_addr), "Encrypted session message for unknown session");
                return;
            }
            FspFrameOutcome::NotEstablished => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Encrypted message but session not established (awaiting handshake completion)"
                );
                return;
            }
            FspFrameOutcome::BadInnerHeader => {
                debug!(src = %self.peer_display_name(src_addr), "Decrypted payload too short for FSP inner header");
                return;
            }
            FspFrameOutcome::DecryptFailed {
                error,
                counter,
                consecutive,
                reinit_pubkey,
            } => {
                debug!(
                    error = %error, src = %self.peer_display_name(src_addr),
                    counter, consecutive_failures = consecutive,
                    "Session AEAD decryption failed"
                );
                if let Some(dest_pubkey) = reinit_pubkey {
                    warn!(
                        peer = %self.peer_display_name(src_addr),
                        consecutive_failures = consecutive,
                        "Session AEAD failures exceeded threshold; dropping session and re-initiating"
                    );
                    // Remove the stale session so initiate_session
                    // sees no existing entry and starts fresh.
                    self.sessions.remove(src_addr);
                    if let Err(re_err) = self.initiate_session(*src_addr, dest_pubkey).await {
                        debug!(
                            error = %re_err,
                            peer = %self.peer_display_name(src_addr),
                            "Failed to re-initiate session after decrypt-failure threshold"
                        );
                    }
                }
                return;
            }
        };

        // Reverse-route learning runs after the borrow drops
        // (`learn_reverse_route` takes `&mut self`).
        if let Some(next_hop) = previous_hop {
            self.learn_reverse_route(*src_addr, next_hop);
        }

        // Capture the post-inner-header length now, before any branch
        // takes ownership of `plaintext` (the EndpointData arm drains
        // the inner header off the front and forwards the Vec to
        // `deliver_endpoint_data` rather than allocating a fresh Vec).
        let rest_len = plaintext.len() - FSP_INNER_HEADER_SIZE;
        let rest = &plaintext[FSP_INNER_HEADER_SIZE..];

        // Dispatch by msg_type
        match SessionMessageType::from_byte(msg_type) {
            Some(SessionMessageType::DataPacket) => {
                // msg_type 0x10: port-multiplexed service dispatch
                if rest.len() < FSP_PORT_HEADER_SIZE {
                    debug!(len = rest.len(), "DataPacket too short for port header");
                    return;
                }
                let dst_port = u16::from_le_bytes([rest[2], rest[3]]);
                let service_payload = &rest[FSP_PORT_HEADER_SIZE..];

                match dst_port {
                    FSP_PORT_IPV6_SHIM => {
                        use crate::FipsAddress;
                        let src_ipv6 = FipsAddress::from_node_addr(src_addr).to_ipv6().octets();
                        let dst_ipv6 = FipsAddress::from_node_addr(self.node_addr())
                            .to_ipv6()
                            .octets();

                        match crate::upper::ipv6_shim::decompress_ipv6(
                            service_payload,
                            src_ipv6,
                            dst_ipv6,
                        ) {
                            Some(mut packet) => {
                                if ce_flag {
                                    mark_ipv6_ecn_ce(&mut packet);
                                    self.stats_mut().congestion.record_ce_received();
                                }
                                if self.external_packet_tx.is_some() {
                                    self.deliver_external_ipv6_packet(src_addr, packet);
                                } else if let Some(tun_tx) = &self.tun_tx {
                                    let _t = crate::perf_profile::Timer::start(
                                        crate::perf_profile::Stage::TunWrite,
                                    );
                                    if let Err(e) = tun_tx.send(packet) {
                                        debug!(error = %e, "Failed to deliver decompressed IPv6 packet to TUN");
                                    }
                                } else {
                                    trace!(
                                        src = %self.peer_display_name(src_addr),
                                        "IPv6 shim packet decompressed (no TUN interface)"
                                    );
                                }
                            }
                            None => {
                                debug!(
                                    src = %self.peer_display_name(src_addr),
                                    len = service_payload.len(),
                                    "IPv6 shim decompression failed"
                                );
                            }
                        }
                    }
                    _ => {
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            dst_port,
                            "Unknown FSP service port, dropping DataPacket"
                        );
                    }
                }
            }
            Some(SessionMessageType::EndpointData) => {
                // Hand the plaintext Vec straight through to the endpoint
                // event queue instead of `rest.to_vec()`-ing a fresh
                // allocation. `Vec::drain` does a single memmove of the
                // payload to the front of the existing buffer (no realloc,
                // no second 1500-byte memcpy), trimming the inner-header
                // prefix in place. At 174 kpps single-stream that's one
                // allocation + one big memcpy saved per packet on the
                // dominant FIPS-endpoint receive path.
                let mut payload = plaintext;
                payload.drain(..FSP_INNER_HEADER_SIZE);
                self.deliver_endpoint_data(src_addr, payload);
            }
            Some(SessionMessageType::SenderReport) => {
                self.handle_session_sender_report(src_addr, rest);
            }
            Some(SessionMessageType::ReceiverReport) => {
                self.handle_session_receiver_report(src_addr, rest);
            }
            Some(SessionMessageType::PathMtuNotification) => {
                self.handle_session_path_mtu_notification(src_addr, rest);
            }
            Some(SessionMessageType::CoordsWarmup) => {
                // Standalone coordinate warming — coords already extracted
                // from CP flag by transit nodes. No action needed at endpoint.
                trace!(src = %self.peer_display_name(src_addr), "CoordsWarmup received");
            }
            _ => {
                debug!(src = %self.peer_display_name(src_addr), msg_type, "Unknown session message type, dropping");
            }
        }

        // Only application data resets the idle timer and traffic counters —
        // MMP reports (SenderReport, ReceiverReport, PathMtuNotification) do not.
        if (msg_type == SessionMessageType::DataPacket.to_byte()
            || msg_type == SessionMessageType::EndpointData.to_byte())
            && let Some(entry) = self.sessions.get_mut(src_addr)
        {
            entry.record_recv(rest_len);
            entry.touch(Self::now_ms());
        }

        // Flush any pending outbound packets (e.g., simultaneous initiation
        // where responder also had queued outbound packets)
        self.flush_pending_packets(src_addr).await;
    }

    /// Handle an incoming SessionSetup (Noise XK msg1).
    ///
    /// The remote node wants to establish an end-to-end session with us.
    /// We create an XK responder handshake, process msg1, send SessionAck with msg2,
    /// and transition to AwaitingMsg3.
    async fn handle_session_setup(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let setup = match SessionSetup::decode(inner) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Malformed SessionSetup");
                return;
            }
        };

        if setup.handshake_payload.len() != XK_HANDSHAKE_MSG1_SIZE {
            debug!(
                len = setup.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG1_SIZE,
                "Invalid handshake payload size in SessionSetup"
            );
            return;
        }

        // Check for existing session with this remote
        if let Some(existing) = self.sessions.get(src_addr) {
            if existing.is_initiating() {
                // Simultaneous initiation: smaller NodeAddr wins as initiator
                if self.identity.node_addr() < src_addr {
                    // We win — drop their setup, they'll process ours
                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "Simultaneous session initiation: we win (smaller addr), dropping their setup"
                    );
                    return;
                }
                // We lose — discard our pending handshake, become responder below
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Simultaneous session initiation: we lose, becoming responder"
                );
            } else if existing.is_awaiting_msg3() {
                // Duplicate setup while we already sent msg2 — resend stored ack
                if let Some(payload) = existing.handshake_payload() {
                    debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, resending SessionAck");
                    let my_addr = *self.node_addr();
                    let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload.to_vec())
                        .with_ttl(self.config.node.session.default_ttl);
                    if let Err(e) = self.send_session_datagram(&mut datagram).await {
                        debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to resend SessionAck");
                    }
                } else {
                    debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, no stored ack to resend");
                }
                return;
            } else if existing.is_established() {
                // Rekey: if rekey enabled, treat as rekey for key rotation.
                // The existing established session remains active for traffic.
                if self.config.node.rekey.enabled {
                    let rekey_in_progress = existing.has_rekey_in_progress();
                    let has_pending = existing.pending_new_session().is_some();

                    // Dual-initiation detection: both sides sent SessionSetup
                    // simultaneously. Apply tie-breaker — smaller NodeAddr
                    // wins as initiator (same as initial session setup).
                    if rekey_in_progress {
                        if self.identity.node_addr() < src_addr {
                            // We win as initiator — drop their msg1.
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "Dual FSP rekey initiation: we win (smaller addr), dropping their msg1"
                            );
                            return;
                        }
                        // We lose — abandon our rekey, become responder below.
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            "Dual FSP rekey initiation: we lose (larger addr), abandoning ours"
                        );
                        let entry = self.sessions.get_mut(src_addr).unwrap();
                        entry.abandon_rekey();
                    } else if has_pending {
                        if pending_rekey_wins_tiebreak(
                            self.identity.node_addr(),
                            src_addr,
                            existing,
                        ) {
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "FSP rekey msg1 received while local pending rekey wins tiebreak, dropping"
                            );
                            return;
                        }

                        debug!(
                            src = %self.peer_display_name(src_addr),
                            local_pending_initiator = existing.is_rekey_initiator(),
                            "FSP rekey msg1 received with stale pending rekey, abandoning pending and responding"
                        );
                        let entry = self.sessions.get_mut(src_addr).unwrap();
                        entry.abandon_rekey();
                    }
                    let our_keypair = self.identity.keypair();
                    let mut handshake = HandshakeState::new_xk_responder(our_keypair);
                    handshake.set_local_epoch(self.startup_epoch);

                    if let Err(e) = handshake.read_xk_message_1(&setup.handshake_payload) {
                        debug!(error = %e, "Failed to process rekey XK msg1");
                        return;
                    }

                    // Generate msg2
                    let msg2 = match handshake.write_xk_message_2() {
                        Ok(m) => m,
                        Err(e) => {
                            debug!(error = %e, "Failed to generate rekey XK msg2");
                            return;
                        }
                    };

                    // Build and send SessionAck
                    let our_coords = self.tree_state.my_coords().clone();
                    let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
                    let ack_payload = ack.encode();
                    let my_addr = *self.node_addr();
                    let mut datagram = SessionDatagram::new(my_addr, *src_addr, ack_payload)
                        .with_ttl(self.config.node.session.default_ttl);

                    if let Err(e) = self.send_session_datagram(&mut datagram).await {
                        debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionAck");
                        return;
                    }

                    // Store rekey state on the existing entry
                    let now_ms = Self::now_ms();
                    let entry = self.sessions.get_mut(src_addr).unwrap();
                    entry.set_rekey_state(handshake, false);
                    entry.record_peer_rekey(now_ms);

                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "FSP rekey: processed peer's msg1, sent msg2, awaiting msg3"
                    );
                    return;
                }

                // Re-establishment: replace existing session below
                debug!(src = %self.peer_display_name(src_addr), "Session re-establishment from peer");
            }
        }

        // Create XK responder handshake and process msg1
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_responder(our_keypair);
        handshake.set_local_epoch(self.startup_epoch);

        if let Err(e) = handshake.read_xk_message_1(&setup.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg1 in SessionSetup");
            return;
        }

        // XK: responder does NOT learn initiator's identity until msg3
        // Use a placeholder pubkey from src_addr for the session entry.
        // The real pubkey will be registered when msg3 arrives.

        // Generate msg2
        let msg2 = match handshake.write_xk_message_2() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XK msg2 for SessionAck");
                return;
            }
        };

        // Build and send SessionAck (include initiator's coords for return-path warming)
        let our_coords = self.tree_state.my_coords().clone();
        let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
        let ack_payload = ack.encode();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, ack_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route the ack back to the initiator
        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionAck");
            return;
        }

        // Store session entry in AwaitingMsg3 state with ack payload for potential resend.
        // Use a dummy pubkey since we don't know the initiator's identity yet.
        // We use our own pubkey as placeholder; it will be replaced in handle_session_msg3.
        let placeholder_pubkey = self.identity.keypair().public_key();
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let mut entry = SessionEntry::new(
            *src_addr,
            placeholder_pubkey,
            EndToEndState::AwaitingMsg3(handshake),
            now_ms,
            false,
        );
        entry.set_handshake_payload(ack_payload, now_ms + resend_interval);
        self.sessions.insert(*src_addr, entry);

        debug!(src = %self.peer_display_name(src_addr), "SessionSetup processed (XK), SessionAck sent, awaiting msg3");
    }

    /// Handle an incoming SessionAck (Noise XK msg2).
    ///
    /// Processes msg2, generates and sends msg3, then transitions to Established.
    async fn handle_session_ack(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let ack = match SessionAck::decode(inner) {
            Ok(a) => a,
            Err(e) => {
                debug!(error = %e, "Malformed SessionAck");
                return;
            }
        };

        if ack.handshake_payload.len() != XK_HANDSHAKE_MSG2_SIZE {
            debug!(
                len = ack.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG2_SIZE,
                "Invalid handshake payload size in SessionAck"
            );
            return;
        }

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck for unknown session");
                return;
            }
        };

        // Rekey path: entry is Established with rekey_state
        if entry.is_established() && entry.has_rekey_in_progress() && entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XK msg2
            if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg2");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Generate XK msg3
            let msg3 = match handshake.write_xk_message_3() {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = %e, "Failed to generate rekey XK msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Send SessionMsg3
            let msg3_wire = SessionMsg3::new(msg3);
            let msg3_payload = msg3_wire.encode();
            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
                .with_ttl(self.config.node.session.default_ttl);

            if let Err(e) = self.send_session_datagram(&mut datagram).await {
                debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionMsg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            entry.set_pending_session(session);
            entry.set_rekey_completed_ms(Self::now_ms());
            self.sessions.insert(*src_addr, entry);

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as initiator, pending cutover"
            );
            return;
        }

        // Must be in Initiating state — check before take to avoid poisoning
        if !entry.is_initiating() {
            debug!(src = %self.peer_display_name(src_addr), "SessionAck but session not in Initiating state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::Initiating(hs)) => hs,
            _ => unreachable!("checked is_initiating above"),
        };

        // Process XK msg2: read_xk_message_2 (extracts responder's epoch)
        if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg2 in SessionAck");
            return; // Entry was already removed, don't put back a broken session
        }

        // Generate XK msg3: write_xk_message_3 (sends encrypted static + epoch)
        let msg3 = match handshake.write_xk_message_3() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XK msg3");
                return;
            }
        };

        // Send SessionMsg3 (phase 0x3)
        let msg3_wire = SessionMsg3::new(msg3);
        let msg3_payload = msg3_wire.encode();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
            .with_ttl(self.config.node.session.default_ttl);

        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionMsg3");
            return;
        }

        // Complete the handshake: into_session()
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session after XK msg3");
                return;
            }
        };

        let now_ms = Self::now_ms();
        entry.set_state(EndToEndState::Established(session));
        entry.set_coords_warmup_remaining(self.config.node.session.coords_warmup_packets);
        entry.mark_established(now_ms);
        entry.init_mmp(&self.config.node.session_mmp);
        entry.clear_handshake_payload();
        entry.touch(now_ms);
        self.sessions.insert(*src_addr, entry);
        self.coord_cache.insert(*src_addr, ack.src_coords, now_ms);

        // Flush any queued outbound packets for this destination
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (initiator, XK)");
    }

    /// Handle an incoming SessionMsg3 (Noise XK msg3).
    ///
    /// The initiator reveals their encrypted static key. The responder
    /// processes msg3, learns the initiator's identity, and transitions
    /// to Established.
    async fn handle_session_msg3(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let msg3 = match SessionMsg3::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed SessionMsg3");
                return;
            }
        };

        if msg3.handshake_payload.len() != XK_HANDSHAKE_MSG3_SIZE {
            debug!(
                len = msg3.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG3_SIZE,
                "Invalid handshake payload size in SessionMsg3"
            );
            return;
        }

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 for unknown session");
                return;
            }
        };

        // Rekey path: entry is Established with rekey_state (responder side)
        if entry.is_established() && entry.has_rekey_in_progress() && !entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XK msg3
            if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete the handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            entry.set_pending_session(session);
            self.sessions.insert(*src_addr, entry);

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as responder, pending cutover"
            );
            return;
        }

        // Must be in AwaitingMsg3 state
        if !entry.is_awaiting_msg3() {
            debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 but session not in AwaitingMsg3 state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::AwaitingMsg3(hs)) => hs,
            _ => unreachable!("checked is_awaiting_msg3 above"),
        };

        // Process XK msg3: read_xk_message_3 (extracts initiator's static key and epoch)
        if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg3");
            return; // Entry was already removed
        }

        // Extract the initiator's static public key (now available after msg3)
        let remote_pubkey = match handshake.remote_static() {
            Some(pk) => *pk,
            None => {
                debug!("No remote static key after processing XK msg3");
                return;
            }
        };

        // Register the initiator's identity for future TUN → session routing
        self.register_identity(*src_addr, remote_pubkey);

        // Complete the handshake
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session from XK handshake");
                return;
            }
        };

        let now_ms = Self::now_ms();
        // Replace the placeholder pubkey with the real one
        let mut new_entry = SessionEntry::new(
            *src_addr,
            remote_pubkey,
            EndToEndState::Established(session),
            now_ms,
            false,
        );
        new_entry.set_coords_warmup_remaining(self.config.node.session.coords_warmup_packets);
        new_entry.mark_established(now_ms);
        new_entry.init_mmp(&self.config.node.session_mmp);
        new_entry.touch(now_ms);
        self.sessions.insert(*src_addr, new_entry);

        // Flush any pending packets
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (responder, XK)");
    }

    // === Session-layer MMP report handlers ===

    /// Handle an incoming session-layer SenderReport (msg_type 0x11).
    ///
    /// Informational only — the peer is telling us about what they sent.
    /// Logged but not used for metrics (same pattern as link-layer).
    fn handle_session_sender_report(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let sr = match SessionSenderReport::decode(body) {
            Ok(sr) => sr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionSenderReport");
                return;
            }
        };

        trace!(
            src = %self.peer_display_name(src_addr),
            cum_pkts = sr.cumulative_packets_sent,
            interval_bytes = sr.interval_bytes_sent,
            "Received SessionSenderReport"
        );
    }

    /// Handle an incoming session-layer ReceiverReport (msg_type 0x12).
    ///
    /// The peer is telling us about what they received from us. We feed
    /// this to our metrics to compute RTT, loss rate, and trend indicators.
    fn handle_session_receiver_report(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let session_rr = match SessionReceiverReport::decode(body) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionReceiverReport");
                return;
            }
        };

        // Convert to link-layer ReceiverReport for MmpMetrics processing
        let rr: ReceiverReport = ReceiverReport::from(&session_rr);

        let now_ms = Self::now_ms();
        let peer_name = self.peer_display_name(src_addr);
        let entry = match self.sessions.get_mut(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %peer_name, "SessionReceiverReport for unknown session");
                return;
            }
        };

        let our_timestamp_ms = entry.session_timestamp(now_ms);

        let Some(mmp) = entry.mmp_mut() else {
            return;
        };

        let now = std::time::Instant::now();
        mmp.metrics
            .process_receiver_report(&rr, our_timestamp_ms, now);

        // Feed SRTT back to sender/receiver report interval tuning (session-layer bounds)
        if let Some(srtt_ms) = mmp.metrics.srtt_ms() {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.receiver.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            // Also update PathMtu notification interval from SRTT
            mmp.path_mtu.update_interval_from_srtt(srtt_ms);
        }

        // Update reverse delivery ratio from our own receiver state, using per-interval deltas.
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

        trace!(
            src = %peer_name,
            rtt_ms = ?mmp.metrics.srtt_ms(),
            loss = format_args!("{:.1}%", mmp.metrics.loss_rate() * 100.0),
            "Processed SessionReceiverReport"
        );
    }

    /// Handle an incoming PathMtuNotification (msg_type 0x13).
    ///
    /// The destination is telling us the path MTU has changed.
    /// Apply source-side rules (decrease immediate, increase validated).
    pub(in crate::node) fn handle_session_path_mtu_notification(
        &mut self,
        src_addr: &NodeAddr,
        body: &[u8],
    ) {
        let notif = match PathMtuNotification::decode(body) {
            Ok(n) => n,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed PathMtuNotification");
                return;
            }
        };

        let peer_name = self.peer_display_name(src_addr);
        let entry = match self.sessions.get_mut(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %peer_name, "PathMtuNotification for unknown session");
                return;
            }
        };

        let Some(mmp) = entry.mmp_mut() else {
            return;
        };

        let old_mtu = mmp.path_mtu.current_mtu();
        let now = std::time::Instant::now();
        let changed = mmp.path_mtu.apply_notification(notif.path_mtu, now);
        let new_mtu = mmp.path_mtu.current_mtu();

        if !changed {
            return;
        }

        debug!(
            src = %peer_name,
            old_mtu,
            new_mtu,
            "Path MTU changed via notification"
        );

        // Mirror the new effective MTU into the FipsAddress-keyed lookup used
        // by the TUN reader/writer at TCP MSS clamp time. Without this, new
        // TCP flows opened on a path the proactive end-to-end echo has
        // already tightened keep getting clamped by the staler discovery-
        // time value until a reactive MtuExceeded happens to fire. Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(src_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= new_mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu,
                        existing,
                        "PathMtuNotification: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, new_mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "PathMtuNotification: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    new_mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; PathMtuNotification not reflected"
                );
            }
        }
    }

    /// Handle a CoordsRequired error signal from a transit router.
    ///
    /// The router couldn't route our packet because it lacks cached
    /// coordinates for the destination. Send a standalone CoordsWarmup
    /// immediately (rate-limited), trigger discovery, and reset the
    /// warmup counter for subsequent data packets.
    async fn handle_coords_required(&mut self, inner: &[u8]) {
        self.stats_mut().errors.coords_required += 1;

        let msg = match CoordsRequired::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed CoordsRequired");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "CoordsRequired: transit router needs coordinates"
        );

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
            if let Some(entry) = self.sessions.get(&msg.dest_addr)
                && entry.is_established()
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to CoordsRequired");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "CoordsRequired response rate-limited, skipping standalone CoordsWarmup");
        }

        // Only trigger discovery if we have the target's identity cached —
        // otherwise we can't verify the LookupResponse proof.
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after CoordsRequired: no cached identity for target");
        }

        // Reset coords warmup counter so the next N packets also include
        // COORDS_PRESENT, re-warming transit caches along the path.
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            let n = self.config.node.session.coords_warmup_packets;
            entry.set_coords_warmup_remaining(n);
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after CoordsRequired"
            );
        }
    }

    /// Handle a PathBroken error signal from a transit router.
    ///
    /// The router has coordinates but still can't route to the destination.
    /// Send a standalone CoordsWarmup immediately (rate-limited), invalidate
    /// cached coordinates, trigger re-discovery, and reset the warmup counter.
    async fn handle_path_broken(&mut self, inner: &[u8]) {
        self.stats_mut().errors.path_broken += 1;

        let msg = match PathBroken::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed PathBroken");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "PathBroken: transit router reports routing failure"
        );

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
            if let Some(entry) = self.sessions.get(&msg.dest_addr)
                && entry.is_established()
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to PathBroken");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "PathBroken response rate-limited, skipping standalone CoordsWarmup");
        }

        // Invalidate stale cached coordinates
        self.coord_cache.remove(&msg.dest_addr);

        // Trigger re-discovery to get fresh coordinates, but only if we have
        // the target's identity cached — otherwise we can't verify the
        // LookupResponse proof. This avoids a race when the XK responder
        // receives PathBroken before msg3 completes (identity unknown).
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after PathBroken: no cached identity for target");
        }

        // Reset coords warmup counter so the next N packets include
        // COORDS_PRESENT, re-warming transit caches along the new path.
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            let n = self.config.node.session.coords_warmup_packets;
            entry.set_coords_warmup_remaining(n);
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after PathBroken"
            );
        }
    }

    /// Handle an MtuExceeded error signal from a transit router.
    ///
    /// A transit router couldn't forward our packet because it exceeded the
    /// next-hop transport MTU. Apply the reported bottleneck MTU to our
    /// PathMtuState for the affected session, causing an immediate decrease.
    pub(in crate::node) async fn handle_mtu_exceeded(&mut self, inner: &[u8]) {
        self.stats_mut().errors.mtu_exceeded += 1;

        let msg = match MtuExceeded::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed MtuExceeded");
                return;
            }
        };

        let peer_name = self.peer_display_name(&msg.dest_addr);
        debug!(
            dest = %peer_name,
            reporter = %msg.reporter,
            bottleneck_mtu = msg.mtu,
            "MtuExceeded: transit router reports oversized packet"
        );

        // Apply to PathMtuState: immediate decrease via apply_notification()
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            let old_mtu = mmp.path_mtu.current_mtu();
            let now = std::time::Instant::now();
            if mmp.path_mtu.apply_notification(msg.mtu, now) {
                let new_mtu = mmp.path_mtu.current_mtu();
                info!(
                    dest = %peer_name,
                    old_mtu,
                    new_mtu,
                    reporter = %msg.reporter,
                    "Path MTU decreased via reactive MtuExceeded signal"
                );
            }
        }

        // Mirror the bottleneck into the FipsAddress-keyed lookup used by
        // the TUN reader/writer at TCP MSS clamp time. Discovery's reverse-
        // path response can carry a value too generous for the actual
        // forward path; the reactive signal from a forwarder that actually
        // dropped a packet is authoritative for "what fits". Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(&msg.dest_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= msg.mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        existing,
                        "Reactive MtuExceeded: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, msg.mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "Reactive MtuExceeded: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    bottleneck_mtu = msg.mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; reactive MtuExceeded not reflected"
                );
            }
        }
    }

    // === Session Initiation (Send Path) ===

    /// Initiate an end-to-end session with a remote node.
    ///
    /// Creates a Noise XK handshake as initiator, wraps msg1 in a
    /// SessionSetup, encapsulates in a SessionDatagram, and routes
    /// toward the destination.
    pub(in crate::node) async fn initiate_session(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
    ) -> Result<(), NodeError> {
        // Check for existing session
        if let Some(existing) = self.sessions.get(&dest_addr)
            && (existing.is_established() || existing.is_initiating())
        {
            return Ok(());
        }

        // Create Noise XK initiator handshake
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_initiator(our_keypair, dest_pubkey);
        handshake.set_local_epoch(self.startup_epoch);
        let msg1 = handshake
            .write_xk_message_1()
            .map_err(|e| NodeError::SendFailed {
                node_addr: dest_addr,
                reason: format!("Noise XK msg1 generation failed: {}", e),
            })?;

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(&dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
        let setup_payload = setup.encode();

        // Wrap in SessionDatagram
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, dest_addr, setup_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route toward destination
        self.send_session_datagram(&mut datagram).await?;

        // Register destination identity for TUN → session routing
        self.register_identity(dest_addr, dest_pubkey);

        // Store session entry with handshake payload for potential resend
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let mut entry = SessionEntry::new(
            dest_addr,
            dest_pubkey,
            EndToEndState::Initiating(handshake),
            now_ms,
            true,
        );
        entry.set_handshake_payload(setup_payload, now_ms + resend_interval);
        self.sessions.insert(dest_addr, entry);

        debug!(dest = %self.peer_display_name(&dest_addr), "Session initiation started");
        Ok(())
    }

    /// Send application data over an established session.
    ///
    /// Uses the FSP pipeline: builds a 12-byte cleartext header (used as AAD),
    /// prepends the 6-byte inner header to the plaintext, encrypts with AAD,
    /// optionally inserts cleartext coords, and wraps in a SessionDatagram.
    ///
    /// The `src_port` and `dst_port` identify the service. A 4-byte port header
    /// `[src_port:2 LE][dst_port:2 LE]` is prepended to `payload` inside the
    /// AEAD envelope. The receiver dispatches by `dst_port`.
    pub(in crate::node) async fn send_session_data(
        &mut self,
        dest_addr: &NodeAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        // First borrow: read session metadata (NLL releases before coord decision)
        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let wants_coords = entry.coords_warmup_remaining() > 0;
        let timestamp = entry.session_timestamp(now_ms);
        let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());
        if !entry.is_established() {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "session not established".into(),
            });
        }

        // Build port-prefixed plaintext: [src_port:2 LE][dst_port:2 LE][payload...]
        let mut port_payload = Vec::with_capacity(FSP_PORT_HEADER_SIZE + payload.len());
        port_payload.extend_from_slice(&src_port.to_le_bytes());
        port_payload.extend_from_slice(&dst_port.to_le_bytes());
        port_payload.extend_from_slice(payload);

        // Build inner plaintext (doesn't depend on counter)
        let msg_type = SessionMessageType::DataPacket.to_byte(); // 0x10
        let inner_flags = FspInnerFlags { spin_bit }.to_byte();
        let inner_plaintext =
            fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &port_payload);

        // Determine whether coords fit within transport MTU.
        // If not, send standalone CoordsWarmup before the data packet.
        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire =
                FIPS_OVERHEAD as usize + FSP_PORT_HEADER_SIZE + coords_size + payload.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                // Coords don't fit piggybacked — send standalone CoordsWarmup first
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before data packet");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        // Decrement warmup counter if we sent coords (piggybacked or standalone)
        if wants_coords && let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        }

        // Build FSP flags (CP flag if coords, K-bit for key epoch)
        let mut flags = if include_coords { FSP_FLAG_CP } else { 0 };
        if let Some(entry) = self.sessions.get(dest_addr)
            && entry.current_k_bit()
        {
            flags |= FSP_FLAG_K;
        }

        // Borrow session for counter + encryption (after potential standalone send)
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let session = match entry.state_mut() {
            EndToEndState::Established(s) => s,
            _ => {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "session not established".into(),
                });
            }
        };
        let counter = session.current_send_counter();

        // Build 12-byte FSP header (used as AAD for AEAD)
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, flags, payload_len);

        // Encrypt with AAD binding to the FSP header
        let ciphertext = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspEncrypt);
            session
                .encrypt_with_aad(&inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?
        };

        // Assemble: header(12) + [coords] + ciphertext
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len() + 200);
        fsp_payload.extend_from_slice(&header);
        if let (Some(src), Some(dst)) = (&my_coords, &dest_coords) {
            encode_coords(src, &mut fsp_payload);
            encode_coords(dst, &mut fsp_payload);
        }
        fsp_payload.extend_from_slice(&ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Re-borrow after send (which borrowed &mut self)
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.record_sent(payload.len());
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender.record_sent(counter, timestamp, ciphertext.len());
            }
            entry.touch(now_ms);
        }

        Ok(())
    }

    /// Send an IPv6 packet through the IPv6 shim (port 256) with header compression.
    ///
    /// Compresses the IPv6 header (format 0x00), then sends via `send_session_data`
    /// with `src_port=256, dst_port=256`.
    pub(in crate::node) async fn send_ipv6_packet(
        &mut self,
        dest_addr: &NodeAddr,
        ipv6_packet: &[u8],
    ) -> Result<(), NodeError> {
        let compressed = crate::upper::ipv6_shim::compress_ipv6(ipv6_packet).ok_or_else(|| {
            NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "IPv6 header compression failed".into(),
            }
        })?;
        self.send_session_data(
            dest_addr,
            FSP_PORT_IPV6_SHIM,
            FSP_PORT_IPV6_SHIM,
            &compressed,
        )
        .await
    }

    /// Handle an embedded endpoint data command.
    pub(in crate::node) async fn handle_endpoint_data_command(
        &mut self,
        command: NodeEndpointCommand,
    ) {
        match command {
            NodeEndpointCommand::Send {
                remote,
                payload,
                response_tx,
            } => {
                let _t =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
                let result = self.send_endpoint_data(remote, payload).await;
                let _ = response_tx.send(result);
            }
            NodeEndpointCommand::SendOneway { remote, payload } => {
                let _t =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
                // Result deliberately discarded — caller wanted
                // fire-and-forget. Errors still get logged inside
                // `send_endpoint_data` so they're not silent.
                let _ = self.send_endpoint_data(remote, payload).await;
            }
            NodeEndpointCommand::PeerSnapshot { response_tx } => {
                let peers = self
                    .peers()
                    .map(|peer| {
                        let link_id = peer.link_id();
                        let transport_type = self.get_link(&link_id).and_then(|link| {
                            self.get_transport(&link.transport_id())
                                .map(|handle| handle.transport_type().name.to_string())
                        });
                        let stats = peer.link_stats();
                        NodeEndpointPeer {
                            npub: peer.npub(),
                            transport_addr: peer.current_addr().map(|addr| addr.to_string()),
                            transport_type,
                            link_id: link_id.as_u64(),
                            srtt_ms: peer
                                .mmp()
                                .and_then(|mmp| mmp.metrics.srtt_ms())
                                .map(|srtt| srtt.round() as u64),
                            packets_sent: stats.packets_sent,
                            packets_recv: stats.packets_recv,
                            bytes_sent: stats.bytes_sent,
                            bytes_recv: stats.bytes_recv,
                        }
                    })
                    .collect();
                let _ = response_tx.send(peers);
            }
        }
    }

    pub(in crate::node) async fn send_endpoint_data(
        &mut self,
        remote: crate::PeerIdentity,
        payload: Vec<u8>,
    ) -> Result<(), NodeError> {
        let dest_addr = *remote.node_addr();
        let dest_pubkey = remote.pubkey_full();
        self.register_identity(dest_addr, dest_pubkey);
        self.send_or_queue_endpoint_data(dest_addr, Some(dest_pubkey), payload)
            .await
    }

    async fn send_or_queue_endpoint_data(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: Option<PublicKey>,
        payload: Vec<u8>,
    ) -> Result<(), NodeError> {
        if let Some(entry) = self.sessions.get(&dest_addr) {
            if entry.is_established() {
                return self.send_session_endpoint_data(&dest_addr, &payload).await;
            }
            self.queue_pending_endpoint_data(dest_addr, payload);
            return Ok(());
        }

        let dest_pubkey = dest_pubkey
            .or_else(|| self.pubkey_for_node_addr(&dest_addr))
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: dest_addr,
                reason: "unknown remote identity for endpoint data".into(),
            })?;
        if self.find_next_hop(&dest_addr).is_none() {
            self.queue_pending_endpoint_data(dest_addr, payload);
            self.maybe_initiate_lookup(&dest_addr).await;
            return Ok(());
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {}
            Err(NodeError::SendFailed { node_addr, reason })
                if node_addr == dest_addr && reason == "no route to destination" =>
            {
                self.queue_pending_endpoint_data(dest_addr, payload);
                self.maybe_initiate_lookup(&dest_addr).await;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        self.queue_pending_endpoint_data(dest_addr, payload);
        Ok(())
    }

    /// Send app-owned endpoint bytes over an established session without DataPacket ports.
    async fn send_session_endpoint_data(
        &mut self,
        dest_addr: &NodeAddr,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        if payload.len() > u16::MAX as usize - FSP_INNER_HEADER_SIZE {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "endpoint data payload too long".into(),
            });
        }

        let now_ms = Self::now_ms();

        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let wants_coords = entry.coords_warmup_remaining() > 0;
        let timestamp = entry.session_timestamp(now_ms);
        let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());
        if !entry.is_established() {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "session not established".into(),
            });
        }

        let msg_type = SessionMessageType::EndpointData.to_byte();
        let inner_flags = FspInnerFlags { spin_bit }.to_byte();
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, payload);

        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire = FIPS_OVERHEAD as usize + coords_size + payload.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before endpoint data");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        if wants_coords && let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        }

        let mut flags = if include_coords { FSP_FLAG_CP } else { 0 };
        if let Some(entry) = self.sessions.get(dest_addr)
            && entry.current_k_bit()
        {
            flags |= FSP_FLAG_K;
        }

        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let session = match entry.state_mut() {
            EndToEndState::Established(s) => s,
            _ => {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "session not established".into(),
                });
            }
        };
        let counter = session.current_send_counter();
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, flags, payload_len);
        let ciphertext = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspEncrypt);
            session
                .encrypt_with_aad(&inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?
        };

        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len() + 200);
        fsp_payload.extend_from_slice(&header);
        if let (Some(src), Some(dst)) = (&my_coords, &dest_coords) {
            encode_coords(src, &mut fsp_payload);
            encode_coords(dst, &mut fsp_payload);
        }
        fsp_payload.extend_from_slice(&ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.record_sent(payload.len());
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender.record_sent(counter, timestamp, ciphertext.len());
            }
            entry.touch(now_ms);
        }

        Ok(())
    }

    fn deliver_endpoint_data(&self, src_addr: &NodeAddr, payload: Vec<u8>) {
        let Some(endpoint_event_tx) = &self.endpoint_event_tx else {
            trace!(
                src = %self.peer_display_name(src_addr),
                "Endpoint data received without an attached endpoint"
            );
            return;
        };

        let event = NodeEndpointEvent::Data {
            source_node_addr: *src_addr,
            source_npub: self.npub_for_node_addr(src_addr),
            payload,
        };

        let _t_deliver =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
        if let Err(error) = endpoint_event_tx.send(event) {
            debug!(
                src = %self.peer_display_name(src_addr),
                error = %error,
                "Failed to deliver endpoint data event"
            );
        }
    }

    /// Send a non-data session message (reports, notifications) over an established session.
    ///
    /// Similar to `send_session_data()` but:
    /// - Takes an explicit `msg_type` byte (0x11, 0x12, 0x13, etc.)
    /// - Never includes COORDS_PRESENT (reports are lightweight)
    /// - Reads spin bit from MMP state for the inner header
    /// - Records the send in MMP sender state
    pub(in crate::node) async fn send_session_msg(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        // Read spin bit and session timestamp from entry
        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let timestamp = entry.session_timestamp(now_ms);
        let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());

        // Build inner flags with spin bit
        let inner_flags = FspInnerFlags { spin_bit }.to_byte();

        // Get mutable access for encryption
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;

        // Read K-bit before mutable borrow of session state
        let k_flags = if entry.current_k_bit() { FSP_FLAG_K } else { 0 };

        let session = match entry.state_mut() {
            EndToEndState::Established(s) => s,
            _ => {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "session not established".into(),
                });
            }
        };

        let counter = session.current_send_counter();

        // FSP inner header + plaintext
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, payload);

        // Build 12-byte FSP header (K-bit for key epoch, no CP for reports)
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, k_flags, payload_len);

        // Encrypt with AAD
        let ciphertext = session
            .encrypt_with_aad(&inner_plaintext, &header)
            .map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
            })?;

        // Assemble: header(12) + ciphertext (no coords)
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len());
        fsp_payload.extend_from_slice(&header);
        fsp_payload.extend_from_slice(&ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP sender state (no touch — MMP reports don't reset idle timer)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender.record_sent(counter, timestamp, ciphertext.len());
        }

        Ok(())
    }

    /// Send a standalone CoordsWarmup message to warm transit node caches.
    ///
    /// Constructs an encrypted FSP message with CP flag set and
    /// msg_type=CoordsWarmup. Transit nodes extract the cleartext
    /// coordinates via `try_warm_coord_cache()` (same as CP-flagged data
    /// packets). The encrypted inner payload is the 6-byte inner header
    /// with no application data.
    async fn send_coords_warmup(&mut self, dest_addr: &NodeAddr) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        let my_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);

        // Read session metadata
        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let timestamp = entry.session_timestamp(now_ms);
        let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());

        // Get mutable access for encryption
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let session = match entry.state_mut() {
            EndToEndState::Established(s) => s,
            _ => {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "session not established".into(),
                });
            }
        };

        let counter = session.current_send_counter();

        // FSP inner header only, no body payload
        let msg_type = SessionMessageType::CoordsWarmup.to_byte();
        let inner_flags = FspInnerFlags { spin_bit }.to_byte();
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &[]);

        // Build FSP header with CP flag
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, FSP_FLAG_CP, payload_len);

        // Encrypt with AAD
        let ciphertext = session
            .encrypt_with_aad(&inner_plaintext, &header)
            .map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
            })?;

        // Assemble: header(12) + coords + ciphertext
        let coords_size = coords_wire_size(&my_coords) + coords_wire_size(&dest_coords);
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + coords_size + ciphertext.len());
        fsp_payload.extend_from_slice(&header);
        encode_coords(&my_coords, &mut fsp_payload);
        encode_coords(&dest_coords, &mut fsp_payload);
        fsp_payload.extend_from_slice(&ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP (infrastructure traffic — no idle timer touch)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender.record_sent(counter, timestamp, ciphertext.len());
        }

        debug!(dest = %self.peer_display_name(dest_addr), "Sent standalone CoordsWarmup");
        Ok(())
    }

    /// Route and send a SessionDatagram through the mesh.
    ///
    /// Finds the next hop for the destination, seeds path_mtu from the
    /// first-hop transport MTU, and sends as an encrypted link message.
    pub(in crate::node) async fn send_session_datagram(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<(), NodeError> {
        let next_hop_addr = match self.find_next_hop(&datagram.dest_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                return Err(NodeError::SendFailed {
                    node_addr: datagram.dest_addr,
                    reason: "no route to destination".into(),
                });
            }
        };

        // Seed path_mtu from the first-hop transport MTU (same as forwarding path)
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            if let Some(addr) = peer.current_addr() {
                datagram.path_mtu = datagram.path_mtu.min(transport.link_mtu(addr));
            } else {
                datagram.path_mtu = datagram.path_mtu.min(transport.mtu());
            }
        }

        // Source-side: seed our PathMtuState.current_mtu from the outbound
        // transport MTU so it doesn't stay at u16::MAX until the destination
        // sends a PathMtuNotification back.
        if let Some(entry) = self.sessions.get_mut(&datagram.dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.path_mtu.seed_source_mtu(datagram.path_mtu);
        }

        let encoded = datagram.encode();
        if let Err(err) = self
            .send_encrypted_link_message(&next_hop_addr, &encoded)
            .await
        {
            self.record_route_failure(datagram.dest_addr, next_hop_addr);
            return Err(err);
        }
        self.stats_mut().forwarding.record_originated(encoded.len());
        Ok(())
    }

    /// Look up destination coordinates from available caches.
    ///
    /// Returns our own coordinates as a fallback (the SessionSetup will
    /// carry src_coords for return path routing; empty dest_coords
    /// would fail wire encoding since TreeCoordinate requires ≥1 entry).
    pub(in crate::node) fn get_dest_coords(&self, dest: &NodeAddr) -> crate::tree::TreeCoordinate {
        let now_ms = Self::now_ms();
        if let Some(coords) = self.coord_cache.get(dest, now_ms) {
            return coords.clone();
        }
        // Fallback: use our own coordinates. The SessionSetup dest_coords
        // field cannot be empty (wire format requires ≥1 entry). Using our
        // own coords is safe — transit routers will still cache them, and
        // the destination will return its actual coords in the SessionAck.
        self.tree_state.my_coords().clone()
    }

    /// Current Unix time in milliseconds.
    pub(in crate::node) fn now_ms() -> u64 {
        crate::time::now_ms()
    }

    // === TUN Outbound (Data Plane) ===

    /// Handle an outbound IPv6 packet from the TUN reader.
    ///
    /// Extracts the destination FipsAddress, looks up the NodeAddr and PublicKey
    /// from the identity cache, and either sends through an established session
    /// or initiates a new one (queuing the packet until established).
    ///
    /// Also performs MTU checking: if the packet (plus FIPS overhead) exceeds
    /// the transport MTU, an ICMP Packet Too Big message is sent back to the
    /// source and the packet is dropped.
    pub(in crate::node) async fn handle_tun_outbound(&mut self, ipv6_packet: Vec<u8>) {
        // Validate IPv6 header
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            return;
        }

        // Check if packet will fit after FIPS encapsulation
        let effective_mtu = self.effective_ipv6_mtu() as usize;
        if ipv6_packet.len() > effective_mtu {
            self.send_icmpv6_packet_too_big(&ipv6_packet, effective_mtu as u32);
            return;
        }

        // Extract destination FipsAddress prefix (IPv6 dest bytes 1-15)
        // IPv6 header: bytes 24-39 are dest addr, so prefix = bytes 25-39
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&ipv6_packet[25..40]);

        // Look up in identity cache
        let (dest_addr, dest_pubkey) = match self.lookup_by_fips_prefix(&prefix) {
            Some((addr, pk)) => (addr, pk),
            None => {
                self.send_icmpv6_dest_unreachable(&ipv6_packet);
                return;
            }
        };

        // Check for established session
        if let Some(entry) = self.sessions.get(&dest_addr) {
            if entry.is_established() {
                // Check per-destination path MTU learned from MtuExceeded signals.
                // The first oversized packet is forwarded normally and triggers
                // the MtuExceeded signal; subsequent packets are caught here and
                // generate ICMPv6 Packet Too Big back to the application.
                if let Some(mmp) = entry.mmp() {
                    let path_mtu = mmp.path_mtu.current_mtu();
                    let path_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as usize;
                    if path_ipv6_mtu < effective_mtu && ipv6_packet.len() > path_ipv6_mtu {
                        self.send_icmpv6_packet_too_big(&ipv6_packet, path_ipv6_mtu as u32);
                        return;
                    }
                }
                if let Err(e) = self.send_ipv6_packet(&dest_addr, &ipv6_packet).await {
                    debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to send TUN packet via session");
                }
                return;
            }
            // Session exists but not yet established — queue the packet
            self.queue_pending_packet(dest_addr, ipv6_packet);
            return;
        }

        // No session: initiate one and queue the packet.
        // If session initiation fails (no route), trigger discovery and
        // queue the packet for retry when discovery completes.
        if let Err(e) = self.initiate_session(dest_addr, dest_pubkey).await {
            debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to initiate session, trying discovery");
            self.maybe_initiate_lookup(&dest_addr).await;
            self.queue_pending_packet(dest_addr, ipv6_packet);
            return;
        }
        self.queue_pending_packet(dest_addr, ipv6_packet);
    }

    /// Send ICMPv6 Destination Unreachable back through TUN.
    pub(in crate::node) fn send_icmpv6_dest_unreachable(&self, original_packet: &[u8]) {
        use crate::FipsAddress;
        use crate::upper::icmp::{
            DestUnreachableCode, build_dest_unreachable, should_send_icmp_error,
        };

        if !should_send_icmp_error(original_packet) {
            return;
        }

        let our_ipv6 = FipsAddress::from_node_addr(self.node_addr()).to_ipv6();
        if let Some(response) =
            build_dest_unreachable(original_packet, DestUnreachableCode::NoRoute, our_ipv6)
            && let Some(tun_tx) = &self.tun_tx
        {
            let _ = tun_tx.send(response);
        }
    }

    /// Send ICMPv6 Packet Too Big back through TUN.
    ///
    /// Rate-limited per source address to prevent ICMP floods from
    /// misconfigured applications sending repeated oversized packets.
    pub(in crate::node) fn send_icmpv6_packet_too_big(&mut self, original_packet: &[u8], mtu: u32) {
        use crate::upper::icmp::build_packet_too_big;
        use std::net::Ipv6Addr;

        // Extract source address for rate limiting
        if original_packet.len() < 40 {
            return;
        }
        let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[8..24]).unwrap());

        // Rate limit ICMP PTB messages per source
        if !self.icmp_rate_limiter.should_send(src_addr) {
            debug!(
                src = %src_addr,
                "Rate limiting ICMP Packet Too Big"
            );
            return;
        }

        // Use the original packet's *destination* as the ICMP source so the
        // kernel sees the PTB coming from a remote router, not from itself.
        // Linux ignores PTBs whose source matches a local address, which
        // causes a PMTUD blackhole when both src and ICMP-src are local.
        let dest_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[24..40]).unwrap());
        if let Some(response) = build_packet_too_big(original_packet, mtu, dest_addr)
            && let Some(tun_tx) = &self.tun_tx
        {
            debug!(
                original_src = %src_addr,
                original_dst = %dest_addr,
                packet_size = original_packet.len(),
                reported_mtu = mtu,
                "Sending ICMP Packet Too Big"
            );
            let _ = tun_tx.send(response);
        }
    }

    /// Queue a packet while waiting for session establishment.
    fn queue_pending_packet(&mut self, dest_addr: NodeAddr, packet: Vec<u8>) {
        // Reject if we already have too many pending destinations
        let max_dests = self.config.node.session.pending_max_destinations;
        if !self.pending_tun_packets.contains_key(&dest_addr)
            && self.pending_tun_packets.len() >= max_dests
        {
            return;
        }

        let queue = self.pending_tun_packets.entry(dest_addr).or_default();
        if queue.len() >= self.config.node.session.pending_packets_per_dest {
            queue.pop_front(); // Drop oldest
        }
        queue.push_back(packet);
    }

    /// Queue endpoint data while waiting for session establishment.
    fn queue_pending_endpoint_data(&mut self, dest_addr: NodeAddr, payload: Vec<u8>) {
        let max_dests = self.config.node.session.pending_max_destinations;
        if !self.pending_endpoint_data.contains_key(&dest_addr)
            && self.pending_endpoint_data.len() >= max_dests
        {
            return;
        }

        let queue = self.pending_endpoint_data.entry(dest_addr).or_default();
        if queue.len() >= self.config.node.session.pending_packets_per_dest {
            queue.pop_front();
        }
        queue.push_back(payload);
    }

    /// Flush pending packets for a destination whose session just reached Established.
    async fn flush_pending_packets(&mut self, dest_addr: &NodeAddr) {
        if let Some(packets) = self.pending_tun_packets.remove(dest_addr) {
            for packet in packets {
                if let Err(e) = self.send_ipv6_packet(dest_addr, &packet).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued TUN packet");
                    break;
                }
            }
        }

        if let Some(payloads) = self.pending_endpoint_data.remove(dest_addr) {
            for payload in payloads {
                if let Err(e) = self.send_session_endpoint_data(dest_addr, &payload).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued endpoint data");
                    break;
                }
            }
        }
    }

    /// Retry session initiation after discovery provided coordinates.
    ///
    /// Called when a LookupResponse arrives and we have pending TUN packets or
    /// endpoint data for the discovered target. The coord_cache now has coords, so
    /// `find_next_hop()` should succeed and the SessionSetup can be sent.
    pub(in crate::node) async fn retry_session_after_discovery(&mut self, dest_addr: NodeAddr) {
        // Look up the destination's public key from the identity cache
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&dest_addr.as_bytes()[0..15]);
        let dest_pubkey = match self.lookup_by_fips_prefix(&prefix) {
            Some((_, pk)) => pk,
            None => {
                debug!(dest = %self.peer_display_name(&dest_addr), "Discovery complete but no identity for session retry");
                return;
            }
        };

        // Skip if a session already exists
        if let Some(existing) = self.sessions.get(&dest_addr)
            && (existing.is_established() || existing.is_initiating())
        {
            return;
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {
                debug!(dest = %self.peer_display_name(&dest_addr), "Session initiated after discovery");
            }
            Err(e) => {
                debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Session retry after discovery failed");
            }
        }
    }
}

/// Mark ECN-CE in an IPv6 packet's Traffic Class field.
///
/// IPv6 Traffic Class occupies bits across bytes 0 and 1:
///   byte[0] bits[3:0] = TC[7:4]
///   byte[1] bits[7:4] = TC[3:0]
/// ECN is TC[1:0]. Only marks CE (0b11) if the packet is ECN-capable
/// (ECT(0) or ECT(1)). Packets with ECN=0b00 (Not-ECT) are never marked
/// per RFC 3168.
///
/// No checksum update needed: IPv6 has no header checksum, and the Traffic
/// Class field is not part of the TCP/UDP pseudo-header.
pub(in crate::node) fn mark_ipv6_ecn_ce(packet: &mut [u8]) {
    if packet.len() < 2 {
        return;
    }
    // Extract 8-bit Traffic Class from IPv6 header bytes 0-1
    let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let ecn = tc & 0x03;
    // Only mark CE on ECN-capable packets (ECT(0)=0b10 or ECT(1)=0b01)
    if ecn == 0 {
        return;
    }
    // Set both ECN bits to 1 (CE = 0b11)
    let new_tc = tc | 0x03;
    packet[0] = (packet[0] & 0xF0) | (new_tc >> 4);
    packet[1] = (new_tc << 4) | (packet[1] & 0x0F);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use crate::noise::NoiseSession;

    fn node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_xk_session(initiator: &Identity, responder: &Identity) -> NoiseSession {
        let mut initiator_hs =
            HandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
        let mut responder_hs = HandshakeState::new_xk_responder(responder.keypair());
        initiator_hs.set_local_epoch([1u8; 8]);
        responder_hs.set_local_epoch([2u8; 8]);

        let msg1 = initiator_hs.write_xk_message_1().unwrap();
        responder_hs.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder_hs.write_xk_message_2().unwrap();
        initiator_hs.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator_hs.write_xk_message_3().unwrap();
        responder_hs.read_xk_message_3(&msg3).unwrap();

        initiator_hs.into_session().unwrap()
    }

    fn established_entry(local: &Identity, peer: &Identity) -> SessionEntry {
        let session = make_xk_session(local, peer);
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(session),
            1000,
            true,
        )
    }

    #[test]
    fn pending_rekey_tiebreak_keeps_local_initiator_only_when_smaller() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        entry.set_pending_session(make_xk_session(&local, &peer));

        assert!(pending_rekey_wins_tiebreak(
            &node_addr(0x01),
            &node_addr(0x02),
            &entry
        ));
        assert!(!pending_rekey_wins_tiebreak(
            &node_addr(0x02),
            &node_addr(0x01),
            &entry
        ));
    }

    #[test]
    fn pending_rekey_tiebreak_does_not_keep_responder_pending() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_responder(local.keypair());
        entry.set_rekey_state(rekey, false);
        entry.set_pending_session(make_xk_session(&peer, &local));

        assert!(!pending_rekey_wins_tiebreak(
            &node_addr(0x01),
            &node_addr(0x02),
            &entry
        ));
    }

    #[test]
    fn session_decrypt_failure_grace_covers_fresh_sessions_only() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(10_000);

        assert!(session_decrypt_failure_in_grace(&entry, 14_999));
        assert!(!session_decrypt_failure_in_grace(&entry, 15_000));
    }
}
