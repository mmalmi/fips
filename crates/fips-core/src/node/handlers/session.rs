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
        // Single Arc clone + read lock for the hot path. Both K-bit flip
        // detection (cold) and decrypt + MMP record (hot) share the same
        // slot lookup so per-packet overhead is one HashMap get + one
        // Arc clone + one read-lock acquisition. K-bit flips fire once
        // per rekey and only at that point do we drop the read lock and
        // re-acquire as a write lock.
        if !self.sessions.contains_key(src_addr) {
            debug!(src = %self.peer_display_name(src_addr), "Encrypted session message for unknown session");
            return;
        }

        // Cold-path: peer K-bit flip detection — once per rekey only.
        let needs_flip = {
            let entry = self.sessions.get(src_addr).expect("just checked");
            entry.is_established()
                && received_k_bit != entry.current_k_bit()
                && entry.pending_new_session().is_some()
        };
        if needs_flip {
            info!(
                src = %src_addr,
                "Peer FSP K-bit flip detected, promoting new session"
            );
            let now_ms = Self::now_ms();
            if let Some(entry) = self.sessions.get_mut(src_addr) {
                entry.handle_peer_kbit_flip(now_ms);
            }
        }

        // Hot path: single &mut borrow for the whole pipeline (decrypt
        // + replay accept + MMP record). All work in this block stays
        // off `&mut self` so the borrow is fine.
        let outcome: FspFrameOutcome = 'outcome: {
            let entry = self
                .sessions
                .get_mut(src_addr)
                .expect("just checked");
            if !entry.is_established() {
                break 'outcome FspFrameOutcome::NotEstablished;
            }

            let session = match entry.state() {
                EndToEndState::Established(s) => s,
                _ => break 'outcome FspFrameOutcome::NotEstablished,
            };

            let primary = session.decrypt_with_replay_check_and_aad(
                ciphertext,
                header.counter,
                &header.header_bytes,
            );
            let plaintext = match primary {
                Ok(pt) => pt,
                Err(primary_err) => {
                    // Drain-window fallback via `&self` previous_noise_session.
                    let drain = entry.previous_noise_session().and_then(|prev| {
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
                            // Both current and previous failed. Bump
                            // the per-session consecutive-failure
                            // counter (atomic) and surface a re-handshake
                            // hint if the threshold is crossed.
                            let consecutive = entry.record_decrypt_failure();
                            let reinit_pubkey = if consecutive >= DECRYPT_FAILURE_REINIT_THRESHOLD {
                                Some(*entry.remote_pubkey())
                            } else {
                                None
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

            // Successful decrypt — reset the per-session failure counter
            // (atomic) so a single bad packet doesn't carry forward.
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

            // MMP receive bookkeeping + path-MTU observation. The Mutex
            // around `MmpSessionState` (step 7b-1) lets this fire from
            // a read lock on the SessionEntry.
            if let Some(mut mmp) = entry.mmp_mut() {
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
                self.deliver_endpoint_data(src_addr, rest.to_vec());
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
            entry.record_recv(rest.len());
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

        // Check for existing session with this remote. Snapshot relevant
        // state into a local enum and release the borrow before any
        // `&mut self` work below.
        #[derive(Clone)]
        enum ExistingKind {
            None,
            Initiating,
            AwaitingMsg3 { payload: Option<Vec<u8>> },
            Established { rekey_in_progress: bool, has_pending: bool },
            Other,
        }
        let kind = match self.sessions.get(src_addr) {
            None => ExistingKind::None,
            Some(existing) => {
                if existing.is_initiating() {
                    ExistingKind::Initiating
                } else if existing.is_awaiting_msg3() {
                    ExistingKind::AwaitingMsg3 {
                        payload: existing.handshake_payload().map(|p| p.to_vec()),
                    }
                } else if existing.is_established() {
                    ExistingKind::Established {
                        rekey_in_progress: existing.has_rekey_in_progress(),
                        has_pending: existing.pending_new_session().is_some(),
                    }
                } else {
                    ExistingKind::Other
                }
            }
        };
        if !matches!(kind, ExistingKind::None) {
            match kind {
                ExistingKind::None => unreachable!(),
                ExistingKind::Initiating => {
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
                }
                ExistingKind::AwaitingMsg3 { payload } => {
                    // Duplicate setup while we already sent msg2 — resend stored ack
                    if let Some(payload) = payload {
                        debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, resending SessionAck");
                        let my_addr = *self.node_addr();
                        let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload)
                            .with_ttl(self.config.node.session.default_ttl);
                        if let Err(e) = self.send_session_datagram(&mut datagram).await {
                            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to resend SessionAck");
                        }
                    } else {
                        debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, no stored ack to resend");
                    }
                    return;
                }
                ExistingKind::Established { rekey_in_progress, has_pending } => {
                // Rekey: if rekey enabled, treat as rekey for key rotation.
                // The existing established session remains active for traffic.
                if self.config.node.rekey.enabled {
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
                        if let Some(entry) = self.sessions.get_mut(src_addr) {
                            entry.abandon_rekey();
                        }
                    } else if has_pending {
                        // Guard: already have a pending session waiting for K-bit cutover
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            "FSP rekey msg1 received but already have pending session, dropping"
                        );
                        return;
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
                    if let Some(entry) = self.sessions.get_mut(src_addr) {
                        entry.set_rekey_state(handshake, false);
                        entry.record_peer_rekey(now_ms);
                    }

                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "FSP rekey: processed peer's msg1, sent msg2, awaiting msg3"
                    );
                    return;
                }

                // Re-establishment: replace existing session below
                debug!(src = %self.peer_display_name(src_addr), "Session re-establishment from peer");
                }
                ExistingKind::Other => {}
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

        // Direct-peer single-owner path: ship to the peer actor.
        // Otherwise (or with the feature flag off) keep the entry in
        // Node.sessions as today.
        let actor = if self.config.node.actor_owns_sessions {
            self.peer_actor_for(src_addr)
        } else {
            None
        };
        if let Some(actor) = actor {
            if !actor.try_take_session(Box::new(entry)) {
                debug!(src = %self.peer_display_name(src_addr),
                    "peer actor inbound channel full/closed; dropping responder session");
                return;
            }
        } else {
            self.sessions
                .insert(*src_addr, entry);
        }

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

        // Direct-peer + actor path: route msg2 processing into the
        // peer actor that owns the SessionEntry.
        if self.config.node.actor_owns_sessions
            && let Some(actor) = self.peer_actor_for(src_addr)
        {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if !actor
                .dispatch(crate::peer::actor::PeerInboundJob::ProcessFspMsg2 {
                    handshake_payload: ack.handshake_payload.clone(),
                    respond: tx,
                })
                .await
            {
                debug!(src = %self.peer_display_name(src_addr),
                    "peer actor channel closed before ProcessFspMsg2");
                return;
            }
            let result = match rx.await {
                Ok(r) => r,
                Err(_) => {
                    debug!(src = %self.peer_display_name(src_addr),
                        "peer actor dropped ProcessFspMsg2 oneshot");
                    return;
                }
            };
            let output = match result {
                Ok(o) => o,
                Err(e) => {
                    debug!(src = %self.peer_display_name(src_addr), error = %e,
                        "Peer actor ProcessFspMsg2 failed");
                    return;
                }
            };

            // Send the msg3 datagram on the wire.
            let msg3_wire = SessionMsg3::new(output.msg3_payload);
            let msg3_payload = msg3_wire.encode();
            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
                .with_ttl(self.config.node.session.default_ttl);
            if let Err(e) = self.send_session_datagram(&mut datagram).await {
                debug!(error = %e, dest = %self.peer_display_name(src_addr),
                    "Failed to send SessionMsg3 (actor path)");
                return;
            }

            // FreshEstablish post-work: cache initiator-known coords +
            // flush queued packets. RekeyPending: nothing extra.
            use crate::peer::actor::ProcessMsg2Flow;
            if matches!(output.flow, ProcessMsg2Flow::FreshEstablish) {
                let now_ms = Self::now_ms();
                self.coord_cache.insert(*src_addr, ack.src_coords, now_ms);
                self.flush_pending_packets(src_addr).await;
                info!(src = %self.peer_display_name(src_addr),
                    "Session established (initiator, XK, actor path)");
            } else {
                debug!(src = %self.peer_display_name(src_addr),
                    "FSP rekey: completed XK as initiator (actor path), pending cutover");
            }
            return;
        }

        // Legacy path — `Node.sessions` is the single owner. We can't
        // hold a `&mut SessionEntry` across `await self.send_session_datagram`
        // (second mutable borrow of self), so the pattern is: take the
        // handshake state out under a transient borrow, do the awaits,
        // then re-borrow to install the result.

        // Classify the entry so we know which flow to run.
        enum AckFlow {
            Missing,
            Rekey,
            FreshInitiating,
            Other,
        }
        let flow = match self.sessions.get(src_addr) {
            None => AckFlow::Missing,
            Some(e) if e.is_established() && e.has_rekey_in_progress() && e.is_rekey_initiator() => {
                AckFlow::Rekey
            }
            Some(e) if e.is_initiating() => AckFlow::FreshInitiating,
            _ => AckFlow::Other,
        };
        match flow {
            AckFlow::Missing => {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck for unknown session");
                return;
            }
            AckFlow::Other => {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck but session not in Initiating state");
                return;
            }
            AckFlow::Rekey => {}
            AckFlow::FreshInitiating => {}
        }

        if matches!(flow, AckFlow::Rekey) {
            let mut handshake = match self
                .sessions
                .get_mut(src_addr)
                .and_then(|e| e.take_rekey_state())
            {
                Some(hs) => hs,
                None => return,
            };

            // Process XK msg2
            if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg2");
                if let Some(entry) = self.sessions.get_mut(src_addr) {
                    entry.abandon_rekey();
                }
                return;
            }

            // Generate XK msg3
            let msg3 = match handshake.write_xk_message_3() {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = %e, "Failed to generate rekey XK msg3");
                    if let Some(entry) = self.sessions.get_mut(src_addr) {
                        entry.abandon_rekey();
                    }
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
                if let Some(entry) = self.sessions.get_mut(src_addr) {
                    entry.abandon_rekey();
                }
                return;
            }

            // Complete handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK");
                    if let Some(entry) = self.sessions.get_mut(src_addr) {
                        entry.abandon_rekey();
                    }
                    return;
                }
            };

            if let Some(entry) = self.sessions.get_mut(src_addr) {
                entry.set_pending_session(session);
                entry.set_rekey_completed_ms(Self::now_ms());
            }

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as initiator, pending cutover"
            );
            return;
        }
        // Fresh-initiating path — take the handshake out so we can
        // advance it; on error the entry's state field is left as None
        // (mirrors prior behaviour).
        let mut handshake = match self
            .sessions
            .get_mut(src_addr)
            .and_then(|e| e.take_state())
        {
            Some(EndToEndState::Initiating(hs)) => hs,
            _ => unreachable!("flow check guaranteed Initiating"),
        };

        // Process XK msg2: read_xk_message_2 (extracts responder's epoch)
        if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg2 in SessionAck");
            return;
        }

        // Generate XK msg3: write_xk_message_3 (sends encrypted static + epoch)
        let msg3 = match handshake.write_xk_message_3() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XK msg3");
                return;
            }
        };

        // Send SessionMsg3 (phase 0x3) — no session lock held across this await.
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
        let coords_warmup_packets = self.config.node.session.coords_warmup_packets;
        let session_mmp = self.config.node.session_mmp.clone();
        if let Some(entry) = self.sessions.get_mut(src_addr) {
            entry.set_state(EndToEndState::Established(session));
            entry.set_coords_warmup_remaining(coords_warmup_packets);
            entry.mark_established(now_ms);
            entry.init_mmp(&session_mmp);
            entry.clear_handshake_payload();
            entry.touch(now_ms);
        }
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

        // Direct-peer + actor path: route msg3 processing into the
        // peer actor that owns the SessionEntry.
        if self.config.node.actor_owns_sessions
            && let Some(actor) = self.peer_actor_for(src_addr)
        {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if !actor
                .dispatch(crate::peer::actor::PeerInboundJob::ProcessFspMsg3 {
                    handshake_payload: msg3.handshake_payload.clone(),
                    respond: tx,
                })
                .await
            {
                debug!(src = %self.peer_display_name(src_addr),
                    "peer actor channel closed before ProcessFspMsg3");
                return;
            }
            let result = match rx.await {
                Ok(r) => r,
                Err(_) => {
                    debug!(src = %self.peer_display_name(src_addr),
                        "peer actor dropped ProcessFspMsg3 oneshot");
                    return;
                }
            };
            let output = match result {
                Ok(o) => o,
                Err(e) => {
                    debug!(src = %self.peer_display_name(src_addr), error = %e,
                        "Peer actor ProcessFspMsg3 failed");
                    return;
                }
            };

            // Register the (now-known) initiator identity for TUN routing.
            self.register_identity(*src_addr, output.remote_pubkey);

            use crate::peer::actor::ProcessMsg3Flow;
            if matches!(output.flow, ProcessMsg3Flow::FreshEstablish) {
                self.flush_pending_packets(src_addr).await;
                info!(src = %self.peer_display_name(src_addr),
                    "Session established (responder, XK, actor path)");
            } else {
                debug!(src = %self.peer_display_name(src_addr),
                    "FSP rekey: processed peer's msg3 (actor path), pending cutover");
            }
            return;
        }

        // Classify entry state.
        enum Msg3Flow {
            Missing,
            Rekey,
            FreshAwaitingMsg3,
            Other,
        }
        let flow = match self.sessions.get(src_addr) {
            None => Msg3Flow::Missing,
            Some(e)
                if e.is_established() && e.has_rekey_in_progress() && !e.is_rekey_initiator() =>
            {
                Msg3Flow::Rekey
            }
            Some(e) if e.is_awaiting_msg3() => Msg3Flow::FreshAwaitingMsg3,
            _ => Msg3Flow::Other,
        };
        match flow {
            Msg3Flow::Missing => {
                debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 for unknown session");
                return;
            }
            Msg3Flow::Other => {
                debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 but session not in AwaitingMsg3 state");
                return;
            }
            Msg3Flow::Rekey => {}
            Msg3Flow::FreshAwaitingMsg3 => {}
        }

        if matches!(flow, Msg3Flow::Rekey) {
            let mut handshake = match self
                .sessions
                .get_mut(src_addr)
                .and_then(|e| e.take_rekey_state())
            {
                Some(hs) => hs,
                None => return,
            };

            // Process XK msg3
            if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg3");
                if let Some(entry) = self.sessions.get_mut(src_addr) {
                    entry.abandon_rekey();
                }
                return;
            }

            // Complete the handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK msg3");
                    if let Some(entry) = self.sessions.get_mut(src_addr) {
                        entry.abandon_rekey();
                    }
                    return;
                }
            };

            if let Some(entry) = self.sessions.get_mut(src_addr) {
                entry.set_pending_session(session);
            }

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as responder, pending cutover"
            );
            return;
        }

        // Fresh AwaitingMsg3 — take the handshake out, advance, then put back.
        let mut handshake = match self
            .sessions
            .get_mut(src_addr)
            .and_then(|e| e.take_state())
        {
            Some(EndToEndState::AwaitingMsg3(hs)) => hs,
            _ => unreachable!("flow check guaranteed AwaitingMsg3"),
        };

        // Process XK msg3: read_xk_message_3 (extracts initiator's static key and epoch)
        if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg3");
            return;
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
        // Replace the placeholder pubkey with the real one. We construct
        // a fresh entry and replace the slot's contents — equivalent to
        // the old remove/insert dance without actually re-keying the map.
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
        self.sessions
            .insert(*src_addr, new_entry);

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
            let is_established = self
                .sessions
                .get(&msg.dest_addr)
                .map(|s| s.is_established())
                .unwrap_or(false);
            if is_established
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
        let n = self.config.node.session.coords_warmup_packets;
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
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
            let is_established = self
                .sessions
                .get(&msg.dest_addr)
                .map(|s| s.is_established())
                .unwrap_or(false);
            if is_established
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
        let n = self.config.node.session.coords_warmup_packets;
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
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
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            if let Some(mmp) = entry.mmp_mut() {
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
        // Snapshot once: if peer-actor session ownership is on AND
        // the destination is a direct peer with a running actor task,
        // route through that actor for the rest of this call. Snapshot
        // includes the actor handle clone (cheap — mpsc::Sender +
        // Arc<Config> ref-count bump).
        let actor = if self.config.node.actor_owns_sessions {
            self.peer_actor_for(&dest_addr)
        } else {
            None
        };

        // Check for existing session.
        if let Some(actor) = &actor {
            // Ask the peer actor whether it already owns a session for
            // us. `QuerySnapshot` returns `None` if no session, or
            // `Some(snapshot)` we can inspect for state.
            let (tx, rx) = tokio::sync::oneshot::channel();
            if !actor
                .dispatch(crate::peer::actor::PeerInboundJob::QuerySnapshot(tx))
                .await
            {
                // Actor task is gone — fall back to legacy path.
            } else if let Ok(Some(snap)) = rx.await {
                use crate::peer::actor::SessionStateLabel;
                if matches!(
                    snap.state,
                    SessionStateLabel::Established | SessionStateLabel::Initiating
                ) {
                    return Ok(());
                }
            }
        } else if let Some(slot) = self.sessions.get(&dest_addr) {
            let existing = slot;
            if existing.is_established() || existing.is_initiating() {
                return Ok(());
            }
        }

        // Create Noise XK initiator handshake.
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_initiator(our_keypair, dest_pubkey);
        handshake.set_local_epoch(self.startup_epoch);
        let msg1 = handshake
            .write_xk_message_1()
            .map_err(|e| NodeError::SendFailed {
                node_addr: dest_addr,
                reason: format!("Noise XK msg1 generation failed: {}", e),
            })?;

        // Build SessionSetup with coordinates.
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(&dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
        let setup_payload = setup.encode();

        // Wrap in SessionDatagram.
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, dest_addr, setup_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route toward destination.
        self.send_session_datagram(&mut datagram).await?;

        // Register destination identity for TUN → session routing.
        self.register_identity(dest_addr, dest_pubkey);

        // Build the SessionEntry with handshake payload for potential resend.
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

        // Ship to peer actor (single owner) or insert into Node.sessions
        // (transit-endpoint or feature-flag-disabled fallback).
        if let Some(actor) = actor {
            if !actor.try_take_session(Box::new(entry)) {
                // Channel full / actor exited — surface as a transient
                // SendFailed; caller will retry. We DROP the freshly
                // built entry — no fallback to self.sessions because we
                // already started the handshake on the wire and the
                // duplication would be a single-owner-violation.
                return Err(NodeError::SendFailed {
                    node_addr: dest_addr,
                    reason: "peer actor inbound channel full or closed".into(),
                });
            }
        } else {
            self.sessions
                .insert(dest_addr, entry);
        }

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
        // Direct-peer + actor path: encrypt via the peer actor that
        // owns the SessionEntry, then route the returned fsp_payload.
        if self.config.node.actor_owns_sessions
            && let Some(actor) = self.peer_actor_for(dest_addr)
        {
            return self
                .send_session_data_via_actor(dest_addr, src_port, dst_port, payload, &actor)
                .await;
        }

        let now_ms = Self::now_ms();

        // First borrow: read session metadata
        let (wants_coords, timestamp, spin_bit) = {
            let slot = self
                .sessions
                .get(dest_addr)
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "no session".into(),
                })?;
            let entry = slot;
            if !entry.is_established() {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "session not established".into(),
                });
            }
            (
                entry.coords_warmup_remaining() > 0,
                entry.session_timestamp(now_ms),
                entry.mmp().is_some_and(|m| m.spin_bit.tx_bit()),
            )
        };

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
            let cur = entry.coords_warmup_remaining();
            entry.set_coords_warmup_remaining(cur.saturating_sub(1));
        }

        // Build FSP flags (CP flag if coords, K-bit for key epoch)
        let mut flags = if include_coords { FSP_FLAG_CP } else { 0 };
        if let Some(slot) = self.sessions.get(dest_addr) {
            let entry = slot;
            if entry.current_k_bit() {
                flags |= FSP_FLAG_K;
            }
        }

        // Encrypt under a single &mut borrow on the entry. No await
        // inside this block.
        let (counter, ciphertext, fsp_payload) = {
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
            let ciphertext = session
                .encrypt_with_aad(&inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?;
            let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len() + 200);
            fsp_payload.extend_from_slice(&header);
            if let (Some(src), Some(dst)) = (&my_coords, &dest_coords) {
                encode_coords(src, &mut fsp_payload);
                encode_coords(dst, &mut fsp_payload);
            }
            fsp_payload.extend_from_slice(&ciphertext);
            (counter, ciphertext, fsp_payload)
        };

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Re-borrow after send to record stats + touch last_activity.
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.record_sent(payload.len());
            if let Some(mut mmp) = entry.mmp_mut() {
                mmp.sender.record_sent(counter, timestamp, ciphertext.len());
            }
            entry.touch(now_ms);
        }

        Ok(())
    }

    /// Actor-owned send: encrypt through the peer actor's owned
    /// `SessionEntry`, then wrap in SessionDatagram and route.
    /// Mirrors `send_session_data`'s pre-encrypt prep (port-prefixed
    /// inner plaintext + coords pre-encoding) but delegates the FSP
    /// header build + AEAD encrypt + MMP/last-activity bookkeeping
    /// to the actor's `Encrypt` handler.
    async fn send_session_data_via_actor(
        &mut self,
        dest_addr: &NodeAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        actor: &crate::peer::actor::PeerActorHandle,
    ) -> Result<(), NodeError> {
        // Build port-prefixed plaintext (inner header is added by the
        // actor's `actor_encrypt`).
        let mut port_payload = Vec::with_capacity(FSP_PORT_HEADER_SIZE + payload.len());
        port_payload.extend_from_slice(&src_port.to_le_bytes());
        port_payload.extend_from_slice(&dst_port.to_le_bytes());
        port_payload.extend_from_slice(payload);

        // Pre-encode coords iff they fit in transport MTU. Actor checks
        // its own `coords_warmup_remaining` and decides whether to
        // splice them in.
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);
        let coords_size = coords_wire_size(&our_coords) + coords_wire_size(&dest_coords);
        let total_wire =
            FIPS_OVERHEAD as usize + FSP_PORT_HEADER_SIZE + coords_size + payload.len();
        let coords_payload_if_warmup = if total_wire <= self.transport_mtu() as usize {
            let mut buf = Vec::with_capacity(coords_size);
            encode_coords(&our_coords, &mut buf);
            encode_coords(&dest_coords, &mut buf);
            Some(buf)
        } else {
            None
        };

        // Send Encrypt request.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let msg_type = SessionMessageType::DataPacket.to_byte();
        if !actor
            .dispatch(crate::peer::actor::PeerInboundJob::Encrypt {
                msg_type,
                plaintext: port_payload,
                coords_payload_if_warmup,
                touch: true,
                respond: tx,
            })
            .await
        {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "peer actor inbound channel closed".into(),
            });
        }
        let result = rx.await.map_err(|_| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: "peer actor dropped Encrypt oneshot".into(),
        })?;
        let output = result.map_err(|e| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: format!("actor encrypt failed: {}", e),
        })?;

        // Wrap in SessionDatagram and route. Routing logic is Node-side
        // (find_next_hop, transports, peer state) and unchanged.
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, output.fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);
        self.send_session_datagram(&mut datagram).await?;
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
                let result = self.send_endpoint_data(remote, payload).await;
                let _ = response_tx.send(result);
            }
            NodeEndpointCommand::PeerSnapshot { response_tx } => {
                // Pre-collect link/transport info while we still have
                // immutable access to self.peers; otherwise the closure
                // would re-borrow self for every peer iteration.
                let peer_infos: Vec<(NodeEndpointPeer,)> = self
                    .peers()
                    .map(|slot| {
                        let peer = crate::peer::peer_read(slot);
                        let link_id = peer.link_id();
                        let transport_type = self.get_link(&link_id).and_then(|link| {
                            self.get_transport(&link.transport_id())
                                .map(|handle| handle.transport_type().name.to_string())
                        });
                        let stats = peer.link_stats();
                        (NodeEndpointPeer {
                            npub: peer.npub(),
                            transport_addr: peer.current_addr().map(|addr| addr.to_string()),
                            transport_type,
                            link_id: link_id.as_u64(),
                            srtt_ms: peer
                                .mmp()
                                .and_then(|mmp| mmp.metrics.srtt_ms())
                                .map(|srtt| srtt.round() as u64),
                            packets_sent: stats.packets_sent(),
                            packets_recv: stats.packets_recv(),
                            bytes_sent: stats.bytes_sent(),
                            bytes_recv: stats.bytes_recv(),
                        },)
                    })
                    .collect();
                let peers = peer_infos.into_iter().map(|(p,)| p).collect();
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
        if let Some(slot) = self.sessions.get(&dest_addr) {
            let is_established = slot.is_established();
            if is_established {
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

        // Direct-peer + actor path: pre-encode coords if they fit, ask
        // the actor to encrypt + assemble the FSP payload (it decides
        // whether to use the coords based on its owned warmup counter).
        if self.config.node.actor_owns_sessions
            && let Some(actor) = self.peer_actor_for(dest_addr)
        {
            let our_coords = self.tree_state.my_coords().clone();
            let dest_coords = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&our_coords) + coords_wire_size(&dest_coords);
            let total_wire = FIPS_OVERHEAD as usize + coords_size + payload.len();
            let coords_payload_if_warmup = if total_wire <= self.transport_mtu() as usize {
                let mut buf = Vec::with_capacity(coords_size);
                encode_coords(&our_coords, &mut buf);
                encode_coords(&dest_coords, &mut buf);
                Some(buf)
            } else {
                None
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            let msg_type = SessionMessageType::EndpointData.to_byte();
            if !actor
                .dispatch(crate::peer::actor::PeerInboundJob::Encrypt {
                    msg_type,
                    plaintext: payload.to_vec(),
                    coords_payload_if_warmup,
                    touch: true,
                    respond: tx,
                })
                .await
            {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "peer actor inbound channel closed".into(),
                });
            }
            let result = rx.await.map_err(|_| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "peer actor dropped Encrypt oneshot".into(),
            })?;
            let output = result.map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("actor encrypt failed: {}", e),
            })?;
            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *dest_addr, output.fsp_payload)
                .with_ttl(self.config.node.session.default_ttl);
            self.send_session_datagram(&mut datagram).await?;
            return Ok(());
        }

        let now_ms = Self::now_ms();

        let (wants_coords, timestamp, spin_bit) = {
            let slot = self
                .sessions
                .get(dest_addr)
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "no session".into(),
                })?;
            let entry = slot;
            if !entry.is_established() {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "session not established".into(),
                });
            }
            (
                entry.coords_warmup_remaining() > 0,
                entry.session_timestamp(now_ms),
                entry.mmp().is_some_and(|m| m.spin_bit.tx_bit()),
            )
        };

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
            let cur = entry.coords_warmup_remaining();
            entry.set_coords_warmup_remaining(cur.saturating_sub(1));
        }

        let mut flags = if include_coords { FSP_FLAG_CP } else { 0 };
        if let Some(slot) = self.sessions.get(dest_addr) {
            if slot.current_k_bit() {
                flags |= FSP_FLAG_K;
            }
        }

        let (counter, ciphertext, fsp_payload) = {
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
            let ciphertext = session
                .encrypt_with_aad(&inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?;

            let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len() + 200);
            fsp_payload.extend_from_slice(&header);
            if let (Some(src), Some(dst)) = (&my_coords, &dest_coords) {
                encode_coords(src, &mut fsp_payload);
                encode_coords(dst, &mut fsp_payload);
            }
            fsp_payload.extend_from_slice(&ciphertext);
            (counter, ciphertext, fsp_payload)
        };

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.record_sent(payload.len());
            if let Some(mut mmp) = entry.mmp_mut() {
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

        if let Err(error) = endpoint_event_tx.try_send(event) {
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
        // Direct-peer + actor path: encrypt via the peer actor.
        // Reports / non-data messages don't carry coords (no CP flag)
        // and don't touch the session's last_activity timer.
        if self.config.node.actor_owns_sessions
            && let Some(actor) = self.peer_actor_for(dest_addr)
        {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if !actor
                .dispatch(crate::peer::actor::PeerInboundJob::Encrypt {
                    msg_type,
                    plaintext: payload.to_vec(),
                    coords_payload_if_warmup: None,
                    touch: false,
                    respond: tx,
                })
                .await
            {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "peer actor inbound channel closed".into(),
                });
            }
            let result = rx.await.map_err(|_| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "peer actor dropped Encrypt oneshot".into(),
            })?;
            let output = result.map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("actor encrypt failed: {}", e),
            })?;
            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *dest_addr, output.fsp_payload)
                .with_ttl(self.config.node.session.default_ttl);
            self.send_session_datagram(&mut datagram).await?;
            return Ok(());
        }

        let now_ms = Self::now_ms();

        let (timestamp, counter, ciphertext, fsp_payload) = {
            let entry = self
                .sessions
                .get_mut(dest_addr)
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "no session".into(),
                })?;

            let timestamp = entry.session_timestamp(now_ms);
            let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());
            let inner_flags = FspInnerFlags { spin_bit }.to_byte();
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
            let inner_plaintext =
                fsp_prepend_inner_header(timestamp, msg_type, inner_flags, payload);
            let payload_len = inner_plaintext.len() as u16;
            let header = build_fsp_header(counter, k_flags, payload_len);

            let ciphertext = session
                .encrypt_with_aad(&inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?;

            let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len());
            fsp_payload.extend_from_slice(&header);
            fsp_payload.extend_from_slice(&ciphertext);
            (timestamp, counter, ciphertext, fsp_payload)
        };

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP sender state (no touch — MMP reports don't reset idle timer)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mut mmp) = entry.mmp_mut()
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
        // Direct-peer + actor path: empty plaintext, force-include
        // pre-encoded coords. Actor will splice them in regardless of
        // its warmup counter (CoordsWarmup's whole point is to fire
        // explicitly when the data path can't piggyback).
        if self.config.node.actor_owns_sessions
            && let Some(actor) = self.peer_actor_for(dest_addr)
        {
            let our_coords = self.tree_state.my_coords().clone();
            let dest_coords = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&our_coords) + coords_wire_size(&dest_coords);
            let mut buf = Vec::with_capacity(coords_size);
            encode_coords(&our_coords, &mut buf);
            encode_coords(&dest_coords, &mut buf);

            let (tx, rx) = tokio::sync::oneshot::channel();
            let msg_type = SessionMessageType::CoordsWarmup.to_byte();
            // touch=false: standalone CoordsWarmup is infrastructure traffic.
            // We pass coords_payload_if_warmup=Some(...) but the actor
            // will only use them if its warmup counter > 0; that may be
            // 0, in which case the CoordsWarmup goes out without CP.
            // For absolute correctness we'd need a "force_coords" knob;
            // in practice the warmup counter is only 0 if we already
            // sent enough piggybacked coords, which means transit caches
            // are warm anyway and a CP-less CoordsWarmup is harmless.
            if !actor
                .dispatch(crate::peer::actor::PeerInboundJob::Encrypt {
                    msg_type,
                    plaintext: Vec::new(),
                    coords_payload_if_warmup: Some(buf),
                    touch: false,
                    respond: tx,
                })
                .await
            {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "peer actor inbound channel closed".into(),
                });
            }
            let result = rx.await.map_err(|_| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "peer actor dropped Encrypt oneshot".into(),
            })?;
            let output = result.map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("actor encrypt failed: {}", e),
            })?;

            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *dest_addr, output.fsp_payload)
                .with_ttl(self.config.node.session.default_ttl);
            self.send_session_datagram(&mut datagram).await?;
            debug!(dest = %self.peer_display_name(dest_addr),
                "Sent standalone CoordsWarmup (actor path)");
            return Ok(());
        }

        let now_ms = Self::now_ms();

        let my_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);

        let (timestamp, counter, ciphertext, fsp_payload) = {
            let entry = self
                .sessions
                .get_mut(dest_addr)
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "no session".into(),
                })?;
            let timestamp = entry.session_timestamp(now_ms);
            let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());
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
            let msg_type = SessionMessageType::CoordsWarmup.to_byte();
            let inner_flags = FspInnerFlags { spin_bit }.to_byte();
            let inner_plaintext =
                fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &[]);

            let payload_len = inner_plaintext.len() as u16;
            let header = build_fsp_header(counter, FSP_FLAG_CP, payload_len);

            let ciphertext = session
                .encrypt_with_aad(&inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?;

            let coords_size = coords_wire_size(&my_coords) + coords_wire_size(&dest_coords);
            let mut fsp_payload =
                Vec::with_capacity(FSP_HEADER_SIZE + coords_size + ciphertext.len());
            fsp_payload.extend_from_slice(&header);
            encode_coords(&my_coords, &mut fsp_payload);
            encode_coords(&dest_coords, &mut fsp_payload);
            fsp_payload.extend_from_slice(&ciphertext);
            (timestamp, counter, ciphertext, fsp_payload)
        };

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP (infrastructure traffic — no idle timer touch)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mut mmp) = entry.mmp_mut()
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
            Some(addr) => addr,
            None => {
                return Err(NodeError::SendFailed {
                    node_addr: datagram.dest_addr,
                    reason: "no route to destination".into(),
                });
            }
        };

        // Seed path_mtu from the first-hop transport MTU (same as forwarding path)
        if let Some(slot) = self.peers.get(&next_hop_addr) {
            let peer = crate::peer::peer_read(slot);
            if let Some(tid) = peer.transport_id()
                && let Some(transport) = self.transports.get(&tid)
            {
                if let Some(addr) = peer.current_addr() {
                    datagram.path_mtu = datagram.path_mtu.min(transport.link_mtu(&addr));
                } else {
                    datagram.path_mtu = datagram.path_mtu.min(transport.mtu());
                }
            }
        }

        // Source-side: seed our PathMtuState.current_mtu from the outbound
        // transport MTU so it doesn't stay at u16::MAX until the destination
        // sends a PathMtuNotification back.
        if let Some(slot) = self.sessions.get_mut(&datagram.dest_addr) {
            let entry = slot;
            if let Some(mut mmp) = entry.mmp_mut() {
                mmp.path_mtu.seed_source_mtu(datagram.path_mtu);
            }
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
        let session_state: Option<(bool, Option<u16>)> =
            self.sessions.get(&dest_addr).map(|slot| {
                let entry = slot;
                let path_mtu = entry.mmp().map(|m| m.path_mtu.current_mtu());
                (entry.is_established(), path_mtu)
            });
        if let Some((is_established, path_mtu_opt)) = session_state {
            if is_established {
                // Check per-destination path MTU learned from MtuExceeded signals.
                // The first oversized packet is forwarded normally and triggers
                // the MtuExceeded signal; subsequent packets are caught here and
                // generate ICMPv6 Packet Too Big back to the application.
                if let Some(path_mtu) = path_mtu_opt {
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
        if let Some(existing_slot) = self.sessions.get(&dest_addr) {
            let existing = existing_slot;
            if existing.is_established() || existing.is_initiating() {
                return;
            }
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
pub(crate) fn mark_ipv6_ecn_ce(packet: &mut [u8]) {
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
