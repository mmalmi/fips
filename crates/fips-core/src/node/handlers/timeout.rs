//! Timeout management for stale handshake connections, idle sessions,
//! and handshake message resend scheduling.

use crate::node::Node;
use crate::peer::HandshakeState;
use crate::transport::LinkId;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionHandshakeResend {
    dest_addr: crate::NodeAddr,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExhaustedEstablishedSessionHandshake {
    dest_addr: crate::NodeAddr,
    abandoned_rekey: bool,
}

impl crate::node::SessionRegistry {
    fn timed_out_pending_handshakes(&self, now_ms: u64, timeout_ms: u64) -> Vec<crate::NodeAddr> {
        self.iter()
            .filter(|(_, entry)| {
                !entry.is_established() && now_ms.saturating_sub(entry.created_at()) > timeout_ms
            })
            .map(|(addr, _)| *addr)
            .collect()
    }

    fn exhaust_established_handshake_resend_budgets(
        &mut self,
        max_resends: u32,
    ) -> Vec<ExhaustedEstablishedSessionHandshake> {
        let exhausted: Vec<crate::NodeAddr> = self
            .iter()
            .filter(|(_, entry)| {
                entry.is_established()
                    && entry.handshake_payload().is_some()
                    && entry.resend_count() >= max_resends
            })
            .map(|(addr, _)| *addr)
            .collect();

        exhausted
            .into_iter()
            .filter_map(|dest_addr| {
                let entry = self.get_mut(&dest_addr)?;
                let abandoned_rekey = entry.has_rekey_in_progress();
                if abandoned_rekey {
                    entry.abandon_rekey();
                } else {
                    entry.clear_handshake_payload();
                }
                Some(ExhaustedEstablishedSessionHandshake {
                    dest_addr,
                    abandoned_rekey,
                })
            })
            .collect()
    }

    fn due_session_handshake_resends(
        &self,
        now_ms: u64,
        max_resends: u32,
    ) -> Vec<SessionHandshakeResend> {
        self.iter()
            .filter(|(_, entry)| {
                entry.handshake_payload().is_some()
                    && entry.resend_count() < max_resends
                    && entry.next_resend_at_ms() > 0
                    && now_ms >= entry.next_resend_at_ms()
            })
            .filter_map(|(dest_addr, entry)| {
                entry
                    .handshake_payload()
                    .map(|payload| SessionHandshakeResend {
                        dest_addr: *dest_addr,
                        payload: payload.to_vec(),
                    })
            })
            .collect()
    }

    fn record_scheduled_session_handshake_resend(
        &mut self,
        dest_addr: &crate::NodeAddr,
        now_ms: u64,
        interval_ms: u64,
        backoff: f64,
    ) -> Option<u32> {
        let entry = self.get_mut(dest_addr)?;
        let count = entry.resend_count() + 1;
        let next = now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
        entry.record_resend(next);
        Some(count)
    }
}

impl Node {
    fn clear_pm2_confirmed_session_retransmits(&mut self) {
        let confirmed: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                entry.handshake_payload().is_some() || entry.rekey_msg3_payload().is_some()
            })
            .filter_map(|(addr, _)| {
                self.packet_mover2
                    .fsp_owner_activity(addr)
                    .is_some_and(|activity| activity.current_epoch_confirmed())
                    .then_some(*addr)
            })
            .collect();

        for addr in confirmed {
            let cleared = self
                .sessions
                .get_mut(&addr)
                .is_some_and(|entry| entry.clear_pm2_confirmed_fsp_retransmits());
            if cleared {
                let name = self.peer_display_name(&addr);
                debug!(
                    dest = %name,
                    "Cleared session retransmit payload after PM2 authenticated current epoch"
                );
            }
        }
    }

    /// Check for timed-out handshake connections and clean them up.
    ///
    /// Called periodically by the RX event loop. Removes connections that have
    /// been idle longer than the configured handshake timeout or are in Failed state.
    pub(in crate::node) fn check_timeouts(&mut self) {
        if self.peers.connection_is_empty() {
            return;
        }

        let now_ms = Self::now_ms();
        let timeout_ms = self.config.node.rate_limit.handshake_timeout_secs * 1000;

        let stale: Vec<LinkId> = self
            .peers
            .connection_iter()
            .filter(|(_, conn)| conn.is_timed_out(now_ms, timeout_ms) || conn.is_failed())
            .map(|(link_id, _)| *link_id)
            .collect();

        for link_id in stale {
            // Log and schedule retry before cleanup (need connection state)
            if let Some(conn) = self.peers.get_connection(&link_id) {
                let direction = conn.direction();
                let idle_ms = conn.idle_time(now_ms);
                if conn.is_failed() {
                    debug!(
                        link_id = %link_id,
                        direction = %direction,
                        "Failed handshake connection cleaned up"
                    );
                } else {
                    debug!(
                        link_id = %link_id,
                        direction = %direction,
                        idle_secs = idle_ms / 1000,
                        "Stale handshake connection timed out"
                    );
                }

                // Schedule retry for failed outbound auto-connect peers
                if conn.is_outbound()
                    && let Some(identity) = conn.expected_identity()
                {
                    let node_addr = *identity.node_addr();
                    if self
                        .peers
                        .get(&node_addr)
                        .is_some_and(|peer| peer.is_healthy())
                    {
                        debug!(
                            peer = %self.peer_display_name(&node_addr),
                            link_id = %link_id,
                            "Stale outbound handshake timed out while active peer is healthy; skipping retry"
                        );
                    } else {
                        self.schedule_retry(node_addr, now_ms);
                    }
                }
            }
            self.cleanup_stale_connection(link_id, now_ms);
        }
    }

    /// Remove a handshake connection and all associated state.
    ///
    /// Frees the session index, removes pending_outbound entry, and cleans up
    /// the link and address mapping. Does not log — callers provide context-appropriate
    /// log messages.
    fn cleanup_stale_connection(&mut self, link_id: LinkId, _now_ms: u64) {
        let conn = match self.peers.remove_connection(&link_id) {
            Some(c) => c,
            None => return,
        };
        let transport_id = conn.transport_id();

        // Free session index and pending_outbound if allocated
        if let Some(idx) = conn.our_index() {
            if let Some(tid) = conn.transport_id() {
                self.pending_outbound.remove(&(tid, idx.as_u32()));
            }
            let _ = self.index_allocator.free(idx);
        }

        // Remove link and its reverse address dispatch entry.
        self.remove_link(&link_id);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }
    }

    /// Resend handshake messages for pending connections.
    ///
    /// For outbound connections in SentMsg1 state, resends the stored msg1
    /// with exponential backoff. Called periodically from the RX event loop.
    pub(in crate::node) async fn resend_pending_handshakes(&mut self, now_ms: u64) {
        if self.peers.connection_is_empty() {
            return;
        }

        let max_resends = self.config.node.rate_limit.handshake_max_resends;
        let interval_ms = self.config.node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config.node.rate_limit.handshake_resend_backoff;

        // Collect resend candidates: outbound, in SentMsg1, with stored msg1,
        // under max resends, and past the scheduled time.
        let candidates: Vec<(LinkId, Vec<u8>)> = self
            .peers
            .connection_iter()
            .filter(|(_, conn)| {
                conn.is_outbound()
                    && conn.handshake_state() == HandshakeState::SentMsg1
                    && conn.resend_count() < max_resends
                    && conn.next_resend_at_ms() > 0
                    && now_ms >= conn.next_resend_at_ms()
            })
            .filter_map(|(link_id, conn)| {
                conn.handshake_msg1().map(|msg1| (*link_id, msg1.to_vec()))
            })
            .collect();

        for (link_id, msg1_bytes) in candidates {
            // Get transport and address info from the connection
            let (transport_id, remote_addr) = match self.peers.get_connection(&link_id) {
                Some(conn) => match (conn.transport_id(), conn.source_addr()) {
                    (Some(tid), Some(addr)) => (tid, addr.clone()),
                    _ => continue,
                },
                None => continue,
            };

            // Send the stored msg1
            let sent = if let Some(transport) = self.transports.get(&transport_id) {
                match transport.send(&remote_addr, &msg1_bytes).await {
                    Ok(_) => true,
                    Err(e) => {
                        debug!(
                            link_id = %link_id,
                            error = %e,
                            "Handshake msg1 resend failed"
                        );
                        false
                    }
                }
            } else {
                false
            };

            if sent && let Some(conn) = self.peers.get_connection_mut(&link_id) {
                let count = conn.resend_count() + 1;
                let next = now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
                conn.record_resend(next);
                debug!(
                    link_id = %link_id,
                    resend = count,
                    "Resent handshake msg1"
                );
            }
        }
    }

    /// Resend session-layer handshake messages and timeout stale handshakes.
    ///
    /// For sessions in Initiating or AwaitingMsg3 state:
    /// - If the handshake has exceeded the timeout window, remove the session.
    /// - If a resend is due and under max resends, resend the stored payload
    ///   wrapped in a fresh SessionDatagram (so routing can adapt).
    pub(in crate::node) async fn resend_pending_session_handshakes(&mut self, now_ms: u64) {
        if self.sessions.is_empty() {
            return;
        }

        let timeout_ms = self.config.node.rate_limit.handshake_timeout_secs * 1000;
        let max_resends = self.config.node.rate_limit.handshake_max_resends;
        let interval_ms = self.config.node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config.node.rate_limit.handshake_resend_backoff;
        let ttl = self.config.node.session.default_ttl;

        let timed_out = self
            .sessions
            .timed_out_pending_handshakes(now_ms, timeout_ms);

        let direct_fallbacks: Vec<_> = timed_out
            .iter()
            .filter_map(|addr| {
                let peer = self.configured_peer(addr)?;
                if !peer.is_auto_connect()
                    || (peer.addresses.is_empty() && !self.config.node.discovery.nostr.enabled)
                {
                    return None;
                }
                Some((*addr, peer.clone()))
            })
            .collect();

        for addr in &timed_out {
            let name = self.peer_display_name(addr);
            info!(dest = %name, "Session handshake timed out, removing");
            self.remove_packet_mover2_fsp_owner(addr);
            self.sessions.remove(addr);
            self.pending_session_traffic.remove_destination(addr);
        }

        for (peer_node_addr, peer_config) in direct_fallbacks {
            info!(
                npub = %peer_config.npub,
                "FIPS graph session timed out; trying direct auto-connect path"
            );
            if let Err(err) = self.initiate_peer_connection(&peer_config).await {
                debug!(
                    npub = %peer_config.npub,
                    error = %err,
                    "Direct auto-connect fallback after graph timeout did not start"
                );
                self.schedule_retry(peer_node_addr, now_ms);
            }
        }

        self.clear_pm2_confirmed_session_retransmits();

        // Established sessions can temporarily retain a session-layer
        // handshake payload: the initial final msg3, an FSP rekey msg1, or a
        // responder ack. Once a rekey resend budget is exhausted, abandon that
        // local rekey so the peer's next msg1 can converge instead of being
        // tiebreak-dropped forever.
        for exhausted in self
            .sessions
            .exhaust_established_handshake_resend_budgets(max_resends)
        {
            let name = self.peer_display_name(&exhausted.dest_addr);
            debug!(
                dest = %name,
                rekey = exhausted.abandoned_rekey,
                "Session handshake resend budget exhausted"
            );
        }

        let my_addr = *self.node_addr();
        let candidates = self
            .sessions
            .due_session_handshake_resends(now_ms, max_resends);

        for candidate in candidates {
            use crate::protocol::SessionDatagram;

            let mut datagram =
                SessionDatagram::new(my_addr, candidate.dest_addr, candidate.payload).with_ttl(ttl);
            let sent = match self.send_session_datagram(&mut datagram).await {
                Ok(_) => true,
                Err(e) => {
                    debug!(
                        dest = %self.peer_display_name(&candidate.dest_addr),
                        error = %e,
                        "Session handshake resend failed"
                    );
                    false
                }
            };

            if sent
                && let Some(count) = self.sessions.record_scheduled_session_handshake_resend(
                    &candidate.dest_addr,
                    now_ms,
                    interval_ms,
                    backoff,
                )
            {
                debug!(
                    dest = %self.peer_display_name(&candidate.dest_addr),
                    resend = count,
                    "Resent session handshake"
                );
            }
        }
    }

    /// Remove established sessions that have been idle too long.
    ///
    /// Only targets sessions in the Established state. Initiating/AwaitingMsg3
    /// sessions are handled by the handshake timeout.
    pub(in crate::node) fn purge_idle_sessions(&mut self, now_ms: u64) {
        let timeout_ms = self.config.node.session.idle_timeout_secs * 1000;
        if timeout_ms == 0 {
            return; // disabled
        }

        let expired: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(addr, entry)| {
                if !entry.is_established() {
                    return None;
                }
                if let Some(activity) = self.packet_mover2.fsp_owner_activity(addr) {
                    if activity.has_stale_outbound_only_activity(now_ms, timeout_ms) {
                        return Some((*addr, "outbound-only"));
                    }
                    if !activity.has_recent_session_activity(now_ms, timeout_ms) {
                        return Some((*addr, "idle"));
                    }
                } else {
                    return Some((*addr, "missing-pm2-owner"));
                }
                None
            })
            .collect();

        for (addr, reason) in expired {
            // Compute display name before removing the session
            let name = self.peer_display_name(&addr);

            let session_mmp = self.session_mmp_snapshot(&addr);
            self.remove_packet_mover2_fsp_owner(&addr);
            self.sessions.remove(&addr);
            if let Some(mmp) = session_mmp {
                Self::log_session_mmp_teardown(&name, &mmp);
            }
            self.pending_session_traffic.remove_destination(&addr);
            debug!(
                dest = %name,
                idle_secs = timeout_ms / 1000,
                reason,
                "Idle session removed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseSession};
    use crate::{Identity, NodeAddr};

    fn node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_xk_session_pair(
        initiator: &Identity,
        responder: &Identity,
    ) -> (NoiseSession, NoiseSession) {
        let mut initiator_hs =
            NoiseHandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
        let mut responder_hs = NoiseHandshakeState::new_xk_responder(responder.keypair());
        initiator_hs.set_local_epoch([1u8; 8]);
        responder_hs.set_local_epoch([2u8; 8]);

        let msg1 = initiator_hs.write_xk_message_1().unwrap();
        responder_hs.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder_hs.write_xk_message_2().unwrap();
        initiator_hs.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator_hs.write_xk_message_3().unwrap();
        responder_hs.read_xk_message_3(&msg3).unwrap();

        (
            initiator_hs.into_session().unwrap(),
            responder_hs.into_session().unwrap(),
        )
    }

    fn initiating_entry(local: &Identity, peer: &Identity, now_ms: u64) -> SessionEntry {
        let handshake = NoiseHandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Initiating(handshake),
            now_ms,
            true,
        )
    }

    fn established_entry(local: &Identity, peer: &Identity, now_ms: u64) -> SessionEntry {
        let (session, _) = make_xk_session_pair(local, peer);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(session),
            now_ms,
            true,
        );
        entry.mark_established(now_ms);
        entry
    }

    #[test]
    fn session_registry_owns_timeout_handshake_selection_and_resend_accounting() {
        let local = Identity::generate();
        let due_peer = Identity::generate();
        let future_peer = Identity::generate();
        let old_peer = Identity::generate();
        let established_peer = Identity::generate();

        let mut due = initiating_entry(&local, &due_peer, 1_000);
        due.set_handshake_payload(vec![0x10, 0x11], 1_500);
        let mut future = initiating_entry(&local, &future_peer, 1_000);
        future.set_handshake_payload(vec![0x20], 2_500);
        let old = initiating_entry(&local, &old_peer, 1_000);
        let established = established_entry(&local, &established_peer, 1_000);

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*due_peer.node_addr(), due);
        sessions.insert(*future_peer.node_addr(), future);
        sessions.insert(*old_peer.node_addr(), old);
        sessions.insert(*established_peer.node_addr(), established);

        assert_eq!(
            sessions.timed_out_pending_handshakes(1_499, 500),
            Vec::<NodeAddr>::new()
        );
        let timed_out = sessions.timed_out_pending_handshakes(1_501, 500);
        assert!(timed_out.contains(due_peer.node_addr()));
        assert!(timed_out.contains(future_peer.node_addr()));
        assert!(timed_out.contains(old_peer.node_addr()));
        assert!(!timed_out.contains(established_peer.node_addr()));

        assert_eq!(
            sessions.due_session_handshake_resends(1_499, 3),
            Vec::<SessionHandshakeResend>::new()
        );
        assert_eq!(
            sessions.due_session_handshake_resends(1_500, 3),
            vec![SessionHandshakeResend {
                dest_addr: *due_peer.node_addr(),
                payload: vec![0x10, 0x11],
            }]
        );

        let count = sessions
            .record_scheduled_session_handshake_resend(due_peer.node_addr(), 1_500, 1_000, 2.0)
            .expect("due session should exist");
        assert_eq!(count, 1);
        let due_entry = sessions
            .get(due_peer.node_addr())
            .expect("due session should remain");
        assert_eq!(due_entry.resend_count(), 1);
        assert_eq!(due_entry.next_resend_at_ms(), 3_500);
        assert_eq!(due_entry.handshake_payload(), Some(&[0x10, 0x11][..]));

        assert!(
            sessions
                .record_scheduled_session_handshake_resend(&node_addr(0x77), 1_500, 1_000, 2.0)
                .is_none()
        );
    }

    #[test]
    fn session_registry_owns_exhausted_established_handshake_cleanup() {
        let local = Identity::generate();
        let plain_peer = Identity::generate();
        let rekey_peer = Identity::generate();
        let under_budget_peer = Identity::generate();

        let mut plain = established_entry(&local, &plain_peer, 1_000);
        plain.set_handshake_payload(vec![0x01], 1_500);
        plain.record_resend(2_000);

        let mut rekey = established_entry(&local, &rekey_peer, 1_000);
        rekey.set_handshake_payload(vec![0x02], 1_500);
        rekey.record_resend(2_000);
        rekey.set_rekey_state(
            NoiseHandshakeState::new_xk_initiator(local.keypair(), rekey_peer.pubkey_full()),
            true,
        );

        let mut under_budget = established_entry(&local, &under_budget_peer, 1_000);
        under_budget.set_handshake_payload(vec![0x03], 1_500);

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*plain_peer.node_addr(), plain);
        sessions.insert(*rekey_peer.node_addr(), rekey);
        sessions.insert(*under_budget_peer.node_addr(), under_budget);

        let mut exhausted = sessions.exhaust_established_handshake_resend_budgets(1);
        exhausted.sort_by_key(|item| item.dest_addr);
        let mut expected = vec![
            ExhaustedEstablishedSessionHandshake {
                dest_addr: *plain_peer.node_addr(),
                abandoned_rekey: false,
            },
            ExhaustedEstablishedSessionHandshake {
                dest_addr: *rekey_peer.node_addr(),
                abandoned_rekey: true,
            },
        ];
        expected.sort_by_key(|item| item.dest_addr);
        assert_eq!(exhausted, expected);

        let plain = sessions
            .get(plain_peer.node_addr())
            .expect("plain session should remain");
        assert!(plain.handshake_payload().is_none());
        assert_eq!(plain.next_resend_at_ms(), 0);
        assert_eq!(plain.resend_count(), 1);

        let rekey = sessions
            .get(rekey_peer.node_addr())
            .expect("rekey session should remain");
        assert!(rekey.handshake_payload().is_none());
        assert!(!rekey.has_rekey_in_progress());
        assert_eq!(rekey.resend_count(), 1);

        let under_budget = sessions
            .get(under_budget_peer.node_addr())
            .expect("under-budget session should remain");
        assert_eq!(under_budget.handshake_payload(), Some(&[0x03][..]));
        assert_eq!(under_budget.resend_count(), 0);
    }
}
