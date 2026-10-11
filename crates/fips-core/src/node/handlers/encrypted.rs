//! Established-frame recovery hooks used by dataplane.
//!
//! Production established receive is owned by dataplane. This module keeps
//! the shared decrypt-failure recovery policy.

use crate::node::Node;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// Start link-session recovery after this many consecutive FMP AEAD failures
/// once the existing authenticated link-liveness window has expired.
const DECRYPT_FAILURE_THRESHOLD: u32 = 4;

enum DecryptFailureAction {
    None,
    StartRecoveryRekey { consecutive_failures: u32 },
    AwaitRecovery { consecutive_failures: u32 },
    RemovePeer { consecutive_failures: u32 },
}

impl Node {
    /// Increment decrypt failure counter and recover stale FMP sessions.
    ///
    /// Stale encrypted packets can arrive after sleep/wake, network roaming,
    /// rekey races, or peer restart. Removing the peer immediately causes a
    /// visible traffic drop even when the existing link is healthy enough to
    /// carry a replacement handshake. Prefer an in-place rekey and keep the
    /// old session usable while that recovery handshake completes; only evict
    /// when recovery cannot be started.
    pub(in crate::node) async fn handle_decrypt_failure(&mut self, node_addr: &crate::NodeAddr) {
        let rekey_enabled = self.config.node.rekey.enabled;
        let action = {
            let Some(peer) = self.peers.get_mut(node_addr) else {
                return;
            };
            let count = peer.increment_decrypt_failures();
            if count < DECRYPT_FAILURE_THRESHOLD {
                DecryptFailureAction::None
            } else if rekey_enabled && peer.has_session() {
                if !peer.rekey_in_progress() && peer.pending_new_session().is_none() {
                    DecryptFailureAction::StartRecoveryRekey {
                        consecutive_failures: count,
                    }
                } else {
                    DecryptFailureAction::AwaitRecovery {
                        consecutive_failures: count,
                    }
                }
            } else {
                DecryptFailureAction::RemovePeer {
                    consecutive_failures: count,
                }
            }
        };

        match action {
            DecryptFailureAction::None => {}
            DecryptFailureAction::StartRecoveryRekey {
                consecutive_failures,
            } => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures,
                    "FMP AEAD failures exceeded threshold; starting recovery rekey"
                );
                if self.initiate_rekey(node_addr).await {
                    if let Some(peer) = self.peers.get_mut(node_addr) {
                        peer.reset_decrypt_failures();
                    }
                } else {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        consecutive_failures,
                        "Failed to start FMP recovery rekey; removing peer"
                    );
                    let addr = *node_addr;
                    self.remove_active_peer(node_addr);
                    let now_ms = Self::now_ms();
                    self.schedule_reconnect(addr, now_ms);
                }
            }
            DecryptFailureAction::AwaitRecovery {
                consecutive_failures,
            } => {
                if consecutive_failures == DECRYPT_FAILURE_THRESHOLD
                    || consecutive_failures.is_multiple_of(1000)
                {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        consecutive_failures,
                        "FMP AEAD failures continuing while recovery rekey is pending"
                    );
                }
            }
            DecryptFailureAction::RemovePeer {
                consecutive_failures,
            } => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures,
                    "FMP AEAD failures exceeded threshold and recovery is unavailable; removing peer"
                );
                let addr = *node_addr;
                self.remove_active_peer(node_addr);
                let now_ms = Self::now_ms();
                self.schedule_reconnect(addr, now_ms);
            }
        }
    }

    pub(in crate::node) async fn handle_dataplane_fmp_decrypt_failure(
        &mut self,
        source_node_addr: &crate::NodeAddr,
        fmp_counter: u64,
        fmp_replay_highest: u64,
    ) -> bool {
        debug!(
            peer = %self.peer_display_name(source_node_addr),
            counter = fmp_counter,
            replay_highest = fmp_replay_highest,
            "dataplane FMP AEAD decryption failed"
        );
        self.handle_reported_fmp_decrypt_failure(source_node_addr, fmp_counter, fmp_replay_highest)
            .await
    }

    async fn handle_reported_fmp_decrypt_failure(
        &mut self,
        source_node_addr: &crate::NodeAddr,
        fmp_counter: u64,
        fmp_replay_highest: u64,
    ) -> bool {
        let Some(peer) = self.peers.get(source_node_addr) else {
            return false;
        };
        // A matching source address does not authenticate a failed datagram.
        // Reuse heartbeat liveness, including completed dataplane receive work,
        // so forged packets cannot rekey a healthy peer between control turns.
        let quiet_for = self.direct_path_liveness_quiet_for(
            source_node_addr,
            peer,
            Instant::now(),
            Self::now_ms(),
        );
        if quiet_for < Duration::from_secs(self.config.node.link_dead_timeout_secs) {
            trace!(
                peer = %self.peer_display_name(source_node_addr),
                counter = fmp_counter,
                replay_highest = fmp_replay_highest,
                quiet_ms = quiet_for.as_millis(),
                "Ignoring unauthenticated FMP failure while the link remains live"
            );
            return true;
        }

        self.handle_decrypt_failure(source_node_addr).await;
        true
    }
}
