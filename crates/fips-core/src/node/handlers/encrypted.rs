//! Established-frame recovery hooks used by packet_mover2.
//!
//! Production established receive is owned by packet_mover2. This module keeps
//! the shared decrypt-failure recovery policy.

use crate::node::Node;
use tracing::{debug, trace, warn};

/// Start link-session recovery after this many consecutive FMP AEAD failures.
const DECRYPT_FAILURE_THRESHOLD: u32 = 4;
/// Newly established sessions can briefly receive stale encrypted packets from
/// the peer's previous link session after restart, rekey, roaming, or NAT
/// traversal handoff. Until one packet authenticates on the new replay window,
/// treat those first failures as stale drain noise.
const DECRYPT_FAILURE_FRESH_SESSION_GRACE_SECS: u64 = 30;
/// After the first authenticated packet on a fresh session, a smaller stale
/// ciphertext tail can still arrive from packets already queued against the old
/// epoch/index. Do not let that tail immediately start another recovery rekey.
const DECRYPT_FAILURE_POST_AUTH_GRACE_SECS: u64 = 10;

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

    pub(in crate::node) async fn handle_packet_mover2_fmp_decrypt_failure(
        &mut self,
        source_node_addr: &crate::NodeAddr,
        fmp_counter: u64,
        fmp_replay_highest: u64,
    ) -> bool {
        debug!(
            peer = %self.peer_display_name(source_node_addr),
            counter = fmp_counter,
            replay_highest = fmp_replay_highest,
            "packet_mover2 FMP AEAD decryption failed"
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
        let session_age = peer.session_established_at().elapsed();
        let grace_secs = if fmp_replay_highest == 0 {
            DECRYPT_FAILURE_FRESH_SESSION_GRACE_SECS
        } else {
            DECRYPT_FAILURE_POST_AUTH_GRACE_SECS
        };
        if session_age.as_secs() < grace_secs {
            trace!(
                peer = %self.peer_display_name(source_node_addr),
                counter = fmp_counter,
                replay_highest = fmp_replay_highest,
                session_age_ms = session_age.as_millis(),
                grace_secs,
                "Ignoring likely stale FMP AEAD failure during fresh-session drain window"
            );
            return true;
        }

        self.handle_decrypt_failure(source_node_addr).await;
        true
    }
}
