use super::drain::PacketProcessAction;
use crate::discovery::is_punch_packet;
use crate::node::Node;
use crate::node::handlers::encrypted::EncryptedFrameFastPath;
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use crate::transport::ReceivedPacket;
use tracing::{debug, trace, warn};

impl Node {
    /// Process a single received packet.
    ///
    /// Dispatches based on the phase field in the 4-byte common prefix.
    pub(in crate::node) async fn process_packet(&mut self, packet: ReceivedPacket) {
        let action = self.begin_process_packet(packet);
        self.finish_packet_process(action).await;
    }

    pub(super) fn begin_process_packet(&mut self, packet: ReceivedPacket) -> PacketProcessAction {
        let timer = crate::perf_profile::Timer::start(crate::perf_profile::Stage::ProcessPacket);
        let priority_sized = packet.is_priority_sized();
        let priority_count = u64::from(priority_sized);
        let bulk_count = u64::from(!priority_sized);
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::TransportQueueWait,
            crate::perf_profile::Stage::TransportPriorityQueueWait,
            crate::perf_profile::Stage::TransportBulkQueueWait,
            packet.trace_enqueued_at,
            1,
            priority_count,
            bulk_count,
        );
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::TransportRxLoopWait,
            crate::perf_profile::Stage::TransportPriorityRxLoopWait,
            crate::perf_profile::Stage::TransportBulkRxLoopWait,
            packet.trace_rx_loop_owned_at,
            1,
            priority_count,
            bulk_count,
        );
        if is_punch_packet(&packet.data) {
            trace!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                "Dropping stray punch probe/ack in FMP rx loop"
            );
            return PacketProcessAction::Done;
        }
        if packet.data.len() < COMMON_PREFIX_SIZE {
            return PacketProcessAction::Done; // Drop packets too short for common prefix
        }

        let prefix = match CommonPrefix::parse(&packet.data) {
            Some(p) => p,
            None => return PacketProcessAction::Done, // Malformed prefix
        };
        if matches!(prefix.phase, PHASE_MSG1 | PHASE_MSG2) {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                phase = prefix.phase,
                version = prefix.version,
                "FMP handshake packet dispatch"
            );
        } else {
            trace!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                phase = prefix.phase,
                version = prefix.version,
                "FMP packet dispatch"
            );
        }

        if prefix.version != FMP_VERSION {
            debug!(
                version = prefix.version,
                transport_id = %packet.transport_id,
                "Unknown FMP version, dropping"
            );

            // If the packet arrived on an adopted Nostr-NAT bootstrap
            // transport, the originating peer is necessarily on a
            // different FMP-protocol version than us. The discovery
            // sweep would otherwise re-traverse them every cycle.
            let looks_like_fmp_phase =
                matches!(prefix.phase, PHASE_ESTABLISHED | PHASE_MSG1 | PHASE_MSG2);
            if looks_like_fmp_phase
                && self.bootstrap_transports.contains(&packet.transport_id)
                && let Some(npub) = self.bootstrap_transports.peer_npub(&packet.transport_id)
                && let Some(handle) = self.nostr_discovery_handle()
            {
                let now_ms = Self::now_ms();
                let cooldown_secs = handle.protocol_mismatch_cooldown_secs();
                if handle.record_protocol_mismatch(npub, now_ms) {
                    warn!(
                        peer_npub = %npub,
                        transport_id = %packet.transport_id,
                        peer_version = prefix.version,
                        our_version = FMP_VERSION,
                        cooldown_secs,
                        "Nostr-discovered peer speaks a different FMP version; suppressing retraversal"
                    );
                }
            }
            return PacketProcessAction::Done;
        }

        match prefix.phase {
            PHASE_ESTABLISHED => match self.try_prepare_encrypted_frame_for_worker(packet) {
                EncryptedFrameFastPath::Dispatch(job) => PacketProcessAction::DecryptJob { job },
                EncryptedFrameFastPath::Dropped => PacketProcessAction::Done,
                EncryptedFrameFastPath::Slow(packet) => {
                    PacketProcessAction::EncryptedSlow { packet, timer }
                }
            },
            PHASE_MSG1 => PacketProcessAction::Msg1 { packet, timer },
            PHASE_MSG2 => PacketProcessAction::Msg2 { packet, timer },
            _ => {
                debug!(
                    phase = prefix.phase,
                    transport_id = %packet.transport_id,
                    "Unknown FMP phase, dropping"
                );
                PacketProcessAction::Done
            }
        }
    }

    pub(super) async fn finish_packet_process(&mut self, action: PacketProcessAction) {
        match action {
            PacketProcessAction::Done => {}
            PacketProcessAction::DecryptJob { job } => {
                if let Some(workers) = self.decrypt_workers.as_ref() {
                    workers.dispatch_job(job);
                }
            }
            PacketProcessAction::EncryptedSlow {
                packet,
                timer: _timer,
            } => {
                self.handle_encrypted_frame_slow(packet).await;
            }
            PacketProcessAction::Msg1 {
                packet,
                timer: _timer,
            } => {
                self.handle_msg1(packet).await;
            }
            PacketProcessAction::Msg2 {
                packet,
                timer: _timer,
            } => {
                self.handle_msg2(packet).await;
            }
        }
    }
}
