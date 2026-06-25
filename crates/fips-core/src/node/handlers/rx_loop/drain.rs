use crate::control::ControlMessage;
use crate::node::decrypt_worker::{DecryptJob, DecryptWorkerReturnReceivers};
use crate::node::{EndpointBulkSendFeedback, NodeEndpointCommand};
use crate::transport::{PacketRx, ReceivedPacket};
use crate::upper::tun::TunOutboundRx;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;

pub(super) enum PacketProcessAction {
    Done,
    DecryptJob {
        job: DecryptJob,
    },
    EncryptedKbitTransition {
        packet: ReceivedPacket,
        timer: crate::perf_profile::Timer,
    },
    Msg1 {
        packet: ReceivedPacket,
        timer: crate::perf_profile::Timer,
    },
    Msg2 {
        packet: ReceivedPacket,
        timer: crate::perf_profile::Timer,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PacketDrainAction<T> {
    Packet(T),
    InterleaveDecryptReturn,
    InterleaveSideQueues,
}

pub(super) struct RxLoopSideQueues<'a> {
    pub(super) control_query_rx: &'a mut Receiver<ControlMessage>,
    pub(super) endpoint_bulk_feedback_rx: &'a mut Receiver<EndpointBulkSendFeedback>,
    pub(super) tun_outbound_rx: &'a mut TunOutboundRx,
    pub(super) endpoint_priority_command_rx: &'a mut Receiver<NodeEndpointCommand>,
    pub(super) endpoint_command_rx: &'a mut Receiver<NodeEndpointCommand>,
}

pub(super) fn decrypt_return_has_ready(rx: &DecryptWorkerReturnReceivers) -> bool {
    !rx.priority.is_empty() || !rx.authenticated_bulk.is_empty()
}

pub(super) fn rx_loop_side_queues_have_ready(side_queues: &RxLoopSideQueues<'_>) -> bool {
    !side_queues.control_query_rx.is_empty()
        || !side_queues.endpoint_bulk_feedback_rx.is_empty()
        || !side_queues.tun_outbound_rx.is_empty()
        || !side_queues.endpoint_priority_command_rx.is_empty()
        || !side_queues.endpoint_command_rx.is_empty()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RxLoopDataDrainStats {
    pub(super) packets: usize,
    pub(super) decrypt: usize,
    pub(super) endpoint_feedback: usize,
    pub(super) tun: usize,
    pub(super) endpoint: usize,
    pub(super) control: usize,
}

impl RxLoopDataDrainStats {
    #[cfg(test)]
    pub(super) fn new(packets: usize, tun: usize, endpoint: usize) -> Self {
        Self {
            packets,
            decrypt: 0,
            endpoint_feedback: 0,
            tun,
            endpoint,
            control: 0,
        }
    }

    #[cfg(test)]
    pub(super) fn with_decrypt(
        packets: usize,
        decrypt: usize,
        tun: usize,
        endpoint: usize,
    ) -> Self {
        Self {
            packets,
            decrypt,
            endpoint_feedback: 0,
            tun,
            endpoint,
            control: 0,
        }
    }

    pub(super) fn with_feedback(
        packets: usize,
        decrypt: usize,
        endpoint_feedback: usize,
        tun: usize,
        endpoint: usize,
    ) -> Self {
        Self {
            packets,
            decrypt,
            endpoint_feedback,
            tun,
            endpoint,
            control: 0,
        }
    }

    pub(super) fn with_control(
        packets: usize,
        endpoint_feedback: usize,
        tun: usize,
        endpoint: usize,
        control: usize,
    ) -> Self {
        Self {
            packets,
            decrypt: 0,
            endpoint_feedback,
            tun,
            endpoint,
            control,
        }
    }

    pub(super) fn data_total(&self) -> usize {
        self.packets + self.decrypt + self.endpoint_feedback + self.tun + self.endpoint
    }

    pub(super) fn total(&self) -> usize {
        self.data_total() + self.control
    }

    pub(super) fn has_drained(&self) -> bool {
        self.total() > 0
    }

    pub(super) fn has_data_drained(&self) -> bool {
        self.data_total() > 0
    }

    pub(super) fn data_pressure(&self, recent_data_activity: bool) -> bool {
        self.has_data_drained() || recent_data_activity
    }
}

#[derive(Debug, Default)]
pub(super) struct RxLoopMaintenanceState {
    last_data_activity: Option<Instant>,
    slow_maintenance_timed_out_under_data: bool,
    consecutive_slow_maintenance_skips: u8,
}

impl RxLoopMaintenanceState {
    pub(super) fn record_data_activity(&mut self, now: Instant) {
        self.last_data_activity = Some(now);
    }

    pub(super) fn data_pressure(
        &self,
        drained: RxLoopDataDrainStats,
        now: Instant,
        activity_window: Duration,
    ) -> bool {
        drained.data_pressure(self.recent_data_activity(now, activity_window))
    }

    pub(super) fn skip_slow_maintenance(
        &self,
        drained: RxLoopDataDrainStats,
        data_pressure: bool,
        max_pressure_skips: u8,
    ) -> bool {
        let pressure_skip = drained.has_data_drained()
            || (data_pressure && self.slow_maintenance_timed_out_under_data);
        pressure_skip && self.consecutive_slow_maintenance_skips < max_pressure_skips
    }

    pub(super) fn plan_maintenance(
        &self,
        drained: RxLoopDataDrainStats,
        now: Instant,
        activity_window: Duration,
        idle_timeout: Duration,
        busy_timeout: Duration,
        max_pressure_skips: u8,
    ) -> RxLoopMaintenancePlan {
        let data_pressure = self.data_pressure(drained, now, activity_window);
        RxLoopMaintenancePlan::new(
            data_pressure,
            self.skip_slow_maintenance(drained, data_pressure, max_pressure_skips),
            idle_timeout,
            busy_timeout,
        )
    }

    pub(super) fn record_maintenance_result(
        &mut self,
        plan: RxLoopMaintenancePlan,
        slow_timed_out: bool,
    ) {
        if plan.slow_maintenance_skipped() {
            self.consecutive_slow_maintenance_skips =
                self.consecutive_slow_maintenance_skips.saturating_add(1);
        } else {
            self.consecutive_slow_maintenance_skips = 0;
        }

        if !plan.data_pressure() {
            self.slow_maintenance_timed_out_under_data = false;
        } else if slow_timed_out {
            self.slow_maintenance_timed_out_under_data = true;
        } else if !plan.slow_maintenance_skipped() {
            self.slow_maintenance_timed_out_under_data = false;
        }
    }

    pub(super) fn recent_data_activity(&self, now: Instant, activity_window: Duration) -> bool {
        self.last_data_activity
            .is_some_and(|last| now.saturating_duration_since(last) <= activity_window)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RxLoopMaintenancePlan {
    data_pressure: bool,
    slow_timeout: Option<Duration>,
    slow_maintenance_skipped: bool,
}

impl RxLoopMaintenancePlan {
    pub(super) fn new(
        data_pressure: bool,
        skip_slow_maintenance: bool,
        idle_timeout: Duration,
        busy_timeout: Duration,
    ) -> Self {
        let slow_maintenance_skipped = data_pressure && skip_slow_maintenance;
        let slow_timeout = if slow_maintenance_skipped {
            None
        } else if data_pressure {
            Some(busy_timeout)
        } else {
            Some(idle_timeout)
        };

        Self {
            data_pressure,
            slow_timeout,
            slow_maintenance_skipped,
        }
    }

    pub(super) fn data_pressure(&self) -> bool {
        self.data_pressure
    }

    pub(super) fn slow_timeout(&self) -> Option<Duration> {
        self.slow_timeout
    }

    pub(super) fn slow_maintenance_skipped(&self) -> bool {
        self.slow_maintenance_skipped
    }
}

pub(super) struct PacketDrainCursor<T> {
    first_packet: Option<T>,
    remaining: usize,
    drained: usize,
    decrypt_return_interleave_every: usize,
    side_queue_interleave_every: usize,
    packets_until_decrypt_return_interleave: usize,
    packets_until_side_queue_interleave: usize,
}

impl<T> PacketDrainCursor<T> {
    pub(super) fn new(
        first_packet: Option<T>,
        budget: usize,
        decrypt_return_interleave_every: usize,
        side_queue_interleave_every: usize,
    ) -> Self {
        Self {
            first_packet,
            remaining: budget,
            drained: 0,
            decrypt_return_interleave_every,
            side_queue_interleave_every,
            packets_until_decrypt_return_interleave: decrypt_return_interleave_every,
            packets_until_side_queue_interleave: side_queue_interleave_every,
        }
    }

    pub(super) fn next<R>(&mut self, packet_rx: &mut R) -> Option<PacketDrainAction<T>>
    where
        R: PacketDrainReceiver<T>,
    {
        if self.remaining == 0 {
            return None;
        }

        if self.decrypt_return_interleave_due() {
            self.packets_until_decrypt_return_interleave = self.decrypt_return_interleave_every;
            self.charge_interleave_turn();
            return Some(PacketDrainAction::InterleaveDecryptReturn);
        }

        if self.side_queue_interleave_due() {
            self.packets_until_side_queue_interleave = self.side_queue_interleave_every;
            self.charge_interleave_turn();
            return Some(PacketDrainAction::InterleaveSideQueues);
        }

        let packet = self
            .first_packet
            .take()
            .or_else(|| packet_rx.try_recv_packet())?;
        self.charge_packet();
        Some(PacketDrainAction::Packet(packet))
    }

    pub(super) fn drained(&self) -> usize {
        self.drained
    }

    fn decrypt_return_interleave_due(&self) -> bool {
        self.drained > 0
            && self.decrypt_return_interleave_every > 0
            && self.packets_until_decrypt_return_interleave == 0
    }

    fn side_queue_interleave_due(&self) -> bool {
        self.drained > 0
            && self.side_queue_interleave_every > 0
            && self.packets_until_side_queue_interleave == 0
    }

    fn charge_packet(&mut self) {
        self.remaining -= 1;
        self.drained += 1;
        if self.packets_until_decrypt_return_interleave > 0 {
            self.packets_until_decrypt_return_interleave -= 1;
        }
        if self.packets_until_side_queue_interleave > 0 {
            self.packets_until_side_queue_interleave -= 1;
        }
    }

    fn charge_interleave_turn(&mut self) {
        self.remaining -= 1;
    }

    pub(super) fn refund_empty_interleave_turn(&mut self) {
        self.remaining += 1;
    }
}

pub(super) trait PacketDrainReceiver<T> {
    fn try_recv_packet(&mut self) -> Option<T>;
}

impl<T> PacketDrainReceiver<T> for tokio::sync::mpsc::UnboundedReceiver<T> {
    fn try_recv_packet(&mut self) -> Option<T> {
        self.try_recv().ok()
    }
}

impl PacketDrainReceiver<ReceivedPacket> for PacketRx {
    fn try_recv_packet(&mut self) -> Option<ReceivedPacket> {
        self.try_recv().ok()
    }
}
