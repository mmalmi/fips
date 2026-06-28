#[cfg(test)]
use crate::{node::decrypt_worker::DecryptJob, transport::ReceivedPacket};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;

#[cfg(test)]
pub(super) enum PacketProcessAction {
    Done,
    DecryptJob {
        job: DecryptJob,
    },
    EncryptedRekeyTrial {
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
        _drained: RxLoopDataDrainStats,
        data_pressure: bool,
    ) -> bool {
        data_pressure && self.slow_maintenance_timed_out_under_data
    }

    pub(super) fn plan_maintenance(
        &self,
        drained: RxLoopDataDrainStats,
        now: Instant,
        activity_window: Duration,
        idle_timeout: Duration,
        busy_timeout: Duration,
    ) -> RxLoopMaintenancePlan {
        let data_pressure = self.data_pressure(drained, now, activity_window);
        RxLoopMaintenancePlan::new(
            data_pressure,
            self.skip_slow_maintenance(drained, data_pressure),
            idle_timeout,
            busy_timeout,
        )
    }

    pub(super) fn record_maintenance_result(&mut self, data_pressure: bool, slow_timed_out: bool) {
        if !data_pressure {
            self.slow_maintenance_timed_out_under_data = false;
        } else if slow_timed_out {
            self.slow_maintenance_timed_out_under_data = true;
        } else {
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
}

impl RxLoopMaintenancePlan {
    pub(super) fn new(
        data_pressure: bool,
        skip_slow_maintenance: bool,
        idle_timeout: Duration,
        busy_timeout: Duration,
    ) -> Self {
        let slow_timeout = if data_pressure && skip_slow_maintenance {
            None
        } else if data_pressure {
            Some(busy_timeout)
        } else {
            Some(idle_timeout)
        };

        Self {
            data_pressure,
            slow_timeout,
        }
    }

    pub(super) fn data_pressure(&self) -> bool {
        self.data_pressure
    }

    pub(super) fn slow_timeout(&self) -> Option<Duration> {
        self.slow_timeout
    }
}

#[cfg(test)]
pub(super) struct DecryptReturnDrainCursor<T> {
    first_priority: Option<T>,
    first_authenticated_bulk: Option<T>,
    first_bulk: Option<T>,
    remaining: usize,
    drained: usize,
}

#[cfg(test)]
impl<T> DecryptReturnDrainCursor<T> {
    pub(super) fn new(
        first_priority: Option<T>,
        first_authenticated_bulk: Option<T>,
        first_bulk: Option<T>,
        budget: usize,
    ) -> Self {
        Self {
            first_priority,
            first_authenticated_bulk,
            first_bulk,
            remaining: budget,
            drained: 0,
        }
    }

    pub(super) fn next(
        &mut self,
        priority_rx: &mut Receiver<T>,
        authenticated_bulk_rx: &mut Receiver<T>,
        bulk_rx: &mut Receiver<T>,
    ) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let item = if let Some(item) = self.first_priority.take() {
            Some(item)
        } else {
            priority_rx
                .try_recv()
                .ok()
                .or_else(|| self.first_authenticated_bulk.take())
                .or_else(|| authenticated_bulk_rx.try_recv().ok())
                .or_else(|| self.first_bulk.take())
                .or_else(|| bulk_rx.try_recv().ok())
        }?;

        self.remaining -= 1;
        self.drained += 1;
        Some(item)
    }

    pub(super) fn drained(&self) -> usize {
        self.drained
    }

    pub(super) fn charge_extra(&mut self, extra: usize) {
        self.remaining = self.remaining.saturating_sub(extra);
        self.drained = self.drained.saturating_add(extra);
    }
}

pub(super) struct SingleLaneDrainCursor<T> {
    first_item: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> SingleLaneDrainCursor<T> {
    pub(super) fn new(first_item: Option<T>, budget: usize) -> Self {
        Self {
            first_item,
            remaining: budget,
            drained: 0,
        }
    }

    pub(super) fn next(&mut self, rx: &mut Receiver<T>) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let packet = self.first_item.take().or_else(|| rx.try_recv().ok())?;
        self.remaining -= 1;
        self.drained += 1;
        Some(packet)
    }

    pub(super) fn drained(&self) -> usize {
        self.drained
    }
}
