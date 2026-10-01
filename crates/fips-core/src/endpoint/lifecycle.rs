use super::*;

pub(super) fn spawn_node_task(
    mut node: Node,
    shutdown_rx: oneshot::Receiver<()>,
    #[cfg(test)] shutdown_trace: Arc<ShutdownTrace>,
) -> JoinHandle<Result<(), NodeError>> {
    tokio::spawn(async move {
        tokio::pin!(shutdown_rx);
        let loop_result = tokio::select! {
            result = node.run_rx_loop() => result,
            _ = &mut shutdown_rx => Ok(()),
        };
        #[cfg(test)]
        shutdown_trace.record(ShutdownPhase::RxSelectReturned);
        let stop_result = if node.state().can_stop() {
            node.stop().await
        } else {
            Ok(())
        };
        #[cfg(test)]
        {
            shutdown_trace.record(ShutdownPhase::StopReturned);
            drop(node);
            shutdown_trace.record(ShutdownPhase::NodeDropped);
        }
        loop_result?;
        stop_result
    })
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum ShutdownPhase {
    Signaled,
    RxSelectReturned,
    StopReturned,
    NodeDropped,
}

#[cfg(test)]
pub(super) struct ShutdownTrace {
    started: std::time::Instant,
    stamps: [std::sync::atomic::AtomicU64; 4],
}

#[cfg(test)]
impl ShutdownTrace {
    pub(super) fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            stamps: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub(super) fn record(&self, phase: ShutdownPhase) {
        let elapsed_us = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX - 1);
        // One bounded stamp per phase, even with repeated shutdown callers.
        let _ = self.stamps[phase as usize].compare_exchange(
            0,
            elapsed_us.saturating_add(1),
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub(super) fn snapshot(&self) -> serde_json::Value {
        let stamps = self.stamps.each_ref().map(|stamp| {
            stamp
                .load(std::sync::atomic::Ordering::Acquire)
                .checked_sub(1)
        });
        serde_json::json!({
            "clock": "microseconds since endpoint task creation",
            "shutdown_signal_attempted": stamps[0],
            "rx_select_returned": stamps[1],
            "stop_returned": stamps[2],
            "node_drop_completed": stamps[3],
        })
    }
}
