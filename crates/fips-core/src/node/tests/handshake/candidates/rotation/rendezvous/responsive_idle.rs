//! Give ready work one prompt ordinary sweep without polling indefinitely.
use super::*;

#[path = "responsive_idle_tests.rs"]
mod tests;

#[derive(Default)]
pub(super) struct Wait {
    yielded_ready: bool,
}

impl Wait {
    pub(super) async fn wait(
        &mut self,
        nodes: &[TestNode],
        phase: Option<&mut phase::Capture>,
        site: &'static str,
    ) {
        let ready = nodes.iter().any(|node| {
            node.packet_rx.queued_packets_for_test() > 0 || node.node.dataplane.has_runnable_work()
        });
        if ready && !self.yielded_ready {
            self.yielded_ready = true;
            // Let the independent contact driver run before the next unchanged
            // node sweep. A still-ready or blocked node cannot cause a busy loop:
            // consecutive readiness falls back to the original idle interval.
            tokio::task::yield_now().await;
        } else {
            self.yielded_ready = false;
            let idle = tokio::time::sleep(Duration::from_millis(5));
            if let Some(phase) = phase {
                phase.before_sleep(nodes, site);
            }
            idle.await;
        }
    }
}
