use super::budget::CONTROL_QUERY_INTERLEAVE_BUDGET;
use crate::node::{Node, NodeEndpointControlCommand};
use tokio::sync::mpsc::Receiver;

// Keep the endpoint receiver Node-owned for completed-handler snapshot reads,
// but retain the old loop-local lifetime even when the loop future is cancelled.
pub(super) struct RxLoopEndpointLifetime<'a>(pub(super) &'a mut Node);

impl Drop for RxLoopEndpointLifetime<'_> {
    fn drop(&mut self) {
        self.0.endpoint_control_rx.take();
        self.0.pending_endpoint_control.take();
    }
}

pub(super) async fn next_endpoint_control(
    pending: &mut Option<NodeEndpointControlCommand>,
    receiver: &mut Option<Receiver<NodeEndpointControlCommand>>,
) -> Option<NodeEndpointControlCommand> {
    if let Some(command) = pending.take() {
        // No await after taking the FIFO barrier: select cancellation must not
        // lose an already-dequeued command.
        return Some(command);
    }
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

impl Node {
    pub(in crate::node::handlers) async fn drain_endpoint_snapshots(&mut self) {
        if self.pending_endpoint_control.is_some() {
            return;
        }
        for _ in 0..CONTROL_QUERY_INTERLEAVE_BUDGET {
            let Some(command) = self
                .endpoint_control_rx
                .as_mut()
                .and_then(|receiver| receiver.try_recv().ok())
            else {
                break;
            };
            match command {
                NodeEndpointControlCommand::PeerSnapshot { .. } => {
                    // This exact arm only reads state and sends a oneshot reply.
                    // Never dispatch mutations or async discovery between handlers.
                    let request = Box::pin(self.handle_endpoint_control(command)).await;
                    debug_assert!(request.is_none());
                }
                command => {
                    // Preserve FIFO, including commands whose caller has gone away.
                    self.pending_endpoint_control = Some(command);
                    break;
                }
            }
        }
    }
}
