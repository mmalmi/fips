use super::super::budget::{PACKET_DRAIN_BUDGET, RX_LOOP_BULK_SERVICE_MAX_TURNS};
use crate::node::{Node, NodeState};
use crate::transport::{PacketBuffer, ReceivedPacket, TransportAddr, TransportId, packet_channel};
use std::future::{Future, poll_fn};
use std::task::{Context, Poll};
use tokio::task::coop::{has_budget_remaining, poll_proceed};

fn leave_one_cooperative_token(cx: &mut Context<'_>) {
    // Tokio restores the pre-decrement value unless made_progress is called.
    // Retaining the last token tests consumption, not select's zero-budget gate.
    for _ in 0..1024 {
        let Poll::Ready(guard) = poll_proceed(cx) else {
            panic!("control must begin with a positive cooperative budget");
        };
        if !has_budget_remaining() {
            drop(guard);
            assert!(
                has_budget_remaining(),
                "last guard restores exactly one token"
            );
            return;
        }
        guard.made_progress();
    }
    panic!("control requires a bounded Tokio task budget");
}

#[tokio::test(start_paused = true)]
async fn ready_raw_ingress_yields_before_exhausting_a_finite_backlog() {
    #[cfg(unix)]
    let directory = tempfile::tempdir().expect("private control socket directory");
    let mut config = crate::config::Config::new();
    config.node.discovery.lan.enabled = false;
    // Keep the real control senders alive: a closed mpsc receive would itself
    // consume budget and conceal non-cooperative ready packet turns.
    config.node.control.enabled = true;
    #[cfg(unix)]
    {
        config.node.control.socket_path = directory
            .path()
            .join("cooperative.sock")
            .to_string_lossy()
            .into_owned();
    }
    #[cfg(windows)]
    {
        config.node.control.socket_path = "0".to_string();
    }
    let mut node = Node::new(config).expect("construct node");
    let backlog = PACKET_DRAIN_BUDGET * RX_LOOP_BULK_SERVICE_MAX_TURNS * 4 + 1;
    let (packet_tx, packet_rx) = packet_channel(backlog);
    node.packet_rx = Some(packet_rx);
    node.state = NodeState::Running;
    let mut rx_loop = Box::pin(node.run_rx_loop());

    // Start the actual loop while empty, consuming its initial interval tick.
    // These direct polls stay in this current-thread task until cleanup below.
    poll_fn(|cx| {
        assert!(rx_loop.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    for _ in 0..backlog {
        packet_tx
            .send(ReceivedPacket::with_timestamp(
                TransportId::new(7),
                TransportAddr::from_string("127.0.0.1:9000"),
                PacketBuffer::new(vec![0]),
                crate::time::now_ms(),
            ))
            .expect("queue malformed raw packet");
    }
    assert_eq!(packet_tx.reserved_packets_for_test(), backlog);

    let (pending, remaining, budget_exhausted) = poll_fn(|cx| {
        leave_one_cooperative_token(cx);
        let pending = rx_loop.as_mut().poll(cx).is_pending();
        Poll::Ready((
            pending,
            packet_tx.reserved_packets_for_test(),
            !has_budget_remaining(),
        ))
    })
    .await;

    // Reap the owned listener even when the following behavioral assertion fails.
    drop(rx_loop);
    let control_task = node.control_task.take().expect("owned control listener");
    control_task.abort();
    let _ = control_task.await;
    assert!(pending, "running RX loop remains open");
    assert!(remaining < backlog, "actual raw ingress made progress");
    assert!(
        remaining > 0,
        "ready RX loop must yield before consuming the entire backlog"
    );
    assert!(
        budget_exhausted,
        "completed RX turn consumes cooperative budget"
    );
}
