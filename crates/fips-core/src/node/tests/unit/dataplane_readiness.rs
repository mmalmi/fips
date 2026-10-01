use super::*;
use crate::dataplane::{
    DataplaneLiveOutboundFirsts, OutboundPacket, OwnerConfig, OwnerId, PacketClass,
};
use crate::transport::PacketBuffer;
use futures::{FutureExt, poll};
use tokio::time::{Instant, advance};

#[tokio::test(start_paused = true)]
async fn stale_notification_does_not_complete_dataplane_wait() {
    let node = make_node();
    assert!(!node.dataplane.has_runnable_work());
    node.dataplane.readiness_notify().notify_one();

    let start = Instant::now();
    let wait = node.wait_for_dataplane_completion();
    tokio::pin!(wait);
    assert!(
        poll!(wait.as_mut()).is_pending(),
        "a retained notification without runnable work must not complete the wait"
    );
    advance(Duration::from_millis(99)).await;
    assert!(poll!(wait.as_mut()).is_pending());
    advance(Duration::from_millis(1)).await;
    assert!(poll!(wait.as_mut()).is_ready());
    assert_eq!(start.elapsed(), Duration::from_millis(100));
}

#[tokio::test(start_paused = true)]
async fn repeated_stale_notifications_keep_original_completion_deadline() {
    let node = make_node();
    let notify = node.dataplane.readiness_notify();
    let start = Instant::now();
    let wait = node.wait_for_dataplane_completion();
    tokio::pin!(wait);
    assert!(poll!(wait.as_mut()).is_pending());

    for elapsed_ms in [20, 40, 60, 80, 99] {
        advance(start + Duration::from_millis(elapsed_ms) - Instant::now()).await;
        assert!(!node.dataplane.has_runnable_work());
        notify.notify_one();
        assert!(
            poll!(wait.as_mut()).is_pending(),
            "a stale wake must neither complete the wait nor count as progress"
        );
    }
    advance(Duration::from_millis(1)).await;
    assert!(
        poll!(wait.as_mut()).is_ready(),
        "stale wakes must not restart the original 100 ms deadline"
    );
    assert_eq!(start.elapsed(), Duration::from_millis(100));
}

#[tokio::test(start_paused = true)]
async fn runnable_dataplane_work_does_not_wait_for_notification() {
    let mut node = make_node();
    let owner = OwnerId::fmp_node(make_node_addr(0xD1));
    node.dataplane.register_owner(owner, OwnerConfig::new(1, 8));
    let turn = node
        .pump_dataplane_pending_outbound_firsts(
            DataplaneLiveOutboundFirsts {
                initial_outbound: Some(OutboundPacket::fmp(
                    owner,
                    1,
                    PacketClass::Liveness,
                    1,
                    0,
                    PacketBuffer::new(b"ready admission".to_vec()),
                )),
                ..Default::default()
            },
            0,
            0,
            0,
        )
        .await;
    assert_eq!(turn.summary().outbound_admitted(), 1);
    assert_eq!(turn.summary().dispatched(), 0);
    assert_eq!(turn.transport_sent(), 0);
    assert!(turn.drops().is_empty());
    assert!(turn.output_drops().is_empty());
    assert!(node.dataplane.has_runnable_work());

    // Consume the pump's advisory wake without consuming its queued packet.
    // A readiness predicate must still observe that real admitted work.
    let notify = node.dataplane.readiness_notify();
    assert!(notify.notified().now_or_never().is_some());
    assert!(notify.notified().now_or_never().is_none());
    let start = Instant::now();
    assert!(
        node.wait_for_dataplane_completion()
            .now_or_never()
            .is_some(),
        "already runnable work must not wait for another notification"
    );
    assert_eq!(start.elapsed(), Duration::ZERO);
}
