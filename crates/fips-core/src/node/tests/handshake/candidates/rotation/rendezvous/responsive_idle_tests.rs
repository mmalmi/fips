//! Real dataplane admission exercises the idle decision used by both drivers.
use super::*;
use crate::dataplane::{
    DataplaneLiveOutboundFirsts, OutboundPacket, OwnerConfig, OwnerId, PacketClass,
};
use crate::node::tests::spanning_tree::make_test_node;
use crate::transport::PacketBuffer;
use futures::{FutureExt, poll};
use tokio::time::{Instant, advance};

enum Control {
    Prompt,
    Fallback,
    Cut,
}

#[test]
fn runnable_dataplane_gets_prompt_contact_turn() {
    run(Control::Prompt);
}

#[test]
fn idle_and_persistent_readiness_keep_five_ms_fallback() {
    run(Control::Fallback);
}

#[test]
fn ready_contact_turns_do_not_postpone_independent_cut() {
    run(Control::Cut);
}

fn run(control: Control) {
    run_large_stack_async_test("responsive-idle-control", move || async move {
        let mut nodes = vec![make_test_node().await];
        tokio::time::pause();
        let result = AssertUnwindSafe(check(&mut nodes, control))
            .catch_unwind()
            .await;
        tokio::time::resume();
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn check(nodes: &mut [TestNode], control: Control) {
    let mut idle = Wait::default();
    if matches!(control, Control::Fallback) {
        assert!(!nodes[0].node.dataplane.has_runnable_work());
        five_ms(&mut idle, nodes).await;
    }
    let node = &mut nodes[0].node;
    let owner = OwnerId::fmp_node(*node.node_addr());
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
                    PacketBuffer::new(b"ready contact turn".to_vec()),
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
    assert!(turn.drops().is_empty() && turn.output_drops().is_empty());
    assert!(node.dataplane.has_runnable_work());
    let notify = node.dataplane.readiness_notify();
    assert!(notify.notified().now_or_never().is_some());
    assert!(notify.notified().now_or_never().is_none());

    if matches!(control, Control::Cut) {
        let cut_at = Instant::now() + Duration::from_millis(1_500);
        let driver = tokio::spawn(async move {
            tokio::time::sleep_until(cut_at).await;
            Instant::now()
        });
        let mut waits = 0;
        while !driver.is_finished() {
            idle.wait(nodes, None, "cut-control").await;
            waits += 1;
            if waits > 1_000 {
                driver.abort();
                let _ = driver.await;
                panic!("persistent readiness must retain bounded idle fallback");
            }
        }
        assert_eq!(
            driver.await.unwrap(),
            cut_at,
            "ready work must not postpone the independent cut"
        );
    } else {
        let before = Instant::now();
        {
            let wait = idle.wait(nodes, None, "ready-control");
            tokio::pin!(wait);
            assert!(
                poll!(wait.as_mut()).is_pending(),
                "ready turn cooperatively yields"
            );
            assert!(
                poll!(wait.as_mut()).is_ready(),
                "runnable dataplane must not wait for the idle timer"
            );
        }
        assert_eq!(before.elapsed(), Duration::ZERO);
        assert!(nodes[0].node.dataplane.has_runnable_work());
        if matches!(control, Control::Fallback) {
            five_ms(&mut idle, nodes).await;
        }
    }
}

async fn five_ms(idle: &mut Wait, nodes: &[TestNode]) {
    let before = Instant::now();
    let wait = idle.wait(nodes, None, "fallback-control");
    tokio::pin!(wait);
    assert!(poll!(wait.as_mut()).is_pending());
    advance(Duration::from_millis(4)).await;
    assert!(poll!(wait.as_mut()).is_pending());
    advance(Duration::from_millis(1)).await;
    assert!(poll!(wait.as_mut()).is_ready());
    assert_eq!(before.elapsed(), Duration::from_millis(5));
}
