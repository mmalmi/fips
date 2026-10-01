use super::*;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

async fn gated_shutdown_endpoint() -> (FipsEndpoint, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let mut config = Config::new();
    config.node.discovery.lan.enabled = false;
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .expect("bind endpoint");
    let original = endpoint.task.lock().await.take().expect("owned node task");
    original.abort();
    let _ = original.await;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (cleanup_started_tx, cleanup_started_rx) = oneshot::channel();
    let (cleanup_release_tx, cleanup_release_rx) = oneshot::channel();
    *endpoint.shutdown_tx.lock().expect("shutdown signal lock") = Some(shutdown_tx);
    *endpoint.task.lock().await = Some(tokio::spawn(async move {
        shutdown_rx.await.expect("production shutdown signal");
        cleanup_started_tx.send(()).expect("cleanup observer");
        cleanup_release_rx.await.expect("release cleanup");
        Ok(())
    }));
    (endpoint, cleanup_started_rx, cleanup_release_tx)
}

async fn assert_pending(
    mut shutdown: Pin<&mut impl Future<Output = Result<(), FipsEndpointError>>>,
    reason: &str,
) {
    poll_fn(|cx| {
        assert!(shutdown.as_mut().poll(cx).is_pending(), "{reason}");
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn canceled_shutdown_preserves_task_for_the_next_waiter() {
    let (endpoint, cleanup_started, cleanup_release) = gated_shutdown_endpoint().await;
    let mut first = Box::pin(endpoint.shutdown());
    assert_pending(first.as_mut(), "first shutdown waits for cleanup").await;
    cleanup_started.await.expect("owned task entered cleanup");
    drop(first);

    let mut next = Box::pin(endpoint.shutdown());
    assert_pending(
        next.as_mut(),
        "canceled shutdown must not detach the owned task",
    )
    .await;
    cleanup_release.send(()).expect("owned task is still alive");
    next.await.expect("next shutdown joins the same task");
    assert!(endpoint.task.lock().await.is_none());
}

#[tokio::test]
async fn concurrent_shutdown_waits_for_the_owned_task_to_exit() {
    let (endpoint, cleanup_started, cleanup_release) = gated_shutdown_endpoint().await;
    let mut first = Box::pin(endpoint.shutdown());
    assert_pending(first.as_mut(), "first shutdown waits for cleanup").await;
    cleanup_started.await.expect("owned task entered cleanup");

    let mut second = Box::pin(endpoint.shutdown());
    assert_pending(
        second.as_mut(),
        "concurrent shutdown must not report success before cleanup",
    )
    .await;
    cleanup_release.send(()).expect("release owned task");
    first.await.expect("first shutdown joins owned task");
    second.await.expect("second shutdown observes completion");
    assert!(endpoint.task.lock().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn shutdown_mutex_wait_and_join_share_the_original_budget() {
    let (endpoint, cleanup_started, _cleanup_release) = gated_shutdown_endpoint().await;
    let mut first = Box::pin(endpoint.shutdown());
    assert_pending(first.as_mut(), "first shutdown waits for cleanup").await;
    cleanup_started.await.expect("owned task entered cleanup");
    let started = tokio::time::Instant::now();
    let mut second = Box::pin(endpoint.shutdown());
    assert_pending(second.as_mut(), "second shutdown waits for its turn").await;

    let spent_waiting = ENDPOINT_OPERATION_TIMEOUT - Duration::from_secs(1);
    tokio::time::advance(spent_waiting).await;
    drop(first);
    assert_pending(second.as_mut(), "second shutdown takes over the join").await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let error = second
        .await
        .expect_err("mutex wait must consume the same budget");
    assert_eq!(started.elapsed(), ENDPOINT_OPERATION_TIMEOUT);
    assert!(matches!(
        error,
        FipsEndpointError::Timeout {
            operation: "shutdown"
        }
    ));
    assert!(
        endpoint.task.lock().await.is_none(),
        "timed-out task was reaped"
    );
}
