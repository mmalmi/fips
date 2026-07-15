use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn stalled_webrtc_send_times_out_and_starts_cleanup() {
    let cleanup_started = Arc::new(AtomicBool::new(false));
    let cleanup_flag = Arc::clone(&cleanup_started);
    let started = tokio::time::Instant::now();

    let result = bounded_webrtc_send(
        Duration::from_millis(10),
        std::future::pending::<Result<usize, std::io::Error>>(),
        move || async move {
            cleanup_flag.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        },
    )
    .await;

    assert!(matches!(result, Err(TransportError::Timeout)));
    assert!(cleanup_started.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_millis(100));
}

#[tokio::test]
async fn failed_webrtc_send_runs_bounded_cleanup_and_preserves_error() {
    let cleanup_started = Arc::new(AtomicBool::new(false));
    let cleanup_flag = Arc::clone(&cleanup_started);
    let started = tokio::time::Instant::now();

    let result = bounded_webrtc_send(
        Duration::from_millis(10),
        async { Err::<usize, _>(std::io::Error::other("carrier send failed")) },
        move || async move {
            cleanup_flag.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        },
    )
    .await;

    assert!(matches!(
        result,
        Err(TransportError::SendFailed(error)) if error == "carrier send failed"
    ));
    assert!(cleanup_started.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_millis(100));
}
