//! Clock boundaries for staggered watches and retained, no-longer-due checks.
use super::*;

#[tokio::test]
async fn refresh_wakeup_preserves_deadlines_without_busy_retries() {
    let root = tempfile::tempdir().unwrap();
    let controller = disconnected_controller(root.path()).await;
    tokio::time::pause();
    let now = tokio::time::Instant::now();
    assert_eq!(controller.next_refresh_delay(), Duration::from_secs(2));
    {
        let mut checks = controller.refresh_checks.lock().unwrap();
        // Two watches started half a second apart. A skipped watch may retain
        // an expired check while paused or waiting for channel renewal.
        for (id, checked) in [
            ("earlier", now - Duration::from_millis(500)),
            ("later", now),
            ("retained", now - Duration::from_secs(10)),
        ] {
            checks.insert(id.into(), RefreshCheck { checked, free: None });
        }
    }
    assert_eq!(controller.next_refresh_delay(), Duration::from_secs(2));
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(controller.next_refresh_delay(), Duration::from_millis(500));
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(controller.next_refresh_delay(), Duration::from_millis(500));
    tokio::time::advance(Duration::from_millis(499)).await;
    assert_eq!(controller.next_refresh_delay(), Duration::from_millis(1));
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..3 {
        assert_eq!(
            controller.next_refresh_delay(),
            Duration::from_secs(2),
            "expired and exact-boundary checks cannot create a zero-delay retry loop"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
    }
    assert!(controller.watched_routes().await.unwrap().is_empty());
    assert!(controller.purchase_history().await.unwrap().is_empty());
    assert!(!root.path().join("wallet").exists());
    tokio::time::resume();
    controller.services.endpoint.shutdown().await.unwrap();
}
