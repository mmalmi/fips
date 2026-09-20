//! Clock boundaries for staggered watches and retained, no-longer-due checks.
use super::*;

fn delay(controller: &Controller) -> Duration {
    controller.next_refresh_delay(tokio::time::Instant::now())
}

#[tokio::test]
async fn refresh_wakeup_preserves_deadlines_without_busy_retries() {
    let root = tempfile::tempdir().unwrap();
    let controller = disconnected_controller(root.path()).await;
    tokio::time::pause();
    let now = tokio::time::Instant::now();
    assert_eq!(delay(&controller), Duration::from_secs(2));
    {
        let mut checks = controller.refresh_checks.lock().unwrap();
        // Two watches started half a second apart. A skipped watch may retain
        // an expired check while paused or waiting for channel renewal.
        for (id, checked) in [
            ("earlier", now - Duration::from_millis(500)),
            ("later", now),
            ("retained", now - Duration::from_secs(10)),
        ] {
            checks.insert(
                id.into(),
                RefreshCheck {
                    checked,
                    free: None,
                    replace_fenced: None,
                },
            );
        }
    }
    assert_eq!(delay(&controller), Duration::from_secs(2));
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(delay(&controller), Duration::from_millis(500));
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(delay(&controller), Duration::from_millis(500));
    tokio::time::advance(Duration::from_millis(499)).await;
    assert_eq!(delay(&controller), Duration::from_millis(1));
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..3 {
        assert_eq!(
            delay(&controller),
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

#[tokio::test]
async fn slow_refresh_keeps_the_existing_ready_tick_without_busy_followups() {
    let root = tempfile::tempdir().unwrap();
    let controller = disconnected_controller(root.path()).await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    controller.refresh_checks.lock().unwrap().insert(
        "slow-quote".into(),
        RefreshCheck {
            checked: started,
            free: None,
            replace_fenced: None,
        },
    );
    tokio::time::advance(Duration::from_millis(5_200)).await;
    assert_eq!(
        controller.next_refresh_delay(started),
        Duration::ZERO,
        "a slow scan has already consumed the housekeeping interval"
    );
    assert_eq!(
        delay(&controller),
        Duration::from_secs(2),
        "a subsequent quick pass cannot spin on that retained expired check"
    );
    tokio::time::resume();
    controller.services.endpoint.shutdown().await.unwrap();
}
