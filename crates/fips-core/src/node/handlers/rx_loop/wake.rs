use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub(super) async fn wait_for_optional_deadline(deadline: Option<Instant>, not_before: Instant) {
    match deadline {
        Some(due) => {
            tokio::time::sleep_until(tokio::time::Instant::from_std(due.max(not_before))).await
        }
        None => std::future::pending().await,
    }
}

pub(super) async fn wait_for_optional_epoch_deadline(deadline_ms: Option<u64>) {
    let Some(due) = deadline_ms else {
        return std::future::pending().await;
    };
    let remaining = due.saturating_sub(crate::time::now_ms());
    if remaining == 0 {
        return;
    }
    // Protocol deadlines use epoch milliseconds, including the simulation
    // clock. This wake is advisory; dispatch rechecks that same clock.
    match tokio::time::Instant::now().checked_add(Duration::from_millis(remaining)) {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

pub(super) async fn wait_for_admission_retry(
    deadline_ms: Option<u64>,
    not_before_ms: u64,
    notify: Option<&Arc<Notify>>,
) -> bool {
    if deadline_ms.is_none() {
        return std::future::pending().await;
    }
    wait_for_optional_epoch_deadline(Some(not_before_ms)).await;
    tokio::select! {
        _ = wait_for_optional_notify_after(notify, Instant::now()) => true,
        _ = wait_for_optional_epoch_deadline(deadline_ms) => false,
    }
}

pub(super) async fn wait_for_optional_notify_after(
    notify: Option<&Arc<Notify>>,
    not_before: Instant,
) {
    let Some(notify) = notify else {
        return std::future::pending().await;
    };
    // A zero-duration sleep can still arm the next millisecond timer tick.
    // Once the rate limit has elapsed, wait directly for actual discovery work.
    if not_before > Instant::now() {
        tokio::time::sleep_until(tokio::time::Instant::from_std(not_before)).await;
    }
    notify.notified().await;
}
