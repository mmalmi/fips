use super::*;
use std::{future::Future, task::Poll};
use tokio::sync::oneshot;

struct OnDrop(Option<oneshot::Sender<()>>);
impl Drop for OnDrop {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

#[tokio::test]
async fn aborting_a_draining_scheduler_cancels_the_pending_exchange() {
    let (dropped, was_dropped) = oneshot::channel();
    let (started, was_started) = oneshot::channel();
    let job = tokio::spawn(async move {
        let _guard = OnDrop(Some(dropped));
        started.send(()).unwrap();
        std::future::pending::<PaymentResult>().await
    });
    was_started.await.unwrap();
    let mut workers = PaymentWorkers::default();
    workers.channels.insert(
        "pending".into(),
        ChannelPayment {
            schedule: ChannelSchedule::default(),
            job: Some(job),
        },
    );
    let (draining, is_draining) = oneshot::channel();
    let supervisor = tokio::spawn(async move {
        let mut drain = Box::pin(workers.drain());
        // Confirm the drain is inside the exchange wait before cancellation.
        std::future::poll_fn(|cx| {
            assert!(drain.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        draining.send(()).unwrap();
        drain.await
    });
    is_draining.await.unwrap();
    supervisor.abort();
    assert!(supervisor.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), was_dropped)
        .await
        .expect("canceling a drain must not detach a live payment exchange")
        .unwrap();
}
