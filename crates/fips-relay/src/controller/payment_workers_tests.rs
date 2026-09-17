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
            #[cfg(feature = "measurements")]
            progress: None,
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

#[cfg(feature = "measurements")]
#[tokio::test]
async fn payment_progress_stays_in_flight_until_harvest_and_failures_are_unknown() {
    let progress = Arc::new(Mutex::new(
        super::super::payment_progress::ScheduleProgress::default(),
    ));
    let (finish, ready) = oneshot::channel();
    progress.lock().unwrap().started();
    let mut payment = ChannelPayment {
        schedule: ChannelSchedule::default(),
        job: Some(tokio::spawn(async move { ready.await.unwrap() })),
        progress: Some(progress.clone()),
    };
    assert!(progress.lock().unwrap().in_flight);
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
    finish
        .send(Ok(Some(ChannelUsage {
            reserved_msat: 1_000,
            submitted_msat: 1_000,
            lost_msat: 0,
            paid_msat: 1_000,
        })))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !payment.job.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        progress.lock().unwrap().in_flight,
        "unharvested completion is pending"
    );
    payment.finish().await.unwrap();
    assert!(!progress.lock().unwrap().in_flight);
    assert_eq!(progress.lock().unwrap().acknowledged_msat, Some(1_000));

    progress.lock().unwrap().started();
    payment.job = Some(tokio::spawn(async { Err("lost acknowledgment".into()) }));
    assert!(payment.finish().await.is_err());
    assert!(!progress.lock().unwrap().in_flight);
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
    progress.lock().unwrap().finished(Some(2_000));
    payment.job = Some(tokio::spawn(async { Ok(None) }));
    payment.finish().await.unwrap();
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
    progress.lock().unwrap().finished(Some(3_000));
    drop(payment);
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
}
