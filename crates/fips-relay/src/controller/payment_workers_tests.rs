use super::*;
use std::{future::Future, task::Poll};
use tokio::sync::oneshot;

struct OnDrop(Option<oneshot::Sender<()>>);
impl Drop for OnDrop {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

#[test]
fn reused_claim_requires_a_new_locally_supported_balance() {
    let usage = ChannelUsage {
        submitted_msat: 2_500,
        reserved_msat: 9_000,
        lost_msat: 6_500,
        paid_msat: 1_000,
    };
    for (evidence, authorized, expected) in [
        (0, 1, false),
        (1_000, 1, false),
        (1_001, 1, true),
        (2_000, 2, false),
        (2_500, 2, true),
        (5_000, 3, false),
    ] {
        assert_eq!(has_unpaid_claim(usage, evidence, authorized), expected);
    }
    assert!(!has_unpaid_claim(
        ChannelUsage {
            paid_msat: 3_000,
            ..usage
        },
        2_500,
        1,
    ));
}

#[tokio::test]
async fn successful_reply_does_not_cover_sends_after_the_exchange_started() {
    let mut payment = ChannelPayment {
        started_evidence_msat: 9_584,
        job: Some(tokio::spawn(async {
            Ok(Some(ChannelUsage {
                submitted_msat: 7_094,
                reserved_msat: 11_094,
                lost_msat: 4_000,
                paid_msat: 8_000,
            }))
        })),
        schedule: ChannelSchedule::default(),
        last_usage: None,
        #[cfg(feature = "measurements")]
        progress: None,
    };
    let now = tokio::time::Instant::now();
    for _ in 0..8 {
        payment.schedule.acknowledge(now, 9_584, 8_000);
    }
    payment.finish().await.unwrap();
    let now = tokio::time::Instant::now();
    let policy = PaymentCadence::default();
    assert!(!payment.schedule.due(now, 9_584, 8, 8_000, &policy));
    assert!(payment.schedule.due(now, 14_000, 8, 8_000, &policy));
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
            job: Some(job),
            schedule: ChannelSchedule::default(),
            started_evidence_msat: 0,
            last_usage: None,
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
async fn payment_progress_tracks_harvested_results_and_retains_last_failure() {
    let progress = Arc::new(Mutex::new(
        super::super::payment_progress::ScheduleProgress::default(),
    ));
    let (finish, ready) = oneshot::channel();
    progress.lock().unwrap().started();
    assert_eq!(
        progress.lock().unwrap().pending().unwrap().stage,
        Stage::Scheduled
    );
    let observation = PaymentObservation {
        progress: Some(progress.clone()),
    };
    let mut payment = ChannelPayment {
        job: Some(tokio::spawn(async move {
            let _observation = observation;
            ready.await.unwrap()
        })),
        progress: Some(progress.clone()),
        schedule: ChannelSchedule::default(),
        started_evidence_msat: 0,
        last_usage: None,
    };
    assert!(progress.lock().unwrap().in_flight());
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
    let usage = ChannelUsage {
        reserved_msat: 1_500,
        submitted_msat: 1_500,
        lost_msat: 0,
        paid_msat: 1_000,
    };
    finish.send(Ok(Some(usage))).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !payment.job.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        progress.lock().unwrap().in_flight(),
        "unharvested completion is pending"
    );
    assert_eq!(
        progress.lock().unwrap().pending().unwrap().stage,
        Stage::AwaitingHarvest
    );
    payment.finish().await.unwrap();
    assert!(!progress.lock().unwrap().in_flight());
    assert_eq!(progress.lock().unwrap().pending(), None);
    assert_eq!(progress.lock().unwrap().acknowledged_msat, Some(1_000));
    assert_eq!(
        payment.last_usage,
        Some(usage),
        "a validated payment reply must retain its newer unpaid claim"
    );

    progress.lock().unwrap().started();
    payment.job = Some(tokio::spawn(async {
        Err(Stage::UpdateRequest.error("lost acknowledgment"))
    }));
    assert_eq!(payment.finish().await.unwrap_err(), "lost acknowledgment");
    assert!(
        payment.last_usage.is_none(),
        "a failed exchange needs fresh usage"
    );
    assert!(!progress.lock().unwrap().in_flight());
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
    assert_eq!(
        progress.lock().unwrap().last_failure_stage,
        Some(Stage::UpdateRequest)
    );
    progress.lock().unwrap().finished(Some(2_000), None);
    assert_eq!(
        progress.lock().unwrap().last_failure_stage,
        Some(Stage::UpdateRequest)
    );
    payment.job = Some(tokio::spawn(async { Ok(None) }));
    payment.last_usage = Some(usage);
    payment.finish().await.unwrap();
    assert!(
        payment.last_usage.is_none(),
        "an inactive purchase loses its claim"
    );
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
    let failed = tokio::spawn(std::future::pending::<PaymentResult>());
    failed.abort();
    payment.job = Some(failed);
    payment.last_usage = Some(usage);
    assert!(payment.finish().await.is_err());
    assert!(payment.last_usage.is_none());
    assert_eq!(
        progress.lock().unwrap().last_failure_stage,
        Some(Stage::Worker)
    );
    progress.lock().unwrap().finished(Some(3_000), None);
    progress.lock().unwrap().started();
    let late_observation = PaymentObservation {
        progress: Some(progress.clone()),
    };
    drop(payment);
    late_observation.stage(Stage::UpdateRequest);
    drop(late_observation);
    assert_eq!(progress.lock().unwrap().acknowledged_msat, None);
    assert_eq!(progress.lock().unwrap().pending(), None);
}
