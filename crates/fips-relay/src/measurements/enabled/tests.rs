use super::*;
use crate::{
    durable::write_private_journal,
    measurements::{inherit, measure, measure_async},
};
use std::time::Duration;
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};

#[test]
fn thread_cpu_excludes_sleep_and_other_threads_and_journal_counts_real_io() {
    let root = tempfile::tempdir().unwrap();
    let before = COUNTERS[Operation::Test as usize].snapshot();
    let other = std::thread::spawn(|| {
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            std::hint::black_box(7u64.wrapping_mul(17));
        }
    });
    measure(Operation::Test, || {
        std::thread::sleep(Duration::from_millis(150));
        write_private_journal(root.path(), "measurement.json", b"{\"ok\":true}").unwrap();
        assert!(write_private_journal(&root.path().join("missing"), "fail.json", b"bad").is_err());
    });
    other.join().unwrap();
    let after = COUNTERS[Operation::Test as usize].snapshot();
    assert_eq!(after.spans - before.spans, 1);
    assert_eq!(
        after.journal_bytes_written - before.journal_bytes_written,
        11
    );
    assert_eq!(after.journal_writes - before.journal_writes, 1);
    assert_eq!(after.journal_syncs - before.journal_syncs, 2);
    assert_eq!(after.journal_commits - before.journal_commits, 1);
    assert_eq!(
        std::fs::read(root.path().join("measurement.json")).unwrap(),
        b"{\"ok\":true}"
    );
    let elapsed = after.elapsed_ns - before.elapsed_ns;
    assert!(elapsed >= 150_000_000);
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        assert_eq!(after.cpu_samples - before.cpu_samples, 1);
        assert!(after.thread_cpu_ns - before.thread_cpu_ns < elapsed / 2);
        assert!(snapshot().unwrap().process_cpu_ns.is_some());
    }
    assert!(matches!(CURRENT.get(), Operation::Other));
}

#[test]
fn attribution_is_restored_after_nested_spans_and_unwinding() {
    let _ = std::panic::catch_unwind(|| {
        measure(Operation::PaymentUsage, || {
            measure(Operation::PaymentSign, || {
                assert!(matches!(CURRENT.get(), Operation::PaymentSign))
            });
            assert!(matches!(CURRENT.get(), Operation::PaymentUsage));
            panic!("cancel synchronous work");
        });
    });
    assert!(matches!(CURRENT.get(), Operation::Other));
}

#[test]
fn nested_spans_do_not_charge_child_work_twice() {
    let before =
        [Operation::TestOuter, Operation::TestChild].map(|op| COUNTERS[op as usize].snapshot());
    let cpu_started = cpu_clock(true);
    let started = Instant::now();
    measure(Operation::TestOuter, || {
        measure(Operation::TestChild, || {
            let until = Instant::now() + Duration::from_millis(20);
            while Instant::now() < until {
                std::hint::black_box(7u64.wrapping_mul(17));
            }
            journal(JournalEvent::Written(11));
        });
    });
    let elapsed = started.elapsed().as_nanos();
    let cpu = cpu_started.zip(cpu_clock(true)).map(|(a, b)| b - a);
    let after =
        [Operation::TestOuter, Operation::TestChild].map(|op| COUNTERS[op as usize].snapshot());
    let mut measured_cpu = 0;
    let mut measured_elapsed = 0;
    for (a, b) in before.iter().zip(&after) {
        assert_eq!(b.spans - a.spans, 1);
        measured_cpu += b.thread_cpu_ns - a.thread_cpu_ns;
        measured_elapsed += b.elapsed_ns - a.elapsed_ns;
    }
    assert!(u128::from(measured_elapsed) <= elapsed);
    if let Some(cpu) = cpu {
        assert!(measured_cpu <= cpu, "nested CPU counted twice");
    }
    assert_eq!(after[0].journal_writes - before[0].journal_writes, 0);
    assert_eq!(
        after[1].journal_bytes_written - before[1].journal_bytes_written,
        11
    );
    assert!(matches!(CURRENT.get(), Operation::Other));
}

#[test]
fn future_polls_restore_attribution_across_threads_and_cancellation() {
    let before = COUNTERS[Operation::TestPoll as usize].snapshot();
    let mut polls = 0;
    let work = std::future::poll_fn(move |_| {
        assert!(matches!(CURRENT.get(), Operation::TestPoll));
        journal(JournalEvent::Written(7));
        polls += 1;
        if polls == 1 {
            Poll::Pending
        } else {
            Poll::Ready(42)
        }
    });
    let work = Box::pin(measure_async(Operation::TestPoll, work));
    fn poll<F: Future + Send + 'static>(
        mut work: std::pin::Pin<Box<F>>,
    ) -> (std::pin::Pin<Box<F>>, Poll<F::Output>, u128) {
        assert!(matches!(CURRENT.get(), Operation::Other));
        let started = Instant::now();
        let result = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        let elapsed = started.elapsed().as_nanos();
        assert!(matches!(CURRENT.get(), Operation::Other));
        (work, result, elapsed)
    }
    let (work, result, first_elapsed) = std::thread::spawn(move || poll(work)).join().unwrap();
    assert!(result.is_pending());
    std::thread::sleep(Duration::from_millis(30));
    assert!(matches!(CURRENT.get(), Operation::Other));
    let (_, result, second_elapsed) = std::thread::spawn(move || poll(work)).join().unwrap();
    assert_eq!(result, Poll::Ready(42));
    let after = COUNTERS[Operation::TestPoll as usize].snapshot();
    assert_eq!(after.spans - before.spans, 2);
    assert_eq!(
        after.journal_bytes_written - before.journal_bytes_written,
        14
    );
    assert!(u128::from(after.elapsed_ns - before.elapsed_ns) <= first_elapsed + second_elapsed);

    let mut cancelled = Box::pin(measure_async(
        Operation::TestPoll,
        std::future::pending::<()>(),
    ));
    assert!(
        cancelled
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(cancelled);
    assert!(matches!(CURRENT.get(), Operation::Other));
    assert_eq!(
        COUNTERS[Operation::TestPoll as usize].snapshot().spans - before.spans,
        3
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_worker_inherits_only_the_active_poll_scope() {
    let before = COUNTERS[Operation::TestBlocking as usize].snapshot();
    measure_async(Operation::TestBlocking, async {
        tokio::task::spawn_blocking(inherit(|| {
            assert!(matches!(CURRENT.get(), Operation::TestBlocking));
            journal(JournalEvent::Written(11));
        }))
        .await
        .unwrap();
        tokio::task::yield_now().await;
        assert!(matches!(CURRENT.get(), Operation::TestBlocking));
    })
    .await;
    assert!(matches!(CURRENT.get(), Operation::Other));
    tokio::task::spawn_blocking(inherit(|| {
        assert!(matches!(CURRENT.get(), Operation::Other));
    }))
    .await
    .unwrap();
    let after = COUNTERS[Operation::TestBlocking as usize].snapshot();
    assert!(after.spans - before.spans >= 3);
    assert_eq!(
        after.journal_bytes_written - before.journal_bytes_written,
        11
    );
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    assert_eq!(
        after.cpu_samples - before.cpu_samples,
        after.spans - before.spans
    );
}
