use super::*;
use crate::{durable::write_private_journal, measurements::measure};
use std::time::Duration;

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
