use super::{AdmissionDenial, JournalEvent, Operation};
use serde::Serialize;
use std::{
    cell::Cell,
    collections::BTreeMap,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Instant,
};

pub(super) mod authorization;

const OPERATIONS: &[&str] = &[
    "other",
    "payment_sign",
    "payment_usage",
    "payment_update",
    "window_checkpoint",
    "payment_exchange",
    // Isolate exact I/O assertions from concurrently running unit tests.
    #[cfg(test)]
    "test",
    #[cfg(test)]
    "test_outer",
    #[cfg(test)]
    "test_child",
    #[cfg(test)]
    "test_poll",
    #[cfg(test)]
    "test_blocking",
];
static COUNTERS: [Counters; OPERATIONS.len()] = [const { Counters::new() }; OPERATIONS.len()];
const DENIAL_REASONS: &[&str] = &["credit_limit", "durable_window"];
static DENIALS: [AtomicU64; DENIAL_REASONS.len()] =
    [const { AtomicU64::new(0) }; DENIAL_REASONS.len()];
thread_local! {
    static CURRENT: Cell<Operation> = const { Cell::new(Operation::Other) };
    static ACCOUNTED: Cell<Accounted> = const { Cell::new(Accounted {
        elapsed_ns: 0, cpu_ns: 0, missing_cpu: 0,
    }) };
}

#[derive(Clone, Copy)]
struct Accounted {
    elapsed_ns: u128,
    cpu_ns: u128,
    missing_cpu: u64,
}

struct Counters {
    spans: AtomicU64,
    cpu_samples: AtomicU64,
    cpu_ns: AtomicU64,
    elapsed_ns: AtomicU64,
    journal_bytes: AtomicU64,
    journal_writes: AtomicU64,
    journal_syncs: AtomicU64,
    journal_commits: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            spans: AtomicU64::new(0),
            cpu_samples: AtomicU64::new(0),
            cpu_ns: AtomicU64::new(0),
            elapsed_ns: AtomicU64::new(0),
            journal_bytes: AtomicU64::new(0),
            journal_writes: AtomicU64::new(0),
            journal_syncs: AtomicU64::new(0),
            journal_commits: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> OperationSnapshot {
        OperationSnapshot {
            spans: self.spans.load(Relaxed),
            cpu_samples: self.cpu_samples.load(Relaxed),
            thread_cpu_ns: self.cpu_ns.load(Relaxed),
            elapsed_ns: self.elapsed_ns.load(Relaxed),
            journal_bytes_written: self.journal_bytes.load(Relaxed),
            journal_writes: self.journal_writes.load(Relaxed),
            journal_syncs: self.journal_syncs.load(Relaxed),
            journal_commits: self.journal_commits.load(Relaxed),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OperationSnapshot {
    /// Completed synchronous spans or future polls, including failures/unwinding.
    pub spans: u64,
    /// A missing CPU sample is never silently represented as zero CPU work.
    pub cpu_samples: u64,
    pub thread_cpu_ns: u64,
    /// Exclusive active span time; excludes child spans and future wait time.
    pub elapsed_ns: u64,
    pub journal_bytes_written: u64,
    pub journal_writes: u64,
    pub journal_syncs: u64,
    pub journal_commits: u64,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub version: u8,
    pub process_id: u32,
    pub process_cpu_ns: Option<u64>,
    pub operations: BTreeMap<&'static str, OperationSnapshot>,
    /// Failed admission attempts, not charged bytes or unique packets.
    pub admission_denials: BTreeMap<&'static str, u64>,
    /// Additive, independently versioned evidence; version 3 counters are unchanged.
    pub authorization_commits: authorization::Snapshot,
}

/// Cumulative counters since this process started. Concurrent snapshots may
/// straddle an operation; compare quiescent boundaries and do not reset them.
pub fn snapshot() -> Option<Snapshot> {
    Some(Snapshot {
        version: 3,
        process_id: std::process::id(),
        process_cpu_ns: cpu_clock(false),
        operations: OPERATIONS
            .iter()
            .zip(&COUNTERS)
            .map(|(name, c)| (*name, c.snapshot()))
            .collect(),
        admission_denials: DENIAL_REASONS
            .iter()
            .zip(&DENIALS)
            .map(|(name, count)| (*name, count.load(Relaxed)))
            .collect(),
        authorization_commits: authorization::snapshot(),
    })
}

pub(super) fn admission_denied(reason: AdmissionDenial) {
    DENIALS[reason as usize].fetch_add(1, Relaxed);
}

pub(super) fn current_operation() -> Option<Operation> {
    let operation = CURRENT.get();
    (!matches!(operation, Operation::Other)).then_some(operation)
}

pub(super) struct Span {
    operation: Operation,
    previous: Operation,
    started: Instant,
    cpu_started: Option<u64>,
    accounted: Accounted,
    // Thread-local attribution and the CPU clock must stay on this thread.
    _same_thread: PhantomData<Rc<()>>,
}

impl Span {
    pub(super) fn enter(operation: Operation) -> Self {
        Self {
            operation,
            previous: CURRENT.replace(operation),
            started: Instant::now(),
            cpu_started: cpu_clock(true),
            accounted: ACCOUNTED.get(),
            _same_thread: PhantomData,
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let accounted = ACCOUNTED.get();
        let elapsed =
            self.started.elapsed().as_nanos() - (accounted.elapsed_ns - self.accounted.elapsed_ns);
        let cpu = self
            .cpu_started
            .zip(cpu_clock(true))
            .and_then(|(a, b)| b.checked_sub(a))
            .filter(|_| accounted.missing_cpu == self.accounted.missing_cpu)
            .and_then(|cpu| {
                cpu.checked_sub(u64::try_from(accounted.cpu_ns - self.accounted.cpu_ns).ok()?)
            });
        ACCOUNTED.set(Accounted {
            elapsed_ns: accounted.elapsed_ns + elapsed,
            cpu_ns: accounted.cpu_ns + u128::from(cpu.unwrap_or(0)),
            missing_cpu: accounted.missing_cpu + u64::from(cpu.is_none()),
        });
        CURRENT.set(self.previous);
        let counters = &COUNTERS[self.operation as usize];
        counters.spans.fetch_add(1, Relaxed);
        counters
            .elapsed_ns
            .fetch_add(elapsed.min(u64::MAX as u128) as u64, Relaxed);
        if let Some(cpu) = cpu {
            counters.cpu_ns.fetch_add(cpu, Relaxed);
            counters.cpu_samples.fetch_add(1, Relaxed);
        }
    }
}

pub(super) fn journal(event: JournalEvent) {
    let counters = &COUNTERS[CURRENT.get() as usize];
    match event {
        JournalEvent::Written(bytes) => {
            counters.journal_bytes.fetch_add(bytes as u64, Relaxed);
            counters.journal_writes.fetch_add(1, Relaxed);
        }
        JournalEvent::Synced => {
            counters.journal_syncs.fetch_add(1, Relaxed);
        }
        JournalEvent::Committed => {
            counters.journal_commits.fetch_add(1, Relaxed);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn cpu_clock(thread: bool) -> Option<u64> {
    let clock = if thread {
        libc::CLOCK_THREAD_CPUTIME_ID
    } else {
        libc::CLOCK_PROCESS_CPUTIME_ID
    };
    clock_ns(clock)
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn monotonic_clock() -> Option<u64> {
    clock_ns(libc::CLOCK_MONOTONIC)
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn clock_ns(clock: libc::clockid_t) -> Option<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime writes one timespec to this valid pointer. It is
    // read only after success. The caller selects a CPU or monotonic clock.
    if unsafe { libc::clock_gettime(clock, value.as_mut_ptr()) } != 0 {
        return None;
    }
    let value = unsafe { value.assume_init() };
    u64::try_from(value.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(
            u64::try_from(value.tv_nsec)
                .ok()
                .filter(|n| *n < 1_000_000_000)?,
        )
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn cpu_clock(_thread: bool) -> Option<u64> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn monotonic_clock() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests;
