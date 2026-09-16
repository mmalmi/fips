use super::{JournalEvent, Operation};
use serde::Serialize;
use std::{
    cell::Cell,
    collections::BTreeMap,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Instant,
};

const OPERATIONS: [&str; 7] = [
    "other",
    "payment_sign",
    "payment_usage",
    "payment_update",
    "payment_open",
    "payment_stop",
    "window_checkpoint",
];
static COUNTERS: [Counters; OPERATIONS.len()] = [const { Counters::new() }; OPERATIONS.len()];
thread_local! {
    static CURRENT: Cell<Operation> = const { Cell::new(Operation::Other) };
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
    /// Completed synchronous spans, including failed results or unwinding.
    pub spans: u64,
    /// A missing CPU sample is never silently represented as zero CPU work.
    pub cpu_samples: u64,
    pub thread_cpu_ns: u64,
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
}

/// Cumulative counters since this process started. Concurrent snapshots may
/// straddle an operation; compare quiescent boundaries and do not reset them.
pub fn snapshot() -> Option<Snapshot> {
    Some(Snapshot {
        version: 1,
        process_id: std::process::id(),
        process_cpu_ns: cpu_clock(false),
        operations: OPERATIONS
            .iter()
            .zip(&COUNTERS)
            .map(|(name, c)| (*name, c.snapshot()))
            .collect(),
    })
}

pub(super) struct Span {
    operation: Operation,
    previous: Operation,
    started: Instant,
    cpu_started: Option<u64>,
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
            _same_thread: PhantomData,
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let cpu = self
            .cpu_started
            .zip(cpu_clock(true))
            .and_then(|(a, b)| b.checked_sub(a));
        CURRENT.set(self.previous);
        let counters = &COUNTERS[self.operation as usize];
        counters.spans.fetch_add(1, Relaxed);
        counters.elapsed_ns.fetch_add(
            self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Relaxed,
        );
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
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime writes one timespec to this valid pointer. It is
    // read only after success. Both IDs are CPU clocks, not elapsed clocks.
    if unsafe { libc::clock_gettime(clock, value.as_mut_ptr()) } != 0 {
        return None;
    }
    let value = unsafe { value.assume_init() };
    u64::try_from(value.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(value.tv_nsec).ok()?)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn cpu_clock(_thread: bool) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests;
