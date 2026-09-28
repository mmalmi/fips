//! Optional, process-local diagnostics. These counters have no financial authority.
//! Synchronous spans use the current thread's CPU clock, never time across an await.
//! Journal bytes are logical writes, excluding Cashu SQLite and physical I/O.

#[cfg(feature = "measurements")]
mod enabled;
#[cfg(feature = "measurements")]
pub use enabled::{Snapshot, snapshot};

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    #[cfg(feature = "measurements")]
    Other,
    PaymentSign,
    PaymentUsage,
    PaymentUpdate,
    WindowCheckpoint,
    #[cfg(all(test, feature = "measurements"))]
    Test,
}

pub(crate) enum JournalEvent {
    Written(usize),
    Synced,
    Committed,
}

/// The closure must finish synchronously on this thread. Never wrap a future.
#[inline]
pub(crate) fn measure<T>(operation: Operation, work: impl FnOnce() -> T) -> T {
    #[cfg(feature = "measurements")]
    let _span = enabled::Span::enter(operation);
    #[cfg(not(feature = "measurements"))]
    let _ = operation;
    work()
}

#[inline]
pub(crate) fn journal(event: JournalEvent) {
    #[cfg(feature = "measurements")]
    enabled::journal(event);
    #[cfg(not(feature = "measurements"))]
    if let JournalEvent::Written(bytes) = event {
        let _ = bytes;
    }
}

#[cfg(not(feature = "measurements"))]
pub fn snapshot() -> Option<()> {
    None
}
