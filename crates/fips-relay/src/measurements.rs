//! Optional, process-local diagnostics. These counters have no financial authority.
//! Exclusive spans use the current thread's CPU clock, never time across an await.
//! Futures are measured per poll; blocking workers explicitly inherit attribution.
//! Journal bytes are logical writes, excluding Cashu SQLite and physical I/O.

#[cfg(feature = "measurements")]
mod enabled;
#[cfg(feature = "measurements")]
pub(crate) use enabled::authorization::begin as authorization_begin;
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
    PaymentExchange,
    #[cfg(all(test, feature = "measurements"))]
    Test,
    #[cfg(all(test, feature = "measurements"))]
    TestOuter,
    #[cfg(all(test, feature = "measurements"))]
    TestChild,
    #[cfg(all(test, feature = "measurements"))]
    TestPoll,
    #[cfg(all(test, feature = "measurements"))]
    TestBlocking,
}

pub(crate) enum JournalEvent {
    Written(usize),
    Synced,
    Committed,
}

pub(crate) enum AdmissionDenial {
    CreditLimit,
    DurableWindow,
}

#[inline]
pub(crate) fn admission_denied(reason: AdmissionDenial) {
    #[cfg(feature = "measurements")]
    enabled::admission_denied(reason);
    #[cfg(not(feature = "measurements"))]
    let _ = reason;
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

/// End each span before yielding: a later poll may run on another thread.
pub(crate) async fn measure_async<F: std::future::Future>(
    operation: Operation,
    work: F,
) -> F::Output {
    #[cfg(feature = "measurements")]
    {
        let mut work = std::pin::pin!(work);
        std::future::poll_fn(|cx| measure(operation, || work.as_mut().poll(cx))).await
    }
    #[cfg(not(feature = "measurements"))]
    {
        let _ = operation;
        work.await
    }
}

/// Capture attribution before spawning; worker CPU belongs to its own thread.
pub(crate) fn inherit<T>(work: impl FnOnce() -> T) -> impl FnOnce() -> T {
    #[cfg(feature = "measurements")]
    let operation = enabled::current_operation();
    move || {
        #[cfg(feature = "measurements")]
        if let Some(operation) = operation {
            return measure(operation, work);
        }
        work()
    }
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
