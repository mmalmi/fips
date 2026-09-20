//! Diagnostics for the current Ethernet data socket, separate from frame counters.

/// A missing value means unsupported, not started, or a failed diagnostic read.
#[derive(Debug, Default)]
pub(crate) struct SocketStats {
    /// Linux AF_PACKET queue drops accumulated since this socket was opened.
    /// Does not include losses before the socket or after the transport handoff.
    pub kernel_drops: Option<u64>,
    /// Actual SO_RCVBUF value returned by the kernel, including its accounting overhead.
    pub recv_buffer_bytes: Option<u64>,
}

#[cfg(any(target_os = "linux", test))]
use std::sync::Mutex;

/// One owner serializes the resetting kernel read and accumulation. No socket I/O
/// hot path takes this lock, and no await occurs while it is held.
#[cfg(any(target_os = "linux", test))]
pub(super) struct KernelDropCounter(Mutex<Option<u64>>);

#[cfg(any(target_os = "linux", test))]
impl Default for KernelDropCounter {
    fn default() -> Self {
        Self(Mutex::new(Some(0)))
    }
}

#[cfg(any(target_os = "linux", test))]
impl KernelDropCounter {
    pub(super) fn sample(&self, read: impl FnOnce() -> std::io::Result<u32>) -> Option<u64> {
        let mut total = self.0.lock().ok()?;
        let previous = (*total)?;
        // PACKET_STATISTICS resets the kernel counters on each successful read.
        // Failed reads return unavailable without discarding earlier observations.
        let drops = match read() {
            Ok(drops) => drops,
            Err(error) => {
                // A successful syscall with an unexpected result shape may
                // already have reset the kernel counters. Continuity is lost.
                if error.kind() == std::io::ErrorKind::InvalidData {
                    *total = None;
                }
                return None;
            }
        };
        *total = previous.checked_add(u64::from(drops));
        *total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn resetting_reads_accumulate_and_failed_reads_are_unavailable() {
        let counter = KernelDropCounter::default();
        let kernel = AtomicU32::new(7);
        let read = || Ok(kernel.swap(0, Ordering::Relaxed));
        assert_eq!(counter.sample(read), Some(7));
        assert_eq!(counter.sample(read), Some(7));
        assert_eq!(
            counter.sample(|| Err(std::io::ErrorKind::Unsupported.into())),
            None
        );
        kernel.store(3, Ordering::Relaxed);
        assert_eq!(counter.sample(read), Some(10));
    }

    #[test]
    fn concurrent_readers_share_one_accumulator() {
        let counter = KernelDropCounter::default();
        let kernel = AtomicU32::new(11);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    assert_eq!(
                        counter.sample(|| Ok(kernel.swap(0, Ordering::Relaxed))),
                        Some(11)
                    );
                });
            }
        });
        assert_eq!(counter.sample(|| Ok(0)), Some(11));
    }

    #[test]
    fn overflow_or_poison_cannot_report_a_false_total() {
        let counter = KernelDropCounter(Mutex::new(Some(u64::MAX)));
        assert_eq!(counter.sample(|| Ok(1)), None);
        assert_eq!(
            counter.sample(|| panic!("invalid total must not consume more statistics")),
            None
        );

        let counter = KernelDropCounter::default();
        let _ = std::panic::catch_unwind(|| counter.sample(|| panic!("interrupted read")));
        assert_eq!(counter.sample(|| Ok(0)), None);
    }

    #[test]
    fn an_unreadable_reset_result_invalidates_the_total() {
        let counter = KernelDropCounter::default();
        assert_eq!(counter.sample(|| Ok(7)), Some(7));
        assert_eq!(
            counter.sample(|| Err(std::io::ErrorKind::InvalidData.into())),
            None
        );
        assert_eq!(
            counter.sample(|| panic!("lost continuity must stay unavailable")),
            None
        );
    }

    #[test]
    fn unavailable_socket_stats_do_not_claim_zero_drops() {
        let stats = SocketStats::default();
        assert_eq!(stats.kernel_drops, None);
        assert_eq!(stats.recv_buffer_bytes, None);
    }
}
