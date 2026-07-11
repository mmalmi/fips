//! UDP transport statistics.

use portable_atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Statistics for a UDP transport instance.
///
/// Uses atomic counters for lock-free updates from the receive loop
/// and send path concurrently.
pub struct UdpStats {
    send: UdpSendStats,
    recv: UdpRecvStats,
}

/// The node task writes send statistics while the socket task writes receive
/// statistics. Keep the two directions on separate cache lines so full-duplex
/// traffic does not bounce one write-hot cache line between executors.
#[repr(align(64))]
struct UdpSendStats {
    packets: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
    mtu_exceeded: AtomicU64,
}

#[repr(align(64))]
struct UdpRecvStats {
    packets: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
    kernel_drops: AtomicU64,
}

impl UdpStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            send: UdpSendStats {
                packets: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                mtu_exceeded: AtomicU64::new(0),
            },
            recv: UdpRecvStats {
                packets: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                kernel_drops: AtomicU64::new(0),
            },
        }
    }

    /// Record a successful send.
    pub fn record_send(&self, bytes: usize) {
        self.record_send_batch(1, bytes);
    }

    /// Record a batch of successful sends with two atomics regardless of its
    /// packet count. The dataplane normally reaches this method with a GSO or
    /// sendmmsg batch, so retaining per-packet increments would throw away part
    /// of the batching win after the syscall returned.
    pub fn record_send_batch(&self, packets: usize, bytes: usize) {
        self.send
            .packets
            .fetch_add(packets as u64, Ordering::Relaxed);
        self.send.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a successful receive.
    pub fn record_recv(&self, bytes: usize) {
        self.recv.packets.fetch_add(1, Ordering::Relaxed);
        self.recv.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a send error.
    pub fn record_send_error(&self) {
        self.send.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a receive error.
    pub fn record_recv_error(&self) {
        self.recv.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an MTU exceeded rejection.
    pub fn record_mtu_exceeded(&self) {
        self.send.mtu_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    /// Update kernel drop count from SO_MEMINFO.
    ///
    /// Not yet wired up — requires `getsockopt(SO_MEMINFO)` on the raw fd
    /// (via socket2 or libc) to read `SK_MEMINFO_DROPS`. Linux-only.
    /// Until implemented, this counter will always be zero.
    pub fn set_kernel_drops(&self, drops: u64) {
        self.recv.kernel_drops.store(drops, Ordering::Relaxed);
    }

    pub fn kernel_drops(&self) -> u64 {
        self.recv.kernel_drops.load(Ordering::Relaxed)
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> UdpStatsSnapshot {
        UdpStatsSnapshot {
            packets_sent: self.send.packets.load(Ordering::Relaxed),
            bytes_sent: self.send.bytes.load(Ordering::Relaxed),
            packets_recv: self.recv.packets.load(Ordering::Relaxed),
            bytes_recv: self.recv.bytes.load(Ordering::Relaxed),
            send_errors: self.send.errors.load(Ordering::Relaxed),
            recv_errors: self.recv.errors.load(Ordering::Relaxed),
            mtu_exceeded: self.send.mtu_exceeded.load(Ordering::Relaxed),
            kernel_drops: self.recv.kernel_drops.load(Ordering::Relaxed),
        }
    }
}

impl Default for UdpStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of UDP stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct UdpStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub mtu_exceeded: u64,
    pub kernel_drops: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_and_scalar_updates_preserve_udp_stats_snapshot() {
        let stats = UdpStats::new();

        stats.record_send_batch(32, 45_120);
        stats.record_send(1410);
        stats.record_recv(1400);
        stats.record_send_error();
        stats.record_recv_error();
        stats.record_mtu_exceeded();
        stats.set_kernel_drops(7);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_sent, 33);
        assert_eq!(snapshot.bytes_sent, 46_530);
        assert_eq!(snapshot.packets_recv, 1);
        assert_eq!(snapshot.bytes_recv, 1400);
        assert_eq!(snapshot.send_errors, 1);
        assert_eq!(snapshot.recv_errors, 1);
        assert_eq!(snapshot.mtu_exceeded, 1);
        assert_eq!(snapshot.kernel_drops, 7);
    }

    #[test]
    fn send_and_receive_writers_do_not_share_a_cache_line() {
        let stats = UdpStats::new();
        let send = std::ptr::addr_of!(stats.send) as usize;
        let recv = std::ptr::addr_of!(stats.recv) as usize;

        assert_eq!(send % 64, 0);
        assert_eq!(recv % 64, 0);
        assert!(send.abs_diff(recv) >= 64);
    }
}
