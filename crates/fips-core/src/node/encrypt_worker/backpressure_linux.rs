fn record_udp_send_path(connected: bool, count: u64) {
    let event = if connected {
        crate::perf_profile::Event::UdpSendConnected
    } else {
        crate::perf_profile::Event::UdpSendWildcard
    };
    crate::perf_profile::record_event_count(event, count);
}

fn is_send_backpressure(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
        || err.raw_os_error().is_some_and(raw_send_backpressure_code)
}

#[cfg(unix)]
fn raw_send_backpressure_code(code: i32) -> bool {
    code == libc::ENOBUFS || code == libc::ENOMEM
}

#[cfg(windows)]
fn raw_send_backpressure_code(code: i32) -> bool {
    const WSAENOBUFS: i32 = 10055;
    const ERROR_NOT_ENOUGH_MEMORY: i32 = 8;
    code == WSAENOBUFS || code == ERROR_NOT_ENOUGH_MEMORY
}

#[cfg(not(any(unix, windows)))]
fn raw_send_backpressure_code(_code: i32) -> bool {
    false
}

#[derive(Default)]
struct SendBackpressurePacer {
    /// Counts consecutive kernel send-queue failures since the last
    /// successful send. This drives the bounded-drop policy.
    consecutive_full: u32,
    /// Counts failures since the last sleep. This is separate from
    /// `consecutive_full` so sleeping does not make `drop_after`
    /// unreachable during a sustained ENOBUFS storm.
    full_since_sleep: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendBackpressureAction {
    Yield,
    Sleep,
    DropBulk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendBackpressureDecision {
    Retry,
    DropCurrentBulk,
}

fn send_backpressure_decision(
    pacer_requested_drop: bool,
    drop_on_backpressure: bool,
) -> SendBackpressureDecision {
    if pacer_requested_drop && drop_on_backpressure {
        SendBackpressureDecision::DropCurrentBulk
    } else {
        SendBackpressureDecision::Retry
    }
}

impl SendBackpressurePacer {
    fn record_success(&mut self) {
        self.consecutive_full = 0;
        self.full_since_sleep = 0;
    }

    fn next_action(
        &mut self,
        would_block: bool,
        sleep_after: u32,
        drop_after: u32,
    ) -> SendBackpressureAction {
        if would_block {
            self.record_success();
            return SendBackpressureAction::Yield;
        }

        self.consecutive_full = self.consecutive_full.saturating_add(1);
        self.full_since_sleep = self.full_since_sleep.saturating_add(1);
        if drop_after > 0 && self.consecutive_full >= drop_after {
            self.record_success();
            return SendBackpressureAction::DropBulk;
        }

        if sleep_after > 0 && self.full_since_sleep >= sleep_after {
            self.full_since_sleep = 0;
            return SendBackpressureAction::Sleep;
        }

        SendBackpressureAction::Yield
    }

    /// Returns true when a bulk-data caller should drop the current
    /// datagram instead of retrying indefinitely.
    fn pause(&mut self, err: &std::io::Error) -> bool {
        crate::perf_profile::record_event(crate::perf_profile::Event::UdpSendBackpressure);
        if err.kind() == std::io::ErrorKind::WouldBlock {
            let action = self.next_action(
                true,
                send_backpressure_sleep_after(),
                send_backpressure_drop_after(),
            );
            debug_assert_eq!(action, SendBackpressureAction::Yield);
            std::thread::yield_now();
            return false;
        }

        static SEND_BACKPRESSURE_COUNT: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let n = SEND_BACKPRESSURE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < 8 || n.is_multiple_of(100_000) {
            warn!(
                error = %err,
                events = n + 1,
                "UDP send queue full; applying kernel backpressure"
            );
        }

        match self.next_action(
            false,
            send_backpressure_sleep_after(),
            send_backpressure_drop_after(),
        ) {
            SendBackpressureAction::DropBulk => return true,
            SendBackpressureAction::Sleep => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::UdpSendBackpressureSleep,
                );
                std::thread::sleep(std::time::Duration::from_micros(
                    send_backpressure_sleep_micros(),
                ));
            }
            SendBackpressureAction::Yield => std::thread::yield_now(),
        }
        false
    }
}

fn send_backpressure_sleep_after() -> u32 {
    static VALUE: OnceLock<u32> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_SEND_BACKPRESSURE_SLEEP_AFTER")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(default_send_backpressure_sleep_after())
    })
}

fn send_backpressure_sleep_micros() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_SEND_BACKPRESSURE_SLEEP_MICROS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(default_send_backpressure_sleep_micros())
            .max(1)
    })
}

fn send_backpressure_drop_after() -> u32 {
    static VALUE: OnceLock<u32> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_SEND_BACKPRESSURE_DROP_AFTER")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(default_send_backpressure_drop_after())
    })
}

#[cfg(target_os = "macos")]
fn default_send_backpressure_sleep_after() -> u32 {
    // Darwin returns ENOBUFS in tight bursts when Wi-Fi/UDP egress is full.
    // Pure yield/retry can spin tens of thousands of times per second, preserve
    // packets TCP should have treated as loss, and hide the bottleneck behind
    // worker-queue latency. Sleep only after a short burst; clean sends reset
    // the counter.
    4
}

#[cfg(not(target_os = "macos"))]
fn default_send_backpressure_sleep_after() -> u32 {
    0
}

#[cfg(target_os = "macos")]
fn default_send_backpressure_sleep_micros() -> u64 {
    100
}

#[cfg(not(target_os = "macos"))]
fn default_send_backpressure_sleep_micros() -> u64 {
    1
}

#[cfg(target_os = "macos")]
fn default_send_backpressure_drop_after() -> u32 {
    // WireGuard's Darwin UDP path returns ENOBUFS to the caller rather than
    // retrying one datagram forever. For bulk endpoint data, a bounded retry
    // budget avoids head-of-line stalls that can last seconds when Wi-Fi
    // egress is saturated, while still preserving short transient bursts.
    // Control frames pass `drop_on_backpressure = false` and keep retrying.
    256
}

#[cfg(not(target_os = "macos"))]
fn default_send_backpressure_drop_after() -> u32 {
    0
}

#[cfg(test)]
mod send_backpressure_tests {
    use super::*;

    #[test]
    fn send_backpressure_pacer_wouldblock_yields_and_resets() {
        let mut pacer = SendBackpressurePacer {
            consecutive_full: 7,
            full_since_sleep: 3,
        };

        assert_eq!(pacer.next_action(true, 1, 1), SendBackpressureAction::Yield);
        assert_eq!(pacer.consecutive_full, 0);
        assert_eq!(pacer.full_since_sleep, 0);
    }

    #[test]
    fn send_backpressure_pacer_drops_bulk_after_explicit_budget() {
        let mut pacer = SendBackpressurePacer::default();

        assert_eq!(
            pacer.next_action(false, 0, 2),
            SendBackpressureAction::Yield
        );
        assert_eq!(pacer.consecutive_full, 1);
        assert_eq!(
            pacer.next_action(false, 0, 2),
            SendBackpressureAction::DropBulk
        );
        assert_eq!(
            pacer.consecutive_full, 0,
            "drop decision should reset the consecutive pressure budget"
        );
        assert_eq!(pacer.full_since_sleep, 0);
    }

    #[test]
    fn send_backpressure_drop_decision_requires_packet_policy() {
        assert_eq!(
            send_backpressure_decision(true, true),
            SendBackpressureDecision::DropCurrentBulk
        );
        assert_eq!(
            send_backpressure_decision(true, false),
            SendBackpressureDecision::Retry
        );
        assert_eq!(
            send_backpressure_decision(false, true),
            SendBackpressureDecision::Retry
        );
    }

    #[test]
    fn send_backpressure_pacer_sleep_does_not_reset_drop_budget() {
        let mut pacer = SendBackpressurePacer::default();

        assert_eq!(
            pacer.next_action(false, 2, 3),
            SendBackpressureAction::Yield
        );
        assert_eq!(
            pacer.next_action(false, 2, 3),
            SendBackpressureAction::Sleep
        );
        assert_eq!(
            pacer.consecutive_full, 2,
            "sleep throttles retry rate without hiding sustained pressure"
        );
        assert_eq!(
            pacer.next_action(false, 2, 3),
            SendBackpressureAction::DropBulk
        );
    }

    #[test]
    #[cfg(unix)]
    fn send_backpressure_classifier_covers_socket_buffer_errors() {
        assert!(is_send_backpressure(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
        assert!(is_send_backpressure(&std::io::Error::from_raw_os_error(
            libc::ENOBUFS
        )));
        assert!(is_send_backpressure(&std::io::Error::from_raw_os_error(
            libc::ENOMEM
        )));
        assert!(!is_send_backpressure(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_send_pace_defaults_on_but_can_opt_out() {
        assert_eq!(
            macos_send_pace_mbps_from_raw(None),
            DEFAULT_MACOS_SEND_PACE_MBPS
        );
        assert_eq!(
            macos_send_pace_mbps_from_raw(Some("")),
            DEFAULT_MACOS_SEND_PACE_MBPS
        );
        assert_eq!(macos_send_pace_mbps_from_raw(Some("0")), 0.0);
        assert_eq!(macos_send_pace_mbps_from_raw(Some("off")), 0.0);
        assert_eq!(
            macos_send_pace_mbps_from_raw(Some("-1")),
            DEFAULT_MACOS_SEND_PACE_MBPS
        );
        assert_eq!(
            macos_send_pace_mbps_from_raw(Some("wat")),
            DEFAULT_MACOS_SEND_PACE_MBPS
        );
        assert_eq!(macos_send_pace_mbps_from_raw(Some("750")), 750.0);
        assert_eq!(
            macos_send_pace_burst_bytes_from_raw(None),
            DEFAULT_MACOS_SEND_PACE_BURST_BYTES
        );
        assert_eq!(
            macos_send_pace_burst_bytes_from_raw(Some("")),
            DEFAULT_MACOS_SEND_PACE_BURST_BYTES
        );
        assert_eq!(
            macos_send_pace_burst_bytes_from_raw(Some("0")),
            DEFAULT_MACOS_SEND_PACE_BURST_BYTES
        );
        assert_eq!(
            macos_send_pace_burst_bytes_from_raw(Some("65536")),
            65_536.0
        );
    }
}

#[cfg(unix)]
fn record_udp_send_backpressure_drop(err: &std::io::Error) {
    crate::perf_profile::record_event(crate::perf_profile::Event::UdpSendBulkDropped);
    static SEND_BACKPRESSURE_DROP_COUNT: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let n = SEND_BACKPRESSURE_DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(100_000) {
        warn!(
            error = %err,
            drops = n + 1,
            "UDP send queue full; dropping bulk data packet"
        );
    }
}

#[cfg(target_os = "macos")]
const DEFAULT_MACOS_SEND_PACE_MBPS: f64 = 350.0;

#[cfg(target_os = "macos")]
const DEFAULT_MACOS_SEND_PACE_BURST_BYTES: f64 = 64.0 * 1024.0;

#[cfg(target_os = "macos")]
struct MacSendRatePacer {
    bytes_per_sec: f64,
    burst_bytes: f64,
    credit_bytes: f64,
    last: std::time::Instant,
}

#[cfg(target_os = "macos")]
impl Default for MacSendRatePacer {
    fn default() -> Self {
        // Darwin has no sendmmsg/GSO path. Unpaced per-datagram UDP bursts can
        // fill Wi-Fi/LAN egress queues for seconds under tunnel bulk load, so
        // smooth only the macOS raw-send path by default. Set
        // FIPS_MACOS_SEND_PACE_MBPS=0 to opt out for controlled benchmarks.
        let mbps = macos_send_pace_mbps_from_raw(
            std::env::var("FIPS_MACOS_SEND_PACE_MBPS")
                .ok()
                .as_deref(),
        );
        let bytes_per_sec = if mbps.is_finite() && mbps > 0.0 {
            mbps * 1_000_000.0 / 8.0
        } else {
            0.0
        };
        let burst_bytes = macos_send_pace_burst_bytes_from_raw(
            std::env::var("FIPS_MACOS_SEND_PACE_BURST_BYTES")
                .ok()
                .as_deref(),
        );
        Self {
            bytes_per_sec,
            burst_bytes,
            credit_bytes: burst_bytes,
            last: std::time::Instant::now(),
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_send_pace_mbps_from_raw(raw: Option<&str>) -> f64 {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return DEFAULT_MACOS_SEND_PACE_MBPS;
    };
    if raw.eq_ignore_ascii_case("off")
        || raw.eq_ignore_ascii_case("false")
        || raw.eq_ignore_ascii_case("disable")
        || raw.eq_ignore_ascii_case("disabled")
    {
        return 0.0;
    }

    match raw.parse::<f64>() {
        Ok(value) if value.is_finite() && value > 0.0 => value,
        Ok(0.0) => 0.0,
        _ => DEFAULT_MACOS_SEND_PACE_MBPS,
    }
}

#[cfg(target_os = "macos")]
fn macos_send_pace_burst_bytes_from_raw(raw: Option<&str>) -> f64 {
    raw.and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(DEFAULT_MACOS_SEND_PACE_BURST_BYTES)
}

#[cfg(target_os = "macos")]
thread_local! {
    static MAC_DIRECT_SEND_RATE_PACER: RefCell<MacSendRatePacer> =
        RefCell::new(MacSendRatePacer::default());
}

#[cfg(target_os = "macos")]
impl MacSendRatePacer {
    fn pace(&mut self, bytes: usize) {
        if self.bytes_per_sec <= 0.0 || bytes == 0 {
            return;
        }

        let needed = bytes as f64;
        let now = std::time::Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.credit_bytes =
            (self.credit_bytes + elapsed * self.bytes_per_sec).min(self.burst_bytes);
        self.last = now;

        if self.credit_bytes >= needed {
            self.credit_bytes -= needed;
            return;
        }

        let wait_secs = (needed - self.credit_bytes) / self.bytes_per_sec;
        self.credit_bytes = 0.0;
        let deadline = now + std::time::Duration::from_secs_f64(wait_secs);
        let spin_window = std::time::Duration::from_micros(75);
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                self.last = now;
                break;
            }
            let remaining = deadline - now;
            if remaining > spin_window {
                std::thread::sleep(remaining - spin_window);
            } else {
                std::hint::spin_loop();
            }
        }
    }
}

/// Process-wide flag: once the kernel returns EINVAL / EOPNOTSUPP from
/// a UDP_GSO send, we stop trying. Set lazily, never reset.
#[cfg(target_os = "linux")]
static GSO_DISABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
fn is_gso_capability_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidInput
        || matches!(err.raw_os_error(), Some(code)
            if code == libc::EOPNOTSUPP || code == libc::ENOPROTOOPT || code == libc::EIO)
}

/// Size-only GSO eligibility check. Callers MUST ensure all packets
/// share one destination + send target — `flush_batch_sync` does this
/// by grouping. A batch is GSO-eligible iff every packet is the same
/// size, except the last one may be shorter (UDP_GSO's documented
/// behaviour). Real-world TCP-over-FIPS traffic at line rate is
/// almost entirely MTU-sized packets, so this hits on >99% of groups.
#[cfg(target_os = "linux")]
fn gso_eligible_sizes_ref(packets: &[Vec<u8>]) -> bool {
    if packets.len() < 2 {
        // Single-packet groups don't benefit from GSO (no segmentation
        // saving) and just add cmsg overhead.
        return false;
    }
    let seg = packets[0].len();
    if seg == 0 {
        return false;
    }
    for p in &packets[..packets.len() - 1] {
        if p.len() != seg {
            return false;
        }
    }
    // Last packet must be <= seg.
    packets[packets.len() - 1].len() <= seg
}

/// Issue a single `sendmsg(2)` with the `UDP_SEGMENT` cmsg, handing
/// the kernel a scatter-gather list of N same-size packets which it
/// emits as N on-the-wire UDP datagrams from one skb walk.
///
/// Scatter-gather: we pass each wire packet as its own iovec. With
/// UDP_GSO, the kernel concatenates iovecs into one logical payload
/// before segmenting, so we avoid a separate "memcpy all packets into
/// one big buffer" step.
#[cfg(target_os = "linux")]
fn send_batch_gso(
    fd: std::os::unix::io::RawFd,
    packets: &[Vec<u8>],
    dest: SocketAddr,
    connected: bool,
) -> std::io::Result<()> {
    debug_assert!(!packets.is_empty());
    let n = packets.len().min(LINUX_UDP_SEND_BATCH_MAX);
    if n == 0 {
        return Ok(());
    }

    let seg_size = packets[0].len() as u16;
    let sa: socket2::SockAddr = dest.into();

    // Stack-allocated arrays sized for the worst case in this batch.
    let mut iovs: [libc::iovec; LINUX_UDP_SEND_BATCH_MAX] = unsafe { std::mem::zeroed() };
    for (i, data) in packets[..n].iter().enumerate() {
        iovs[i].iov_base = data.as_ptr() as *mut libc::c_void;
        iovs[i].iov_len = data.len();
    }

    // Storage for the destination address. Only populated + linked
    // into `msghdr.msg_name` when sending via the wildcard listen
    // socket — the connected socket has the destination cached
    // kernel-side via `connect()`.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let sa_len = sa.len();
    if !connected {
        unsafe {
            std::ptr::copy_nonoverlapping(
                sa.as_ptr() as *const u8,
                &mut storage as *mut _ as *mut u8,
                sa_len as usize,
            );
        }
    }

    // Control message buffer: one cmsghdr + 2 bytes payload (u16
    // segment_size), padded to the cmsg alignment.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize };
    let mut cmsg_buf = [0u8; 64];
    debug_assert!(cmsg_space <= cmsg_buf.len());

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    if connected {
        // Connected socket: kernel rejects non-null msg_name with
        // EISCONN unless it matches the connect()'ed address. Safest
        // and fastest is to leave it null.
        msg.msg_name = std::ptr::null_mut();
        msg.msg_namelen = 0;
    } else {
        msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
        msg.msg_namelen = sa_len;
    }
    msg.msg_iov = iovs.as_mut_ptr();
    // `msg_iovlen` is `usize` on glibc and `i32` on musl — explicit `as _`
    // cast picks the right one for the target libc.
    msg.msg_iovlen = n as _;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // Fill the UDP_SEGMENT cmsg.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        // `cmsg_level` / `cmsg_type` types differ between glibc and
        // musl; cast through `_` so the field's declared type wins.
        (*cmsg).cmsg_level = libc::IPPROTO_UDP as _;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT as _;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut u16;
        *data = seg_size;
    }

    let r = unsafe { libc::sendmsg(fd, &msg, 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // sendmsg+UDP_GSO either submits the whole super-skb or returns
        // -1; partial submission isn't a thing here.
        Ok(())
    }
}

/// Direct `sendmmsg(2)` wrapper for the sync worker. The
/// `transport::udp::socket` module's existing `send_batch` is
/// pub(crate) on `UdpRawSocket`, but we don't have a handle to the
/// raw socket from here — we just have the FD. Re-implementing
/// inline is ~15 lines and avoids tunnelling the inner socket
/// through `AsyncUdpSocket` for the sync path.
#[cfg(target_os = "linux")]
fn send_batch_raw(
    fd: std::os::unix::io::RawFd,
    packets: &[Vec<u8>],
    dest: SocketAddr,
    connected: bool,
) -> std::io::Result<usize> {
    let n = packets.len().min(LINUX_UDP_SEND_BATCH_MAX);
    if n == 0 {
        return Ok(0);
    }
    let mut iovs: [libc::iovec; LINUX_UDP_SEND_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut storage_len: libc::socklen_t = 0;
    let mut msgs: [libc::mmsghdr; LINUX_UDP_SEND_BATCH_MAX] = unsafe { std::mem::zeroed() };

    // Within one group, every packet shares the destination — build
    // the sockaddr once and point every mmsghdr at it. (kernel copies
    // out of msg_name during the syscall, so a shared backing store
    // is safe.)
    if !connected {
        let sa: socket2::SockAddr = dest.into();
        let sa_len = sa.len();
        unsafe {
            std::ptr::copy_nonoverlapping(
                sa.as_ptr() as *const u8,
                &mut storage as *mut _ as *mut u8,
                sa_len as usize,
            );
        }
        storage_len = sa_len;
    }

    for i in 0..n {
        let data = &packets[i];
        iovs[i].iov_base = data.as_ptr() as *mut libc::c_void;
        iovs[i].iov_len = data.len();
        msgs[i].msg_hdr.msg_iov = &mut iovs[i];
        // `msg_iovlen` is `usize` on glibc / `i32` on musl.
        msgs[i].msg_hdr.msg_iovlen = 1 as _;
        if connected {
            // Connected socket: kernel has destination cached. Leaving
            // msg_name null skips the per-message sockaddr fixup +
            // route lookup; that's the whole point of the connected
            // fast path.
            msgs[i].msg_hdr.msg_name = std::ptr::null_mut();
            msgs[i].msg_hdr.msg_namelen = 0;
        } else {
            msgs[i].msg_hdr.msg_name = &mut storage as *mut _ as *mut libc::c_void;
            msgs[i].msg_hdr.msg_namelen = storage_len;
        }
    }

    let r = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}
