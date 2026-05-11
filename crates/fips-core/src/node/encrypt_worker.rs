//! Off-task FMP encrypt + UDP send worker.
//!
//! The sender hot path of FIPS used to do every step of an outbound
//! packet — session lookup, FSP encrypt, datagram serialise, link
//! lookup, FMP encrypt, UDP `sendto` — sequentially on the single
//! `rx_loop` tokio task. At line rate that task pegs at 99.9% CPU on
//! one core while five other tokio workers sit at 6–40% each. The
//! send pipeline's measured cost breakdown (FIPS_PERF stats on AMD
//! Ryzen 7 7700, single-stream TCP at ~91 kpps):
//!
//! ```
//! endpoint_send  ≈ 2170 ns/pkt   (whole handle_endpoint_data_command)
//!   fsp_encrypt  ≈  550 ns/pkt
//!   fmp_encrypt  ≈  550 ns/pkt
//!   udp_send     ≈  150 ns/pkt   (amortised sendmmsg)
//!   "other"      ≈  920 ns/pkt   (dispatch + state ops)
//! ```
//!
//! The two AEADs + the syscall are pure CPU work that can run on
//! another core; only the "other" 920 ns is genuinely serial because
//! it mutates per-session / per-peer state. Splitting the pipeline at
//! the FMP layer hands the rx_loop ~700 ns back per packet — at
//! 100 kpps that's ~70 ms/s of one core, which is exactly what we
//! need to unstick the single-task bottleneck.
//!
//! The worker takes a pre-cooked [`FmpSendJob`] (pre-reserved counter,
//! a fully-built wire buffer `[16-byte FMP header][inner plaintext]`
//! with TAG_SIZE trailing capacity, a cloned cipher, an `AsyncUdpSocket`
//! handle, and the destination `SocketAddr`) and does the AEAD
//! `seal_in_place_separate_tag` + a single `sendmsg(2) + UDP_SEGMENT`
//! (Linux GSO) or `sendmmsg(2)` fallback. It never touches `Node`
//! state, so any number of these can run in parallel against the same
//! peer.
//!
//! **UDP_GSO note** — the GSO path is verified end-to-end via a
//! loopback round-trip unit test (see `tests::gso_roundtrip_loopback`).
//! On a docker veth/bridge the perf gain from GSO is muted because the
//! kernel does software segmentation on egress and the veth peer-skb
//! cost dominates; on a real NIC (or `--network=host` benches) the
//! single skb walk through the TX stack lands the expected win.

use crate::node::wire::ESTABLISHED_HEADER_SIZE;
use crate::transport::udp::socket::AsyncUdpSocket;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// A pre-cooked FMP-encrypt-and-send job. All state-touching work
/// (counter reservation, MMP/stats update) was already done on the
/// rx_loop before this was built; the worker only does the AEAD +
/// syscall.
///
/// **Wire-buf layout** — `wire_buf` is built on the rx_loop side as
/// the **final wire packet, minus the trailing AEAD tag**:
///
/// ```text
///   ┌──────────────────────────────┬────────────────────────────┐
///   │ FMP outer header (16 bytes)  │   inner plaintext (var)    │
///   └──────────────────────────────┴────────────────────────────┘
///   ^ wire_buf[0..16]                ^ wire_buf[16..]
///   used as AAD                      sealed in place
/// ```
///
/// Capacity is reserved for an additional 16-byte tag at the end so
/// the worker can `seal_in_place_separate_tag` on `wire_buf[16..]` and
/// then `wire_buf.extend_from_slice(&tag)` without re-growing. After
/// seal, `wire_buf` IS the wire packet — no second alloc / memcpy.
///
/// (Previous design used a separate `header: [u8; 16]` + `inner_plaintext:
/// Vec<u8>` and then memcpy'd header + ciphertext into a fresh `Vec`
/// inside the worker. That second alloc + ~1.5 KB memcpy per packet at
/// line rate cost ~150 MB/sec of memory bandwidth on the hot worker.)
pub(crate) struct FmpSendJob {
    /// Cloned FMP send cipher. `LessSafeKey` is `Clone` (`ring::aead`)
    /// — the clone is just a refcount bump on the inner key material.
    pub cipher: LessSafeKey,
    /// Pre-reserved monotonic counter (via `take_send_counter`).
    pub counter: u64,
    /// Pre-built wire buffer: `[16-byte FMP header][inner plaintext]`
    /// with TAG_SIZE bytes of trailing capacity reserved for the AEAD
    /// tag. The header bytes (`[0..16]`) double as both the AAD input
    /// and the prefix of the final wire packet — there is exactly one
    /// allocation per outbound packet (already incurred on the rx_loop
    /// path to build the inner header), reused end-to-end.
    pub wire_buf: Vec<u8>,
    /// AsyncUdpSocket clone (internally `Arc<AsyncFd<UdpRawSocket>>`,
    /// so the clone is just a refcount bump). Used as the **fallback**
    /// send fd when no per-peer connected socket is available — i.e.
    /// the wildcard listen socket. Kernel serialises concurrent
    /// `sendto` calls so multiple workers sharing this handle is safe.
    pub socket: AsyncUdpSocket,
    /// Destination kernel `SocketAddr` — resolved on rx_loop side so
    /// the worker can skip the per-packet DNS / address parse. Used
    /// when sending via the listen socket (msg_name field of mmsghdr).
    /// Ignored when `connected_socket` is `Some` (the kernel knows
    /// the destination already).
    pub dest_addr: SocketAddr,
    /// **Linux fast path:** when set, the worker `sendmsg(2)`s on
    /// this socket's fd with `msg_name = NULL` instead of the listen
    /// socket. The kernel skips per-packet sockaddr handling + route
    /// + neighbor resolution because they're cached from the
    /// `connect()` call. The `Arc` keeps the kernel fd alive for the
    /// lifetime of this job; once the job completes and the worker
    /// drops it, only the peer's strong ref remains.
    #[cfg(target_os = "linux")]
    pub connected_socket:
        Option<std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
}

/// Handle to the encrypt worker pool. Dispatches jobs **hash-by-
/// destination** across N worker tasks via per-worker unbounded
/// mpsc senders. The channels are unbounded because rx_loop's
/// natural drain cap (256 commands per scheduler tick) and the
/// kernel UDP recv buffer further upstream already bound the
/// inflight count; an unbounded push here is wait-free at the
/// dispatcher side.
///
/// **Ordering: hash-by-destination, not round-robin.** Round-robin
/// across N workers causes UDP packet reordering on the wire, which
/// the receiving TCP layer reacts to with dup-ACK-triggered
/// fast-retransmits — measured in bench: 2 workers on a single-flow
/// TCP run dropped throughput 1308 → 1069 Mbps and pushed Retr count
/// from 0 to 8058. Hashing on the destination kernel `SocketAddr`
/// keeps all packets for one flow on one worker, preserving the FIFO
/// order TCP expects. Multi-peer / multi-flow benches still get the
/// parallelism since different destinations hash to different workers.
/// Per-worker bounded crossbeam channel cap. The crossbeam channel
/// uses a sync `Condvar` for blocking on empty — there's no tokio
/// involvement on either end of the wire, so wake cost is the raw
/// kernel futex (~150 ns on Linux, ~250 ns on macOS) instead of
/// tokio's runtime bookkeeping + futex_wake bridge (~600 ns measured
/// in this session's earlier `blocking_recv` regression on bounded
/// mpsc → blocking_lock path). Bounded so the producer back-pressures
/// the rx_loop if the worker thread can't keep up — same rationale as
/// the bounded endpoint_commands channel further upstream.
const WORKER_CHANNEL_CAP: usize = 32768;

/// Handle to the encrypt worker pool.
///
/// Workers are **dedicated `std::thread`s** with **`crossbeam_channel`**
/// between them and the rx_loop. The earlier tokio-task version of
/// this worker pool was the right shape, but every cross-runtime
/// wake (rx_loop's tokio task → tokio worker task) costs the tokio
/// scheduler an internal hop. Replacing the worker side with a sync
/// OS thread, and the channel with crossbeam (where both `.send()`
/// and `.recv()` are wait-free fast-paths and the blocking wake is a
/// single kernel futex), cuts the dispatch round-trip to the
/// platform minimum — same pattern boringtun uses for its main loop.
///
/// **Ordering: hash-by-destination** so single-flow TCP keeps its
/// FIFO ordering (round-robin caused 8000 retransmits in an earlier
/// experiment — see the git log for the 56e0ca8 fix). Multi-peer /
/// multi-flow benches still get parallelism since different
/// destinations hash to different workers.
#[derive(Clone)]
pub(crate) struct EncryptWorkerPool {
    senders: Arc<[Sender<FmpSendJob>]>,
}

impl EncryptWorkerPool {
    /// Spawn `n` worker **OS threads** and return a handle that
    /// dispatches jobs hash-by-destination to them. The workers exit
    /// when all senders for their channel are dropped (i.e. when the
    /// returned `EncryptWorkerPool` and all clones go away).
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = bounded::<FmpSendJob>(WORKER_CHANNEL_CAP);
            std::thread::Builder::new()
                .name(format!("fips-encrypt-{i}"))
                .spawn(move || run_worker(i, rx))
                .expect("failed to spawn fips-encrypt OS thread");
            senders.push(tx);
        }
        Self {
            senders: senders.into(),
        }
    }

    /// Dispatch a job to the worker that owns its destination flow.
    /// The hash is over `dest_addr` so every packet for one peer's
    /// kernel `SocketAddr` lands on the same worker and stays in
    /// order — required for TCP's fast-retransmit logic above to
    /// behave on a single-flow run. Fire-and-forget — the worker
    /// handles send errors itself via stats counters.
    ///
    /// Uses `try_send` rather than blocking `send`: under sustained
    /// rate-overrun this *will* drop packets at the dispatch point
    /// (i.e. the caller can't push faster than the worker can chew),
    /// which is the correct UDP behaviour and matches what the kernel
    /// TUN tx queue does upstream. A debug log fires on the first few
    /// drops to surface the cliff.
    pub fn dispatch(&self, job: FmpSendJob) {
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping job");
            return;
        }
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        job.dest_addr.hash(&mut h);
        let idx = (h.finish() as usize) % self.senders.len();
        match self.senders[idx].try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                static FULL_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        drops = n + 1,
                        "EncryptWorker channel full; dropping outbound packet"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(worker = idx, "EncryptWorker thread gone; dropping job");
            }
        }
    }
}

/// Sync OS-thread worker loop. Blocks on the crossbeam channel via
/// kernel futex (no tokio runtime involvement), drains follow-on
/// packets into a fixed-size local batch, then issues one
/// `sendmmsg(2)` per drain cycle.
fn run_worker(idx: usize, rx: Receiver<FmpSendJob>) {
    trace!(worker = idx, "FMP encrypt worker thread starting");

    const BATCH_SIZE: usize = 32;
    let mut batch: Vec<FmpSendJob> = Vec::with_capacity(BATCH_SIZE);

    loop {
        // Blocking recv — parks the OS thread on the channel's
        // internal Condvar/futex until a job arrives or the channel
        // closes.
        let first = match rx.recv() {
            Ok(j) => j,
            Err(_) => break, // all senders dropped → graceful exit
        };
        batch.push(first);
        // Drain follow-on jobs without blocking, up to BATCH_SIZE.
        // Same drain pattern as the bounded mpsc one above — gives
        // sendmmsg something to amortise over.
        while batch.len() < BATCH_SIZE {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        if let Err(err) = flush_batch_sync(&mut batch) {
            debug!(worker = idx, error = %err, "FMP encrypt worker batch flush failed");
        }
    }
    trace!(worker = idx, "FMP encrypt worker thread exiting");
}

/// Encrypt every job in `batch` in place, then issue one or more
/// bulk-send syscalls grouped **by exact send target**. Clears
/// `batch` on return. Sync version — operates directly on the raw
/// nonblocking UDP fd with a retry-on-EAGAIN loop; no tokio reactor.
///
/// **Why grouping is required:** `EncryptWorkerPool::dispatch` hashes
/// `job.dest_addr` modulo the worker count to pick a worker — this
/// pins one peer's flow to one worker (FIFO order preserved for
/// TCP), but it does NOT mean every job in a worker's drained batch
/// shares a target. Two different peers can hash to the same
/// worker. The previous implementation cloned `batch[0].socket` /
/// `batch[0].connected_socket` and used them for the entire batch,
/// silently misdirecting packets:
///
/// - **Connected-socket path:** `sendmsg(.., msg_name=NULL)` delivers
///   to the peer cached at `connect(2)` time. Mixing jobs across
///   peers sent all of them to the first peer's connected socket.
/// - **UDP_GSO path:** the super-skb has one `msg_name` + one
///   `UDP_SEGMENT` cmsg. Mixing destinations sent the segmented
///   payload to `packets[0].dest_addr` regardless of each job's
///   intended target.
/// - **Plain `sendmmsg` path:** the kernel honours per-message
///   `msg_name`, so the non-connected fallback was actually safe —
///   but we group anyway for code symmetry and to keep GSO
///   eligibility checks simple.
///
/// **Order preservation:** within one target group the iteration
/// order is the channel-drain order, which is FIFO from the
/// rx_loop. TCP's fast-retransmit logic only cares about per-flow
/// ordering, and a single flow lives entirely inside one group.
fn flush_batch_sync(
    batch: &mut Vec<FmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if batch.is_empty() {
        return Ok(());
    }

    // FIPS_PERF: one AEAD timer span over the whole batch — average
    // per-packet falls out of the COUNT increment once per flush.
    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);

    // Per-target encrypted-packet group. Vec layout (not HashMap)
    // because the typical batch has 1 target (hash-by-dest dispatch),
    // 2-3 worst-case under hash collisions — linear lookup beats
    // hashing for that range and keeps insertion order stable, so
    // the bursty peer's tail packets flush first.
    #[cfg(unix)]
    struct EncryptedGroup {
        socket: AsyncUdpSocket,
        #[cfg(target_os = "linux")]
        connected_socket:
            Option<std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
        dest_addr: SocketAddr,
        wire_packets: Vec<Vec<u8>>,
    }
    #[cfg(unix)]
    let mut groups: Vec<EncryptedGroup> = Vec::with_capacity(1);

    for job in batch.drain(..) {
        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            socket,
            dest_addr,
            #[cfg(target_os = "linux")]
            connected_socket,
        } = job;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        // Split-borrow: AAD reads from header bytes [0..16], seal writes
        // into the plaintext slice [16..]. ring::aead's `seal_in_place_
        // separate_tag` takes `&mut [u8]` so we can hand it the
        // post-header slice while AAD references the header slice.
        // `split_at_mut` is the standard way to do this safely.
        let (header_slice, plaintext_slice) = wire_buf.split_at_mut(ESTABLISHED_HEADER_SIZE);
        let tag = match cipher.seal_in_place_separate_tag(
            nonce,
            Aad::from(&*header_slice),
            plaintext_slice,
        ) {
            Ok(tag) => tag,
            Err(_) => continue,
        };
        // wire_buf already has `+16` capacity reserved → no realloc.
        wire_buf.extend_from_slice(tag.as_ref());

        #[cfg(unix)]
        {
            // Compare by RawFd, not the `AsyncUdpSocket` / Arc identity —
            // identity comparison breaks if two jobs carry separately-
            // cloned handles to the same kernel fd, which happens
            // routinely on the rx_loop side. The kernel fd is the only
            // thing that matters for what `sendmsg(2)` actually does.
            let socket_fd = socket.as_raw_fd();
            #[cfg(target_os = "linux")]
            let connected_fd = connected_socket.as_ref().map(|s| s.as_raw_fd());
            let matched = groups.iter_mut().position(|g| {
                if g.dest_addr != dest_addr {
                    return false;
                }
                if g.socket.as_raw_fd() != socket_fd {
                    return false;
                }
                #[cfg(target_os = "linux")]
                {
                    if g.connected_socket.as_ref().map(|s| s.as_raw_fd()) != connected_fd {
                        return false;
                    }
                }
                true
            });
            if let Some(idx) = matched {
                groups[idx].wire_packets.push(wire_buf);
            } else {
                groups.push(EncryptedGroup {
                    socket,
                    #[cfg(target_os = "linux")]
                    connected_socket,
                    dest_addr,
                    wire_packets: vec![wire_buf],
                });
            }
        }
        #[cfg(not(unix))]
        {
            // Windows: encrypt worker pool isn't spawned (see
            // lifecycle.rs); this function is unreachable. Drop
            // values explicitly so the compiler sees them as used.
            let _ = (socket, dest_addr, wire_buf);
        }
    }

    drop(_t); // close the encrypt timer before we open the send timer

    // 2) Bulk send each group via its own raw FD.
    //
    // **Preferred (Linux only): UDP_GSO** — when every wire packet in
    // a group is the same size (last may be shorter, which the kernel
    // handles), one `sendmsg(2)` with the `UDP_SEGMENT` cmsg lets the
    // kernel split one "super-skb" into N on-the-wire UDP datagrams
    // in a single skb-walk. Profiling on AMD VM showed `sendmmsg(2)`
    // taking ~4.5 µs per packet at single-flow TCP rates — the kernel
    // TX path was the actual bottleneck, not the AEAD. UDP_GSO
    // collapses that to ~one walk per group. Same primitive WireGuard
    // kernel + boringtun use to hit 2.5-3.2 Gbps.
    //
    // **Fallback: sendmmsg(2)** — used when sizes differ in the
    // group (FIPS control frames + EndpointData mixed), and after a
    // one-shot EINVAL/EOPNOTSUPP from UDP_GSO sticks the
    // GSO_DISABLED flag. Same retry-on-EAGAIN loop as before.
    //
    // On EAGAIN we `yield_now()` — the kernel UDP socket is in
    // nonblocking mode (`UdpRawSocket::open`), and at line rate the
    // kernel send buffer (8 MiB by `DEFAULT_UDP_SEND_BUF`) is rarely
    // full so this is the cold path.
    let _t2 = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);

    #[cfg(target_os = "linux")]
    for group in groups {
        let EncryptedGroup {
            socket,
            connected_socket,
            dest_addr,
            wire_packets,
        } = group;
        let (fd, connected) = match connected_socket.as_ref() {
            Some(s) => (s.as_raw_fd(), true),
            None => (socket.as_raw_fd(), false),
        };

        // Within a group, destination is uniform by construction —
        // GSO needs only the size check now.
        if !GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed)
            && gso_eligible_sizes(&wire_packets)
        {
            match send_batch_gso(fd, &wire_packets, dest_addr, connected) {
                Ok(()) => continue,
                Err(err)
                    if err.kind() == std::io::ErrorKind::InvalidInput
                        || err.raw_os_error() == Some(libc::EOPNOTSUPP)
                        || err.raw_os_error() == Some(libc::ENOPROTOOPT) =>
                {
                    GSO_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        error = %err,
                        "UDP_GSO refused by kernel; falling back to sendmmsg for life of process"
                    );
                    // fall through to sendmmsg path for this group
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // Send buffer full mid-GSO — fall through to
                    // sendmmsg retry loop. No GSO_DISABLED toggle.
                }
                Err(err) => {
                    return Err(format!("sendmsg+UDP_GSO failed: {err}").into());
                }
            }
        }

        let mut sent = 0usize;
        while sent < wire_packets.len() {
            let n = match send_batch_raw(fd, &wire_packets[sent..], dest_addr, connected) {
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                    continue;
                }
                Err(err) => {
                    return Err(format!("sendmmsg(2) failed: {err}").into());
                }
            };
            if n == 0 {
                break;
            }
            sent += n;
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    for group in groups {
        let fd = group.socket.as_raw_fd();
        for data in &group.wire_packets {
            loop {
                match send_one_raw(fd, data, &group.dest_addr) {
                    Ok(_) => break,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(err) => {
                        return Err(format!("sendto failed: {err}").into());
                    }
                }
            }
        }
    }
    // Windows: encrypt worker pool isn't spawned at all (see
    // lifecycle.rs), so this function is never reached. The
    // tokio-backed `AsyncUdpSocket::send_to` path on the rx_loop
    // remains the only outbound path on that platform.
    Ok(())
}

/// Process-wide flag: once the kernel returns EINVAL / EOPNOTSUPP from
/// a UDP_GSO send, we stop trying. Set lazily, never reset.
#[cfg(target_os = "linux")]
static GSO_DISABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Size-only GSO eligibility check. Callers MUST ensure all packets
/// share one destination + send target — `flush_batch_sync` does this
/// by grouping. A batch is GSO-eligible iff every packet is the same
/// size, except the last one may be shorter (UDP_GSO's documented
/// behaviour). Real-world TCP-over-FIPS traffic at line rate is
/// almost entirely MTU-sized packets, so this hits on >99% of groups.
#[cfg(target_os = "linux")]
fn gso_eligible_sizes(packets: &[Vec<u8>]) -> bool {
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
    const MAX_BATCH: usize = 64;
    let n = packets.len().min(MAX_BATCH);
    if n == 0 {
        return Ok(());
    }

    let seg_size = packets[0].len() as u16;
    let sa: socket2::SockAddr = dest.into();

    // Stack-allocated arrays sized for the worst case in this batch.
    let mut iovs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
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
    const MAX_BATCH: usize = 32;
    let n = packets.len().min(MAX_BATCH);
    if n == 0 {
        return Ok(0);
    }
    let mut iovs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut storage_len: libc::socklen_t = 0;
    let mut msgs: [libc::mmsghdr; MAX_BATCH] = unsafe { std::mem::zeroed() };

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

/// Standalone tests for the GSO-eligibility predicate. The full
/// `send_batch_gso` is exercised in `tests::gso_roundtrip` below
/// (Linux only — UDP_GSO + connected-peer fast paths are Linux-only,
/// so the entire test module is gated to Linux to avoid dead-code
/// warnings on macOS / BSD builds).
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn pkt(bytes: usize) -> Vec<u8> {
        vec![0u8; bytes]
    }

    #[test]
    fn gso_eligible_rejects_single_packet() {
        assert!(!gso_eligible_sizes(&[pkt(1500)]));
    }

    #[test]
    fn gso_eligible_accepts_uniform_batch() {
        let batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        assert!(gso_eligible_sizes(&batch));
    }

    #[test]
    fn gso_eligible_accepts_short_trailer() {
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        batch.push(pkt(900)); // last shorter — kernel handles this
        assert!(gso_eligible_sizes(&batch));
    }

    #[test]
    fn gso_eligible_rejects_mixed_sizes() {
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        batch[3] = pkt(800); // mid-batch short packet
        batch.push(pkt(1500));
        assert!(!gso_eligible_sizes(&batch));
    }

    /// End-to-end: bind a real UDP socket pair on loopback, fire
    /// `send_batch_gso` from the sender, recv on the receiver, confirm
    /// we get N segmented datagrams back (one per logical packet).
    ///
    /// This validates the entire UDP_GSO codepath: cmsg setup,
    /// scatter-gather iov assembly, kernel segmentation. If the
    /// running kernel doesn't support UDP_SEGMENT the syscall returns
    /// EOPNOTSUPP and we skip the assertion (the prod path falls back
    /// to sendmmsg via the GSO_DISABLED flag).
    #[test]
    fn gso_roundtrip_loopback() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        // Sender + receiver on loopback.
        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let recv_addr = recv_sock.local_addr().expect("recv local_addr");
        recv_sock
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set_read_timeout");
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");

        // Build a uniform 18-packet batch addressed at recv_sock.
        const SEG: usize = 200;
        const N: usize = 18;
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(N);
        for i in 0..N {
            let mut buf = vec![0u8; SEG];
            // Stamp the packet index in the first byte so we can verify
            // ordering on the receive side.
            buf[0] = i as u8;
            batch.push(buf);
        }

        let r = send_batch_gso(
            send_sock.as_raw_fd(),
            &batch,
            recv_addr,
            /* connected */ false,
        );
        match r {
            Ok(()) => {} // proceed to recv
            Err(err)
                if err.raw_os_error() == Some(libc::EOPNOTSUPP)
                    || err.raw_os_error() == Some(libc::ENOPROTOOPT)
                    || err.kind() == std::io::ErrorKind::InvalidInput =>
            {
                eprintln!(
                    "gso_roundtrip_loopback: kernel doesn't support UDP_GSO ({err}); skipping"
                );
                return;
            }
            Err(err) => panic!("send_batch_gso failed: {err}"),
        }

        // Drain receive side — expect exactly N datagrams of SEG bytes
        // each, in order.
        let mut recv_buf = [0u8; SEG + 32];
        for i in 0..N {
            let (len, _from) = recv_sock
                .recv_from(&mut recv_buf)
                .unwrap_or_else(|e| panic!("recv {i}: {e}"));
            assert_eq!(len, SEG, "datagram {i} has wrong length");
            assert_eq!(
                recv_buf[0], i as u8,
                "datagram {i} arrived out of order or with wrong stamp"
            );
        }
    }

    /// `send_batch_raw` (the sendmmsg fallback) must deliver every
    /// packet to the shared dest passed alongside the slice. Two
    /// receivers + one mixed batch would be the wrong shape (the
    /// shared sockaddr means one receiver per call); this test
    /// validates the per-call contract: N packets in, N packets out
    /// at one address.
    #[test]
    fn sendmmsg_uniform_dest_roundtrip() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let recv_addr = recv_sock.local_addr().unwrap();
        recv_sock
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set_read_timeout");
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");
        send_sock.set_nonblocking(true).unwrap();

        let packets: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let mut v = vec![0u8; 16];
                v[0] = i as u8;
                v
            })
            .collect();
        let n =
            send_batch_raw(send_sock.as_raw_fd(), &packets, recv_addr, false).expect("sendmmsg ok");
        assert_eq!(n, 4);

        let mut buf = [0u8; 64];
        let mut stamps: Vec<u8> = Vec::new();
        for _ in 0..4 {
            let (len, _) = recv_sock.recv_from(&mut buf).expect("recv");
            assert_eq!(len, 16);
            stamps.push(buf[0]);
        }
        stamps.sort();
        assert_eq!(stamps, vec![0, 1, 2, 3]);
    }

    /// Mixed-destination batch dispatched to a single worker. The
    /// pre-fix bug used `batch[0].socket` / `batch[0].connected_socket`
    /// / `packets[0].dest_addr` for the whole drained batch, so a
    /// hash-collision (two peers hashing to the same worker) silently
    /// misdirected the second peer's packets to the first peer's
    /// destination. The fix groups jobs by `(socket_fd, connected_fd,
    /// dest_addr)` before flushing.
    ///
    /// This test goes through `flush_batch_sync` directly: it constructs
    /// three `FmpSendJob`s split across two distinct receiver sockaddrs
    /// (A, B, A) on a shared send socket with no connected socket, then
    /// asserts that recv_a gets the two A-stamped packets and recv_b
    /// gets exactly the one B-stamped packet.
    ///
    /// We have to spin a tokio runtime because `AsyncUdpSocket` wraps a
    /// `tokio::io::unix::AsyncFd`, which requires a registered reactor
    /// at construction time. The actual `flush_batch_sync` work is sync
    /// (raw-fd `sendmmsg`); we just need the AsyncFd alive for the
    /// AsRawFd impl.
    #[test]
    fn flush_batch_routes_each_target_separately() {
        use crate::transport::udp::socket::UdpRawSocket;
        use ring::aead::{LessSafeKey, UnboundKey};
        use std::net::UdpSocket;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            // Two receivers — distinct kernel sockaddrs.
            let recv_a = UdpSocket::bind("127.0.0.1:0").expect("bind recv_a");
            let recv_b = UdpSocket::bind("127.0.0.1:0").expect("bind recv_b");
            for s in [&recv_a, &recv_b] {
                s.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .expect("set_read_timeout");
            }
            let addr_a = recv_a.local_addr().unwrap();
            let addr_b = recv_b.local_addr().unwrap();

            // One send socket shared by all jobs (the wildcard listen
            // socket in production). `UdpRawSocket::open` builds a
            // socket2 socket; `into_async` wraps it in tokio's AsyncFd
            // and hands back an AsyncUdpSocket.
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let send_sock = raw.into_async().expect("into_async");

            // Throwaway AEAD cipher — content doesn't matter, we just
            // need encrypt to succeed so a wire packet lands.
            let key_bytes = [0u8; 32];
            let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes)
                .expect("build unbound key");
            let cipher = LessSafeKey::new(unbound);

            fn make_job(
                socket: crate::transport::udp::socket::AsyncUdpSocket,
                cipher: &LessSafeKey,
                counter: u64,
                dest: SocketAddr,
                stamp: u8,
            ) -> FmpSendJob {
                // wire_buf: 16-byte header + 32-byte plaintext + tag-room.
                // Stamp a marker after the header so we can identify
                // which packet landed where.
                let mut wire_buf = Vec::with_capacity(16 + 32 + 16);
                wire_buf.extend_from_slice(&[0u8; 16]);
                wire_buf.extend_from_slice(&[0u8; 32]);
                wire_buf[16] = stamp;
                FmpSendJob {
                    cipher: cipher.clone(),
                    counter,
                    wire_buf,
                    socket,
                    dest_addr: dest,
                    connected_socket: None,
                }
            }

            let mut batch = vec![
                make_job(send_sock.clone(), &cipher, 1, addr_a, 0xAA),
                make_job(send_sock.clone(), &cipher, 2, addr_b, 0xBB),
                make_job(send_sock.clone(), &cipher, 3, addr_a, 0xCC),
            ];
            flush_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            // recv_a expects two distinct stamps (AA, CC).
            let mut buf = [0u8; 128];
            let mut stamps_a: Vec<u8> = Vec::new();
            for _ in 0..2 {
                let (len, _) = recv_a.recv_from(&mut buf).expect("recv_a");
                assert!(len > 16, "packet too short");
                stamps_a.push(buf[16]);
            }
            stamps_a.sort();
            assert_eq!(stamps_a, vec![0xAA, 0xCC]);

            // recv_b expects exactly one stamp (BB).
            let (len, _) = recv_b.recv_from(&mut buf).expect("recv_b");
            assert!(len > 16, "packet too short");
            assert_eq!(buf[16], 0xBB);

            // recv_b must NOT receive any extra packets — the pre-fix
            // bug would have sent everything to addr_a (the first
            // job's destination).
            recv_b
                .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                .unwrap();
            let drained = recv_b.recv_from(&mut buf);
            assert!(
                drained.is_err(),
                "recv_b got unexpected extra packet: {:?}",
                drained
            );
        });
    }
}

/// Direct `sendto(2)` for non-Linux unix (macOS / BSD). Windows
/// doesn't reach this — encrypt_worker is gated to `unix` in
/// `lifecycle.rs` (the per-worker raw-fd send loop only applies on
/// unix; on Windows the rx_loop fallback path takes outbound packets
/// through tokio's `AsyncUdpSocket::send_to`).
#[cfg(all(unix, not(target_os = "linux")))]
fn send_one_raw(
    fd: std::os::unix::io::RawFd,
    data: &[u8],
    dest: &SocketAddr,
) -> std::io::Result<usize> {
    let sa: socket2::SockAddr = (*dest).into();
    let r = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            sa.as_ptr() as *const libc::sockaddr,
            sa.len(),
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}
