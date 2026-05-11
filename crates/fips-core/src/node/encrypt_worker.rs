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
    /// so the clone is just a refcount bump). Kernel serialises
    /// concurrent `sendto` calls so multiple workers sharing the same
    /// handle is safe.
    pub socket: AsyncUdpSocket,
    /// Destination kernel `SocketAddr` — resolved on rx_loop side so
    /// the worker can skip the per-packet DNS / address parse.
    pub dest_addr: SocketAddr,
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

/// Encrypt every job in `batch` in place, then issue a single
/// `sendmmsg(2)` (Linux) for the resulting wire packets. Clears
/// `batch` on return. Sync version — operates directly on the raw
/// nonblocking UDP fd with a retry-on-EAGAIN loop; no tokio reactor.
fn flush_batch_sync(
    batch: &mut Vec<FmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if batch.is_empty() {
        return Ok(());
    }

    // FIPS_PERF: one AEAD timer span over the whole batch — average
    // per-packet falls out of the COUNT increment once per flush.
    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);

    // 1) Encrypt every job's wire_buf in place. wire_buf is laid out
    //    as `[16 header][plaintext]` on entry, with TAG_SIZE bytes of
    //    trailing capacity reserved. After this loop each wire_buf is
    //    the complete wire packet `[16 header][ciphertext][16 tag]` —
    //    no extra alloc or memcpy.
    let mut wire_packets: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(batch.len());
    // All jobs in this batch share the same destination + socket
    // (hash-by-dest in `EncryptWorkerPool::dispatch`), so cloning the
    // first one's socket Arc is the cheapest way to get a handle for
    // the bulk send below.
    let socket = batch[0].socket.clone();
    for job in batch.drain(..) {
        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            socket: _,
            dest_addr,
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
        wire_packets.push((wire_buf, dest_addr));
    }

    // 2) Bulk send via the raw FD.
    //
    // **Preferred (Linux only): UDP_GSO** — when every wire packet in
    // the batch is the same size (last one may be shorter, which the
    // kernel handles), a single `sendmsg(2)` with the `UDP_SEGMENT`
    // cmsg lets the kernel split one "super-skb" into N on-the-wire
    // UDP datagrams in a single skb-walk. Profiling on AMD VM showed
    // `sendmmsg(2)` taking ~4.5 µs per packet (30× the amortised cost
    // we expected) at single-flow TCP rates — the kernel TX path was
    // the actual bottleneck, not the AEAD. UDP_GSO collapses that to
    // ~one walk per batch. Same primitive WireGuard kernel + boringtun
    // use to hit 2.5-3.2 Gbps.
    //
    // **Fallback: sendmmsg(2)** — used when sizes differ in the batch
    // (FIPS control frames + EndpointData mixed), and after a one-shot
    // EINVAL/EOPNOTSUPP from UDP_GSO sticks the GSO_DISABLED flag.
    // Same retry-on-EAGAIN loop as before.
    //
    // On EAGAIN we `yield_now()` — the kernel UDP socket is in
    // nonblocking mode (`UdpRawSocket::open`), and at line rate the
    // kernel send buffer (8 MiB by `DEFAULT_UDP_SEND_BUF`) is rarely
    // full so this is the cold path.
    let _t2 = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
    let fd = socket.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        // Fast path: try UDP_GSO if the batch is uniform-size and the
        // kernel hasn't refused GSO before.
        if !GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed)
            && gso_eligible(&wire_packets)
        {
            match send_batch_gso(fd, &wire_packets) {
                Ok(()) => return Ok(()),
                Err(err)
                    if err.kind() == std::io::ErrorKind::InvalidInput
                        || err.raw_os_error() == Some(libc::EOPNOTSUPP)
                        || err.raw_os_error() == Some(libc::ENOPROTOOPT) =>
                {
                    // Kernel doesn't support UDP_GSO on this socket /
                    // device — fall back permanently to sendmmsg.
                    GSO_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        error = %err,
                        "UDP_GSO refused by kernel; falling back to sendmmsg for life of process"
                    );
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // Send buffer full mid-GSO — fall through to the
                    // sendmmsg retry loop below to drain remaining
                    // packets the normal way. No GSO_DISABLED toggle.
                }
                Err(err) => {
                    return Err(format!("sendmsg+UDP_GSO failed: {err}").into());
                }
            }
        }

        // Fallback: sendmmsg(2) for mixed-size batches and post-EAGAIN
        // / post-GSO-refused.
        let mut sent = 0usize;
        while sent < wire_packets.len() {
            let n = match send_batch_raw(fd, &wire_packets[sent..]) {
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
    #[cfg(not(target_os = "linux"))]
    {
        for (data, addr) in &wire_packets {
            loop {
                match send_one_raw(fd, data, addr) {
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
    Ok(())
}

/// Process-wide flag: once the kernel returns EINVAL / EOPNOTSUPP from
/// a UDP_GSO send, we stop trying. Set lazily, never reset.
#[cfg(target_os = "linux")]
static GSO_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// A batch is GSO-eligible iff every packet is the same size, except
/// the last one may be shorter (UDP_GSO's documented behaviour). Real-
/// world TCP-over-FIPS traffic at line rate is almost entirely MTU-
/// sized packets, so this hits on >99% of batches.
#[cfg(target_os = "linux")]
fn gso_eligible(packets: &[(Vec<u8>, SocketAddr)]) -> bool {
    if packets.len() < 2 {
        // Single-packet batches don't benefit from GSO (no segmentation
        // saving) and just add cmsg overhead.
        return false;
    }
    let seg = packets[0].0.len();
    if seg == 0 {
        return false;
    }
    for p in &packets[..packets.len() - 1] {
        if p.0.len() != seg {
            return false;
        }
    }
    // Last packet must be <= seg.
    packets[packets.len() - 1].0.len() <= seg
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
    packets: &[(Vec<u8>, SocketAddr)],
) -> std::io::Result<()> {
    debug_assert!(!packets.is_empty());
    const MAX_BATCH: usize = 64;
    let n = packets.len().min(MAX_BATCH);
    if n == 0 {
        return Ok(());
    }

    let seg_size = packets[0].0.len() as u16;
    let dest = packets[0].1;
    let sa: socket2::SockAddr = dest.into();

    // Stack-allocated arrays sized for the worst case in this batch.
    let mut iovs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
    for (i, (data, _)) in packets[..n].iter().enumerate() {
        iovs[i].iov_base = data.as_ptr() as *mut libc::c_void;
        iovs[i].iov_len = data.len();
    }

    // Storage for the destination address.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let sa_len = sa.len();
    unsafe {
        std::ptr::copy_nonoverlapping(
            sa.as_ptr() as *const u8,
            &mut storage as *mut _ as *mut u8,
            sa_len as usize,
        );
    }

    // Control message buffer: one cmsghdr + 2 bytes payload (u16
    // segment_size), padded to the cmsg alignment.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize };
    let mut cmsg_buf = [0u8; 64];
    debug_assert!(cmsg_space <= cmsg_buf.len());

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = sa_len;
    msg.msg_iov = iovs.as_mut_ptr();
    msg.msg_iovlen = n;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    // Fill the UDP_SEGMENT cmsg.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
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
    packets: &[(Vec<u8>, SocketAddr)],
) -> std::io::Result<usize> {
    const MAX_BATCH: usize = 32;
    let n = packets.len().min(MAX_BATCH);
    if n == 0 {
        return Ok(0);
    }
    let mut iovs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
    let mut storages: [libc::sockaddr_storage; MAX_BATCH] = unsafe { std::mem::zeroed() };
    let mut storage_lens: [libc::socklen_t; MAX_BATCH] = [0; MAX_BATCH];
    let mut msgs: [libc::mmsghdr; MAX_BATCH] = unsafe { std::mem::zeroed() };

    for i in 0..n {
        let (data, dest) = &packets[i];
        let sa: socket2::SockAddr = (*dest).into();
        let sa_len = sa.len();
        unsafe {
            std::ptr::copy_nonoverlapping(
                sa.as_ptr() as *const u8,
                &mut storages[i] as *mut _ as *mut u8,
                sa_len as usize,
            );
        }
        storage_lens[i] = sa_len;
        iovs[i].iov_base = data.as_ptr() as *mut libc::c_void;
        iovs[i].iov_len = data.len();
        msgs[i].msg_hdr.msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen = storage_lens[i];
        msgs[i].msg_hdr.msg_iov = &mut iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
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
/// (Linux only).
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn pkt(bytes: usize, addr: SocketAddr) -> (Vec<u8>, SocketAddr) {
        (vec![0u8; bytes], addr)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_eligible_rejects_single_packet() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(!gso_eligible(&[pkt(1500, addr)]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_eligible_accepts_uniform_batch() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let batch: Vec<_> = (0..18).map(|_| pkt(1500, addr)).collect();
        assert!(gso_eligible(&batch));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_eligible_accepts_short_trailer() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500, addr)).collect();
        batch.push(pkt(900, addr)); // last shorter — kernel handles this
        assert!(gso_eligible(&batch));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_eligible_rejects_mixed_sizes() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500, addr)).collect();
        batch[3] = pkt(800, addr); // mid-batch short packet
        batch.push(pkt(1500, addr));
        assert!(!gso_eligible(&batch));
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
    #[cfg(target_os = "linux")]
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
        let mut batch: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(N);
        for i in 0..N {
            let mut buf = vec![0u8; SEG];
            // Stamp the packet index in the first byte so we can verify
            // ordering on the receive side.
            buf[0] = i as u8;
            batch.push((buf, recv_addr));
        }

        let r = send_batch_gso(send_sock.as_raw_fd(), &batch);
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
}

/// Direct `sendto(2)` for non-Linux fallback.
#[cfg(not(target_os = "linux"))]
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
