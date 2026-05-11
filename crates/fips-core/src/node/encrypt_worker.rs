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
//! The worker takes a pre-cooked [`FmpSendJob`] (cloned cipher,
//! pre-reserved counter, header bytes for AAD, the inner plaintext
//! Vec, an `AsyncUdpSocket` handle, and the destination `SocketAddr`)
//! and does the AEAD `seal_in_place_append_tag` + a `sendto`. It
//! never touches `Node` state, so any number of these can run in
//! parallel against the same peer.

use crate::node::wire::ESTABLISHED_HEADER_SIZE;
use crate::transport::udp::socket::AsyncUdpSocket;
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// A pre-cooked FMP-encrypt-and-send job. All state-touching work
/// (counter reservation, MMP/stats update) was already done on the
/// rx_loop before this was built; the worker only does the AEAD +
/// syscall.
pub(crate) struct FmpSendJob {
    /// Cloned FMP send cipher. `LessSafeKey` is `Clone` (`ring::aead`)
    /// — the clone is just a refcount bump on the inner key material.
    pub cipher: LessSafeKey,
    /// Pre-reserved monotonic counter (via `take_send_counter`).
    pub counter: u64,
    /// 16-byte FMP outer header. Used as AAD during AEAD and prepended
    /// to the ciphertext to form the wire packet.
    pub header: [u8; ESTABLISHED_HEADER_SIZE],
    /// Inner plaintext (4-byte session timestamp + link-layer
    /// message body). Mutated in place during seal: on entry it's
    /// `plaintext`, on exit it's `plaintext + 16-byte AEAD tag` so we
    /// must reserve TAG_SIZE bytes of capacity *before* dispatch.
    pub inner_plaintext: Vec<u8>,
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
#[derive(Clone)]
pub(crate) struct EncryptWorkerPool {
    senders: Arc<[mpsc::UnboundedSender<FmpSendJob>]>,
}

impl EncryptWorkerPool {
    /// Spawn `n` worker tasks and return a handle that dispatches
    /// jobs hash-by-destination to them. The workers shut down when
    /// all senders for their channel are dropped (i.e. when the
    /// returned `EncryptWorkerPool` and all clones go away).
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = mpsc::unbounded_channel::<FmpSendJob>();
            tokio::spawn(run_worker(i, rx));
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
    pub fn dispatch(&self, job: FmpSendJob) {
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping job");
            return;
        }
        // Cheap hash: fold the SocketAddr into a usize via its octets
        // + port. ahash/SipHash would be more uniform but for the
        // bench's small N (1–8 peers) any reasonable mixing function
        // works and we want to keep the dispatch cost in the noise.
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        job.dest_addr.hash(&mut h);
        let idx = (h.finish() as usize) % self.senders.len();
        if let Err(err) = self.senders[idx].send(job) {
            debug!(worker = idx, error = %err, "EncryptWorker channel closed; dropping job");
        }
    }
}

async fn run_worker(idx: usize, mut rx: mpsc::UnboundedReceiver<FmpSendJob>) {
    trace!(worker = idx, "FMP encrypt worker starting");

    // Per-worker batch buffer. Collect up to BATCH_SIZE jobs from
    // the channel before flushing via `sendmmsg`, amortising the
    // per-syscall kernel cost across the batch (same idea as the
    // per-transport pending_send buffer, but per-worker so workers
    // don't contend for a shared mutex). Workers using hash-by-dest
    // see all packets for one flow → one worker → one batched
    // sendmmsg(2) per drain cycle.
    const BATCH_SIZE: usize = 32;
    let mut batch: Vec<FmpSendJob> = Vec::with_capacity(BATCH_SIZE);

    while let Some(job) = rx.recv().await {
        batch.push(job);
        // Drain follow-on jobs that arrived while we were waking up,
        // up to BATCH_SIZE - 1 more, then flush. Keeps us on this
        // task and gives sendmmsg something to amortise over.
        while batch.len() < BATCH_SIZE {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        if let Err(err) = flush_batch(&mut batch).await {
            debug!(worker = idx, error = %err, "FMP encrypt worker batch flush failed");
        }
        // Some sub-batches followed by drain-empty; loop back to
        // recv().await for the next wake. The above try_recv loop
        // is bounded by BATCH_SIZE so we won't monopolise the task.
    }
    trace!(worker = idx, "FMP encrypt worker exiting");
}

/// Encrypt every job in `batch` in place, then issue a single
/// `sendmmsg(2)` for the resulting wire packets. Clears `batch` on
/// return regardless of success — failed sends are observability,
/// not retried (UDP semantics).
async fn flush_batch(
    batch: &mut Vec<FmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if batch.is_empty() {
        return Ok(());
    }

    // FIPS_PERF for the AEAD step. One timer span over the whole
    // batch — average per-packet falls out of the COUNT increment
    // happening once per call here.
    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);

    // 1) Encrypt every job into its existing inner_plaintext buffer.
    //    Build the wire packet (header || ciphertext+tag) as a fresh
    //    Vec per packet; ring's seal_in_place_append_tag has already
    //    reserved TAG_SIZE since the caller did `.reserve(16)`.
    let mut wire_packets: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(batch.len());
    let socket = batch[0].socket.clone();
    for job in batch.drain(..) {
        let FmpSendJob {
            cipher,
            counter,
            header,
            mut inner_plaintext,
            socket: _,
            dest_addr,
        } = job;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        if cipher
            .seal_in_place_append_tag(nonce, Aad::from(&header), &mut inner_plaintext)
            .is_err()
        {
            // Drop this packet; AEAD seal can only fail on capacity
            // bugs which are not retryable at this layer.
            continue;
        }
        let mut wire = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + inner_plaintext.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&inner_plaintext);
        wire_packets.push((wire, dest_addr));
    }

    // 2) Bulk send. On Linux we wrap `sendmmsg(2)` via
    //    `AsyncUdpSocket::send_batch` to amortise the syscall cost
    //    across the batch; on other unix targets we fall back to
    //    per-packet `send_to` because there's no portable batch send.
    let _t2 = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
    #[cfg(target_os = "linux")]
    {
        let pkt_refs: Vec<(&[u8], SocketAddr)> = wire_packets
            .iter()
            .map(|(data, addr)| (data.as_slice(), *addr))
            .collect();
        let mut sent = 0usize;
        while sent < pkt_refs.len() {
            match socket.send_batch(&pkt_refs[sent..]).await {
                Ok(0) => break,
                Ok(n) => sent += n,
                Err(e) => {
                    return Err(format!("send_batch failed: {e}").into());
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        for (data, addr) in &wire_packets {
            if let Err(e) = socket.send_to(data, addr).await {
                return Err(format!("send_to failed: {e}").into());
            }
        }
    }
    Ok(())
}
