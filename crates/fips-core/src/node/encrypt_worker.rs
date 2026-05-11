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
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Handle to the encrypt worker pool. Dispatches jobs round-robin
/// across N worker tasks via per-worker unbounded mpsc senders. The
/// channels are unbounded because rx_loop's natural drain cap (256
/// commands per scheduler tick) and the kernel UDP recv buffer
/// further upstream already bound the inflight count; an unbounded
/// push here is wait-free at the dispatcher side.
#[derive(Clone)]
pub(crate) struct EncryptWorkerPool {
    senders: Arc<[mpsc::UnboundedSender<FmpSendJob>]>,
    next: Arc<AtomicUsize>,
}

impl EncryptWorkerPool {
    /// Spawn `n` worker tasks and return a handle that dispatches
    /// jobs round-robin to them. The workers shut down when all
    /// senders for their channel are dropped (i.e. when the returned
    /// `EncryptWorkerPool` and all clones go away).
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
            next: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Dispatch a job to the next worker. Round-robin keeps work
    /// balanced even when one worker briefly stalls behind a
    /// scheduler hop. Fire-and-forget — the worker handles send
    /// errors itself via stats counters.
    pub fn dispatch(&self, job: FmpSendJob) {
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping job");
            return;
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        if let Err(err) = self.senders[idx].send(job) {
            debug!(worker = idx, error = %err, "EncryptWorker channel closed; dropping job");
        }
    }
}

async fn run_worker(idx: usize, mut rx: mpsc::UnboundedReceiver<FmpSendJob>) {
    trace!(worker = idx, "FMP encrypt worker starting");
    while let Some(job) = rx.recv().await {
        if let Err(err) = handle_job(job).await {
            debug!(worker = idx, error = %err, "FMP encrypt worker job failed");
        }
        // Drain any follow-on jobs that arrived while we were doing
        // the AEAD + sendto above — keeps us on this task instead of
        // yielding back to the scheduler between every packet.
        let mut drained = 0usize;
        while drained < 256 {
            match rx.try_recv() {
                Ok(job) => {
                    if let Err(err) = handle_job(job).await {
                        debug!(worker = idx, error = %err, "FMP encrypt worker job failed (drain)");
                    }
                    drained += 1;
                }
                Err(_) => break,
            }
        }
    }
    trace!(worker = idx, "FMP encrypt worker exiting");
}

async fn handle_job(job: FmpSendJob) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let FmpSendJob {
        cipher,
        counter,
        header,
        mut inner_plaintext,
        socket,
        dest_addr,
    } = job;

    // FIPS_PERF timer for the AEAD step on the worker side. Counts
    // separately from the rx_loop's `FmpEncrypt` so we can see how
    // off-task encrypt compares.
    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);

    // Nonce derivation mirrors `CipherState::counter_to_nonce` (8-byte
    // LE counter with 4-byte zero prefix). Kept inline here to avoid
    // making the noise crate's counter_to_nonce pub.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    cipher
        .seal_in_place_append_tag(nonce, Aad::from(&header), &mut inner_plaintext)
        .map_err(|_| "FMP AEAD seal failed")?;

    // Build the wire packet: [header:16][ciphertext+tag]. One alloc.
    let mut wire = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + inner_plaintext.len());
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&inner_plaintext);
    drop(inner_plaintext);

    // Timer for the syscall itself.
    let _t2 = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
    socket
        .send_to(&wire, &dest_addr)
        .await
        .map_err(|e| format!("send_to failed: {e}"))?;
    Ok(())
}
