//! Parallel-decrypt worker pool for the FMP receive hot path.
//!
//! ## Why
//!
//! As of mid-2026 the rx_loop is single-threaded: one tokio task owns the
//! drain-from-`packet_rx` → FMP-decrypt → dispatch → FSP-decrypt → TUN
//! pipeline. Per-thread CPU sampling on the 2-node Docker bench shows that
//! one worker thread is pegged at ~100% on a single core on both nodes
//! while 14 other tokio workers idle, regardless of stream count
//! (`scripts/perf-docker-threads.sh`). The dual-AEAD architecture means
//! ~6000 ns of pure AEAD per packet, which on a single core caps the box
//! around ~1.5 Gbps single-stream.
//!
//! ## Architecture (mirrors wireguard-go's RoutineDecryption)
//!
//! ```text
//!     rx_loop (single task)
//!       │  drain packet_rx, classify each packet:
//!       │    • PHASE_ESTABLISHED with known peer → AeadInboundElem
//!       │    • everything else (handshake, unknown peer, replay)
//!       │      stays inline as before
//!       │
//!       │  build a DecryptJob from the batch's AEAD elems and a paired
//!       │  oneshot, submit to BOTH:
//!       │    decrypt_tx (DecryptJob)        — workers race for it
//!       │    ordered_tx (OrderedJob)        — sequencer pops in order
//!       │
//!       ▼
//!   ┌──────────┐    ┌──────────┐
//!   │ worker 1 │ …  │ worker N │   each pops a DecryptJob, runs the
//!   └────┬─────┘    └────┬─────┘   per-elem AEAD open, ships
//!        │               │         Vec<DecryptedElem> back via the
//!        └───────┬───────┘         oneshot.
//!                │
//!                ▼
//!       sequencer (single task)
//!         pop OrderedJob (in dispatch order), await its oneshot,
//!         forward the Vec<DecryptedElem> to the rx_loop via
//!         completion_tx — so the rx_loop sees results in the same
//!         order the dispatcher submitted them.
//!
//!     rx_loop sees completion_rx.recv() in its select!,
//!     advances replay windows, runs dispatch_link_message, etc.
//! ```
//!
//! ## Why a sequencer task and not just one queue?
//!
//! The rx_loop's `select!` can't `await` on every batch's oneshot inline
//! — that would block other arms (tun_outbound, tick, control). So the
//! sequencer absorbs the per-batch await and turns "completed in any
//! order" into "completed in submit order" before handing back to the
//! rx_loop.
//!
//! Per-peer ordering is preserved because the dispatcher submits batches
//! in the order packets came off `packet_rx`, the sequencer pops in that
//! order, and within each batch the elem `Vec` is in dispatch order. So
//! TCP streams over a session see in-order delivery.
//!
//! ## What stays sequential
//!
//! The replay window is updated only on the rx_loop side (success path,
//! after `completion_rx.recv()`), so workers never touch session state.
//! Workers only run pure-functional `LessSafeKey::open_in_place` on their
//! provided `Arc<LessSafeKey>`. This keeps the `peers` HashMap and
//! `NoiseSession` mutex-free — the only contended state is the channels.

use crate::node::wire::{ESTABLISHED_HEADER_SIZE, EncryptedHeader};
use crate::noise::{self, NoiseError};
use crate::transport::ReceivedPacket;
use crate::NodeAddr;
use ring::aead::LessSafeKey;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::warn;

/// One AEAD-decrypt unit: a single PHASE_ESTABLISHED packet whose FMP
/// header has been parsed and whose receiving session has been resolved.
///
/// Constructed by the rx_loop while it still holds the `peers` borrow.
/// Moved to a worker for the actual `LessSafeKey::open` round.
pub struct AeadInboundElem {
    /// Original packet; ciphertext lives at `&packet.data[ciphertext_offset..]`.
    pub packet: ReceivedPacket,
    /// Parsed outer header (also serves as AEAD AAD via `header_bytes`).
    pub header: EncryptedHeader,
    /// Counter copied out of `header.counter` for convenience (workers
    /// don't reach into `header` for the AEAD nonce — they take this).
    pub counter: u64,
    /// AAD for the AEAD `open`. Always equal to `header.header_bytes`,
    /// inlined as a fixed-size array so workers don't have to copy out
    /// of the parsed header struct.
    pub aad: [u8; ESTABLISHED_HEADER_SIZE],
    /// Where ciphertext begins in `packet.data`.
    pub ciphertext_offset: usize,
    /// Current-session AEAD recv key. Non-`Option` because the dispatcher
    /// only enqueues elems whose session has a live recv cipher.
    pub key_current: Arc<LessSafeKey>,
    /// Drain-window previous-session recv key, if any. Workers fall back
    /// to this only if `key_current` decrypt fails.
    pub key_previous: Option<Arc<LessSafeKey>>,
    /// Resolved peer `NodeAddr`. Saves the rx_loop a `peers_by_index`
    /// lookup on the completion side.
    pub node_addr: NodeAddr,
}

/// Outcome of decrypting one elem. Owned by the sequencer/rx_loop after
/// the worker fires.
pub struct DecryptedElem {
    pub packet: ReceivedPacket,
    pub header: EncryptedHeader,
    pub node_addr: NodeAddr,
    /// `Ok(plaintext)` on success — plaintext still includes the 4-byte
    /// inner timestamp prefix, mirroring `handle_encrypted_frame`'s
    /// pre-refactor shape.
    pub result: Result<Vec<u8>, NoiseError>,
    /// True if the previous session was used (drain-window fallback).
    /// rx_loop logs at debug; doesn't currently change behaviour.
    pub used_previous_session: bool,
}

/// Worker job: a Vec of elems to decrypt + a back-channel for results.
///
/// When the sequencer is enabled, the worker sends a `Vec<DecryptedElem>`
/// down `result_tx` and the sequencer forwards it to the rx_loop in
/// submit order. When `FIPS_AEAD_NO_SEQUENCER=1` the build skips the
/// sequencer entirely and the worker sends directly to the rx_loop's
/// completion mpsc — order is lost but channel hops drop from 4 per
/// batch to 2.
enum ResultSink {
    Sequenced(oneshot::Sender<Vec<DecryptedElem>>),
    Direct(mpsc::Sender<Vec<DecryptedElem>>),
}

struct DecryptJob {
    elems: Vec<AeadInboundElem>,
    result_tx: ResultSink,
}

/// Sequencer job: hold the oneshot's receive end and wait for it. This
/// is what enforces submit-order delivery. Only used when the sequencer
/// is enabled.
struct OrderedJob {
    result_rx: oneshot::Receiver<Vec<DecryptedElem>>,
}

/// Submit handle. Owned by `Node` and used through `&self` from the
/// rx_loop's drain path. The completion receiver lives separately
/// (`AeadCompletionRx`) so the rx_loop can hold the receiver `&mut` in
/// one `select!` arm while submitting via `&self` from another.
pub struct AeadPool {
    decrypt_tx: mpsc::Sender<DecryptJob>,
    ordered_tx: mpsc::Sender<OrderedJob>,
    /// When set (FIPS_AEAD_NO_SEQUENCER mode), the dispatcher attaches
    /// this sender to each `DecryptJob` so workers send their result
    /// straight to the rx_loop. When `None`, results route through the
    /// sequencer for in-order delivery.
    direct_completion_tx: Option<mpsc::Sender<Vec<DecryptedElem>>>,
    /// Worker join handles; retained so a future `shutdown` can wait on
    /// them. Currently unused under steady-state operation — the pool
    /// shuts down when `Node` is dropped and tokio cancels the tasks.
    #[allow(dead_code)]
    worker_handles: Vec<JoinHandle<()>>,
    /// Sequencer join handle. `None` in `FIPS_AEAD_NO_SEQUENCER` mode.
    #[allow(dead_code)]
    sequencer_handle: Option<JoinHandle<()>>,
    /// Number of workers spawned, retained for diagnostics / metrics.
    #[allow(dead_code)]
    num_workers: usize,
}

/// Receiver half of the pool's completion channel. Held separately on
/// `Node` so the rx_loop can borrow it `&mut` in a `select!` arm
/// without conflicting with submit-side borrows on the pool itself.
pub struct AeadCompletionRx(mpsc::Receiver<Vec<DecryptedElem>>);

impl AeadCompletionRx {
    /// Pop the next completed batch, in submit order. `None` when the
    /// sequencer has shut down.
    pub async fn recv(&mut self) -> Option<Vec<DecryptedElem>> {
        self.0.recv().await
    }

    /// Non-blocking variant for the rx_loop's drain-the-rest pattern.
    pub fn try_recv(&mut self) -> Option<Vec<DecryptedElem>> {
        self.0.try_recv().ok()
    }
}

impl AeadPool {
    /// Spawn `num_workers` decrypt tasks plus one sequencer task.
    /// Returns `(pool, completion_rx)` so the caller can place each
    /// half on its own field.
    ///
    /// `decrypt_q_depth` and `ordered_q_depth` cap how many in-flight
    /// batches the dispatcher can have outstanding before back-pressuring.
    /// `completion_q_depth` does the same on the rx_loop side.
    pub fn new(
        num_workers: usize,
        decrypt_q_depth: usize,
        ordered_q_depth: usize,
        completion_q_depth: usize,
    ) -> (Self, AeadCompletionRx) {
        assert!(num_workers > 0, "AeadPool requires >=1 worker");
        // Build-time toggle: with FIPS_AEAD_NO_SEQUENCER=1 the workers
        // send results directly to the completion mpsc, skipping the
        // sequencer task and its per-batch oneshot. Order across
        // batches is no longer guaranteed but channel hops drop from
        // 4/batch to 2/batch. Used to A/B whether the sequencer is
        // the dominant overhead vs the AEAD-pool architecture itself.
        let no_sequencer = std::env::var("FIPS_AEAD_NO_SEQUENCER")
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let (decrypt_tx, decrypt_rx) = mpsc::channel::<DecryptJob>(decrypt_q_depth);
        let (ordered_tx, ordered_rx) = mpsc::channel::<OrderedJob>(ordered_q_depth);
        let (completion_tx, completion_rx) =
            mpsc::channel::<Vec<DecryptedElem>>(completion_q_depth);

        // Workers share a single decrypt_rx via a tokio Mutex. mpsc::Receiver
        // is single-consumer; wrap it in a Mutex<async_channel> equivalent
        // by using a separate fan-out task or by using async_channel. Tokio
        // mpsc doesn't natively support multi-consumer; use async_channel.
        //
        // Use async_channel-equivalent via `tokio_util::sync::PollSemaphore`?
        // Simpler: wrap the receiver in `Arc<tokio::sync::Mutex<...>>` and
        // have each worker briefly lock it to take the next job. The lock
        // is held only across `recv()` so other workers proceed once a job
        // is pulled. On a steady stream the contention is one lock per
        // job per worker — small fraction of a microsecond.
        let shared_rx = Arc::new(tokio::sync::Mutex::new(decrypt_rx));

        let mut worker_handles = Vec::with_capacity(num_workers);
        for worker_id in 0..num_workers {
            let rx = shared_rx.clone();
            worker_handles.push(tokio::spawn(async move {
                worker_loop(worker_id, rx).await;
            }));
        }

        let direct_completion_tx = if no_sequencer {
            Some(completion_tx.clone())
        } else {
            None
        };
        let sequencer_handle = if no_sequencer {
            // Drop ordered_rx so the dispatcher's send to ordered_tx
            // returns Err quickly. We still keep ordered_tx around to
            // avoid restructuring AeadPool's fields.
            drop(ordered_rx);
            drop(completion_tx);
            None
        } else {
            Some(tokio::spawn(async move {
                sequencer_loop(ordered_rx, completion_tx).await;
            }))
        };

        let pool = Self {
            decrypt_tx,
            ordered_tx,
            direct_completion_tx,
            worker_handles,
            sequencer_handle,
            num_workers,
        };
        (pool, AeadCompletionRx(completion_rx))
    }

    /// Number of decrypt workers spawned (informational).
    #[allow(dead_code)]
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Submit a batch of elems for parallel decryption. Returns once the
    /// job is enqueued. The decrypted results land on `completion_rx` in
    /// submit order.
    ///
    /// On a closed channel (pool already shut down) the elems are
    /// silently dropped after a warn log — callers can't recover, and
    /// the rx_loop is the only caller, so the alternative is to plumb a
    /// new error type through every dispatch site for a case that only
    /// fires during shutdown.
    pub async fn submit_batch(&self, elems: Vec<AeadInboundElem>) {
        if elems.is_empty() {
            return;
        }
        match self.direct_completion_tx.as_ref() {
            Some(direct_tx) => {
                // No-sequencer fast path: workers send straight to the
                // rx_loop's completion mpsc. Ordering is lost across
                // batches; within a batch the elem `Vec` order is
                // preserved.
                let job = DecryptJob {
                    elems,
                    result_tx: ResultSink::Direct(direct_tx.clone()),
                };
                if let Err(e) = self.decrypt_tx.send(job).await {
                    warn!(error = %e, "AEAD pool decrypt_tx closed; dropping batch");
                }
            }
            None => {
                let (result_tx, result_rx) = oneshot::channel();
                let job = DecryptJob {
                    elems,
                    result_tx: ResultSink::Sequenced(result_tx),
                };
                let ordered = OrderedJob { result_rx };

                // Push the ordered slot FIRST so the sequencer sees the
                // in-order placeholder before the worker tries to fire
                // its oneshot.
                if let Err(e) = self.ordered_tx.send(ordered).await {
                    warn!(error = %e, "AEAD pool ordered_tx closed; dropping batch");
                    return;
                }
                if let Err(e) = self.decrypt_tx.send(job).await {
                    warn!(error = %e, "AEAD pool decrypt_tx closed; orphaning ordered slot");
                }
            }
        }
    }

    /// Close the pool: drop sender halves and await all worker tasks.
    /// Idempotent if called twice (later calls are no-ops because the
    /// handles are taken).
    #[allow(dead_code)]
    pub async fn shutdown(mut self) {
        // Drop senders so the workers' `recv()` loops return None.
        drop(self.decrypt_tx);
        drop(self.ordered_tx);
        // Cancel/await worker tasks.
        for h in self.worker_handles.drain(..) {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.sequencer_handle.take() {
            h.abort();
            let _ = h.await;
        }
    }
}

/// One worker's lifecycle: pull a `DecryptJob`, run AEAD on each elem,
/// send the resulting `Vec<DecryptedElem>` back via the oneshot.
///
/// Receivers share a `Mutex<mpsc::Receiver<DecryptJob>>` — only one
/// worker holds it at a time, but the lock is released as soon as a job
/// is pulled, so other workers immediately race for the next one. Under
/// load this serializes the queue head but parallelizes everything past
/// it (the actual AEAD work).
async fn worker_loop(_worker_id: usize, rx: Arc<tokio::sync::Mutex<mpsc::Receiver<DecryptJob>>>) {
    loop {
        let job = {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(j) => j,
                None => return, // channel closed, pool shutting down
            }
        };

        let mut out: Vec<DecryptedElem> = Vec::with_capacity(job.elems.len());
        for elem in job.elems {
            let ciphertext = &elem.packet.data[elem.ciphertext_offset..];
            // Try current session.
            let res = noise::open(
                Some(elem.key_current.as_ref()),
                elem.counter,
                &elem.aad,
                ciphertext,
            );

            let (result, used_previous) = match res {
                Ok(pt) => (Ok(pt), false),
                Err(e_current) => {
                    // Drain-window fallback to previous session, if any.
                    if let Some(prev) = elem.key_previous.as_ref() {
                        match noise::open(Some(prev.as_ref()), elem.counter, &elem.aad, ciphertext)
                        {
                            Ok(pt) => (Ok(pt), true),
                            Err(_) => (Err(e_current), false),
                        }
                    } else {
                        (Err(e_current), false)
                    }
                }
            };

            out.push(DecryptedElem {
                packet: elem.packet,
                header: elem.header,
                node_addr: elem.node_addr,
                result,
                used_previous_session: used_previous,
            });
        }

        match job.result_tx {
            ResultSink::Sequenced(tx) => {
                // If the receiver is gone (sequencer shut down), drop results.
                let _ = tx.send(out);
            }
            ResultSink::Direct(tx) => {
                // No-sequencer fast path: send directly to rx_loop.
                // Drop on closed channel (rx_loop gone).
                let _ = tx.send(out).await;
            }
        }
    }
}

/// Sequencer: pop an `OrderedJob` (in dispatch order), await its oneshot,
/// forward the result to `completion_tx`. If a oneshot is dropped without
/// being filled (worker died mid-job), skip and continue with the next.
async fn sequencer_loop(
    mut ordered_rx: mpsc::Receiver<OrderedJob>,
    completion_tx: mpsc::Sender<Vec<DecryptedElem>>,
) {
    while let Some(job) = ordered_rx.recv().await {
        match job.result_rx.await {
            Ok(decrypted) => {
                if completion_tx.send(decrypted).await.is_err() {
                    // rx_loop is gone; drain remaining ordered jobs to
                    // unblock pending oneshots, then exit.
                    while let Some(j) = ordered_rx.recv().await {
                        let _ = j.result_rx.await;
                    }
                    return;
                }
            }
            Err(_) => {
                // Worker dropped the oneshot without sending. Pool is
                // probably shutting down; keep draining to honor any
                // remaining queued jobs.
                continue;
            }
        }
    }
}
