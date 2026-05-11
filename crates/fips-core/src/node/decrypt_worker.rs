//! Off-task FMP + FSP decrypt + delivery worker.
//!
//! Mirror of `encrypt_worker` for the receive side. The rx_loop's
//! `process_packet` is the dominant bottleneck on the receiver
//! (measured 99.9 % CPU on a single tokio worker thread at line
//! rate, with FMP decrypt + FSP decrypt eating ~2 µs/pkt of that).
//! Moving the AEAD work to a `std::thread` worker + `crossbeam_channel`
//! follows the same pattern that gave the sender side +22 %:
//!
//! - **Channel:** `crossbeam_channel::bounded(32768)` — both ends sync,
//!   wake is one kernel futex with no tokio scheduler involvement.
//! - **Worker:** `std::thread::Builder::spawn` of a sync `run_worker`.
//!   AEAD ops (`ring`) + the synchronous push to the endpoint event
//!   queue (`tokio::sync::mpsc::UnboundedSender::send` is a wait-free
//!   linked-list append from any thread).
//! - **Dispatch:** hash-by-source-NodeAddr so every packet for one
//!   peer's session lands on the same worker. The session's replay
//!   window is then a single-writer resource (the assigned worker)
//!   even though we expose it as `Arc<Mutex<ReplayWindow>>` for
//!   correctness on the rare-slow-path / rekey edge.
//!
//! Only the **bulk-data** path (FMP DataPacket → FSP EndpointData)
//! is handled by the worker. Anything else (handshakes, MMP reports,
//! routing errors, IPv6-shim packets going to TUN) is bounced back
//! to the rx_loop via a fallback channel so the existing slow paths
//! continue to work.

use crate::transport::{TransportAddr, TransportId};
use crate::NodeAddr;
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, trace, warn};

use crate::noise::ReplayWindow;

const WORKER_CHANNEL_CAP: usize = 32768;

/// Pre-cooked decrypt + dispatch job. Built on rx_loop after parsing
/// the FMP header and looking up the receiving session; the worker
/// pulls everything it needs from this struct.
pub(crate) struct DecryptJob {
    /// The raw packet bytes (incl. the 16-byte FMP outer header).
    /// Mutated in place during AEAD open — must reach the worker
    /// with the full ciphertext + tag intact.
    pub packet_data: Vec<u8>,
    /// Source kernel transport. Used only for stats — `set_current_addr`
    /// short-circuits on unchanged source, and the address change
    /// path is rare. Skip on the worker fast path; the rx_loop's
    /// later non-fast-path activity (heartbeats, etc.) keeps
    /// `current_addr` correctly updated.
    pub _transport_id: TransportId,
    pub _remote_addr: TransportAddr,
    pub timestamp_ms: u64,
    /// Source NodeAddr (looked up via `peers_by_index` on rx_loop).
    pub source_node_addr: NodeAddr,
    /// Source npub (looked up via `npub_for_node_addr` on rx_loop).
    /// Cached so the worker can attach it to the `NodeEndpointEvent::Data`
    /// without going back through Node state.
    pub source_npub: Option<String>,

    /// Cloned FMP recv cipher. Refcount bump.
    pub fmp_cipher: LessSafeKey,
    /// Counter from the FMP outer header. Used both as nonce input
    /// and to update the replay window.
    pub fmp_counter: u64,
    /// 16-byte FMP outer header used as AAD during AEAD open.
    pub fmp_header: [u8; 16],
    /// Offset within `packet_data` where the FMP ciphertext+tag begins.
    pub fmp_ciphertext_offset: usize,

    /// Snapshot of the FMP replay window at session-establishment
    /// time. The worker is the sole writer once a session is
    /// dispatched here; the rx_loop's NoiseSession holds its own
    /// (no-longer-authoritative) copy for rekey / drain-window use.
    pub fmp_replay: Arc<Mutex<ReplayWindow>>,

    /// FSP recv cipher + replay window (set on session establishment).
    pub fsp_cipher: LessSafeKey,
    pub fsp_replay: Arc<Mutex<ReplayWindow>>,

    /// Where to deliver successfully-decrypted `EndpointData` events.
    /// Unbounded so the send from a non-tokio thread is a wait-free
    /// linked-list push — no runtime involvement on the worker side.
    pub endpoint_event_tx: UnboundedSender<crate::node::NodeEndpointEvent>,

    /// Anything that's NOT bulk EndpointData gets bounced back to the
    /// rx_loop via this channel along with its now-decrypted plaintext.
    /// The rx_loop drains this in a select! arm and runs the legacy
    /// dispatch (handshakes, MMP reports, routing errors, IPv6-shim →
    /// TUN). Keeps the slow paths working unchanged.
    pub fallback_tx: UnboundedSender<DecryptFallback>,
}

/// Result of a successful FMP decrypt + replay accept, when the
/// worker has decided this packet isn't on the EndpointData fast
/// path and is bouncing it back to rx_loop for the legacy slow path.
#[allow(dead_code)] // timestamp_ms / fmp_counter / fmp_flags retained for future debug paths
pub(crate) struct DecryptFallback {
    pub source_node_addr: NodeAddr,
    pub timestamp_ms: u64,
    pub fmp_counter: u64,
    pub fmp_flags: u8,
    /// FMP plaintext (the inner message; FSP if `prefix.phase ==
    /// FSP_PHASE_ESTABLISHED`).
    pub fmp_plaintext: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[Sender<DecryptJob>]>,
}

impl DecryptWorkerPool {
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = bounded::<DecryptJob>(WORKER_CHANNEL_CAP);
            std::thread::Builder::new()
                .name(format!("fips-decrypt-{i}"))
                .spawn(move || run_worker(i, rx))
                .expect("failed to spawn fips-decrypt OS thread");
            senders.push(tx);
        }
        Self {
            senders: senders.into(),
        }
    }

    /// Dispatch by source NodeAddr (hash on the address bytes) so a
    /// single session always lands on the same worker — its replay
    /// window stays single-writer even though the `Arc<Mutex<...>>`
    /// machinery would be safe under contention. Drops if the
    /// per-worker channel is full (sustained rate overrun); the
    /// rx_loop's drain caps inbound at the same scale upstream so
    /// the cliff is bounded.
    pub fn dispatch(&self, job: DecryptJob) {
        if self.senders.is_empty() {
            return;
        }
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        job.source_node_addr.hash(&mut h);
        let idx = (h.finish() as usize) % self.senders.len();
        match self.senders[idx].try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        drops = n + 1,
                        "DecryptWorker channel full; dropping inbound packet"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(worker = idx, "DecryptWorker thread gone; dropping job");
            }
        }
    }
}

fn run_worker(idx: usize, rx: Receiver<DecryptJob>) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");
    loop {
        let job = match rx.recv() {
            Ok(j) => j,
            Err(_) => break,
        };
        if let Err(err) = handle_job(job) {
            debug!(worker = idx, error = %err, "decrypt worker job failed");
        }
        // Drain follow-ons before parking again. Same pattern as the
        // encrypt worker — keeps the thread on-core for a burst.
        loop {
            match rx.try_recv() {
                Ok(j) => {
                    if let Err(err) = handle_job(j) {
                        debug!(worker = idx, error = %err, "decrypt worker job failed (drain)");
                    }
                }
                Err(_) => break,
            }
        }
    }
    trace!(worker = idx, "FMP+FSP decrypt worker thread exiting");
}

fn handle_job(job: DecryptJob) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let DecryptJob {
        mut packet_data,
        timestamp_ms: _ts,
        source_node_addr,
        source_npub,
        fmp_cipher,
        fmp_counter,
        fmp_header,
        fmp_ciphertext_offset,
        fmp_replay,
        fsp_cipher,
        fsp_replay,
        endpoint_event_tx,
        fallback_tx,
        ..
    } = job;

    // === Phase 1: FMP decrypt ===
    let _t_fmp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);

    // Replay-window check before AEAD work to avoid wasting CPU on
    // replays. Lock briefly.
    {
        let win = fmp_replay.lock().map_err(|e| format!("fmp replay poisoned: {e}"))?;
        if !win.check(fmp_counter) {
            return Ok(()); // replay; drop silently
        }
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&fmp_counter.to_le_bytes());
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let buf = &mut packet_data[fmp_ciphertext_offset..];
    let plaintext_len = match fmp_cipher.open_in_place(nonce, Aad::from(&fmp_header), buf) {
        Ok(p) => p.len(),
        Err(_) => return Ok(()), // tag check failed; drop silently
    };

    // FMP decrypt succeeded — accept the counter into the replay
    // window. (Locks briefly; single-writer in steady state.)
    {
        let mut win = fmp_replay
            .lock()
            .map_err(|e| format!("fmp replay poisoned: {e}"))?;
        win.accept(fmp_counter);
    }
    drop(_t_fmp);

    // The FMP plaintext lives in packet_data[fmp_ciphertext_offset..
    // fmp_ciphertext_offset + plaintext_len]. It carries a 4-byte
    // session-relative timestamp prefix, then the link-layer message.
    let fmp_plaintext_start = fmp_ciphertext_offset;
    let fmp_plaintext_end = fmp_ciphertext_offset + plaintext_len;
    const INNER_TIMESTAMP_LEN: usize = 4;
    if plaintext_len < INNER_TIMESTAMP_LEN + 1 {
        // Too short to be a valid link message; drop.
        return Ok(());
    }
    let link_msg_start = fmp_plaintext_start + INNER_TIMESTAMP_LEN;
    let link_msg_end = fmp_plaintext_end;
    let link_msg = &packet_data[link_msg_start..link_msg_end];

    // === Phase 2: dispatch by link msg_type ===
    let msg_type = link_msg[0];
    // SessionDatagram (msg_type 0x00) is the only bulk-data path
    // worth handling on the fast path here. Everything else bounces
    // back to rx_loop.
    if msg_type != 0x00 {
        // Bounce: re-allocate the FMP plaintext into a fresh Vec so
        // rx_loop can take ownership. This is the slow path; the
        // alloc cost doesn't matter (control traffic is rare).
        let fmp_plaintext = packet_data[fmp_plaintext_start..fmp_plaintext_end].to_vec();
        let _ = fallback_tx.send(DecryptFallback {
            source_node_addr,
            timestamp_ms: _ts,
            fmp_counter,
            fmp_flags: 0, // worker doesn't need to forward flags; rx_loop re-parses
            fmp_plaintext,
        });
        return Ok(());
    }

    // === Phase 3: parse SessionDatagram (zero-copy) and find local-delivery FSP payload ===
    //
    // SessionDatagram wire format (minimal subset we care about):
    //   [msg_type:1=0x00][ttl:1][path_mtu:2][src:16][dst:16][payload...]
    // We need to check `dst == self.node_addr()` to confirm local
    // delivery — but the worker doesn't have access to `self`. The
    // hash-by-source dispatch already implies this is for us (the
    // session was set up for this peer to talk to us), so we can
    // skip the dest check here. Routing-only datagrams shouldn't
    // hit the dispatch path because they're addressed elsewhere.
    //
    // Old code used `SessionDatagram::decode` which internally did a
    // `payload[35..].to_vec()` — a per-packet alloc + ~1.5 KB memcpy
    // of the inner FSP payload. The borrow-only `decode_ref` lets us
    // capture the FSP payload's absolute offset inside `packet_data`
    // and then decrypt FSP IN PLACE on `packet_data` after dropping
    // the borrow. No alloc, no copy.
    use crate::protocol::SessionDatagramRef;
    let sd_body_abs_start = link_msg_start + 1; // skip msg_type=0x00
    let sd_body = &link_msg[1..];
    let datagram = match SessionDatagramRef::decode(sd_body) {
        Ok(dg) => dg,
        Err(_) => {
            // Malformed; bounce so rx_loop can log + record stats
            let fmp_plaintext = packet_data[fmp_plaintext_start..fmp_plaintext_end].to_vec();
            let _ = fallback_tx.send(DecryptFallback {
                source_node_addr,
                timestamp_ms: _ts,
                fmp_counter,
                fmp_flags: 0,
                fmp_plaintext,
            });
            return Ok(());
        }
    };

    // FSP payload starts with the 12-byte FSP encrypted header
    // (phase=0x0, flags, payload_len, counter). We need to parse it
    // to get the FSP counter and decrypt in place.
    use crate::node::session_wire::{
        FspCommonPrefix, FspEncryptedHeader, FSP_PHASE_ESTABLISHED, FSP_INNER_HEADER_SIZE,
        FSP_HEADER_SIZE,
    };

    let fsp_payload = datagram.payload;
    let fsp_prefix = match FspCommonPrefix::parse(fsp_payload) {
        Some(p) => p,
        None => return Ok(()),
    };
    if fsp_prefix.phase != FSP_PHASE_ESTABLISHED || fsp_prefix.is_unencrypted() {
        // Plaintext error signal or non-bulk; bounce.
        let fmp_plaintext = packet_data[fmp_plaintext_start..fmp_plaintext_end].to_vec();
        let _ = fallback_tx.send(DecryptFallback {
            source_node_addr,
            timestamp_ms: _ts,
            fmp_counter,
            fmp_flags: 0,
            fmp_plaintext,
        });
        return Ok(());
    }
    let fsp_header = match FspEncryptedHeader::parse(fsp_payload) {
        Some(h) => h,
        None => return Ok(()),
    };
    let fsp_counter = fsp_header.counter;
    let fsp_aad = fsp_header.header_bytes;

    // Replay-check FSP counter.
    {
        let win = fsp_replay.lock().map_err(|e| format!("fsp replay poisoned: {e}"))?;
        if !win.check(fsp_counter) {
            return Ok(());
        }
    }

    // Compute the FSP ciphertext absolute range inside `packet_data`,
    // then drop the `datagram` borrow so we can re-borrow mutably.
    //
    // Layout (offsets in packet_data):
    //   ...
    //   link_msg_start                    -- msg_type=0x00
    //   link_msg_start + 1                -- start of sd_body
    //   link_msg_start + 1 + 35           -- start of FSP payload
    //   ↑ (== sd_body_abs_start + SessionDatagramRef::HEADER_LEN)
    //   + FSP_HEADER_SIZE                 -- start of FSP ciphertext
    //   ...                               -- ciphertext + tag, up to fmp_plaintext_end
    let fsp_payload_abs_start = sd_body_abs_start + SessionDatagramRef::HEADER_LEN;
    let fsp_ct_abs_start = fsp_payload_abs_start + FSP_HEADER_SIZE;
    let fsp_ct_abs_end = fmp_plaintext_end;
    let _ = datagram; // release the borrow on packet_data (Copy type, just goes out of scope)

    // FSP decrypt **in place** — ring's open_in_place mutates the
    // ciphertext slice into plaintext + drops the tag (returns the
    // plaintext-slice length). Previously this path did a
    // `datagram.payload[fsp_ciphertext_offset..].to_vec()` — one alloc
    // + ~1.5 KB memcpy per packet. Now: zero copies.
    let _t_fsp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&fsp_counter.to_le_bytes());
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let fsp_plaintext_len = match fsp_cipher.open_in_place(
        nonce,
        Aad::from(&fsp_aad),
        &mut packet_data[fsp_ct_abs_start..fsp_ct_abs_end],
    ) {
        Ok(p) => p.len(),
        Err(_) => return Ok(()),
    };
    {
        let mut win = fsp_replay
            .lock()
            .map_err(|e| format!("fsp replay poisoned: {e}"))?;
        win.accept(fsp_counter);
    }
    drop(_t_fsp);

    // FSP plaintext is [timestamp:4][msg_type:1][inner_flags:1][app data]
    // and now lives at `packet_data[fsp_ct_abs_start..fsp_ct_abs_start+fsp_plaintext_len]`.
    if fsp_plaintext_len < FSP_INNER_HEADER_SIZE + 1 {
        return Ok(());
    }
    let fsp_pt_start = fsp_ct_abs_start;
    let fsp_pt_end = fsp_ct_abs_start + fsp_plaintext_len;
    let fsp_msg_type = packet_data[fsp_pt_start + 4]; // byte 4 = msg_type
    // EndpointData = 0x11 (see SessionMessageType::EndpointData
    // wire byte). For anything else, bounce: MMP reports, DataPacket
    // (IPv6 shim), CoordsWarmup, etc.
    if fsp_msg_type != 0x11 {
        // For these the rx_loop's legacy path runs. We'd need to send
        // back not just the FMP plaintext but also the FSP plaintext.
        // For now, bounce just the FMP plaintext and let rx_loop redo
        // the FSP decrypt — slow path is rare, this is fine.
        let fmp_plaintext = packet_data[fmp_plaintext_start..fmp_plaintext_end].to_vec();
        let _ = fallback_tx.send(DecryptFallback {
            source_node_addr,
            timestamp_ms: _ts,
            fmp_counter,
            fmp_flags: 0,
            fmp_plaintext,
        });
        return Ok(());
    }

    // EndpointData fast path: copy out just the app payload (post
    // FSP inner header). One alloc + copy, replacing the old
    // `fsp_buf.to_vec()` (1 alloc + copy) **and** the
    // `payload.drain(..FSP_INNER_HEADER_SIZE)` (1.5 KB memmove). Net:
    // half the per-packet memory bandwidth of the old path.
    let inner_payload_start = fsp_pt_start + FSP_INNER_HEADER_SIZE;
    let payload = packet_data[inner_payload_start..fsp_pt_end].to_vec();
    let event = crate::node::NodeEndpointEvent::Data {
        source_node_addr,
        source_npub,
        payload,
    };
    let _t_deliver = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
    let _ = endpoint_event_tx.send(event);
    Ok(())
}

/// Per-session cached recv state, populated at session establishment
/// time and read on every inbound packet to build a `DecryptJob`.
/// Stored on `Node` as `Arc<RwLock<HashMap<TransportId × index, …>>>`
/// (keyed by the same `peers_by_index` key that the rx_loop already
/// uses for session lookup).
#[derive(Clone)]
pub(crate) struct WorkerSessionState {
    pub fmp_cipher: LessSafeKey,
    pub fmp_replay: Arc<Mutex<ReplayWindow>>,
    pub fsp_cipher: LessSafeKey,
    pub fsp_replay: Arc<Mutex<ReplayWindow>>,
    pub source_npub: Option<String>,
}

