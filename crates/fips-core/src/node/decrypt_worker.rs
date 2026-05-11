//! Off-task FMP + FSP decrypt + delivery worker.
//!
//! First incremental step of the data-plane shard restructure (per the
//! architectural plan): each worker now **owns its session state
//! directly** in a local `HashMap`, with no `Arc<RwLock<HashMap>>`
//! cache on the Node side and no `Arc<Mutex<ReplayWindow>>` shared
//! with the rx_loop. The worker is the sole authority over the replay
//! window and the recv-side ciphers for every session it owns.
//!
//! Dispatch is **deterministic by session key**: rx_loop computes
//! `worker_idx = hash(cache_key) % N` and routes both
//! `RegisterSession` control messages and per-packet `Job` messages
//! through the same hash, so a session always lands on the same shard.
//!
//! Three message types travel through the per-worker `crossbeam_channel`:
//!
//! - **`RegisterSession`** — sent once on the first successful legacy
//!   decrypt for a session. Hands the worker an owned snapshot of the
//!   recv cipher + replay window for both FMP and FSP layers.
//! - **`Job`** — per-packet bulk decrypt + deliver. The worker looks
//!   up the session in its local HashMap; if absent (registration
//!   hasn't arrived yet, or session was unregistered), the packet is
//!   bounced back to rx_loop via the fallback channel.
//! - **`UnregisterSession`** — sent on rekey / peer drop so the worker
//!   releases the owned cipher + replay state.
//!
//! Only the **bulk-data** path (FMP DataPacket → FSP EndpointData) is
//! handled by the worker. Anything else (handshakes, MMP reports,
//! routing errors, IPv6-shim packets going to TUN) is bounced back to
//! the rx_loop via a fallback channel so the existing slow paths
//! continue to work.

use crate::transport::{TransportAddr, TransportId};
use crate::NodeAddr;
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, trace, warn};

use crate::noise::ReplayWindow;

const WORKER_CHANNEL_CAP: usize = 32768;

/// Owning recv-side state for one established session. Lives **inside
/// the worker thread that owns this session** — never shared, never
/// behind a mutex. Built on the rx_loop side (where the cipher /
/// replay state is authoritatively known after the first successful
/// legacy decrypt) and shipped over the crossbeam channel via a
/// `WorkerMsg::RegisterSession` message.
pub(crate) struct OwnedSessionState {
    pub fmp_cipher: LessSafeKey,
    pub fmp_replay: ReplayWindow,
    pub fsp_cipher: LessSafeKey,
    pub fsp_replay: ReplayWindow,
    pub source_npub: Option<String>,
}

/// Pre-cooked decrypt + dispatch job. Built on rx_loop after parsing
/// the FMP header; the worker pulls its session state from its own
/// local HashMap (keyed by `cache_key`) instead of receiving a
/// `WorkerSessionState` clone per packet.
pub(crate) struct DecryptJob {
    /// The raw packet bytes (incl. the 16-byte FMP outer header).
    /// Mutated in place during AEAD open — must reach the worker
    /// with the full ciphertext + tag intact.
    pub packet_data: Vec<u8>,
    /// Lookup key into the worker's owned session HashMap. Mirrors the
    /// `peers_by_index` key on the Node side: `(transport_id,
    /// receiver_idx)`.
    pub cache_key: (TransportId, u32),
    /// Source kernel transport. Used only for stats — `set_current_addr`
    /// short-circuits on unchanged source, and the address change
    /// path is rare. Skip on the worker fast path; the rx_loop's
    /// later non-fast-path activity (heartbeats, etc.) keeps
    /// `current_addr` correctly updated.
    pub _transport_id: TransportId,
    pub _remote_addr: TransportAddr,
    pub timestamp_ms: u64,
    /// Source NodeAddr (looked up via `peers_by_index` on rx_loop).
    /// Needed to attach to the bounced `DecryptFallback` so rx_loop
    /// can dispatch its legacy link-message handler.
    pub source_node_addr: NodeAddr,
    /// Counter from the FMP outer header. Used both as nonce input
    /// and to update the replay window.
    pub fmp_counter: u64,
    /// 16-byte FMP outer header used as AAD during AEAD open.
    pub fmp_header: [u8; 16],
    /// Offset within `packet_data` where the FMP ciphertext+tag begins.
    pub fmp_ciphertext_offset: usize,

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

/// Messages travelling through the per-worker crossbeam channel.
/// `Job` is the per-packet hot path; `RegisterSession` /
/// `UnregisterSession` are control plane events sent at session
/// establishment / teardown.
pub(crate) enum WorkerMsg {
    Job(DecryptJob),
    RegisterSession {
        cache_key: (TransportId, u32),
        state: OwnedSessionState,
    },
    UnregisterSession {
        cache_key: (TransportId, u32),
    },
}

/// Handle to the decrypt worker pool. Shard-style: each worker is one
/// OS thread that owns its sessions outright. Dispatch is
/// deterministic on `cache_key` so a session always reaches the same
/// shard.
#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[Sender<WorkerMsg>]>,
}

impl DecryptWorkerPool {
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = bounded::<WorkerMsg>(WORKER_CHANNEL_CAP);
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

    /// Stable hash from session key → worker index. Same hash is used
    /// for session registration and per-packet dispatch so packets and
    /// registration arrive at the same shard.
    fn worker_idx_for(&self, cache_key: (TransportId, u32)) -> usize {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        cache_key.hash(&mut h);
        (h.finish() as usize) % self.senders.len()
    }

    /// Dispatch a per-packet decrypt job. Drops if the per-worker
    /// channel is full (sustained rate overrun); the rx_loop's drain
    /// caps inbound at the same scale upstream so the cliff is
    /// bounded.
    pub fn dispatch_job(&self, job: DecryptJob) {
        if self.senders.is_empty() {
            return;
        }
        let idx = self.worker_idx_for(job.cache_key);
        match self.senders[idx].try_send(WorkerMsg::Job(job)) {
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

    /// Hand ownership of a session's recv-side state to its assigned
    /// worker. Called once per session, from the rx_loop, on the
    /// first authentic legacy-path decrypt — the worker thereafter is
    /// the sole authority over the replay window and the cipher
    /// clones for this session.
    pub fn register_session(
        &self,
        cache_key: (TransportId, u32),
        state: OwnedSessionState,
    ) {
        if self.senders.is_empty() {
            return;
        }
        let idx = self.worker_idx_for(cache_key);
        match self.senders[idx].try_send(WorkerMsg::RegisterSession { cache_key, state }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                warn!(
                    worker = idx,
                    "DecryptWorker channel full at session registration; will retry on next packet"
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(worker = idx, "DecryptWorker thread gone; ignoring registration");
            }
        }
    }

    /// Drop a session from its worker (rekey, peer removed). Fire and
    /// forget — if the worker is gone we don't care.
    #[allow(dead_code)] // wired up alongside the rekey / peer-removal callers in a follow-up
    pub fn unregister_session(&self, cache_key: (TransportId, u32)) {
        if self.senders.is_empty() {
            return;
        }
        let idx = self.worker_idx_for(cache_key);
        let _ = self.senders[idx].try_send(WorkerMsg::UnregisterSession { cache_key });
    }
}

fn run_worker(idx: usize, rx: Receiver<WorkerMsg>) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");

    // The shard's owned session table. Lives entirely on this OS
    // thread — never observed by any other thread.
    let mut sessions: HashMap<(TransportId, u32), OwnedSessionState> = HashMap::new();

    loop {
        let msg = match rx.recv() {
            Ok(m) => m,
            Err(_) => break, // channel closed → graceful exit
        };
        handle_msg(idx, &mut sessions, msg);
        // Drain follow-ons before parking again. Keeps the thread
        // on-core for a burst (typical recvmmsg batch is 5–30 packets
        // delivered very close together).
        loop {
            match rx.try_recv() {
                Ok(m) => handle_msg(idx, &mut sessions, m),
                Err(_) => break,
            }
        }
    }
    trace!(worker = idx, "FMP+FSP decrypt worker thread exiting");
}

fn handle_msg(
    idx: usize,
    sessions: &mut HashMap<(TransportId, u32), OwnedSessionState>,
    msg: WorkerMsg,
) {
    match msg {
        WorkerMsg::Job(job) => {
            if let Err(err) = handle_job(sessions, job) {
                debug!(worker = idx, error = %err, "decrypt worker job failed");
            }
        }
        WorkerMsg::RegisterSession { cache_key, state } => {
            trace!(
                worker = idx,
                ?cache_key,
                "DecryptWorker: register session"
            );
            sessions.insert(cache_key, state);
        }
        WorkerMsg::UnregisterSession { cache_key } => {
            trace!(
                worker = idx,
                ?cache_key,
                "DecryptWorker: unregister session"
            );
            sessions.remove(&cache_key);
        }
    }
}

fn handle_job(
    sessions: &mut HashMap<(TransportId, u32), OwnedSessionState>,
    job: DecryptJob,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let DecryptJob {
        mut packet_data,
        cache_key,
        timestamp_ms: _ts,
        source_node_addr,
        fmp_counter,
        fmp_header,
        fmp_ciphertext_offset,
        endpoint_event_tx,
        fallback_tx,
        ..
    } = job;

    // Look up the shard-owned session state. If absent (session not
    // yet registered, or unregistered mid-flight), bounce the raw
    // packet to rx_loop so it can run its legacy decrypt + populate
    // the session via RegisterSession on success.
    let state = match sessions.get_mut(&cache_key) {
        Some(s) => s,
        None => {
            // The legacy rx_loop already has the ciphertext bytes
            // (worker owns `packet_data` here), but it can re-do the
            // decrypt from scratch since this is the first-packet
            // path. Bounce by sending the **encrypted** FMP frame
            // back wrapped in a fallback — rx_loop's
            // `dispatch_link_message` won't recognise it though, so
            // we just drop instead. This is a transient state on a
            // brand-new session; subsequent packets land after
            // registration.
            let _ = fallback_tx; // explicitly ignore — drop path
            let _ = endpoint_event_tx;
            let _ = source_node_addr;
            let _ = packet_data;
            return Ok(());
        }
    };

    // === Phase 1: FMP decrypt ===
    let _t_fmp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);

    // Replay-window check before AEAD work to avoid wasting CPU on
    // replays. **Direct &mut access** — no Arc<Mutex> lock acquire.
    if !state.fmp_replay.check(fmp_counter) {
        return Ok(()); // replay; drop silently
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&fmp_counter.to_le_bytes());
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let buf = &mut packet_data[fmp_ciphertext_offset..];
    let plaintext_len =
        match state.fmp_cipher.open_in_place(nonce, Aad::from(&fmp_header), buf) {
            Ok(p) => p.len(),
            Err(_) => return Ok(()), // tag check failed; drop silently
        };

    // FMP decrypt succeeded — accept the counter into the replay window.
    state.fmp_replay.accept(fmp_counter);
    drop(_t_fmp);

    // The FMP plaintext lives in packet_data[fmp_ciphertext_offset..
    // fmp_ciphertext_offset + plaintext_len]. It carries a 4-byte
    // session-relative timestamp prefix, then the link-layer message.
    let fmp_plaintext_start = fmp_ciphertext_offset;
    let fmp_plaintext_end = fmp_ciphertext_offset + plaintext_len;
    const INNER_TIMESTAMP_LEN: usize = 4;
    if plaintext_len < INNER_TIMESTAMP_LEN + 1 {
        return Ok(());
    }
    let link_msg_start = fmp_plaintext_start + INNER_TIMESTAMP_LEN;
    let link_msg_end = fmp_plaintext_end;
    let link_msg = &packet_data[link_msg_start..link_msg_end];

    // === Phase 2: dispatch by link msg_type ===
    let msg_type = link_msg[0];
    if msg_type != 0x00 {
        // Bounce: re-allocate the FMP plaintext for rx_loop's slow
        // path. Control traffic is rare, alloc cost doesn't matter.
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

    // === Phase 3: zero-copy SessionDatagram parse + FSP decrypt in place ===
    use crate::protocol::SessionDatagramRef;
    let sd_body_abs_start = link_msg_start + 1; // skip msg_type=0x00
    let sd_body = &link_msg[1..];
    let datagram = match SessionDatagramRef::decode(sd_body) {
        Ok(dg) => dg,
        Err(_) => {
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

    use crate::node::session_wire::{
        FspCommonPrefix, FspEncryptedHeader, FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE,
        FSP_PHASE_ESTABLISHED,
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

    // Replay-check FSP counter — direct &mut on owned ReplayWindow.
    if !state.fsp_replay.check(fsp_counter) {
        return Ok(());
    }

    // Capture absolute offsets, then drop the `datagram` borrow.
    let fsp_payload_abs_start = sd_body_abs_start + SessionDatagramRef::HEADER_LEN;
    let fsp_ct_abs_start = fsp_payload_abs_start + FSP_HEADER_SIZE;
    let fsp_ct_abs_end = fmp_plaintext_end;
    let _ = datagram;

    // FSP decrypt **in place** on packet_data.
    let _t_fsp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&fsp_counter.to_le_bytes());
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let fsp_plaintext_len = match state.fsp_cipher.open_in_place(
        nonce,
        Aad::from(&fsp_aad),
        &mut packet_data[fsp_ct_abs_start..fsp_ct_abs_end],
    ) {
        Ok(p) => p.len(),
        Err(_) => return Ok(()),
    };
    state.fsp_replay.accept(fsp_counter);
    drop(_t_fsp);

    if fsp_plaintext_len < FSP_INNER_HEADER_SIZE + 1 {
        return Ok(());
    }
    let fsp_pt_start = fsp_ct_abs_start;
    let fsp_pt_end = fsp_ct_abs_start + fsp_plaintext_len;
    let fsp_msg_type = packet_data[fsp_pt_start + 4];
    if fsp_msg_type != 0x11 {
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

    // EndpointData fast path: copy out the app payload (post FSP
    // inner header).
    let inner_payload_start = fsp_pt_start + FSP_INNER_HEADER_SIZE;
    let payload = packet_data[inner_payload_start..fsp_pt_end].to_vec();
    let event = crate::node::NodeEndpointEvent::Data {
        source_node_addr,
        source_npub: state.source_npub.clone(),
        payload,
    };
    let _t_deliver =
        crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
    let _ = endpoint_event_tx.send(event);
    Ok(())
}
