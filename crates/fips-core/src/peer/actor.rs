//! Per-peer actor task — step 6 of the peer-actor refactor.
//!
//! Spawned once per authenticated peer in `promote_connection`. Owns
//! a clone of the peer's `ActivePeer` (Arc<RwLock<ActivePeer>>)
//! and an `mpsc::Receiver` for inbound jobs. The rx_loop dispatches
//! per-packet work into this channel after FMP-decrypt; the peer task
//! runs the per-peer state mutations (replay accept, MMP record,
//! link_stats record, touch) on its own tokio worker thread, freeing
//! the rx_loop for concurrent processing of other peers' packets and
//! its tick / tun_outbound / control arms.
//!
//! After the peer task finishes the per-peer updates, it forwards the
//! decoded link message back to the rx_loop via a shared
//! `link_dispatch_tx` channel — `dispatch_link_message` itself still
//! needs `&mut Node` (it touches sessions, transports, coord cache,
//! etc.), so the dispatch chain stays on the central thread for now.
//! Step 7 will extend this to push FSP decrypt + local-delivery TUN
//! write into the peer task too.
//!
//! ## Lifecycle
//!
//! * Spawn: `PeerActorHandle::spawn` is called from `promote_connection`
//!   right after the peer slot is inserted into `Node.peers`.
//! * Send: `apply_decrypted_elem` calls `handle.dispatch(job)` to push
//!   work into the peer task's inbox. Falls back to the legacy inline
//!   path if the handle is `None` (e.g. for peers established before
//!   step 6 lands or in tests that bypass `promote_connection`).
//! * Stop: `remove_active_peer` drops the handle, which closes the
//!   sender; the peer task observes `recv() -> None` and exits.

use crate::node::NodeEndpointEvent;
use crate::node::session::SessionEntry;
use crate::peer::ActivePeer;
use crate::upper::tun::TunTx;
use secp256k1::PublicKey;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, trace};

/// Per-actor IO context: clones of the IO sinks the peer actor needs to
/// deliver locally-terminated SessionDatagram payloads (TUN packets,
/// endpoint data events) without round-tripping through the rx_loop,
/// plus a shared `Arc<Config>` for read-only access to deployment-time
/// settings (coords warmup count, MMP config, handshake-resend tuning,
/// rate-limit thresholds, etc).
///
/// The `Arc<Config>` pattern is the standard "actor owns its config"
/// approach for read-mostly settings: every actor holds an `Arc::clone`
/// of the same immutable `Config` object — cheap (one ref-count bump
/// per spawn), no synchronisation. If we ever add hot-reload, swap-the-
/// Arc (`arc_swap`) slots in without touching this struct's API.
///
/// Built once on Node startup and passed to every `PeerActorHandle::spawn`.
#[derive(Clone)]
pub(crate) struct PeerActorIoCtx {
    /// This node's own NodeAddr — used to recognise SessionDatagrams
    /// destined for us (`datagram.dest_addr == self.node_addr`).
    pub node_addr: crate::NodeAddr,
    /// TUN-write sink for IPv6-shim DataPackets. `None` when no TUN
    /// interface is attached (relay-only mode, tests).
    pub tun_tx: Option<TunTx>,
    /// Endpoint-event sink for app-bound EndpointData packets. `None`
    /// when no endpoint is attached.
    pub endpoint_event_tx: Option<mpsc::Sender<NodeEndpointEvent>>,
    /// Shared, read-only config. Actor reads the relevant sub-configs
    /// (`config.node.session`, `config.node.session_mmp`,
    /// `config.node.rate_limit`, …) directly via the Arc.
    pub config: Arc<crate::config::Config>,
}

/// One unit of work pushed from Node into a peer task.
///
/// The pure-actor model (step 7c-2) routes *every* Node-side
/// SessionEntry access through these messages — the actor is the sole
/// owner of `SessionEntry` for direct-peer-to-this-node sessions, no
/// `Arc<RwLock<…>>`, no shared map. Node-side ops that would have
/// touched `self.sessions[addr]` send a request here and either
/// fire-and-forget (lifecycle / push events) or await a response
/// (encrypt, query stats).
pub(crate) enum PeerInboundJob {
    /// FMP-decrypted frame on this peer. The peer task accepts the
    /// replay counter, records MMP / link stats, touches last-seen,
    /// and forwards the link message to the rx_loop's dispatch queue.
    Decrypted(Box<DecryptedJob>),
    /// Hand ownership of a (newly-Established) `SessionEntry` to the
    /// peer actor. Node calls this from its handshake-completion path
    /// when the session's `remote_addr` matches this peer's NodeAddr
    /// (direct peer = direct session). The entry MOVES — Node removes
    /// its copy from `self.sessions` at the same time, so there is
    /// only ever one owner.
    TakeSession(Box<SessionEntry>),
    /// Tell the peer actor to drop its owned `SessionEntry` (peer
    /// disconnect, idle purge, decrypt-failure-threshold reinit).
    /// The actor logs MMP teardown locally, then drops the entry.
    RemoveSession,
    /// Session-encrypt for an outbound message. Reaches into the
    /// actor's owned `SessionEntry` to:
    /// 1. Read the current send_counter, K-bit, and coords_warmup
    ///    counter — actor decides whether to splice coords on this
    ///    send (CP flag) and decrements the warmup counter atomically
    ///    with the encrypt
    /// 2. AEAD-encrypt the inner plaintext with `send_cipher`
    /// 3. Build the FSP header (counter / flags / payload_len) +
    ///    optional cleartext coords + ciphertext
    /// 4. Record the send into the MMP sender state, traffic counters,
    ///    and (if `touch`) last_activity
    /// 5. Reply via `respond` with `EncryptOutput` carrying the wire
    ///    bytes Node wraps in a `SessionDatagram`.
    /// `Err(SessionGone)` if the actor doesn't own the session — Node
    /// falls back to its legacy path.
    Encrypt {
        msg_type: u8,
        plaintext: Vec<u8>,
        /// Pre-encoded coords (src+dest) ready for the actor to splice
        /// in if its warmup counter still has tokens AND the caller
        /// requested coords. None when Node already decided coords
        /// don't fit in transport MTU. Actor returns
        /// `included_coords: false` if it chose not to use them.
        coords_payload_if_warmup: Option<Vec<u8>>,
        /// Whether this send should `touch()` the session's
        /// last_activity (DataPacket / EndpointData) or not (MMP
        /// reports / CoordsWarmup).
        touch: bool,
        respond: oneshot::Sender<Result<EncryptOutput, EncryptError>>,
    },
    /// Tick-driven request: the peer actor decides whether the session
    /// is due for a periodic MMP report send (sender + receiver +
    /// path-mtu) and returns the encoded report bodies the rx_loop
    /// should ship via `Encrypt`.
    BuildMmpReports {
        now: std::time::Instant,
        respond: oneshot::Sender<Vec<MmpReportToSend>>,
    },
    /// Tick-driven request: should Node initiate an FSP rekey for
    /// this session?
    IsRekeyDue {
        now_ms: u64,
        respond: oneshot::Sender<RekeyDecision>,
    },
    /// Control-plane snapshot for `show_sessions` / `show_mmp` queries.
    /// Returns `None` if the actor doesn't own a session.
    QuerySnapshot(oneshot::Sender<Option<SessionSnapshot>>),
    /// Process inbound FSP msg2 (Noise XK) — initiator-side handshake
    /// advance from `Initiating` to `Established` (or from rekey-in-
    /// progress to pending-cutover for rekey path). Actor advances its
    /// owned `SessionEntry`'s state machine and returns the msg3 bytes
    /// for Node to wrap in a `SessionDatagram` and send.
    ProcessFspMsg2 {
        handshake_payload: Vec<u8>,
        respond: oneshot::Sender<Result<ProcessMsg2Output, ProcessHandshakeError>>,
    },
    /// Process inbound FSP msg3 (Noise XK) — responder-side handshake
    /// advance from `AwaitingMsg3` to `Established`. Reveals the
    /// initiator's static pubkey, which the actor returns so Node can
    /// register identity / fix any placeholder entries.
    ProcessFspMsg3 {
        handshake_payload: Vec<u8>,
        respond: oneshot::Sender<Result<ProcessMsg3Output, ProcessHandshakeError>>,
    },
    /// Raw inbound encrypted packet for actor-owned ActivePeer
    /// processing (post ActivePeer-to-actor migration). Actor parses
    /// the FMP header, calls `ActivePeer::process_inbound_fmp_frame`
    /// against its owned peer, and dispatches the resulting link
    /// message via `link_dispatch_tx` (or the FSP fast path when the
    /// owned `SessionEntry` allows). Dropped silently if the actor
    /// doesn't own a peer — Node falls back to its inline path.
    ///
    /// Boxed because `ReceivedPacket` carries a `Vec<u8>` and we want
    /// to keep the `PeerInboundJob` enum size small (every variant
    /// pays for the largest one).
    Packet(Box<crate::transport::ReceivedPacket>),
    /// Hand ownership of an `ActivePeer` to the peer actor. After this
    /// the actor is the sole owner — Node removes the `ActivePeer`
    /// from `self.peers` at the same time. Used by `promote_connection`
    /// to enable the `Packet` fast path for newly-authenticated peers.
    TakePeer(Box<ActivePeer>),
    /// Take the `ActivePeer` back from the actor, e.g. for cold-path
    /// reads/writes that haven't been migrated to actor messages yet,
    /// or for `remove_active_peer` cleanup. Returns `None` if the
    /// actor isn't currently holding a peer.
    ReleasePeer {
        respond: oneshot::Sender<Option<Box<ActivePeer>>>,
    },
}

/// Reply for `ProcessFspMsg2`.
#[derive(Debug)]
pub(crate) struct ProcessMsg2Output {
    /// XK msg3 bytes — Node wraps this in a `SessionMsg3` body and
    /// sends as a `SessionDatagram`.
    pub msg3_payload: Vec<u8>,
    /// Distinguishes the fresh-establish path (Initiating →
    /// Established) from the rekey-in-progress path (was already
    /// Established, now has a pending NoiseSession waiting for K-bit
    /// cutover).
    pub flow: ProcessMsg2Flow,
}

#[derive(Debug)]
pub(crate) enum ProcessMsg2Flow {
    /// Fresh handshake completing — Node should `coord_cache.insert(
    /// src_addr, ack.src_coords)` and `flush_pending_packets(src_addr)`.
    FreshEstablish,
    /// Rekey msg2 — actor parked the new session as `pending_new_session`
    /// awaiting K-bit cutover. No coord-cache or pending-packet
    /// updates needed.
    RekeyPending,
}

/// Reply for `ProcessFspMsg3`.
#[derive(Debug)]
pub(crate) struct ProcessMsg3Output {
    /// Initiator's real static pubkey, learned from XK msg3. Node
    /// uses this to update its identity_cache (replacing any
    /// placeholder previously associated with this NodeAddr).
    pub remote_pubkey: PublicKey,
    /// As with msg2, distinguishes fresh-establish from rekey.
    pub flow: ProcessMsg3Flow,
}

#[derive(Debug)]
pub(crate) enum ProcessMsg3Flow {
    /// AwaitingMsg3 → Established. Node should
    /// `flush_pending_packets(src_addr)`.
    FreshEstablish,
    /// Rekey msg3 — actor parked new session as pending; awaiting
    /// initiator's K-bit-flipped data to trigger cutover.
    RekeyPending,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProcessHandshakeError {
    #[error("peer actor does not own a session")]
    SessionGone,
    #[error("session not in expected handshake state")]
    UnexpectedState,
    #[error("Noise read failed: {0}")]
    NoiseRead(String),
    #[error("Noise write failed: {0}")]
    NoiseWrite(String),
    #[error("Noise into_session failed: {0}")]
    IntoSession(String),
}

/// Result of a successful `Encrypt` call.
#[derive(Debug)]
pub(crate) struct EncryptOutput {
    /// Wire bytes for the FSP layer (header + optional coords + ciphertext).
    /// Node wraps this in a `SessionDatagram` envelope.
    pub fsp_payload: Vec<u8>,
    /// FSP send counter used for this packet. Node uses it for
    /// path-mtu seeding + logging.
    pub counter: u64,
    /// Session timestamp at encrypt time.
    pub timestamp: u32,
    /// Inner ciphertext length (for MMP sender record_sent — already
    /// done inside the actor, but Node's stats track total too).
    pub ciphertext_len: usize,
    /// True iff actor included coords on this send (CP flag set).
    /// Node uses this to decide whether to fire a standalone
    /// CoordsWarmup as a follow-up if the caller wanted coords but
    /// they didn't fit (Node would pass `coords_payload_if_warmup =
    /// None` in that case anyway, so this mostly mirrors back the
    /// actor's accounting).
    pub included_coords: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EncryptError {
    #[error("peer actor does not own a session")]
    SessionGone,
    #[error("session is not Established")]
    NotEstablished,
    #[error("AEAD encrypt failed: {0}")]
    Crypto(String),
}

/// One MMP report the actor wants Node to ship via the regular send path.
#[derive(Debug)]
pub(crate) struct MmpReportToSend {
    pub msg_type: u8, // SessionMessageType byte
    pub body: Vec<u8>,
}

/// Reply for `IsRekeyDue`. The actor decides; rx_loop initiates the
/// new XK handshake when `Yes`.
#[derive(Debug)]
pub(crate) enum RekeyDecision {
    /// Not Established or rekey already in progress — no action.
    NotApplicable,
    /// Initiate a fresh rekey. Carries the remote pubkey so the rx_loop
    /// doesn't need to re-fetch from the actor.
    InitiateRekey { remote_pubkey: PublicKey },
    /// Cutover from pending → current is due (initiator side, after
    /// FSP_CUTOVER_DELAY_MS post-msg3-send).
    InitiatorCutover,
    /// Drain window expired — actor has cleaned up the previous session.
    DrainExpired,
    /// Nothing to do this tick.
    Nothing,
}

/// Read-only snapshot of session state for control queries / idle purge.
/// Computed in the actor under its owned-state assumption (no locks).
#[derive(Debug, Clone)]
pub(crate) struct SessionSnapshot {
    pub last_activity_ms: u64,
    pub session_start_ms: u64,
    pub state: SessionStateLabel,
    pub is_initiator: bool,
    pub current_k_bit: bool,
    pub coords_warmup_remaining: u8,
    pub is_draining: bool,
    pub resend_count: u32,
    pub remote_pubkey: PublicKey,
    pub traffic_counters: (u64, u64, u64, u64),
    /// Coarse MMP snapshot. `None` if MMP not initialised.
    pub mmp: Option<MmpSnapshot>,
}

#[derive(Debug, Clone)]
pub(crate) enum SessionStateLabel {
    Established,
    Initiating,
    AwaitingMsg3,
    Other,
}

#[derive(Debug, Clone)]
pub(crate) struct MmpSnapshot {
    pub mode: String,
    pub loss_rate: f64,
    pub etx: f64,
    pub goodput_bps: f64,
    pub srtt_ms: Option<f64>,
    pub smoothed_loss: Option<f64>,
    pub smoothed_etx: Option<f64>,
    pub path_mtu: u16,
    pub delivery_ratio_forward: f64,
    pub delivery_ratio_reverse: f64,
}

/// Push events the actor emits to Node. Sent via a shared mpsc that
/// the rx_loop drains from a dedicated `select!` arm.
#[derive(Debug)]
#[allow(dead_code)] // wired in 7c-2 step C+
pub(crate) enum PeerOutboundEvent {
    /// Actor's owned session just touched its last_activity. Node
    /// updates a per-peer atomic for the idle-purge timer.
    LastActivityUpdate {
        peer_addr: crate::NodeAddr,
        last_activity_ms: u64,
    },
    /// Actor's owned session has accumulated `consecutive_decrypt_
    /// failures` >= threshold. Node should drop the session and
    /// initiate a fresh XK handshake.
    DecryptFailureThresholdExceeded {
        peer_addr: crate::NodeAddr,
        remote_pubkey: PublicKey,
    },
    /// Actor's owned session's drain window expired and the previous
    /// NoiseSession has been cleaned up. Informational.
    SessionDrained { peer_addr: crate::NodeAddr },
    /// Actor's owned session has been removed by the actor (e.g. the
    /// remote disconnected gracefully via a session-layer signal).
    /// Node updates its peer-actor index / control-query caches.
    SessionRemovedByActor { peer_addr: crate::NodeAddr },
}

pub struct DecryptedJob {
    /// FMP-decrypted plaintext (still includes the 4-byte inner
    /// timestamp prefix; the link message body is at index 4).
    pub plaintext: Vec<u8>,
    /// CE flag from the FMP header — propagated into the link-message
    /// dispatch.
    pub ce_flag: bool,
}

/// What the peer task hands back to the rx_loop after its per-peer
/// state mutations are done.
pub struct PeerLinkDispatch {
    /// Source NodeAddr (the peer this came from). Carried so the
    /// rx_loop's dispatch_link_message can route by source.
    pub from: crate::NodeAddr,
    /// The link-message body (msg_type byte + payload).
    pub link_message: Vec<u8>,
    /// CE flag, propagated.
    pub ce_flag: bool,
}

/// Handle stored on `ActivePeer` for the rx_loop to push work into.
/// `None` means "no actor task yet" — the rx_loop falls back to the
/// inline path. After step 7+ the inline path can be removed.
#[derive(Clone, Debug)]
pub struct PeerActorHandle {
    inbound_tx: mpsc::Sender<PeerInboundJob>,
}

impl PeerActorHandle {
    /// Spawn a new per-peer actor task. The task lives until
    /// `inbound_tx` is dropped (which happens when the peer is
    /// removed).
    ///
    /// Returns `None` if no tokio runtime is available (e.g. unit
    /// tests that build peers without an `#[tokio::test]` harness);
    /// callers fall back to the legacy inline path in that case.
    pub fn spawn(
        peer_addr: crate::NodeAddr,
        link_dispatch_tx: mpsc::Sender<PeerLinkDispatch>,
        io_ctx: PeerActorIoCtx,
        queue_depth: usize,
    ) -> Option<Self> {
        // Probe for a current runtime — `tokio::spawn` panics when
        // called outside one.
        if tokio::runtime::Handle::try_current().is_err() {
            return None;
        }
        let (inbound_tx, inbound_rx) = mpsc::channel(queue_depth);
        let _join: JoinHandle<()> = tokio::spawn(peer_actor_loop(
            peer_addr,
            inbound_rx,
            link_dispatch_tx,
            io_ctx,
        ));
        // We deliberately drop the JoinHandle: the task exits cleanly
        // when its inbound_tx half is dropped (i.e. when the peer is
        // removed). No need to await on shutdown — tokio cancels
        // tasks when the runtime stops anyway.
        Some(Self { inbound_tx })
    }

    /// Push a job into the peer's inbox. Returns false if the channel
    /// is closed (the task has exited).
    pub(crate) async fn dispatch(&self, job: PeerInboundJob) -> bool {
        self.inbound_tx.send(job).await.is_ok()
    }

    /// Try to push without awaiting — returns false if the channel is
    /// full or closed. The rx_loop uses this to avoid blocking the
    /// drain loop on a slow peer.
    #[allow(dead_code)]
    pub(crate) fn try_dispatch(&self, job: PeerInboundJob) -> bool {
        self.inbound_tx.try_send(job).is_ok()
    }

    /// Hand a `SessionEntry` over to the peer actor as owned state.
    /// Falls back to `try_send` (non-blocking) since the rx_loop calls
    /// this from cold paths (handshake completion / rekey cutover);
    /// dropping the message under back-pressure is acceptable — the
    /// session stays usable via central dispatch until the next
    /// hand-off attempt.
    #[allow(dead_code)]
    pub(crate) fn try_take_session(&self, entry: Box<SessionEntry>) -> bool {
        self.inbound_tx
            .try_send(PeerInboundJob::TakeSession(entry))
            .is_ok()
    }

    /// Tell the peer actor to drop its owned session, if any.
    /// Non-blocking; if the channel is full the actor's owned copy
    /// stays for now and Node retries on the next removal trigger.
    #[allow(dead_code)]
    pub fn try_remove_session(&self) -> bool {
        self.inbound_tx
            .try_send(PeerInboundJob::RemoveSession)
            .is_ok()
    }
}

/// The peer task body. Pulls jobs from the inbox and processes
/// session-related work. Per-peer state mutations (replay accept,
/// MMP record, link_stats, set_current_addr, touch) are NOT done
/// here — those run on rx_loop where ActivePeer lives plain owned in
/// `Node.peers` (post 7d wrapper removal). The actor's job is purely
/// session lifecycle + FSP work on its owned `SessionEntry`.
async fn peer_actor_loop(
    peer_addr: crate::NodeAddr,
    mut inbound_rx: mpsc::Receiver<PeerInboundJob>,
    link_dispatch_tx: mpsc::Sender<PeerLinkDispatch>,
    io_ctx: PeerActorIoCtx,
) {
    trace!(peer = %peer_addr, "Peer actor task started");
    let mut owned_session: Option<Box<SessionEntry>> = None;
    // ActivePeer ownership — `Some` once Node hands the peer over via
    // `TakePeer` (in `promote_connection` post-migration). When set,
    // `Packet` jobs run end-to-end on the actor task: FMP decrypt +
    // per-peer mutations + link dispatch all happen here, freeing
    // rx_loop to keep reading packets for other peers.
    let mut owned_peer: Option<Box<ActivePeer>> = None;
    while let Some(job) = inbound_rx.recv().await {
        match job {
            PeerInboundJob::Decrypted(decrypted) => {
                handle_decrypted(
                    *decrypted,
                    &link_dispatch_tx,
                    &peer_addr,
                    owned_session.as_deref_mut(),
                    &io_ctx,
                )
                .await;
            }
            PeerInboundJob::TakeSession(entry) => {
                trace!(
                    peer = %peer_addr,
                    "Peer actor took ownership of SessionEntry"
                );
                owned_session = Some(entry);
            }
            PeerInboundJob::RemoveSession => {
                if owned_session.is_some() {
                    trace!(
                        peer = %peer_addr,
                        "Peer actor dropped owned SessionEntry"
                    );
                }
                owned_session = None;
            }
            PeerInboundJob::Encrypt {
                msg_type,
                plaintext,
                coords_payload_if_warmup,
                touch,
                respond,
            } => {
                let result = actor_encrypt(
                    owned_session.as_deref_mut(),
                    msg_type,
                    plaintext,
                    coords_payload_if_warmup,
                    touch,
                );
                let _ = respond.send(result);
            }
            PeerInboundJob::BuildMmpReports { now, respond } => {
                let _ = now;
                // TODO(7c-2 step E): build sender + receiver + path_mtu
                // reports from owned_session.mmp(). Until then, return
                // empty (no reports built by actor) — Node still runs
                // its legacy iteration over self.sessions.
                let _ = respond.send(Vec::new());
            }
            PeerInboundJob::IsRekeyDue { now_ms, respond } => {
                let _ = now_ms;
                // TODO(7c-2 step E): inspect owned_session for cutover/
                // drain/rekey-trigger conditions. Default: nothing —
                // Node still runs its legacy check over self.sessions.
                let _ = respond.send(RekeyDecision::NotApplicable);
            }
            PeerInboundJob::QuerySnapshot(respond) => {
                // TODO(7c-2 step F): build a SessionSnapshot from
                // owned_session. Until then, return None — Node falls
                // back to its legacy show_sessions path over
                // self.sessions.
                let _ = respond.send(None);
            }
            PeerInboundJob::ProcessFspMsg2 {
                handshake_payload,
                respond,
            } => {
                let result = actor_process_fsp_msg2(
                    owned_session.as_deref_mut(),
                    handshake_payload,
                    &io_ctx,
                );
                let _ = respond.send(result);
            }
            PeerInboundJob::ProcessFspMsg3 {
                handshake_payload,
                respond,
            } => {
                let result = actor_process_fsp_msg3(
                    owned_session.as_deref_mut(),
                    handshake_payload,
                    &io_ctx,
                );
                let _ = respond.send(result);
            }
            PeerInboundJob::Packet(packet) => {
                handle_packet(
                    *packet,
                    &link_dispatch_tx,
                    &peer_addr,
                    owned_peer.as_deref_mut(),
                    owned_session.as_deref_mut(),
                    &io_ctx,
                )
                .await;
            }
            PeerInboundJob::TakePeer(peer) => {
                trace!(
                    peer = %peer_addr,
                    "Peer actor took ownership of ActivePeer"
                );
                owned_peer = Some(peer);
            }
            PeerInboundJob::ReleasePeer { respond } => {
                let peer = owned_peer.take();
                if peer.is_some() {
                    trace!(
                        peer = %peer_addr,
                        "Peer actor released owned ActivePeer back to Node"
                    );
                }
                let _ = respond.send(peer);
            }
        }
    }
    // Drop owned state explicitly so destructors run before the task
    // exits. (Implicit drop would do the same; explicit makes intent
    // obvious.)
    drop(owned_session);
    drop(owned_peer);
    trace!(peer = %peer_addr, "Peer actor task exiting (channel closed)");
}

/// Run an `Encrypt` request against the actor's owned `SessionEntry`.
///
/// Mirrors the FSP send pipeline previously inlined in `Node::send_session_data`,
/// but operating on `&mut SessionEntry` (no Arc/RwLock — owned by exactly
/// one task). Caller passes the inner-header-prefixed plaintext; this
/// function builds the FSP header (12 bytes), encrypts with AAD binding,
/// assembles `header + [coords_payload] + ciphertext`, records the send
/// in MMP sender state, optionally touches `last_activity`, and returns
/// the wire bytes for Node to wrap in a `SessionDatagram` envelope.
fn actor_encrypt(
    session: Option<&mut SessionEntry>,
    msg_type: u8,
    plaintext: Vec<u8>,
    coords_payload_if_warmup: Option<Vec<u8>>,
    touch: bool,
) -> Result<EncryptOutput, EncryptError> {
    use crate::node::session::EndToEndState;
    use crate::node::session_wire::{
        FSP_FLAG_CP, FSP_FLAG_K, FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE, build_fsp_header,
        fsp_prepend_inner_header,
    };
    use crate::protocol::FspInnerFlags;

    let entry = session.ok_or(EncryptError::SessionGone)?;
    if !entry.is_established() {
        return Err(EncryptError::NotEstablished);
    }

    // Read spin bit + session timestamp under MMP lock (mmp() is &self
    // via the inner Mutex — step 7b-1).
    let now_ms = crate::time::now_ms();
    let timestamp = entry.session_timestamp(now_ms);
    let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());

    // Decide whether to actually splice coords on this send. Actor is
    // the sole reader/writer of `coords_warmup_remaining` so this is
    // race-free.
    let include_coords =
        coords_payload_if_warmup.is_some() && entry.coords_warmup_remaining() > 0;
    if include_coords {
        let cur = entry.coords_warmup_remaining();
        entry.set_coords_warmup_remaining(cur.saturating_sub(1));
    }
    let coords_payload = if include_coords { coords_payload_if_warmup } else { None };

    // Build inner plaintext: 6-byte FSP inner header + caller's payload.
    let inner_flags = FspInnerFlags { spin_bit }.to_byte();
    let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &plaintext);

    // Build FSP outer flags (CP if coords present, K-bit for current key epoch).
    let mut flags: u8 = 0;
    if coords_payload.is_some() {
        flags |= FSP_FLAG_CP;
    }
    if entry.current_k_bit() {
        flags |= FSP_FLAG_K;
    }

    // Encrypt with AAD binding to the FSP header.
    let session_state = match entry.state_mut() {
        EndToEndState::Established(s) => s,
        _ => return Err(EncryptError::NotEstablished),
    };
    let counter = session_state.current_send_counter();
    let payload_len = inner_plaintext.len() as u16;
    let header = build_fsp_header(counter, flags, payload_len);
    let ciphertext = session_state
        .encrypt_with_aad(&inner_plaintext, &header)
        .map_err(|e| EncryptError::Crypto(format!("{}", e)))?;

    // Assemble: header(12) + [coords] + ciphertext
    let coords_len = coords_payload.as_ref().map(|c| c.len()).unwrap_or(0);
    let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + coords_len + ciphertext.len());
    fsp_payload.extend_from_slice(&header);
    if let Some(coords) = &coords_payload {
        fsp_payload.extend_from_slice(coords);
    }
    fsp_payload.extend_from_slice(&ciphertext);
    let ciphertext_len = ciphertext.len();

    // Bookkeeping: MMP sender record + traffic counters + last_activity.
    if let Some(mut mmp) = entry.mmp_mut() {
        mmp.sender.record_sent(counter, timestamp, ciphertext_len);
    }
    entry.record_sent(plaintext.len());
    if touch {
        entry.touch(now_ms);
    }
    let _ = FSP_INNER_HEADER_SIZE; // silence unused-import path

    Ok(EncryptOutput {
        fsp_payload,
        counter,
        timestamp,
        ciphertext_len,
        included_coords: include_coords,
    })
}

/// Process inbound Noise XK msg2 (initiator side).
///
/// Two flows multiplexed on entry state:
///
/// * **Fresh handshake** — `state == Initiating(handshake)`. Take
///   handshake out, advance through `read_xk_message_2` +
///   `write_xk_message_3`, convert to `NoiseSession`, set state to
///   `Established(...)`, init MMP, mark established. Return msg3
///   payload + `FreshEstablish` flow flag.
///
/// * **Rekey** — `state == Established(...)` and `rekey_state.is_some()`
///   and `is_rekey_initiator`. Run the rekey handshake from
///   `rekey_state` instead, store the result as
///   `pending_new_session`. Established session keeps running on
///   current keys until peer's K-bit flip triggers cutover. Return
///   msg3 + `RekeyPending`.
///
/// On any Noise failure the entry's state field is left as `None`
/// (handshake taken, not put back) — mirrors the existing
/// `handle_session_ack` behaviour. Caller (Node) on Err should
/// `RemoveSession` the actor / re-init.
fn actor_process_fsp_msg2(
    session: Option<&mut SessionEntry>,
    handshake_payload: Vec<u8>,
    io_ctx: &PeerActorIoCtx,
) -> Result<ProcessMsg2Output, ProcessHandshakeError> {
    use crate::node::session::EndToEndState;

    let entry = session.ok_or(ProcessHandshakeError::SessionGone)?;

    // Rekey path: established session with rekey_state and we're the
    // initiator of the rekey.
    if entry.is_established() && entry.has_rekey_in_progress() && entry.is_rekey_initiator() {
        let mut handshake = entry
            .take_rekey_state()
            .ok_or(ProcessHandshakeError::UnexpectedState)?;

        if let Err(e) = handshake.read_xk_message_2(&handshake_payload) {
            entry.abandon_rekey();
            return Err(ProcessHandshakeError::NoiseRead(format!("{}", e)));
        }
        let msg3 = handshake.write_xk_message_3().map_err(|e| {
            entry.abandon_rekey();
            ProcessHandshakeError::NoiseWrite(format!("{}", e))
        })?;
        let new_session = handshake.into_session().map_err(|e| {
            entry.abandon_rekey();
            ProcessHandshakeError::IntoSession(format!("{}", e))
        })?;

        entry.set_pending_session(new_session);
        entry.set_rekey_completed_ms(crate::time::now_ms());

        return Ok(ProcessMsg2Output {
            msg3_payload: msg3,
            flow: ProcessMsg2Flow::RekeyPending,
        });
    }

    // Fresh-establish path: must be Initiating.
    if !entry.is_initiating() {
        return Err(ProcessHandshakeError::UnexpectedState);
    }

    // Take the handshake state out; the entry's state slot is now None
    // until we put Established back at the end.
    let mut handshake = match entry.take_state() {
        Some(EndToEndState::Initiating(hs)) => hs,
        // Re-establish the slot if we got something else (defensive),
        // then bail.
        Some(other) => {
            entry.set_state(other);
            return Err(ProcessHandshakeError::UnexpectedState);
        }
        None => return Err(ProcessHandshakeError::UnexpectedState),
    };

    handshake
        .read_xk_message_2(&handshake_payload)
        .map_err(|e| ProcessHandshakeError::NoiseRead(format!("{}", e)))?;

    let msg3 = handshake
        .write_xk_message_3()
        .map_err(|e| ProcessHandshakeError::NoiseWrite(format!("{}", e)))?;

    let new_session = handshake
        .into_session()
        .map_err(|e| ProcessHandshakeError::IntoSession(format!("{}", e)))?;

    let now_ms = crate::time::now_ms();
    entry.set_state(EndToEndState::Established(new_session));
    entry.set_coords_warmup_remaining(io_ctx.config.node.session.coords_warmup_packets);
    entry.mark_established(now_ms);
    entry.init_mmp(&io_ctx.config.node.session_mmp);
    entry.clear_handshake_payload();
    entry.touch(now_ms);

    Ok(ProcessMsg2Output {
        msg3_payload: msg3,
        flow: ProcessMsg2Flow::FreshEstablish,
    })
}

/// Process inbound Noise XK msg3 (responder side).
///
/// Two flows analogous to msg2:
///
/// * **Fresh handshake** — `state == AwaitingMsg3(handshake)`. Take
///   the handshake out, run `read_xk_message_3` (which discloses the
///   initiator's static pubkey), convert to NoiseSession, set state
///   to `Established`, init MMP. Returns the learned
///   `remote_pubkey` so Node can register identity.
///
/// * **Rekey** — `state == Established(...)` with rekey_state and
///   we're the responder. Process msg3 against rekey_state, park
///   the resulting NoiseSession as `pending_new_session`, awaiting
///   peer's K-bit flip on the next data packet to trigger cutover.
fn actor_process_fsp_msg3(
    session: Option<&mut SessionEntry>,
    handshake_payload: Vec<u8>,
    io_ctx: &PeerActorIoCtx,
) -> Result<ProcessMsg3Output, ProcessHandshakeError> {
    use crate::node::session::EndToEndState;

    let entry = session.ok_or(ProcessHandshakeError::SessionGone)?;

    // Rekey responder path.
    if entry.is_established() && entry.has_rekey_in_progress() && !entry.is_rekey_initiator() {
        let mut handshake = entry
            .take_rekey_state()
            .ok_or(ProcessHandshakeError::UnexpectedState)?;

        if let Err(e) = handshake.read_xk_message_3(&handshake_payload) {
            entry.abandon_rekey();
            return Err(ProcessHandshakeError::NoiseRead(format!("{}", e)));
        }
        let remote_pubkey = *handshake.remote_static().ok_or_else(|| {
            entry.abandon_rekey();
            ProcessHandshakeError::IntoSession("missing remote_static after msg3".into())
        })?;
        let new_session = handshake.into_session().map_err(|e| {
            entry.abandon_rekey();
            ProcessHandshakeError::IntoSession(format!("{}", e))
        })?;

        entry.set_pending_session(new_session);

        return Ok(ProcessMsg3Output {
            remote_pubkey,
            flow: ProcessMsg3Flow::RekeyPending,
        });
    }

    // Fresh-establish path.
    if !entry.is_awaiting_msg3() {
        return Err(ProcessHandshakeError::UnexpectedState);
    }

    let mut handshake = match entry.take_state() {
        Some(EndToEndState::AwaitingMsg3(hs)) => hs,
        Some(other) => {
            entry.set_state(other);
            return Err(ProcessHandshakeError::UnexpectedState);
        }
        None => return Err(ProcessHandshakeError::UnexpectedState),
    };

    handshake
        .read_xk_message_3(&handshake_payload)
        .map_err(|e| ProcessHandshakeError::NoiseRead(format!("{}", e)))?;

    let remote_pubkey = *handshake
        .remote_static()
        .ok_or_else(|| ProcessHandshakeError::IntoSession("missing remote_static after msg3".into()))?;

    let new_session = handshake
        .into_session()
        .map_err(|e| ProcessHandshakeError::IntoSession(format!("{}", e)))?;

    let now_ms = crate::time::now_ms();
    entry.set_state(EndToEndState::Established(new_session));
    entry.set_coords_warmup_remaining(io_ctx.config.node.session.coords_warmup_packets);
    entry.mark_established(now_ms);
    entry.init_mmp(&io_ctx.config.node.session_mmp);
    entry.clear_handshake_payload();
    entry.touch(now_ms);
    entry.set_remote_pubkey(remote_pubkey);

    Ok(ProcessMsg3Output {
        remote_pubkey,
        flow: ProcessMsg3Flow::FreshEstablish,
    })
}

/// Apply per-peer mutations for a successfully FMP-decrypted frame.
///
/// All operations after step 4 of the peer-actor refactor are
/// `&self`-callable on `ActivePeer`, so a read lock suffices — the
/// rx_loop and the peer task can hold concurrent read locks on the
/// same slot without contention.
async fn handle_decrypted(
    job: DecryptedJob,
    link_dispatch_tx: &mpsc::Sender<PeerLinkDispatch>,
    peer_addr: &crate::NodeAddr,
    owned_session: Option<&mut SessionEntry>,
    io_ctx: &PeerActorIoCtx,
) {
    let DecryptedJob {
        plaintext,
        ce_flag,
        ..
    } = job;

    const INNER_TIMESTAMP_LEN: usize = 4;
    if plaintext.len() <= INNER_TIMESTAMP_LEN {
        debug!(
            peer = %peer_addr,
            len = plaintext.len(),
            "Decrypted payload too short for inner header (peer actor)"
        );
        return;
    }
    let link_message = &plaintext[INNER_TIMESTAMP_LEN..];

    // Fast path: if we own a SessionEntry for this peer, AND the link
    // message is a SessionDatagram destined for us, AND the FSP phase
    // is ESTABLISHED + encrypted + msg_type is DataPacket, do the
    // FSP-receive pipeline (decrypt + replay + MMP record + IPv6-shim
    // decompress + tun_tx.send) inline. Bypasses the rx_loop's
    // central dispatch entirely. Falls through to NeedsCentralDispatch
    // if any precondition fails.
    if let Some(session) = owned_session
        && try_actor_fast_path_receive(session, link_message, ce_flag, peer_addr, io_ctx).await
    {
        return;
    }

    // Fallback: forward link message to rx_loop for dispatch.
    let _ = link_dispatch_tx
        .send(PeerLinkDispatch {
            from: *peer_addr,
            link_message: link_message.to_vec(),
            ce_flag,
        })
        .await;
}

/// Handle a raw inbound encrypted packet end-to-end on the actor.
///
/// Mirrors `Node::handle_encrypted_frame` but without any access to
/// `Node.peers` / `Node.peers_by_index` — the FMP receive pipeline runs
/// against the actor's owned `ActivePeer` (post ActivePeer-to-actor
/// migration). Successful frames flow through the same FSP fast path /
/// link_dispatch_tx fallback as `handle_decrypted`.
///
/// If the actor doesn't own a peer (e.g. Node hasn't called `TakePeer`
/// yet, or it's been released), the packet is dropped — the rx_loop
/// is the source of truth in that case and would have run the inline
/// path itself.
///
/// `peers_by_index` cleanup on stale-index / decrypt-failure-threshold
/// removal is currently best-effort: the actor logs and increments
/// counters but does not escalate to Node yet (no PeerOutboundEvent
/// channel wired in this phase). Subsequent phases will route those
/// through `peer_event_tx` so feature parity matches the inline path.
async fn handle_packet(
    packet: crate::transport::ReceivedPacket,
    link_dispatch_tx: &mpsc::Sender<PeerLinkDispatch>,
    peer_addr: &crate::NodeAddr,
    owned_peer: Option<&mut ActivePeer>,
    owned_session: Option<&mut SessionEntry>,
    io_ctx: &PeerActorIoCtx,
) {
    use crate::node::wire::{EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP};
    use crate::peer::{InboundFrame, InboundFrameOutcome};

    let Some(peer) = owned_peer else {
        debug!(
            peer = %peer_addr,
            "Packet job dropped — actor does not own peer"
        );
        return;
    };

    // Parse outer FMP header — fail fast on malformed.
    let header = match EncryptedHeader::parse(&packet.data) {
        Some(h) => h,
        None => return,
    };

    let ce_flag = header.flags & FLAG_CE != 0;
    let frame = InboundFrame {
        ciphertext: &packet.data[header.ciphertext_offset()..],
        counter: header.counter,
        header_bytes: &header.header_bytes,
        received_k_bit: header.flags & FLAG_KEY_EPOCH != 0,
        ce_flag,
        sp_flag: header.flags & FLAG_SP != 0,
        packet_len: packet.data.len(),
        packet_timestamp_ms: packet.timestamp_ms,
        packet_transport_id: packet.transport_id,
        packet_remote_addr: packet.remote_addr.clone(),
    };

    let outcome = peer.process_inbound_fmp_frame(frame);

    match outcome {
        InboundFrameOutcome::Authentic { plaintext, .. } => {
            const INNER_TIMESTAMP_LEN: usize = 4;
            if plaintext.len() <= INNER_TIMESTAMP_LEN {
                debug!(
                    peer = %peer_addr,
                    len = plaintext.len(),
                    "Decrypted payload too short for inner header (peer actor packet)"
                );
                return;
            }
            let link_message = &plaintext[INNER_TIMESTAMP_LEN..];

            // Fast path: actor-owned SessionEntry, SessionDatagram → us,
            // FSP ESTABLISHED, DataPacket → IPv6 shim → TUN. Same
            // preconditions as `handle_decrypted`'s fast path.
            if let Some(session) = owned_session
                && try_actor_fast_path_receive(session, link_message, ce_flag, peer_addr, io_ctx)
                    .await
            {
                return;
            }

            let _ = link_dispatch_tx
                .send(PeerLinkDispatch {
                    from: *peer_addr,
                    link_message: link_message.to_vec(),
                    ce_flag,
                })
                .await;
        }
        InboundFrameOutcome::InnerHeaderTooShort { plaintext_len } => {
            debug!(
                peer = %peer_addr,
                len = plaintext_len,
                "Decrypted payload too short for inner header (peer actor packet)"
            );
        }
        InboundFrameOutcome::DecryptFailed { error } => {
            // Increment for telemetry; threshold-driven removal is
            // wired in a follow-up phase via PeerOutboundEvent.
            let count = peer.increment_decrypt_failures();
            debug!(
                peer = %peer_addr,
                error = %error,
                consecutive_failures = count,
                "Decryption failed (peer actor packet)"
            );
        }
        InboundFrameOutcome::NoSession => {
            debug!(
                peer = %peer_addr,
                "Packet for actor-owned peer with no Noise session"
            );
        }
    }
}

/// Try the actor-owned FSP receive fast path. Returns `true` iff the
/// message was fully handled by the actor (DataPacket → TUN delivery);
/// `false` means the caller should NeedsCentralDispatch instead.
///
/// Preconditions for fast-path success:
/// 1. `link_message[0] == 0x00` (LinkMessageType::SessionDatagram)
/// 2. The wrapped SessionDatagram's `dest_addr == io_ctx.node_addr`
/// 3. FSP phase is ESTABLISHED with the U flag clear
/// 4. The session is in the actor's owned state and Established
/// 5. The msg_type after FSP decrypt is `DataPacket` (0x10)
/// 6. The DataPacket destination port is `FSP_PORT_IPV6_SHIM`
///
/// CP-flagged datagrams (coords-piggybacked) fall through because
/// updating `coord_cache` requires Node-side state. Other msg_types
/// (EndpointData / SR / RR / PMtuNotification / CoordsWarmup) fall
/// through too — Node still owns those handlers in step v.
async fn try_actor_fast_path_receive(
    session: &mut SessionEntry,
    link_message: &[u8],
    ce_flag: bool,
    peer_addr: &crate::NodeAddr,
    io_ctx: &PeerActorIoCtx,
) -> bool {
    use crate::node::session::EndToEndState;
    use crate::node::session_wire::{
        FSP_COMMON_PREFIX_SIZE, FSP_FLAG_CP, FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE,
        FSP_PORT_HEADER_SIZE, FSP_PORT_IPV6_SHIM, FspCommonPrefix, FspEncryptedHeader,
        fsp_strip_inner_header,
    };
    use crate::protocol::{LinkMessageType, SessionDatagram, SessionMessageType};

    if link_message.first().copied() != Some(LinkMessageType::SessionDatagram.to_byte()) {
        return false;
    }
    let datagram = match SessionDatagram::decode(&link_message[1..]) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if datagram.dest_addr != io_ctx.node_addr {
        return false;
    }
    let payload = &datagram.payload;

    // Parse common prefix to gate on phase + encryption.
    let prefix = match FspCommonPrefix::parse(payload) {
        Some(p) => p,
        None => return false,
    };
    if prefix.phase != crate::node::session_wire::FSP_PHASE_ESTABLISHED || prefix.is_unencrypted() {
        return false;
    }

    // Parse the 12-byte FSP header.
    let header = match FspEncryptedHeader::parse(payload) {
        Some(h) => h,
        None => return false,
    };
    // CP-flagged data needs coord_cache writes — fall through to Node.
    if header.flags & FSP_FLAG_CP != 0 {
        return false;
    }
    let received_k_bit = header.flags & crate::node::session_wire::FSP_FLAG_K != 0;

    // K-bit flip — rare cold path. If detected, advance under the same
    // owned-session ref (we have `&mut SessionEntry` already).
    if received_k_bit != session.current_k_bit() && session.pending_new_session().is_some() {
        let now_ms = crate::time::now_ms();
        session.handle_peer_kbit_flip(now_ms);
    }

    if !session.is_established() {
        return false;
    }

    let ciphertext = &payload[FSP_HEADER_SIZE..];
    let path_mtu = datagram.path_mtu;
    let src_addr = datagram.src_addr;

    // Try current then drain-window decrypt. After 7d single-owner,
    // `decrypt_with_replay_check_and_aad` is `&mut self`. We have
    // `&mut SessionEntry` so this works without locks.
    let plaintext = {
        let noise = match session.state_mut() {
            EndToEndState::Established(s) => s,
            _ => return false,
        };
        match noise.decrypt_with_replay_check_and_aad(
            ciphertext,
            header.counter,
            &header.header_bytes,
        ) {
            Ok(pt) => pt,
            Err(_) => match session.previous_noise_session_mut().and_then(|prev| {
                prev.decrypt_with_replay_check_and_aad(
                    ciphertext,
                    header.counter,
                    &header.header_bytes,
                )
                .ok()
            }) {
                Some(pt) => pt,
                None => {
                    // Both failed — bump counter, fall through to Node
                    // for re-handshake threshold logic.
                    session.record_decrypt_failure();
                    return false;
                }
            },
        }
    };

    session.reset_decrypt_failures();

    let (timestamp, msg_type, inner_flags_byte) = match fsp_strip_inner_header(&plaintext) {
        Some((ts, mt, inf, _rest)) => (ts, mt, inf),
        None => return false,
    };

    // MMP receive bookkeeping.
    if let Some(mut mmp) = session.mmp_mut() {
        let now = std::time::Instant::now();
        mmp.receiver
            .record_recv(header.counter, timestamp, plaintext.len(), ce_flag, now);
        let inner_flags = crate::protocol::FspInnerFlags::from_byte(inner_flags_byte);
        let _ = mmp.spin_bit.rx_observe(inner_flags.spin_bit, header.counter, now);
        mmp.path_mtu.observe_incoming_mtu(path_mtu);
    }

    // Only DataPacket (msg_type 0x10) gets the IPv6-shim → TUN fast path.
    // Everything else falls through to Node.
    if SessionMessageType::from_byte(msg_type) != Some(SessionMessageType::DataPacket) {
        return false;
    }

    let rest = &plaintext[FSP_INNER_HEADER_SIZE..];
    if rest.len() < FSP_PORT_HEADER_SIZE {
        return false;
    }
    let dst_port = u16::from_le_bytes([rest[2], rest[3]]);
    if dst_port != FSP_PORT_IPV6_SHIM {
        return false;
    }
    let service_payload = &rest[FSP_PORT_HEADER_SIZE..];

    use crate::FipsAddress;
    let src_ipv6 = FipsAddress::from_node_addr(&src_addr).to_ipv6().octets();
    let dst_ipv6 = FipsAddress::from_node_addr(&io_ctx.node_addr).to_ipv6().octets();
    let mut packet = match crate::upper::ipv6_shim::decompress_ipv6(service_payload, src_ipv6, dst_ipv6) {
        Some(p) => p,
        None => return false,
    };
    if ce_flag {
        crate::node::handlers::session::mark_ipv6_ecn_ce(&mut packet);
    }

    // Application-layer record + last_activity touch.
    session.record_recv(plaintext.len());
    let now_ms = crate::time::now_ms();
    session.touch(now_ms);

    if let Some(tx) = &io_ctx.tun_tx {
        if let Err(e) = tx.send(packet) {
            debug!(
                peer = %peer_addr,
                error = %e,
                "actor fast path: TUN send failed"
            );
        }
    } else {
        // No TUN attached — drop. Mirrors Node's behaviour of
        // tracing the drop and not erroring.
        trace!(
            peer = %peer_addr,
            "actor fast path: IPv6 packet decompressed but no TUN attached"
        );
    }
    true
}

/// Receiver side of the per-peer link-dispatch channel. Held by `Node`
/// and drained from the rx_loop's `select!`. Wrapped in a small
/// `Arc<...>`-friendly newtype so `Node`'s lifecycle code can construct
/// the pair once and hand the sender to each new peer task.
pub struct PeerLinkDispatchRx(pub mpsc::Receiver<PeerLinkDispatch>);
pub type PeerLinkDispatchTx = mpsc::Sender<PeerLinkDispatch>;

/// Construct the (sender, receiver) pair for the link-dispatch channel.
///
/// `queue_depth` caps how many post-actor link messages can be in
/// flight before peer tasks back-pressure. 256 matches the rx_loop's
/// existing inbound drain cap.
pub fn link_dispatch_channel(queue_depth: usize) -> (Arc<PeerLinkDispatchTx>, PeerLinkDispatchRx) {
    let (tx, rx) = mpsc::channel(queue_depth);
    (Arc::new(tx), PeerLinkDispatchRx(rx))
}
