//! Per-peer actor task — step 6 of the peer-actor refactor.
//!
//! Spawned once per authenticated peer in `promote_connection`. Owns
//! a clone of the peer's `ActivePeerSlot` (Arc<RwLock<ActivePeer>>)
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

use crate::node::session::SessionEntry;
use crate::peer::ActivePeerSlot;
use crate::transport::{ReceivedPacket, TransportAddr, TransportId};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace};

/// One unit of work pushed from the rx_loop into a peer task.
pub(crate) enum PeerInboundJob {
    /// FMP-decrypted frame on this peer. The peer task accepts the
    /// replay counter, records MMP / link stats, touches last-seen,
    /// and forwards the link message to the rx_loop's dispatch queue.
    Decrypted(Box<DecryptedJob>),
    /// Hand ownership of a (newly-Established) `SessionEntry` to the
    /// peer actor. Node calls this from its handshake-completion path
    /// when the session's `remote_addr` matches this peer's NodeAddr
    /// (direct peer = direct session). The actor parks the entry as
    /// owned local state so subsequent FSP-receive work can run with
    /// no shared-state access. Step 7c — currently scaffolding; the
    /// hot-path FSP-decrypt-in-actor will land in 7c-2.
    TakeSession(Box<SessionEntry>),
    /// Tell the peer actor to drop its owned `SessionEntry` (peer
    /// disconnect, idle purge, decrypt-failure-threshold reinit).
    /// After this the actor's owned session is `None`; FSP-receive
    /// work falls back to the central dispatch path until a new
    /// `TakeSession` arrives.
    RemoveSession,
}

pub struct DecryptedJob {
    /// Original packet. Used for `record_recv(packet.data.len(), ...)`
    /// and for `set_current_addr(transport_id, remote_addr)`.
    pub packet: ReceivedPacket,
    /// FMP-decrypted plaintext (still includes the 4-byte inner
    /// timestamp prefix; the link message body is at index 4).
    pub plaintext: Vec<u8>,
    /// Counter from the FMP outer header. Replay accept uses this.
    pub fmp_counter: u64,
    /// Inner-header timestamp (already extracted by the rx_loop).
    pub inner_timestamp: u32,
    /// Did the rx_loop fall back to the previous (drain-window)
    /// session for this frame? Used to direct `accept_replay` to the
    /// right NoiseSession.
    pub used_previous_session: bool,
    /// CE flag from the FMP header — propagated into MMP and into
    /// the downstream link-message dispatch.
    pub ce_flag: bool,
    /// SP flag from the FMP header — fed into the spin-bit observer.
    pub sp_flag: bool,
    /// Convenience copy of `packet.transport_id` so `set_current_addr`
    /// doesn't need to touch the packet again.
    pub packet_transport_id: TransportId,
    /// Convenience copy of `packet.remote_addr.clone()`.
    pub packet_remote_addr: TransportAddr,
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
        peer_slot: ActivePeerSlot,
        link_dispatch_tx: mpsc::Sender<PeerLinkDispatch>,
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
            peer_slot,
            inbound_rx,
            link_dispatch_tx,
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

/// The peer task body. Pulls jobs from the inbox and runs the
/// per-peer state mutations.
async fn peer_actor_loop(
    peer_addr: crate::NodeAddr,
    peer_slot: ActivePeerSlot,
    mut inbound_rx: mpsc::Receiver<PeerInboundJob>,
    link_dispatch_tx: mpsc::Sender<PeerLinkDispatch>,
) {
    trace!(peer = %peer_addr, "Peer actor task started");
    // Owned per-actor state. `session` is `None` until a `TakeSession`
    // job arrives from Node (handshake completion path). When present,
    // the actor can run the FSP-receive fast path entirely on owned
    // state — no Arc<RwLock>, no central HashMap lookup. Step 7c-1
    // installs the channel scaffolding; 7c-2 wires the fast-path
    // decrypt + TUN write here.
    let mut owned_session: Option<Box<SessionEntry>> = None;
    while let Some(job) = inbound_rx.recv().await {
        match job {
            PeerInboundJob::Decrypted(decrypted) => {
                handle_decrypted(&peer_slot, *decrypted, &link_dispatch_tx, &peer_addr).await;
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
        }
    }
    // Drop owned_session explicitly so its destructor runs before the
    // task exits. (Implicit drop would do the same; explicit makes the
    // intent obvious.)
    drop(owned_session);
    trace!(peer = %peer_addr, "Peer actor task exiting (channel closed)");
}

/// Apply per-peer mutations for a successfully FMP-decrypted frame.
///
/// All operations after step 4 of the peer-actor refactor are
/// `&self`-callable on `ActivePeer`, so a read lock suffices — the
/// rx_loop and the peer task can hold concurrent read locks on the
/// same slot without contention.
async fn handle_decrypted(
    peer_slot: &ActivePeerSlot,
    job: DecryptedJob,
    link_dispatch_tx: &mpsc::Sender<PeerLinkDispatch>,
    peer_addr: &crate::NodeAddr,
) {
    let DecryptedJob {
        packet,
        plaintext,
        fmp_counter,
        inner_timestamp,
        used_previous_session,
        ce_flag,
        sp_flag,
        packet_transport_id,
        packet_remote_addr,
    } = job;

    let packet_len = packet.data.len();
    let packet_timestamp_ms = packet.timestamp_ms;

    // Per-peer state mutations. After step 4, all of these go through
    // `&self`/interior mutability, so a read lock is enough.
    {
        let peer = crate::peer::peer_read(peer_slot);
        if used_previous_session {
            if let Some(prev) = peer.previous_session() {
                prev.accept_replay(fmp_counter);
            }
        } else if let Some(s) = peer.noise_session() {
            s.accept_replay(fmp_counter);
        }

        peer.reset_decrypt_failures();
        let now = std::time::Instant::now();
        if let Some(mut mmp) = peer.mmp_mut() {
            mmp.receiver
                .record_recv(fmp_counter, inner_timestamp, packet_len, ce_flag, now);
            let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, fmp_counter, now);
        }
        peer.set_current_addr(packet_transport_id, packet_remote_addr);
        peer.link_stats()
            .record_recv(packet_len, packet_timestamp_ms);
        peer.touch(packet_timestamp_ms);
    }

    // The link message is plaintext minus the 4-byte inner timestamp
    // (mirrors the strip_inner_header slice). Forward to the rx_loop
    // for dispatch — handle_session_datagram and friends still need
    // `&mut Node`, so the central dispatch task runs those.
    const INNER_TIMESTAMP_LEN: usize = 4;
    if plaintext.len() <= INNER_TIMESTAMP_LEN {
        debug!(
            peer = %peer_addr,
            len = plaintext.len(),
            "Decrypted payload too short for inner header (peer actor)"
        );
        return;
    }
    let link_message = plaintext[INNER_TIMESTAMP_LEN..].to_vec();

    let _ = link_dispatch_tx
        .send(PeerLinkDispatch {
            from: *peer_addr,
            link_message,
            ce_flag,
        })
        .await;
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
