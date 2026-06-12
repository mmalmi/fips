//! Off-task FMP encrypt + UDP send worker.
//!
//! **Unix only** — the per-worker send loop issues direct
//! `sendmmsg(2)` / `sendmsg(2)+UDP_GSO` calls on raw file descriptors
//! via `AsRawFd`. On Windows the worker pool isn't spawned (see
//! `lifecycle.rs`) and the rx_loop's tokio-based send path remains
//! the canonical outbound route.
//!
//! The sender hot path of FIPS used to do every step of an outbound
//! packet — session lookup, FSP encrypt, datagram serialise, link
//! lookup, FMP encrypt, UDP `sendto` — sequentially on the single
//! `rx_loop` tokio task. At line rate that task pegs at 99.9% CPU on
//! one core while five other tokio workers sit at 6–40% each. The
//! send pipeline's measured cost breakdown (FIPS_PERF stats on AMD
//! Ryzen 7 7700, single-stream TCP at ~91 kpps):
//!
//! ```text
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

// On Windows nothing inside this module is called (the pool isn't
// spawned in lifecycle::start). Silence the cascade of dead-code
// warnings rather than gate every function individually.
#![cfg_attr(not(unix), allow(dead_code))]

use crate::node::session_wire::FSP_HEADER_SIZE;
use crate::node::wire::ESTABLISHED_HEADER_SIZE;
use crate::transport::udp::socket::AsyncUdpSocket;
#[cfg(not(target_os = "macos"))]
use crossbeam_channel::{Receiver, SendError, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
#[cfg(target_os = "macos")]
use std::cell::RefCell;
#[cfg(target_os = "macos")]
use std::collections::BTreeMap;
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::collections::VecDeque;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::{Condvar, Mutex};
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
    /// Optional inner FSP AEAD operation to perform before the outer FMP seal.
    /// The rx_loop pre-reserves the FSP counter and lays out `wire_buf` so the
    /// FSP plaintext is the current tail. The worker seals that tail in place,
    /// appends the FSP tag, then seals the full FMP plaintext. This keeps both
    /// AEADs off the rx_loop while preserving FSP/FMP wire format.
    pub fsp_seal: Option<FspSealJob>,
    /// Kernel send target selected by the rx_loop. Worker dispatch, fair
    /// admission, macOS flow selection, and flush grouping all consume this
    /// same value instead of rebuilding target identity independently.
    pub send_target: SelectedSendTarget,
    /// True for tunnel endpoint-data payloads that should use the worker's
    /// bulk lane instead of the control/liveness reserve. If this lane is
    /// already full, dispatch treats the worker queue as a saturated network
    /// queue and drops the packet rather than parking the node rx_loop behind
    /// bulk egress. TCP bulk can recover from that as packet loss; ACKs,
    /// handshakes, heartbeats, and other latency-sensitive payloads are kept
    /// out of this lane by the endpoint payload classifier.
    pub bulk_endpoint_data: bool,
    /// Bulk endpoint data may be dropped when the kernel reports UDP
    /// send-queue exhaustion. This is separate from worker-queue admission:
    /// this flag remains false for TCP endpoint data so kernel send
    /// backpressure still retries TCP packets that have already reached a
    /// worker.
    pub drop_on_backpressure: bool,
    /// Bounded scheduler weight for this send target. `1` is normal
    /// best-effort service; configured peers can get a small boost and
    /// future paid traffic can use the same clamp without bypassing fairness.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub scheduling_weight: u8,
    /// Monotonic timestamp captured before dispatch into the worker
    /// queue, used only when pipeline tracing is enabled.
    pub queued_at: Option<crate::perf_profile::TraceStamp>,
}

pub(crate) struct FspSealJob {
    pub cipher: LessSafeKey,
    pub counter: u64,
    pub aad_offset: usize,
    pub plaintext_offset: usize,
}

#[derive(Clone)]
pub(crate) struct SelectedSendTarget {
    /// AsyncUdpSocket clone (internally `Arc<AsyncFd<UdpRawSocket>>`,
    /// so the clone is just a refcount bump). Used as the **fallback**
    /// send fd when no per-peer connected socket is available — i.e.
    /// the wildcard listen socket. Kernel serialises concurrent
    /// `sendto` calls so multiple workers sharing this handle is safe.
    socket: AsyncUdpSocket,
    /// **Unix connected-UDP fast path:** when set, the worker sends
    /// on this socket's fd without a destination sockaddr instead of
    /// the wildcard listen socket. The kernel skips per-packet
    /// sockaddr handling, route lookup, and neighbor resolution
    /// because they're cached from the `connect()` call. The `Arc`
    /// keeps the kernel fd alive for the lifetime of this target; once
    /// the job completes and the worker drops it, only the peer's
    /// strong ref remains.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_socket:
        Option<std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>>,
    /// Destination kernel `SocketAddr` — resolved on rx_loop side so
    /// the worker can skip the per-packet DNS / address parse. Used
    /// when sending via the listen socket (msg_name field of mmsghdr).
    /// Ignored when `connected_socket` is `Some` (the kernel knows
    /// the destination already).
    dest_addr: SocketAddr,
    #[cfg(unix)]
    key: SendTargetKey,
}

impl SelectedSendTarget {
    pub(crate) fn new(
        socket: AsyncUdpSocket,
        #[cfg(any(target_os = "linux", target_os = "macos"))] connected_socket: Option<
            std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
        >,
        dest_addr: SocketAddr,
    ) -> Self {
        #[cfg(unix)]
        let key = SendTargetKey::from_parts(
            &socket,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket.as_ref(),
            dest_addr,
        );
        Self {
            socket,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket,
            dest_addr,
            #[cfg(unix)]
            key,
        }
    }

    #[cfg(unix)]
    fn key(&self) -> SendTargetKey {
        self.key
    }

    #[cfg(unix)]
    fn dest_addr(&self) -> SocketAddr {
        self.dest_addr
    }

    #[cfg(unix)]
    fn fd_and_connected(&self) -> (RawFd, bool) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(socket) = self.connected_socket.as_ref() {
            return (socket.as_raw_fd(), true);
        }
        (self.socket.as_raw_fd(), false)
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct SendTargetKey {
    socket_fd: RawFd,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_fd: Option<RawFd>,
    dest_addr: SocketAddr,
}

#[cfg(unix)]
impl SendTargetKey {
    fn from_parts(
        socket: &AsyncUdpSocket,
        #[cfg(any(target_os = "linux", target_os = "macos"))] connected_socket: Option<
            &std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
        >,
        dest_addr: SocketAddr,
    ) -> Self {
        Self {
            socket_fd: socket.as_raw_fd(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_fd: connected_socket.map(|socket| socket.as_raw_fd()),
            dest_addr,
        }
    }
}

impl FmpSendJob {
    #[cfg(unix)]
    fn send_target_key(&self) -> SendTargetKey {
        self.send_target.key()
    }
}

#[cfg(unix)]
struct SelectedSendBatch {
    send_target: SelectedSendTarget,
    target_key: SendTargetKey,
    wire_packets: Vec<Vec<u8>>,
    drop_on_backpressure: bool,
}

#[cfg(unix)]
impl SelectedSendBatch {
    fn new(
        send_target: SelectedSendTarget,
        target_key: SendTargetKey,
        wire_packet: Vec<u8>,
        drop_on_backpressure: bool,
    ) -> Self {
        debug_assert_eq!(
            send_target.key(),
            target_key,
            "selected send batch must keep the queued target key"
        );
        Self {
            send_target,
            target_key,
            wire_packets: vec![wire_packet],
            drop_on_backpressure,
        }
    }

    fn target_key(&self) -> SendTargetKey {
        self.target_key
    }

    fn push(&mut self, wire_packet: Vec<u8>, drop_on_backpressure: bool) {
        debug_assert_eq!(
            self.drop_on_backpressure, drop_on_backpressure,
            "send batches keep one backpressure policy so bulk remains droppable"
        );
        self.wire_packets.push(wire_packet);
    }

    fn drop_on_backpressure(&self) -> bool {
        self.drop_on_backpressure
    }

    fn into_parts(self) -> (SelectedSendTarget, Vec<Vec<u8>>, bool) {
        (
            self.send_target,
            self.wire_packets,
            self.drop_on_backpressure,
        )
    }
}

#[cfg(target_os = "linux")]
struct LinuxSendBatchAttempt {
    send_target: SelectedSendTarget,
    wire_packets: Vec<Vec<u8>>,
    drop_on_backpressure: bool,
    backpressure: SendBackpressurePacer,
    sent: usize,
}

#[cfg(target_os = "linux")]
impl LinuxSendBatchAttempt {
    fn from_batch(batch: SelectedSendBatch) -> Self {
        let (send_target, wire_packets, drop_on_backpressure) = batch.into_parts();
        Self {
            send_target,
            wire_packets,
            drop_on_backpressure,
            backpressure: SendBackpressurePacer::default(),
            sent: 0,
        }
    }

    #[cfg(test)]
    fn target_key(&self) -> SendTargetKey {
        self.send_target.key()
    }

    fn target_parts(&self) -> (std::os::unix::io::RawFd, bool, SocketAddr) {
        let (fd, connected) = self.send_target.fd_and_connected();
        (fd, connected, self.send_target.dest_addr())
    }

    fn packets(&self) -> &[Vec<u8>] {
        &self.wire_packets
    }

    fn remaining_packets(&self) -> &[Vec<u8>] {
        &self.wire_packets[self.sent..]
    }

    fn is_complete(&self) -> bool {
        self.sent >= self.wire_packets.len()
    }

    fn mark_all_sent(&mut self) {
        let remaining = self.remaining_packets().len();
        self.mark_sent(remaining);
    }

    fn mark_sent(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        debug_assert!(
            self.sent + n <= self.wire_packets.len(),
            "sendmmsg reported more packets than remained in the batch"
        );
        let n = n.min(self.wire_packets.len().saturating_sub(self.sent));
        self.sent += n;
        self.backpressure.record_success();
        let (_, connected, _) = self.target_parts();
        record_udp_send_path(connected, n as u64);
    }

    fn handle_backpressure(&mut self, err: &std::io::Error) -> SendBackpressureDecision {
        let pacer_requested_drop = self.backpressure.pause(err);
        self.handle_backpressure_request(pacer_requested_drop, err)
    }

    fn handle_backpressure_request(
        &mut self,
        pacer_requested_drop: bool,
        err: &std::io::Error,
    ) -> SendBackpressureDecision {
        let decision = send_backpressure_decision(pacer_requested_drop, self.drop_on_backpressure);
        if matches!(decision, SendBackpressureDecision::DropCurrentBulk) && !self.is_complete() {
            record_udp_send_backpressure_drop(err);
            self.sent += 1;
        }
        decision
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
struct DirectSendBatchAttempt {
    send_target: SelectedSendTarget,
    wire_packets: Vec<Vec<u8>>,
    drop_on_backpressure: bool,
    backpressure: SendBackpressurePacer,
    sent: usize,
}

#[cfg(all(unix, not(target_os = "linux")))]
impl DirectSendBatchAttempt {
    fn from_batch(batch: SelectedSendBatch) -> Self {
        let (send_target, wire_packets, drop_on_backpressure) = batch.into_parts();
        Self {
            send_target,
            wire_packets,
            drop_on_backpressure,
            backpressure: SendBackpressurePacer::default(),
            sent: 0,
        }
    }

    #[cfg(test)]
    fn target_key(&self) -> SendTargetKey {
        self.send_target.key()
    }

    fn target_parts(&self) -> (RawFd, bool, SocketAddr) {
        let (fd, connected) = self.send_target.fd_and_connected();
        (fd, connected, self.send_target.dest_addr())
    }

    #[cfg(test)]
    fn remaining_packets(&self) -> &[Vec<u8>] {
        &self.wire_packets[self.sent..]
    }

    fn current_packet_len(&self) -> Option<usize> {
        self.wire_packets.get(self.sent).map(Vec::len)
    }

    fn is_complete(&self) -> bool {
        self.sent >= self.wire_packets.len()
    }

    fn mark_current_sent(&mut self) {
        if self.is_complete() {
            return;
        }
        self.sent += 1;
        self.backpressure.record_success();
        let (_, connected, _) = self.target_parts();
        record_udp_send_path(connected, 1);
    }

    fn handle_backpressure(&mut self, err: &std::io::Error) -> SendBackpressureDecision {
        let pacer_requested_drop = self.backpressure.pause(err);
        self.handle_backpressure_request(pacer_requested_drop, err)
    }

    fn handle_backpressure_request(
        &mut self,
        pacer_requested_drop: bool,
        err: &std::io::Error,
    ) -> SendBackpressureDecision {
        let decision = send_backpressure_decision(pacer_requested_drop, self.drop_on_backpressure);
        if matches!(decision, SendBackpressureDecision::DropCurrentBulk) && !self.is_complete() {
            record_udp_send_backpressure_drop(err);
            self.sent += 1;
        }
        decision
    }

    fn send_current(&mut self) -> std::io::Result<()> {
        let (fd, connected, dest_addr) = self.target_parts();
        loop {
            let Some(data) = self.wire_packets.get(self.sent).map(Vec::as_slice) else {
                return Ok(());
            };
            let result = if connected {
                send_connected_raw(fd, data)
            } else {
                send_one_raw(fd, data, &dest_addr)
            };
            match result {
                Ok(_) => {
                    self.mark_current_sent();
                    return Ok(());
                }
                Err(err) if is_send_backpressure(&err) => {
                    if matches!(
                        self.handle_backpressure(&err),
                        SendBackpressureDecision::DropCurrentBulk
                    ) {
                        return Ok(());
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }
}

#[cfg(unix)]
fn push_selected_send_batch(
    groups: &mut Vec<SelectedSendBatch>,
    send_target: SelectedSendTarget,
    target_key: SendTargetKey,
    wire_packet: Vec<u8>,
    drop_on_backpressure: bool,
) {
    if let Some(idx) = groups
        .iter()
        .rposition(|group| group.target_key() == target_key)
    {
        if groups[idx].drop_on_backpressure() == drop_on_backpressure {
            groups[idx].push(wire_packet, drop_on_backpressure);
            return;
        }
    }

    groups.push(SelectedSendBatch::new(
        send_target,
        target_key,
        wire_packet,
        drop_on_backpressure,
    ));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncryptWorkerLane {
    Priority,
    Bulk,
}

fn encrypt_worker_lane_for_endpoint_data(bulk_endpoint_data: bool) -> EncryptWorkerLane {
    if bulk_endpoint_data {
        EncryptWorkerLane::Bulk
    } else {
        EncryptWorkerLane::Priority
    }
}

fn fmp_worker_queue_wait_stage_for_lane(lane: EncryptWorkerLane) -> crate::perf_profile::Stage {
    match lane {
        EncryptWorkerLane::Priority => crate::perf_profile::Stage::FmpWorkerPriorityQueueWait,
        EncryptWorkerLane::Bulk => crate::perf_profile::Stage::FmpWorkerBulkQueueWait,
    }
}

fn record_fmp_worker_queue_wait(
    lane: EncryptWorkerLane,
    queued_at: Option<crate::perf_profile::TraceStamp>,
) {
    crate::perf_profile::record_since(crate::perf_profile::Stage::FmpWorkerQueueWait, queued_at);
    crate::perf_profile::record_since(fmp_worker_queue_wait_stage_for_lane(lane), queued_at);
}

struct QueuedFmpSendJob {
    job: FmpSendJob,
    lane: EncryptWorkerLane,
    #[cfg(unix)]
    target_key: SendTargetKey,
    #[cfg(not(target_os = "macos"))]
    scheduling_weight: usize,
    #[cfg(not(target_os = "macos"))]
    fair_reservation: Option<FairAdmissionReservation>,
    #[cfg(target_os = "macos")]
    macos_flow: Option<Arc<MacSequencedSendFlow>>,
    #[cfg(target_os = "macos")]
    macos_seq: u64,
}

impl QueuedFmpSendJob {
    #[allow(dead_code)] // used on non-macOS and by tests; macOS production uses sequenced flows.
    fn direct(job: FmpSendJob) -> Self {
        let lane = encrypt_worker_lane_for_endpoint_data(job.bulk_endpoint_data);
        #[cfg(unix)]
        let target_key = job.send_target_key();
        #[cfg(not(target_os = "macos"))]
        let scheduling_weight = clamp_send_scheduling_weight(job.scheduling_weight);
        Self {
            job,
            lane,
            #[cfg(unix)]
            target_key,
            #[cfg(not(target_os = "macos"))]
            scheduling_weight,
            #[cfg(not(target_os = "macos"))]
            fair_reservation: None,
            #[cfg(target_os = "macos")]
            macos_flow: None,
            #[cfg(target_os = "macos")]
            macos_seq: 0,
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_sequenced(job: FmpSendJob, macos_flow: Arc<MacSequencedSendFlow>) -> Self {
        let macos_seq = macos_flow.reserve_seq();
        let lane = encrypt_worker_lane_for_endpoint_data(job.bulk_endpoint_data);
        let target_key = job.send_target_key();
        Self {
            job,
            lane,
            target_key,
            macos_flow: Some(macos_flow),
            macos_seq,
        }
    }

    #[cfg(unix)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn target_key(&self) -> SendTargetKey {
        self.target_key
    }

    #[cfg(not(target_os = "macos"))]
    fn flow_key(&self) -> SendTargetKey {
        self.target_key
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn queue_lane(&self) -> EncryptWorkerLane {
        self.lane
    }

    #[cfg(not(target_os = "macos"))]
    fn mark_fair_reserved(&mut self, reservation: FairAdmissionReservation) {
        self.fair_reservation = Some(reservation);
    }

    #[cfg(not(target_os = "macos"))]
    fn take_fair_reservation(&mut self) -> Option<FairAdmissionReservation> {
        self.fair_reservation.take()
    }

    #[cfg(not(target_os = "macos"))]
    fn scheduling_weight(&self) -> usize {
        self.scheduling_weight
    }
}

/// Handle to the encrypt worker pool. Dispatches jobs **hash-by-
/// send-target** across N worker tasks via per-worker bounded queues.
/// The bounded queue keeps bulk tunnel packets from growing without
/// bound when encryption/sending falls behind. Control traffic must not
/// sit behind that bulk backlog: blocking the rx_loop on a full send
/// queue also blocks decrypt-fallback/liveness processing, which can
/// turn a busy tunnel into a false link-dead removal.
///
/// **Ordering: hash-by-send-target, not round-robin.** Round-robin
/// across N workers causes UDP packet reordering on the wire, which
/// the receiving TCP layer reacts to with dup-ACK-triggered
/// fast-retransmits — measured in bench: 2 workers on a single-flow
/// TCP run dropped throughput 1308 → 1069 Mbps and pushed Retr count
/// from 0 to 8058. Hashing on the exact kernel send target keeps all
/// packets for one flow on one worker, preserving the FIFO order TCP
/// expects. Multi-peer / multi-flow benches still get the parallelism
/// since different send targets hash to different workers.
///
/// macOS defaults to the same hash-by-send-target shape unless explicitly
/// opted into the ordered sender. Live Wi-Fi sender tests showed the
/// worker-owned path beats the per-flow ordered sender handoff when the
/// Darwin UDP syscall/pacer path, not FMP AEAD, is the limiting stage.
/// Per-flow bounded bulk queue cap. Keep this shallower than wireguard-go's
/// 1024-slot outbound queue because this worker also has a 4x total Linux
/// bulk lane and a separate control reserve. A deeper queue hides a saturated
/// sender from TCP for tens of milliseconds, inflating RTT/retransmits instead
/// of pushing back to TUN promptly.
const DEFAULT_WORKER_CHANNEL_CAP: usize = 512;
// Keep the control/ACK-shaped reserve independent from synthetic bulk-pressure
// tests that deliberately shrink `FIPS_WORKER_CHANNEL_CAP`.
#[cfg(not(target_os = "macos"))]
const DEFAULT_WORKER_PRIORITY_CHANNEL_CAP: usize = 1024;
#[cfg(target_os = "macos")]
const MAC_WORKER_CONTROL_RESERVE_CAP: usize = 128;
#[cfg(not(target_os = "macos"))]
const WORKER_FAIR_QUANTUM_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const DEFAULT_WORKER_BATCH_SIZE: usize = 48;
#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
const DEFAULT_WORKER_BATCH_SIZE: usize = 32;
pub(crate) const DEFAULT_SEND_WEIGHT: u8 = 1;
pub(crate) const EXPLICIT_PEER_SEND_WEIGHT: u8 = 2;
#[cfg(not(target_os = "macos"))]
const MIN_SEND_WEIGHT: u8 = 1;
#[cfg(not(target_os = "macos"))]
const MAX_SEND_WEIGHT: u8 = 4;

#[cfg(not(target_os = "macos"))]
fn clamp_send_scheduling_weight(weight: u8) -> usize {
    weight.clamp(MIN_SEND_WEIGHT, MAX_SEND_WEIGHT) as usize
}

fn worker_channel_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let raw = std::env::var("FIPS_WORKER_CHANNEL_CAP").ok();
        parse_worker_channel_cap(raw.as_deref(), DEFAULT_WORKER_CHANNEL_CAP)
    })
}

#[cfg(not(target_os = "macos"))]
fn worker_priority_channel_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let raw = std::env::var("FIPS_ENCRYPT_WORKER_PRIORITY_CHANNEL_CAP").ok();
        parse_worker_channel_cap(raw.as_deref(), DEFAULT_WORKER_PRIORITY_CHANNEL_CAP)
    })
}

fn parse_worker_channel_cap(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(1, 32768)
}

#[cfg(not(target_os = "macos"))]
fn worker_batch_size() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let raw = std::env::var("FIPS_WORKER_BATCH").ok();
        parse_worker_batch_size(raw.as_deref(), DEFAULT_WORKER_BATCH_SIZE)
    })
}

#[cfg(not(target_os = "macos"))]
fn worker_fast_lane_cap(total_cap: usize, per_flow_cap: usize) -> usize {
    worker_batch_size()
        .min(per_flow_cap.max(1))
        .min(total_cap.max(1))
        .max(1)
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn parse_worker_batch_size(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(default)
        // Linux UDP_GSO submission in this module is capped at 64 iovecs.
        // Keep the worker drain cap aligned so a same-target group never asks
        // the GSO path to submit a prefix while accounting the whole group.
        .clamp(1, 64)
}

#[cfg(not(target_os = "macos"))]
type FairFlowMap =
    HashMap<SendTargetKey, FairFlowQueue, std::hash::BuildHasherDefault<SendTargetFastHasher>>;

#[cfg(not(target_os = "macos"))]
struct SendTargetFastHasher(u64);

#[cfg(not(target_os = "macos"))]
impl Default for SendTargetFastHasher {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

#[cfg(not(target_os = "macos"))]
impl std::hash::Hasher for SendTargetFastHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = 0u64;
            for (idx, byte) in chunk.iter().enumerate() {
                word |= u64::from(*byte) << (idx * 8);
            }
            self.write_u64(word);
        }
    }

    fn write_u8(&mut self, i: u8) {
        self.write_u64(u64::from(i));
    }

    fn write_u16(&mut self, i: u16) {
        self.write_u64(u64::from(i));
    }

    fn write_u32(&mut self, i: u32) {
        self.write_u64(u64::from(i));
    }

    fn write_u64(&mut self, i: u64) {
        self.0 ^= i.wrapping_add(0x9e37_79b9_7f4a_7c15);
        self.0 = self.0.rotate_left(27).wrapping_mul(0x94d0_49bb_1331_11eb);
    }

    fn write_u128(&mut self, i: u128) {
        self.write_u64(i as u64);
        self.write_u64((i >> 64) as u64);
    }
}

#[cfg(not(target_os = "macos"))]
fn send_target_fast_hash(target: &SendTargetKey) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = SendTargetFastHasher::default();
    target.hash(&mut hasher);
    hasher.finish()
}

#[cfg(target_os = "macos")]
struct MacWorkerSender {
    inner: Arc<MacWorkerQueueInner>,
}

#[cfg(target_os = "macos")]
struct MacWorkerReceiver {
    inner: Arc<MacWorkerQueueInner>,
}

#[cfg(target_os = "macos")]
struct MacWorkerQueueInner {
    state: Mutex<MacWorkerQueueState>,
    not_empty: Condvar,
    not_full: Condvar,
    cap: usize,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacWorkerQueueState {
    control_queue: VecDeque<QueuedFmpSendJob>,
    bulk_queue: VecDeque<QueuedFmpSendJob>,
    waiting: bool,
    closed: bool,
}

#[cfg(target_os = "macos")]
impl MacWorkerQueueState {
    fn len(&self) -> usize {
        self.control_queue.len() + self.bulk_queue.len()
    }

    fn is_empty(&self) -> bool {
        self.control_queue.is_empty() && self.bulk_queue.is_empty()
    }

    fn push_job(&mut self, job: QueuedFmpSendJob) {
        match job.queue_lane() {
            EncryptWorkerLane::Priority => self.control_queue.push_back(job),
            EncryptWorkerLane::Bulk => self.bulk_queue.push_back(job),
        }
    }

    fn pop_job(&mut self) -> Option<QueuedFmpSendJob> {
        self.control_queue
            .pop_front()
            .or_else(|| self.bulk_queue.pop_front())
    }
}

#[cfg(target_os = "macos")]
enum MacWorkerTryPushError {
    Full(Box<QueuedFmpSendJob>),
    Closed,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacWorkerPushError;

#[cfg(target_os = "macos")]
fn mac_worker_channel(cap: usize) -> (MacWorkerSender, MacWorkerReceiver) {
    let inner = Arc::new(MacWorkerQueueInner {
        state: Mutex::new(MacWorkerQueueState {
            control_queue: VecDeque::with_capacity(MAC_WORKER_CONTROL_RESERVE_CAP),
            bulk_queue: VecDeque::with_capacity(cap),
            waiting: false,
            closed: false,
        }),
        not_empty: Condvar::new(),
        not_full: Condvar::new(),
        cap,
    });
    (
        MacWorkerSender {
            inner: Arc::clone(&inner),
        },
        MacWorkerReceiver { inner },
    )
}

#[cfg(target_os = "macos")]
impl MacWorkerSender {
    fn try_push(&self, job: QueuedFmpSendJob) -> Result<(), MacWorkerTryPushError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        if state.closed {
            drop(job);
            return Err(MacWorkerTryPushError::Closed);
        }
        let cap = match job.queue_lane() {
            EncryptWorkerLane::Priority => self.inner.cap + MAC_WORKER_CONTROL_RESERVE_CAP,
            EncryptWorkerLane::Bulk => self.inner.cap,
        };
        if state.len() >= cap {
            return Err(MacWorkerTryPushError::Full(Box::new(job)));
        }
        let was_empty = state.is_empty();
        let should_notify = was_empty && state.waiting;
        state.push_job(job);
        drop(state);
        if should_notify {
            self.inner.not_empty.notify_one();
        }
        Ok(())
    }

    fn push_blocking(&self, job: QueuedFmpSendJob) -> Result<(), MacWorkerPushError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        loop {
            if state.closed {
                drop(job);
                return Err(MacWorkerPushError);
            }
            let cap = match job.queue_lane() {
                EncryptWorkerLane::Priority => self.inner.cap + MAC_WORKER_CONTROL_RESERVE_CAP,
                EncryptWorkerLane::Bulk => self.inner.cap,
            };
            if state.len() < cap {
                let was_empty = state.is_empty();
                let should_notify = was_empty && state.waiting;
                state.push_job(job);
                drop(state);
                if should_notify {
                    self.inner.not_empty.notify_one();
                }
                return Ok(());
            }
            state = self
                .inner
                .not_full
                .wait(state)
                .expect("encrypt worker queue poisoned");
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacWorkerSender {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        state.closed = true;
        drop(state);
        self.inner.not_empty.notify_all();
        self.inner.not_full.notify_all();
    }
}

#[cfg(target_os = "macos")]
impl MacWorkerReceiver {
    fn recv_batch(&self, batch: &mut Vec<QueuedFmpSendJob>, max: usize) -> bool {
        debug_assert!(batch.is_empty());
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        loop {
            while let Some(job) = state.pop_job() {
                batch.push(job);
                if batch.len() >= max {
                    break;
                }
            }
            if !batch.is_empty() {
                self.inner.not_full.notify_one();
                return true;
            }
            if state.closed {
                return false;
            }
            state.waiting = true;
            state = self
                .inner
                .not_empty
                .wait(state)
                .expect("encrypt worker queue poisoned");
            state.waiting = false;
        }
    }
}

#[cfg(not(target_os = "macos"))]
struct FairWorkerSender {
    priority_tx: Sender<QueuedFmpSendJob>,
    bulk_tx: Sender<QueuedFmpSendJob>,
    admission: Arc<FairAdmission>,
}

#[cfg(not(target_os = "macos"))]
struct FairWorkerReceiver {
    priority_rx: Receiver<QueuedFmpSendJob>,
    bulk_rx: Receiver<QueuedFmpSendJob>,
    admission: Arc<FairAdmission>,
}

#[cfg(not(target_os = "macos"))]
struct FairAdmission {
    state: Mutex<FairAdmissionState>,
    not_full: Condvar,
    total_cap: usize,
    per_flow_cap: usize,
    fast_lane_cap: usize,
}

#[cfg(not(target_os = "macos"))]
#[derive(Default)]
struct FairAdmissionState {
    flows: FairFlowMap,
    total_len: usize,
    full_waiters: usize,
    closed: bool,
}

#[cfg(not(target_os = "macos"))]
struct FairFlowQueue {
    queued: usize,
    weight: usize,
}

#[cfg(not(target_os = "macos"))]
impl FairFlowQueue {
    fn new(weight: usize) -> Self {
        Self { queued: 0, weight }
    }
}

#[cfg(not(target_os = "macos"))]
struct FairAdmissionReservation {
    key: SendTargetKey,
}

#[cfg(not(target_os = "macos"))]
impl FairAdmissionReservation {
    fn new(key: SendTargetKey) -> Self {
        Self { key }
    }

    fn key(&self) -> SendTargetKey {
        self.key
    }
}

#[cfg(not(target_os = "macos"))]
enum FairReserve {
    Reserved(FairAdmissionReservation),
    Full,
    Closed,
}

#[cfg(not(target_os = "macos"))]
enum FairWorkerTryPushError {
    Full(Box<QueuedFmpSendJob>),
    Closed,
}

#[cfg(not(target_os = "macos"))]
impl std::fmt::Debug for FairWorkerTryPushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(_) => f.write_str("Full"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

#[cfg(not(target_os = "macos"))]
struct FairWorkerPushError;

#[cfg(not(target_os = "macos"))]
fn fair_worker_channel(
    total_cap: usize,
    per_flow_cap: usize,
    quantum_bytes: usize,
) -> (FairWorkerSender, FairWorkerReceiver) {
    fair_worker_channel_with_priority_cap(
        total_cap,
        per_flow_cap,
        worker_priority_channel_cap(),
        quantum_bytes,
    )
}

#[cfg(not(target_os = "macos"))]
fn fair_worker_channel_with_priority_cap(
    total_cap: usize,
    per_flow_cap: usize,
    priority_cap: usize,
    _quantum_bytes: usize,
) -> (FairWorkerSender, FairWorkerReceiver) {
    let total_cap = total_cap.max(1);
    let per_flow_cap = per_flow_cap.max(1);
    let priority_cap = priority_cap.max(1);
    let (priority_tx, priority_rx) = bounded(priority_cap);
    let (bulk_tx, bulk_rx) = bounded(total_cap);
    let admission = Arc::new(FairAdmission {
        state: Mutex::new(FairAdmissionState::default()),
        not_full: Condvar::new(),
        total_cap,
        per_flow_cap,
        // Let a freshly idle worker accept one syscall-sized worker batch
        // without taking the fairness mutex, but don't let that mutex bypass
        // hide a whole extra per-flow queue window.
        fast_lane_cap: worker_fast_lane_cap(total_cap, per_flow_cap),
    });
    (
        FairWorkerSender {
            priority_tx,
            bulk_tx,
            admission: Arc::clone(&admission),
        },
        FairWorkerReceiver {
            priority_rx,
            bulk_rx,
            admission,
        },
    )
}

#[cfg(not(target_os = "macos"))]
impl FairWorkerSender {
    fn try_push(&self, job: QueuedFmpSendJob) -> Result<(), FairWorkerTryPushError> {
        if job.queue_lane() == EncryptWorkerLane::Priority {
            return match self.priority_tx.try_send(job) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(job)) => Err(FairWorkerTryPushError::Full(Box::new(job))),
                Err(TrySendError::Disconnected(job)) => {
                    drop(job);
                    Err(FairWorkerTryPushError::Closed)
                }
            };
        }

        let job = if self.admission.is_idle() && self.bulk_tx.len() < self.admission.fast_lane_cap {
            match self.bulk_tx.try_send(job) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(job)) => job,
                Err(TrySendError::Disconnected(job)) => {
                    drop(job);
                    return Err(FairWorkerTryPushError::Closed);
                }
            }
        } else {
            job
        };

        let key = job.flow_key();
        let weight = job.scheduling_weight();
        match self.admission.try_reserve(key, weight) {
            FairReserve::Reserved(reservation) => {
                let mut job = job;
                job.mark_fair_reserved(reservation);
                match self.bulk_tx.try_send(job) {
                    Ok(()) => Ok(()),
                    Err(TrySendError::Full(mut job)) => {
                        if let Some(reservation) = job.take_fair_reservation() {
                            self.admission.release(reservation);
                        }
                        Err(FairWorkerTryPushError::Full(Box::new(job)))
                    }
                    Err(TrySendError::Disconnected(mut job)) => {
                        if let Some(reservation) = job.take_fair_reservation() {
                            self.admission.release(reservation);
                        }
                        drop(job);
                        Err(FairWorkerTryPushError::Closed)
                    }
                }
            }
            FairReserve::Full => Err(FairWorkerTryPushError::Full(Box::new(job))),
            FairReserve::Closed => {
                drop(job);
                Err(FairWorkerTryPushError::Closed)
            }
        }
    }

    fn push_blocking(&self, job: QueuedFmpSendJob) -> Result<(), FairWorkerPushError> {
        if job.queue_lane() == EncryptWorkerLane::Priority {
            if let Err(SendError(job)) = self.priority_tx.send(job) {
                drop(job);
                return Err(FairWorkerPushError);
            }
            return Ok(());
        }
        let key = job.flow_key();
        let weight = job.scheduling_weight();
        let reservation = match self.admission.reserve_blocking(key, weight) {
            Ok(reservation) => reservation,
            Err(err) => {
                drop(job);
                return Err(err);
            }
        };
        let mut job = job;
        job.mark_fair_reserved(reservation);
        if let Err(SendError(mut job)) = self.bulk_tx.send(job) {
            if let Some(reservation) = job.take_fair_reservation() {
                self.admission.release(reservation);
            }
            drop(job);
            return Err(FairWorkerPushError);
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
impl FairAdmission {
    fn try_reserve(&self, key: SendTargetKey, weight: usize) -> FairReserve {
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        if state.closed {
            return FairReserve::Closed;
        }
        if Self::reserve_locked(&mut state, self.total_cap, self.per_flow_cap, key, weight) {
            return FairReserve::Reserved(FairAdmissionReservation::new(key));
        }
        FairReserve::Full
    }

    fn reserve_blocking(
        &self,
        key: SendTargetKey,
        weight: usize,
    ) -> Result<FairAdmissionReservation, FairWorkerPushError> {
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        loop {
            if state.closed {
                return Err(FairWorkerPushError);
            }
            if Self::reserve_locked(&mut state, self.total_cap, self.per_flow_cap, key, weight) {
                return Ok(FairAdmissionReservation::new(key));
            }
            state.full_waiters += 1;
            state = self
                .not_full
                .wait(state)
                .expect("encrypt worker fair admission poisoned");
            state.full_waiters = state.full_waiters.saturating_sub(1);
        }
    }

    fn is_idle(&self) -> bool {
        self.state
            .lock()
            .expect("encrypt worker fair admission poisoned")
            .total_len
            == 0
    }

    fn release(&self, reservation: FairAdmissionReservation) {
        let key = reservation.key();
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        if let Some(flow) = state.flows.get_mut(&key) {
            flow.queued = flow.queued.saturating_sub(1);
            if flow.queued == 0 {
                state.flows.remove(&key);
            }
        }
        state.total_len = state.total_len.saturating_sub(1);
        let should_notify = state.full_waiters > 0;
        drop(state);
        if should_notify {
            self.not_full.notify_all();
        }
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        state.closed = true;
        drop(state);
        self.not_full.notify_all();
    }

    fn reserve_locked(
        state: &mut FairAdmissionState,
        total_cap: usize,
        per_flow_cap: usize,
        key: SendTargetKey,
        weight: usize,
    ) -> bool {
        if state.total_len.saturating_add(1) > total_cap {
            return false;
        }
        let weight = weight.clamp(MIN_SEND_WEIGHT as usize, MAX_SEND_WEIGHT as usize);
        match state.flows.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let flow = entry.get_mut();
                flow.weight = flow.weight.max(weight);
                let cap = per_flow_cap
                    .saturating_mul(flow.weight)
                    .min(total_cap)
                    .max(1);
                if flow.queued.saturating_add(1) > cap {
                    return false;
                }
                flow.queued += 1;
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mut flow = FairFlowQueue::new(weight);
                flow.queued = 1;
                entry.insert(flow);
            }
        }
        state.total_len += 1;
        true
    }
}

#[cfg(not(target_os = "macos"))]
impl Drop for FairWorkerSender {
    fn drop(&mut self) {
        self.admission.close();
    }
}

#[cfg(not(target_os = "macos"))]
impl FairWorkerReceiver {
    fn recv_batch(&mut self, batch: &mut Vec<QueuedFmpSendJob>, max: usize) -> bool {
        debug_assert!(batch.is_empty());
        let Some(first) = self.recv_next_blocking() else {
            return false;
        };
        self.push_received(batch, first);
        while batch.len() < max {
            if let Ok(job) = self.priority_rx.try_recv() {
                self.push_received(batch, job);
                continue;
            }
            match self.bulk_rx.try_recv() {
                Ok(job) => self.push_received(batch, job),
                Err(_) => break,
            }
        }
        true
    }

    fn recv_next_blocking(&mut self) -> Option<QueuedFmpSendJob> {
        if let Ok(job) = self.priority_rx.try_recv() {
            return Some(job);
        }
        crossbeam_channel::select! {
            recv(self.priority_rx) -> msg => msg.ok().or_else(|| self.recv_bulk_blocking()),
            recv(self.bulk_rx) -> msg => msg.ok().or_else(|| self.priority_rx.recv().ok()),
        }
    }

    fn recv_bulk_blocking(&mut self) -> Option<QueuedFmpSendJob> {
        self.bulk_rx.recv().ok()
    }

    fn push_received(&self, batch: &mut Vec<QueuedFmpSendJob>, mut job: QueuedFmpSendJob) {
        if let Some(reservation) = job.take_fair_reservation() {
            self.admission.release(reservation);
        }
        batch.push(job);
    }
}

#[cfg(target_os = "macos")]
type WorkerSender = MacWorkerSender;

#[cfg(not(target_os = "macos"))]
type WorkerSender = FairWorkerSender;

/// Handle to the encrypt worker pool.
///
/// Workers are **dedicated `std::thread`s** with bounded queues between
/// them and the rx_loop. The earlier tokio-task version of this worker
/// pool was the right shape, but every cross-runtime
/// wake (rx_loop's tokio task → tokio worker task) costs the tokio
/// scheduler an internal hop. Replacing the worker side with a sync
/// OS thread cuts the dispatch round-trip to the platform minimum —
/// same pattern boringtun uses for its main loop.
///
/// **Ordering: hash-by-send-target** so single-flow TCP keeps its
/// FIFO ordering (round-robin caused 8000 retransmits in an earlier
/// experiment — see the git log for the 56e0ca8 fix). Multi-peer /
/// multi-flow benches still get parallelism since different
/// send targets hash to different workers.
#[derive(Clone)]
pub(crate) struct EncryptWorkerPool {
    senders: Arc<[WorkerSender]>,
    #[cfg(target_os = "macos")]
    macos_senders: Arc<MacSequencedSendFlows>,
    #[cfg(target_os = "macos")]
    next_worker: Arc<std::sync::atomic::AtomicUsize>,
}

impl EncryptWorkerPool {
    /// Spawn `n` worker **OS threads** and return a handle that
    /// dispatches jobs hash-by-send-target to them. The workers exit
    /// when all senders for their channel are dropped (i.e. when the
    /// returned `EncryptWorkerPool` and all clones go away).
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let worker_channel_cap = worker_channel_cap();
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            #[cfg(target_os = "macos")]
            {
                let (tx, rx) = mac_worker_channel(worker_channel_cap);
                std::thread::Builder::new()
                    .name(format!("fips-encrypt-{i}"))
                    .spawn(move || run_worker_macos(i, rx))
                    .expect("failed to spawn fips-encrypt OS thread");
                senders.push(tx);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let (tx, rx) = fair_worker_channel(
                    worker_channel_cap.saturating_mul(4).max(1),
                    worker_channel_cap,
                    WORKER_FAIR_QUANTUM_BYTES,
                );
                std::thread::Builder::new()
                    .name(format!("fips-encrypt-{i}"))
                    .spawn(move || run_worker(i, rx))
                    .expect("failed to spawn fips-encrypt OS thread");
                senders.push(tx);
            }
        }
        Self {
            senders: senders.into(),
            #[cfg(target_os = "macos")]
            macos_senders: Arc::new(MacSequencedSendFlows::default()),
            #[cfg(target_os = "macos")]
            next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Dispatch a job to the worker that owns its send-target flow.
    /// The hash is over `(socket fd, connected fd, dest_addr)` so every
    /// packet for one exact kernel send target lands on the same worker and
    /// stays in order — required for TCP's fast-retransmit logic above to
    /// behave on a single-flow run. Fire-and-forget — the worker
    /// handles send errors itself via stats counters.
    ///
    /// Uses `try_send` for the common uncontended case. Control/liveness jobs
    /// may still block if their reserve is exhausted, but a full bulk lane is
    /// treated like a congested network queue: drop the newly admitted bulk
    /// packet instead of blocking the node rx_loop that must keep ACKs,
    /// heartbeats, and route measurements moving.
    pub fn dispatch(&self, job: FmpSendJob) {
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping job");
            return;
        }
        let (idx, job) = self.prepare_dispatch(job);
        self.dispatch_to_worker(idx, job);
    }

    pub(crate) fn dispatch_bulk_batch(&self, jobs: Vec<FmpSendJob>) {
        for job in jobs {
            self.dispatch(job);
        }
    }

    #[cfg(target_os = "macos")]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        if !macos_ordered_sender_enabled() {
            use std::hash::{Hash, Hasher};

            let queued = QueuedFmpSendJob::direct(job);
            let key = queued.target_key();
            let mut h = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut h);
            let idx = (h.finish() as usize) % self.senders.len();
            return (idx, queued);
        }

        // Darwin has no sendmmsg/UDP_GSO equivalent in the standard UDP
        // path, and high-rate Wi-Fi sends regularly block in ENOBUFS. Keep
        // nonce assignment in rx_loop, spread FMP AEAD over the worker pool,
        // then serialize already-encrypted packets through one sender per
        // kernel 5-tuple. This mirrors wireguard-go's
        // route/nonce -> parallel encrypt -> sequential transmit shape.
        let flow = self.macos_senders.flow_for(&job);
        let ticket = self
            .next_worker
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            / macos_worker_stride();
        let idx = ticket % self.senders.len();
        (idx, QueuedFmpSendJob::macos_sequenced(job, flow))
    }

    #[cfg(not(target_os = "macos"))]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        let queued = QueuedFmpSendJob::direct(job);
        let idx = (send_target_fast_hash(&queued.flow_key()) as usize) % self.senders.len();
        (idx, queued)
    }

    #[cfg(target_os = "macos")]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        match self.senders[idx].try_push(job) {
            Ok(()) => {}
            Err(MacWorkerTryPushError::Full(job)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::EncryptWorkerQueueFull,
                );
                if job.queue_lane() == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                    return;
                }
                static FULL_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                if let Err(MacWorkerPushError) = self.senders[idx].push_blocking(*job) {
                    debug!(worker = idx, "EncryptWorker thread gone; dropping job");
                }
            }
            Err(MacWorkerTryPushError::Closed) => {
                debug!(worker = idx, "EncryptWorker thread gone; dropping job");
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        let sender = &self.senders[idx];
        match sender.try_push(job) {
            Ok(()) => {}
            Err(FairWorkerTryPushError::Full(job)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::EncryptWorkerQueueFull,
                );
                if job.queue_lane() == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                    return;
                }
                static FULL_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                if let Err(FairWorkerPushError) = sender.push_blocking(*job) {
                    debug!(worker = idx, "EncryptWorker thread gone; dropping job");
                }
            }
            Err(FairWorkerTryPushError::Closed) => {
                debug!(worker = idx, "EncryptWorker thread gone; dropping job");
            }
        }
    }
}

fn record_encrypt_worker_backpressure_drop(worker: usize) {
    crate::perf_profile::record_event(crate::perf_profile::Event::EncryptWorkerBulkDropped);
    static DROP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(100_000) {
        warn!(
            worker,
            drops = n + 1,
            "EncryptWorker channel full; dropping bulk data packet"
        );
    }
}

#[cfg(target_os = "macos")]
type MacSendFlowKey = SendTargetKey;

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacSequencedSendFlows {
    flows: Mutex<HashMap<MacSendFlowKey, Arc<MacSequencedSendFlow>>>,
    last_prune_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "macos")]
impl MacSequencedSendFlows {
    fn flow_for(&self, job: &FmpSendJob) -> Arc<MacSequencedSendFlow> {
        let now_ms = mac_now_ms();
        let key = job.send_target_key();

        let mut flows = self.flows.lock().expect("mac send flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = MacSequencedSendFlow::spawn(key, job.send_target.clone(), now_ms);
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    fn prune_idle_locked(
        &self,
        flows: &mut HashMap<MacSendFlowKey, Arc<MacSequencedSendFlow>>,
        now_ms: u64,
    ) {
        let last = self
            .last_prune_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 10_000 {
            return;
        }
        if self
            .last_prune_ms
            .compare_exchange(
                last,
                now_ms,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        let idle_ms = mac_send_flow_idle_ms();
        flows.retain(|_, flow| {
            if flow.is_idle(now_ms, idle_ms) {
                flow.close();
                false
            } else {
                true
            }
        });
    }
}

#[cfg(target_os = "macos")]
fn macos_ordered_sender_enabled() -> bool {
    // Ordered mode parallelizes one peer's FMP AEAD while preserving UDP order,
    // but the extra flow map + sender-thread handoff regressed the measured
    // MacBook Wi-Fi -> Ethernet path. Keep it opt-in for AEAD-bound comparisons;
    // the default keeps packets on the worker selected by send target.
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_ORDERED_SENDER")
            .ok()
            .map(|raw| {
                !matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(false)
    })
}

#[cfg(target_os = "macos")]
fn macos_worker_stride() -> usize {
    // One-packet round-robin maximizes FMP AEAD parallelism but wakes an idle
    // worker for nearly every packet on Darwin. Short strides let a hot worker
    // drain a local queue batch before the next worker is signalled, while still
    // spreading sustained single-peer traffic across the full pool.
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_WORKER_STRIDE")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "macos")]
fn macos_worker_batch_size() -> usize {
    // The direct Darwin sender has no sendmmsg/GSO equivalent, so a large
    // worker-drain batch becomes a tight burst of send/sendto calls. MacBook
    // Wi-Fi -> Ethernet tests showed the previous default of 32 could trigger
    // TCP collapse and long queue waits even when Darwin did not report
    // ENOBUFS. A smaller default keeps the kernel/radio pacer in the loop
    // without waking the worker for every datagram; keep this runtime-tunable
    // for LAN/NIC-specific A/B tests.
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_WORKER_BATCH")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(8)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "macos")]
fn mac_send_flow_idle_ms() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_SEND_FLOW_IDLE_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(120_000)
            .max(10_000)
    })
}

#[cfg(target_os = "macos")]
fn mac_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
struct MacSequencedSendFlow {
    key: MacSendFlowKey,
    send_target: SelectedSendTarget,
    next_seq: std::sync::atomic::AtomicU64,
    last_used_ms: std::sync::atomic::AtomicU64,
    state: Mutex<MacSendFlowState>,
    ready_cv: Condvar,
    space_cv: Condvar,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacSendFlowState {
    next_send_seq: u64,
    pending: BTreeMap<u64, MacSendItem>,
    closed: bool,
}

#[cfg(target_os = "macos")]
struct MacCompletionGroup {
    flow_key: MacSendFlowKey,
    flow: Arc<MacSequencedSendFlow>,
    items: Vec<(u64, MacSendItem)>,
}

#[cfg(target_os = "macos")]
enum MacSendItem {
    Packet {
        packet: Vec<u8>,
        drop_on_backpressure: bool,
    },
    Skip,
}

#[cfg(target_os = "macos")]
impl MacCompletionGroup {
    fn new(flow: Arc<MacSequencedSendFlow>, seq: u64, item: MacSendItem) -> Self {
        let flow_key = flow.key;
        Self {
            flow_key,
            flow,
            items: vec![(seq, item)],
        }
    }

    #[cfg(test)]
    fn target_key(&self) -> MacSendFlowKey {
        self.flow_key
    }

    fn push(&mut self, flow: &Arc<MacSequencedSendFlow>, seq: u64, item: MacSendItem) {
        debug_assert_eq!(
            self.flow_key, flow.key,
            "macOS completion group must keep the queued flow key"
        );
        debug_assert!(
            Arc::ptr_eq(&self.flow, flow),
            "macOS completion group must not merge a different flow owner"
        );
        self.items.push((seq, item));
    }

    fn complete(self) {
        self.flow.complete_many(self.items);
    }
}

#[cfg(target_os = "macos")]
impl MacSequencedSendFlow {
    fn spawn(key: MacSendFlowKey, send_target: SelectedSendTarget, now_ms: u64) -> Arc<Self> {
        let flow = Arc::new(Self {
            key,
            send_target,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(now_ms),
            state: Mutex::new(MacSendFlowState::default()),
            ready_cv: Condvar::new(),
            space_cv: Condvar::new(),
        });
        let thread_flow = Arc::clone(&flow);
        std::thread::Builder::new()
            .name(format!("fips-mac-send-{}", key.socket_fd))
            .spawn(move || thread_flow.run())
            .expect("failed to spawn fips macOS send thread");
        flow
    }

    fn reserve_seq(&self) -> u64 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn mark_used(&self, now_ms: u64) {
        self.last_used_ms
            .store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        let last_used = self.last_used_ms.load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last_used) < idle_ms {
            return false;
        }

        let state = self.state.lock().expect("mac send flow state poisoned");
        state.pending.is_empty()
            && state.next_send_seq == self.next_seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("mac send flow state poisoned");
        state.closed = true;
        drop(state);
        self.ready_cv.notify_one();
        self.space_cv.notify_all();
    }

    fn complete_many(&self, items: Vec<(u64, MacSendItem)>) {
        const PENDING_CAP: usize = 4096;
        if items.is_empty() {
            return;
        }

        let mut state = self.state.lock().expect("mac send flow state poisoned");
        if state.closed {
            return;
        }
        let mut wakes_sender = false;
        for (seq, item) in items {
            while state.pending.len() >= PENDING_CAP && seq != state.next_send_seq && !wakes_sender
            {
                state = self
                    .space_cv
                    .wait(state)
                    .expect("mac send flow state poisoned");
            }
            if seq == state.next_send_seq {
                wakes_sender = true;
            }
            state.pending.insert(seq, item);
        }
        drop(state);
        if wakes_sender {
            self.ready_cv.notify_one();
        }
    }

    fn run(self: Arc<Self>) {
        trace!(
            socket_fd = self.key.socket_fd,
            connected_fd = ?self.key.connected_fd,
            dest = %self.send_target.dest_addr(),
            "macOS ordered UDP sender starting"
        );
        let (fd, connected) = self.send_target.fd_and_connected();
        let mut backpressure = SendBackpressurePacer::default();
        let mut rate_pacer = MacSendRatePacer::default();

        loop {
            let item = {
                let mut state = self.state.lock().expect("mac send flow state poisoned");
                loop {
                    let next = state.next_send_seq;
                    if let Some(item) = state.pending.remove(&next) {
                        state.next_send_seq = next.wrapping_add(1);
                        self.space_cv.notify_one();
                        break item;
                    }
                    if state.closed {
                        return;
                    }
                    state = self
                        .ready_cv
                        .wait(state)
                        .expect("mac send flow state poisoned");
                }
            };

            match item {
                MacSendItem::Packet {
                    packet,
                    drop_on_backpressure,
                } => {
                    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
                    rate_pacer.pace(packet.len());
                    if let Err(err) = send_one_with_backpressure(
                        fd,
                        connected,
                        &self.send_target.dest_addr(),
                        &packet,
                        &mut backpressure,
                        drop_on_backpressure,
                    ) {
                        debug!(
                            socket_fd = self.key.socket_fd,
                            connected_fd = ?self.key.connected_fd,
                            dest = %self.send_target.dest_addr(),
                            error = %err,
                            "macOS ordered UDP send failed"
                        );
                    }
                }
                MacSendItem::Skip => {}
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn push_mac_completion(
    groups: &mut Vec<MacCompletionGroup>,
    flow: Arc<MacSequencedSendFlow>,
    seq: u64,
    item: MacSendItem,
) {
    if let Some(group) = groups
        .iter_mut()
        .find(|group| Arc::ptr_eq(&group.flow, &flow))
    {
        group.push(&flow, seq, item);
    } else {
        groups.push(MacCompletionGroup::new(flow, seq, item));
    }
}

struct EncryptWorkerShard {
    idx: usize,
    batch: Vec<QueuedFmpSendJob>,
    max_batch: usize,
}

impl EncryptWorkerShard {
    fn new(idx: usize, max_batch: usize) -> Self {
        Self {
            idx,
            batch: Vec::with_capacity(max_batch),
            max_batch,
        }
    }

    fn drain_and_flush_once<R, F>(&mut self, recv_batch: R, flush_batch: F) -> bool
    where
        R: FnOnce(&mut Vec<QueuedFmpSendJob>, usize) -> bool,
        F: FnOnce(
            &mut Vec<QueuedFmpSendJob>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    {
        debug_assert!(self.batch.is_empty());
        if !recv_batch(&mut self.batch, self.max_batch) {
            return false;
        }
        prioritize_worker_batch(&mut self.batch);
        let (priority_packets, bulk_packets) = worker_batch_lane_counts(&self.batch);
        crate::perf_profile::record_fmp_worker_batch(
            self.batch.len(),
            priority_packets,
            bulk_packets,
            self.max_batch,
        );
        if let Err(err) = flush_batch(&mut self.batch) {
            debug!(
                worker = self.idx,
                error = %err,
                "FMP encrypt worker batch flush failed"
            );
            self.batch.clear();
        }
        true
    }

    #[cfg(test)]
    fn batch_len(&self) -> usize {
        self.batch.len()
    }
}

fn worker_batch_lane_counts(batch: &[QueuedFmpSendJob]) -> (usize, usize) {
    let mut priority_packets = 0usize;
    let mut bulk_packets = 0usize;
    for job in batch {
        match job.queue_lane() {
            EncryptWorkerLane::Priority => priority_packets += 1,
            EncryptWorkerLane::Bulk => bulk_packets += 1,
        }
    }
    (priority_packets, bulk_packets)
}

fn prioritize_worker_batch(batch: &mut [QueuedFmpSendJob]) {
    let mut saw_bulk = false;
    let mut priority_behind_bulk = false;
    for job in batch.iter() {
        match job.queue_lane() {
            EncryptWorkerLane::Priority if saw_bulk => {
                priority_behind_bulk = true;
                break;
            }
            EncryptWorkerLane::Bulk => saw_bulk = true,
            EncryptWorkerLane::Priority => {}
        }
    }
    if priority_behind_bulk {
        batch.sort_by_key(|job| match job.queue_lane() {
            EncryptWorkerLane::Priority => 0u8,
            EncryptWorkerLane::Bulk => 1u8,
        });
    }
}

struct SealedSendPacket {
    send_target: SelectedSendTarget,
    #[cfg(unix)]
    target_key: SendTargetKey,
    wire_packet: Vec<u8>,
    drop_on_backpressure: bool,
}

impl SealedSendPacket {
    #[cfg(any(test, not(unix)))]
    fn from_job(job: FmpSendJob) -> Result<Self, SealPacketError> {
        #[cfg(unix)]
        let target_key = job.send_target_key();
        #[cfg(unix)]
        return Self::from_job_with_target_key(job, target_key);

        #[cfg(not(unix))]
        return Self::from_job_without_target_key(job);
    }

    #[cfg(all(unix, any(test, not(target_os = "macos"))))]
    fn from_queued(queued: QueuedFmpSendJob) -> Result<Self, SealPacketError> {
        let QueuedFmpSendJob {
            job, target_key, ..
        } = queued;
        Self::from_job_with_target_key(job, target_key)
    }

    #[cfg(unix)]
    fn from_job_with_target_key(
        job: FmpSendJob,
        target_key: SendTargetKey,
    ) -> Result<Self, SealPacketError> {
        Self::from_job_inner(job, target_key)
    }

    #[cfg(not(unix))]
    fn from_job_without_target_key(job: FmpSendJob) -> Result<Self, SealPacketError> {
        Self::from_job_inner(job)
    }

    #[cfg(unix)]
    fn from_job_inner(job: FmpSendJob, target_key: SendTargetKey) -> Result<Self, SealPacketError> {
        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            fsp_seal,
            send_target,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight: _,
            queued_at,
        } = job;
        debug_assert_eq!(
            send_target.key(),
            target_key,
            "sealed packet must keep the queued target key"
        );
        record_fmp_worker_queue_wait(
            encrypt_worker_lane_for_endpoint_data(bulk_endpoint_data),
            queued_at,
        );

        Self::seal_wire_packet(cipher, counter, &mut wire_buf, fsp_seal)?;

        Ok(Self {
            send_target,
            #[cfg(unix)]
            target_key,
            wire_packet: wire_buf,
            drop_on_backpressure,
        })
    }

    #[cfg(not(unix))]
    fn from_job_inner(job: FmpSendJob) -> Result<Self, SealPacketError> {
        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            fsp_seal,
            send_target,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight: _,
            queued_at,
        } = job;
        record_fmp_worker_queue_wait(
            encrypt_worker_lane_for_endpoint_data(bulk_endpoint_data),
            queued_at,
        );

        Self::seal_wire_packet(cipher, counter, &mut wire_buf, fsp_seal)?;

        Ok(Self {
            send_target,
            wire_packet: wire_buf,
            drop_on_backpressure,
        })
    }

    fn seal_wire_packet(
        cipher: LessSafeKey,
        counter: u64,
        wire_buf: &mut Vec<u8>,
        fsp_seal: Option<FspSealJob>,
    ) -> Result<(), SealPacketError> {
        if let Some(fsp) = fsp_seal {
            if fsp.aad_offset + FSP_HEADER_SIZE > fsp.plaintext_offset
                || fsp.plaintext_offset > wire_buf.len()
            {
                return Err(SealPacketError::InvalidFspLayout);
            }

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..12].copy_from_slice(&fsp.counter.to_le_bytes());
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let (prefix, plaintext_slice) = wire_buf.split_at_mut(fsp.plaintext_offset);
            let aad = &prefix[fsp.aad_offset..fsp.aad_offset + FSP_HEADER_SIZE];
            let tag = fsp
                .cipher
                .seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext_slice)
                .map_err(|_| SealPacketError::FspSeal)?;
            wire_buf.extend_from_slice(tag.as_ref());
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        // Split-borrow: AAD reads from header bytes [0..16], seal writes into
        // the plaintext slice [16..].
        let (header_slice, plaintext_slice) = wire_buf.split_at_mut(ESTABLISHED_HEADER_SIZE);
        let tag = cipher
            .seal_in_place_separate_tag(nonce, Aad::from(&*header_slice), plaintext_slice)
            .map_err(|_| SealPacketError::FmpSeal)?;
        // wire_buf already has `+16` capacity reserved -> no realloc.
        wire_buf.extend_from_slice(tag.as_ref());
        Ok(())
    }

    #[cfg(unix)]
    fn into_parts(self) -> (SelectedSendTarget, SendTargetKey, Vec<u8>, bool) {
        (
            self.send_target,
            self.target_key,
            self.wire_packet,
            self.drop_on_backpressure,
        )
    }

    #[cfg(not(unix))]
    fn into_parts(self) -> (SelectedSendTarget, Vec<u8>, bool) {
        (
            self.send_target,
            self.wire_packet,
            self.drop_on_backpressure,
        )
    }

    #[cfg(all(test, unix))]
    fn target_key(&self) -> SendTargetKey {
        self.target_key
    }

    #[cfg(test)]
    fn wire_packet(&self) -> &[u8] {
        &self.wire_packet
    }

    #[cfg(test)]
    fn drop_on_backpressure(&self) -> bool {
        self.drop_on_backpressure
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealPacketError {
    InvalidFspLayout,
    FspSeal,
    FmpSeal,
}

/// Sync OS-thread worker loop. Blocks on the bounded fair queue,
/// drains follow-on packets into a fixed-size local batch, then issues
/// one `sendmmsg(2)` per drain cycle.
#[cfg(not(target_os = "macos"))]
fn run_worker(idx: usize, mut rx: FairWorkerReceiver) {
    trace!(worker = idx, "FMP encrypt worker thread starting");

    let mut shard = EncryptWorkerShard::new(idx, worker_batch_size());

    while shard.drain_and_flush_once(|batch, max| rx.recv_batch(batch, max), flush_batch_sync) {}
    trace!(worker = idx, "FMP encrypt worker thread exiting");
}

#[cfg(target_os = "macos")]
fn run_worker_macos(idx: usize, rx: MacWorkerReceiver) {
    trace!(worker = idx, "FMP encrypt worker thread starting");

    let batch_size = macos_worker_batch_size();
    let mut shard = EncryptWorkerShard::new(idx, batch_size);

    while shard.drain_and_flush_once(|batch, max| rx.recv_batch(batch, max), flush_batch_sync) {}
    trace!(worker = idx, "FMP encrypt worker thread exiting");
}

/// Encrypt every job in `batch` in place, then issue one or more
/// bulk-send syscalls grouped **by exact send target**. Clears
/// `batch` on return. Sync version — operates directly on the raw
/// nonblocking UDP fd with a retry-on-EAGAIN loop; no tokio reactor.
///
/// **Why grouping is required:** `EncryptWorkerPool::dispatch` hashes
/// the exact send target modulo the worker count to pick a worker — this
/// pins one peer's flow to one worker (FIFO order preserved for TCP), but
/// it does NOT mean every job in a worker's drained batch shares a target.
/// Two different peers can hash to the same worker. The previous
/// implementation cloned `batch[0].socket` /
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
    batch: &mut Vec<QueuedFmpSendJob>,
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
    let mut groups: Vec<SelectedSendBatch> = Vec::with_capacity(1);
    #[cfg(target_os = "macos")]
    let mut macos_completions: Vec<MacCompletionGroup> = Vec::with_capacity(1);

    for queued in batch.drain(..) {
        #[cfg(target_os = "macos")]
        let QueuedFmpSendJob {
            job,
            target_key,
            macos_flow,
            macos_seq,
            ..
        } = queued;

        #[cfg(target_os = "macos")]
        let sealed_result = SealedSendPacket::from_job_with_target_key(job, target_key);
        #[cfg(all(unix, not(target_os = "macos")))]
        let sealed_result = SealedSendPacket::from_queued(queued);
        #[cfg(not(unix))]
        let sealed_result = {
            let QueuedFmpSendJob { job, .. } = queued;
            SealedSendPacket::from_job(job)
        };

        let sealed = match sealed_result {
            Ok(sealed) => sealed,
            Err(_) => {
                #[cfg(target_os = "macos")]
                if let Some(flow) = macos_flow.as_ref() {
                    push_mac_completion(
                        &mut macos_completions,
                        Arc::clone(flow),
                        macos_seq,
                        MacSendItem::Skip,
                    );
                }
                continue;
            }
        };

        #[cfg(target_os = "macos")]
        if let Some(flow) = macos_flow {
            let (_send_target, _target_key, wire_packet, drop_on_backpressure) =
                sealed.into_parts();
            push_mac_completion(
                &mut macos_completions,
                flow,
                macos_seq,
                MacSendItem::Packet {
                    packet: wire_packet,
                    drop_on_backpressure,
                },
            );
            continue;
        }

        #[cfg(unix)]
        {
            let (send_target, target_key, wire_packet, drop_on_backpressure) = sealed.into_parts();
            push_selected_send_batch(
                &mut groups,
                send_target,
                target_key,
                wire_packet,
                drop_on_backpressure,
            );
        }
        #[cfg(not(unix))]
        {
            // Windows: encrypt worker pool isn't spawned (see
            // lifecycle.rs); this function is unreachable. Drop
            // values explicitly so the compiler sees them as used.
            let _ = sealed;
        }
    }

    #[cfg(target_os = "macos")]
    for group in macos_completions {
        group.complete();
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
        let mut send_attempt = LinuxSendBatchAttempt::from_batch(group);
        let (fd, connected, dest_addr) = send_attempt.target_parts();

        // Within a group, destination is uniform by construction —
        // GSO needs only the size check now.
        if !GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed)
            && gso_eligible_sizes(send_attempt.packets())
        {
            match send_batch_gso(fd, send_attempt.packets(), dest_addr, connected) {
                Ok(()) => {
                    send_attempt.mark_all_sent();
                    continue;
                }
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
                Err(err) if is_send_backpressure(&err) => {
                    // Send buffer full mid-GSO — fall through to
                    // sendmmsg retry loop. No GSO_DISABLED toggle.
                }
                Err(err) => {
                    return Err(format!("sendmsg+UDP_GSO failed: {err}").into());
                }
            }
        }

        while !send_attempt.is_complete() {
            let n = match send_batch_raw(fd, send_attempt.remaining_packets(), dest_addr, connected)
            {
                Ok(n) => n,
                Err(err) if is_send_backpressure(&err) => {
                    send_attempt.handle_backpressure(&err);
                    continue;
                }
                Err(err) => {
                    return Err(format!("sendmmsg(2) failed: {err}").into());
                }
            };
            if n == 0 {
                break;
            }
            send_attempt.mark_sent(n);
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    for group in groups {
        let send_attempt = DirectSendBatchAttempt::from_batch(group);
        if let Err(err) = flush_direct_send_attempt(send_attempt) {
            return Err(format!("sendto failed: {err}").into());
        }
    }
    // Windows: encrypt worker pool isn't spawned at all (see
    // lifecycle.rs), so this function is never reached. The
    // tokio-backed `AsyncUdpSocket::send_to` path on the rx_loop
    // remains the only outbound path on that platform.
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn flush_direct_send_attempt(mut send_attempt: DirectSendBatchAttempt) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        MAC_DIRECT_SEND_RATE_PACER.with(|pacer| {
            let mut rate_pacer = pacer.borrow_mut();
            while let Some(len) = send_attempt.current_packet_len() {
                rate_pacer.pace(len);
                send_attempt.send_current()?;
            }
            Ok(())
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        while !send_attempt.is_complete() {
            send_attempt.send_current()?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
fn flush_direct_batch_sync(
    batch: &mut Vec<FmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut queued: Vec<QueuedFmpSendJob> = batch.drain(..).map(QueuedFmpSendJob::direct).collect();
    flush_batch_sync(&mut queued)
}

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
struct MacSendRatePacer {
    bytes_per_sec: f64,
    burst_bytes: f64,
    credit_bytes: f64,
    last: std::time::Instant,
}

#[cfg(target_os = "macos")]
impl Default for MacSendRatePacer {
    fn default() -> Self {
        // Default-on for Darwin's direct sender: without sendmmsg/GSO, tight
        // send bursts can wedge Wi-Fi/utun queues while the daemon is mostly
        // idle. Keep the rate above typical Tailscale-over-LAN throughput, and
        // leave FIPS_MACOS_SEND_PACE_MBPS=0 as the lab opt-out.
        let mbps = std::env::var("FIPS_MACOS_SEND_PACE_MBPS")
            .ok()
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .unwrap_or(350.0);
        let bytes_per_sec = if mbps.is_finite() && mbps > 0.0 {
            mbps * 1_000_000.0 / 8.0
        } else {
            0.0
        };
        let burst_bytes = std::env::var("FIPS_MACOS_SEND_PACE_BURST_BYTES")
            .ok()
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value > 0.0)
            .unwrap_or(256.0 * 1024.0);
        Self {
            bytes_per_sec,
            burst_bytes,
            credit_bytes: burst_bytes,
            last: std::time::Instant::now(),
        }
    }
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

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use crate::transport::udp::socket::UdpRawSocket;
    use ring::aead::{LessSafeKey, UnboundKey};
    use std::net::UdpSocket;

    fn test_cipher(byte: u8) -> LessSafeKey {
        let key_bytes = [byte; 32];
        let unbound =
            UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).expect("build key");
        LessSafeKey::new(unbound)
    }

    fn queued_test_job_classified(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
        bulk_endpoint_data: bool,
    ) -> QueuedFmpSendJob {
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + payload_len + 16);
        wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + payload_len, 0);
        QueuedFmpSendJob::direct(FmpSendJob {
            cipher: cipher.clone(),
            counter: 0,
            wire_buf,
            fsp_seal: None,
            send_target: SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_addr,
            ),
            bulk_endpoint_data,
            drop_on_backpressure: bulk_endpoint_data,
            scheduling_weight: DEFAULT_SEND_WEIGHT,
            queued_at: None,
        })
    }

    fn queued_test_job(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
    ) -> QueuedFmpSendJob {
        queued_test_job_classified(socket, cipher, dest_addr, payload_len, true)
    }

    #[test]
    fn encrypt_worker_shard_owns_batch_drain_and_flush_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(3);
            let dest: SocketAddr = "127.0.0.1:10034".parse().unwrap();
            let mut shard = EncryptWorkerShard::new(7, 2);
            let mut recv_max = 0;
            let mut flush_count = 0;

            assert!(shard.drain_and_flush_once(
                |batch, max| {
                    recv_max = max;
                    assert!(batch.is_empty());
                    batch.push(queued_test_job(socket.clone(), &cipher, dest, 32));
                    batch.push(queued_test_job(socket.clone(), &cipher, dest, 48));
                    true
                },
                |batch| {
                    flush_count += 1;
                    assert_eq!(batch.len(), 2);
                    Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "forced flush failure",
                    ))
                        as Box<dyn std::error::Error + Send + Sync>)
                },
            ));
            assert_eq!(recv_max, 2);
            assert_eq!(flush_count, 1);
            assert_eq!(
                shard.batch_len(),
                0,
                "the shard owns and clears the local batch after flush failure"
            );

            assert!(!shard.drain_and_flush_once(
                |batch, max| {
                    assert_eq!(max, 2);
                    assert!(batch.is_empty());
                    false
                },
                |_batch| panic!("flush must not run when receive returns closed"),
            ));
        });
    }

    #[test]
    fn encrypt_worker_shard_prioritizes_local_batch_without_reordering_lanes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(7);
            let dest: SocketAddr = "127.0.0.1:10035".parse().unwrap();
            let mut shard = EncryptWorkerShard::new(3, 4);

            assert!(shard.drain_and_flush_once(
                |batch, _max| {
                    batch.push(queued_test_job_classified(
                        socket.clone(),
                        &cipher,
                        dest,
                        101,
                        true,
                    ));
                    batch.push(queued_test_job_classified(
                        socket.clone(),
                        &cipher,
                        dest,
                        11,
                        false,
                    ));
                    batch.push(queued_test_job_classified(
                        socket.clone(),
                        &cipher,
                        dest,
                        102,
                        true,
                    ));
                    batch.push(queued_test_job_classified(socket, &cipher, dest, 12, false));
                    true
                },
                |batch| {
                    let lanes: Vec<_> = batch.iter().map(QueuedFmpSendJob::queue_lane).collect();
                    assert_eq!(
                        lanes,
                        vec![
                            EncryptWorkerLane::Priority,
                            EncryptWorkerLane::Priority,
                            EncryptWorkerLane::Bulk,
                            EncryptWorkerLane::Bulk,
                        ],
                        "priority work should not sit behind bulk inside a worker-owned batch"
                    );
                    let payload_lens: Vec<_> = batch
                        .iter()
                        .map(|job| job.job.wire_buf.len() - ESTABLISHED_HEADER_SIZE)
                        .collect();
                    assert_eq!(
                        payload_lens,
                        vec![11, 12, 101, 102],
                        "stable lane ordering must preserve FIFO within priority and bulk lanes"
                    );
                    assert_eq!(
                        worker_batch_lane_counts(batch),
                        (2, 2),
                        "FMP worker batch telemetry should preserve priority/bulk mix"
                    );
                    batch.clear();
                    Ok(())
                },
            ));
        });
    }

    #[test]
    fn sealed_send_packet_owns_target_wire_and_drop_policy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(4);
            let counter = 44;
            let dest: SocketAddr = "127.0.0.1:10035".parse().unwrap();
            let target = SelectedSendTarget::new(
                socket.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let target_key = target.key();
            let header = [0x42; ESTABLISHED_HEADER_SIZE];
            let plaintext = b"sealed owner packet";
            let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + plaintext.len() + 16);
            wire_buf.extend_from_slice(&header);
            wire_buf.extend_from_slice(plaintext);

            let sealed = SealedSendPacket::from_job(FmpSendJob {
                cipher: cipher.clone(),
                counter,
                wire_buf,
                fsp_seal: None,
                send_target: target,
                bulk_endpoint_data: true,
                drop_on_backpressure: false,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            })
            .expect("seal packet");

            assert_eq!(sealed.target_key(), target_key);
            assert!(
                !sealed.drop_on_backpressure(),
                "the sealed packet owns the original drop policy"
            );
            assert_eq!(
                sealed.wire_packet().len(),
                ESTABLISHED_HEADER_SIZE + plaintext.len() + crate::noise::TAG_SIZE
            );
            assert_eq!(&sealed.wire_packet()[..ESTABLISHED_HEADER_SIZE], &header);
            let opened = crate::noise::open(
                Some(&cipher),
                counter,
                &header,
                &sealed.wire_packet()[ESTABLISHED_HEADER_SIZE..],
            )
            .expect("open sealed packet");
            assert_eq!(opened, plaintext);

            let invalid_target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let invalid = SealedSendPacket::from_job(FmpSendJob {
                cipher,
                counter: counter + 1,
                wire_buf: vec![0; ESTABLISHED_HEADER_SIZE + 8],
                fsp_seal: Some(FspSealJob {
                    cipher: test_cipher(5),
                    counter: 1,
                    aad_offset: ESTABLISHED_HEADER_SIZE,
                    plaintext_offset: ESTABLISHED_HEADER_SIZE,
                }),
                send_target: invalid_target,
                bulk_endpoint_data: true,
                drop_on_backpressure: true,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            });
            assert!(matches!(invalid, Err(SealPacketError::InvalidFspLayout)));
        });
    }

    #[test]
    fn encrypt_worker_lane_policy_keeps_endpoint_bulk_explicit() {
        assert_eq!(
            encrypt_worker_lane_for_endpoint_data(false),
            EncryptWorkerLane::Priority
        );
        assert_eq!(
            encrypt_worker_lane_for_endpoint_data(true),
            EncryptWorkerLane::Bulk
        );
    }

    #[test]
    fn encrypt_worker_queue_wait_stage_follows_lane_policy() {
        assert_eq!(
            fmp_worker_queue_wait_stage_for_lane(EncryptWorkerLane::Priority),
            crate::perf_profile::Stage::FmpWorkerPriorityQueueWait
        );
        assert_eq!(
            fmp_worker_queue_wait_stage_for_lane(EncryptWorkerLane::Bulk),
            crate::perf_profile::Stage::FmpWorkerBulkQueueWait
        );
    }

    #[test]
    fn worker_batch_size_parse_stays_within_sender_accounting_limit() {
        assert_eq!(parse_worker_batch_size(Some("0"), 32), 1);
        assert_eq!(parse_worker_batch_size(Some("999"), 32), 64);
        assert_eq!(parse_worker_batch_size(Some("17"), 32), 17);
        assert_eq!(
            parse_worker_batch_size(Some("not-a-number"), 31),
            31,
            "invalid env values should keep the supplied platform default"
        );
    }

    #[test]
    fn worker_bulk_channel_default_is_latency_bounded() {
        assert_eq!(
            parse_worker_channel_cap(None, DEFAULT_WORKER_CHANNEL_CAP),
            512
        );
        assert_eq!(
            parse_worker_channel_cap(Some("not-a-number"), DEFAULT_WORKER_CHANNEL_CAP),
            512,
            "invalid env values should keep the tuned default"
        );
        assert_eq!(
            parse_worker_channel_cap(Some("0"), DEFAULT_WORKER_CHANNEL_CAP),
            1
        );
        assert_eq!(
            parse_worker_channel_cap(Some("999999"), DEFAULT_WORKER_CHANNEL_CAP),
            32768
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            parse_worker_channel_cap(None, DEFAULT_WORKER_PRIORITY_CHANNEL_CAP),
            1024,
            "control reserve must remain independent from bulk queue tuning"
        );
    }

    #[test]
    fn queued_fmp_send_job_owns_lane_and_target_key() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(6);
            let dest: SocketAddr = "127.0.0.1:10036".parse().unwrap();

            fn make_job(
                socket: AsyncUdpSocket,
                cipher: LessSafeKey,
                dest: SocketAddr,
                bulk_endpoint_data: bool,
            ) -> FmpSendJob {
                let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + 32 + 16);
                wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
                wire_buf.resize(ESTABLISHED_HEADER_SIZE + 32, 0);
                FmpSendJob {
                    cipher,
                    counter: 7,
                    wire_buf,
                    fsp_seal: None,
                    send_target: SelectedSendTarget::new(
                        socket,
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        None,
                        dest,
                    ),
                    bulk_endpoint_data,
                    drop_on_backpressure: bulk_endpoint_data,
                    scheduling_weight: DEFAULT_SEND_WEIGHT,
                    queued_at: None,
                }
            }

            let priority_target = SelectedSendTarget::new(
                socket.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let priority_key = priority_target.key();
            let mut priority_job = make_job(socket.clone(), cipher.clone(), dest, false);
            priority_job.send_target = priority_target;
            let priority = QueuedFmpSendJob::direct(priority_job);
            assert_eq!(priority.queue_lane(), EncryptWorkerLane::Priority);
            assert_eq!(
                priority.target_key(),
                priority_key,
                "queued worker messages own the selected target key"
            );
            #[cfg(not(target_os = "macos"))]
            assert_eq!(priority.flow_key(), priority_key);

            let bulk = QueuedFmpSendJob::direct(make_job(socket, cipher, dest, true));
            assert_eq!(bulk.queue_lane(), EncryptWorkerLane::Bulk);
            assert_eq!(
                bulk.target_key(),
                priority_key,
                "same selected socket and destination keep the same queued key"
            );
        });
    }

    #[test]
    fn queued_target_key_survives_seal_and_batch_grouping() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(7);
            let dest: SocketAddr = "127.0.0.1:10037".parse().unwrap();
            let target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let target_key = target.key();
            let counter = 13;
            let header = [0x23; ESTABLISHED_HEADER_SIZE];
            let plaintext = b"queued key survives";
            let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + plaintext.len() + 16);
            wire_buf.extend_from_slice(&header);
            wire_buf.extend_from_slice(plaintext);

            let queued = QueuedFmpSendJob::direct(FmpSendJob {
                cipher: cipher.clone(),
                counter,
                wire_buf,
                fsp_seal: None,
                send_target: target,
                bulk_endpoint_data: true,
                drop_on_backpressure: true,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            });
            assert_eq!(queued.target_key(), target_key);

            let sealed = SealedSendPacket::from_queued(queued).expect("seal packet");
            assert_eq!(
                sealed.target_key(),
                target_key,
                "sealing must consume the queued message's selected key"
            );
            let (send_target, sealed_key, wire_packet, drop_on_backpressure) = sealed.into_parts();
            assert_eq!(sealed_key, target_key);
            assert!(drop_on_backpressure);

            let opened = crate::noise::open(
                Some(&cipher),
                counter,
                &header,
                &wire_packet[ESTABLISHED_HEADER_SIZE..],
            )
            .expect("open sealed packet");
            assert_eq!(opened, plaintext);

            let mut groups = Vec::new();
            push_selected_send_batch(
                &mut groups,
                send_target,
                sealed_key,
                wire_packet,
                drop_on_backpressure,
            );
            assert_eq!(groups.len(), 1);
            assert_eq!(
                groups[0].target_key(),
                target_key,
                "batch grouping must use the sealed packet's queued key"
            );
            assert_eq!(groups[0].wire_packets.len(), 1);
        });
    }

    #[test]
    fn fsp_preseal_runs_before_outer_fmp_seal() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
            recv.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .expect("set_read_timeout");
            let recv_addr = recv.local_addr().expect("recv local_addr");
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let send_sock = raw.into_async().expect("into_async");

            let fmp_cipher = test_cipher(1);
            let fsp_cipher = test_cipher(2);
            let fmp_counter = 11;
            let fsp_counter = 22;
            let fmp_header = [0xA5; ESTABLISHED_HEADER_SIZE];
            let fsp_header = [0x5A; FSP_HEADER_SIZE];
            let fsp_plaintext = b"inner payload";

            let mut wire_buf = Vec::with_capacity(
                ESTABLISHED_HEADER_SIZE
                    + FSP_HEADER_SIZE
                    + fsp_plaintext.len()
                    + crate::noise::TAG_SIZE
                    + crate::noise::TAG_SIZE,
            );
            wire_buf.extend_from_slice(&fmp_header);
            let fsp_aad_offset = wire_buf.len();
            wire_buf.extend_from_slice(&fsp_header);
            let fsp_plaintext_offset = wire_buf.len();
            wire_buf.extend_from_slice(fsp_plaintext);

            let expected_wire_len = ESTABLISHED_HEADER_SIZE
                + FSP_HEADER_SIZE
                + fsp_plaintext.len()
                + crate::noise::TAG_SIZE
                + crate::noise::TAG_SIZE;
            let mut batch = vec![FmpSendJob {
                cipher: fmp_cipher.clone(),
                counter: fmp_counter,
                wire_buf,
                fsp_seal: Some(FspSealJob {
                    cipher: fsp_cipher.clone(),
                    counter: fsp_counter,
                    aad_offset: fsp_aad_offset,
                    plaintext_offset: fsp_plaintext_offset,
                }),
                send_target: SelectedSendTarget::new(
                    send_sock,
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    None,
                    recv_addr,
                ),
                bulk_endpoint_data: true,
                drop_on_backpressure: true,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            }];

            flush_direct_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            let mut buf = [0u8; 256];
            let (len, _) = recv.recv_from(&mut buf).expect("recv");
            assert_eq!(len, expected_wire_len);
            assert_eq!(&buf[..ESTABLISHED_HEADER_SIZE], &fmp_header);

            let outer_plaintext = crate::noise::open(
                Some(&fmp_cipher),
                fmp_counter,
                &fmp_header,
                &buf[ESTABLISHED_HEADER_SIZE..len],
            )
            .expect("outer open");
            assert_eq!(&outer_plaintext[..FSP_HEADER_SIZE], &fsp_header);
            let inner_plaintext = crate::noise::open(
                Some(&fsp_cipher),
                fsp_counter,
                &outer_plaintext[..FSP_HEADER_SIZE],
                &outer_plaintext[FSP_HEADER_SIZE..],
            )
            .expect("inner open");
            assert_eq!(inner_plaintext, fsp_plaintext);
        });
    }

    #[test]
    fn selected_send_batch_owns_target_fifo_and_drop_policy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw_a = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket a");
            let socket_a = raw_a.into_async().expect("into_async a");
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket b");
            let socket_b = raw_b.into_async().expect("into_async b");
            let dest_a: SocketAddr = "127.0.0.1:10029".parse().unwrap();
            let dest_b: SocketAddr = "127.0.0.1:10030".parse().unwrap();

            let target_a = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_target_a = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_target_a_droppable_again = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_target_a_droppable_after_control = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_dest_different_socket = SelectedSendTarget::new(
                socket_b,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_socket_different_dest = SelectedSendTarget::new(
                socket_a,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_b,
            );

            let key_a = target_a.key();
            let key_other_socket = same_dest_different_socket.key();
            let key_other_dest = same_socket_different_dest.key();
            assert_ne!(
                key_a, key_other_socket,
                "same sockaddr on a different socket is a different send batch"
            );
            assert_ne!(
                key_a, key_other_dest,
                "same socket to a different sockaddr is a different send batch"
            );

            let mut groups = Vec::new();
            push_selected_send_batch(&mut groups, target_a, key_a, vec![1], true);
            push_selected_send_batch(
                &mut groups,
                same_dest_different_socket,
                key_other_socket,
                vec![2],
                true,
            );
            push_selected_send_batch(
                &mut groups,
                same_target_a_droppable_again,
                key_a,
                vec![3],
                true,
            );
            push_selected_send_batch(&mut groups, same_target_a, key_a, vec![4], false);
            push_selected_send_batch(
                &mut groups,
                same_target_a_droppable_after_control,
                key_a,
                vec![5],
                true,
            );
            push_selected_send_batch(
                &mut groups,
                same_socket_different_dest,
                key_other_dest,
                vec![6],
                true,
            );

            assert_eq!(groups.len(), 5);
            assert_eq!(groups[0].target_key(), key_a);
            assert_eq!(groups[0].wire_packets, vec![vec![1], vec![3]]);
            assert!(
                groups[0].drop_on_backpressure,
                "droppable packets for the same target may still coalesce across unrelated targets"
            );
            assert_eq!(groups[1].target_key(), key_other_socket);
            assert_eq!(groups[1].wire_packets, vec![vec![2]]);
            assert!(groups[1].drop_on_backpressure);
            assert_eq!(groups[2].target_key(), key_a);
            assert_eq!(groups[2].wire_packets, vec![vec![4]]);
            assert!(
                !groups[2].drop_on_backpressure,
                "non-droppable control-shaped packets get their own retry policy"
            );
            assert_eq!(groups[3].target_key(), key_a);
            assert_eq!(groups[3].wire_packets, vec![vec![5]]);
            assert!(groups[3].drop_on_backpressure);
            assert_eq!(groups[4].target_key(), key_other_dest);
            assert_eq!(groups[4].wire_packets, vec![vec![6]]);
            assert!(groups[4].drop_on_backpressure);
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_send_batch_attempt_owns_cursor_and_backpressure_policy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let dest: SocketAddr = "127.0.0.1:10031".parse().unwrap();

            let target = SelectedSendTarget::new(
                socket.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let target_key = target.key();
            let mut batch = SelectedSendBatch::new(target, target_key, vec![1], true);
            batch.push(vec![2], true);

            let mut attempt = LinuxSendBatchAttempt::from_batch(batch);
            assert_eq!(attempt.target_key(), target_key);
            assert_eq!(attempt.remaining_packets(), &[vec![1], vec![2]]);
            attempt.mark_sent(1);
            assert_eq!(attempt.remaining_packets(), &[vec![2]]);

            let err = std::io::Error::from_raw_os_error(libc::ENOBUFS);
            assert_eq!(
                attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::DropCurrentBulk
            );
            assert!(
                attempt.is_complete(),
                "droppable backpressure advances exactly one current packet"
            );

            let target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let retry_target_key = target.key();
            let mut retry_batch = SelectedSendBatch::new(target, retry_target_key, vec![3], false);
            retry_batch.push(vec![4], false);
            let mut retry_attempt = LinuxSendBatchAttempt::from_batch(retry_batch);
            assert_eq!(
                retry_attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::Retry
            );
            assert_eq!(
                retry_attempt.remaining_packets(),
                &[vec![3], vec![4]],
                "non-droppable send batches must not advance on a drop request"
            );
        });
    }
}

#[cfg(all(test, target_os = "macos"))]
mod mac_queue_tests {
    use super::*;
    use crate::transport::udp::socket::UdpRawSocket;
    use ring::aead::{LessSafeKey, UnboundKey};

    fn test_cipher() -> LessSafeKey {
        let unbound =
            UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[0u8; 32]).expect("build key");
        LessSafeKey::new(unbound)
    }

    fn with_test_socket(test: impl FnOnce(AsyncUdpSocket, LessSafeKey)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            test(raw.into_async().expect("into_async"), test_cipher());
        });
    }

    fn queued_job(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        drop_on_backpressure: bool,
    ) -> QueuedFmpSendJob {
        queued_job_classified(
            socket,
            cipher,
            dest_addr,
            drop_on_backpressure,
            drop_on_backpressure,
        )
    }

    fn queued_job_classified(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
    ) -> QueuedFmpSendJob {
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + 64 + 16);
        wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + 64, 0);
        QueuedFmpSendJob::direct(FmpSendJob {
            cipher: cipher.clone(),
            counter: 0,
            wire_buf,
            fsp_seal: None,
            send_target: SelectedSendTarget::new(socket, None, dest_addr),
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight: DEFAULT_SEND_WEIGHT,
            queued_at: None,
        })
    }

    fn test_mac_send_flow(
        socket: AsyncUdpSocket,
        dest_addr: SocketAddr,
    ) -> Arc<MacSequencedSendFlow> {
        let send_target = SelectedSendTarget::new(socket, None, dest_addr);
        let key = send_target.key();
        Arc::new(MacSequencedSendFlow {
            key,
            send_target,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(0),
            state: Mutex::new(MacSendFlowState::default()),
            ready_cv: Condvar::new(),
            space_cv: Condvar::new(),
        })
    }

    #[test]
    fn mac_worker_prioritizes_control_when_bulk_queue_is_full() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(2);
            let addr: SocketAddr = "127.0.0.1:10010".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket, &cipher, addr, false))
                    .is_ok()
            );

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 3));
            assert_eq!(batch.len(), 3);
            assert!(!batch[0].job.drop_on_backpressure);
            assert!(batch[1].job.drop_on_backpressure);
            assert!(batch[2].job.drop_on_backpressure);
        });
    }

    #[test]
    fn mac_completion_group_owns_flow_key_and_fifo_items() {
        with_test_socket(|socket, _cipher| {
            let flow_a = test_mac_send_flow(socket.clone(), "127.0.0.1:10033".parse().unwrap());
            let flow_b = test_mac_send_flow(socket, "127.0.0.1:10034".parse().unwrap());
            let key_a = flow_a.key;
            let key_b = flow_b.key;
            assert_ne!(key_a, key_b);

            let mut groups = Vec::new();
            push_mac_completion(
                &mut groups,
                Arc::clone(&flow_a),
                7,
                MacSendItem::Packet {
                    packet: vec![1],
                    drop_on_backpressure: true,
                },
            );
            push_mac_completion(&mut groups, Arc::clone(&flow_b), 3, MacSendItem::Skip);
            push_mac_completion(
                &mut groups,
                Arc::clone(&flow_a),
                8,
                MacSendItem::Packet {
                    packet: vec![2],
                    drop_on_backpressure: false,
                },
            );

            assert_eq!(groups.len(), 2);
            assert_eq!(groups[0].target_key(), key_a);
            assert_eq!(groups[1].target_key(), key_b);
            assert_eq!(groups[0].items.len(), 2);
            assert_eq!(groups[0].items[0].0, 7);
            assert_eq!(groups[0].items[1].0, 8);
            match &groups[0].items[0].1 {
                MacSendItem::Packet {
                    packet,
                    drop_on_backpressure,
                } => {
                    assert_eq!(packet.as_slice(), &[1]);
                    assert!(*drop_on_backpressure);
                }
                MacSendItem::Skip => panic!("expected first flow item to be a packet"),
            }
            match &groups[0].items[1].1 {
                MacSendItem::Packet {
                    packet,
                    drop_on_backpressure,
                } => {
                    assert_eq!(packet.as_slice(), &[2]);
                    assert!(!*drop_on_backpressure);
                }
                MacSendItem::Skip => panic!("expected second flow item to be a packet"),
            }
            assert!(matches!(groups[1].items[0].1, MacSendItem::Skip));
        });
    }

    #[test]
    fn mac_worker_rejects_bulk_when_bulk_queue_is_full() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = mac_worker_channel(2);
            let addr: SocketAddr = "127.0.0.1:10011".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(matches!(
                tx.try_push(queued_job(socket, &cipher, addr, true)),
                Err(MacWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn mac_worker_keeps_non_droppable_endpoint_data_in_bulk_lane() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(2);
            let addr: SocketAddr = "127.0.0.1:10013".parse().unwrap();

            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false
                ))
                .is_ok()
            );
            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false
                ))
                .is_ok()
            );
            assert!(matches!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false
                )),
                Err(MacWorkerTryPushError::Full(_))
            ));
            assert!(
                tx.try_push(queued_job_classified(socket, &cipher, addr, false, false))
                    .is_ok()
            );

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 3));
            assert_eq!(batch.len(), 3);
            assert_eq!(batch[0].queue_lane(), EncryptWorkerLane::Priority);
            assert!(!batch[0].job.drop_on_backpressure);
            assert_eq!(batch[1].queue_lane(), EncryptWorkerLane::Bulk);
            assert!(!batch[1].job.drop_on_backpressure);
            assert_eq!(batch[2].queue_lane(), EncryptWorkerLane::Bulk);
            assert!(!batch[2].job.drop_on_backpressure);
        });
    }

    #[test]
    fn mac_dispatch_does_not_block_rx_loop_on_full_bulk_queue() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = mac_worker_channel(1);
            let addr: SocketAddr = "127.0.0.1:10014".parse().unwrap();

            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false,
                ))
                .is_ok(),
                "initial bulk job should fit"
            );

            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx].into_boxed_slice()),
                macos_senders: Arc::new(MacSequencedSendFlows::default()),
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_done = Arc::clone(&done);
            let job = queued_job_classified(socket, &cipher, addr, true, false);
            let handle = std::thread::spawn(move || {
                pool.dispatch_to_worker(0, job);
                thread_done.store(true, std::sync::atomic::Ordering::Release);
            });

            for _ in 0..20 {
                if done.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }

            assert!(
                done.load(std::sync::atomic::Ordering::Acquire),
                "full bulk dispatch must not block the rx loop"
            );
            handle.join().expect("dispatch thread should finish");
        });
    }

    #[test]
    fn mac_worker_bulk_push_blocks_until_space_is_available() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(1);
            let addr: SocketAddr = "127.0.0.1:10012".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );

            let queued = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let queued_in_thread = Arc::clone(&queued);
            let thread_cipher = cipher.clone();
            let handle = std::thread::spawn(move || {
                tx.push_blocking(queued_job(socket, &thread_cipher, addr, true))
                    .expect("bulk push should complete after queue space opens");
                queued_in_thread.store(true, std::sync::atomic::Ordering::Release);
            });

            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(
                !queued.load(std::sync::atomic::Ordering::Acquire),
                "bulk push should wait while the bulk queue is full"
            );

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 1));
            assert_eq!(batch.len(), 1);
            assert!(batch[0].job.drop_on_backpressure);

            handle.join().expect("bulk push thread should not panic");
            assert!(queued.load(std::sync::atomic::Ordering::Acquire));

            batch.clear();
            assert!(rx.recv_batch(&mut batch, 1));
            assert_eq!(batch.len(), 1);
            assert!(batch[0].job.drop_on_backpressure);
        });
    }

    #[test]
    fn direct_send_batch_attempt_owns_cursor_and_backpressure_policy() {
        with_test_socket(|socket, _cipher| {
            let dest: SocketAddr = "127.0.0.1:10032".parse().unwrap();
            let target = SelectedSendTarget::new(socket.clone(), None, dest);
            let target_key = target.key();
            let mut batch = SelectedSendBatch::new(target, target_key, vec![1], true);
            batch.push(vec![2], true);

            let mut attempt = DirectSendBatchAttempt::from_batch(batch);
            assert_eq!(attempt.target_key(), target_key);
            assert_eq!(attempt.remaining_packets(), &[vec![1], vec![2]]);
            attempt.mark_current_sent();
            assert_eq!(attempt.remaining_packets(), &[vec![2]]);

            let err = std::io::Error::from_raw_os_error(libc::ENOBUFS);
            assert_eq!(
                attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::DropCurrentBulk
            );
            assert!(
                attempt.is_complete(),
                "droppable backpressure advances exactly one current packet"
            );

            let target = SelectedSendTarget::new(socket, None, dest);
            let retry_target_key = target.key();
            let mut retry_batch = SelectedSendBatch::new(target, retry_target_key, vec![3], false);
            retry_batch.push(vec![4], false);
            let mut retry_attempt = DirectSendBatchAttempt::from_batch(retry_batch);
            assert_eq!(
                retry_attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::Retry
            );
            assert_eq!(
                retry_attempt.remaining_packets(),
                &[vec![3], vec![4]],
                "non-droppable direct-send batches must not advance on a drop request"
            );
        });
    }
}

#[cfg(all(test, unix, not(target_os = "macos")))]
mod fair_queue_tests {
    use super::*;
    use crate::transport::udp::socket::UdpRawSocket;
    use ring::aead::{LessSafeKey, UnboundKey};

    fn test_cipher() -> LessSafeKey {
        let unbound =
            UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[0u8; 32]).expect("build key");
        LessSafeKey::new(unbound)
    }

    fn with_test_socket(test: impl FnOnce(AsyncUdpSocket, LessSafeKey)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            test(raw.into_async().expect("into_async"), test_cipher());
        });
    }

    fn queued_job(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
        drop_on_backpressure: bool,
        scheduling_weight: u8,
    ) -> QueuedFmpSendJob {
        queued_job_classified(
            socket,
            cipher,
            dest_addr,
            payload_len,
            drop_on_backpressure,
            drop_on_backpressure,
            scheduling_weight,
        )
    }

    fn queued_job_classified(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
        scheduling_weight: u8,
    ) -> QueuedFmpSendJob {
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + payload_len + 16);
        wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + payload_len, 0);
        QueuedFmpSendJob::direct(FmpSendJob {
            cipher: cipher.clone(),
            counter: 0,
            wire_buf,
            fsp_seal: None,
            send_target: SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_addr,
            ),
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight,
            queued_at: None,
        })
    }

    #[test]
    fn single_flow_full_backpressures_instead_of_dropping() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(2, 2, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10000".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, 128, true, 1))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, 128, true, 1))
                    .is_ok()
            );
            assert!(matches!(
                tx.try_push(queued_job(socket, &cipher, addr, 128, true, 1)),
                Err(FairWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn tight_bulk_cap_limits_single_flow_to_fast_lane_plus_fair_budget() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(16, 4, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10026".parse().unwrap();

            for _ in 0..8 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("one flow should get one fast burst plus its fair budget");
            }

            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket,
                        &cipher,
                        addr,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "tight caps must not hide a third per-flow burst before reporting pressure"
            );
        });
    }

    #[test]
    fn fast_lane_cap_is_one_worker_batch_not_a_second_queue_window() {
        assert_eq!(
            worker_fast_lane_cap(2048, 512),
            DEFAULT_WORKER_BATCH_SIZE,
            "default bulk workers may bypass fair admission for one local batch, not one full per-flow queue"
        );
        assert_eq!(
            worker_fast_lane_cap(16, 4),
            4,
            "tight test caps still bound the bypass by the fair per-flow cap"
        );
        assert_eq!(
            worker_fast_lane_cap(2, 8),
            2,
            "tiny channels cannot grow a fast lane larger than the physical queue"
        );
    }

    #[test]
    fn single_flow_fast_lane_stops_after_batch_plus_fair_budget() {
        with_test_socket(|socket, cipher| {
            let total_cap = 128;
            let per_flow_cap = 64;
            let (tx, _rx) = fair_worker_channel(total_cap, per_flow_cap, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10034".parse().unwrap();
            let allowed = worker_fast_lane_cap(total_cap, per_flow_cap) + per_flow_cap;

            assert!(
                allowed < total_cap,
                "test should prove per-flow pressure before the physical queue is full"
            );
            for _ in 0..allowed {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("single flow should get one fast batch plus its fair budget");
            }

            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket,
                        &cipher,
                        addr,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "single flow must report pressure before a hidden second per-flow queue window"
            );
        });
    }

    #[test]
    fn new_flow_can_enter_when_hot_flow_reaches_per_flow_cap() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(4, 2, WORKER_FAIR_QUANTUM_BYTES);
            let hot: SocketAddr = "127.0.0.1:10001".parse().unwrap();
            let quiet: SocketAddr = "127.0.0.1:10002".parse().unwrap();

            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket, &cipher, quiet, 128, true, 1))
                .unwrap();

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 4));
            let dests: Vec<_> = batch.iter().map(|job| job.flow_key().dest_addr).collect();
            assert_eq!(dests.len(), 3);
            assert_eq!(dests.iter().filter(|addr| **addr == hot).count(), 2);
            assert_eq!(dests.iter().filter(|addr| **addr == quiet).count(), 1);
        });
    }

    #[test]
    fn hot_flow_backpressures_when_others_are_waiting() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(8, 2, WORKER_FAIR_QUANTUM_BYTES);
            let hot: SocketAddr = "127.0.0.1:10003".parse().unwrap();
            let quiet: SocketAddr = "127.0.0.1:10004".parse().unwrap();

            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, quiet, 128, true, 1))
                .unwrap();

            assert!(matches!(
                tx.try_push(queued_job(socket, &cipher, hot, 128, true, 1)),
                Err(FairWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn priority_flow_enters_when_bulk_flow_reaches_per_flow_cap() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(8, 2, WORKER_FAIR_QUANTUM_BYTES);
            let warmup: SocketAddr = "127.0.0.1:10022".parse().unwrap();
            let hot: SocketAddr = "127.0.0.1:10023".parse().unwrap();

            // Fill enough bulk slots first so the hot-flow jobs below use fair
            // admission and actually consume the per-flow bulk budget.
            for _ in 0..4 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    warmup,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("warmup bulk should enter fast lane");
            }

            for _ in 0..2 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    hot,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("hot bulk should consume fair per-flow budget");
            }

            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket.clone(),
                        &cipher,
                        hot,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "bulk should be capped for the hot flow"
            );

            tx.try_push(queued_job_classified(
                socket,
                &cipher,
                hot,
                64,
                false,
                false,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("priority job must bypass bulk per-flow pressure");

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 8));
            assert_eq!(batch.len(), 7);
            assert!(
                batch.iter().any(|job| job.flow_key().dest_addr == hot
                    && job.queue_lane() == EncryptWorkerLane::Priority),
                "priority job should be present despite the capped bulk flow"
            );
        });
    }

    #[test]
    fn priority_flow_enters_when_bulk_worker_queue_is_full() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(2, 1, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10024".parse().unwrap();

            for _ in 0..2 {
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("bulk jobs should fill the bounded bulk queue");
            }

            tx.try_push(queued_job_classified(
                socket,
                &cipher,
                addr,
                64,
                false,
                false,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("priority job must keep its reserve when bulk is full");

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 3));
            assert_eq!(batch.len(), 3);
            assert_eq!(batch[0].queue_lane(), EncryptWorkerLane::Priority);
            assert!(
                batch[1..]
                    .iter()
                    .all(|job| job.queue_lane() == EncryptWorkerLane::Bulk)
            );
        });
    }

    #[test]
    fn priority_reserve_does_not_shrink_with_tight_bulk_channel_cap() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(2, 1, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10025".parse().unwrap();

            for _ in 0..2 {
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("bulk jobs should fill the bounded bulk queue");
            }

            for _ in 0..3 {
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    64,
                    false,
                    false,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("priority reserve must not be derived from the tight bulk cap");
            }

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 5));
            assert_eq!(batch.len(), 5);
            assert_eq!(
                batch
                    .iter()
                    .filter(|job| job.queue_lane() == EncryptWorkerLane::Priority)
                    .count(),
                3
            );
        });
    }

    #[test]
    fn single_flow_drains_full_batch() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(16, 16, 2048);
            let addr: SocketAddr = "127.0.0.1:10005".parse().unwrap();

            for _ in 0..8 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .unwrap();
            }

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 8));
            assert_eq!(batch.len(), 8);
            assert!(batch.iter().all(|job| job.flow_key().dest_addr == addr));
        });
    }

    #[test]
    fn encrypt_worker_dispatch_preserves_single_flow_worker_and_fifo_order() {
        with_test_socket(|socket, cipher| {
            let senders: Vec<_> = (0..4)
                .map(|_| fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES).0)
                .collect();
            let pool = EncryptWorkerPool {
                senders: Arc::from(senders.into_boxed_slice()),
            };
            let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 10009));

            let mut owner = None;
            for counter in 0..16 {
                let mut queued = queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                );
                queued.job.counter = counter;
                let (idx, queued) = pool.prepare_dispatch(queued.job);
                assert_eq!(queued.flow_key().dest_addr, addr);
                match owner {
                    Some(owner) => assert_eq!(
                        idx, owner,
                        "one TCP-shaped flow must not round-robin across workers"
                    ),
                    None => owner = Some(idx),
                }
            }

            let (tx, mut rx) = fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES);
            for counter in 0..8 {
                let mut queued = queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                );
                queued.job.counter = counter;
                tx.try_push(queued).expect("single-flow job should enqueue");
            }

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 8));
            let counters: Vec<_> = batch.iter().map(|job| job.job.counter).collect();
            assert_eq!(
                counters,
                (0..8).collect::<Vec<_>>(),
                "single-flow queue must preserve FIFO order"
            );
        });
    }

    #[test]
    fn fair_admission_keys_pressure_by_exact_send_target() {
        with_test_socket(|socket_a, cipher| {
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open second send socket");
            let socket_b = raw_b.into_async().expect("into_async second socket");
            assert_ne!(
                socket_a.as_raw_fd(),
                socket_b.as_raw_fd(),
                "test requires two distinct send fds"
            );

            let (tx, _rx) = fair_worker_channel(4, 1, WORKER_FAIR_QUANTUM_BYTES);
            let warmup: SocketAddr = "127.0.0.1:10020".parse().unwrap();
            let shared_dest: SocketAddr = "127.0.0.1:10021".parse().unwrap();

            // Fill enough bulk slots first so the next sends exercise
            // fair-admission keys instead of bypassing admission.
            tx.try_push(queued_job(
                socket_a.clone(),
                &cipher,
                warmup,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .unwrap();
            tx.try_push(queued_job(
                socket_a.clone(),
                &cipher,
                warmup,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .unwrap();

            tx.try_push(queued_job(
                socket_a.clone(),
                &cipher,
                shared_dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("first send target should reserve its per-target budget");

            tx.try_push(queued_job(
                socket_b,
                &cipher,
                shared_dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("different fd to the same dest is a different send target");
        });
    }

    #[test]
    fn fair_admission_reservation_owns_release_key() {
        with_test_socket(|socket_a, cipher| {
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open second send socket");
            let socket_b = raw_b.into_async().expect("into_async second socket");
            let dest: SocketAddr = "127.0.0.1:10033".parse().unwrap();
            let key_a =
                queued_job(socket_a, &cipher, dest, 128, true, DEFAULT_SEND_WEIGHT).flow_key();
            let key_b =
                queued_job(socket_b, &cipher, dest, 128, true, DEFAULT_SEND_WEIGHT).flow_key();
            assert_ne!(
                key_a, key_b,
                "same destination on different sockets must have different reservations"
            );

            let admission = FairAdmission {
                state: Mutex::new(FairAdmissionState::default()),
                not_full: Condvar::new(),
                total_cap: 2,
                per_flow_cap: 1,
                fast_lane_cap: 1,
            };
            let reservation_a = match admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("first key should reserve"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            assert_eq!(reservation_a.key(), key_a);
            assert!(
                matches!(
                    admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize),
                    FairReserve::Full
                ),
                "per-flow cap should block a second reservation for the same key"
            );
            let reservation_b = match admission.try_reserve(key_b, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("different key should reserve independently"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            assert_eq!(reservation_b.key(), key_b);

            admission.release(reservation_a);
            let reservation_a = match admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("released key should reserve again"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            assert_eq!(reservation_a.key(), key_a);
            admission.release(reservation_a);
            admission.release(reservation_b);
        });
    }

    #[test]
    fn queued_fmp_send_job_owns_clamped_scheduling_weight() {
        with_test_socket(|socket, cipher| {
            let addr: SocketAddr = "127.0.0.1:10026".parse().unwrap();

            let mut explicit = queued_job(
                socket.clone(),
                &cipher,
                addr,
                128,
                true,
                EXPLICIT_PEER_SEND_WEIGHT,
            );
            assert_eq!(
                explicit.scheduling_weight(),
                EXPLICIT_PEER_SEND_WEIGHT as usize
            );
            explicit.job.scheduling_weight = MAX_SEND_WEIGHT;
            assert_eq!(
                explicit.scheduling_weight(),
                EXPLICIT_PEER_SEND_WEIGHT as usize,
                "queued worker messages own the scheduling weight used by admission"
            );

            let low = queued_job(socket.clone(), &cipher, addr, 128, true, 0);
            assert_eq!(low.scheduling_weight(), MIN_SEND_WEIGHT as usize);

            let high = queued_job(socket, &cipher, addr, 128, true, u8::MAX);
            assert_eq!(high.scheduling_weight(), MAX_SEND_WEIGHT as usize);
        });
    }

    #[test]
    fn selected_send_target_key_drives_dispatch_and_admission() {
        with_test_socket(|socket_a, cipher| {
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open second send socket");
            let socket_b = raw_b.into_async().expect("into_async second socket");
            let dest: SocketAddr = "127.0.0.1:10027".parse().unwrap();

            let senders: Vec<_> = (0..4)
                .map(|_| fair_worker_channel(8, 2, WORKER_FAIR_QUANTUM_BYTES).0)
                .collect();
            let pool = EncryptWorkerPool {
                senders: Arc::from(senders.into_boxed_slice()),
            };

            let queued_a = queued_job(
                socket_a.clone(),
                &cipher,
                dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            );
            let key_a = queued_a.flow_key();
            let expected_idx_a = (send_target_fast_hash(&key_a) as usize) % pool.senders.len();
            let (idx_a, queued_a) = pool.prepare_dispatch(queued_a.job);
            assert_eq!(idx_a, expected_idx_a);
            assert_eq!(
                queued_a.flow_key(),
                key_a,
                "dispatch must carry the selected target key, not rebuild it differently"
            );

            let queued_b = queued_job(
                socket_b.clone(),
                &cipher,
                dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            );
            let key_b = queued_b.flow_key();
            assert_ne!(
                key_a, key_b,
                "same sockaddr on a different send fd is a different selected target"
            );

            let (tx, _rx) = fair_worker_channel(4, 1, WORKER_FAIR_QUANTUM_BYTES);
            let warmup: SocketAddr = "127.0.0.1:10028".parse().unwrap();
            for _ in 0..2 {
                tx.try_push(queued_job(
                    socket_a.clone(),
                    &cipher,
                    warmup,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("warmup bulk should enter fast lane");
            }

            tx.try_push(queued_a)
                .expect("first selected target should reserve its budget");
            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket_a,
                        &cipher,
                        dest,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "same selected target should hit the per-target admission cap"
            );
            tx.try_push(queued_b)
                .expect("different selected target should get its own budget");
        });
    }

    #[test]
    fn boosted_flow_gets_larger_queue_budget() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(12, 2, 2048);
            let boosted: SocketAddr = "127.0.0.1:10006".parse().unwrap();
            let normal: SocketAddr = "127.0.0.1:10007".parse().unwrap();

            for _ in 0..6 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    boosted,
                    1500,
                    true,
                    EXPLICIT_PEER_SEND_WEIGHT,
                ))
                .unwrap();
            }
            assert!(matches!(
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    boosted,
                    1500,
                    true,
                    EXPLICIT_PEER_SEND_WEIGHT,
                )),
                Err(FairWorkerTryPushError::Full(_))
            ));

            for _ in 0..2 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    normal,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .unwrap();
            }
            assert!(matches!(
                tx.try_push(queued_job(
                    socket,
                    &cipher,
                    normal,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                )),
                Err(FairWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn fair_dispatch_does_not_block_rx_loop_on_full_bulk_queue() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(1, 1, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10008".parse().unwrap();

            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    false,
                    DEFAULT_SEND_WEIGHT,
                ))
                .is_ok(),
                "initial bulk job should fit"
            );

            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx].into_boxed_slice()),
            };
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_done = Arc::clone(&done);
            let job =
                queued_job_classified(socket, &cipher, addr, 128, true, false, DEFAULT_SEND_WEIGHT);
            let handle = std::thread::spawn(move || {
                pool.dispatch_to_worker(0, job);
                thread_done.store(true, std::sync::atomic::Ordering::Release);
            });

            for _ in 0..20 {
                if done.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }

            assert!(
                done.load(std::sync::atomic::Ordering::Acquire),
                "full bulk dispatch must not block the rx loop"
            );
            handle.join().expect("dispatch thread should finish");
        });
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

            // Per-target plaintext sizes are distinct so we can
            // identify which receiver got which job by wire-packet
            // length alone — `seal_in_place_separate_tag` scrambles
            // the post-header bytes, so byte-level stamps don't
            // survive the AEAD. Final wire size is 16-byte header
            // + plaintext_size + 16-byte tag.
            const A_PLAINTEXT: usize = 32;
            const B_PLAINTEXT: usize = 64;
            const A_WIRE: usize = 16 + A_PLAINTEXT + 16; // 64
            const B_WIRE: usize = 16 + B_PLAINTEXT + 16; // 96

            fn make_job(
                socket: crate::transport::udp::socket::AsyncUdpSocket,
                cipher: &LessSafeKey,
                counter: u64,
                dest: SocketAddr,
                plaintext_size: usize,
            ) -> FmpSendJob {
                // wire_buf: 16-byte header + plaintext + tag-room.
                let mut wire_buf = Vec::with_capacity(16 + plaintext_size + 16);
                wire_buf.extend_from_slice(&[0u8; 16]);
                wire_buf.extend_from_slice(&vec![0u8; plaintext_size]);
                FmpSendJob {
                    cipher: cipher.clone(),
                    counter,
                    wire_buf,
                    fsp_seal: None,
                    send_target: SelectedSendTarget::new(
                        socket,
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        None,
                        dest,
                    ),
                    bulk_endpoint_data: true,
                    drop_on_backpressure: true,
                    scheduling_weight: DEFAULT_SEND_WEIGHT,
                    queued_at: None,
                }
            }

            let mut batch = vec![
                make_job(send_sock.clone(), &cipher, 1, addr_a, A_PLAINTEXT),
                make_job(send_sock.clone(), &cipher, 2, addr_b, B_PLAINTEXT),
                make_job(send_sock.clone(), &cipher, 3, addr_a, A_PLAINTEXT),
            ];
            flush_direct_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            // recv_a expects exactly two packets, each A_WIRE bytes.
            let mut buf = [0u8; 256];
            for i in 0..2 {
                let (len, _) = recv_a.recv_from(&mut buf).expect("recv_a");
                assert_eq!(
                    len, A_WIRE,
                    "recv_a packet {i} has wrong length: got {len}, expected {A_WIRE}"
                );
            }

            // recv_b expects exactly one packet, B_WIRE bytes.
            let (len, _) = recv_b.recv_from(&mut buf).expect("recv_b");
            assert_eq!(
                len, B_WIRE,
                "recv_b packet has wrong length: got {len}, expected {B_WIRE}"
            );

            // Neither receiver may have leftovers. The pre-fix bug
            // would have either:
            //   (a) sent all 3 packets to addr_a (first-job dest
            //       used for the whole batch), causing recv_a to
            //       see a B_WIRE-sized packet and recv_b to see
            //       nothing, or
            //   (b) silently sent A's wire packets to addr_b's
            //       connected fd if any was installed.
            for (name, sock) in [("recv_a", &recv_a), ("recv_b", &recv_b)] {
                sock.set_read_timeout(Some(std::time::Duration::from_millis(50)))
                    .unwrap();
                let leftover = sock.recv_from(&mut buf);
                assert!(
                    leftover.is_err(),
                    "{name} got unexpected extra packet: {:?}",
                    leftover
                );
            }
        });
    }
}

/// Direct `sendto(2)` for non-Linux unix (macOS / BSD). Windows
/// doesn't reach this — encrypt_worker is gated to `unix` in
/// `lifecycle.rs` (the per-worker raw-fd send loop only applies on
/// unix; on Windows the rx_loop fallback path takes outbound packets
/// through tokio's `AsyncUdpSocket::send_to`).
#[cfg(all(unix, not(target_os = "linux")))]
fn send_connected_raw(fd: std::os::unix::io::RawFd, data: &[u8]) -> std::io::Result<usize> {
    let r = unsafe { libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

#[cfg(target_os = "macos")]
fn send_one_with_backpressure(
    fd: std::os::unix::io::RawFd,
    connected: bool,
    dest: &SocketAddr,
    data: &[u8],
    backpressure: &mut SendBackpressurePacer,
    drop_on_backpressure: bool,
) -> std::io::Result<()> {
    loop {
        let result = if connected {
            send_connected_raw(fd, data)
        } else {
            send_one_raw(fd, data, dest)
        };
        match result {
            Ok(_) => {
                backpressure.record_success();
                record_udp_send_path(connected, 1);
                return Ok(());
            }
            Err(err) if is_send_backpressure(&err) => {
                match send_backpressure_decision(backpressure.pause(&err), drop_on_backpressure) {
                    SendBackpressureDecision::DropCurrentBulk => {
                        record_udp_send_backpressure_drop(&err);
                        return Err(err);
                    }
                    SendBackpressureDecision::Retry => {}
                }
            }
            Err(err) => return Err(err),
        }
    }
}

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
