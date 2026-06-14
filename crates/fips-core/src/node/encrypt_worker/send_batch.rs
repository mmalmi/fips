
use crate::node::session_wire::FSP_HEADER_SIZE;
use crate::node::wire::ESTABLISHED_HEADER_SIZE;
use crate::transport::udp::socket::AsyncUdpSocket;
#[cfg(not(target_os = "macos"))]
use crossbeam_channel::{Receiver, SendError, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
#[cfg(target_os = "macos")]
use std::cell::RefCell;
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
            key,
        }
    }

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

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct SendTargetKey {
    #[cfg(unix)]
    socket_fd: RawFd,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_fd: Option<RawFd>,
    dest_addr: SocketAddr,
}

impl SendTargetKey {
    fn from_parts(
        #[cfg_attr(not(unix), allow(unused_variables))]
        socket: &AsyncUdpSocket,
        #[cfg(any(target_os = "linux", target_os = "macos"))] connected_socket: Option<
            &std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
        >,
        dest_addr: SocketAddr,
    ) -> Self {
        Self {
            #[cfg(unix)]
            socket_fd: socket.as_raw_fd(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_fd: connected_socket.map(|socket| socket.as_raw_fd()),
            dest_addr,
        }
    }
}

impl FmpSendJob {
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
    #[cfg(target_os = "linux")]
    gso_segment_len: usize,
    #[cfg(target_os = "linux")]
    gso_last_len: usize,
    #[cfg(target_os = "linux")]
    gso_prefix_uniform: bool,
    #[cfg(target_os = "linux")]
    gso_eligible_sizes: bool,
}

#[cfg(unix)]
impl SelectedSendBatch {
    #[cfg(test)]
    fn new(
        send_target: SelectedSendTarget,
        target_key: SendTargetKey,
        wire_packet: Vec<u8>,
        drop_on_backpressure: bool,
    ) -> Self {
        Self::new_with_capacity(
            send_target,
            target_key,
            wire_packet,
            drop_on_backpressure,
            1,
        )
    }

    fn new_with_capacity(
        send_target: SelectedSendTarget,
        target_key: SendTargetKey,
        wire_packet: Vec<u8>,
        drop_on_backpressure: bool,
        packet_capacity: usize,
    ) -> Self {
        debug_assert_eq!(
            send_target.key(),
            target_key,
            "selected send batch must keep the queued target key"
        );
        #[cfg(target_os = "linux")]
        let gso_segment_len = wire_packet.len();
        let mut wire_packets = Vec::with_capacity(packet_capacity.max(1));
        wire_packets.push(wire_packet);
        Self {
            send_target,
            target_key,
            wire_packets,
            drop_on_backpressure,
            #[cfg(target_os = "linux")]
            gso_segment_len,
            #[cfg(target_os = "linux")]
            gso_last_len: gso_segment_len,
            #[cfg(target_os = "linux")]
            gso_prefix_uniform: gso_segment_len > 0,
            #[cfg(target_os = "linux")]
            gso_eligible_sizes: false,
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
        #[cfg(target_os = "linux")]
        {
            let packet_len = wire_packet.len();
            self.gso_prefix_uniform &= self.gso_last_len == self.gso_segment_len;
            self.gso_last_len = packet_len;
            self.gso_eligible_sizes = self.gso_prefix_uniform && packet_len <= self.gso_segment_len;
        }
        self.wire_packets.push(wire_packet);
    }

    fn drop_on_backpressure(&self) -> bool {
        self.drop_on_backpressure
    }

    fn packet_count(&self) -> usize {
        self.wire_packets.len()
    }

    #[cfg(target_os = "linux")]
    fn gso_eligible_sizes(&self) -> bool {
        self.gso_eligible_sizes
    }

    #[cfg(test)]
    fn wire_packet_capacity(&self) -> usize {
        self.wire_packets.capacity()
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
    gso_eligible_sizes: bool,
    drop_on_backpressure: bool,
    backpressure: SendBackpressurePacer,
    sent: usize,
}

#[cfg(target_os = "linux")]
impl LinuxSendBatchAttempt {
    fn from_batch(batch: SelectedSendBatch) -> Self {
        let gso_eligible_sizes = batch.gso_eligible_sizes();
        debug_assert_eq!(
            gso_eligible_sizes,
            gso_eligible_sizes_ref(&batch.wire_packets)
        );
        let (send_target, wire_packets, drop_on_backpressure) = batch.into_parts();
        Self {
            send_target,
            wire_packets,
            gso_eligible_sizes,
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

    fn gso_eligible_sizes(&self) -> bool {
        self.gso_eligible_sizes
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

    #[cfg(target_os = "macos")]
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
#[cfg(test)]
fn push_selected_send_batch(
    groups: &mut Vec<SelectedSendBatch>,
    send_target: SelectedSendTarget,
    target_key: SendTargetKey,
    wire_packet: Vec<u8>,
    drop_on_backpressure: bool,
) {
    push_selected_send_batch_with_capacity(
        groups,
        send_target,
        target_key,
        wire_packet,
        drop_on_backpressure,
        1,
    )
}

#[cfg(unix)]
fn push_selected_send_batch_with_capacity(
    groups: &mut Vec<SelectedSendBatch>,
    send_target: SelectedSendTarget,
    target_key: SendTargetKey,
    wire_packet: Vec<u8>,
    drop_on_backpressure: bool,
    packet_capacity: usize,
) {
    if let Some(group) = groups.last_mut()
        && group.target_key() == target_key
    {
        if group.drop_on_backpressure() == drop_on_backpressure {
            group.push(wire_packet, drop_on_backpressure);
        } else {
            groups.push(SelectedSendBatch::new_with_capacity(
                send_target,
                target_key,
                wire_packet,
                drop_on_backpressure,
                packet_capacity,
            ));
        }
        return;
    }

    groups.push(SelectedSendBatch::new_with_capacity(
        send_target,
        target_key,
        wire_packet,
        drop_on_backpressure,
        packet_capacity,
    ));
}

#[cfg(unix)]
fn selected_send_group_stats(groups: &[SelectedSendBatch]) -> (usize, usize, usize) {
    let mut packets = 0usize;
    let mut single_groups = 0usize;
    for group in groups {
        let count = group.packet_count();
        packets = packets.saturating_add(count);
        if count == 1 {
            single_groups = single_groups.saturating_add(1);
        }
    }
    (groups.len(), packets, single_groups)
}

#[cfg(unix)]
fn record_selected_send_groups(groups: &[SelectedSendBatch]) {
    let (group_count, packets, single_groups) = selected_send_group_stats(groups);
    crate::perf_profile::record_fmp_send_groups(group_count, packets, single_groups);
}
