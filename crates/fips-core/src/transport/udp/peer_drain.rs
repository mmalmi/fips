//! Recv-side drain thread for a per-peer connected UDP socket.
//!
//! Once a UDP socket is `connect()`-ed to a peer, Linux and Darwin
//! UDP demux preferentially route inbound packets matching the peer's
//! 5-tuple to that socket (most-specific match wins over the wildcard
//! listen socket under `SO_REUSEPORT`). So a connected socket **must**
//! be drained, or packets pile up in its recv buffer until it overflows
//! and the kernel drops them silently.
//!
//! This module owns the drain side: spawn one OS thread per connected
//! socket, drain into a fixed-size batch (`recvmmsg(2)` on Linux,
//! repeated nonblocking `recv(2)` on Darwin), and exit cleanly when the
//! parent signals shutdown via a self-pipe.
//!
//! When a decrypt fast path is installed, the dispatch thread may skip
//! the wildcard packet-channel hop for matching established packets, but
//! that is still the canonical decrypt-worker path: session/peer ownership,
//! replay, and TUN/endpoint delivery stay with the normal worker owner.
//! Non-matching packets return untouched to `packet_tx`; bulk pressure is
//! handled by visible bounded-ring/worker drops, not by alternate replay
//! ownership.
//!
//! Future: when the full data-plane shard lands, this per-peer thread
//! becomes a `epoll_wait` arm inside the shard's event loop instead
//! of a dedicated OS thread. The drain *function* `drain_loop` stays
//! useful in either shape; only the wakeup mechanism differs.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use super::super::{
    PacketBuffer, ReceivedPacket, TransportAddr, TransportId, received_timestamp_ms,
};
use super::PacketTx;
use super::connected_peer::ConnectedPeerSocket;
use crate::discovery::is_punch_packet;
use crate::transport::packet_channel::PacketBatch;
use crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError, bounded, unbounded};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

const CONNECTED_UDP_RECV_BUF_SIZE: usize = 1600; // covers any practical FIPS MTU.
pub(crate) const CONNECTED_UDP_PRIORITY_MAX_LEN: usize = 512;
const DEFAULT_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS: usize = 32 * 1024;
const MIN_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS: usize = 1024;
const MAX_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS: usize = 256 * 1024;
const CONNECTED_UDP_DISPATCH_BATCH_LIMIT: usize = super::UDP_RECV_BATCH_SIZE;

pub(crate) trait ConnectedUdpPacketFastPath: Send + Sync {
    fn batcher(&self) -> Box<dyn ConnectedUdpPacketFastPathBatcher>;
}

pub(crate) trait ConnectedUdpPacketFastPathBatcher {
    fn try_dispatch(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        packet_data: PacketBuffer,
        timestamp_ms: u64,
    ) -> Result<(), PacketBuffer>;

    fn flush(&mut self);
}

struct ConnectedUdpDrainPacket {
    data: PacketBuffer,
    timestamp_ms: u64,
    enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

#[derive(Clone)]
struct ConnectedUdpDrainQueue {
    priority: Sender<ConnectedUdpDrainPacket>,
    bulk: Sender<ConnectedUdpDrainPacket>,
}

enum ConnectedUdpDrainEnqueueError {
    Closed,
    BulkFull(ConnectedUdpDrainPacket),
}

impl ConnectedUdpDrainQueue {
    fn enqueue(
        &self,
        packet: ConnectedUdpDrainPacket,
    ) -> Result<(), ConnectedUdpDrainEnqueueError> {
        if packet.data.len() <= CONNECTED_UDP_PRIORITY_MAX_LEN {
            self.priority
                .send(packet)
                .map_err(|_| ConnectedUdpDrainEnqueueError::Closed)
        } else {
            self.bulk.try_send(packet).map_err(|error| match error {
                TrySendError::Full(packet) => ConnectedUdpDrainEnqueueError::BulkFull(packet),
                TrySendError::Disconnected(_) => ConnectedUdpDrainEnqueueError::Closed,
            })
        }
    }
}

/// Handle to a running per-peer drain thread. Drops the thread (and
/// closes its self-pipe) on drop; the thread exits next time it
/// returns from `poll(2)`.
#[derive(Debug)]
pub(crate) struct PeerRecvDrain {
    /// Write end of the shutdown self-pipe. Write a single byte to
    /// wake the drain thread out of `poll(2)` so it sees the stop
    /// flag and exits.
    stop_pipe_tx: Option<RawFd>,
    /// Atomic stop signal — primary mechanism for the drain thread
    /// to know it should exit. Set before writing to `stop_pipe_tx`
    /// so the thread observes the flag once woken.
    stop: Arc<AtomicBool>,
    /// Joined on drop; the thread is cheap (just exits after the
    /// next `poll` returns) so the wait is bounded.
    joins: Vec<std::thread::JoinHandle<()>>,
}

impl PeerRecvDrain {
    /// Spawn a drain thread for the given connected socket.
    ///
    /// The thread holds an `Arc<ConnectedPeerSocket>` to keep the
    /// kernel fd alive while it's running. When this handle drops,
    /// the stop pipe fires; the thread exits; its `Arc` releases.
    /// If the parent also releases its `Arc`, the socket's `Drop`
    /// closes the kernel fd.
    pub fn spawn(
        socket: Arc<ConnectedPeerSocket>,
        transport_id: TransportId,
        peer_addr: SocketAddr,
        packet_tx: PacketTx,
        fast_path: Option<Arc<dyn ConnectedUdpPacketFastPath>>,
    ) -> io::Result<Self> {
        // Self-pipe for shutdown signaling. The drain thread polls
        // (socket_fd | pipe_rx) so a write to pipe_tx wakes it.
        let (pipe_rx, pipe_tx) = make_pipe()?;

        let stop = Arc::new(AtomicBool::new(false));
        let bulk_ring_packets = connected_udp_drain_bulk_ring_packets();
        let (priority_tx, priority_rx) = unbounded();
        let (bulk_tx, bulk_rx) = bounded(bulk_ring_packets);

        let dispatch_stop = stop.clone();
        let dispatch_packet_tx = packet_tx.clone();
        let dispatch_thread = std::thread::Builder::new()
            .name(format!("fips-peer-dispatch-{}", socket.peer_addr()))
            .spawn(move || {
                dispatch_loop(
                    transport_id,
                    peer_addr,
                    dispatch_packet_tx,
                    fast_path,
                    priority_rx,
                    bulk_rx,
                    dispatch_stop,
                );
            });
        let dispatch_join = match dispatch_thread {
            Ok(join) => join,
            Err(e) => {
                unsafe {
                    libc::close(pipe_rx);
                    libc::close(pipe_tx);
                }
                return Err(io::Error::other(format!(
                    "failed to spawn peer dispatch thread: {e}"
                )));
            }
        };

        let drain_queue = ConnectedUdpDrainQueue {
            priority: priority_tx,
            bulk: bulk_tx,
        };
        let stop_clone = stop.clone();
        let socket_clone = socket.clone();
        let drain_thread = std::thread::Builder::new()
            .name(format!("fips-peer-drain-{}", socket.peer_addr()))
            .spawn(move || {
                drain_loop(
                    socket_clone,
                    transport_id,
                    peer_addr,
                    packet_tx,
                    drain_queue,
                    pipe_rx,
                    stop_clone,
                );
                // Drain thread cleans up the read end of the pipe on exit.
                unsafe { libc::close(pipe_rx) };
            });

        match drain_thread {
            Ok(join) => Ok(Self {
                stop_pipe_tx: Some(pipe_tx),
                stop,
                joins: vec![join, dispatch_join],
            }),
            Err(e) => {
                stop.store(true, Ordering::Release);
                unsafe {
                    libc::close(pipe_rx);
                    libc::close(pipe_tx);
                }
                let _ = dispatch_join.join();
                Err(io::Error::other(format!(
                    "failed to spawn peer drain thread: {e}"
                )))
            }
        }
    }
}

impl Drop for PeerRecvDrain {
    fn drop(&mut self) {
        // 1. Set the stop flag.
        self.stop.store(true, Ordering::Release);

        // 2. Wake the drain thread. Closing the write end after the
        //    best-effort byte write guarantees poll(2) observes either
        //    POLLIN or POLLHUP, even if write(2) is interrupted or the
        //    pipe reader already exited.
        if let Some(fd) = self.stop_pipe_tx.take() {
            let byte = [1u8];
            loop {
                let r = unsafe { libc::write(fd, byte.as_ptr() as *const libc::c_void, 1) };
                if r >= 0 {
                    break;
                }
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
            unsafe { libc::close(fd) };
        }

        // 3. Detach the std::thread. Joining here can block the single
        // runtime driver while the drain worker is parked in blocking_send
        // waiting for that same runtime to make progress.
        self.joins.clear();
    }
}

/// The drain thread's main loop. Runs until `stop` is set + the
/// stop-pipe is written to (Drop does both in order).
fn drain_loop(
    socket: Arc<ConnectedPeerSocket>,
    transport_id: TransportId,
    peer_addr: SocketAddr,
    packet_tx: PacketTx,
    drain_queue: ConnectedUdpDrainQueue,
    stop_pipe_rx: RawFd,
    stop: Arc<AtomicBool>,
) {
    let socket_fd = socket.as_raw_fd();
    trace!(
        transport_id = %transport_id,
        peer_addr = %peer_addr,
        "fips-peer-drain: starting"
    );

    const BATCH: usize = super::UDP_RECV_BATCH_SIZE;
    let mut backing: Vec<Vec<u8>> = (0..BATCH)
        .map(|_| packet_tx.recv_buffer(CONNECTED_UDP_RECV_BUF_SIZE))
        .collect();
    let mut lens: [usize; BATCH] = [0; BATCH];
    #[cfg(target_os = "linux")]
    let mut kernel_drop_sampler = ConnectedUdpKernelDropSampler::new(socket_fd);

    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        // poll(2) on the socket + stop pipe. -1 timeout = block
        // until at least one is readable; the stop pipe wake-up
        // guarantees forward progress under Drop.
        let mut pfds = [
            libc::pollfd {
                fd: socket_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop_pipe_rx,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            warn!(error = %err, "fips-peer-drain: poll failed; exiting");
            break;
        }
        if pfds[1].revents != 0 {
            // Stop pipe fired. We may or may not also have data on
            // the socket; check the flag and exit if set.
            if stop.load(Ordering::Acquire) {
                break;
            }
        }
        let socket_revents = pfds[0].revents;
        if socket_revents & libc::POLLNVAL != 0 {
            warn!("fips-peer-drain: socket fd became invalid; exiting");
            break;
        }
        if socket_revents & libc::POLLHUP != 0 {
            debug!("fips-peer-drain: socket hung up; exiting");
            break;
        }
        if socket_revents & libc::POLLERR != 0 {
            match take_socket_error(socket_fd) {
                Ok(Some(err)) => {
                    debug!(error = %err, "fips-peer-drain: consumed socket error");
                }
                Ok(None) => {
                    debug!("fips-peer-drain: poll reported socket error with SO_ERROR=0");
                }
                Err(err) => {
                    debug!(error = %err, "fips-peer-drain: failed to read socket error");
                }
            }
        }
        if socket_revents & libc::POLLIN == 0 {
            continue;
        }

        // Drain whatever is currently queued in the kernel.
        let drain_started_at = crate::perf_profile::stamp();
        let drain_result = drain_packets(socket_fd, &mut backing, &mut lens);
        let count = match drain_result {
            Ok(count) => count,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                debug!(error = %err, "fips-peer-drain: recv failed; exiting");
                break;
            }
        };
        #[cfg(target_os = "linux")]
        kernel_drop_sampler.maybe_sample(socket_fd);
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::ConnectedUdpDrainRecv,
            drain_started_at,
            count as u64,
        );

        let timestamp_ms = received_timestamp_ms();
        for i in 0..count {
            let len = lens[i];
            if len == 0 {
                super::reset_recv_buffer(&mut backing[i]);
                continue;
            }
            if is_punch_packet(&backing[i][..len]) {
                trace!(
                    transport_id = %transport_id,
                    peer_addr = %peer_addr,
                    bytes = len,
                    "fips-peer-drain: dropping stray punch probe/ack"
                );
                super::reset_recv_buffer(&mut backing[i]);
                continue;
            }
            // Move the filled buffer out, refill the slot with a
            // fresh one. Same zero-copy pattern the wildcard listen
            // socket uses (see `transport/udp/mod.rs::run_receive_loop`).
            let mut data = std::mem::replace(
                &mut backing[i],
                packet_tx.recv_buffer(CONNECTED_UDP_RECV_BUF_SIZE),
            );
            data.truncate(len);
            let packet = ConnectedUdpDrainPacket {
                data: packet_tx.packet_buffer(data),
                timestamp_ms,
                enqueued_at: crate::perf_profile::stamp(),
            };
            match drain_queue.enqueue(packet) {
                Ok(()) => {}
                Err(ConnectedUdpDrainEnqueueError::BulkFull(packet)) => {
                    drop(packet);
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::TransportBulkDropped,
                    );
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::ConnectedUdpDrainBulkDropped,
                    );
                }
                Err(ConnectedUdpDrainEnqueueError::Closed) => {
                    trace!("fips-peer-drain: dispatch channel closed; exiting");
                    return;
                }
            }
        }
    }

    trace!(
        transport_id = %transport_id,
        peer_addr = %peer_addr,
        "fips-peer-drain: stopped"
    );
}

fn dispatch_loop(
    transport_id: TransportId,
    peer_addr: SocketAddr,
    packet_tx: PacketTx,
    fast_path: Option<Arc<dyn ConnectedUdpPacketFastPath>>,
    priority_rx: Receiver<ConnectedUdpDrainPacket>,
    bulk_rx: Receiver<ConnectedUdpDrainPacket>,
    stop: Arc<AtomicBool>,
) {
    let packet_addr = TransportAddr::from_socket_addr(peer_addr);
    let mut fast_path_batcher = fast_path.as_ref().map(|fast_path| fast_path.batcher());
    let never = crossbeam_channel::never();
    let mut priority_open = true;
    let mut bulk_open = true;

    trace!(
        transport_id = %transport_id,
        peer_addr = %peer_addr,
        "fips-peer-dispatch: starting"
    );

    while priority_open || bulk_open {
        let first = {
            let priority_wait = if priority_open { &priority_rx } else { &never };
            let bulk_wait = if bulk_open { &bulk_rx } else { &never };
            crossbeam_channel::select_biased! {
                recv(priority_wait) -> msg => match msg {
                    Ok(packet) => Some(packet),
                    Err(_) => {
                        priority_open = false;
                        None
                    }
                },
                recv(bulk_wait) -> msg => match msg {
                    Ok(packet) => Some(packet),
                    Err(_) => {
                        bulk_open = false;
                        None
                    }
                },
            }
        };
        let Some(first) = first else {
            continue;
        };

        if !dispatch_ready_packets(
            first,
            transport_id,
            &packet_addr,
            &packet_tx,
            fast_path_batcher.as_mut(),
            &priority_rx,
            &bulk_rx,
            &mut priority_open,
            &mut bulk_open,
        ) {
            break;
        }

        if stop.load(Ordering::Acquire) && !priority_open && !bulk_open {
            break;
        }
    }

    trace!(
        transport_id = %transport_id,
        peer_addr = %peer_addr,
        "fips-peer-dispatch: stopped"
    );
}

fn dispatch_ready_packets(
    first: ConnectedUdpDrainPacket,
    transport_id: TransportId,
    packet_addr: &TransportAddr,
    packet_tx: &PacketTx,
    mut fast_path_batcher: Option<&mut Box<dyn ConnectedUdpPacketFastPathBatcher>>,
    priority_rx: &Receiver<ConnectedUdpDrainPacket>,
    bulk_rx: &Receiver<ConnectedUdpDrainPacket>,
    priority_open: &mut bool,
    bulk_open: &mut bool,
) -> bool {
    let dispatch_started_at = crate::perf_profile::stamp();
    let mut dispatch_count = 0u64;
    let mut packets = packet_tx.packet_batch(CONNECTED_UDP_DISPATCH_BATCH_LIMIT);

    dispatch_one_packet(
        first,
        transport_id,
        packet_addr,
        &mut packets,
        &mut fast_path_batcher,
        &mut dispatch_count,
    );

    while dispatch_count < CONNECTED_UDP_DISPATCH_BATCH_LIMIT as u64 {
        match priority_rx.try_recv() {
            Ok(packet) => dispatch_one_packet(
                packet,
                transport_id,
                packet_addr,
                &mut packets,
                &mut fast_path_batcher,
                &mut dispatch_count,
            ),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                *priority_open = false;
                break;
            }
        }
    }

    while dispatch_count < CONNECTED_UDP_DISPATCH_BATCH_LIMIT as u64 {
        match bulk_rx.try_recv() {
            Ok(packet) => dispatch_one_packet(
                packet,
                transport_id,
                packet_addr,
                &mut packets,
                &mut fast_path_batcher,
                &mut dispatch_count,
            ),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                *bulk_open = false;
                break;
            }
        }
    }

    if let Some(fast_path) = fast_path_batcher.as_mut() {
        fast_path.flush();
    }
    let send_failed = !packets.is_empty() && packet_tx.send_packet_batch(packets).is_err();
    crate::perf_profile::record_since_count(
        crate::perf_profile::Stage::ConnectedUdpFastPathDispatch,
        dispatch_started_at,
        dispatch_count,
    );
    !send_failed
}

fn dispatch_one_packet(
    packet: ConnectedUdpDrainPacket,
    transport_id: TransportId,
    packet_addr: &TransportAddr,
    packets: &mut PacketBatch,
    fast_path_batcher: &mut Option<&mut Box<dyn ConnectedUdpPacketFastPathBatcher>>,
    dispatch_count: &mut u64,
) {
    *dispatch_count = dispatch_count.saturating_add(1);
    let timestamp_ms = packet.timestamp_ms;
    let trace_enqueued_at = packet.enqueued_at;
    record_connected_udp_drain_ring_wait(packet.data.len(), trace_enqueued_at);
    let mut packet_data = packet.data;
    if let Some(fast_path) = fast_path_batcher.as_mut() {
        match fast_path.try_dispatch(transport_id, packet_addr.clone(), packet_data, timestamp_ms) {
            Ok(()) => return,
            Err(returned) => packet_data = returned,
        }
    }
    let packet = ReceivedPacket::with_trace_timestamp(
        transport_id,
        packet_addr.clone(),
        packet_data,
        timestamp_ms,
        trace_enqueued_at,
    );
    packets.push(packet);
}

fn record_connected_udp_drain_ring_wait(
    packet_len: usize,
    enqueued_at: Option<crate::perf_profile::TraceStamp>,
) {
    crate::perf_profile::record_since_count(
        crate::perf_profile::Stage::ConnectedUdpDrainRingWait,
        enqueued_at,
        1,
    );
    let lane_stage = if packet_len <= CONNECTED_UDP_PRIORITY_MAX_LEN {
        crate::perf_profile::Stage::ConnectedUdpDrainPriorityRingWait
    } else {
        crate::perf_profile::Stage::ConnectedUdpDrainBulkRingWait
    };
    crate::perf_profile::record_since_count(lane_stage, enqueued_at, 1);
}

fn connected_udp_drain_bulk_ring_packets() -> usize {
    std::env::var("FIPS_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS")
        .ok()
        .and_then(|value| parse_connected_udp_drain_bulk_ring_packets(&value))
        .unwrap_or(DEFAULT_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS)
}

fn parse_connected_udp_drain_bulk_ring_packets(raw: &str) -> Option<usize> {
    raw.trim().parse::<usize>().ok().map(|value| {
        value.clamp(
            MIN_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS,
            MAX_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS,
        )
    })
}

fn take_socket_error(fd: RawFd) -> io::Result<Option<io::Error>> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if value == 0 {
        Ok(None)
    } else {
        Ok(Some(io::Error::from_raw_os_error(value)))
    }
}

fn make_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut pipe_fds = [0i32; 2];
    #[cfg(target_os = "linux")]
    {
        let r = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let r = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Err(err) = set_nonblocking_cloexec(pipe_fds[0]) {
            unsafe {
                libc::close(pipe_fds[0]);
                libc::close(pipe_fds[1]);
            }
            return Err(err);
        }
        if let Err(err) = set_nonblocking_cloexec(pipe_fds[1]) {
            unsafe {
                libc::close(pipe_fds[0]);
                libc::close(pipe_fds[1]);
            }
            return Err(err);
        }
    }
    Ok((pipe_fds[0], pipe_fds[1]))
}

#[cfg(not(target_os = "linux"))]
fn set_nonblocking_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drain_packets(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    recvmmsg_drain(fd, backing, lens)
}

#[cfg(not(target_os = "linux"))]
fn drain_packets(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    recv_drain(fd, backing, lens)
}

/// One-shot `recvmmsg(2)` on a non-blocking fd. Returns the number of
/// datagrams received (0 on no data ready). Same minimal-overhead shape as
/// the wildcard listen socket's `recv_batch` helper, but without per-packet
/// control-buffer parsing; connected-socket receive drops are sampled from
/// SO_MEMINFO once per second by `ConnectedUdpKernelDropSampler`.
#[cfg(target_os = "linux")]
fn recvmmsg_drain(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    const BATCH: usize = super::UDP_RECV_BATCH_SIZE;
    let n = backing.len().min(lens.len()).min(BATCH);
    if n == 0 {
        return Ok(0);
    }

    let mut iovs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
    let mut storages: [libc::sockaddr_storage; BATCH] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        backing[i].clear();
        let spare = backing[i].spare_capacity_mut();
        if spare.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP receive buffer has no spare capacity",
            ));
        }
        iovs[i].iov_base = spare.as_mut_ptr() as *mut libc::c_void;
        iovs[i].iov_len = spare.len();
        msgs[i].msg_hdr.msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msgs[i].msg_hdr.msg_iov = &mut iovs[i];
        // `msg_iovlen` is `usize` on glibc / `i32` on musl.
        msgs[i].msg_hdr.msg_iovlen = 1 as _;
        msgs[i].msg_len = 0;
    }

    // `MSG_DONTWAIT` is `c_int` (i32) on glibc but `u32` on musl;
    // `as _` resolves to whichever the recvmmsg signature wants.
    let r = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            n as libc::c_uint,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = r as usize;
    for i in 0..count {
        let len = msgs[i].msg_len as usize;
        if len > backing[i].capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recvmmsg reported a datagram larger than the receive buffer",
            ));
        }
        // SAFETY: `recvmmsg` wrote `len` initialized bytes into
        // `backing[i]`'s spare capacity through the iovec above, and
        // `len <= capacity` was checked before extending the Vec.
        unsafe {
            backing[i].set_len(len);
        }
        lens[i] = len;
    }
    Ok(count)
}

#[cfg(not(target_os = "linux"))]
fn recv_drain(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    let n = backing.len().min(lens.len());
    if n == 0 {
        return Ok(0);
    }

    let mut count = 0usize;
    while count < n {
        let r = unsafe {
            libc::recv(
                fd,
                backing[count].as_mut_ptr() as *mut libc::c_void,
                backing[count].len(),
                0,
            )
        };
        if r < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock && count > 0 {
                return Ok(count);
            }
            return Err(err);
        }
        lens[count] = r as usize;
        count += 1;
    }
    Ok(count)
}

#[cfg(target_os = "linux")]
struct ConnectedUdpKernelDropSampler {
    last_sample: Instant,
    last_drops: u32,
    supported: bool,
}

#[cfg(target_os = "linux")]
impl ConnectedUdpKernelDropSampler {
    const INTERVAL: Duration = Duration::from_secs(1);

    fn new(fd: RawFd) -> Self {
        match socket_kernel_drop_count(fd) {
            Ok(drops) => Self {
                last_sample: Instant::now(),
                last_drops: drops,
                supported: true,
            },
            Err(_) => Self {
                last_sample: Instant::now(),
                last_drops: 0,
                supported: false,
            },
        }
    }

    fn maybe_sample(&mut self, fd: RawFd) {
        if !self.supported || self.last_sample.elapsed() < Self::INTERVAL {
            return;
        }
        self.last_sample = Instant::now();
        match socket_kernel_drop_count(fd) {
            Ok(drops) => {
                let delta = drops.wrapping_sub(self.last_drops);
                self.last_drops = drops;
                crate::perf_profile::record_connected_udp_peer_kernel_drops(delta as u64);
            }
            Err(_) => {
                self.supported = false;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn socket_kernel_drop_count(fd: RawFd) -> io::Result<u32> {
    const MEMINFO_LEN: usize = (libc::SK_MEMINFO_DROPS as usize) + 1;
    let mut values: [u32; MEMINFO_LEN] = [0; MEMINFO_LEN];
    let mut len = std::mem::size_of_val(&values) as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MEMINFO,
            values.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let drop_offset = (libc::SK_MEMINFO_DROPS as usize + 1) * std::mem::size_of::<u32>();
    if (len as usize) < drop_offset {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "SO_MEMINFO did not include SK_MEMINFO_DROPS",
        ));
    }
    Ok(values[libc::SK_MEMINFO_DROPS as usize])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet_channel;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::Duration;

    struct RecordingFastPath {
        flushed_tx: mpsc::Sender<Vec<Vec<u8>>>,
    }

    struct RecordingFastPathBatcher {
        pending: Vec<Vec<u8>>,
        flushed_tx: mpsc::Sender<Vec<Vec<u8>>>,
    }

    struct DroppingFastPath {
        ptr_tx: mpsc::Sender<usize>,
    }

    struct DroppingFastPathBatcher {
        ptr_tx: mpsc::Sender<usize>,
    }

    struct IneligibleFastPath;

    struct IneligibleFastPathBatcher;

    impl ConnectedUdpPacketFastPath for RecordingFastPath {
        fn batcher(&self) -> Box<dyn ConnectedUdpPacketFastPathBatcher> {
            Box::new(RecordingFastPathBatcher {
                pending: Vec::new(),
                flushed_tx: self.flushed_tx.clone(),
            })
        }
    }

    impl ConnectedUdpPacketFastPath for DroppingFastPath {
        fn batcher(&self) -> Box<dyn ConnectedUdpPacketFastPathBatcher> {
            Box::new(DroppingFastPathBatcher {
                ptr_tx: self.ptr_tx.clone(),
            })
        }
    }

    impl ConnectedUdpPacketFastPath for IneligibleFastPath {
        fn batcher(&self) -> Box<dyn ConnectedUdpPacketFastPathBatcher> {
            Box::new(IneligibleFastPathBatcher)
        }
    }

    impl ConnectedUdpPacketFastPathBatcher for RecordingFastPathBatcher {
        fn try_dispatch(
            &mut self,
            _transport_id: TransportId,
            _remote_addr: TransportAddr,
            packet_data: PacketBuffer,
            _timestamp_ms: u64,
        ) -> Result<(), PacketBuffer> {
            self.pending.push(packet_data.into_vec());
            Ok(())
        }

        fn flush(&mut self) {
            if self.pending.is_empty() {
                return;
            }
            let packets = std::mem::take(&mut self.pending);
            self.flushed_tx
                .send(packets)
                .expect("recording fast path receiver should stay alive");
        }
    }

    impl ConnectedUdpPacketFastPathBatcher for DroppingFastPathBatcher {
        fn try_dispatch(
            &mut self,
            _transport_id: TransportId,
            _remote_addr: TransportAddr,
            packet_data: PacketBuffer,
            _timestamp_ms: u64,
        ) -> Result<(), PacketBuffer> {
            let ptr = packet_data.as_ptr() as usize;
            drop(packet_data);
            self.ptr_tx
                .send(ptr)
                .expect("dropping fast path receiver should stay alive");
            Ok(())
        }

        fn flush(&mut self) {}
    }

    impl ConnectedUdpPacketFastPathBatcher for IneligibleFastPathBatcher {
        fn try_dispatch(
            &mut self,
            _transport_id: TransportId,
            _remote_addr: TransportAddr,
            packet_data: PacketBuffer,
            _timestamp_ms: u64,
        ) -> Result<(), PacketBuffer> {
            Err(packet_data)
        }

        fn flush(&mut self) {}
    }

    #[test]
    fn connected_udp_drain_bulk_ring_parser_is_bounded() {
        assert_eq!(parse_connected_udp_drain_bulk_ring_packets(""), None);
        assert_eq!(
            parse_connected_udp_drain_bulk_ring_packets("not-a-number"),
            None
        );
        assert_eq!(
            parse_connected_udp_drain_bulk_ring_packets("1"),
            Some(MIN_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS)
        );
        assert_eq!(
            parse_connected_udp_drain_bulk_ring_packets("32768"),
            Some(32 * 1024)
        );
        assert_eq!(
            parse_connected_udp_drain_bulk_ring_packets("999999999"),
            Some(MAX_CONNECTED_UDP_DRAIN_BULK_RING_PACKETS)
        );
    }

    /// End-to-end: open a ConnectedPeerSocket, spawn a drain thread
    /// on it, send packets at it from a remote, verify they land in
    /// the packet_tx mpsc with the correct transport_id + peer_addr.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_delivers_packets_to_packet_tx() {
        // Peer (remote) — sends packets at our connected socket.
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");

        // Our connected socket. Use an ephemeral local port so we
        // don't conflict with anything else on the test host.
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = Arc::new(
            ConnectedPeerSocket::open(local_addr, peer_addr, 1 << 20, 1 << 20)
                .expect("ConnectedPeerSocket::open"),
        );

        // packet_tx for the drain thread to push into.
        let (tx, mut rx) = packet_channel(32);
        let transport_id = TransportId::new(42);

        // Find out what local_addr the kernel assigned to our socket
        // so the peer can sendto() it. Use getsockname; cast the
        // returned sockaddr_storage to sockaddr_in (we only test on
        // IPv4 loopback here, so this is safe).
        let our_local_addr: SocketAddr = {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let r = unsafe {
                libc::getsockname(
                    socket.as_raw_fd(),
                    &mut storage as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            assert!(r >= 0, "getsockname failed");
            assert_eq!(
                storage.ss_family as i32,
                libc::AF_INET,
                "test assumes IPv4 loopback"
            );
            let sin: &libc::sockaddr_in =
                unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
            let port = u16::from_be(sin.sin_port);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            SocketAddr::from((ip, port))
        };

        // Spawn the drain.
        let _drain = PeerRecvDrain::spawn(socket.clone(), transport_id, peer_addr, tx, None)
            .expect("PeerRecvDrain::spawn");

        // Send a couple of packets from the peer to our socket.
        for i in 0u8..5 {
            let payload = [i, 0xAA, 0xBB, 0xCC];
            peer.send_to(&payload, our_local_addr).expect("peer sendto");
        }

        // Verify the drain picked them up.
        for i in 0u8..5 {
            let pkt = tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout waiting for packet {i}"))
                .expect("packet channel closed");
            assert_eq!(pkt.transport_id, transport_id);
            assert_eq!(pkt.data.len(), 4);
            assert_eq!(pkt.data[0], i, "packet {i} payload mismatch");
        }
        // Drop the drain handle — should stop the thread within one
        // poll iteration.
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_flushes_connected_udp_fast_path_batches() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = Arc::new(
            ConnectedPeerSocket::open(local_addr, peer_addr, 1 << 20, 1 << 20)
                .expect("ConnectedPeerSocket::open"),
        );
        let our_local_addr: SocketAddr = {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let r = unsafe {
                libc::getsockname(
                    socket.as_raw_fd(),
                    &mut storage as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            assert!(r >= 0, "getsockname failed");
            assert_eq!(
                storage.ss_family as i32,
                libc::AF_INET,
                "test assumes IPv4 loopback"
            );
            let sin: &libc::sockaddr_in =
                unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
            let port = u16::from_be(sin.sin_port);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            SocketAddr::from((ip, port))
        };

        let (flushed_tx, flushed_rx) = mpsc::channel();
        let fast_path = Arc::new(RecordingFastPath { flushed_tx });
        let (tx, mut rx) = packet_channel(32);
        let _drain =
            PeerRecvDrain::spawn(socket, TransportId::new(42), peer_addr, tx, Some(fast_path))
                .expect("PeerRecvDrain::spawn");

        for i in 0u8..5 {
            let payload = [i, 0xDD, 0xEE, 0xFF];
            peer.send_to(&payload, our_local_addr).expect("peer sendto");
        }

        let mut observed = Vec::new();
        while observed.len() < 5 {
            let batch = flushed_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("timeout waiting for fast-path batch flush");
            observed.extend(batch);
        }

        assert_eq!(observed.len(), 5);
        for (i, packet) in observed.iter().enumerate() {
            assert_eq!(packet, &[i as u8, 0xDD, 0xEE, 0xFF]);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "fast-path-consumed packets must not also enter PacketRx"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_routes_fast_path_ineligible_packets_to_packet_rx() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = Arc::new(
            ConnectedPeerSocket::open(local_addr, peer_addr, 1 << 20, 1 << 20)
                .expect("ConnectedPeerSocket::open"),
        );
        let our_local_addr: SocketAddr = {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let r = unsafe {
                libc::getsockname(
                    socket.as_raw_fd(),
                    &mut storage as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            assert!(r >= 0, "getsockname failed");
            assert_eq!(
                storage.ss_family as i32,
                libc::AF_INET,
                "test assumes IPv4 loopback"
            );
            let sin: &libc::sockaddr_in =
                unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
            let port = u16::from_be(sin.sin_port);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            SocketAddr::from((ip, port))
        };

        let (tx, mut rx) = packet_channel(32);
        let _drain = PeerRecvDrain::spawn(
            socket,
            TransportId::new(42),
            peer_addr,
            tx,
            Some(Arc::new(IneligibleFastPath)),
        )
        .expect("PeerRecvDrain::spawn");

        for i in 0u8..3 {
            let payload = [i, 0x11, 0x22, 0x33];
            peer.send_to(&payload, our_local_addr).expect("peer sendto");
        }

        for i in 0u8..3 {
            let pkt = tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout waiting for ineligible packet {i}"))
                .expect("packet channel closed");
            assert_eq!(pkt.transport_id, TransportId::new(42));
            assert_eq!(pkt.data.as_ref(), &[i, 0x11, 0x22, 0x33]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_recycles_receive_buffer_when_fast_path_drops_packet() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = Arc::new(
            ConnectedPeerSocket::open(local_addr, peer_addr, 1 << 20, 1 << 20)
                .expect("ConnectedPeerSocket::open"),
        );
        let our_local_addr: SocketAddr = {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let r = unsafe {
                libc::getsockname(
                    socket.as_raw_fd(),
                    &mut storage as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            assert!(r >= 0, "getsockname failed");
            assert_eq!(
                storage.ss_family as i32,
                libc::AF_INET,
                "test assumes IPv4 loopback"
            );
            let sin: &libc::sockaddr_in =
                unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
            let port = u16::from_be(sin.sin_port);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            SocketAddr::from((ip, port))
        };

        let (ptr_tx, ptr_rx) = mpsc::channel();
        let fast_path = Arc::new(DroppingFastPath { ptr_tx });
        let (tx, _rx) = packet_channel(32);
        let _drain = PeerRecvDrain::spawn(
            socket,
            TransportId::new(42),
            peer_addr,
            tx.clone(),
            Some(fast_path),
        )
        .expect("PeerRecvDrain::spawn");

        peer.send_to(&[0xAA; 128], our_local_addr)
            .expect("peer sendto");
        let dropped_ptr = ptr_rx
            .recv_timeout(Duration::from_millis(500))
            .expect("timeout waiting for fast-path drop");
        let reused = tx.recv_buffer(CONNECTED_UDP_RECV_BUF_SIZE);
        assert_eq!(
            reused.as_ptr() as usize,
            dropped_ptr,
            "connected fast-path drops should recycle the receive buffer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_idle_drain_returns_promptly() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");
        let socket = Arc::new(
            ConnectedPeerSocket::open("127.0.0.1:0".parse().unwrap(), peer_addr, 1 << 20, 1 << 20)
                .expect("ConnectedPeerSocket::open"),
        );
        let (tx, _rx) = packet_channel(32);
        let drain = PeerRecvDrain::spawn(socket, TransportId::new(42), peer_addr, tx, None)
            .expect("PeerRecvDrain::spawn");

        let started = std::time::Instant::now();
        drop(drain);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "drain drop should not block the caller"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_error_is_consumed_so_poll_does_not_spin() {
        let closed_peer = UdpSocket::bind("127.0.0.1:0").expect("bind closed peer");
        let peer_addr = closed_peer.local_addr().expect("closed peer local_addr");
        drop(closed_peer);

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind connected socket");
        socket.connect(peer_addr).expect("connect to closed peer");
        socket
            .set_nonblocking(true)
            .expect("set connected socket nonblocking");
        socket.send(&[0xA5]).expect("send to closed peer");

        let fd = socket.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut saw_error = false;
        for _ in 0..100 {
            pfd.revents = 0;
            let r = unsafe { libc::poll(&mut pfd, 1, 10) };
            assert!(r >= 0, "poll failed: {}", io::Error::last_os_error());
            if pfd.revents & libc::POLLERR != 0 {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error, "connected UDP socket should report POLLERR");
        assert_eq!(
            pfd.revents & libc::POLLIN,
            0,
            "regression setup expects socket error without readable data"
        );

        let err = take_socket_error(fd)
            .expect("take socket error")
            .expect("pending socket error");
        assert_eq!(err.raw_os_error(), Some(libc::ECONNREFUSED));

        pfd.revents = 0;
        let r = unsafe { libc::poll(&mut pfd, 1, 0) };
        assert!(r >= 0, "poll after SO_ERROR failed");
        assert_eq!(
            pfd.revents & libc::POLLERR,
            0,
            "SO_ERROR must be consumed so poll stops waking in a tight loop"
        );
    }
}
