//! UDP Transport Implementation
//!
//! Provides UDP-based transport for FIPS peer communication.

#[cfg(target_os = "linux")]
use super::received_timestamp_ms;
use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod connected_peer;
#[cfg(target_os = "macos")]
pub(crate) mod darwin_sockopts;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod peer_drain;
pub(crate) mod socket;
mod stats;
use super::resolve_socket_addr;
use crate::config::UdpConfig;
use crate::discovery::is_punch_packet;
use socket::{AsyncUdpSocket, UdpRawSocket};
use stats::UdpStats;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// DNS cache TTL for hostname resolution (60 seconds).
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Datagrams drained per UDP receive syscall / connected-peer poll cycle.
///
/// Keep one receive-batch width across the wildcard socket, connected peer
/// drain threads, and Linux recvmmsg wrapper. WireGuard-go and Tailscale use
/// 128 as their ideal userspace packet batch, and the current measured
/// bottleneck is pre-`PacketRx` dequeue backlog, so a wider receive batch
/// reduces syscall/channel-item churn without changing the priority/bulk lane
/// contract at the packet channel boundary.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const UDP_RECV_BATCH_SIZE: usize = 128;

#[cfg(target_os = "linux")]
pub(crate) fn fresh_recv_buffer(size: usize) -> Vec<u8> {
    Vec::with_capacity(size)
}

#[cfg(target_os = "macos")]
pub(crate) fn fresh_recv_buffer(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

#[cfg(target_os = "linux")]
pub(crate) fn reset_recv_buffer(buffer: &mut Vec<u8>) {
    buffer.clear();
}

#[cfg(target_os = "macos")]
pub(crate) fn reset_recv_buffer(_buffer: &mut Vec<u8>) {}

fn socket_addr_families_compatible(local: SocketAddr, remote: SocketAddr) -> bool {
    matches!(
        (local, remote),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}

/// Threshold above which `send_async` triggers a sendmmsg flush
/// instead of just buffering. Matches the rx_loop's per-drain cap
/// (256) so the trailing-burst flush at the end of a drain cycle can
/// land in a single kernel syscall. The previous value (32) saw the
/// per-batch sendmmsg cost dominate at multi-Gbps single-stream: the
/// FIPS_PERF profile showed ~2.1 µs amortised per packet on the send
/// path (~37% of one core at 164 kpps) with threshold=32, almost all
/// UDP transport for FIPS.
///
/// Provides connectionless, unreliable packet delivery over UDP/IP.
/// A single socket serves all peers; links are virtual tuples of
/// (transport_id, remote_addr).
///
/// **No per-transport send buffering.** An earlier iteration of this
/// transport (commit 5929019) maintained a `pending_send` queue and
/// flushed it via `sendmmsg(2)` once a threshold was hit, in order
/// to amortise the per-syscall cost on the bulk-data hot path. That
/// path now flows through the encrypt worker pool — which does its
/// own `sendmmsg(2)` (target-grouped) directly on the raw fd — so
/// `send_async` is left handling only low-rate handshakes, MMP
/// reports, control messages, and rekeys (typical aggregate < 100
/// pps). The buffered version silently dropped packets in those
/// paths: idle tick / decrypt-fallback / control branches could leave
/// a heartbeat in the buffer until the next inbound batch arrived.
/// Result was MMP link-dead timeouts on idle peers + 60+ failing
/// integration tests (which construct `UdpTransport` outside the
/// rx_loop entirely). One sendmmsg-with-1 ≈ one sendto in kernel
/// time; the bulk path already gets real batching elsewhere.
pub struct UdpTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: UdpConfig,
    /// Current state.
    state: TransportState,
    /// Bound socket (None until started).
    socket: Option<AsyncUdpSocket>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Receive loop task handle.
    recv_task: Option<JoinHandle<()>>,
    /// Local bound address (after start).
    local_addr: Option<SocketAddr>,
    /// Transport statistics.
    stats: Arc<UdpStats>,
    /// DNS resolution cache for hostname addresses.
    dns_cache: StdMutex<HashMap<TransportAddr, (SocketAddr, Instant)>>,
}

impl UdpTransport {
    /// Create a new UDP transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: UdpConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            socket: None,
            packet_tx,
            recv_task: None,
            local_addr: None,
            stats: Arc::new(UdpStats::new()),
            dns_cache: StdMutex::new(HashMap::new()),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the local bound address (only valid after start).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Configured recv buffer size — used when opening per-peer
    /// `ConnectedPeerSocket`s so they get the same buffer ceiling as
    /// the wildcard listen socket.
    pub fn recv_buf_size(&self) -> usize {
        self.config.recv_buf_size()
    }

    /// Configured send buffer size — companion to `recv_buf_size`.
    pub fn send_buf_size(&self) -> usize {
        self.config.send_buf_size()
    }

    /// Clone the `PacketTx` end of the packet channel for off-task
    /// receive paths (per-peer connected-socket drains, future shard
    /// recv loops). The clone is just a refcount bump.
    pub fn clone_packet_tx(&self) -> PacketTx {
        self.packet_tx.clone()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<UdpStats> {
        &self.stats
    }

    /// Resolve a transport address (which may be a string like
    /// `"1.2.3.4:5678"` or a hostname) to a kernel `SocketAddr`,
    /// using the per-transport DNS cache. Public companion to
    /// `async_socket()` for off-task workers that want to skip the
    /// per-packet address parse / DNS lookup that `send_async` does
    /// inline. Returns `Err` if neither numeric parse nor DNS resolves
    /// the address.
    pub async fn resolve_for_off_task(
        &self,
        addr: &TransportAddr,
    ) -> Result<SocketAddr, TransportError> {
        self.resolve_cached(addr).await
    }

    /// Clone the underlying async UDP socket (internally an
    /// `Arc<AsyncFd<UdpRawSocket>>`, so the "clone" is just a refcount
    /// bump). Returns `None` if the transport hasn't been started yet.
    ///
    /// Intended for off-task workers that need to issue raw
    /// `send_to` / `send_batch` calls — useful when the AEAD
    /// encrypt + UDP-send pipeline is parallelised across N worker
    /// threads that each own a shared handle to the same kernel
    /// socket. The kernel serialises concurrent `sendto` calls
    /// itself, so concurrent userland sends are safe.
    pub fn async_socket(&self) -> Option<AsyncUdpSocket> {
        self.socket.clone()
    }

    /// Resolve a transport address, using cached results for hostnames.
    ///
    /// Numeric IP addresses bypass the cache entirely. Hostnames are
    /// resolved via DNS and cached for `DNS_CACHE_TTL` to avoid
    /// per-packet resolution overhead.
    async fn resolve_cached(&self, addr: &TransportAddr) -> Result<SocketAddr, TransportError> {
        // Fast path: try numeric IP parse (no cache, no DNS)
        if let Some(s) = addr.as_str()
            && let Ok(sock_addr) = s.parse::<SocketAddr>()
        {
            return Ok(sock_addr);
        }

        // Check cache
        {
            let cache = self.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((resolved, cached_at)) = cache.get(addr)
                && cached_at.elapsed() < DNS_CACHE_TTL
            {
                return Ok(*resolved);
            }
        }

        // Cache miss or expired — resolve via DNS
        let resolved = resolve_socket_addr(addr).await?;

        // Store in cache
        {
            let mut cache = self.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(addr.clone(), (resolved, Instant::now()));
        }

        Ok(resolved)
    }

    /// Query transport-local congestion indicators.
    pub fn congestion(&self) -> super::TransportCongestion {
        super::TransportCongestion {
            recv_drops: Some(
                self.stats
                    .kernel_drops
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }

    /// Start the transport asynchronously.
    ///
    /// Binds the UDP socket and spawns the receive loop.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        if self.config.outbound_only() && self.config.bind_addr.is_some() {
            warn!(
                configured_bind_addr = ?self.config.bind_addr,
                "udp.outbound_only = true; configured bind_addr is ignored, binding to 0.0.0.0:0"
            );
        }

        // Parse bind address
        let bind_addr: SocketAddr = self
            .config
            .bind_addr()
            .parse()
            .map_err(|e| TransportError::StartFailed(format!("invalid bind address: {}", e)))?;

        // Create, bind, and configure UDP socket
        let raw_socket = UdpRawSocket::open(
            bind_addr,
            self.config.recv_buf_size(),
            self.config.send_buf_size(),
        )?;

        let actual_recv = raw_socket.recv_buffer_size()?;
        let actual_send = raw_socket.send_buffer_size()?;
        self.local_addr = Some(raw_socket.local_addr());

        // Wrap in AsyncFd for tokio integration
        let async_socket = raw_socket.into_async()?;
        self.socket = Some(async_socket.clone());

        // Spawn receive loop
        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let mtu = self.config.mtu();
        let stats = self.stats.clone();

        let recv_task = tokio::spawn(async move {
            udp_receive_loop(async_socket, transport_id, packet_tx, mtu, stats).await;
        });

        self.recv_task = Some(recv_task);
        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                local_addr = %self.local_addr.map_or_else(|| "<unbound>".to_string(), |addr| addr.to_string()),
                recv_buf = actual_recv,
                send_buf = actual_send,
                "UDP transport started"
            );
        } else {
            info!(
                local_addr = %self.local_addr.map_or_else(|| "<unbound>".to_string(), |addr| addr.to_string()),
                recv_buf = actual_recv,
                send_buf = actual_send,
                "UDP transport started"
            );
        }

        Ok(())
    }

    /// Start the transport using an already-bound UDP socket.
    ///
    /// This preserves an existing NAT mapping established by another
    /// subsystem, such as STUN or UDP hole punching.
    pub async fn adopt_socket_async(
        &mut self,
        socket: std::net::UdpSocket,
    ) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        let raw_socket = UdpRawSocket::adopt(
            socket,
            self.config.recv_buf_size(),
            self.config.send_buf_size(),
        )?;

        let actual_recv = raw_socket.recv_buffer_size()?;
        let actual_send = raw_socket.send_buffer_size()?;
        self.local_addr = Some(raw_socket.local_addr());

        let async_socket = raw_socket.into_async()?;
        self.socket = Some(async_socket.clone());

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let mtu = self.config.mtu();
        let stats = self.stats.clone();

        let recv_task = tokio::spawn(async move {
            udp_receive_loop(async_socket, transport_id, packet_tx, mtu, stats).await;
        });

        self.recv_task = Some(recv_task);
        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                local_addr = %self.local_addr.map_or_else(|| "<unbound>".to_string(), |addr| addr.to_string()),
                recv_buf = actual_recv,
                send_buf = actual_send,
                "UDP transport adopted existing socket"
            );
        } else {
            info!(
                local_addr = %self.local_addr.map_or_else(|| "<unbound>".to_string(), |addr| addr.to_string()),
                recv_buf = actual_recv,
                send_buf = actual_send,
                "UDP transport adopted existing socket"
            );
        }

        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort receive task
        if let Some(task) = self.recv_task.take() {
            task.abort();
            let _ = task.await; // Ignore JoinError from abort
        }

        // Drop socket
        self.socket.take();
        self.local_addr = None;

        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "UDP transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// One syscall per call (`sendto(2)` on macOS / BSD, `sendmsg(2)`
    /// on Linux via the AsyncUdpSocket wrapper). No batching at this
    /// layer — see the module docs for why the previous buffered
    /// implementation was removed.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        if data.len() > self.config.mtu() as usize {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        let socket_addr = self.resolve_cached(addr).await?;
        let socket = self.socket.as_ref().ok_or(TransportError::NotStarted)?;
        let local_addr = self.local_addr.ok_or(TransportError::NotStarted)?;
        if !socket_addr_families_compatible(local_addr, socket_addr) {
            return Err(TransportError::InvalidAddress(format!(
                "remote address family {socket_addr} is incompatible with local UDP socket {local_addr}"
            )));
        }
        match socket.send_to(data, &socket_addr).await {
            Ok(bytes_sent) => {
                self.stats.record_send(bytes_sent);
                trace!(
                    transport_id = %self.transport_id,
                    remote_addr = %socket_addr,
                    bytes = bytes_sent,
                    "UDP packet sent"
                );
                Ok(bytes_sent)
            }
            Err(e) => {
                self.stats.record_send_error();
                Err(e)
            }
        }
    }
}

impl Transport for UdpTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::UDP
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        // Synchronous start not supported - use start_async()
        Err(TransportError::NotSupported(
            "use start_async() for UDP transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        // Synchronous stop not supported - use stop_async()
        Err(TransportError::NotSupported(
            "use stop_async() for UDP transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        // Synchronous send not supported - use send_async()
        Err(TransportError::NotSupported(
            "use send_async() for UDP transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        // UDP discovery not yet implemented (would use multicast/DNS-SD)
        // Peer configuration is handled at the node level, not transport level
        Ok(Vec::new())
    }

    /// Whether the transport accepts inbound handshake initiations.
    /// `outbound_only` mode forces this to false; otherwise reflects the
    /// `accept_connections` config field (default: true). Note that the
    /// hard gate is at the Node level (see ISSUE-2026-0004 fix in
    /// `src/node/handlers/handshake.rs`); this method is what that gate
    /// consults for transports that lack runtime-state-based filtering.
    fn accept_connections(&self) -> bool {
        if self.config.outbound_only() {
            false
        } else {
            self.config.accept_connections()
        }
    }
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        let had_task = self.recv_task.is_some();
        let had_socket = self.socket.is_some();
        if had_task || had_socket {
            debug!(
                transport_id = %self.transport_id,
                state = ?self.state,
                had_recv_task = had_task,
                had_socket = had_socket,
                "UdpTransport dropped without stop_async(); cleaning up",
            );
        }
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
        self.socket.take();
        self.local_addr = None;
    }
}

/// UDP receive loop - runs as a spawned task.
///
/// On Linux, drains the kernel UDP queue in `UDP_RECV_BATCH_SIZE` bursts via
/// `recvmmsg` to amortise the per-syscall + per-task-wakeup overhead. macOS /
/// Windows fall through to single-packet `recv_from`. Either way every
/// datagram is forwarded to `packet_tx` in arrival order.
async fn udp_receive_loop(
    socket: AsyncUdpSocket,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
    stats: Arc<UdpStats>,
) {
    debug!(transport_id = %transport_id, "UDP receive loop starting");

    #[cfg(target_os = "linux")]
    {
        const BATCH: usize = UDP_RECV_BATCH_SIZE;
        let buf_size = mtu as usize + 100;
        // Backing pool: one Vec<u8> per recvmmsg slot. We **own** each
        // slot here — when a packet lands, we `mem::replace` the filled
        // Vec out (handing the buffer directly to rx_loop via mpsc) and
        // drop in a fresh capacity-only Vec to refill that slot on the
        // next call.
        //
        // Previous code did `let data = buf.to_vec();` per packet,
        // which was 1 alloc + 1 memcpy of the entire packet (~1.5 KB)
        // for every received UDP datagram. At 100 kpps that's
        // ~150 MB/sec of avoidable memory bandwidth on the RX hot path.
        // The new code does the same alloc count (one fresh Vec to
        // refill the slot) but zero per-packet memcpy and no per-refill
        // memset on Linux — the receive buffer becomes the packet buffer
        // in one move.
        let mut backing: Vec<Vec<u8>> = (0..BATCH).map(|_| fresh_recv_buffer(buf_size)).collect();
        let mut addrs: [Option<std::net::SocketAddr>; BATCH] = std::array::from_fn(|_| None);

        loop {
            let recv_result = {
                let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpRecv);
                socket.recv_batch(&mut backing, &mut addrs).await
            };
            match recv_result {
                Ok((count, kernel_drops)) => {
                    stats.set_kernel_drops(kernel_drops as u64);
                    let timestamp_ms = received_timestamp_ms();
                    let trace_enqueued_at = crate::perf_profile::stamp();
                    let mut packets = Vec::with_capacity(count);
                    for i in 0..count {
                        let len = backing[i].len();
                        let Some(remote_addr) = addrs[i].take() else {
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        };
                        stats.record_recv(len);

                        // Peek before swap: punch probes / acks are
                        // discarded without consuming a buffer move.
                        if is_punch_packet(&backing[i][..len]) {
                            trace!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                "Dropping stray punch probe/ack on UDP transport"
                            );
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        }

                        // Move the filled buffer out of the slot and
                        // refill with a fresh one. `mem::replace`
                        // returns the OLD value and writes the new one
                        // — single pointer swap, no copy.
                        let data = std::mem::replace(&mut backing[i], fresh_recv_buffer(buf_size));
                        let addr = TransportAddr::from_socket_addr(remote_addr);
                        let packet = ReceivedPacket::with_trace_timestamp(
                            transport_id,
                            addr,
                            data,
                            timestamp_ms,
                            trace_enqueued_at,
                        );

                        trace!(
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            bytes = len,
                            "UDP packet received"
                        );

                        packets.push(packet);
                    }

                    if !packets.is_empty() && packet_tx.send_batch(packets).is_err() {
                        debug!(
                            transport_id = %transport_id,
                            "Packet channel closed, stopping receive loop"
                        );
                        return;
                    }
                }
                Err(e) => {
                    stats.record_recv_error();
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "UDP receive error"
                    );
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut buf = vec![0u8; mtu as usize + 100];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, remote_addr, kernel_drops)) => {
                    stats.record_recv(len);
                    stats.set_kernel_drops(kernel_drops as u64);

                    if is_punch_packet(&buf[..len]) {
                        trace!(
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            bytes = len,
                            "Dropping stray punch probe/ack on UDP transport"
                        );
                        continue;
                    }

                    let data = buf[..len].to_vec();
                    let addr = TransportAddr::from_socket_addr(remote_addr);
                    let packet = ReceivedPacket::new(transport_id, addr, data);

                    trace!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        bytes = len,
                        "UDP packet received"
                    );

                    if packet_tx.send(packet).is_err() {
                        debug!(
                            transport_id = %transport_id,
                            "Packet channel closed, stopping receive loop"
                        );
                        break;
                    }
                }
                Err(e) => {
                    stats.record_recv_error();
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "UDP receive error"
                    );
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
