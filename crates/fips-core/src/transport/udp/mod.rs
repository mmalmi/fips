//! UDP Transport Implementation
//!
//! Provides UDP-based transport for FIPS peer communication.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::received_timestamp_ms;
use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
#[cfg(target_os = "macos")]
pub(crate) mod darwin_sockopts;
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

/// Datagrams drained per UDP receive syscall.
///
/// WireGuard-go and Tailscale use 128 as their ideal userspace packet batch,
/// and the current measured bottleneck is pre-`PacketRx` dequeue backlog, so a
/// wider receive batch reduces syscall/channel-item churn without changing the
/// priority/bulk lane contract at the packet channel boundary.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) const UDP_RECV_BATCH_SIZE: usize = 128;

#[cfg(target_os = "linux")]
const UDP_GRO_RECV_BUFFER_SIZE: usize = u16::MAX as usize;

#[derive(Clone)]
pub(crate) struct UdpSendSnapshot {
    socket: AsyncUdpSocket,
    local_addr: SocketAddr,
    mtu: u16,
    stats: Arc<UdpStats>,
}

pub(crate) const UDP_PAYLOAD_MAX_SLICES: usize = 2;

pub(crate) trait UdpPayloadBatch {
    fn len(&self) -> usize;
    fn payload_len(&self, index: usize) -> usize;
    #[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
    fn contiguous_payload(&self, index: usize) -> Option<&[u8]>;
    fn payload_slices<'a>(
        &'a self,
        index: usize,
        out: &mut [Option<&'a [u8]>; UDP_PAYLOAD_MAX_SLICES],
    ) -> usize;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn copy_payload_into(&self, index: usize, out: &mut Vec<u8>) {
        out.clear();
        let mut slices = [None; UDP_PAYLOAD_MAX_SLICES];
        let slice_count = self.payload_slices(index, &mut slices);
        for slice in slices.iter().take(slice_count).flatten() {
            out.extend_from_slice(slice);
        }
    }
}

impl std::fmt::Debug for UdpSendSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSendSnapshot")
            .field("local_addr", &self.local_addr)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl UdpSendSnapshot {
    pub(crate) fn validate_packet(
        &self,
        data_len: usize,
        remote_addr: SocketAddr,
    ) -> Result<(), TransportError> {
        if data_len > self.mtu as usize {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data_len,
                mtu: self.mtu,
            });
        }
        if !socket_addr_families_compatible(self.local_addr, remote_addr) {
            return Err(TransportError::InvalidAddress(format!(
                "remote address family {remote_addr} is incompatible with local UDP socket {}",
                self.local_addr
            )));
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) async fn send_payload_batch_to<B>(
        &self,
        payloads: &B,
        remote_addr: SocketAddr,
    ) -> usize
    where
        B: UdpPayloadBatch + ?Sized,
    {
        let packet_count = payloads.len();
        if packet_count == 0 {
            return 0;
        }

        let mut failed = 0usize;
        let mut offset = 0usize;
        while offset < packet_count {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
            match self
                .socket
                .send_batch_to(payloads, offset, remote_addr)
                .await
            {
                Ok(0) => {
                    self.stats.record_send_error();
                    failed = failed.saturating_add(packet_count.saturating_sub(offset));
                    break;
                }
                Ok(sent) => {
                    let end = offset.saturating_add(sent).min(packet_count);
                    for batch_index in offset..end {
                        self.stats.record_send(payloads.payload_len(batch_index));
                    }
                    offset = end;
                }
                Err(_) => {
                    self.stats.record_send_error();
                    failed = failed.saturating_add(packet_count.saturating_sub(offset));
                    break;
                }
            }
        }
        failed
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) async fn send_payload_batch_to<B>(
        &self,
        payloads: &B,
        remote_addr: SocketAddr,
    ) -> usize
    where
        B: UdpPayloadBatch + ?Sized,
    {
        let mut failed = 0usize;
        let mut scratch = Vec::new();
        for index in 0..payloads.len() {
            let expected_len = payloads.payload_len(index);
            let data = match payloads.contiguous_payload(index) {
                Some(data) => data,
                None => {
                    payloads.copy_payload_into(index, &mut scratch);
                    scratch.as_slice()
                }
            };
            let result = self.socket.send_to(data, &remote_addr).await;
            if let Ok(bytes_sent) = result {
                debug_assert_eq!(bytes_sent, expected_len);
                self.stats.record_send(bytes_sent);
            } else {
                self.stats.record_send_error();
                failed = failed.saturating_add(1);
            }
        }
        failed
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn reset_recv_buffer(buffer: &mut Vec<u8>) {
    buffer.clear();
}

#[cfg(target_os = "linux")]
fn udp_gro_segment_count(len: usize, segment_size: usize) -> usize {
    if len == 0 || segment_size == 0 {
        0
    } else {
        len.div_ceil(segment_size)
    }
}

#[cfg(target_os = "linux")]
fn linux_udp_rcvbuf_errors() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/net/snmp").ok()?;
    parse_proc_net_snmp_udp_rcvbuf_errors(&contents)
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_snmp_udp_rcvbuf_errors(contents: &str) -> Option<u64> {
    let mut lines = contents.lines();
    while let Some(header) = lines.next() {
        if !header.starts_with("Udp:") {
            continue;
        }
        let values = lines.next()?;
        if !values.starts_with("Udp:") {
            continue;
        }
        let header_fields: Vec<&str> = header.split_whitespace().collect();
        let value_fields: Vec<&str> = values.split_whitespace().collect();
        let idx = header_fields
            .iter()
            .position(|field| *field == "RcvbufErrors")?;
        return value_fields.get(idx)?.parse().ok();
    }
    None
}

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
/// path now flows through dataplane — which does its own
/// `sendmmsg(2)` (target-grouped) directly on the raw fd — so
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
    /// Linux namespace-level UDP receive-buffer error baseline.
    ///
    /// This is broader than the wildcard socket. It is reported separately
    /// from `SO_RXQ_OVFL` so benchmark artifacts can distinguish this socket
    /// dropping from unrelated UDP receive-buffer pressure in the namespace.
    #[cfg(target_os = "linux")]
    udp_rcvbuf_error_baseline: u64,
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
            #[cfg(target_os = "linux")]
            udp_rcvbuf_error_baseline: linux_udp_rcvbuf_errors().unwrap_or(0),
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

    /// Configured recv buffer size.
    pub fn recv_buf_size(&self) -> usize {
        self.config.recv_buf_size()
    }

    /// Configured send buffer size.
    pub fn send_buf_size(&self) -> usize {
        self.config.send_buf_size()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<UdpStats> {
        &self.stats
    }

    /// Resolve a transport address (which may be a string like
    /// `"1.2.3.4:5678"` or a hostname) to a kernel `SocketAddr`,
    /// using the per-transport DNS cache. Public companion to
    /// `send_async` does inline. Returns `Err` if neither numeric parse nor DNS
    /// resolves the address.
    pub async fn resolve_for_off_task(
        &self,
        addr: &TransportAddr,
    ) -> Result<SocketAddr, TransportError> {
        self.resolve_cached(addr).await
    }

    pub(crate) fn send_snapshot(&self) -> Result<UdpSendSnapshot, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        let Some(socket) = self.socket.clone() else {
            return Err(TransportError::NotStarted);
        };
        let Some(local_addr) = self.local_addr else {
            return Err(TransportError::NotStarted);
        };
        Ok(UdpSendSnapshot {
            socket,
            local_addr,
            mtu: self.config.mtu(),
            stats: Arc::clone(&self.stats),
        })
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
        let socket_drops = self
            .stats
            .kernel_drops
            .load(std::sync::atomic::Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        let namespace_drops = linux_udp_rcvbuf_errors()
            .unwrap_or(self.udp_rcvbuf_error_baseline)
            .saturating_sub(self.udp_rcvbuf_error_baseline);
        #[cfg(target_os = "linux")]
        let recv_drops = socket_drops.max(namespace_drops);
        #[cfg(not(target_os = "linux"))]
        let recv_drops = socket_drops;

        super::TransportCongestion {
            recv_drops: Some(recv_drops),
            socket_recv_drops: Some(socket_drops),
            #[cfg(target_os = "linux")]
            namespace_recv_drops: Some(namespace_drops),
            #[cfg(not(target_os = "linux"))]
            namespace_recv_drops: None,
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
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
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
/// `recvmmsg` to amortise the per-syscall + per-task-wakeup overhead. macOS
/// uses Darwin `recvmsg_x` for the same batching shape. Windows falls through
/// to single-packet `recv_from`. Either way every
/// datagram is forwarded to `packet_tx` in arrival order.
async fn udp_receive_loop(
    socket: AsyncUdpSocket,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
    stats: Arc<UdpStats>,
) {
    debug!(transport_id = %transport_id, "UDP receive loop starting");

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn cached_transport_addr(
        cache: &mut Vec<(SocketAddr, TransportAddr)>,
        remote_addr: SocketAddr,
    ) -> TransportAddr {
        if let Some((_, addr)) = cache
            .iter()
            .find(|(socket_addr, _)| *socket_addr == remote_addr)
        {
            return addr.clone();
        }

        const UDP_ADDR_CACHE_CAP: usize = 16;
        let addr = TransportAddr::from_socket_addr(remote_addr);
        if cache.len() >= UDP_ADDR_CACHE_CAP {
            cache.remove(0);
        }
        cache.push((remote_addr, addr.clone()));
        addr
    }

    #[cfg(target_os = "linux")]
    {
        const BATCH: usize = UDP_RECV_BATCH_SIZE;
        let packet_buf_size = mtu as usize + 100;
        let udp_gro_enabled = socket.udp_gro_enabled();
        let recv_buf_size = if udp_gro_enabled {
            UDP_GRO_RECV_BUFFER_SIZE
        } else {
            packet_buf_size
        };
        // Backing pool: one Vec<u8> per recvmmsg slot. Without UDP_GRO,
        // when a packet lands we `mem::replace` the filled Vec out
        // (handing the buffer directly to rx_loop via mpsc) and drop in
        // a fresh capacity-only Vec to refill that slot on the next call.
        //
        // Previous code did `let data = buf.to_vec();` per packet,
        // which was 1 alloc + 1 memcpy of the entire packet (~1.5 KB)
        // for every received UDP datagram. At 100 kpps that's
        // ~150 MB/sec of avoidable memory bandwidth on the RX hot path.
        // With UDP_GRO enabled, the backing slot is large enough for a
        // coalesced kernel receive and is split back into ordinary FIPS
        // datagrams before dataplane fast ingress or packet-channel delivery.
        let mut backing: Vec<Vec<u8>> = (0..BATCH)
            .map(|_| packet_tx.recv_buffer(recv_buf_size))
            .collect();
        let mut addrs: [Option<std::net::SocketAddr>; BATCH] = std::array::from_fn(|_| None);
        let mut gro_segment_sizes = [0usize; BATCH];
        let mut addr_cache: Vec<(SocketAddr, TransportAddr)> = Vec::new();

        loop {
            let recv_result = {
                let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpRecv);
                socket
                    .recv_batch(&mut backing, &mut addrs, &mut gro_segment_sizes)
                    .await
            };
            match recv_result {
                Ok((count, kernel_drops)) => {
                    stats.set_kernel_drops(kernel_drops as u64);
                    let timestamp_ms = received_timestamp_ms();
                    let trace_enqueued_at = crate::perf_profile::stamp();
                    let mut packets = packet_tx.packet_batch(count);
                    for i in 0..count {
                        let len = backing[i].len();
                        let gro_segment_size = gro_segment_sizes[i];
                        gro_segment_sizes[i] = 0;
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

                        if gro_segment_size == 0 && len > packet_buf_size {
                            stats.record_recv_error();
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                packet_buf_size = packet_buf_size,
                                "Dropping oversized UDP receive without GRO segment metadata"
                            );
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        }
                        if gro_segment_size > packet_buf_size {
                            stats.record_recv_error();
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                gro_segment_size = gro_segment_size,
                                packet_buf_size = packet_buf_size,
                                "Dropping UDP GRO receive with oversized segment"
                            );
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        }

                        let addr = cached_transport_addr(&mut addr_cache, remote_addr);
                        let gro_segment_count = udp_gro_segment_count(len, gro_segment_size);
                        if gro_segment_count > 1 {
                            crate::perf_profile::record_udp_recv_gro_split(gro_segment_count, len);
                            let source = &backing[i][..len];
                            let mut start = 0usize;
                            while start < source.len() {
                                let end = start.saturating_add(gro_segment_size).min(source.len());
                                let mut data = packet_tx.recv_buffer(end - start);
                                data.extend_from_slice(&source[start..end]);
                                packets.push(ReceivedPacket::with_trace_timestamp(
                                    transport_id,
                                    addr.clone(),
                                    packet_tx.packet_buffer(data),
                                    timestamp_ms,
                                    trace_enqueued_at,
                                ));
                                start = end;
                            }
                            reset_recv_buffer(&mut backing[i]);
                            trace!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                gro_segment_size = gro_segment_size,
                                gro_segments = gro_segment_count,
                                "UDP GRO packet split"
                            );
                            continue;
                        }

                        crate::perf_profile::record_udp_recv_plain_packet();
                        let data = if recv_buf_size == packet_buf_size {
                            // Move the filled buffer out of the slot and
                            // refill with a fresh one. `mem::replace`
                            // returns the OLD value and writes the new one
                            // — single pointer swap, no copy.
                            std::mem::replace(&mut backing[i], packet_tx.recv_buffer(recv_buf_size))
                        } else {
                            let mut data = packet_tx.recv_buffer(len);
                            data.extend_from_slice(&backing[i][..len]);
                            reset_recv_buffer(&mut backing[i]);
                            data
                        };
                        let packet = ReceivedPacket::with_trace_timestamp(
                            transport_id,
                            addr,
                            packet_tx.packet_buffer(data),
                            timestamp_ms,
                            trace_enqueued_at,
                        );

                        trace!(
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            bytes = len,
                            gro_segment_size = gro_segment_size,
                            "UDP packet received"
                        );

                        packets.push(packet);
                    }

                    packet_tx.try_fast_ingress_packet_batch(&mut packets);
                    if !packets.is_empty() && packet_tx.send_packet_batch(packets).is_err() {
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

    #[cfg(target_os = "macos")]
    {
        const BATCH: usize = UDP_RECV_BATCH_SIZE;
        let buf_size = mtu as usize + 100;
        let mut backing: Vec<Vec<u8>> = (0..BATCH)
            .map(|_| packet_tx.recv_buffer(buf_size))
            .collect();
        let mut addrs: [Option<std::net::SocketAddr>; BATCH] = std::array::from_fn(|_| None);
        let mut gro_segment_sizes = [0usize; BATCH];
        let mut addr_cache: Vec<(SocketAddr, TransportAddr)> = Vec::new();

        loop {
            match socket
                .recv_batch(&mut backing, &mut addrs, &mut gro_segment_sizes)
                .await
            {
                Ok((count, kernel_drops)) => {
                    stats.set_kernel_drops(kernel_drops as u64);
                    let timestamp_ms = received_timestamp_ms();
                    let trace_enqueued_at = crate::perf_profile::stamp();
                    let mut packets = packet_tx.packet_batch(count);
                    for i in 0..count {
                        let len = backing[i].len();
                        gro_segment_sizes[i] = 0;
                        let Some(remote_addr) = addrs[i].take() else {
                            backing[i].clear();
                            continue;
                        };
                        stats.record_recv(len);

                        if is_punch_packet(&backing[i][..len]) {
                            trace!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                "Dropping stray punch probe/ack on UDP transport"
                            );
                            backing[i].clear();
                            continue;
                        }

                        let data =
                            std::mem::replace(&mut backing[i], packet_tx.recv_buffer(buf_size));
                        let addr = cached_transport_addr(&mut addr_cache, remote_addr);
                        let packet = ReceivedPacket::with_trace_timestamp(
                            transport_id,
                            addr,
                            packet_tx.packet_buffer(data),
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
                    packet_tx.try_fast_ingress_packet_batch(&mut packets);
                    if packets.is_empty() {
                        continue;
                    }
                    if packet_tx.send_packet_batch(packets).is_err() {
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

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let mut buf = vec![0u8; mtu as usize + 100];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, remote_addr, kernel_drops, _gro_segment_size)) => {
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

                    let mut packets = packet_tx.packet_batch(1);
                    packets.push(packet);
                    packet_tx.try_fast_ingress_packet_batch(&mut packets);
                    if packets.is_empty() {
                        continue;
                    }
                    if packet_tx.send_packet_batch(packets).is_err() {
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
