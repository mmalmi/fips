//! UDP Transport Implementation
//!
//! Provides UDP-based transport for FIPS peer communication.

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

/// Minimum interval between configured UDP socket rebuilds after the kernel
/// reports that the local route/source address is no longer usable.
const LOCAL_ROUTE_SOCKET_RECOVERY_COOLDOWN: Duration = Duration::from_secs(5);

/// `/proc/net/snmp` describes the whole Linux network namespace and is only a
/// diagnostic supplement to the socket's kernel drop counter. Sampling it on
/// every one-second node tick spends measurable idle CPU parsing the same
/// procfs table, so retain the last good value between bounded polls.
#[cfg(any(target_os = "linux", test))]
const LINUX_UDP_RCVBUF_ERRORS_POLL_INTERVAL: Duration = Duration::from_secs(10);

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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn debug_udp_fmp_batch(
    stage: &'static str,
    transport_id: TransportId,
    packets: &[ReceivedPacket],
    accepted_fast_ingress: Option<usize>,
) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }

    for packet in packets {
        let Ok(header) = crate::dataplane::FmpWireHeader::parse(packet.data.as_slice()) else {
            continue;
        };
        debug!(
            stage,
            transport_id = %transport_id,
            remote_addr = %packet.remote_addr,
            receiver_idx = header.receiver_idx(),
            counter = header.counter(),
            flags = header.flags(),
            bytes = packet.data.len(),
            accepted_fast_ingress,
            batch_packets = packets.len(),
            "UDP FMP receive handoff"
        );
    }
}

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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
                    let bytes = (offset..end)
                        .map(|batch_index| payloads.payload_len(batch_index))
                        .sum();
                    self.stats.record_send_batch(end - offset, bytes);
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
struct LinuxUdpRcvbufErrorSnapshot {
    baseline: u64,
    observed: u64,
    checked_at: Instant,
}

#[cfg(any(target_os = "linux", test))]
impl LinuxUdpRcvbufErrorSnapshot {
    fn new(initial: u64, checked_at: Instant) -> Self {
        Self {
            baseline: initial,
            observed: initial,
            checked_at,
        }
    }

    fn namespace_drops(&mut self, now: Instant, read: impl FnOnce() -> Option<u64>) -> u64 {
        if now.saturating_duration_since(self.checked_at) >= LINUX_UDP_RCVBUF_ERRORS_POLL_INTERVAL {
            self.checked_at = now;
            if let Some(observed) = read() {
                self.observed = observed;
            }
        }
        self.observed.saturating_sub(self.baseline)
    }
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
    /// How the active socket was created. Adopted sockets cannot be rebuilt
    /// without invalidating their NAT traversal handoff; exclusive sockets
    /// must retain their ownership semantics when rebuilt.
    socket_origin: UdpSocketOrigin,
    /// Last configured-socket rebuild after a local route error.
    last_local_route_socket_recovery: Option<Instant>,
    /// Transport statistics.
    stats: Arc<UdpStats>,
    /// Linux namespace-level UDP receive-buffer error baseline.
    ///
    /// This is broader than the wildcard socket. It is reported separately
    /// from `SO_RXQ_OVFL` so benchmark artifacts can distinguish this socket
    /// dropping from unrelated UDP receive-buffer pressure in the namespace.
    #[cfg(target_os = "linux")]
    udp_rcvbuf_errors: StdMutex<LinuxUdpRcvbufErrorSnapshot>,
    /// DNS resolution cache for hostname addresses.
    dns_cache: StdMutex<HashMap<TransportAddr, (SocketAddr, Instant)>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UdpSocketOrigin {
    Configured,
    Exclusive,
    Adopted,
}

impl UdpSocketOrigin {
    fn label(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Exclusive => "exclusive",
            Self::Adopted => "adopted",
        }
    }
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
            socket_origin: UdpSocketOrigin::Configured,
            last_local_route_socket_recovery: None,
            stats: Arc::new(UdpStats::new()),
            #[cfg(target_os = "linux")]
            udp_rcvbuf_errors: {
                let initial = linux_udp_rcvbuf_errors().unwrap_or(0);
                StdMutex::new(LinuxUdpRcvbufErrorSnapshot::new(initial, Instant::now()))
            },
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

    pub(crate) fn is_operator_routing_adjacency(&self, handshake_is_initiator: bool) -> bool {
        !handshake_is_initiator
            && self.config.is_public()
            && !self.config.outbound_only()
            && self.config.accept_connections()
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

    /// Return a numeric socket address without doing DNS on the caller's task.
    ///
    /// Numeric addresses resolve immediately. Hostnames are returned only when
    /// a recent send path has already populated this transport's DNS cache.
    pub(crate) fn resolved_socket_addr_if_cached(
        &self,
        addr: &TransportAddr,
    ) -> Option<SocketAddr> {
        if let Some(s) = addr.as_str()
            && let Ok(sock_addr) = s.parse::<SocketAddr>()
        {
            return Some(sock_addr);
        }

        let cache = self.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.get(addr).and_then(|(resolved, cached_at)| {
            (cached_at.elapsed() < DNS_CACHE_TTL).then_some(*resolved)
        })
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
        let socket_drops = self.stats.kernel_drops();
        #[cfg(target_os = "linux")]
        let namespace_drops = self
            .udp_rcvbuf_errors
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .namespace_drops(Instant::now(), linux_udp_rcvbuf_errors);
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
        self.start_bound_async(UdpSocketOrigin::Configured).await
    }

    /// Start with an exclusive bind on the configured UDP address.
    ///
    /// The bound socket remains the transport's live FIPS carrier, so the OS
    /// bind is also a durable ownership lock until this transport stops or the
    /// process exits. Callers can match [`TransportError::AddressInUse`] to
    /// distinguish losing the ownership election from other startup failures.
    pub async fn start_exclusive_async(&mut self) -> Result<(), TransportError> {
        self.start_bound_async(UdpSocketOrigin::Exclusive).await
    }

    async fn start_bound_async(&mut self, origin: UdpSocketOrigin) -> Result<(), TransportError> {
        debug_assert!(origin != UdpSocketOrigin::Adopted);
        self.begin_start(origin)?;

        if self.config.outbound_only() && self.config.bind_addr.is_some() {
            warn!(
                configured_bind_addr = ?self.config.bind_addr,
                "udp.outbound_only = true; configured bind_addr is ignored, binding to 0.0.0.0:0"
            );
        }

        let bind_addr =
            self.config.bind_addr().parse().map_err(|error| {
                TransportError::StartFailed(format!("invalid bind address: {error}"))
            });
        let bind_addr = self.require_start(bind_addr)?;
        let raw_socket = match origin {
            UdpSocketOrigin::Configured => UdpRawSocket::open(
                bind_addr,
                self.config.recv_buf_size(),
                self.config.send_buf_size(),
            ),
            UdpSocketOrigin::Exclusive => UdpRawSocket::open_exclusive(
                bind_addr,
                self.config.recv_buf_size(),
                self.config.send_buf_size(),
            ),
            UdpSocketOrigin::Adopted => unreachable!("checked above"),
        };

        let raw_socket = self.require_start(raw_socket)?;
        self.install_raw_socket(raw_socket, origin)
    }

    fn begin_start(&mut self, origin: UdpSocketOrigin) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;
        self.socket_origin = origin;
        Ok(())
    }

    fn require_start<T>(&mut self, result: Result<T, TransportError>) -> Result<T, TransportError> {
        if result.is_err() {
            self.state = TransportState::Failed;
            self.socket = None;
            self.recv_task = None;
            self.local_addr = None;
        }
        result
    }

    fn install_raw_socket(
        &mut self,
        raw_socket: UdpRawSocket,
        origin: UdpSocketOrigin,
    ) -> Result<(), TransportError> {
        let actual_recv = self.require_start(raw_socket.recv_buffer_size())?;
        let actual_send = self.require_start(raw_socket.send_buffer_size())?;
        self.local_addr = Some(raw_socket.local_addr());

        let async_socket = self.require_start(raw_socket.into_async())?;
        self.socket = Some(async_socket.clone());
        self.recv_task = Some(tokio::spawn(udp_receive_loop(
            async_socket,
            self.transport_id,
            self.packet_tx.clone(),
            self.config.mtu(),
            self.stats.clone(),
        )));
        self.state = TransportState::Up;

        info!(
            name = self.name.as_deref(),
            local_addr = %self.local_addr.map_or_else(|| "<unbound>".to_string(), |addr| addr.to_string()),
            recv_buf = actual_recv,
            send_buf = actual_send,
            socket_origin = origin.label(),
            "UDP transport started"
        );

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
        self.begin_start(UdpSocketOrigin::Adopted)?;

        let raw_socket = UdpRawSocket::adopt(
            socket,
            self.config.recv_buf_size(),
            self.config.send_buf_size(),
        );
        let raw_socket = self.require_start(raw_socket)?;
        self.install_raw_socket(raw_socket, UdpSocketOrigin::Adopted)
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

    /// Rebuild a configured UDP socket after the local route/source address
    /// backing it disappeared during an interface change.
    ///
    /// Darwin can keep returning `EADDRNOTAVAIL` from an otherwise wildcard-
    /// bound UDP socket after moving between Wi-Fi networks or a hotspot. Peer
    /// retry alone cannot heal that socket. Rebinding preserves the configured
    /// listen port while letting the kernel select the new underlay path.
    /// NAT-traversal sockets are excluded because recreating one would discard
    /// the established mapping. Exclusive sockets are also excluded: their
    /// live bind is an ownership lock and must never be dropped for recovery.
    pub(crate) async fn recover_local_route_socket(&mut self) -> Result<bool, TransportError> {
        if self.socket_origin != UdpSocketOrigin::Configured || !self.state.is_operational() {
            return Ok(false);
        }

        let now = Instant::now();
        if self
            .last_local_route_socket_recovery
            .is_some_and(|last| now.duration_since(last) < LOCAL_ROUTE_SOCKET_RECOVERY_COOLDOWN)
        {
            return Ok(false);
        }
        self.last_local_route_socket_recovery = Some(now);

        self.stop_async().await?;
        if let Err(error) = self.start_async().await {
            self.state = TransportState::Failed;
            return Err(error);
        }

        info!(
            transport_id = %self.transport_id,
            local_addr = %self.local_addr.map_or_else(|| "<unbound>".to_string(), |addr| addr.to_string()),
            "Rebuilt UDP transport after local route failure"
        );
        Ok(true)
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

include!("transport_impl.rs");
