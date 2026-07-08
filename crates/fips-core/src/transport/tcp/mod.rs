//! TCP Transport Implementation
//!
//! Provides TCP-based transport for FIPS peer communication. TCP enables
//! firewall traversal (many networks allow TCP on port 443 but block UDP)
//! and serves as the foundation for the future Tor transport.
//!
//! FIPS protocols (FMP, FSP, MMP) are all unreliable datagrams. This
//! transport carries those datagrams over TCP — the main pathology is
//! head-of-line blocking, which adds latency jitter that MMP correctly
//! measures and cost-based parent selection correctly penalizes.
//!
//! ## Architecture
//!
//! Unlike UDP (one socket serves all peers), TCP requires one `TcpStream`
//! per peer. The transport maintains a connection pool mapping
//! `TransportAddr` to per-connection state, plus an optional `TcpListener`
//! for inbound connections.
//!
//! ## Framing
//!
//! Uses the existing 4-byte FMP common prefix to recover packet boundaries.
//! No additional framing overhead — packets are written directly to the
//! TCP stream and the receiver uses phase-dependent size computation.

pub mod stats;
pub mod stream;
mod tasks;

use tasks::{AcceptConfig, TcpReceiveContext, accept_loop, tcp_receive_loop};

use super::resolve_socket_addrs;
use super::{
    ConnectionState, DiscoveredPeer, PacketTx, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::TcpConfig;
use stats::TcpStats;

use futures::FutureExt;
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

// ============================================================================
// Connection Pool
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
}

/// State for a single TCP connection to a peer.
struct TcpConnection {
    /// Write half of the split stream.
    writer: Arc<Mutex<OwnedWriteHalf>>,
    /// Receive task for this connection.
    recv_task: JoinHandle<()>,
    direction: Direction,
}

/// Shared connection pool.
type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, TcpConnection>>>;

/// A pending background connection attempt.
///
/// Holds the JoinHandle for a spawned TCP connect task. The task
/// produces a configured `TcpStream` and MSS-derived MTU on success.
struct ConnectingEntry {
    /// Background task performing TCP connect + socket configuration.
    task: JoinHandle<Result<(TcpStream, u16), TransportError>>,
}

/// Map of addresses with background connection attempts in progress.
type ConnectingPool = Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>;

// ============================================================================
// TCP Transport
// ============================================================================

/// TCP transport for FIPS.
///
/// Provides connection-oriented, reliable byte stream delivery over TCP/IP.
/// Each peer has its own TCP connection; links are managed per-connection
/// with a connection pool keyed by `TransportAddr`.
pub struct TcpTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: TcpConfig,
    /// Current state.
    state: TransportState,
    /// Connection pool: addr -> established connections.
    pool: ConnectionPool,
    /// Pending connection attempts: addr -> background connect task.
    connecting: ConnectingPool,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Accept loop task handle (if listener bound).
    accept_task: Option<JoinHandle<()>>,
    /// Local listener address (after start, if bind_addr configured).
    local_addr: Option<SocketAddr>,
    /// Transport statistics.
    stats: Arc<TcpStats>,
}

impl TcpTransport {
    /// Create a new TCP transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: TcpConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            pool: Arc::new(Mutex::new(HashMap::new())),
            connecting: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            accept_task: None,
            local_addr: None,
            stats: Arc::new(TcpStats::new()),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the local listener address (only valid after start with bind_addr).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<TcpStats> {
        &self.stats
    }

    /// Start the transport asynchronously.
    ///
    /// If `bind_addr` is configured, binds a TCP listener and spawns
    /// the accept loop. Otherwise, operates in outbound-only mode.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        // Bind listener if configured
        if let Some(ref bind_addr) = self.config.bind_addr {
            let addr: SocketAddr = bind_addr
                .parse()
                .map_err(|e| TransportError::StartFailed(format!("invalid bind address: {}", e)))?;

            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| TransportError::StartFailed(format!("bind failed: {}", e)))?;

            self.local_addr = Some(
                listener
                    .local_addr()
                    .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?,
            );

            // Spawn accept loop
            let transport_id = self.transport_id;
            let packet_tx = self.packet_tx.clone();
            let pool = self.pool.clone();
            let stats = self.stats.clone();
            let cfg = AcceptConfig {
                mtu: self.config.mtu(),
                max_inbound: self.config.max_inbound_connections(),
                nodelay: self.config.nodelay(),
                keepalive_secs: self.config.keepalive_secs(),
                recv_buf: self.config.recv_buf_size(),
                send_buf: self.config.send_buf_size(),
                first_frame_timeout_ms: self.config.first_frame_timeout_ms(),
            };

            let accept_task = tokio::spawn(async move {
                accept_loop(listener, transport_id, packet_tx, pool, cfg, stats).await;
            });
            self.accept_task = Some(accept_task);
        }

        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                local_addr = ?self.local_addr,
                mtu = self.config.mtu(),
                "TCP transport started"
            );
        } else {
            info!(
                local_addr = ?self.local_addr,
                mtu = self.config.mtu(),
                "TCP transport started"
            );
        }

        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort accept loop
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Abort pending connection attempts
        let mut connecting = self.connecting.lock().await;
        for (addr, entry) in connecting.drain() {
            entry.task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "TCP connect aborted (transport stopping)"
            );
        }
        drop(connecting);

        // Close all established connections
        let mut pool = self.pool.lock().await;
        for (addr, conn) in pool.drain() {
            conn.recv_task.abort();
            let _ = conn.recv_task.await;
            match conn.direction {
                Direction::Inbound => self.stats.record_pool_inbound_removed(),
                Direction::Outbound => self.stats.record_pool_outbound_removed(),
            }
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                direction = ?conn.direction,
                "TCP connection closed (transport stopping)"
            );
        }
        drop(pool);

        self.local_addr = None;
        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "TCP transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// If no connection exists to the given address, performs connect-on-send:
    /// establishes a new TCP connection, configures socket options, splits the
    /// stream, spawns a receive task, and stores the connection in the pool.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Pre-send MTU check: reject oversize packets before writing them
        // to the TCP stream. Without this, the receiver's FMP stream reader
        // would see payload_len > max and close the connection, causing a
        // disruptive reset-reconnect cycle.
        let mtu = self.config.mtu() as usize;
        if data.len() > mtu {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        // Get or create connection
        let writer = {
            let pool = self.pool.lock().await;
            pool.get(addr).map(|c| c.writer.clone())
        };

        let writer = match writer {
            Some(w) => w,
            None => {
                // Connect-on-send
                self.connect(addr).await?
            }
        };

        // Write packet directly (no framing transformation needed)
        let mut w = writer.lock().await;
        match w.write_all(data).await {
            Ok(()) => {
                self.stats.record_send(data.len());
                trace!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    bytes = data.len(),
                    "TCP packet sent"
                );
                Ok(data.len())
            }
            Err(e) => {
                self.stats.record_send_error();
                drop(w);
                // Remove failed connection from pool
                let mut pool = self.pool.lock().await;
                if let Some(conn) = pool.remove(addr) {
                    conn.recv_task.abort();
                    match conn.direction {
                        Direction::Inbound => self.stats.record_pool_inbound_removed(),
                        Direction::Outbound => self.stats.record_pool_outbound_removed(),
                    }
                }
                Err(TransportError::SendFailed(format!("{}", e)))
            }
        }
    }

    /// Establish a new TCP connection to the given address.
    ///
    /// Configures socket options, reads TCP_MAXSEG for MTU, splits the
    /// stream, spawns a receive task, and stores in the pool.
    async fn connect(
        &self,
        addr: &TransportAddr,
    ) -> Result<Arc<Mutex<OwnedWriteHalf>>, TransportError> {
        let socket_addrs = resolve_socket_addrs(addr).await?;
        let timeout_ms = self.config.connect_timeout_ms();

        let stream = match connect_to_any_addr(&socket_addrs, timeout_ms).await {
            Ok(stream) => stream,
            Err(error @ TransportError::Timeout) => {
                self.stats.record_connect_timeout();
                return Err(error);
            }
            Err(error @ TransportError::ConnectionRefused) => {
                self.stats.record_connect_refused();
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        // Configure socket options via socket2
        let std_stream = stream
            .into_std()
            .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
        configure_socket(&std_stream, &self.config)?;

        // Read TCP_MAXSEG for per-connection MTU
        let mss_mtu = read_mss_mtu(&std_stream, self.config.mtu());

        // Convert back to tokio
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

        // Split and spawn receive task
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();
        let mtu = mss_mtu;

        let recv_task = tokio::spawn(async move {
            tcp_receive_loop(
                read_half,
                TcpReceiveContext {
                    transport_id,
                    remote_addr,
                    packet_tx,
                    pool,
                    mtu,
                    stats: recv_stats,
                    first_frame_timeout: None,
                    direction: Direction::Outbound,
                },
            )
            .await;
        });

        let conn = TcpConnection {
            writer: writer.clone(),
            recv_task,
            direction: Direction::Outbound,
        };

        let mut pool = self.pool.lock().await;
        pool.insert(addr.clone(), conn);

        self.stats.record_connection_established();
        self.stats.record_pool_outbound_added();

        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            mtu = mss_mtu,
            "TCP connection established (connect-on-send)"
        );

        Ok(writer)
    }

    /// Close a specific connection asynchronously.
    ///
    /// Removes the connection from the pool, aborts its receive task,
    /// and drops the write half (sends FIN to remote).
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.remove(addr) {
            conn.recv_task.abort();
            match conn.direction {
                Direction::Inbound => self.stats.record_pool_inbound_removed(),
                Direction::Outbound => self.stats.record_pool_outbound_removed(),
            }
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                direction = ?conn.direction,
                "TCP connection closed (close_connection)"
            );
        }
    }

    /// Initiate a non-blocking connection to a remote address.
    ///
    /// Spawns a background task that performs TCP connect with timeout,
    /// configures socket options, and reads MSS. The connection becomes
    /// available for `send_async()` once the task completes successfully.
    ///
    /// Poll `connection_state_sync()` to check progress.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Already established?
        {
            let pool = self.pool.lock().await;
            if pool.contains_key(addr) {
                return Ok(());
            }
        }

        // Already connecting?
        {
            let connecting = self.connecting.lock().await;
            if connecting.contains_key(addr) {
                return Ok(());
            }
        }

        let socket_addrs = resolve_socket_addrs(addr).await?;
        let timeout_ms = self.config.connect_timeout_ms();
        let config = self.config.clone();
        let transport_id = self.transport_id;
        let remote_addr = addr.clone();

        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            timeout_ms,
            "Initiating background TCP connect"
        );

        let task = tokio::spawn(async move {
            let stream = match connect_to_any_addr(&socket_addrs, timeout_ms).await {
                Ok(stream) => stream,
                Err(error @ TransportError::ConnectionRefused) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        error = %error,
                        "Background TCP connect refused"
                    );
                    return Err(error);
                }
                Err(error @ TransportError::Timeout) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        "Background TCP connect timed out"
                    );
                    return Err(error);
                }
                Err(error) => return Err(error),
            };

            // Configure socket options via socket2
            let std_stream = stream
                .into_std()
                .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
            configure_socket(&std_stream, &config)?;

            // Read TCP_MAXSEG for per-connection MTU
            let mss_mtu = read_mss_mtu(&std_stream, config.mtu());

            // Convert back to tokio
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

            Ok((stream, mss_mtu))
        });

        let mut connecting = self.connecting.lock().await;
        connecting.insert(addr.clone(), ConnectingEntry { task });

        Ok(())
    }

    /// Query the state of a connection to a remote address.
    ///
    /// Checks both established and connecting pools. If a background
    /// connect task has completed, promotes it to the established pool
    /// (spawning a receive loop) or reports the failure.
    ///
    /// This method is synchronous but uses `try_lock` internally.
    /// Returns `ConnectionState::Connecting` if locks can't be acquired.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        // Check established pool first
        if let Ok(pool) = self.pool.try_lock() {
            if pool.contains_key(addr) {
                return ConnectionState::Connected;
            }
        } else {
            return ConnectionState::Connecting; // can't tell, assume still going
        }

        // Check connecting pool
        let mut connecting = match self.connecting.try_lock() {
            Ok(c) => c,
            Err(_) => return ConnectionState::Connecting,
        };

        let entry = match connecting.get_mut(addr) {
            Some(e) => e,
            None => return ConnectionState::None,
        };

        // Check if the background task has completed
        if !entry.task.is_finished() {
            return ConnectionState::Connecting;
        }

        // Task is done — take the result and remove from connecting pool.
        // We need to poll the finished task. Since it's finished, we use
        // now_or_never to get the result without blocking.
        let addr_clone = addr.clone();
        let task = connecting.remove(&addr_clone).unwrap().task;

        // Use futures::FutureExt::now_or_never or block_on for the finished task.
        // Since the task is finished, we can safely poll it.
        match task.now_or_never() {
            Some(Ok(Ok((stream, mss_mtu)))) => {
                // Promote to established pool
                self.promote_connection(addr, stream, mss_mtu);
                ConnectionState::Connected
            }
            Some(Ok(Err(e))) => ConnectionState::Failed(format!("{}", e)),
            Some(Err(e)) => {
                // JoinError (panic or cancel)
                ConnectionState::Failed(format!("task failed: {}", e))
            }
            None => {
                // Shouldn't happen since is_finished() was true
                ConnectionState::Connecting
            }
        }
    }

    /// Promote a completed background connection to the established pool.
    ///
    /// Splits the stream, spawns a receive loop, and inserts into the pool.
    /// Called from `connection_state_sync()` when a background task completes.
    fn promote_connection(&self, addr: &TransportAddr, stream: TcpStream, mss_mtu: u16) {
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();

        let recv_task = tokio::spawn(async move {
            tcp_receive_loop(
                read_half,
                TcpReceiveContext {
                    transport_id,
                    remote_addr,
                    packet_tx,
                    pool,
                    mtu: mss_mtu,
                    stats: recv_stats,
                    first_frame_timeout: None,
                    direction: Direction::Outbound,
                },
            )
            .await;
        });

        let conn = TcpConnection {
            writer,
            recv_task,
            direction: Direction::Outbound,
        };

        // Use try_lock since we're in a sync context and the pool
        // should be available (connection_state_sync already checked it)
        if let Ok(mut pool) = self.pool.try_lock() {
            pool.insert(addr.clone(), conn);
            self.stats.record_connection_established();
            self.stats.record_pool_outbound_added();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                mtu = mss_mtu,
                "TCP connection established (background connect)"
            );
        } else {
            // Pool locked — abort the recv task, connection will be retried
            conn.recv_task.abort();
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Failed to promote connection (pool locked)"
            );
        }
    }
}

impl Transport for TcpTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::TCP
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn link_mtu(&self, _addr: &TransportAddr) -> u16 {
        // Per-link MTU would require synchronous pool access.
        // For now, return the configured default. The async send path
        // uses the per-connection MSS-derived MTU for validation.
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for TCP transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for TCP transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for TCP transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        // TCP has no discovery mechanism
        Ok(Vec::new())
    }

    fn accept_connections(&self) -> bool {
        // If bind_addr is configured, we accept inbound connections
        self.config.bind_addr.is_some()
    }
}

// ============================================================================
// Socket Configuration Helpers
// ============================================================================

async fn connect_to_any_addr(
    socket_addrs: &[SocketAddr],
    timeout_ms: u64,
) -> Result<TcpStream, TransportError> {
    let mut last_error = None;
    for socket_addr in socket_addrs {
        match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => {
                trace!(
                    remote_addr = %socket_addr,
                    error = %error,
                    "TCP connect candidate failed"
                );
                last_error = Some(TransportError::ConnectionRefused);
            }
            Err(_) => {
                trace!(
                    remote_addr = %socket_addr,
                    timeout_ms,
                    "TCP connect candidate timed out"
                );
                last_error = Some(TransportError::Timeout);
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| TransportError::InvalidAddress("no TCP addresses to dial".to_string())))
}

/// Configure a TCP socket with the transport's settings.
fn configure_socket(
    stream: &std::net::TcpStream,
    config: &TcpConfig,
) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream)
        .try_clone()
        .map_err(|e| TransportError::StartFailed(format!("clone socket: {}", e)))?;

    // TCP_NODELAY
    socket
        .set_tcp_nodelay(config.nodelay())
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    // Keepalive
    let keepalive_secs = config.keepalive_secs();
    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(keepalive_secs));
        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    // Buffer sizes
    socket
        .set_recv_buffer_size(config.recv_buf_size())
        .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
    socket
        .set_send_buffer_size(config.send_buf_size())
        .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

    Ok(())
}

/// Configure an accepted TCP socket (without TcpConfig reference).
fn configure_accepted_socket(
    stream: &std::net::TcpStream,
    nodelay: bool,
    keepalive_secs: u64,
    recv_buf: usize,
    send_buf: usize,
) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream)
        .try_clone()
        .map_err(|e| TransportError::StartFailed(format!("clone socket: {}", e)))?;

    socket
        .set_tcp_nodelay(nodelay)
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(keepalive_secs));
        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    socket
        .set_recv_buffer_size(recv_buf)
        .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
    socket
        .set_send_buffer_size(send_buf)
        .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

    Ok(())
}

/// Read TCP_MAXSEG and derive per-connection MTU, falling back to default.
fn read_mss_mtu(stream: &std::net::TcpStream, default_mtu: u16) -> u16 {
    // Try to read TCP_MAXSEG. Not all platforms support this.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let mut mss: libc::c_int = 0;
            let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let fd = stream.as_raw_fd();
            let ret = libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                &mut mss as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            );
            if ret == 0 && mss > 0 {
                let mss_mtu = (mss as u32).min(u16::MAX as u32) as u16;
                // Use the smaller of MSS and configured default
                return mss_mtu.min(default_mtu);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    let _ = stream;

    // Fallback: use configured default MTU
    default_mtu
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
