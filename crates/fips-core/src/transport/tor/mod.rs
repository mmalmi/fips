//! Tor Transport Implementation
//!
//! Provides Tor-based transport for FIPS peer communication. Supports
//! three modes:
//!
//! - **socks5**: Outbound-only connections through a Tor SOCKS5 proxy
//!   to both clearnet peers and .onion hidden services.
//! - **control_port**: Outbound via SOCKS5 plus control port connection
//!   for Tor daemon monitoring (bootstrap status, traffic stats, network liveness).
//! - **directory**: Inbound via a Tor-managed `HiddenServiceDir` onion
//!   service, outbound via SOCKS5. No control port needed; enables
//!   Tor's `Sandbox 1` mode. Reads `.onion` address from hostname file.
//!
//! ## Architecture
//!
//! Like TCP, each peer has its own connection. The transport reuses FMP
//! stream framing from `tcp::stream` and follows the same connection pool
//! pattern as the TCP transport. Inbound connections arrive via a local
//! TCP listener that the Tor daemon forwards onion service traffic to.

pub mod control;
pub mod stats;

mod address;
#[cfg(test)]
mod mock_control;
#[cfg(test)]
mod mock_socks5;
mod monitoring;
mod tasks;
mod trait_impl;

#[cfg(test)]
mod tests;

use super::{
    ConnectionState, PacketTx, TransportAddr, TransportError, TransportId, TransportState,
};
use crate::config::TorConfig;
pub use address::TorAddr;
use address::{parse_tor_addr, validate_host_port};
use control::{ControlAuth, TorControlClient, TorMonitoringInfo};
use stats::TorStats;
use tasks::{configure_socket, tor_accept_loop, tor_receive_loop};

use futures::FutureExt;
use std::collections::HashMap;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, info, trace, warn};

// ============================================================================
// Connection Pool
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
}

/// State for a single Tor connection to a peer.
struct TorConnection {
    /// Write half of the split stream.
    writer: Arc<Mutex<OwnedWriteHalf>>,
    /// Receive task for this connection.
    recv_task: JoinHandle<()>,
    /// MTU for this connection.
    #[allow(dead_code)]
    mtu: u16,
    /// When the connection was established.
    #[allow(dead_code)]
    established_at: Instant,
    direction: Direction,
}

/// Shared connection pool.
type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, TorConnection>>>;

/// A pending background connection attempt.
///
/// Holds the JoinHandle for a spawned SOCKS5 connect task. The task
/// produces a configured `TcpStream` and MTU on success.
struct ConnectingEntry {
    /// Background task performing SOCKS5 connect + socket configuration.
    task: JoinHandle<Result<(TcpStream, u16), TransportError>>,
}

/// Map of addresses with background connection attempts in progress.
type ConnectingPool = Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>;

// ============================================================================
// Tor Transport
// ============================================================================

/// Tor transport for FIPS.
///
/// Provides connection-oriented, reliable byte stream delivery over Tor.
/// In `socks5` mode, outbound-only through a SOCKS5 proxy. In
/// `control_port` mode, also manages an onion service for inbound
/// connections via the Tor control port.
pub struct TorTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: TorConfig,
    /// Current state.
    state: TransportState,
    /// Connection pool: addr -> per-connection state.
    pool: ConnectionPool,
    /// Pending connection attempts: addr -> background connect task.
    connecting: ConnectingPool,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Transport statistics.
    stats: Arc<TorStats>,
    /// Accept loop task handle (active when onion service is running).
    accept_task: Option<JoinHandle<()>>,
    /// Onion service hostname (e.g., "abcdef...xyz.onion").
    /// Set in directory mode from the Tor-managed hostname file.
    onion_address: Option<String>,
    /// Control port client (monitoring queries).
    control_client: Option<Arc<Mutex<TorControlClient>>>,
    /// Cached Tor daemon monitoring info, updated by background task.
    cached_monitoring: Arc<std::sync::RwLock<Option<TorMonitoringInfo>>>,
    /// Background monitoring task handle.
    monitoring_task: Option<JoinHandle<()>>,
}

impl TorTransport {
    /// Create a new Tor transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: TorConfig,
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
            stats: Arc::new(TorStats::new()),
            accept_task: None,
            onion_address: None,
            control_client: None,
            cached_monitoring: Arc::new(std::sync::RwLock::new(None)),
            monitoring_task: None,
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the onion service address (if active).
    pub fn onion_address(&self) -> Option<&str> {
        self.onion_address.as_deref()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<TorStats> {
        &self.stats
    }

    /// Get the cached Tor daemon monitoring info (if available).
    pub fn cached_monitoring(&self) -> Option<TorMonitoringInfo> {
        self.cached_monitoring.read().ok()?.clone()
    }

    /// Get the Tor transport mode.
    pub fn mode(&self) -> &str {
        self.config.mode()
    }

    /// Start the transport asynchronously.
    ///
    /// In `socks5` mode: validates config and transitions to Up.
    /// In `control_port` mode: also connects to the Tor control port
    /// and authenticates for monitoring.
    /// In `directory` mode: reads .onion address from hostname file,
    /// binds a listener, and spawns an accept loop for inbound.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        // Validate SOCKS5 address format (all modes need it for outbound)
        let socks5_addr = self.config.socks5_addr().to_string();
        validate_host_port(&socks5_addr, "socks5_addr")?;

        let mode = self.config.mode().to_string();
        match mode.as_str() {
            "socks5" => {
                // Reject inbound service configs in socks5 mode
                if self.config.directory_service.is_some() {
                    return Err(TransportError::StartFailed(
                        "directory_service config requires mode 'directory', not 'socks5'".into(),
                    ));
                }
                self.state = TransportState::Up;
            }
            "control_port" => {
                self.start_control_port_mode().await?;
            }
            "directory" => {
                self.start_directory_mode().await?;
            }
            other => {
                return Err(TransportError::StartFailed(format!(
                    "unsupported Tor mode '{}' (expected 'socks5', 'control_port', or 'directory')",
                    other
                )));
            }
        }

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                mode = %mode,
                socks5_addr = %socks5_addr,
                onion_address = ?self.onion_address,
                mtu = self.config.mtu(),
                "Tor transport started"
            );
        } else {
            info!(
                mode = %mode,
                socks5_addr = %socks5_addr,
                onion_address = ?self.onion_address,
                mtu = self.config.mtu(),
                "Tor transport started"
            );
        }

        Ok(())
    }

    /// Start control_port mode: connect to control port and authenticate
    /// for monitoring queries.
    async fn start_control_port_mode(&mut self) -> Result<(), TransportError> {
        let control_addr = self.config.control_addr().to_string();
        // Unix socket paths start with / or ./ — skip host:port validation
        if !control_addr.starts_with('/') && !control_addr.starts_with("./") {
            validate_host_port(&control_addr, "control_addr")?;
        }

        // Connect to Tor control port
        let mut client = TorControlClient::connect(&control_addr)
            .await
            .map_err(|e| {
                self.stats.record_control_error();
                TransportError::StartFailed(format!("Tor control port: {}", e))
            })?;

        // Authenticate
        let auth = ControlAuth::from_config(self.config.control_auth(), self.config.cookie_path())
            .map_err(|e| TransportError::StartFailed(format!("Tor auth config: {}", e)))?;

        client.authenticate(&auth).await.map_err(|e| {
            self.stats.record_control_error();
            TransportError::StartFailed(format!("Tor authentication: {}", e))
        })?;

        // Store control client (used for monitoring queries)
        self.control_client = Some(Arc::new(Mutex::new(client)));
        self.state = TransportState::Up;
        self.spawn_monitoring_task();

        Ok(())
    }

    /// Start directory mode: read .onion address from Tor-managed hostname
    /// file, bind a local listener, and spawn the accept loop.
    ///
    /// In directory mode, Tor manages the onion service via `HiddenServiceDir`
    /// in torrc. No control port connection is needed. This enables Tor's
    /// `Sandbox 1` mode (strongest single hardening option).
    async fn start_directory_mode(&mut self) -> Result<(), TransportError> {
        let dir_config = self.config.directory_service.clone().unwrap_or_default();

        // Read .onion address from Tor-managed hostname file
        let hostname_file = dir_config.hostname_file();
        let onion_addr = std::fs::read_to_string(hostname_file)
            .map_err(|e| {
                TransportError::StartFailed(format!(
                    "failed to read onion hostname from '{}': {} \
                     (ensure HiddenServiceDir is configured in torrc and Tor has started)",
                    hostname_file, e
                ))
            })?
            .trim()
            .to_string();

        if onion_addr.is_empty() || !onion_addr.ends_with(".onion") {
            return Err(TransportError::StartFailed(format!(
                "invalid onion address in '{}': '{}'",
                hostname_file, onion_addr
            )));
        }

        self.onion_address = Some(onion_addr.clone());

        // Bind local listener (must match HiddenServicePort target in torrc)
        let bind_addr = dir_config.bind_addr();
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            TransportError::StartFailed(format!(
                "failed to bind directory-mode listener on {}: {}",
                bind_addr, e
            ))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| TransportError::StartFailed(format!("failed to get local addr: {}", e)))?;

        info!(
            onion_address = %onion_addr,
            local_addr = %local_addr,
            hostname_file = %hostname_file,
            "Directory-mode onion service active"
        );

        // Spawn accept loop (same as control_port mode)
        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let mtu = self.config.mtu();
        let max_inbound = self.config.max_inbound_connections();
        let stats = self.stats.clone();

        let accept_handle = tokio::spawn(async move {
            tor_accept_loop(
                listener,
                transport_id,
                packet_tx,
                pool,
                mtu,
                max_inbound,
                stats,
            )
            .await;
        });

        self.accept_task = Some(accept_handle);
        self.state = TransportState::Up;

        // Optionally connect to control port for monitoring (non-fatal)
        if self.config.control_addr.is_some() {
            self.try_connect_control_port().await;
        }

        Ok(())
    }

    /// Attempt to connect to the Tor control port for monitoring.
    /// Non-fatal: logs a warning on failure and continues without monitoring.
    async fn try_connect_control_port(&mut self) {
        let control_addr = self.config.control_addr().to_string();
        if !control_addr.starts_with('/')
            && !control_addr.starts_with("./")
            && let Err(e) = validate_host_port(&control_addr, "control_addr")
        {
            warn!(
                transport_id = %self.transport_id,
                error = %e,
                "Tor control port address invalid, monitoring disabled"
            );
            return;
        }

        let client = match TorControlClient::connect(&control_addr).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    transport_id = %self.transport_id,
                    addr = %control_addr,
                    error = %e,
                    "Tor control port connect failed, monitoring disabled"
                );
                return;
            }
        };

        let auth =
            match ControlAuth::from_config(self.config.control_auth(), self.config.cookie_path()) {
                Ok(a) => a,
                Err(e) => {
                    warn!(
                        transport_id = %self.transport_id,
                        error = %e,
                        "Tor control auth config error, monitoring disabled"
                    );
                    return;
                }
            };

        let mut client = client;
        if let Err(e) = client.authenticate(&auth).await {
            warn!(
                transport_id = %self.transport_id,
                error = %e,
                "Tor control port auth failed, monitoring disabled"
            );
            return;
        }

        info!(
            transport_id = %self.transport_id,
            addr = %control_addr,
            "Tor control port connected (monitoring enabled)"
        );

        self.control_client = Some(Arc::new(Mutex::new(client)));
        self.spawn_monitoring_task();
    }

    /// Stop the transport asynchronously.
    ///
    /// Aborts the accept loop (if running), closes all connections,
    /// and transitions to Down.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort accept loop (if running)
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
            debug!(
                transport_id = %self.transport_id,
                "Onion service accept loop stopped"
            );
        }

        // Abort monitoring task (if running)
        if let Some(task) = self.monitoring_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Ok(mut w) = self.cached_monitoring.write() {
            *w = None;
        }

        self.control_client = None;
        self.onion_address = None;

        // Abort pending connection attempts
        let mut connecting = self.connecting.lock().await;
        for (addr, entry) in connecting.drain() {
            entry.task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Tor connect aborted (transport stopping)"
            );
        }
        drop(connecting);

        // Close all connections
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
                "Tor connection closed (transport stopping)"
            );
        }
        drop(pool);

        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "Tor transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// If no connection exists to the given address, performs connect-on-send:
    /// establishes a new connection through the SOCKS5 proxy, configures
    /// socket options, splits the stream, spawns a receive task, and stores
    /// the connection in the pool.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Pre-send MTU check
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
                    "Tor packet sent"
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

    /// Establish a new connection through the SOCKS5 proxy.
    ///
    /// Performs SOCKS5 CONNECT to the target via the proxy, configures
    /// socket options, splits the stream, spawns a receive task, and
    /// stores in the pool.
    async fn connect(
        &self,
        addr: &TransportAddr,
    ) -> Result<Arc<Mutex<OwnedWriteHalf>>, TransportError> {
        let tor_addr = parse_tor_addr(addr)?;
        let proxy_addr = self.config.socks5_addr();
        let timeout_ms = self.config.connect_timeout_ms();

        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            proxy = %proxy_addr,
            timeout_secs = timeout_ms / 1000,
            "Connecting via Tor SOCKS5"
        );

        // SOCKS5 CONNECT through proxy with timeout.
        // Uses username/password auth for stream isolation: each destination
        // gets its own Tor circuit via IsolateSOCKSAuth. The credentials are
        // not verified by Tor — they serve purely as circuit isolation keys.
        let isolation_key = addr.to_string();
        let connect_start = Instant::now();
        let socks_result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            match &tor_addr {
                TorAddr::Onion(host, port) | TorAddr::ClearnetHostname(host, port) => {
                    Socks5Stream::connect_with_password(
                        proxy_addr,
                        (host.as_str(), *port),
                        "fips",
                        &isolation_key,
                    )
                    .await
                }
                TorAddr::Clearnet(socket_addr) => {
                    Socks5Stream::connect_with_password(
                        proxy_addr,
                        *socket_addr,
                        "fips",
                        &isolation_key,
                    )
                    .await
                }
            }
        })
        .await;

        let stream = match socks_result {
            Ok(Ok(socks_stream)) => socks_stream.into_inner(),
            Ok(Err(e)) => {
                self.stats.record_socks5_error();
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    error = %e,
                    elapsed_secs = connect_start.elapsed().as_secs(),
                    "Tor SOCKS5 connection failed"
                );
                return Err(TransportError::ConnectionRefused);
            }
            Err(_) => {
                self.stats.record_connect_timeout();
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    timeout_secs = timeout_ms / 1000,
                    "Tor SOCKS5 connection timed out"
                );
                return Err(TransportError::Timeout);
            }
        };

        // Configure socket options via socket2
        let std_stream = stream
            .into_std()
            .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
        configure_socket(&std_stream, &self.config)?;

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
        let mtu = self.config.mtu();

        let recv_task = tokio::spawn(async move {
            tor_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mtu,
                recv_stats,
                Direction::Outbound,
            )
            .await;
        });

        let conn = TorConnection {
            writer: writer.clone(),
            recv_task,
            mtu,
            established_at: Instant::now(),
            direction: Direction::Outbound,
        };

        let mut pool = self.pool.lock().await;
        pool.insert(addr.clone(), conn);

        self.stats.record_connection_established();
        self.stats.record_pool_outbound_added();

        info!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            elapsed_secs = connect_start.elapsed().as_secs(),
            "Tor circuit established via SOCKS5"
        );

        Ok(writer)
    }

    /// Initiate a non-blocking connection to a remote address.
    ///
    /// Spawns a background task that performs SOCKS5 connect with timeout,
    /// configures socket options, and returns the configured stream. The
    /// connection becomes available for `send_async()` once the task
    /// completes successfully.
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

        let tor_addr = parse_tor_addr(addr)?;
        let proxy_addr = self.config.socks5_addr().to_string();
        let timeout_ms = self.config.connect_timeout_ms();
        let transport_id = self.transport_id;
        let remote_addr = addr.clone();
        let config = self.config.clone();

        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            timeout_ms,
            "Initiating background Tor SOCKS5 connect"
        );

        // Stream isolation key for this destination
        let isolation_key = addr.to_string();

        let task = tokio::spawn(async move {
            // SOCKS5 CONNECT through proxy with timeout.
            // Uses username/password auth for stream isolation (see connect()).
            let socks_result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
                match &tor_addr {
                    TorAddr::Onion(host, port) | TorAddr::ClearnetHostname(host, port) => {
                        Socks5Stream::connect_with_password(
                            proxy_addr.as_str(),
                            (host.as_str(), *port),
                            "fips",
                            &isolation_key,
                        )
                        .await
                    }
                    TorAddr::Clearnet(socket_addr) => {
                        Socks5Stream::connect_with_password(
                            proxy_addr.as_str(),
                            *socket_addr,
                            "fips",
                            &isolation_key,
                        )
                        .await
                    }
                }
            })
            .await;

            let stream = match socks_result {
                Ok(Ok(socks_stream)) => socks_stream.into_inner(),
                Ok(Err(e)) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        error = %e,
                        "Background Tor SOCKS5 connect failed"
                    );
                    return Err(TransportError::ConnectionRefused);
                }
                Err(_) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        "Background Tor SOCKS5 connect timed out"
                    );
                    return Err(TransportError::Timeout);
                }
            };

            // Configure socket options via socket2
            let std_stream = stream
                .into_std()
                .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
            configure_socket(&std_stream, &config)?;

            let mtu = config.mtu();

            // Convert back to tokio
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

            Ok((stream, mtu))
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
        let addr_clone = addr.clone();
        let task = connecting.remove(&addr_clone).unwrap().task;

        // Since the task is finished, we can safely poll it with now_or_never.
        match task.now_or_never() {
            Some(Ok(Ok((stream, mtu)))) => {
                // Promote to established pool
                self.promote_connection(addr, stream, mtu);
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
    fn promote_connection(&self, addr: &TransportAddr, stream: TcpStream, mtu: u16) {
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();

        let recv_task = tokio::spawn(async move {
            tor_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mtu,
                recv_stats,
                Direction::Outbound,
            )
            .await;
        });

        let conn = TorConnection {
            writer,
            recv_task,
            mtu,
            established_at: Instant::now(),
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
                "Tor connection established (background connect)"
            );
        } else {
            // Pool locked — abort the recv task, connection will be retried
            conn.recv_task.abort();
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Failed to promote Tor connection (pool locked)"
            );
        }
    }

    /// Close a specific connection asynchronously.
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
                "Tor connection closed"
            );
        }
    }
}
