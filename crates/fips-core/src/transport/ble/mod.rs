//! BLE L2CAP Transport Implementation
//!
//! Provides BLE-based transport for FIPS peer communication using L2CAP
//! Connection-Oriented Channels (CoC). A small GATT bootstrap record exposes
//! the dynamically assigned PSM and packet limit. FIPS BLE framing preserves
//! packet boundaries across both SeqPacket and byte-stream platform APIs.
//!
//! ## Architecture
//!
//! Transport logic (pool, discovery, lifecycle) is separated from the
//! BlueZ/bluer and mobile platform stacks via the `BleIo` trait. `BluerIo`
//! provides the Linux implementation, `HostBleIo` bridges Android and Apple
//! APIs, and `MockBleIo` provides an in-memory test double.
//!
//! ## Connection Pool
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum (default 7) with priority eviction:
//! static (configured) peers get priority over discovered peers.

pub mod addr;
pub mod bootstrap;
pub mod discovery;
pub mod framing;
#[cfg(feature = "host-ble-transport")]
pub mod host;
pub mod io;
pub mod pool;
pub mod stats;
mod tasks;

use tasks::{
    AcceptLoopContext, ScanProbeContext, accept_loop, pubkey_exchange, receive_loop,
    scan_probe_loop,
};

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::BleConfig;
use crate::identity::NodeAddr;
use addr::BleAddr;
use discovery::DiscoveryBuffer;
use framing::FramedBleStream;
use io::{BleAcceptor, BleIo, BleStream};
use pool::{BleConnection, ConnectionPool};
use stats::BleStats;

use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

pub(super) type SharedBlePool<S> = Arc<Mutex<ConnectionPool<Arc<FramedBleStream<S>>>>>;

/// Default FIPS L2CAP PSM (Protocol Service Multiplexer).
///
/// 0x0085 (133) is in the dynamic range (0x0080-0x00FF).
pub const DEFAULT_PSM: u16 = 0x0085;

/// Concrete BLE transport type for use in TransportHandle.
///
/// Host-feature builds use the command adapter, glibc-linux production builds
/// use BlueZ, and tests plus unsupported targets use the mock adapter.
#[cfg(feature = "host-ble-transport")]
pub type DefaultBleTransport = BleTransport<host::HostBleIo>;

#[cfg(all(not(feature = "host-ble-transport"), bluer_available, not(test)))]
pub type DefaultBleTransport = BleTransport<io::BluerIo>;

#[cfg(all(not(feature = "host-ble-transport"), any(not(bluer_available), test)))]
pub type DefaultBleTransport = BleTransport<io::MockBleIo>;

// ============================================================================
// BLE Transport
// ============================================================================

/// BLE transport for FIPS.
///
/// Provides connection-oriented, reliable delivery over BLE L2CAP CoC.
/// Each peer has its own L2CAP connection; the pool enforces hardware
/// connection limits with priority eviction.
pub struct BleTransport<I: BleIo> {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name.
    name: Option<String>,
    /// Configuration.
    config: BleConfig,
    /// Current state.
    state: TransportState,
    /// BLE I/O implementation (BluerIo or MockBleIo).
    io: Arc<I>,
    /// Established connection pool.
    pool: SharedBlePool<I::Stream>,
    /// Pending connection attempts.
    connecting: Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Accept loop task handle.
    accept_task: Option<JoinHandle<()>>,
    /// Combined scan + probe loop task handle.
    scan_probe_task: Option<JoinHandle<()>>,
    /// Discovery buffer for discovered peers.
    discovery_buffer: Arc<DiscoveryBuffer>,
    /// Transport statistics.
    stats: Arc<BleStats>,
    /// Our public key for pre-handshake identity exchange.
    ///
    /// BLE advertisements carry only the FIPS UUID, not the pubkey.
    /// After L2CAP connection, both sides exchange `[0x00][pubkey:32]`
    /// so the node layer can initiate the IK handshake.
    /// Temporary — removed when FMP switches to XX.
    local_pubkey: Option<[u8; 32]>,
}

/// A pending background connection attempt.
struct ConnectingEntry {
    task: JoinHandle<()>,
}

impl<I: BleIo> BleTransport<I> {
    /// Create a new BLE transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: BleConfig,
        io: I,
        packet_tx: PacketTx,
    ) -> Self {
        let max_conns = config.max_connections();
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            io: Arc::new(io),
            pool: Arc::new(Mutex::new(ConnectionPool::new(max_conns))),
            connecting: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            accept_task: None,
            scan_probe_task: None,
            discovery_buffer: Arc::new(DiscoveryBuffer::new(transport_id)),
            stats: Arc::new(BleStats::new()),
            local_pubkey: None,
        }
    }

    /// Get the instance name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<BleStats> {
        &self.stats
    }

    /// Get the I/O implementation (for test injection).
    pub fn io(&self) -> &Arc<I> {
        &self.io
    }

    /// Set the local public key for pre-handshake identity exchange.
    ///
    /// Must be called before `start_async()`. Without this, BLE
    /// connections skip the pubkey exchange and discovered peers
    /// won't have identity information for auto-connect.
    pub fn set_local_pubkey(&mut self, pubkey: [u8; 32]) {
        self.local_pubkey = Some(pubkey);
    }

    /// Start the transport asynchronously.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;

        let preferred_psm = self.config.psm();
        let mut listener_psm = preferred_psm;
        let adapter = self.io.adapter_name().to_string();

        // Pre-compute local NodeAddr for cross-probe tie-breaking
        let local_node_addr = self.local_pubkey.and_then(|pk| {
            XOnlyPublicKey::from_slice(&pk)
                .ok()
                .map(|xonly| NodeAddr::from_pubkey(&xonly))
        });

        // Start L2CAP listener for inbound connections
        if self.config.accept_connections() {
            match self.io.listen(preferred_psm).await {
                Ok(acceptor) => {
                    listener_psm = acceptor.psm();
                    self.accept_task = Some(tokio::spawn(accept_loop(
                        acceptor,
                        AcceptLoopContext {
                            pool: Arc::clone(&self.pool),
                            packet_tx: self.packet_tx.clone(),
                            transport_id: self.transport_id,
                            stats: Arc::clone(&self.stats),
                            local_pubkey: self.local_pubkey,
                            discovery_buffer: Arc::clone(&self.discovery_buffer),
                            local_node_addr,
                            max_packet: self.config.mtu(),
                        },
                    )));
                    debug!(adapter = %adapter, psm = listener_psm, "BLE accept loop started");
                }
                Err(e) => {
                    warn!(adapter = %adapter, error = %e, "failed to start BLE listener");
                    self.state = TransportState::Failed;
                    return Err(e);
                }
            }
        }

        // Start continuous advertising
        if self.config.advertise() {
            let bootstrap = crate::transport::ble::bootstrap::BleBootstrap::new(
                listener_psm,
                self.config.mtu(),
            )
            .map_err(|error| TransportError::StartFailed(error.to_string()))?;
            if let Err(e) = self.io.start_advertising(bootstrap).await {
                warn!(adapter = %adapter, error = %e, "failed to start BLE advertising");
            } else {
                self.stats.record_advertisement();
                debug!(adapter = %adapter, "BLE advertising started (continuous)");
            }
        }

        // Start combined scan + probe loop
        if self.config.scan() {
            match self.io.start_scanning().await {
                Ok(scanner) => {
                    self.scan_probe_task = Some(tokio::spawn(scan_probe_loop::<I>(
                        scanner,
                        ScanProbeContext {
                            io: Arc::clone(&self.io),
                            pool: Arc::clone(&self.pool),
                            buffer: Arc::clone(&self.discovery_buffer),
                            stats: Arc::clone(&self.stats),
                            local_pubkey: self.local_pubkey,
                            connect_timeout_ms: self.config.connect_timeout_ms(),
                            cooldown_secs: self.config.probe_cooldown_secs(),
                            local_node_addr,
                            packet_tx: self.packet_tx.clone(),
                            transport_id: self.transport_id,
                            max_packet: self.config.mtu(),
                        },
                    )));
                    debug!(adapter = %adapter, "BLE scan+probe loop started");
                }
                Err(e) => {
                    warn!(adapter = %adapter, error = %e, "failed to start BLE scanning");
                }
            }
        }

        self.state = TransportState::Up;
        info!(adapter = %adapter, psm = listener_psm, "BLE transport started");
        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        // Stop advertising
        let _ = self.io.stop_advertising().await;

        // Abort accept loop
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }

        // Abort scan+probe loop
        if let Some(task) = self.scan_probe_task.take() {
            task.abort();
        }

        // Drain connecting pool
        {
            let mut connecting = self.connecting.lock().await;
            for (_, entry) in connecting.drain() {
                entry.task.abort();
            }
        }

        // Drain established connections (recv tasks aborted via Drop)
        {
            let mut pool = self.pool.lock().await;
            for addr in pool.addrs() {
                pool.remove(&addr);
            }
        }

        self.state = TransportState::Down;
        info!("BLE transport stopped");
        Ok(())
    }

    /// Send data to a remote BLE address.
    ///
    /// If no connection exists, triggers a background connect and fails
    /// fast. The next send retry (typically 1s later for handshake msg1)
    /// will find the connection established. This avoids blocking the
    /// event loop on L2CAP connect (up to 10s).
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        let pool = self.pool.lock().await;
        let conn = match pool.get(addr) {
            Some(c) => c,
            None => {
                // Drop pool lock before triggering background connect
                drop(pool);
                // Fire-and-forget: connect_async spawns a background task
                let _ = self.connect_async(addr).await;
                return Err(TransportError::SendFailed("not connected".into()));
            }
        };

        // MTU check
        let mtu = conn.effective_mtu() as usize;
        if data.len() > mtu {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: mtu as u16,
            });
        }

        match conn.stream.send(data).await {
            Ok(()) => {
                self.stats.record_send(data.len());
                Ok(data.len())
            }
            Err(e) => {
                self.stats.record_send_error();
                // Drop pool lock before removing to avoid deadlock
                drop(pool);
                let mut pool = self.pool.lock().await;
                pool.remove(addr);
                warn!(addr = %addr, error = %e, "BLE send failed, connection removed");
                Err(e)
            }
        }
    }

    /// Initiate a non-blocking connection to a remote BLE device.
    ///
    /// Spawns a background task that connects with timeout and promotes
    /// to the pool on success. Poll `connection_state_sync()` to check.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        // Already connected?
        {
            let pool = self.pool.lock().await;
            if pool.contains(addr) {
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

        let ble_addr = BleAddr::parse(
            addr.as_str()
                .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?,
        )?;

        let io = Arc::clone(&self.io);
        let pool = Arc::clone(&self.pool);
        let connecting = Arc::clone(&self.connecting);
        let packet_tx = self.packet_tx.clone();
        let transport_id = self.transport_id;
        let stats = Arc::clone(&self.stats);
        let psm = self.config.psm();
        let timeout_ms = self.config.connect_timeout_ms();
        let addr_clone = addr.clone();
        let local_pubkey = self.local_pubkey;
        let discovery_buffer = Arc::clone(&self.discovery_buffer);
        let max_packet = self.config.mtu();

        let task = tokio::spawn(async move {
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                io.connect(&ble_addr, psm),
            )
            .await;

            // Remove from connecting pool
            connecting.lock().await.remove(&addr_clone);

            match result {
                Ok(Ok(stream)) => {
                    let stream = FramedBleStream::new(stream, max_packet);
                    // Pre-handshake pubkey exchange (temporary, pre-XX)
                    if let Some(ref our_pubkey) = local_pubkey {
                        match pubkey_exchange(&stream, our_pubkey).await {
                            Ok(peer_pubkey) => {
                                debug!(addr = %addr_clone, "BLE outbound pubkey exchange complete");
                                discovery_buffer.add_peer_with_pubkey(&ble_addr, peer_pubkey);
                            }
                            Err(e) => {
                                warn!(
                                    addr = %addr_clone, error = %e,
                                    "BLE outbound pubkey exchange failed"
                                );
                                return;
                            }
                        }
                    }

                    let send_mtu = stream.send_mtu();
                    let recv_mtu = stream.recv_mtu();
                    let stream = Arc::new(stream);

                    let recv_task = tokio::spawn(receive_loop(
                        Arc::clone(&stream),
                        addr_clone.clone(),
                        Arc::clone(&pool),
                        packet_tx,
                        transport_id,
                        Arc::clone(&stats),
                        recv_mtu,
                    ));

                    let conn = BleConnection {
                        stream,
                        recv_task: Some(recv_task),
                        send_mtu,
                        recv_mtu,
                        established_at: tokio::time::Instant::now(),
                        is_static: false,
                        addr: ble_addr,
                    };

                    let mut pool = pool.lock().await;
                    match pool.insert(addr_clone.clone(), conn) {
                        Ok(Some(evicted)) => {
                            stats.record_pool_eviction();
                            debug!(addr = %addr_clone, evicted = %evicted, "BLE connection established (evicted peer)");
                        }
                        Ok(None) => {
                            debug!(addr = %addr_clone, "BLE connection established");
                        }
                        Err(e) => {
                            warn!(addr = %addr_clone, error = %e, "BLE pool full, connection dropped");
                            stats.record_connection_rejected();
                            return;
                        }
                    }
                    stats.record_connection_established();
                }
                Ok(Err(e)) => {
                    debug!(addr = %addr_clone, error = %e, "BLE connect failed");
                }
                Err(_) => {
                    stats.record_connect_timeout();
                    debug!(addr = %addr_clone, "BLE connect timeout");
                }
            }
        });

        self.connecting
            .lock()
            .await
            .insert(addr.clone(), ConnectingEntry { task });

        Ok(())
    }

    /// Query the state of a connection attempt.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        // Check established pool (try_lock to avoid blocking)
        if let Ok(pool) = self.pool.try_lock()
            && pool.contains(addr)
        {
            return ConnectionState::Connected;
        }

        // Check connecting pool
        if let Ok(connecting) = self.connecting.try_lock()
            && connecting.contains_key(addr)
        {
            return ConnectionState::Connecting;
        }

        ConnectionState::None
    }

    /// Close a specific connection.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.remove(addr) {
            debug!(addr = %addr, "BLE connection closed");
            drop(conn); // recv_task aborted via Drop
        }
    }

    /// Get the link MTU for a specific address.
    pub fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        if let Ok(pool) = self.pool.try_lock()
            && let Some(conn) = pool.get(addr)
        {
            return conn.effective_mtu();
        }
        self.config.mtu()
    }
}

impl<I: BleIo> Transport for BleTransport<I> {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::BLE
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        self.link_mtu(addr)
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for BLE transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for BLE transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for BLE transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(self.discovery_buffer.take())
    }

    fn auto_connect(&self) -> bool {
        self.config.auto_connect()
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }

    fn close_connection(&self, _addr: &TransportAddr) {
        // use close_connection_async()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
