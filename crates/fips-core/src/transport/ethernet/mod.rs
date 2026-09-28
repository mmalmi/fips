//! Ethernet Transport Implementation
//!
//! Provides raw Ethernet transport for FIPS peer communication. On Linux,
//! uses AF_PACKET/SOCK_DGRAM sockets; on macOS, uses BPF devices (`/dev/bpf*`).
//! Works on wired Ethernet and WiFi interfaces (kernel mac80211 abstracts
//! 802.11 transparently on Linux).

mod binding;
pub mod discovery;
pub mod socket;
mod socket_stats;
pub mod stats;

use super::{
    DiscoveredPeer, PacketBuffer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::NodeAddr;
use crate::config::EthernetConfig;
use discovery::{
    DiscoveryBuffer, FRAME_TYPE_BEACON, FRAME_TYPE_DATA, build_topology_beacon, parse_beacon_record,
};
use socket::{AsyncPacketSocket, ETHERNET_BROADCAST, PacketSocket};
use stats::EthernetStats;

use binding::{Binding, BindingSupervisor};
use secp256k1::XOnlyPublicKey;
use std::sync::{Arc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// Ethernet transport for FIPS.
///
/// Uses AF_PACKET with SOCK_DGRAM for raw Ethernet frame I/O. A single
/// socket per interface serves all peers; links are virtual tuples of
/// (transport_id, remote_mac).
pub struct EthernetTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: EthernetConfig,
    /// Current state.
    state: TransportState,
    /// Current interface binding, shared with the recovery task.
    binding: Arc<RwLock<Option<Arc<Binding>>>>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Watches interface presence and replaces the complete binding after churn.
    binding_task: Option<JoinHandle<()>>,
    /// Interface name (from config).
    interface: String,
    /// Discovery buffer for discovered peers.
    discovery_buffer: Arc<DiscoveryBuffer>,
    /// Transport-level statistics.
    stats: Arc<EthernetStats>,
    /// Node's public key for beacon construction.
    local_pubkey: Option<XOnlyPublicKey>,
    /// Advisory state published by the owning Node, shared with the beacon task.
    discovery_root: Arc<Mutex<Option<NodeAddr>>>,
}

impl EthernetTransport {
    /// Create a new Ethernet transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: EthernetConfig,
        packet_tx: PacketTx,
    ) -> Self {
        let interface = config.interface.clone();
        let discovery_buffer = Arc::new(DiscoveryBuffer::new(
            transport_id,
            config.discovery_scope().map(str::to_string),
        ));
        let stats = Arc::new(EthernetStats::new());

        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            binding: Arc::new(RwLock::new(None)),
            packet_tx,
            binding_task: None,
            interface,
            discovery_buffer,
            stats,
            local_pubkey: None,
            discovery_root: Arc::new(Mutex::new(None)),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the interface name.
    pub fn interface_name(&self) -> &str {
        &self.interface
    }

    /// Get the local MAC address (only valid after start).
    pub fn local_mac(&self) -> Option<[u8; 6]> {
        self.current_binding().map(|binding| binding.local_mac)
    }

    /// Set the node's public key for beacon construction.
    ///
    /// Must be called before start if announce is enabled.
    pub fn set_local_pubkey(&mut self, pubkey: XOnlyPublicKey) {
        self.local_pubkey = Some(pubkey);
    }

    /// Publish the current root only while the owning Node has active neighbors.
    pub(crate) fn publish_discovery_root(&self, root: Option<NodeAddr>) {
        *self
            .discovery_root
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = root;
    }

    /// Get a reference to the statistics.
    pub fn stats(&self) -> &Arc<EthernetStats> {
        &self.stats
    }

    /// Socket-local diagnostics, unavailable before start or on unsupported platforms.
    pub(crate) fn socket_stats(&self) -> socket_stats::SocketStats {
        #[cfg(target_os = "linux")]
        if let Some(binding) = self.current_binding() {
            return binding.socket.get_ref().socket_stats();
        }
        socket_stats::SocketStats::default()
    }

    fn current_binding(&self) -> Option<Arc<Binding>> {
        self.binding
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Start the interface supervisor. A missing or down interface remains
    /// configured and is bound when it becomes available.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        let mut supervisor = BindingSupervisor::new(self)?;
        self.state = TransportState::Starting;
        supervisor.refresh().await;
        self.binding_task = Some(tokio::spawn(supervisor.run()));
        self.state = TransportState::Up;
        Ok(())
    }

    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        self.binding
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = self.binding_task.take() {
            task.abort();
            let _ = task.await;
        }
        self.discovery_buffer.take();
        self.state = TransportState::Down;
        info!(transport_id = %self.transport_id, interface = %self.interface,
            "Ethernet transport stopped");
        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// The data is prepended with a FRAME_TYPE_DATA prefix byte before
    /// transmission.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        let binding = self.current_binding().ok_or(TransportError::NotStarted)?;
        if data.len() > binding.mtu as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: binding.mtu,
            });
        }

        let dest_mac = parse_mac_addr(addr)?;
        let mut shutdown = binding.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(TransportError::NotStarted);
        }

        // Prepend frame type prefix and 2-byte LE payload length.
        // The length field lets the receiver trim Ethernet minimum-frame padding
        // (NICs pad frames shorter than 46 bytes payload to 46 bytes with zeros,
        // which would otherwise corrupt AEAD ciphertext verification).
        let mut frame = Vec::with_capacity(3 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(data);

        let bytes_sent = tokio::select! {
            result = binding.socket.send_to(&frame, &dest_mac) => result?,
            _ = shutdown.changed() => return Err(TransportError::NotStarted),
        };
        self.stats.record_send(bytes_sent);

        trace!(
            transport_id = %self.transport_id,
            remote_mac = %format_mac(&dest_mac),
            bytes = bytes_sent,
            "Ethernet frame sent"
        );

        // Return the data bytes sent (excluding frame type prefix and length field)
        Ok(bytes_sent.saturating_sub(3))
    }
}

impl Drop for EthernetTransport {
    fn drop(&mut self) {
        if let Some(binding) = self
            .binding
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            binding.shutdown();
        }
        if let Some(task) = self.binding_task.take() {
            task.abort();
        }
    }
}

impl Transport for EthernetTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::ETHERNET
    }

    fn state(&self) -> TransportState {
        if self.state == TransportState::Up && self.current_binding().is_none() {
            TransportState::Down
        } else {
            self.state
        }
    }

    fn mtu(&self) -> u16 {
        self.current_binding()
            .map_or(self.config.mtu.unwrap_or(1497), |b| b.mtu)
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for Ethernet transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for Ethernet transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for Ethernet transport".into(),
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
}

// ============================================================================
// Receive Loop
// ============================================================================

struct EthernetReceiveContext {
    socket: Arc<AsyncPacketSocket>,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
    discovery_enabled: bool,
    discovery_buffer: Arc<DiscoveryBuffer>,
    stats: Arc<EthernetStats>,
    local_mac: [u8; 6],
}

/// Ethernet receive loop — runs as a spawned task.
async fn ethernet_receive_loop(ctx: EthernetReceiveContext) {
    let EthernetReceiveContext {
        socket,
        transport_id,
        packet_tx,
        mtu,
        discovery_enabled,
        discovery_buffer,
        stats,
        local_mac,
    } = ctx;

    // Buffer with headroom: frame type prefix + MTU + some extra
    let mut buf = vec![0u8; mtu as usize + 100];

    debug!(transport_id = %transport_id, "Ethernet receive loop starting");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src_mac)) => {
                if len == 0 {
                    continue;
                }
                if src_mac == local_mac {
                    trace!(
                        transport_id = %transport_id,
                        local_mac = %format_mac(&local_mac),
                        "Ignoring self-echoed Ethernet frame"
                    );
                    continue;
                }

                stats.record_recv(len);

                let frame_type = buf[0];
                match frame_type {
                    FRAME_TYPE_DATA => {
                        // Data frame: [type:1][length:2 LE][payload:N]
                        // Use the length field to trim Ethernet minimum-frame padding.
                        if len < 3 {
                            trace!("Data frame too short ({len} bytes), ignoring");
                            continue;
                        }
                        let payload_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
                        if payload_len > len - 3 {
                            trace!(
                                "Data frame length field ({payload_len}) exceeds \
                                 available bytes ({}), ignoring",
                                len - 3
                            );
                            continue;
                        }
                        let data = buf[3..3 + payload_len].to_vec();
                        let addr = TransportAddr::from_bytes(&src_mac);
                        let packet = ReceivedPacket::with_timestamp(
                            transport_id,
                            addr,
                            PacketBuffer::new(data),
                            crate::time::now_ms(),
                        );

                        trace!(
                            transport_id = %transport_id,
                            remote_mac = %format_mac(&src_mac),
                            bytes = payload_len,
                            "Ethernet data frame received"
                        );

                        if packet_tx.send(packet).is_err() {
                            debug!(
                                transport_id = %transport_id,
                                "Packet channel closed, stopping receive loop"
                            );
                            break;
                        }
                    }
                    FRAME_TYPE_BEACON => {
                        stats.record_beacon_recv();

                        if discovery_enabled && let Some(beacon) = parse_beacon_record(&buf[..len])
                        {
                            if !discovery_buffer.add_peer(src_mac, beacon) {
                                stats.record_beacon_dropped();
                            }
                            trace!(
                                transport_id = %transport_id,
                                remote_mac = %format_mac(&src_mac),
                                "Discovery beacon received"
                            );
                        }
                    }
                    _ => {
                        // Unknown frame type, ignore
                        trace!(
                            transport_id = %transport_id,
                            frame_type = frame_type,
                            "Unknown frame type, dropping"
                        );
                    }
                }
            }
            Err(e) => {
                stats.record_recv_error();
                warn!(
                    transport_id = %transport_id,
                    error = %e,
                    "Ethernet receive error; rebinding"
                );
                break;
            }
        }
    }

    debug!(transport_id = %transport_id, "Ethernet receive loop stopped");
}

// ============================================================================
// Beacon Sender
// ============================================================================

/// Beacons use the same binding as data send and receive. The supervisor
/// replaces all three together if either worker fails or the interface changes.
struct EthernetBeaconContext {
    socket: Arc<AsyncPacketSocket>,
    pubkey: XOnlyPublicKey,
    discovery_scope: Option<String>,
    discovery_root: Arc<Mutex<Option<NodeAddr>>>,
    interval_secs: u64,
    stats: Arc<EthernetStats>,
    transport_id: TransportId,
}

async fn beacon_sender_loop(ctx: EthernetBeaconContext) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(ctx.interval_secs));
    loop {
        interval.tick().await;
        let beacon = build_current_beacon(
            &ctx.pubkey,
            ctx.discovery_scope.as_deref(),
            &ctx.discovery_root,
        );
        match ctx.socket.send_to(&beacon, &ETHERNET_BROADCAST).await {
            Ok(_) => ctx.stats.record_beacon_sent(),
            Err(error) => {
                ctx.stats.record_send_error();
                warn!(transport_id = %ctx.transport_id, %error, "Ethernet beacon send failed; rebinding");
                break;
            }
        }
    }
}

fn build_current_beacon(
    pubkey: &XOnlyPublicKey,
    scope: Option<&str>,
    discovery_root: &Mutex<Option<NodeAddr>>,
) -> Vec<u8> {
    let root = *discovery_root.lock().unwrap_or_else(|e| e.into_inner());
    build_topology_beacon(pubkey, scope, root)
}

// ============================================================================
// MAC Address Helpers
// ============================================================================

/// Parse a TransportAddr as a 6-byte MAC address.
fn parse_mac_addr(addr: &TransportAddr) -> Result<[u8; 6], TransportError> {
    let bytes = addr.as_bytes();
    if bytes.len() != 6 {
        return Err(TransportError::InvalidAddress(format!(
            "expected 6-byte MAC, got {} bytes",
            bytes.len()
        )));
    }
    if bytes == [0, 0, 0, 0, 0, 0] {
        return Err(TransportError::InvalidAddress(
            "destination MAC is all zeros".into(),
        ));
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(bytes);
    Ok(mac)
}

/// Format a MAC address as colon-separated hex for display.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse a colon-separated MAC string (e.g., "aa:bb:cc:dd:ee:ff") into bytes.
pub fn parse_mac_string(s: &str) -> Result<[u8; 6], TransportError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(TransportError::InvalidAddress(format!(
            "invalid MAC format: expected 6 colon-separated hex bytes, got '{}'",
            s
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
            TransportError::InvalidAddress(format!("invalid hex byte '{}' in MAC address", part))
        })?;
    }
    Ok(mac)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_uses_latest_published_root_without_starting_transport() {
        let (tx, _rx) = crate::transport::packet_channel(1);
        let transport =
            EthernetTransport::new(TransportId::new(1), None, EthernetConfig::default(), tx);
        let secret = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (pubkey, _) = secret
            .public_key(&secp256k1::Secp256k1::new())
            .x_only_public_key();
        // This is the same shared value the sender retains when it starts.
        let sender_root = transport.discovery_root.clone();
        let mut previous_wire = None;
        for root in [
            Some(NodeAddr::from_bytes([1; 16])),
            Some(NodeAddr::from_bytes([2; 16])),
            None,
        ] {
            transport.publish_discovery_root(root);
            let wire = build_current_beacon(&pubkey, Some("scope-a"), &sender_root);
            let parsed = parse_beacon_record(&wire).unwrap();
            assert_eq!(parsed.pubkey, pubkey);
            assert_eq!(parsed.scope.as_deref(), Some("scope-a"));
            assert_eq!(parsed.connected_root_hint, root);
            assert_ne!(previous_wire.as_ref(), Some(&wire));
            previous_wire = Some(wire);
        }
        assert_eq!(
            previous_wire.unwrap(),
            discovery::build_scoped_beacon(&pubkey, Some("scope-a"))
        );
        assert!(transport.current_binding().is_none());
        assert!(transport.binding_task.is_none());
    }

    #[test]
    fn ethernet_socket_diagnostics_are_null_before_start() {
        let (tx, _rx) = crate::transport::packet_channel(1);
        let transport =
            EthernetTransport::new(TransportId::new(1), None, EthernetConfig::default(), tx);
        let handle = crate::transport::TransportHandle::Ethernet(transport);
        let stats = handle.transport_stats();
        assert!(stats.get("kernel_drops").unwrap().is_null());
        assert!(stats.get("recv_buffer_bytes").unwrap().is_null());
        assert_eq!(stats["recv_errors"], 0);
    }

    #[test]
    fn test_parse_mac_addr_valid() {
        let addr = TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mac = parse_mac_addr(&addr).unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_addr_wrong_length() {
        let addr = TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc]);
        assert!(parse_mac_addr(&addr).is_err());

        let addr = TransportAddr::from_string("192.168.1.1:2121");
        assert!(parse_mac_addr(&addr).is_err());
    }

    #[test]
    fn test_parse_mac_addr_all_zeros() {
        let addr = TransportAddr::from_bytes(&[0, 0, 0, 0, 0, 0]);
        assert!(parse_mac_addr(&addr).is_err());
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_format_mac_leading_zeros() {
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(format_mac(&mac), "01:02:03:04:05:06");
    }

    #[test]
    fn test_parse_mac_string_valid() {
        let mac = parse_mac_string("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_string_uppercase() {
        let mac = parse_mac_string("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_string_invalid() {
        assert!(parse_mac_string("aa:bb:cc").is_err());
        assert!(parse_mac_string("not:a:mac:at:all:x").is_err());
        assert!(parse_mac_string("").is_err());
        assert!(parse_mac_string("aa-bb-cc-dd-ee-ff").is_err());
    }

    #[test]
    fn test_frame_type_data_prefix() {
        // Verify data frames have type prefix + 2-byte LE length + payload
        let data = vec![1, 2, 3, 4];
        let mut frame = Vec::with_capacity(3 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(&data);

        assert_eq!(frame[0], 0x00); // frame type
        assert_eq!(u16::from_le_bytes([frame[1], frame[2]]), 4); // length
        assert_eq!(&frame[3..], &[1, 2, 3, 4]); // payload
    }

    #[test]
    fn test_data_frame_padding_trimmed() {
        // Simulate Ethernet minimum-frame padding: a 4-byte payload produces
        // a 7-byte frame (type + len + payload), padded to 46 bytes by NIC.
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let payload_len = payload.len() as u16;

        // Build frame as sender would
        let mut frame = Vec::with_capacity(3 + payload.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&payload);

        // Simulate NIC padding to 46 bytes
        frame.resize(46, 0x00);

        // Receiver extracts using length field
        let recv_len = u16::from_le_bytes([frame[1], frame[2]]) as usize;
        let extracted = &frame[3..3 + recv_len];
        assert_eq!(extracted, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_beacon_size() {
        assert_eq!(discovery::BEACON_SIZE, 34);
    }
}
