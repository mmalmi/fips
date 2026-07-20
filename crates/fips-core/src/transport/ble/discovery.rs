//! BLE discovery via advertising and scanning.
//!
//! BLE advertisements carry a 128-bit FIPS service UUID for identification.
//! Post-forklift, advertisements are UUID-only (no identity material);
//! identity is exchanged during the Noise handshake.

use crate::transport::{DiscoveredPeer, TransportId};
use secp256k1::XOnlyPublicKey;
use std::sync::Mutex;

use super::{addr::BleAddr, bootstrap::BleBootstrap};

const MAX_DISCOVERY_RECORDS: usize = 64;

/// Buffer for discovered BLE peers, drained by `discover()`.
///
/// Follows the same pattern as Ethernet's `DiscoveryBuffer`: peers are
/// added from the scan loop and drained by the node's discovery polling.
pub struct DiscoveryBuffer {
    transport_id: TransportId,
    peers: Mutex<Vec<DiscoveredPeer>>,
    bootstraps: Mutex<Vec<(BleAddr, BleBootstrap)>>,
}

impl DiscoveryBuffer {
    /// Create a new empty discovery buffer.
    pub fn new(transport_id: TransportId) -> Self {
        Self {
            transport_id,
            peers: Mutex::new(Vec::new()),
            bootstraps: Mutex::new(Vec::new()),
        }
    }

    /// Remember the latest connection parameters advertised by a peer.
    pub fn remember_bootstrap(&self, addr: &BleAddr, bootstrap: BleBootstrap) {
        let mut records = self
            .bootstraps
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(index) = records.iter().position(|(known, _)| known == addr) {
            records.remove(index);
        } else if records.len() == MAX_DISCOVERY_RECORDS {
            records.remove(0);
        }
        records.push((addr.clone(), bootstrap));
    }

    /// Return the latest connection parameters advertised by a peer.
    pub fn bootstrap_for(&self, addr: &BleAddr) -> Option<BleBootstrap> {
        self.bootstraps
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .find_map(|(known, bootstrap)| (known == addr).then_some(*bootstrap))
    }

    /// Add a discovered BLE peer.
    ///
    /// Deduplicates by device address — keeps the latest entry.
    pub fn add_peer(&self, addr: &BleAddr) {
        let ta = addr.to_transport_addr();
        self.add_peer_record(addr, DiscoveredPeer::new(self.transport_id, ta));
    }

    /// Add a discovered BLE peer with a known public key.
    ///
    /// Used after the pre-handshake pubkey exchange confirms the peer's
    /// identity. The pubkey_hint enables the node's auto-connect path
    /// to initiate the IK handshake.
    pub fn add_peer_with_pubkey(&self, addr: &BleAddr, pubkey: XOnlyPublicKey) {
        let ta = addr.to_transport_addr();
        self.add_peer_record(
            addr,
            DiscoveredPeer::with_hint(self.transport_id, ta, pubkey),
        );
    }

    fn add_peer_record(&self, addr: &BleAddr, peer: DiscoveredPeer) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let addr_str = addr.to_string_repr();
        peers.retain(|p| p.addr.as_str() != Some(addr_str.as_str()));
        if peers.len() == MAX_DISCOVERY_RECORDS {
            peers.remove(0);
        }
        peers.push(peer);
    }

    /// Drain all discovered peers since the last call.
    pub fn take(&self) -> Vec<DiscoveredPeer> {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *peers)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportAddr;

    fn test_addr(n: u8) -> BleAddr {
        BleAddr::from_mac("hci0", [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n])
    }

    #[test]
    fn test_discovery_buffer_add_take() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(1));

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);

        // Second take should be empty
        let peers = buffer.take();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_discovery_buffer_dedup() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(1));
        buffer.add_peer(&test_addr(1)); // same address again

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_discovery_buffer_multiple_peers() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(1));
        buffer.add_peer(&test_addr(2));
        buffer.add_peer(&test_addr(3));

        let peers = buffer.take();
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn test_discovery_buffer_bounds_pending_peers() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        for n in 0..=MAX_DISCOVERY_RECORDS as u8 {
            buffer.add_peer(&test_addr(n));
        }

        let peers = buffer.take();
        let evicted = test_addr(0).to_string_repr();
        assert_eq!(peers.len(), MAX_DISCOVERY_RECORDS);
        assert!(
            !peers
                .iter()
                .any(|peer| peer.addr.as_str() == Some(evicted.as_str()))
        );
    }

    #[test]
    fn test_discovery_buffer_remembers_latest_bootstrap() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        let addr = test_addr(1);
        let first = BleBootstrap::new(0x0085, 1024).unwrap();
        let latest = BleBootstrap::new(0x0097, 2048).unwrap();

        buffer.remember_bootstrap(&addr, first);
        buffer.remember_bootstrap(&addr, latest);

        assert_eq!(buffer.bootstrap_for(&addr), Some(latest));
    }

    #[test]
    fn test_discovery_buffer_bounds_bootstrap_records() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        let bootstrap = BleBootstrap::new(0x0085, 1024).unwrap();
        for n in 0..=MAX_DISCOVERY_RECORDS as u8 {
            buffer.remember_bootstrap(&test_addr(n), bootstrap);
        }

        assert_eq!(buffer.bootstrap_for(&test_addr(0)), None);
        assert_eq!(
            buffer.bootstrap_for(&test_addr(MAX_DISCOVERY_RECORDS as u8)),
            Some(bootstrap)
        );
    }

    #[test]
    fn test_discovery_buffer_transport_addr_format() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(0x42));

        let peers = buffer.take();
        assert_eq!(
            peers[0].addr,
            TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:42")
        );
    }
}
