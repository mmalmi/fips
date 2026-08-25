//! Ethernet LAN discovery via broadcast beacons.
//!
//! Beacon format:
//! - `0x01` (1 byte): frame type = discovery announcement
//! - `0x01` (1 byte): discovery protocol version
//! - x-only public key (32 bytes): node's Nostr identity
//! - optional discovery scope length (1 byte) + UTF-8 scope bytes
//!
//! The optional scope trailer is a discovery/noise filter, not access control.
//! It keeps version 1 beacons backward compatible: older nodes parse the first
//! 34 bytes and ignore the trailing scope.

use crate::transport::{DiscoveredPeer, TransportAddr, TransportId};
use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;
use tracing::warn;

/// Discovery protocol version.
pub const DISCOVERY_VERSION: u8 = 0x01;

/// Frame type prefix for discovery announcement beacons.
pub const FRAME_TYPE_BEACON: u8 = 0x01;

/// Frame type prefix for FIPS data frames.
pub const FRAME_TYPE_DATA: u8 = 0x00;

/// Total beacon payload size: type(1) + version(1) + pubkey(32).
pub const BEACON_SIZE: usize = 34;

/// Largest scope that fits in the current one-byte scope length field.
const MAX_SCOPE_LEN: usize = u8::MAX as usize;

/// Maximum distinct unauthenticated source MACs retained between drains.
const MAX_BUFFERED_PEERS: usize = 1024;

/// Parsed Ethernet discovery beacon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    pub pubkey: XOnlyPublicKey,
    pub scope: Option<String>,
}

/// Build a discovery announcement beacon payload.
pub fn build_beacon(pubkey: &XOnlyPublicKey) -> [u8; BEACON_SIZE] {
    let mut buf = [0u8; BEACON_SIZE];
    buf[0] = FRAME_TYPE_BEACON;
    buf[1] = DISCOVERY_VERSION;
    buf[2..BEACON_SIZE].copy_from_slice(&pubkey.serialize());
    buf
}

/// Build a discovery announcement beacon payload with an optional scope.
pub fn build_scoped_beacon(pubkey: &XOnlyPublicKey, scope: Option<&str>) -> Vec<u8> {
    let mut buf = build_beacon(pubkey).to_vec();
    let Some(scope) = scope.filter(|s| !s.is_empty()) else {
        return buf;
    };
    let scope = scope.as_bytes();
    let scope_len = scope.len().min(MAX_SCOPE_LEN);
    buf.push(scope_len as u8);
    buf.extend_from_slice(&scope[..scope_len]);
    buf
}

/// Parse a discovery announcement beacon payload.
///
/// Returns the sender's public key, or None if the payload is invalid.
pub fn parse_beacon(data: &[u8]) -> Option<XOnlyPublicKey> {
    parse_beacon_record(data).map(|beacon| beacon.pubkey)
}

/// Parse a discovery announcement beacon payload including optional scope.
pub fn parse_beacon_record(data: &[u8]) -> Option<Beacon> {
    if data.len() < BEACON_SIZE {
        return None;
    }
    if data[0] != FRAME_TYPE_BEACON {
        return None;
    }
    if data[1] != DISCOVERY_VERSION {
        return None;
    }
    let pubkey = XOnlyPublicKey::from_slice(&data[2..34]).ok()?;
    let scope = if data.len() > BEACON_SIZE {
        let scope_len = data[BEACON_SIZE] as usize;
        let scope_start = BEACON_SIZE + 1;
        let scope_end = scope_start.checked_add(scope_len)?;
        if data.len() < scope_end {
            return None;
        }
        let scope = std::str::from_utf8(&data[scope_start..scope_end])
            .ok()?
            .to_string();
        (!scope.is_empty()).then_some(scope)
    } else {
        None
    };
    Some(Beacon { pubkey, scope })
}

/// Buffer for discovered peers, drained by `discover()`.
pub struct DiscoveryBuffer {
    transport_id: TransportId,
    scope_filter: Option<String>,
    peers: Mutex<BufferedPeers>,
}

#[derive(Default)]
struct BufferedPeers {
    by_mac: HashMap<[u8; 6], (u64, DiscoveredPeer)>,
    sequence: u64,
    dropped: u64,
    warn_at: u64,
}

impl DiscoveryBuffer {
    /// Create a new empty discovery buffer.
    pub fn new(transport_id: TransportId, scope_filter: Option<String>) -> Self {
        Self {
            transport_id,
            scope_filter: scope_filter.filter(|s| !s.is_empty()),
            peers: Mutex::new(BufferedPeers::default()),
        }
    }

    /// Add a discovered peer from a received beacon.
    ///
    /// Returns false only when a new MAC was refused because the bounded
    /// buffer was full. An existing neighbor is always refreshed.
    pub fn add_peer(&self, src_mac: [u8; 6], beacon: Beacon) -> bool {
        if let Some(scope_filter) = self.scope_filter.as_deref()
            && beacon.scope.as_deref() != Some(scope_filter)
        {
            return true;
        }

        let addr = TransportAddr::from_bytes(&src_mac);
        let peer = DiscoveredPeer::with_hint(self.transport_id, addr, beacon.pubkey);
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        peers.sequence = peers.sequence.saturating_add(1);
        let sequence = peers.sequence;
        let full = peers.by_mac.len() >= MAX_BUFFERED_PEERS;
        let stored = match peers.by_mac.entry(src_mac) {
            Entry::Occupied(mut entry) => {
                entry.insert((sequence, peer));
                true
            }
            Entry::Vacant(entry) if !full => {
                entry.insert((sequence, peer));
                true
            }
            Entry::Vacant(_) => false,
        };
        if !stored {
            peers.dropped = peers.dropped.saturating_add(1);
        }
        stored
    }

    /// Drain discovered peers in last-seen order.
    pub fn take(&self) -> Vec<DiscoveredPeer> {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let mut ordered = peers
            .by_mac
            .drain()
            .map(|(_, peer)| peer)
            .collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|(sequence, _)| *sequence);
        if peers.dropped >= peers.warn_at.max(1) {
            warn!(
                transport_id = %self.transport_id,
                dropped = peers.dropped,
                cap = MAX_BUFFERED_PEERS,
                "Ethernet discovery buffer full; unseen beacons refused"
            );
            peers.warn_at = next_decade(peers.dropped);
        }
        ordered.into_iter().map(|(_, peer)| peer).collect()
    }

    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).dropped
    }
}

fn next_decade(n: u64) -> u64 {
    let mut threshold = 1u64;
    while threshold <= n {
        match threshold.checked_mul(10) {
            Some(next) => threshold = next,
            None => return u64::MAX,
        }
    }
    threshold
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (xonly, _) = sk.public_key(&secp).x_only_public_key();
        xonly
    }

    #[test]
    fn test_build_parse_beacon() {
        let pubkey = test_pubkey();
        let beacon = build_beacon(&pubkey);

        assert_eq!(beacon.len(), BEACON_SIZE);
        assert_eq!(beacon[0], FRAME_TYPE_BEACON);
        assert_eq!(beacon[1], DISCOVERY_VERSION);

        let parsed = parse_beacon(&beacon).unwrap();
        assert_eq!(parsed, pubkey);
    }

    #[test]
    fn test_build_parse_scoped_beacon() {
        let pubkey = test_pubkey();
        let beacon = build_scoped_beacon(&pubkey, Some("iris-chat:host"));

        let parsed = parse_beacon_record(&beacon).unwrap();
        assert_eq!(parsed.pubkey, pubkey);
        assert_eq!(parsed.scope.as_deref(), Some("iris-chat:host"));

        // The legacy parser still extracts the pubkey from scoped beacons.
        assert_eq!(parse_beacon(&beacon), Some(pubkey));
    }

    #[test]
    fn test_parse_scoped_beacon_rejects_truncated_scope() {
        let pubkey = test_pubkey();
        let mut beacon = build_beacon(&pubkey).to_vec();
        beacon.push(9);
        beacon.extend_from_slice(b"too");
        assert!(parse_beacon_record(&beacon).is_none());
    }

    #[test]
    fn test_parse_beacon_too_short() {
        assert!(parse_beacon(&[0x01, 0x01]).is_none());
        assert!(parse_beacon(&[]).is_none());
    }

    #[test]
    fn test_parse_beacon_wrong_type() {
        let mut beacon = build_beacon(&test_pubkey());
        beacon[0] = 0x00; // data frame, not beacon
        assert!(parse_beacon(&beacon).is_none());
    }

    #[test]
    fn test_parse_beacon_wrong_version() {
        let mut beacon = build_beacon(&test_pubkey());
        beacon[1] = 0xFF;
        assert!(parse_beacon(&beacon).is_none());
    }

    #[test]
    fn test_frame_type_prefix() {
        assert_eq!(FRAME_TYPE_DATA, 0x00);
        assert_eq!(FRAME_TYPE_BEACON, 0x01);
    }

    #[test]
    fn test_discovery_buffer() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1), None);
        let pubkey = test_pubkey();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        buffer.add_peer(
            mac,
            Beacon {
                pubkey,
                scope: None,
            },
        );

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr.as_bytes(), &mac);
        assert_eq!(peers[0].pubkey_hint, Some(pubkey));

        // Second take should be empty
        let peers = buffer.take();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_discovery_buffer_dedup() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1), None);
        let pubkey = test_pubkey();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let beacon = Beacon {
            pubkey,
            scope: None,
        };
        buffer.add_peer(mac, beacon.clone());
        buffer.add_peer(mac, beacon); // same MAC again

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_discovery_buffer_scope_filter() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1), Some("scope-a".to_string()));
        let pubkey = test_pubkey();
        let mac_a = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let mac_b = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];

        buffer.add_peer(
            mac_a,
            Beacon {
                pubkey,
                scope: Some("scope-b".to_string()),
            },
        );
        buffer.add_peer(
            mac_b,
            Beacon {
                pubkey,
                scope: Some("scope-a".to_string()),
            },
        );

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr.as_bytes(), &mac_b);
    }

    fn nth_mac(n: usize) -> [u8; 6] {
        let bytes = (n as u64).to_be_bytes();
        [0x02, bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    #[test]
    fn discovery_buffer_is_bounded_and_refreshes_known_neighbors() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1), None);
        let beacon = Beacon {
            pubkey: test_pubkey(),
            scope: None,
        };
        for n in 0..MAX_BUFFERED_PEERS + 7 {
            buffer.add_peer(nth_mac(n), beacon.clone());
        }
        assert_eq!(buffer.dropped(), 7);
        assert!(buffer.add_peer(nth_mac(0), beacon));

        let peers = buffer.take();
        assert_eq!(peers.len(), MAX_BUFFERED_PEERS);
        assert_eq!(peers.last().unwrap().addr.as_bytes(), &nth_mac(0));
    }

    #[test]
    fn warning_threshold_advances_by_decades() {
        assert_eq!(next_decade(0), 1);
        assert_eq!(next_decade(1), 10);
        assert_eq!(next_decade(10), 100);
        assert_eq!(next_decade(u64::MAX), u64::MAX);
    }
}
