//! Wire Format Parsing and Serialization
//!
//! Defines the FIPS mesh-layer wire format (FMP) for packet dispatch.
//! All packets begin with a 4-byte common prefix followed by phase-specific fields.
//!
//! ## Common Prefix (4 bytes)
//!
//! ```text
//! [ver+phase:1][flags:1][payload_len:2 LE]
//! ```
//!
//! ## Packet Types
//!
//! | Phase | Type            | Size       | Description                    |
//! |-------|-----------------|------------|--------------------------------|
//! | 0x0   | Encrypted frame | 32+ bytes  | Post-handshake encrypted data  |
//! | 0x1   | Noise IK msg1   | 114 bytes  | Handshake initiation           |
//! | 0x2   | Noise IK msg2   | 69 bytes   | Handshake response             |

use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE};
use crate::utils::index::SessionIndex;

// ============================================================================
// Constants
// ============================================================================

/// FMP protocol version (4 high bits of byte 0).
pub const FMP_VERSION: u8 = 0;

/// Phase value for established (encrypted) frames.
pub const PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for Noise IK message 1 (handshake initiation).
pub const PHASE_MSG1: u8 = 0x1;

/// Phase value for Noise IK message 2 (handshake response).
pub const PHASE_MSG2: u8 = 0x2;

/// Size of the common packet prefix (all packet types).
pub const COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full established frame header (prefix + receiver_idx + counter).
pub const ESTABLISHED_HEADER_SIZE: usize = 16;

/// Size of Noise IK message 1 wire packet: prefix + sender_idx + noise_msg1.
pub const MSG1_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + HANDSHAKE_MSG1_SIZE; // 114 bytes

/// Size of Noise IK message 2 wire packet: prefix + sender_idx + receiver_idx + noise_msg2.
pub const MSG2_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + 4 + HANDSHAKE_MSG2_SIZE; // 69 bytes

// Flag bit constants (byte 1 of common prefix, meaningful only for phase 0x0).
// Reserved for upcoming rekeying, congestion signaling, and RTT measurement.
/// Key epoch flag — selects active key during rekeying.
pub const FLAG_KEY_EPOCH: u8 = 0x01;
/// Congestion Experienced echo flag.
pub const FLAG_CE: u8 = 0x02;
/// Spin bit for RTT measurement.
pub const FLAG_SP: u8 = 0x04;
// ============================================================================
// Common Prefix
// ============================================================================

/// Parsed common packet prefix (first 4 bytes of every FMP packet).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct CommonPrefix {
    /// Protocol version (high nibble of byte 0).
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-packet signal flags (meaningful only for phase 0x0).
    #[cfg(test)]
    pub flags: u8,
    /// Length of payload following the phase-specific header (excludes AEAD tag).
    #[cfg(test)]
    pub payload_len: u16,
}

impl CommonPrefix {
    /// Parse a common prefix from the first 4 bytes of packet data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < COMMON_PREFIX_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;
        #[cfg(test)]
        let flags = data[1];
        #[cfg(test)]
        let payload_len = u16::from_le_bytes([data[2], data[3]]);

        Some(Self {
            version,
            phase,
            #[cfg(test)]
            flags,
            #[cfg(test)]
            payload_len,
        })
    }

    /// Encode the ver+phase byte.
    fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

// ============================================================================
// Msg1 Header
// ============================================================================

/// Parsed Noise IK message 1 header (phase 0x1).
///
/// Wire format (114 bytes):
/// ```text
/// [0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:106]
/// ```
#[derive(Clone, Debug)]
pub struct Msg1Header {
    /// Session index chosen by the sender (becomes receiver_idx for responses).
    pub sender_idx: SessionIndex,
    /// Offset where Noise msg1 payload begins.
    pub noise_msg1_offset: usize,
}

impl Msg1Header {
    /// Parse a msg1 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG1_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_MSG1 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Some(Self {
            sender_idx,
            noise_msg1_offset: COMMON_PREFIX_SIZE + 4, // 8
        })
    }

    /// Get the Noise msg1 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg1<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg1_offset..]
    }
}

// ============================================================================
// Msg2 Header
// ============================================================================

/// Parsed Noise IK message 2 header (phase 0x2).
///
/// Wire format (69 bytes):
/// ```text
/// [0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:57]
/// ```
#[derive(Clone, Debug)]
pub struct Msg2Header {
    /// Session index chosen by the responder.
    pub sender_idx: SessionIndex,
    /// Echo of the initiator's sender_idx from msg1.
    pub receiver_idx: SessionIndex,
    /// Offset where Noise msg2 payload begins.
    pub noise_msg2_offset: usize,
}

impl Msg2Header {
    /// Parse a msg2 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG2_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_MSG2 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[8], data[9], data[10], data[11]]);

        Some(Self {
            sender_idx,
            receiver_idx,
            noise_msg2_offset: COMMON_PREFIX_SIZE + 4 + 4, // 12
        })
    }

    /// Get the Noise msg2 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg2<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg2_offset..]
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build a wire-format msg1 packet.
///
/// Format: `[0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:106]`
pub fn build_msg1(sender_idx: SessionIndex, noise_msg1: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg1.len(), HANDSHAKE_MSG1_SIZE);

    let payload_len = (4 + noise_msg1.len()) as u16; // sender_idx + noise_msg1

    let mut packet = Vec::with_capacity(MSG1_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_MSG1));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg1);
    packet
}

/// Build a wire-format msg2 packet.
///
/// Format: `[0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:57]`
pub fn build_msg2(
    sender_idx: SessionIndex,
    receiver_idx: SessionIndex,
    noise_msg2: &[u8],
) -> Vec<u8> {
    debug_assert_eq!(noise_msg2.len(), HANDSHAKE_MSG2_SIZE);

    let payload_len = (4 + 4 + noise_msg2.len()) as u16; // sender + receiver + noise

    let mut packet = Vec::with_capacity(MSG2_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_MSG2));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg2);
    packet
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_prefix_parse() {
        let data = [0x00, 0x04, 0x20, 0x00]; // ver=0, phase=0, flags=SP, payload_len=32
        let prefix = CommonPrefix::parse(&data).unwrap();
        assert_eq!(prefix.version, 0);
        assert_eq!(prefix.phase, 0);
        assert_eq!(prefix.flags, FLAG_SP);
        assert_eq!(prefix.payload_len, 32);
    }

    #[test]
    fn test_common_prefix_too_short() {
        assert!(CommonPrefix::parse(&[0, 0, 0]).is_none());
    }

    #[test]
    fn test_msg1_header_parse() {
        let sender_idx = SessionIndex::new(0xABCDEF01);
        let noise_msg1 = vec![0xbb; HANDSHAKE_MSG1_SIZE];

        let packet = build_msg1(sender_idx, &noise_msg1);

        assert_eq!(packet.len(), MSG1_WIRE_SIZE);
        assert_eq!(packet[0], 0x01); // ver=0, phase=1

        let header = Msg1Header::parse(&packet).expect("should parse");
        assert_eq!(header.sender_idx, sender_idx);
        assert_eq!(header.noise_msg1_offset, 8);
        assert_eq!(header.noise_msg1(&packet), &noise_msg1[..]);
    }

    #[test]
    fn test_msg1_header_wrong_size() {
        let packet = vec![0x01; MSG1_WIRE_SIZE - 1];
        assert!(Msg1Header::parse(&packet).is_none());

        let packet = vec![0x01; MSG1_WIRE_SIZE + 1];
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg1_header_wrong_phase() {
        let mut packet = vec![0x00; MSG1_WIRE_SIZE];
        packet[0] = 0x02; // phase 2, not phase 1
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg1_header_nonzero_flags() {
        let mut packet = build_msg1(SessionIndex::new(1), &[0u8; HANDSHAKE_MSG1_SIZE]);
        packet[1] = 0x01; // flags must be zero during handshake
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg2_header_parse() {
        let sender_idx = SessionIndex::new(0x11223344);
        let receiver_idx = SessionIndex::new(0x55667788);
        let noise_msg2 = vec![0xcc; HANDSHAKE_MSG2_SIZE];

        let packet = build_msg2(sender_idx, receiver_idx, &noise_msg2);

        assert_eq!(packet.len(), MSG2_WIRE_SIZE);
        assert_eq!(packet[0], 0x02); // ver=0, phase=2

        let header = Msg2Header::parse(&packet).expect("should parse");
        assert_eq!(header.sender_idx, sender_idx);
        assert_eq!(header.receiver_idx, receiver_idx);
        assert_eq!(header.noise_msg2_offset, 12);
        assert_eq!(header.noise_msg2(&packet), &noise_msg2[..]);
    }

    #[test]
    fn test_msg2_header_wrong_size() {
        let packet = vec![0x02; MSG2_WIRE_SIZE - 1];
        assert!(Msg2Header::parse(&packet).is_none());

        let packet = vec![0x02; MSG2_WIRE_SIZE + 1];
        assert!(Msg2Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg2_header_wrong_phase() {
        let mut packet = vec![0x00; MSG2_WIRE_SIZE];
        packet[0] = 0x00; // phase 0, not phase 2
        assert!(Msg2Header::parse(&packet).is_none());
    }

    #[test]
    fn test_wire_sizes() {
        assert_eq!(MSG1_WIRE_SIZE, 114); // 4 + 4 + 106
        assert_eq!(MSG2_WIRE_SIZE, 69); // 4 + 4 + 4 + 57
        assert_eq!(COMMON_PREFIX_SIZE, 4);
        assert_eq!(ESTABLISHED_HEADER_SIZE, 16);
    }

    #[test]
    fn test_roundtrip_indices() {
        let idx = SessionIndex::new(0xDEADBEEF);

        let msg1 = build_msg1(idx, &[0u8; HANDSHAKE_MSG1_SIZE]);
        let parsed = Msg1Header::parse(&msg1).unwrap();
        assert_eq!(parsed.sender_idx.as_u32(), 0xDEADBEEF);

        // Verify little-endian encoding (sender_idx starts at offset 4)
        assert_eq!(msg1[4], 0xEF);
        assert_eq!(msg1[5], 0xBE);
        assert_eq!(msg1[6], 0xAD);
        assert_eq!(msg1[7], 0xDE);
    }

    #[test]
    fn test_payload_len_in_msg1() {
        let packet = build_msg1(SessionIndex::new(1), &[0u8; HANDSHAKE_MSG1_SIZE]);
        let prefix = CommonPrefix::parse(&packet).unwrap();
        // payload_len = sender_idx(4) + noise_msg1(106) = 110
        assert_eq!(prefix.payload_len, 110);
    }

    #[test]
    fn test_payload_len_in_msg2() {
        let packet = build_msg2(
            SessionIndex::new(1),
            SessionIndex::new(2),
            &[0u8; HANDSHAKE_MSG2_SIZE],
        );
        let prefix = CommonPrefix::parse(&packet).unwrap();
        // payload_len = sender_idx(4) + receiver_idx(4) + noise_msg2(57) = 65
        assert_eq!(prefix.payload_len, 65);
    }
}
