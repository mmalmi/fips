//! FSP Wire Format Parsing and Serialization
//!
//! Defines the FIPS session-layer wire format (FSP) for packet dispatch.
//! All FSP messages begin with a 4-byte common prefix followed by phase-specific
//! fields. Encrypted messages use a 12-byte cleartext header as AAD for AEAD,
//! and a 6-byte encrypted inner header containing timestamps and message type.
//!
//! ## Common Prefix (4 bytes)
//!
//! ```text
//! [ver+phase:1][flags:1][payload_len:2 LE]
//! ```
//!
//! ## DataPacket Port Multiplexing
//!
//! DataPacket (msg_type 0x10) payloads inside the AEAD envelope carry a 4-byte
//! port header for service dispatch:
//!
//! ```text
//! [src_port:2 LE][dst_port:2 LE][service payload...]
//! ```
//!
//! Port 256 (0x100) = IPv6 shim with header compression.
//!
//! App-owned endpoint data uses EndpointData/EndpointDataBulk directly, without
//! DataPacket port dispatch.
//!
//! ## Message Classes
//!
//! | Phase | U Flag | Type             | Description                       |
//! |-------|--------|------------------|-----------------------------------|
//! | 0x0   | 0      | Encrypted        | Post-handshake encrypted data     |
//! | 0x0   | 1      | Plaintext error  | CoordsRequired, PathBroken        |
//! | 0x1   | -      | Handshake msg1   | SessionSetup (Noise XK msg1)      |
//! | 0x2   | -      | Handshake msg2   | SessionAck (Noise XK msg2)        |
//! | 0x3   | -      | Handshake msg3   | SessionMsg3 (Noise XK msg3)       |

use crate::protocol::{ProtocolError, decode_optional_coords};
use crate::transport::PacketBuffer;
use crate::tree::TreeCoordinate;
use std::ops::Range;

// ============================================================================
// Constants
// ============================================================================

/// FSP protocol version (4 high bits of byte 0).
pub const FSP_VERSION: u8 = 0;

/// Phase value for established (encrypted or plaintext error) messages.
pub const FSP_PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for SessionSetup (Noise IK message 1).
pub const FSP_PHASE_MSG1: u8 = 0x1;

/// Phase value for SessionAck (Noise handshake message 2).
pub const FSP_PHASE_MSG2: u8 = 0x2;

/// Phase value for XK message 3 (initiator's encrypted static).
pub const FSP_PHASE_MSG3: u8 = 0x3;

/// Size of the common packet prefix (all FSP message types).
pub const FSP_COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full encrypted message header (prefix + counter).
pub const FSP_HEADER_SIZE: usize = 12;

/// Size of the encrypted inner header (timestamp + msg_type + inner_flags).
pub const FSP_INNER_HEADER_SIZE: usize = 6;

// FSP DataPacket port header constants.

/// Size of the FSP DataPacket port header (src_port + dst_port).
pub const FSP_PORT_HEADER_SIZE: usize = 4;

/// FSP port: IPv6 shim service.
pub const FSP_PORT_IPV6_SHIM: u16 = 256;

/// Maximum endpoint payloads carried by one authenticated endpoint-data bulk record.
///
/// The u16 FSP body length can hold about 48 nvpn MTU-sized packets. Keeping
/// that whole Linux vnet/GRO-sized run in one direct-FSP record avoids
/// splitting a natural TUN batch into multiple AEAD records on the hot path.
pub const FSP_ENDPOINT_DATA_BULK_MAX_PACKETS: usize = 48;

const FSP_ENDPOINT_DATA_BULK_COUNT_SIZE: usize = 2;
const FSP_ENDPOINT_DATA_BULK_LEN_SIZE: usize = 2;

// Cleartext flag bit constants (byte 1 of common prefix, phase 0x0 only).

/// Coords Present — source and destination coordinates follow the header.
pub const FSP_FLAG_CP: u8 = 0x01;

/// Key Epoch — selects active key during rekeying.
#[allow(dead_code)]
pub const FSP_FLAG_K: u8 = 0x02;

/// Unencrypted — payload is plaintext (error signals).
pub const FSP_FLAG_U: u8 = 0x04;

/// Direct Transport — encrypted FSP is carried directly on the transport.
pub const FSP_FLAG_DIRECT_TRANSPORT: u8 = 0x08;

// Inner flag bit constants (byte 5 of decrypted inner header).

/// Spin bit for end-to-end RTT measurement (inside AEAD).
#[allow(dead_code)]
pub const FSP_INNER_FLAG_SP: u8 = 0x01;

/// Maximum endpoint-data body bytes that fit under the FSP u16 payload length.
pub const fn fsp_endpoint_data_max_body_len() -> usize {
    u16::MAX as usize - FSP_INNER_HEADER_SIZE
}

/// Encoded body bytes added by one packet in an endpoint-data bulk record.
pub const fn fsp_endpoint_data_bulk_packet_wire_len(packet_len: usize) -> Option<usize> {
    if packet_len > u16::MAX as usize {
        return None;
    }
    Some(FSP_ENDPOINT_DATA_BULK_LEN_SIZE + packet_len)
}

/// Initial encoded body length for an endpoint-data bulk record before packet entries.
pub const fn fsp_endpoint_data_bulk_base_wire_len() -> usize {
    FSP_ENDPOINT_DATA_BULK_COUNT_SIZE
}

/// Encode packet boundaries and bytes for `SessionMessageType::EndpointDataBulk`.
pub fn encode_fsp_endpoint_data_bulk_payload(mut packets: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    if packets.is_empty() || packets.len() > FSP_ENDPOINT_DATA_BULK_MAX_PACKETS {
        return None;
    }

    let mut wire_len = fsp_endpoint_data_bulk_base_wire_len();
    for packet in &packets {
        wire_len = wire_len.checked_add(fsp_endpoint_data_bulk_packet_wire_len(packet.len())?)?;
    }
    if wire_len > fsp_endpoint_data_max_body_len() {
        return None;
    }

    let mut encoded = Vec::with_capacity(wire_len);
    encoded.extend_from_slice(&(packets.len() as u16).to_le_bytes());
    for packet in &mut packets {
        encoded.extend_from_slice(&(packet.len() as u16).to_le_bytes());
        encoded.append(packet);
    }
    Some(encoded)
}

/// Decode packet lengths from an endpoint-data bulk body.
pub fn decode_fsp_endpoint_data_bulk_lengths(payload: &[u8]) -> Option<Vec<usize>> {
    Some(
        decode_fsp_endpoint_data_bulk_ranges(payload)?
            .into_iter()
            .map(|range| range.len())
            .collect(),
    )
}

/// Decode packet byte ranges from an endpoint-data bulk body.
///
/// The returned ranges point into `payload`; they skip the bulk count and each
/// per-packet length field. Keeping ranges instead of splitting immediately lets
/// endpoint embedders borrow packet slices from one opened AEAD buffer.
pub fn decode_fsp_endpoint_data_bulk_ranges(payload: &[u8]) -> Option<Vec<Range<usize>>> {
    if payload.len() < FSP_ENDPOINT_DATA_BULK_COUNT_SIZE {
        return None;
    }
    let count = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if count == 0 || count > FSP_ENDPOINT_DATA_BULK_MAX_PACKETS {
        return None;
    }

    let mut lengths = Vec::with_capacity(count);
    let mut offset = FSP_ENDPOINT_DATA_BULK_COUNT_SIZE;
    for _ in 0..count {
        let len_end = offset.checked_add(FSP_ENDPOINT_DATA_BULK_LEN_SIZE)?;
        let len_bytes = payload.get(offset..len_end)?;
        let packet_len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
        offset = len_end;
        let packet_end = offset.checked_add(packet_len)?;
        payload.get(offset..packet_end)?;
        lengths.push(offset..packet_end);
        offset = packet_end;
    }

    (offset == payload.len()).then_some(lengths)
}

/// Split an owned endpoint-data bulk body into owned packet buffers.
pub fn split_fsp_endpoint_data_bulk_payload(
    payload: PacketBuffer,
    lengths: &[usize],
) -> Vec<PacketBuffer> {
    let body = payload.as_slice();
    let mut packets = Vec::with_capacity(lengths.len());
    let mut offset = FSP_ENDPOINT_DATA_BULK_COUNT_SIZE;
    for packet_len in lengths {
        offset += FSP_ENDPOINT_DATA_BULK_LEN_SIZE;
        let packet_end = offset + packet_len;
        packets.push(body[offset..packet_end].to_vec().into());
        offset = packet_end;
    }
    packets
}

// ============================================================================
// Common Prefix
// ============================================================================

/// Parsed FSP common packet prefix (first 4 bytes of every FSP message).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct FspCommonPrefix {
    /// Protocol version (high nibble of byte 0).
    #[cfg_attr(not(test), allow(dead_code))]
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-message signal flags.
    pub flags: u8,
    /// Length of payload following the phase-specific header.
    #[cfg_attr(not(test), allow(dead_code))]
    pub payload_len: u16,
}

impl FspCommonPrefix {
    /// Parse a common prefix from the first 4 bytes of FSP message data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < FSP_COMMON_PREFIX_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;
        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);

        Some(Self {
            version,
            phase,
            flags,
            payload_len,
        })
    }

    /// Check if the Unencrypted flag is set.
    pub fn is_unencrypted(&self) -> bool {
        self.flags & FSP_FLAG_U != 0
    }

    /// Check if the Coords Present flag is set.
    pub fn has_coords(&self) -> bool {
        self.flags & FSP_FLAG_CP != 0
    }

    /// Encode the ver+phase byte.
    fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build the 12-byte cleartext header for an encrypted FSP message.
///
/// Returns the header bytes for use as AEAD AAD.
#[cfg(test)]
pub fn build_fsp_header(counter: u64, flags: u8, payload_len: u16) -> [u8; FSP_HEADER_SIZE] {
    let mut header = [0u8; FSP_HEADER_SIZE];
    header[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, FSP_PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..12].copy_from_slice(&counter.to_le_bytes());
    header
}

/// Build a 4-byte common prefix for a handshake message.
///
/// `phase` should be `FSP_PHASE_MSG1`, `FSP_PHASE_MSG2`, or `FSP_PHASE_MSG3`.
/// Flags are zero during handshake.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_handshake_prefix(phase: u8, payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    let mut prefix = [0u8; FSP_COMMON_PREFIX_SIZE];
    prefix[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, phase);
    prefix[1] = 0x00; // flags must be zero during handshake
    prefix[2..4].copy_from_slice(&payload_len.to_le_bytes());
    prefix
}

/// Build a 4-byte common prefix for a plaintext error signal.
///
/// Sets phase 0x0 and U flag.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_error_prefix(payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    let mut prefix = [0u8; FSP_COMMON_PREFIX_SIZE];
    prefix[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, FSP_PHASE_ESTABLISHED);
    prefix[1] = FSP_FLAG_U;
    prefix[2..4].copy_from_slice(&payload_len.to_le_bytes());
    prefix
}

// ============================================================================
// Inner Header Helpers
// ============================================================================

/// Prepend the 6-byte FSP inner header to a message payload.
///
/// Inner header: `[timestamp:4 LE][msg_type:1][inner_flags:1]`
///
/// The caller provides the message-type-specific payload (e.g., application
/// data for msg_type 0x10, report fields for SenderReport). This function
/// prepends the inner header.
#[cfg(test)]
pub fn fsp_prepend_inner_header(
    timestamp_ms: u32,
    msg_type: u8,
    inner_flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FSP_INNER_HEADER_SIZE + payload.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(msg_type);
    buf.push(inner_flags);
    buf.extend_from_slice(payload);
    buf
}

/// Strip the 6-byte FSP inner header from a decrypted payload.
///
/// Returns `(timestamp, msg_type, inner_flags, &rest)` or None if too short.
pub fn fsp_strip_inner_header(plaintext: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    if plaintext.len() < FSP_INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    let msg_type = plaintext[4];
    let inner_flags = plaintext[5];
    Some((
        timestamp,
        msg_type,
        inner_flags,
        &plaintext[FSP_INNER_HEADER_SIZE..],
    ))
}

// ============================================================================
// Coordinate Parsing (for transit nodes and receive path)
// ============================================================================

/// Parse source and destination coordinates from the cleartext section
/// of an encrypted FSP message when the CP flag is set.
///
/// Coordinates appear between the 12-byte header and the ciphertext:
/// `[src_coords_count:2 LE][src_coords:16×n][dest_coords_count:2 LE][dest_coords:16×m]`
///
/// Returns `(src_coords, dest_coords, bytes_consumed)`.
pub fn parse_encrypted_coords(
    data: &[u8],
) -> Result<(Option<TreeCoordinate>, Option<TreeCoordinate>, usize), ProtocolError> {
    let (src_coords, src_consumed) = decode_optional_coords(data)?;
    let (dest_coords, dest_consumed) = decode_optional_coords(&data[src_consumed..])?;
    Ok((src_coords, dest_coords, src_consumed + dest_consumed))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Size Constant Tests =====

    #[test]
    fn test_wire_sizes() {
        assert_eq!(FSP_COMMON_PREFIX_SIZE, 4);
        assert_eq!(FSP_HEADER_SIZE, 12);
        assert_eq!(FSP_INNER_HEADER_SIZE, 6);
    }

    // ===== Common Prefix Tests =====

    #[test]
    fn test_common_prefix_parse_established() {
        let data = [0x00, 0x01, 0x40, 0x00]; // ver=0, phase=0, flags=CP, payload_len=64
        let prefix = FspCommonPrefix::parse(&data).unwrap();
        assert_eq!(prefix.version, 0);
        assert_eq!(prefix.phase, FSP_PHASE_ESTABLISHED);
        assert_eq!(prefix.flags, FSP_FLAG_CP);
        assert_eq!(prefix.payload_len, 64);
        assert!(prefix.has_coords());
        assert!(!prefix.is_unencrypted());
    }

    #[test]
    fn test_common_prefix_parse_handshake() {
        let data = [0x01, 0x00, 0x50, 0x00]; // ver=0, phase=1, flags=0, payload_len=80
        let prefix = FspCommonPrefix::parse(&data).unwrap();
        assert_eq!(prefix.version, 0);
        assert_eq!(prefix.phase, FSP_PHASE_MSG1);
        assert_eq!(prefix.flags, 0);
        assert_eq!(prefix.payload_len, 80);
    }

    #[test]
    fn test_common_prefix_parse_error_signal() {
        let data = [0x00, FSP_FLAG_U, 0x22, 0x00]; // ver=0, phase=0, U flag, payload_len=34
        let prefix = FspCommonPrefix::parse(&data).unwrap();
        assert_eq!(prefix.phase, FSP_PHASE_ESTABLISHED);
        assert!(prefix.is_unencrypted());
        assert_eq!(prefix.payload_len, 34);
    }

    #[test]
    fn test_common_prefix_too_short() {
        assert!(FspCommonPrefix::parse(&[0, 0, 0]).is_none());
    }

    // ===== Build Header Tests =====

    #[test]
    fn test_build_fsp_header() {
        let header = build_fsp_header(1000, FSP_FLAG_CP, 200);
        assert_eq!(header[0], 0x00); // ver=0, phase=0
        assert_eq!(header[1], FSP_FLAG_CP);
        assert_eq!(u16::from_le_bytes([header[2], header[3]]), 200);
        assert_eq!(
            u64::from_le_bytes([
                header[4], header[5], header[6], header[7], header[8], header[9], header[10],
                header[11],
            ]),
            1000
        );
    }

    // ===== Handshake Prefix Tests =====

    #[test]
    fn test_build_fsp_handshake_prefix_msg1() {
        let prefix = build_fsp_handshake_prefix(FSP_PHASE_MSG1, 100);
        assert_eq!(prefix[0], 0x01); // ver=0, phase=1
        assert_eq!(prefix[1], 0x00); // flags zero
        assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 100);

        let parsed = FspCommonPrefix::parse(&prefix).unwrap();
        assert_eq!(parsed.phase, FSP_PHASE_MSG1);
    }

    #[test]
    fn test_build_fsp_handshake_prefix_msg2() {
        let prefix = build_fsp_handshake_prefix(FSP_PHASE_MSG2, 50);
        assert_eq!(prefix[0], 0x02); // ver=0, phase=2
        assert_eq!(prefix[1], 0x00);
        assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 50);
    }

    #[test]
    fn test_build_fsp_handshake_prefix_msg3() {
        let prefix = build_fsp_handshake_prefix(FSP_PHASE_MSG3, 73);
        assert_eq!(prefix[0], 0x03); // ver=0, phase=3
        assert_eq!(prefix[1], 0x00); // flags zero
        assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 73);

        let parsed = FspCommonPrefix::parse(&prefix).unwrap();
        assert_eq!(parsed.phase, FSP_PHASE_MSG3);
    }

    // ===== Error Prefix Tests =====

    #[test]
    fn test_build_fsp_error_prefix() {
        let prefix = build_fsp_error_prefix(34);
        assert_eq!(prefix[0], 0x00); // ver=0, phase=0
        assert_eq!(prefix[1], FSP_FLAG_U);
        assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 34);

        let parsed = FspCommonPrefix::parse(&prefix).unwrap();
        assert!(parsed.is_unencrypted());
        assert_eq!(parsed.phase, FSP_PHASE_ESTABLISHED);
    }

    // ===== Inner Header Tests =====

    #[test]
    fn test_inner_header_prepend_strip() {
        let timestamp: u32 = 12345;
        let msg_type: u8 = 0x10;
        let inner_flags: u8 = 0x01; // SP bit
        let payload = vec![0xAA, 0xBB, 0xCC];

        let with_header = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &payload);
        assert_eq!(with_header.len(), FSP_INNER_HEADER_SIZE + 3);

        let (ts, mt, flags, rest) = fsp_strip_inner_header(&with_header).unwrap();
        assert_eq!(ts, 12345);
        assert_eq!(mt, 0x10);
        assert_eq!(flags, 0x01);
        assert_eq!(rest, &payload[..]);
    }

    #[test]
    fn test_inner_header_empty_payload() {
        let with_header = fsp_prepend_inner_header(0, 0x13, 0, &[]);
        assert_eq!(with_header.len(), FSP_INNER_HEADER_SIZE);

        let (ts, mt, flags, rest) = fsp_strip_inner_header(&with_header).unwrap();
        assert_eq!(ts, 0);
        assert_eq!(mt, 0x13);
        assert_eq!(flags, 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_inner_header_too_short() {
        assert!(fsp_strip_inner_header(&[0, 0, 0, 0, 0]).is_none()); // needs 6 bytes
        assert!(fsp_strip_inner_header(&[]).is_none());
    }

    #[test]
    fn endpoint_data_bulk_payload_roundtrips_packet_boundaries() {
        let encoded = encode_fsp_endpoint_data_bulk_payload(vec![
            b"first".to_vec(),
            b"second-packet".to_vec(),
            b"third".to_vec(),
        ])
        .unwrap();

        let lengths = decode_fsp_endpoint_data_bulk_lengths(&encoded).unwrap();
        assert_eq!(lengths, vec![5, 13, 5]);

        let packets = split_fsp_endpoint_data_bulk_payload(encoded.into(), &lengths);
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].as_slice(), b"first");
        assert_eq!(packets[1].as_slice(), b"second-packet");
        assert_eq!(packets[2].as_slice(), b"third");
    }

    #[test]
    fn endpoint_data_bulk_payload_rejects_malformed_records() {
        assert!(encode_fsp_endpoint_data_bulk_payload(Vec::new()).is_none());
        assert!(decode_fsp_endpoint_data_bulk_lengths(&[]).is_none());
        assert!(decode_fsp_endpoint_data_bulk_lengths(&[0, 0]).is_none());
        assert!(decode_fsp_endpoint_data_bulk_lengths(&[1, 0, 5, 0, b'a']).is_none());

        let too_many = vec![Vec::new(); FSP_ENDPOINT_DATA_BULK_MAX_PACKETS + 1];
        assert!(encode_fsp_endpoint_data_bulk_payload(too_many).is_none());
    }

    #[test]
    fn endpoint_data_bulk_payload_preserves_vnet_sized_run() {
        let mtu_sized_packets = vec![vec![0x42; 1342]; FSP_ENDPOINT_DATA_BULK_MAX_PACKETS];
        let encoded =
            encode_fsp_endpoint_data_bulk_payload(mtu_sized_packets).expect("48 MTU packets fit");
        let lengths = decode_fsp_endpoint_data_bulk_lengths(&encoded).unwrap();
        assert_eq!(lengths, vec![1342; FSP_ENDPOINT_DATA_BULK_MAX_PACKETS]);

        let one_too_many = vec![vec![0x42; 1342]; FSP_ENDPOINT_DATA_BULK_MAX_PACKETS + 1];
        assert!(encode_fsp_endpoint_data_bulk_payload(one_too_many).is_none());
    }

    // ===== Flag Constants Tests =====

    #[test]
    fn test_flag_bits_distinct() {
        // Cleartext flags don't overlap
        assert_eq!(FSP_FLAG_CP & FSP_FLAG_K, 0);
        assert_eq!(FSP_FLAG_CP & FSP_FLAG_U, 0);
        assert_eq!(FSP_FLAG_K & FSP_FLAG_U, 0);
    }

    #[test]
    fn test_all_message_types_through_prefix() {
        // Encrypted (phase 0, no U)
        let prefix = FspCommonPrefix::parse(&[0x00, 0x00, 0x10, 0x00]).unwrap();
        assert_eq!(prefix.phase, 0);
        assert!(!prefix.is_unencrypted());

        // Error signal (phase 0, U set)
        let prefix = FspCommonPrefix::parse(&[0x00, FSP_FLAG_U, 0x22, 0x00]).unwrap();
        assert_eq!(prefix.phase, 0);
        assert!(prefix.is_unencrypted());

        // SessionSetup (phase 1)
        let prefix = FspCommonPrefix::parse(&[0x01, 0x00, 0x50, 0x00]).unwrap();
        assert_eq!(prefix.phase, 1);

        // SessionAck (phase 2)
        let prefix = FspCommonPrefix::parse(&[0x02, 0x00, 0x21, 0x00]).unwrap();
        assert_eq!(prefix.phase, 2);

        // SessionMsg3 (phase 3)
        let prefix = FspCommonPrefix::parse(&[0x03, 0x00, 0x49, 0x00]).unwrap();
        assert_eq!(prefix.phase, 3);
    }
}
