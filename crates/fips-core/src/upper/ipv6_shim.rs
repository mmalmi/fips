//! IPv6 Header Compression for the FIPS IPv6 Shim (FSP Port 256)
//!
//! Compresses and decompresses IPv6 headers for mesh-internal traffic.
//! Source and destination addresses are stripped (derivable from session
//! context), along with version and payload length. Residual fields
//! (traffic class, flow label, next header, hop limit) are preserved.
//!
//! ## Compressed Format (format 0x00)
//!
//! ```text
//! [format:1][ver_tc_flow:4][next_header:1][hop_limit:1][upper_layer_payload...]
//! ```
//!
//! The `ver_tc_flow` field stores the original IPv6 bytes 0-3 verbatim
//! (including the version nibble). On decompression, the version nibble
//! is forced to 6, payload length is computed from the remaining data,
//! and source/destination addresses are reconstructed from session context.

use crate::transport::PacketBuffer;

/// Compressed format byte for mesh-internal traffic.
pub const IPV6_SHIM_FORMAT_COMPRESSED: u8 = 0x00;

/// Size of the compressed residual fields (ver_tc_flow + next_header + hop_limit).
const IPV6_SHIM_RESIDUAL_SIZE: usize = 6;

/// IPv6 header size.
const IPV6_HEADER_SIZE: usize = 40;

/// Compress an IPv6 packet for the shim.
///
/// Strips source/destination addresses (32 bytes) and payload length (2 bytes).
/// Preserves traffic class, flow label, next header, and hop limit as residual
/// fields.
///
/// Returns `None` if the packet is not a valid IPv6 packet (too short or wrong
/// version).
pub fn compress_ipv6(ipv6_packet: &[u8]) -> Option<Vec<u8>> {
    if ipv6_packet.len() < IPV6_HEADER_SIZE || ipv6_packet[0] >> 4 != 6 {
        return None;
    }

    let upper_payload = &ipv6_packet[IPV6_HEADER_SIZE..];
    let mut out = Vec::with_capacity(1 + IPV6_SHIM_RESIDUAL_SIZE + upper_payload.len());

    // Format byte
    out.push(IPV6_SHIM_FORMAT_COMPRESSED);

    // Residual: bytes 0-3 of IPv6 header (version + TC + flow label)
    out.extend_from_slice(&ipv6_packet[0..4]);

    // Residual: next header and hop limit
    out.push(ipv6_packet[6]); // next_header
    out.push(ipv6_packet[7]); // hop_limit

    // Upper-layer payload (everything after the 40-byte IPv6 header)
    out.extend_from_slice(upper_payload);

    Some(out)
}

/// Compress an IPv6 packet in-place and prepend the FSP DataPacket port header.
///
/// On success `packet` is rewritten to:
///
/// ```text
/// [src_port:2][dst_port:2][format:1][ver_tc_flow:4][next_header:1][hop_limit:1][payload...]
/// ```
///
/// This is byte-identical to prefixing [`compress_ipv6`] with the two LE port
/// fields, but it avoids allocating and copying the whole upper-layer payload on
/// the TUN outbound hot path.
pub fn compress_ipv6_with_port_header_in_place(
    packet: &mut Vec<u8>,
    src_port: u16,
    dst_port: u16,
) -> bool {
    if packet.len() < IPV6_HEADER_SIZE || packet[0] >> 4 != 6 {
        return false;
    }

    let residual_0_3 = [packet[0], packet[1], packet[2], packet[3]];
    let next_header = packet[6];
    let hop_limit = packet[7];
    let upper_payload_len = packet.len() - IPV6_HEADER_SIZE;
    const PORT_HEADER_SIZE: usize = 4;
    let compressed_len = PORT_HEADER_SIZE + 1 + IPV6_SHIM_RESIDUAL_SIZE + upper_payload_len;

    packet[0..2].copy_from_slice(&src_port.to_le_bytes());
    packet[2..4].copy_from_slice(&dst_port.to_le_bytes());
    packet[4] = IPV6_SHIM_FORMAT_COMPRESSED;
    packet[5..9].copy_from_slice(&residual_0_3);
    packet[9] = next_header;
    packet[10] = hop_limit;
    packet.copy_within(
        IPV6_HEADER_SIZE..,
        PORT_HEADER_SIZE + 1 + IPV6_SHIM_RESIDUAL_SIZE,
    );
    packet.truncate(compressed_len);
    true
}

pub(crate) fn compress_ipv6_packet_buffer_with_port_header_in_place(
    packet: &mut PacketBuffer,
    src_port: u16,
    dst_port: u16,
) -> bool {
    if packet.len() < IPV6_HEADER_SIZE || packet.as_slice()[0] >> 4 != 6 {
        return false;
    }

    let bytes = packet.as_slice();
    const PORT_HEADER_SIZE: usize = 4;
    let mut prefix = [0u8; PORT_HEADER_SIZE + 1 + IPV6_SHIM_RESIDUAL_SIZE];
    prefix[0..2].copy_from_slice(&src_port.to_le_bytes());
    prefix[2..4].copy_from_slice(&dst_port.to_le_bytes());
    prefix[4] = IPV6_SHIM_FORMAT_COMPRESSED;
    prefix[5..9].copy_from_slice(&bytes[0..4]);
    prefix[9] = bytes[6];
    prefix[10] = bytes[7];

    packet.replace_prefix(IPV6_HEADER_SIZE, &prefix)
}

/// Decompress a shim payload back to a full IPv6 packet.
///
/// Reconstructs the full 40-byte IPv6 header from the residual fields and
/// session context (source/destination addresses). The payload length field
/// is computed from the remaining data length.
///
/// Returns `None` if the format byte is unrecognized or the payload is too
/// short.
pub fn decompress_ipv6(
    shim_payload: &[u8],
    src_ipv6: [u8; 16],
    dst_ipv6: [u8; 16],
) -> Option<Vec<u8>> {
    if shim_payload.len() < 1 + IPV6_SHIM_RESIDUAL_SIZE {
        return None;
    }

    let format = shim_payload[0];
    if format != IPV6_SHIM_FORMAT_COMPRESSED {
        return None;
    }

    let residual = &shim_payload[1..1 + IPV6_SHIM_RESIDUAL_SIZE];
    let upper_payload = &shim_payload[1 + IPV6_SHIM_RESIDUAL_SIZE..];
    let upper_len = upper_payload.len();

    let mut ipv6 = Vec::with_capacity(IPV6_HEADER_SIZE + upper_len);

    // Bytes 0-3: restore version nibble to 6
    ipv6.push((residual[0] & 0x0F) | 0x60);
    ipv6.extend_from_slice(&residual[1..4]);

    // Bytes 4-5: payload length (big-endian)
    ipv6.extend_from_slice(&(upper_len as u16).to_be_bytes());

    // Byte 6: next header
    ipv6.push(residual[4]);

    // Byte 7: hop limit
    ipv6.push(residual[5]);

    // Bytes 8-23: source address
    ipv6.extend_from_slice(&src_ipv6);

    // Bytes 24-39: destination address
    ipv6.extend_from_slice(&dst_ipv6);

    // Upper-layer payload
    ipv6.extend_from_slice(upper_payload);

    Some(ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv6 packet with the given fields and payload.
    fn build_ipv6_packet(
        traffic_class: u8,
        flow_label: u32,
        next_header: u8,
        hop_limit: u8,
        src: [u8; 16],
        dst: [u8; 16],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(IPV6_HEADER_SIZE + payload.len());

        // Byte 0: version(4) | TC high nibble(4)
        pkt.push(0x60 | (traffic_class >> 4));
        // Byte 1: TC low nibble(4) | flow label high nibble(4)
        pkt.push((traffic_class << 4) | ((flow_label >> 16) as u8 & 0x0F));
        // Bytes 2-3: flow label low 16 bits
        pkt.push((flow_label >> 8) as u8);
        pkt.push(flow_label as u8);

        // Bytes 4-5: payload length
        pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());

        // Byte 6: next header
        pkt.push(next_header);

        // Byte 7: hop limit
        pkt.push(hop_limit);

        // Bytes 8-23: source address
        pkt.extend_from_slice(&src);

        // Bytes 24-39: destination address
        pkt.extend_from_slice(&dst);

        // Payload
        pkt.extend_from_slice(payload);

        pkt
    }

    fn sample_src() -> [u8; 16] {
        [
            0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]
    }

    fn sample_dst() -> [u8; 16] {
        [
            0xfd, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]
    }

    // ===== Round-trip fidelity =====

    #[test]
    fn test_compress_decompress_roundtrip() {
        let payload = vec![0xAA; 100];
        let pkt = build_ipv6_packet(0, 0, 17, 64, sample_src(), sample_dst(), &payload);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        assert_eq!(decompressed, pkt);
    }

    #[test]
    fn test_in_place_port_header_compression_matches_allocating_path() {
        let payload = vec![0x5A; 256];
        let pkt = build_ipv6_packet(0x24, 0x12345, 6, 32, sample_src(), sample_dst(), &payload);
        let compressed = compress_ipv6(&pkt).unwrap();
        let src_port = 0x0100u16;
        let dst_port = 0x0200u16;
        let mut expected = Vec::with_capacity(4 + compressed.len());
        expected.extend_from_slice(&src_port.to_le_bytes());
        expected.extend_from_slice(&dst_port.to_le_bytes());
        expected.extend_from_slice(&compressed);

        let mut in_place = pkt.clone();
        assert!(compress_ipv6_with_port_header_in_place(
            &mut in_place,
            src_port,
            dst_port
        ));

        assert_eq!(in_place, expected);
    }

    #[test]
    fn test_packet_buffer_port_header_compression_matches_vec_path() {
        let payload = vec![0x5A; 256];
        let pkt = build_ipv6_packet(0x24, 0x12345, 6, 32, sample_src(), sample_dst(), &payload);
        let mut expected = pkt.clone();
        let src_port = 0x0100u16;
        let dst_port = 0x0200u16;
        assert!(compress_ipv6_with_port_header_in_place(
            &mut expected,
            src_port,
            dst_port
        ));

        let mut packet_buffer = PacketBuffer::new(pkt);
        assert!(compress_ipv6_packet_buffer_with_port_header_in_place(
            &mut packet_buffer,
            src_port,
            dst_port
        ));

        assert_eq!(packet_buffer.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_roundtrip_empty_payload() {
        let pkt = build_ipv6_packet(0, 0, 59, 1, sample_src(), sample_dst(), &[]);

        let compressed = compress_ipv6(&pkt).unwrap();
        assert_eq!(compressed.len(), 1 + IPV6_SHIM_RESIDUAL_SIZE); // format + residual only

        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();
        assert_eq!(decompressed, pkt);
    }

    #[test]
    fn test_roundtrip_large_payload() {
        let payload = vec![0x55; 1400];
        let pkt = build_ipv6_packet(0, 0, 6, 128, sample_src(), sample_dst(), &payload);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        assert_eq!(decompressed, pkt);
    }

    // ===== Field preservation =====

    #[test]
    fn test_preserves_traffic_class() {
        // TC = 0xAB (DSCP=0x2A, ECN=0x03)
        let pkt = build_ipv6_packet(0xAB, 0, 17, 64, sample_src(), sample_dst(), &[1, 2, 3]);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        assert_eq!(decompressed, pkt);
        // Verify TC is in the right position
        let tc = ((decompressed[0] & 0x0F) << 4) | (decompressed[1] >> 4);
        assert_eq!(tc, 0xAB);
    }

    #[test]
    fn test_preserves_flow_label() {
        let pkt = build_ipv6_packet(0, 0xFEDCB, 17, 64, sample_src(), sample_dst(), &[1]);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        assert_eq!(decompressed, pkt);
    }

    #[test]
    fn test_preserves_tc_and_flow_label_combined() {
        // TC=0xFF, flow_label=0xFFFFF (maximum values)
        let pkt = build_ipv6_packet(0xFF, 0xFFFFF, 17, 64, sample_src(), sample_dst(), &[1]);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        assert_eq!(decompressed, pkt);
    }

    #[test]
    fn test_preserves_next_header_tcp() {
        let pkt = build_ipv6_packet(0, 0, 6, 64, sample_src(), sample_dst(), &[0; 20]);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        assert_eq!(decompressed[6], 6); // TCP
    }

    #[test]
    fn test_preserves_next_header_icmpv6() {
        let pkt = build_ipv6_packet(0, 0, 58, 255, sample_src(), sample_dst(), &[0; 8]);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        assert_eq!(decompressed[6], 58); // ICMPv6
        assert_eq!(decompressed[7], 255); // hop limit
    }

    #[test]
    fn test_preserves_hop_limit() {
        for hop_limit in [0, 1, 64, 128, 255] {
            let pkt = build_ipv6_packet(0, 0, 17, hop_limit, sample_src(), sample_dst(), &[1]);

            let compressed = compress_ipv6(&pkt).unwrap();
            let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

            assert_eq!(decompressed[7], hop_limit);
        }
    }

    // ===== Payload length reconstruction =====

    #[test]
    fn test_payload_length_reconstructed() {
        let payload = vec![0xBB; 256];
        let pkt = build_ipv6_packet(0, 0, 17, 64, sample_src(), sample_dst(), &payload);

        let compressed = compress_ipv6(&pkt).unwrap();
        let decompressed = decompress_ipv6(&compressed, sample_src(), sample_dst()).unwrap();

        let payload_len = u16::from_be_bytes([decompressed[4], decompressed[5]]);
        assert_eq!(payload_len, 256);
    }

    // ===== Compression size savings =====

    #[test]
    fn test_compression_saves_bytes() {
        let payload = vec![0; 100];
        let pkt = build_ipv6_packet(0, 0, 17, 64, sample_src(), sample_dst(), &payload);

        let compressed = compress_ipv6(&pkt).unwrap();

        // Original: 40 header + 100 payload = 140
        // Compressed: 1 format + 6 residual + 100 payload = 107
        // Savings: 33 bytes (version nibble kept in residual, so 34 - 1 = 33)
        assert_eq!(pkt.len(), 140);
        assert_eq!(compressed.len(), 107);
        assert_eq!(pkt.len() - compressed.len(), 33);
    }

    // ===== Error cases =====

    #[test]
    fn test_compress_rejects_non_ipv6() {
        let mut pkt = build_ipv6_packet(0, 0, 17, 64, sample_src(), sample_dst(), &[1]);
        pkt[0] = 0x40; // version 4 (IPv4)
        assert!(compress_ipv6(&pkt).is_none());
    }

    #[test]
    fn test_compress_rejects_short_packet() {
        assert!(compress_ipv6(&[0x60; 39]).is_none());
        assert!(compress_ipv6(&[]).is_none());
    }

    #[test]
    fn test_decompress_rejects_unknown_format() {
        let mut compressed = vec![0x01]; // format 0x01 = unknown
        compressed.extend_from_slice(&[0; IPV6_SHIM_RESIDUAL_SIZE]);
        assert!(decompress_ipv6(&compressed, sample_src(), sample_dst()).is_none());
    }

    #[test]
    fn test_decompress_rejects_short_payload() {
        // Needs at least 1 (format) + 6 (residual) = 7 bytes
        assert!(decompress_ipv6(&[0x00; 6], sample_src(), sample_dst()).is_none());
        assert!(decompress_ipv6(&[], sample_src(), sample_dst()).is_none());
    }

    // ===== Address reconstruction =====

    #[test]
    fn test_addresses_from_context() {
        let original_src = [
            0xfd, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA,
        ];
        let original_dst = [
            0xfd, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB,
        ];
        let pkt = build_ipv6_packet(0, 0, 17, 64, original_src, original_dst, &[1, 2]);

        let compressed = compress_ipv6(&pkt).unwrap();

        // Decompress with different addresses (simulating session context)
        let context_src = sample_src();
        let context_dst = sample_dst();
        let decompressed = decompress_ipv6(&compressed, context_src, context_dst).unwrap();

        // Addresses come from context, not original packet
        assert_eq!(&decompressed[8..24], &context_src);
        assert_eq!(&decompressed[24..40], &context_dst);

        // But TC, flow label, next header, hop limit, payload match original
        assert_eq!(&decompressed[0..4], &pkt[0..4]); // ver+TC+flow
        assert_eq!(decompressed[6], pkt[6]); // next_header
        assert_eq!(decompressed[7], pkt[7]); // hop_limit
        assert_eq!(&decompressed[40..], &pkt[40..]); // payload
    }
}
