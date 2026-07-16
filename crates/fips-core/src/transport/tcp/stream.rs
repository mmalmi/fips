//! FIPS Stream Reader
//!
//! Recovers FIPS packet boundaries from a TCP byte stream using the
//! shared 4-byte FMP/FSP prefix `[ver+phase:1][flags:1][payload_len:2 LE]`.
//!
//! This module is deliberately separate from the TCP transport so it can
//! be reused by the future Tor transport.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::proto::fsp_wire::{FSP_FLAG_CP, FSP_FLAG_DIRECT_TRANSPORT, FSP_FLAG_U, FSP_HEADER_SIZE};

/// FMP phase values (low nibble of byte 0).
const PHASE_ESTABLISHED: u8 = 0x0;
const PHASE_MSG1: u8 = 0x1;
const PHASE_MSG2: u8 = 0x2;

/// Size of the FMP common prefix.
const PREFIX_SIZE: usize = 4;

/// Overhead for established frames: 12 bytes remaining header + 16 bytes AEAD tag.
/// The full established header is 16 bytes (PREFIX_SIZE + 12), so after reading
/// the 4-byte prefix, 12 more header bytes remain. Then payload_len bytes of
/// ciphertext, then 16 bytes of AEAD tag.
const FMP_ESTABLISHED_REMAINING_HEADER: usize = 12;
const DIRECT_FSP_REMAINING_HEADER: usize = FSP_HEADER_SIZE - PREFIX_SIZE;
const AEAD_TAG_SIZE: usize = 16;

/// Maximum time allowed to finish a byte-stream record after its first byte.
/// Waiting for that first byte remains unbounded on established idle links.
pub(crate) const DEFAULT_FRAME_COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors from the FMP stream reader.
#[derive(Debug)]
pub enum StreamError {
    /// Unknown FMP version — not a FIPS connection (e.g., TLS ClientHello).
    UnknownVersion(u8),
    /// Unknown FMP phase byte — protocol error, close connection.
    UnknownPhase(u8),
    /// Payload length exceeds the connection's MTU — corrupted or malicious.
    PayloadTooLarge {
        payload_len: u16,
        max_payload_len: u16,
    },
    /// Handshake packet has unexpected payload_len for its phase.
    HandshakeSizeMismatch { phase: u8, expected: u16, got: u16 },
    /// I/O error (including EOF).
    Io(std::io::Error),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::UnknownVersion(v) => write!(f, "unknown FMP version: {}", v),
            StreamError::UnknownPhase(p) => write!(f, "unknown FMP phase: 0x{:02x}", p),
            StreamError::PayloadTooLarge {
                payload_len,
                max_payload_len,
            } => {
                write!(
                    f,
                    "payload_len {} exceeds max {}",
                    payload_len, max_payload_len
                )
            }
            StreamError::HandshakeSizeMismatch {
                phase,
                expected,
                got,
            } => {
                write!(
                    f,
                    "handshake phase 0x{:x}: expected payload_len {}, got {}",
                    phase, expected, got
                )
            }
            StreamError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        StreamError::Io(e)
    }
}

/// Known wire sizes for handshake messages.
/// msg1: 4 (prefix) + 4 (sender_idx) + 106 (noise_msg1) = 114 bytes
/// msg2: 4 (prefix) + 4 (sender_idx) + 4 (receiver_idx) + 57 (noise_msg2) = 69 bytes
const MSG1_WIRE_SIZE: usize = 114;
const MSG2_WIRE_SIZE: usize = 69;

/// Expected payload_len for msg1: sender_idx(4) + noise_msg1(106) = 110.
const MSG1_PAYLOAD_LEN: u16 = (MSG1_WIRE_SIZE - PREFIX_SIZE) as u16;

/// Expected payload_len for msg2: sender_idx(4) + receiver_idx(4) + noise_msg2(57) = 65.
const MSG2_PAYLOAD_LEN: u16 = (MSG2_WIRE_SIZE - PREFIX_SIZE) as u16;

fn invalid_data(message: impl Into<String>) -> StreamError {
    StreamError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn completion_timed_out() -> StreamError {
    StreamError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "stream frame completion timed out",
    ))
}

fn stream_record_len(prefix: &[u8; PREFIX_SIZE]) -> Result<usize, StreamError> {
    let version = prefix[0] >> 4;
    let phase = prefix[0] & 0x0F;

    if version != 0 {
        return Err(StreamError::UnknownVersion(version));
    }

    let payload_len = u16::from_le_bytes([prefix[2], prefix[3]]);

    let remaining = match phase {
        PHASE_ESTABLISHED => {
            let is_direct_fsp = prefix[1] & FSP_FLAG_DIRECT_TRANSPORT != 0;
            if is_direct_fsp && prefix[1] & (FSP_FLAG_CP | FSP_FLAG_U) != 0 {
                return Err(invalid_data(format!(
                    "invalid direct FSP flags: 0x{:02x}",
                    prefix[1]
                )));
            }
            let remaining_header = if is_direct_fsp {
                DIRECT_FSP_REMAINING_HEADER
            } else {
                FMP_ESTABLISHED_REMAINING_HEADER
            };
            remaining_header + payload_len as usize + AEAD_TAG_SIZE
        }
        PHASE_MSG1 => {
            if payload_len != MSG1_PAYLOAD_LEN {
                return Err(StreamError::HandshakeSizeMismatch {
                    phase,
                    expected: MSG1_PAYLOAD_LEN,
                    got: payload_len,
                });
            }
            payload_len as usize
        }
        PHASE_MSG2 => {
            if payload_len != MSG2_PAYLOAD_LEN {
                return Err(StreamError::HandshakeSizeMismatch {
                    phase,
                    expected: MSG2_PAYLOAD_LEN,
                    got: payload_len,
                });
            }
            payload_len as usize
        }
        _ => {
            return Err(StreamError::UnknownPhase(phase));
        }
    };

    Ok(PREFIX_SIZE + remaining)
}

/// Validate that one byte slice is exactly one FIPS byte-stream record.
pub(crate) fn validate_stream_record(data: &[u8]) -> Result<(), StreamError> {
    let prefix: [u8; PREFIX_SIZE] = data
        .get(..PREFIX_SIZE)
        .ok_or_else(|| {
            invalid_data(format!(
                "record size mismatch: expected at least {PREFIX_SIZE}, got {}",
                data.len()
            ))
        })?
        .try_into()
        .expect("four-byte prefix slice");
    let expected = stream_record_len(&prefix)?;
    if data.len() != expected {
        return Err(invalid_data(format!(
            "record size mismatch: expected {expected}, got {}",
            data.len()
        )));
    }
    Ok(())
}

/// Read one complete FIPS packet from an async reader.
///
/// This preserves the public v0.4.4 API and its MTU validation semantics for
/// external callers. Transport runtimes use the private timed reader below;
/// their byte-stream record limit is the protocol's u16 payload field rather
/// than the advertised path MTU.
pub async fn read_fmp_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    mtu: u16,
) -> Result<Vec<u8>, StreamError> {
    let mut prefix = [0u8; PREFIX_SIZE];
    reader.read_exact(&mut prefix).await?;
    let total = stream_record_len(&prefix)?;

    if prefix[0] & 0x0f == PHASE_ESTABLISHED {
        let payload_len = u16::from_le_bytes([prefix[2], prefix[3]]);
        let remaining_header = if prefix[1] & FSP_FLAG_DIRECT_TRANSPORT != 0 {
            DIRECT_FSP_REMAINING_HEADER
        } else {
            FMP_ESTABLISHED_REMAINING_HEADER
        };
        let max_payload_len =
            mtu.saturating_sub((PREFIX_SIZE + remaining_header + AEAD_TAG_SIZE) as u16);
        if payload_len > max_payload_len {
            return Err(StreamError::PayloadTooLarge {
                payload_len,
                max_payload_len,
            });
        }
    }

    let mut packet = vec![0u8; total];
    packet[..PREFIX_SIZE].copy_from_slice(&prefix);
    reader.read_exact(&mut packet[PREFIX_SIZE..]).await?;
    Ok(packet)
}

/// Read one complete FIPS packet for a transport byte stream.
///
/// An established idle link may wait indefinitely for the first record byte.
/// Once any byte arrives, the rest of the prefix and body share one absolute
/// completion deadline, preventing partial-prefix and partial-body stalls.
pub(crate) async fn read_fmp_packet_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    completion_timeout: Duration,
) -> Result<Vec<u8>, StreamError> {
    let mut prefix = [0u8; PREFIX_SIZE];
    reader.read_exact(&mut prefix[..1]).await?;

    timeout(completion_timeout, async {
        reader.read_exact(&mut prefix[1..]).await?;
        let total = stream_record_len(&prefix)?;
        let mut packet = vec![0u8; total];
        packet[..PREFIX_SIZE].copy_from_slice(&prefix);
        reader.read_exact(&mut packet[PREFIX_SIZE..]).await?;
        Ok::<_, StreamError>(packet)
    })
    .await
    .map_err(|_| completion_timed_out())?
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const READ_TIMEOUT: Duration = Duration::from_secs(1);

    async fn read_fmp_packet<R: AsyncRead + Unpin>(
        reader: &mut R,
        completion_timeout: Duration,
    ) -> Result<Vec<u8>, StreamError> {
        read_fmp_packet_with_timeout(reader, completion_timeout).await
    }

    /// Build a minimal established frame with the given payload_len.
    /// Layout: [ver+phase:1][flags:1][payload_len:2 LE][12 bytes header][payload_len bytes][16 bytes tag]
    fn build_established_frame(payload_len: u16) -> Vec<u8> {
        let total =
            PREFIX_SIZE + FMP_ESTABLISHED_REMAINING_HEADER + payload_len as usize + AEAD_TAG_SIZE;
        let mut frame = vec![0u8; total];
        frame[0] = 0x00; // ver=0, phase=0 (established)
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
        // Fill remaining with pattern for verification
        for (i, byte) in frame[PREFIX_SIZE..total].iter_mut().enumerate() {
            *byte = ((PREFIX_SIZE + i) & 0xFF) as u8;
        }
        frame
    }

    /// Build an established direct-FSP frame. Its full cleartext header is
    /// four bytes shorter than an established FMP frame.
    fn build_direct_fsp_frame(payload_len: u16) -> Vec<u8> {
        let remaining_header = crate::proto::fsp_wire::FSP_HEADER_SIZE - PREFIX_SIZE;
        let total = PREFIX_SIZE + remaining_header + payload_len as usize + AEAD_TAG_SIZE;
        let mut frame = vec![0u8; total];
        frame[0] = 0x00;
        frame[1] = crate::proto::fsp_wire::FSP_FLAG_DIRECT_TRANSPORT;
        frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
        for (i, byte) in frame[PREFIX_SIZE..total].iter_mut().enumerate() {
            *byte = (0x80 | ((PREFIX_SIZE + i) & 0x7F)) as u8;
        }
        frame
    }

    /// Build a msg1 frame (114 bytes total).
    fn build_msg1_frame() -> Vec<u8> {
        let mut frame = vec![0xAA; MSG1_WIRE_SIZE];
        frame[0] = 0x01; // ver=0, phase=1
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&MSG1_PAYLOAD_LEN.to_le_bytes());
        frame
    }

    /// Build a msg2 frame (69 bytes total).
    fn build_msg2_frame() -> Vec<u8> {
        let mut frame = vec![0xBB; MSG2_WIRE_SIZE];
        frame[0] = 0x02; // ver=0, phase=2
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&MSG2_PAYLOAD_LEN.to_le_bytes());
        frame
    }

    #[tokio::test]
    async fn test_read_established_frame() {
        let payload_len = 64u16;
        let frame = build_established_frame(payload_len);
        let expected = frame.clone();

        let mut cursor = Cursor::new(frame);
        let packet = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(packet, expected);
    }

    #[tokio::test]
    async fn test_read_msg1_frame() {
        let frame = build_msg1_frame();
        let expected = frame.clone();

        let mut cursor = Cursor::new(frame);
        let packet = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(packet.len(), MSG1_WIRE_SIZE);
        assert_eq!(packet, expected);
    }

    #[tokio::test]
    async fn test_read_msg2_frame() {
        let frame = build_msg2_frame();
        let expected = frame.clone();

        let mut cursor = Cursor::new(frame);
        let packet = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(packet.len(), MSG2_WIRE_SIZE);
        assert_eq!(packet, expected);
    }

    #[tokio::test]
    async fn test_read_multiple_packets() {
        let mut data = Vec::new();
        let msg1 = build_msg1_frame();
        let est = build_established_frame(32);
        let msg2 = build_msg2_frame();
        data.extend_from_slice(&msg1);
        data.extend_from_slice(&est);
        data.extend_from_slice(&msg2);

        let mut cursor = Cursor::new(data);
        let p1 = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(p1.len(), MSG1_WIRE_SIZE);

        let p2 = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(p2, est);

        let p3 = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(p3.len(), MSG2_WIRE_SIZE);
    }

    #[tokio::test]
    async fn direct_fsp_and_fmp_frames_keep_exact_stream_boundaries() {
        let direct_fsp = build_direct_fsp_frame(23);
        let fmp = build_established_frame(31);
        let mut data = direct_fsp.clone();
        data.extend_from_slice(&fmp);

        let mut cursor = Cursor::new(data);
        assert_eq!(
            read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap(),
            direct_fsp
        );
        assert_eq!(
            read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap(),
            fmp
        );
    }

    #[tokio::test]
    async fn direct_fsp_accepts_full_wire_range_and_rejects_bad_shape_or_flags() {
        let max_payload = build_direct_fsp_frame(u16::MAX);
        assert_eq!(
            read_fmp_packet(&mut Cursor::new(max_payload.clone()), READ_TIMEOUT)
                .await
                .unwrap(),
            max_payload
        );

        let mut truncated = build_direct_fsp_frame(23);
        truncated.pop();
        assert!(matches!(
            read_fmp_packet(&mut Cursor::new(truncated), READ_TIMEOUT).await,
            Err(StreamError::Io(_))
        ));

        let mut extra_byte = build_direct_fsp_frame(23);
        extra_byte.push(0);
        assert!(matches!(
            validate_stream_record(&extra_byte),
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData
        ));

        let mut invalid_flags = build_direct_fsp_frame(23);
        invalid_flags[1] |= crate::proto::fsp_wire::FSP_FLAG_U;
        assert!(matches!(
            read_fmp_packet(&mut Cursor::new(invalid_flags), READ_TIMEOUT).await,
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData
        ));

        let mut invalid_flags = build_direct_fsp_frame(23);
        invalid_flags[1] |= crate::proto::fsp_wire::FSP_FLAG_CP;
        assert!(matches!(
            read_fmp_packet(&mut Cursor::new(invalid_flags), READ_TIMEOUT).await,
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData
        ));

        let mut rekey_epoch = build_direct_fsp_frame(23);
        rekey_epoch[1] |= crate::proto::fsp_wire::FSP_FLAG_K;
        assert_eq!(
            read_fmp_packet(&mut Cursor::new(rekey_epoch.clone()), READ_TIMEOUT)
                .await
                .unwrap(),
            rekey_epoch,
            "DIRECT and the encrypted epoch K bit are compatible"
        );
    }

    #[tokio::test]
    async fn test_unknown_version_error() {
        // TLS ClientHello starts with 0x16 (record type "Handshake"),
        // which parses as FMP version=1, phase=6.
        let mut frame = vec![0u8; 100];
        frame[0] = 0x16;
        let mut cursor = Cursor::new(frame);
        let err = read_fmp_packet(&mut cursor, READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::UnknownVersion(1)));
    }

    #[tokio::test]
    async fn test_unknown_phase_error() {
        let mut frame = vec![0u8; 100];
        frame[0] = 0x05; // unknown phase
        frame[2..4].copy_from_slice(&10u16.to_le_bytes());

        let mut cursor = Cursor::new(frame);
        let err = read_fmp_packet(&mut cursor, READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::UnknownPhase(0x5)));
    }

    #[tokio::test]
    async fn test_handshake_size_mismatch_msg1() {
        let mut frame = vec![0u8; 200];
        frame[0] = 0x01; // msg1
        // Wrong payload_len (should be 110)
        frame[2..4].copy_from_slice(&50u16.to_le_bytes());

        let mut cursor = Cursor::new(frame);
        let err = read_fmp_packet(&mut cursor, READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StreamError::HandshakeSizeMismatch { phase: 0x1, .. }
        ));
    }

    #[tokio::test]
    async fn test_handshake_size_mismatch_msg2() {
        let mut frame = vec![0u8; 200];
        frame[0] = 0x02; // msg2
        // Wrong payload_len (should be 65)
        frame[2..4].copy_from_slice(&50u16.to_le_bytes());

        let mut cursor = Cursor::new(frame);
        let err = read_fmp_packet(&mut cursor, READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StreamError::HandshakeSizeMismatch { phase: 0x2, .. }
        ));
    }

    #[tokio::test]
    async fn test_eof_on_prefix() {
        // Only 2 bytes available (need 4 for prefix)
        let data = vec![0u8; 2];
        let mut cursor = Cursor::new(data);
        let err = read_fmp_packet(&mut cursor, READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::Io(_)));
    }

    #[tokio::test]
    async fn test_eof_on_body() {
        // Valid msg1 prefix but truncated body
        let mut data = vec![0u8; 10]; // need 114 total
        data[0] = 0x01; // msg1
        data[2..4].copy_from_slice(&MSG1_PAYLOAD_LEN.to_le_bytes());

        let mut cursor = Cursor::new(data);
        let err = read_fmp_packet(&mut cursor, READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::Io(_)));
    }

    #[tokio::test]
    async fn test_zero_payload_established() {
        // payload_len = 0 is valid (header-only encrypted frame with tag)
        let frame = build_established_frame(0);
        let expected_len = PREFIX_SIZE + FMP_ESTABLISHED_REMAINING_HEADER + AEAD_TAG_SIZE;
        assert_eq!(frame.len(), expected_len);

        let mut cursor = Cursor::new(frame.clone());
        let packet = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(packet.len(), expected_len);
        assert_eq!(packet, frame);
    }

    #[tokio::test]
    async fn test_max_fmp_payload_uses_the_full_wire_length() {
        let frame = build_established_frame(u16::MAX);

        let mut cursor = Cursor::new(frame.clone());
        let packet = read_fmp_packet(&mut cursor, READ_TIMEOUT).await.unwrap();
        assert_eq!(packet, frame);
        validate_stream_record(&frame).unwrap();
    }

    #[tokio::test]
    async fn public_reader_keeps_the_released_mtu_api_and_error_variant() {
        let frame = build_established_frame(64);
        assert_eq!(
            super::read_fmp_packet(&mut Cursor::new(frame.clone()), 1400)
                .await
                .unwrap(),
            frame
        );

        let over_budget = build_established_frame(1369);
        assert!(matches!(
            super::read_fmp_packet(&mut Cursor::new(over_budget), 1400).await,
            Err(StreamError::PayloadTooLarge {
                payload_len: 1369,
                max_payload_len: 1368,
            })
        ));
    }

    #[tokio::test]
    async fn idle_wait_is_unbounded_but_partial_prefix_and_body_are_bounded() {
        let completion = Duration::from_millis(30);

        let (mut writer, mut reader) = tokio::io::duplex(256);
        let idle_read = tokio::spawn(async move { read_fmp_packet(&mut reader, completion).await });
        tokio::time::sleep(completion + Duration::from_millis(10)).await;
        let frame = build_direct_fsp_frame(7);
        tokio::io::AsyncWriteExt::write_all(&mut writer, &frame)
            .await
            .unwrap();
        assert_eq!(idle_read.await.unwrap().unwrap(), frame);

        let (mut writer, mut reader) = tokio::io::duplex(256);
        tokio::io::AsyncWriteExt::write_all(&mut writer, &[0x00])
            .await
            .unwrap();
        assert!(matches!(
            read_fmp_packet(&mut reader, completion).await,
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut
        ));

        let (mut writer, mut reader) = tokio::io::duplex(256);
        tokio::io::AsyncWriteExt::write_all(&mut writer, &[0x00, 0x00, 0x04, 0x00, 0xAA])
            .await
            .unwrap();
        assert!(matches!(
            read_fmp_packet(&mut reader, completion).await,
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut
        ));
    }
}
