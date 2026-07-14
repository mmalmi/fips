//! FIPS BLE v2 packet framing over byte-stream L2CAP channels.

use super::{addr::BleAddr, io::BleStream};
use crate::transport::TransportError;
use std::collections::VecDeque;
use thiserror::Error;
use tokio::sync::Mutex;

pub const BLE_V2_MAGIC: [u8; 2] = *b"FB";
pub const BLE_V2_VERSION: u8 = 2;
pub const BLE_V2_HEADER_LEN: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BleFrameError {
    #[error("BLE frame payload must not be empty")]
    EmptyPayload,
    #[error("BLE frame payload {payload_len} exceeds configured maximum {max_payload_len}")]
    Oversized {
        payload_len: usize,
        max_payload_len: usize,
    },
    #[error("invalid BLE frame magic")]
    InvalidMagic,
    #[error("unsupported BLE frame version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported BLE frame flags 0x{0:02x}")]
    UnsupportedFlags(u8),
}

pub fn encode_frame(payload: &[u8], max_payload_len: usize) -> Result<Vec<u8>, BleFrameError> {
    if payload.is_empty() {
        return Err(BleFrameError::EmptyPayload);
    }
    let effective_max = max_payload_len.min(u16::MAX as usize);
    if payload.len() > effective_max {
        return Err(BleFrameError::Oversized {
            payload_len: payload.len(),
            max_payload_len: effective_max,
        });
    }

    let payload_len = payload.len() as u16;
    let mut encoded = Vec::with_capacity(BLE_V2_HEADER_LEN + payload.len());
    encoded.extend_from_slice(&BLE_V2_MAGIC);
    encoded.push(BLE_V2_VERSION);
    encoded.push(0);
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

#[derive(Debug)]
pub struct BleFrameDecoder {
    max_payload_len: usize,
    buffered: Vec<u8>,
}

impl BleFrameDecoder {
    pub fn new(max_payload_len: usize) -> Self {
        Self {
            max_payload_len: max_payload_len.min(u16::MAX as usize),
            buffered: Vec::new(),
        }
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, BleFrameError> {
        let mut packets = Vec::new();
        while !bytes.is_empty() {
            if self.buffered.len() < BLE_V2_HEADER_LEN {
                let needed = BLE_V2_HEADER_LEN - self.buffered.len();
                let take = needed.min(bytes.len());
                self.buffered.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.buffered.len() < BLE_V2_HEADER_LEN {
                    break;
                }
            }

            let payload_len = match validate_header(&self.buffered, self.max_payload_len) {
                Ok(payload_len) => payload_len,
                Err(error) => {
                    self.buffered.clear();
                    return Err(error);
                }
            };
            let frame_len = BLE_V2_HEADER_LEN + payload_len;
            let needed = frame_len - self.buffered.len();
            let take = needed.min(bytes.len());
            self.buffered.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];

            if self.buffered.len() == frame_len {
                packets.push(self.buffered[BLE_V2_HEADER_LEN..].to_vec());
                self.buffered.clear();
            }
        }
        Ok(packets)
    }

    pub(crate) fn buffered_len(&self) -> usize {
        self.buffered.len()
    }
}

fn validate_header(header: &[u8], max_payload_len: usize) -> Result<usize, BleFrameError> {
    debug_assert!(header.len() >= BLE_V2_HEADER_LEN);
    if header[..2] != BLE_V2_MAGIC {
        return Err(BleFrameError::InvalidMagic);
    }
    if header[2] != BLE_V2_VERSION {
        return Err(BleFrameError::UnsupportedVersion(header[2]));
    }
    if header[3] != 0 {
        return Err(BleFrameError::UnsupportedFlags(header[3]));
    }
    let payload_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if payload_len == 0 {
        return Err(BleFrameError::EmptyPayload);
    }
    if payload_len > max_payload_len {
        return Err(BleFrameError::Oversized {
            payload_len,
            max_payload_len,
        });
    }
    Ok(payload_len)
}

/// Packet-preserving FIPS view over an ordered BLE byte stream.
///
/// Frames are segmented into raw writes no larger than the platform-reported
/// send MTU. The send mutex prevents concurrent FIPS packets from interleaving.
pub struct FramedBleStream<S> {
    raw: S,
    max_payload: u16,
    send_lock: Mutex<()>,
    receive: Mutex<ReceiveState>,
}

struct ReceiveState {
    decoder: BleFrameDecoder,
    pending: VecDeque<Vec<u8>>,
    raw_buffer: Vec<u8>,
}

impl<S: BleStream> FramedBleStream<S> {
    pub fn new(raw: S, max_payload: u16) -> Self {
        let raw_buffer_len = usize::from(raw.recv_mtu()).max(BLE_V2_HEADER_LEN);
        Self {
            raw,
            max_payload,
            send_lock: Mutex::new(()),
            receive: Mutex::new(ReceiveState {
                decoder: BleFrameDecoder::new(max_payload.into()),
                pending: VecDeque::new(),
                raw_buffer: vec![0; raw_buffer_len],
            }),
        }
    }

    fn copy_packet(packet: &[u8], output: &mut [u8]) -> Result<usize, TransportError> {
        if packet.len() > output.len() {
            return Err(TransportError::RecvFailed(format!(
                "BLE v2 frame {} exceeds receive buffer {}",
                packet.len(),
                output.len()
            )));
        }
        output[..packet.len()].copy_from_slice(packet);
        Ok(packet.len())
    }
}

impl<S: BleStream> BleStream for FramedBleStream<S> {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let encoded = encode_frame(data, self.max_payload.into())
            .map_err(|error| TransportError::SendFailed(error.to_string()))?;
        let raw_mtu = usize::from(self.raw.send_mtu()).max(1);
        let _guard = self.send_lock.lock().await;
        for chunk in encoded.chunks(raw_mtu) {
            self.raw.send(chunk).await?;
        }
        Ok(())
    }

    async fn recv(&self, output: &mut [u8]) -> Result<usize, TransportError> {
        let mut state = self.receive.lock().await;
        if let Some(packet) = state.pending.pop_front() {
            return Self::copy_packet(&packet, output);
        }

        loop {
            let mut raw_buffer = std::mem::take(&mut state.raw_buffer);
            let received = self.raw.recv(&mut raw_buffer).await?;
            if received == 0 {
                let had_partial_frame = state.decoder.buffered_len() != 0;
                state.raw_buffer = raw_buffer;
                return if had_partial_frame {
                    Err(TransportError::RecvFailed(
                        "BLE v2 stream closed in the middle of a frame".into(),
                    ))
                } else {
                    Ok(0)
                };
            }

            let decoded = state
                .decoder
                .push(&raw_buffer[..received])
                .map_err(|error| TransportError::RecvFailed(error.to_string()))?;
            state.raw_buffer = raw_buffer;
            state.pending.extend(decoded);
            if let Some(packet) = state.pending.pop_front() {
                return Self::copy_packet(&packet, output);
            }
        }
    }

    fn send_mtu(&self) -> u16 {
        self.max_payload
    }

    fn recv_mtu(&self) -> u16 {
        self.max_payload
    }

    fn remote_addr(&self) -> &BleAddr {
        self.raw.remote_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ble::{addr::BleAddr, io::MockBleStream};

    const MAX_PAYLOAD: usize = 2048;

    #[test]
    fn encodes_v2_header_and_payload() {
        let encoded = encode_frame(&[1, 2, 3], MAX_PAYLOAD).unwrap();
        assert_eq!(
            encoded,
            [
                BLE_V2_MAGIC.as_slice(),
                &[BLE_V2_VERSION, 0, 0, 3],
                &[1, 2, 3]
            ]
            .concat()
        );
    }

    #[test]
    fn decodes_a_frame_delivered_one_byte_at_a_time() {
        let encoded = encode_frame(b"fragmented", MAX_PAYLOAD).unwrap();
        let mut decoder = BleFrameDecoder::new(MAX_PAYLOAD);
        let mut packets = Vec::new();
        for byte in encoded {
            packets.extend(decoder.push(&[byte]).unwrap());
        }
        assert_eq!(packets, vec![b"fragmented".to_vec()]);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn decodes_multiple_coalesced_frames() {
        let bytes = [
            encode_frame(b"one", MAX_PAYLOAD).unwrap(),
            encode_frame(b"two", MAX_PAYLOAD).unwrap(),
        ]
        .concat();
        let mut decoder = BleFrameDecoder::new(MAX_PAYLOAD);
        assert_eq!(
            decoder.push(&bytes).unwrap(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn rejects_oversized_length_before_payload_arrives() {
        let mut decoder = BleFrameDecoder::new(32);
        let header = [BLE_V2_MAGIC[0], BLE_V2_MAGIC[1], BLE_V2_VERSION, 0, 0, 33];
        assert_eq!(
            decoder.push(&header),
            Err(BleFrameError::Oversized {
                payload_len: 33,
                max_payload_len: 32,
            })
        );
        assert!(decoder.buffered_len() <= BLE_V2_HEADER_LEN);
    }

    #[test]
    fn rejects_empty_payloads() {
        assert_eq!(
            encode_frame(&[], MAX_PAYLOAD),
            Err(BleFrameError::EmptyPayload)
        );
    }

    #[test]
    fn rejects_wrong_magic_version_and_flags() {
        let mut decoder = BleFrameDecoder::new(MAX_PAYLOAD);
        assert_eq!(
            decoder.push(&[b'X', b'B', BLE_V2_VERSION, 0, 0, 1]),
            Err(BleFrameError::InvalidMagic)
        );

        let mut decoder = BleFrameDecoder::new(MAX_PAYLOAD);
        assert_eq!(
            decoder.push(&[b'F', b'B', 3, 0, 0, 1]),
            Err(BleFrameError::UnsupportedVersion(3))
        );

        let mut decoder = BleFrameDecoder::new(MAX_PAYLOAD);
        assert_eq!(
            decoder.push(&[b'F', b'B', BLE_V2_VERSION, 1, 0, 1]),
            Err(BleFrameError::UnsupportedFlags(1))
        );
    }

    #[tokio::test]
    async fn framed_stream_segments_and_reassembles_packets() {
        let left = BleAddr::from_mac("hci0", [0, 0, 0, 0, 0, 1]);
        let right = BleAddr::from_mac("hci0", [0, 0, 0, 0, 0, 2]);
        let (a, b) = MockBleStream::pair(left, right, 4);
        let a = FramedBleStream::new(a, 128);
        let b = FramedBleStream::new(b, 128);

        a.send(b"one packet split across raw writes").await.unwrap();
        let mut output = [0u8; 128];
        let received = b.recv(&mut output).await.unwrap();
        assert_eq!(&output[..received], b"one packet split across raw writes");
    }

    #[tokio::test]
    async fn framed_stream_preserves_consecutive_packet_boundaries() {
        let left = BleAddr::from_mac("hci0", [0, 0, 0, 0, 0, 1]);
        let right = BleAddr::from_mac("hci0", [0, 0, 0, 0, 0, 2]);
        let (a, b) = MockBleStream::pair(left, right, 64);
        let a = FramedBleStream::new(a, 128);
        let b = FramedBleStream::new(b, 128);

        a.send(b"one").await.unwrap();
        a.send(b"two").await.unwrap();

        let mut output = [0u8; 128];
        let first = b.recv(&mut output).await.unwrap();
        assert_eq!(&output[..first], b"one");
        let second = b.recv(&mut output).await.unwrap();
        assert_eq!(&output[..second], b"two");
    }
}
