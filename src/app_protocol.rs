//! Application protocol frames carried inside FSP data packets.

use thiserror::Error;

const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 14;
const KIND_OPEN: u8 = 1;
const KIND_DATA: u8 = 2;
const KIND_CLOSE: u8 = 3;

/// Maximum protocol name length accepted by the embedded endpoint.
pub(crate) const MAX_APP_PROTOCOL_NAME_LEN: usize = 512;

/// Maximum application frame payload length accepted by the embedded endpoint.
pub(crate) const MAX_APP_PROTOCOL_PAYLOAD_LEN: usize = 60 * 1024;

/// A logical application protocol frame multiplexed over an FSP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppProtocolFrame {
    Open { session_id: u64, protocol: Vec<u8> },
    Data { session_id: u64, payload: Vec<u8> },
    Close { session_id: u64 },
}

/// Errors returned when decoding application protocol frames.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum AppProtocolFrameError {
    #[error("app protocol frame is too short")]
    TooShort,

    #[error("unsupported app protocol frame version: {0}")]
    UnsupportedVersion(u8),

    #[error("unknown app protocol frame kind: {0}")]
    UnknownKind(u8),

    #[error("app protocol frame length mismatch")]
    LengthMismatch,

    #[error("application protocol is empty")]
    EmptyProtocol,

    #[error("application protocol name is too long")]
    ProtocolTooLong,

    #[error("application protocol payload is too long")]
    PayloadTooLong,

    #[error("close frame must not carry a payload")]
    CloseWithPayload,
}

impl AppProtocolFrame {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let (kind, session_id, payload): (u8, u64, &[u8]) = match self {
            Self::Open {
                session_id,
                protocol,
            } => (KIND_OPEN, *session_id, protocol),
            Self::Data {
                session_id,
                payload,
            } => (KIND_DATA, *session_id, payload),
            Self::Close { session_id } => (KIND_CLOSE, *session_id, &[]),
        };

        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        out.push(FRAME_VERSION);
        out.push(kind);
        out.extend_from_slice(&session_id.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Self, AppProtocolFrameError> {
        if data.len() < FRAME_HEADER_LEN {
            return Err(AppProtocolFrameError::TooShort);
        }
        let version = data[0];
        if version != FRAME_VERSION {
            return Err(AppProtocolFrameError::UnsupportedVersion(version));
        }

        let kind = data[1];
        let session_id = u64::from_le_bytes(
            data[2..10]
                .try_into()
                .expect("slice length checked by frame header length"),
        );
        let payload_len = u32::from_le_bytes(
            data[10..14]
                .try_into()
                .expect("slice length checked by frame header length"),
        ) as usize;
        if data.len() != FRAME_HEADER_LEN + payload_len {
            return Err(AppProtocolFrameError::LengthMismatch);
        }

        let payload = &data[FRAME_HEADER_LEN..];
        match kind {
            KIND_OPEN => {
                if payload.is_empty() {
                    return Err(AppProtocolFrameError::EmptyProtocol);
                }
                if payload.len() > MAX_APP_PROTOCOL_NAME_LEN {
                    return Err(AppProtocolFrameError::ProtocolTooLong);
                }
                Ok(Self::Open {
                    session_id,
                    protocol: payload.to_vec(),
                })
            }
            KIND_DATA => {
                if payload.len() > MAX_APP_PROTOCOL_PAYLOAD_LEN {
                    return Err(AppProtocolFrameError::PayloadTooLong);
                }
                Ok(Self::Data {
                    session_id,
                    payload: payload.to_vec(),
                })
            }
            KIND_CLOSE => {
                if !payload.is_empty() {
                    return Err(AppProtocolFrameError::CloseWithPayload);
                }
                Ok(Self::Close { session_id })
            }
            _ => Err(AppProtocolFrameError::UnknownKind(kind)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_protocol_frame_roundtrips_open() {
        let frame = AppProtocolFrame::Open {
            session_id: 7,
            protocol: b"nostr-vpn/ip/1".to_vec(),
        };

        assert_eq!(AppProtocolFrame::decode(&frame.encode()), Ok(frame));
    }

    #[test]
    fn app_protocol_frame_roundtrips_data() {
        let frame = AppProtocolFrame::Data {
            session_id: 9,
            payload: b"hello".to_vec(),
        };

        assert_eq!(AppProtocolFrame::decode(&frame.encode()), Ok(frame));
    }

    #[test]
    fn app_protocol_frame_rejects_malformed_length() {
        let mut encoded = AppProtocolFrame::Data {
            session_id: 9,
            payload: b"hello".to_vec(),
        }
        .encode();
        encoded.pop();

        assert_eq!(
            AppProtocolFrame::decode(&encoded),
            Err(AppProtocolFrameError::LengthMismatch)
        );
    }
}
