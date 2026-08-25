#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WirePreflightError {
    TooShort,
    WrongVersion,
    WrongPhase,
    PlaintextFsp,
    BadFspCoords,
    LengthMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireBuildError {
    PlaintextFsp,
    BadFspCoords,
    MissingFspTimestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FmpWireHeader {
    receiver_idx: u32,
    counter: u64,
    flags: u8,
}

impl FmpWireHeader {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, WirePreflightError> {
        if data.len() < FMP_ESTABLISHED_HEADER_SIZE {
            return Err(WirePreflightError::TooShort);
        }
        let version = data[0] >> 4;
        if version != FMP_VERSION {
            return Err(WirePreflightError::WrongVersion);
        }
        let phase = data[0] & 0x0f;
        if phase != FMP_PHASE_ESTABLISHED {
            return Err(WirePreflightError::WrongPhase);
        }

        Ok(Self {
            receiver_idx: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            counter: u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
            flags: data[1],
        })
    }

    /// Parse a complete encrypted wire frame and validate its declared
    /// plaintext length. The ordinary parser is also used after AEAD opening,
    /// when the tag has already been removed, so the full-frame check belongs
    /// specifically at raw ingress.
    pub(crate) fn parse_encrypted(data: &[u8]) -> Result<Self, WirePreflightError> {
        let header = Self::parse(data)?;
        let phase = data[0] & 0x0f;
        let declared = u16::from_le_bytes([data[2], data[3]]);
        if Some(declared) != crate::node::wire::expected_payload_len(phase, data.len()) {
            return Err(WirePreflightError::LengthMismatch);
        }
        Ok(header)
    }

    pub(crate) fn receiver_idx(&self) -> u32 {
        self.receiver_idx
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn flags(&self) -> u8 {
        self.flags
    }

    pub(crate) fn ciphertext_offset(self) -> u16 {
        FMP_ESTABLISHED_HEADER_SIZE as u16
    }
}

#[cfg(test)]
mod wire_length_tests {
    use super::*;

    #[test]
    fn fmp_established_header_rejects_declared_length_mismatch() {
        let header = build_fmp_established_header(7, 9, 0, 4);
        let mut frame = header.to_vec();
        frame.extend_from_slice(&[0; 4 + AEAD_TAG_SIZE]);
        assert!(FmpWireHeader::parse_encrypted(&frame).is_ok());

        frame[2..4].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            FmpWireHeader::parse_encrypted(&frame),
            Err(WirePreflightError::LengthMismatch)
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FspWireHeader {
    counter: u64,
    ciphertext_offset: u16,
    flags: u8,
}

impl FspWireHeader {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, WirePreflightError> {
        if data.len() < FSP_HEADER_SIZE {
            return Err(WirePreflightError::TooShort);
        }
        let version = data[0] >> 4;
        if version != FSP_VERSION {
            return Err(WirePreflightError::WrongVersion);
        }
        let phase = data[0] & 0x0f;
        if phase != FSP_PHASE_ESTABLISHED {
            return Err(WirePreflightError::WrongPhase);
        }
        let flags = data[1];
        if flags & FSP_FLAG_U != 0 {
            return Err(WirePreflightError::PlaintextFsp);
        }

        let mut ciphertext_offset = FSP_HEADER_SIZE;
        if flags & crate::node::session_wire::FSP_FLAG_CP != 0 {
            let (_source_coords, _dest_coords, coords_len) =
                crate::node::session_wire::parse_encrypted_coords(&data[FSP_HEADER_SIZE..])
                    .map_err(|_| WirePreflightError::BadFspCoords)?;
            ciphertext_offset = ciphertext_offset.saturating_add(coords_len);
        }
        let ciphertext_offset =
            u16::try_from(ciphertext_offset).map_err(|_| WirePreflightError::BadFspCoords)?;

        Ok(Self {
            counter: u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]),
            ciphertext_offset,
            flags,
        })
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn flags(&self) -> u8 {
        self.flags
    }

    pub(crate) fn ciphertext_offset(self) -> u16 {
        self.ciphertext_offset
    }
}

pub(crate) fn build_fmp_established_header(
    receiver_idx: u32,
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> [u8; FMP_ESTABLISHED_HEADER_SIZE] {
    let mut header = [0u8; FMP_ESTABLISHED_HEADER_SIZE];
    header[0] = (FMP_VERSION << 4) | FMP_PHASE_ESTABLISHED;
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
    header[8..16].copy_from_slice(&counter.to_le_bytes());
    header
}

fn build_fsp_established_header(
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> Result<[u8; FSP_HEADER_SIZE], WireBuildError> {
    if flags & FSP_FLAG_U != 0 {
        return Err(WireBuildError::PlaintextFsp);
    }

    let mut header = [0u8; FSP_HEADER_SIZE];
    header[0] = (FSP_VERSION << 4) | FSP_PHASE_ESTABLISHED;
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..12].copy_from_slice(&counter.to_le_bytes());
    Ok(header)
}
