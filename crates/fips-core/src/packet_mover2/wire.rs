#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WirePreflightError {
    TooShort,
    WrongVersion,
    WrongPhase,
    PlaintextFsp,
    BadFspCoords,
    CounterMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireBuildError {
    PayloadTooLarge,
    ProtocolMismatch,
    PlaintextFsp,
    BadFspCoords,
    MissingFspTimestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FmpWireHeader {
    header_bytes: [u8; FMP_ESTABLISHED_HEADER_SIZE],
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

        let mut header_bytes = [0u8; FMP_ESTABLISHED_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..FMP_ESTABLISHED_HEADER_SIZE]);

        Ok(Self { header_bytes })
    }

    pub(crate) fn receiver_idx(&self) -> u32 {
        let bytes = &self.header_bytes;
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    }

    pub(crate) fn counter(&self) -> u64 {
        let bytes = &self.header_bytes;
        u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    }

    pub(crate) fn flags(&self) -> u8 {
        self.header_bytes[1]
    }

    pub(crate) fn header_bytes(self) -> [u8; FMP_ESTABLISHED_HEADER_SIZE] {
        self.header_bytes
    }

    pub(crate) fn ciphertext_offset(self) -> usize {
        FMP_ESTABLISHED_HEADER_SIZE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FspWireHeader {
    header_bytes: [u8; FSP_HEADER_SIZE],
    ciphertext_offset: usize,
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

        let mut header_bytes = [0u8; FSP_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..FSP_HEADER_SIZE]);

        let mut ciphertext_offset = FSP_HEADER_SIZE;
        if flags & crate::node::session_wire::FSP_FLAG_CP != 0 {
            let (_source_coords, _dest_coords, coords_len) =
                crate::node::session_wire::parse_encrypted_coords(&data[FSP_HEADER_SIZE..])
                    .map_err(|_| WirePreflightError::BadFspCoords)?;
            ciphertext_offset = ciphertext_offset.saturating_add(coords_len);
        }

        Ok(Self {
            header_bytes,
            ciphertext_offset,
        })
    }

    pub(crate) fn counter(&self) -> u64 {
        let bytes = &self.header_bytes;
        u64::from_le_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ])
    }

    pub(crate) fn flags(&self) -> u8 {
        self.header_bytes[1]
    }

    pub(crate) fn header_bytes(self) -> [u8; FSP_HEADER_SIZE] {
        self.header_bytes
    }

    pub(crate) fn ciphertext_offset(self) -> usize {
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
