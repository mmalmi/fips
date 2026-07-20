//! GATT bootstrap record for FIPS BLE v2.

use thiserror::Error;

pub const FIPS_BLE_V2_SERVICE_UUID: u128 = 0x9c90_b792_2cc5_42c0_9f87_c9cc_4064_8f4c;
pub const FIPS_BLE_V2_BOOTSTRAP_CHARACTERISTIC_UUID: u128 =
    0x9c90_b793_2cc5_42c0_9f87_c9cc_4064_8f4c;
pub const BOOTSTRAP_LEN: usize = 8;
const MAGIC: [u8; 2] = *b"FB";
const VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleBootstrap {
    pub capabilities: u8,
    pub psm: u16,
    pub max_packet: u16,
}

impl BleBootstrap {
    pub fn new(psm: u16, max_packet: u16) -> Result<Self, BleBootstrapError> {
        if psm == 0 {
            return Err(BleBootstrapError::InvalidPsm);
        }
        if max_packet == 0 {
            return Err(BleBootstrapError::InvalidMaxPacket);
        }
        Ok(Self {
            capabilities: 0,
            psm,
            max_packet,
        })
    }

    pub fn encode(self) -> [u8; BOOTSTRAP_LEN] {
        let psm = self.psm.to_be_bytes();
        let max_packet = self.max_packet.to_be_bytes();
        [
            MAGIC[0],
            MAGIC[1],
            VERSION,
            self.capabilities,
            psm[0],
            psm[1],
            max_packet[0],
            max_packet[1],
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BleBootstrapError> {
        if bytes.len() != BOOTSTRAP_LEN {
            return Err(BleBootstrapError::InvalidLength(bytes.len()));
        }
        if bytes[..2] != MAGIC {
            return Err(BleBootstrapError::InvalidMagic);
        }
        if bytes[2] != VERSION {
            return Err(BleBootstrapError::UnsupportedVersion(bytes[2]));
        }
        if bytes[3] != 0 {
            return Err(BleBootstrapError::UnsupportedCapabilities(bytes[3]));
        }
        let record = Self {
            capabilities: bytes[3],
            psm: u16::from_be_bytes([bytes[4], bytes[5]]),
            max_packet: u16::from_be_bytes([bytes[6], bytes[7]]),
        };
        Self::new(record.psm, record.max_packet)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BleBootstrapError {
    #[error("BLE bootstrap must contain exactly {BOOTSTRAP_LEN} bytes, got {0}")]
    InvalidLength(usize),
    #[error("invalid BLE bootstrap magic")]
    InvalidMagic,
    #[error("unsupported BLE bootstrap version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported BLE bootstrap capabilities 0x{0:02x}")]
    UnsupportedCapabilities(u8),
    #[error("BLE bootstrap PSM must not be zero")]
    InvalidPsm,
    #[error("BLE bootstrap maximum packet must not be zero")]
    InvalidMaxPacket,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_roundtrip() {
        let record = BleBootstrap::new(0x0085, 2048).unwrap();
        assert_eq!(BleBootstrap::decode(&record.encode()), Ok(record));
    }

    #[test]
    fn rejects_unknown_or_invalid_bootstrap_values() {
        let valid = BleBootstrap::new(0x0085, 2048).unwrap().encode();

        let mut wrong_version = valid;
        wrong_version[2] = 3;
        assert_eq!(
            BleBootstrap::decode(&wrong_version),
            Err(BleBootstrapError::UnsupportedVersion(3))
        );

        let mut unknown_capability = valid;
        unknown_capability[3] = 1;
        assert_eq!(
            BleBootstrap::decode(&unknown_capability),
            Err(BleBootstrapError::UnsupportedCapabilities(1))
        );

        assert_eq!(
            BleBootstrap::new(0, 2048),
            Err(BleBootstrapError::InvalidPsm)
        );
        assert_eq!(
            BleBootstrap::new(0x0085, 0),
            Err(BleBootstrapError::InvalidMaxPacket)
        );
    }
}
