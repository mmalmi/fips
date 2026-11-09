//! Optional extensions carried inside authenticated standard FSP DataPackets.
//!
//! Service port 257 also carries the JSON link-negotiation envelope. The fixed
//! binary magic keeps these messages disjoint. Upstream peers can ignore this
//! unbound service without encountering nonstandard handshake fields.

pub(crate) const SESSION_CAPABILITY_PORT: u16 = 257;
const MAGIC: &[u8; 8] = b"FIPS-EXT";
const VERSION: u8 = 1;
pub(crate) const DIRECT_FSP: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionCapabilities {
    pub(crate) request: bool,
    pub(crate) bits: u16,
}

impl SessionCapabilities {
    pub(crate) fn local(request: bool) -> Self {
        Self {
            request,
            bits: DIRECT_FSP,
        }
    }

    pub(crate) fn encode(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = VERSION;
        bytes[9] = if self.request { 1 } else { 2 };
        bytes[10..].copy_from_slice(&self.bits.to_le_bytes());
        bytes
    }

    pub(crate) fn has_magic(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 12 || !Self::has_magic(bytes) || bytes[8] != VERSION {
            return None;
        }
        let request = match bytes[9] {
            1 => true,
            2 => false,
            _ => return None,
        };
        Some(Self {
            request,
            // Unknown bits do not enable any local feature.
            bits: u16::from_le_bytes([bytes[10], bytes[11]]) & DIRECT_FSP,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_capability_bytes_and_unknown_bits() {
        assert_eq!(
            SessionCapabilities::local(true).encode(),
            *b"FIPS-EXT\x01\x01\x01\x00"
        );
        assert_eq!(
            SessionCapabilities::local(false).encode(),
            *b"FIPS-EXT\x01\x02\x01\x00"
        );
        let mut bytes = SessionCapabilities::local(true).encode();
        bytes[11] = 0x80;
        assert_eq!(
            SessionCapabilities::decode(&bytes),
            Some(SessionCapabilities::local(true))
        );
        bytes[10] = 0;
        assert_eq!(SessionCapabilities::decode(&bytes).unwrap().bits, 0);
    }

    #[test]
    fn malformed_or_unrelated_envelopes_cannot_negotiate() {
        let valid = SessionCapabilities::local(true).encode();
        for len in 0..valid.len() {
            assert!(SessionCapabilities::decode(&valid[..len]).is_none());
        }
        let mut longer = valid.to_vec();
        longer.push(0);
        assert!(SessionCapabilities::decode(&longer).is_none());
        for (offset, value) in [(0, b'X'), (8, 2), (9, 0), (9, 3)] {
            let mut bytes = valid;
            bytes[offset] = value;
            assert!(SessionCapabilities::decode(&bytes).is_none());
        }
        assert!(!SessionCapabilities::has_magic(br#"{"version":1}"#));
    }
}
