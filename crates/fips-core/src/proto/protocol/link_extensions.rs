//! Fork-only link features in an authenticated, versioned namespace.
//! Upstream peers ignore outer type 0xe0. The old 0x52–0x54 assignments now
//! belong to upstream multipath and may only be used after legacy detection.

pub(crate) const LINK_EXTENSION_CLIENT_SUPPORT: u16 = 0x0002;
const MAGIC: &[u8; 8] = b"FIPS-EXT";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkExtension<'a> {
    ClientSupport { response: bool, capabilities: u16 },
    ClientOnly(u64),
    LocalUdpListeners(&'a [u8]),
}

impl<'a> LinkExtension<'a> {
    /// Decode the body after the outer link message type.
    pub(crate) fn decode(body: &'a [u8]) -> Option<Self> {
        if body.get(..8)? != MAGIC || *body.get(8)? != VERSION {
            return None;
        }
        let payload = body.get(10..)?;
        match body[9] {
            kind @ (1 | 2) => Some(Self::ClientSupport {
                response: kind == 2,
                capabilities: u16::from_le_bytes(payload.try_into().ok()?),
            }),
            3 => Some(Self::ClientOnly(u64::from_le_bytes(payload.try_into().ok()?))),
            4 => Some(Self::LocalUdpListeners(payload)),
            _ => None,
        }
    }

    /// Encode a whole link message, including its outer type.
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut message = Vec::with_capacity(19);
        message.push(super::LinkMessageType::Extension.to_byte());
        message.extend_from_slice(MAGIC);
        message.push(VERSION);
        match self {
            Self::ClientSupport { response, capabilities } => {
                message.push(if response { 2 } else { 1 });
                message.extend_from_slice(&capabilities.to_le_bytes());
            }
            Self::ClientOnly(sequence) => {
                message.push(3);
                message.extend_from_slice(&sequence.to_le_bytes());
            }
            Self::LocalUdpListeners(payload) => {
                message.push(4);
                message.extend_from_slice(payload);
            }
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_extension_golden_capability_and_strict_header() {
        let message = LinkExtension::ClientSupport {
            response: false,
            capabilities: LINK_EXTENSION_CLIENT_SUPPORT,
        }.encode();
        assert_eq!(message, b"\xe0FIPS-EXT\x01\x01\x02\x00");
        assert!(matches!(LinkExtension::decode(&message[1..]), Some(LinkExtension::ClientSupport { response: false, capabilities: 2 })));
        for len in 0..message.len() - 1 {
            assert!(LinkExtension::decode(&message[1..=len]).is_none());
        }
        for index in [1, 9, 10] {
            let mut invalid = message.clone();
            invalid[index] = 0xff;
            assert!(LinkExtension::decode(&invalid[1..]).is_none());
        }
        let mut invalid = message;
        invalid.push(0);
        assert!(LinkExtension::decode(&invalid[1..]).is_none());
    }
}
