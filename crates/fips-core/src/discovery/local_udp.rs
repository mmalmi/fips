//! Bounded codec for same-host capabilities exchanged over authenticated FSP.

use super::local::LocalInstanceCapability;

pub const LOCAL_KEY_HINT_VERSION: u8 = 1;
pub const LOCAL_KEY_HINT_REQUEST_BYTES: usize = 9;
pub const LOCAL_KEY_HINT_RESPONSE_BYTES: usize = 41;
pub const LOCAL_CAPABILITY_WIRE_VERSION: u8 = 1;
pub const LOCAL_CAPABILITY_FSP_PORT: u16 = 258;
pub const LOCAL_CAPABILITY_MAX_NAME_BYTES: usize = 64;
pub const LOCAL_CAPABILITY_MAX_COUNT: usize = 16;
pub const LOCAL_CAPABILITY_MAX_PROVIDERS: usize = 32;

const CAPABILITY_MAX_WIRE_BYTES: usize = 1 + LOCAL_CAPABILITY_MAX_NAME_BYTES + 1 + 2 + 2;
const PROVIDER_MAX_WIRE_BYTES: usize =
    32 + 8 + 1 + LOCAL_CAPABILITY_MAX_COUNT * CAPABILITY_MAX_WIRE_BYTES;
/// Exact largest roster admitted by the declared provider/capability bounds.
pub const LOCAL_CAPABILITY_MAX_MESSAGE_BYTES: usize =
    1 + 1 + 8 + 8 + 1 + LOCAL_CAPABILITY_MAX_PROVIDERS * PROVIDER_MAX_WIRE_BYTES;

const CAPABILITY_ANNOUNCE: u8 = 1;
const CAPABILITY_ROSTER: u8 = 2;

/// Minimal same-host discovery prelude used only to obtain an untrusted IK
/// responder-key hint. Message kind is determined by exact wire length:
/// request = version + nonce; response = version + nonce + x-only pubkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalKeyHint {
    Request { nonce: u64 },
    Response { nonce: u64, pubkey: [u8; 32] },
}

impl LocalKeyHint {
    pub fn encode(self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(match self {
            Self::Request { .. } => LOCAL_KEY_HINT_REQUEST_BYTES,
            Self::Response { .. } => LOCAL_KEY_HINT_RESPONSE_BYTES,
        });
        wire.push(LOCAL_KEY_HINT_VERSION);
        match self {
            Self::Request { nonce } => wire.extend_from_slice(&nonce.to_be_bytes()),
            Self::Response { nonce, pubkey } => {
                wire.extend_from_slice(&nonce.to_be_bytes());
                wire.extend_from_slice(&pubkey);
            }
        }
        wire
    }

    pub fn decode(wire: &[u8]) -> Option<Self> {
        if wire.first().copied()? != LOCAL_KEY_HINT_VERSION {
            return None;
        }
        let nonce = u64::from_be_bytes(wire.get(1..9)?.try_into().ok()?);
        match wire.len() {
            LOCAL_KEY_HINT_REQUEST_BYTES => Some(Self::Request { nonce }),
            LOCAL_KEY_HINT_RESPONSE_BYTES => Some(Self::Response {
                nonce,
                pubkey: wire.get(9..41)?.try_into().ok()?,
            }),
            _ => None,
        }
    }

    pub fn is_wire_shape(wire: &[u8]) -> bool {
        matches!(
            wire.len(),
            LOCAL_KEY_HINT_REQUEST_BYTES | LOCAL_KEY_HINT_RESPONSE_BYTES
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCapabilityProvider {
    pub pubkey: [u8; 32],
    pub process_epoch: [u8; 8],
    pub capabilities: Vec<LocalInstanceCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalCapabilityMessage {
    Announce {
        process_epoch: [u8; 8],
        revision: u64,
        capabilities: Vec<LocalInstanceCapability>,
    },
    Roster {
        anchor_epoch: [u8; 8],
        revision: u64,
        providers: Vec<LocalCapabilityProvider>,
    },
}

impl LocalCapabilityMessage {
    pub fn encode(&self) -> Result<Vec<u8>, LocalCapabilityCodecError> {
        let mut wire = vec![LOCAL_CAPABILITY_WIRE_VERSION];
        match self {
            Self::Announce {
                process_epoch,
                revision,
                capabilities,
            } => {
                wire.push(CAPABILITY_ANNOUNCE);
                wire.extend_from_slice(process_epoch);
                wire.extend_from_slice(&revision.to_be_bytes());
                put_capabilities(&mut wire, capabilities)?;
            }
            Self::Roster {
                anchor_epoch,
                revision,
                providers,
            } => {
                check_count(providers.len(), LOCAL_CAPABILITY_MAX_PROVIDERS)?;
                wire.push(CAPABILITY_ROSTER);
                wire.extend_from_slice(anchor_epoch);
                wire.extend_from_slice(&revision.to_be_bytes());
                wire.push(providers.len() as u8);
                for provider in providers {
                    wire.extend_from_slice(&provider.pubkey);
                    wire.extend_from_slice(&provider.process_epoch);
                    put_capabilities(&mut wire, &provider.capabilities)?;
                }
            }
        }
        if wire.len() > LOCAL_CAPABILITY_MAX_MESSAGE_BYTES {
            return Err(LocalCapabilityCodecError::LimitExceeded);
        }
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> Result<Self, LocalCapabilityCodecError> {
        if wire.len() > LOCAL_CAPABILITY_MAX_MESSAGE_BYTES {
            return Err(LocalCapabilityCodecError::LimitExceeded);
        }
        let mut input = Input { wire, at: 0 };
        let version = input.byte()?;
        if version != LOCAL_CAPABILITY_WIRE_VERSION {
            return Err(LocalCapabilityCodecError::Malformed);
        }
        let kind = input.byte()?;
        let message = match kind {
            CAPABILITY_ANNOUNCE => {
                let process_epoch = input.array()?;
                let revision = u64::from_be_bytes(input.array()?);
                let capabilities = input.capabilities()?;
                Self::Announce {
                    process_epoch,
                    revision,
                    capabilities,
                }
            }
            CAPABILITY_ROSTER => {
                let anchor_epoch = input.array()?;
                let revision = u64::from_be_bytes(input.array()?);
                let count = input.byte()? as usize;
                check_count(count, LOCAL_CAPABILITY_MAX_PROVIDERS)?;
                let mut providers = Vec::with_capacity(count);
                for _ in 0..count {
                    providers.push(LocalCapabilityProvider {
                        pubkey: input.array()?,
                        process_epoch: input.array()?,
                        capabilities: input.capabilities()?,
                    });
                }
                Self::Roster {
                    anchor_epoch,
                    revision,
                    providers,
                }
            }
            _ => return Err(LocalCapabilityCodecError::Malformed),
        };
        input.finish()?;
        Ok(message)
    }
}

fn check_count(actual: usize, max: usize) -> Result<(), LocalCapabilityCodecError> {
    (actual <= max)
        .then_some(())
        .ok_or(LocalCapabilityCodecError::LimitExceeded)
}

fn put_capabilities(
    wire: &mut Vec<u8>,
    capabilities: &[LocalInstanceCapability],
) -> Result<(), LocalCapabilityCodecError> {
    check_count(capabilities.len(), LOCAL_CAPABILITY_MAX_COUNT)?;
    wire.push(capabilities.len() as u8);
    for capability in capabilities {
        put_name(wire, &capability.name)?;
        put_port(wire, capability.fsp_port);
        wire.extend_from_slice(&capability.priority.to_be_bytes());
    }
    Ok(())
}

fn put_name(wire: &mut Vec<u8>, name: &str) -> Result<(), LocalCapabilityCodecError> {
    if !local_capability_name_is_valid(name) {
        return Err(LocalCapabilityCodecError::LimitExceeded);
    }
    wire.push(name.len() as u8);
    wire.extend_from_slice(name.as_bytes());
    Ok(())
}

pub(crate) fn local_capability_name_is_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= LOCAL_CAPABILITY_MAX_NAME_BYTES
}

fn put_port(wire: &mut Vec<u8>, port: Option<u16>) {
    wire.push(u8::from(port.is_some()));
    wire.extend_from_slice(&port.unwrap_or(0).to_be_bytes());
}

struct Input<'a> {
    wire: &'a [u8],
    at: usize,
}

impl<'a> Input<'a> {
    fn bytes(&mut self, len: usize) -> Result<&'a [u8], LocalCapabilityCodecError> {
        let end = self.at + len;
        let bytes = self
            .wire
            .get(self.at..end)
            .ok_or(LocalCapabilityCodecError::Malformed)?;
        self.at = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], LocalCapabilityCodecError> {
        Ok(self.bytes(N)?.try_into().expect("exact codec field"))
    }

    fn byte(&mut self) -> Result<u8, LocalCapabilityCodecError> {
        Ok(self.array::<1>()?[0])
    }

    fn name(&mut self) -> Result<String, LocalCapabilityCodecError> {
        let len = self.byte()? as usize;
        if len == 0 || len > LOCAL_CAPABILITY_MAX_NAME_BYTES {
            return Err(LocalCapabilityCodecError::LimitExceeded);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| LocalCapabilityCodecError::InvalidUtf8)
    }

    fn port(&mut self) -> Result<Option<u16>, LocalCapabilityCodecError> {
        let flag = self.byte()?;
        let port = u16::from_be_bytes(self.array()?);
        match (flag, port) {
            (0, 0) => Ok(None),
            (1, port) => Ok(Some(port)),
            _ => Err(LocalCapabilityCodecError::Malformed),
        }
    }

    fn capabilities(&mut self) -> Result<Vec<LocalInstanceCapability>, LocalCapabilityCodecError> {
        let count = self.byte()? as usize;
        check_count(count, LOCAL_CAPABILITY_MAX_COUNT)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(LocalInstanceCapability {
                name: self.name()?,
                fsp_port: self.port()?,
                priority: i16::from_be_bytes(self.array()?),
            });
        }
        Ok(capabilities)
    }

    fn finish(self) -> Result<(), LocalCapabilityCodecError> {
        (self.at == self.wire.len())
            .then_some(())
            .ok_or(LocalCapabilityCodecError::Malformed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalCapabilityCodecError {
    Malformed,
    LimitExceeded,
    InvalidUtf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const EPOCH: [u8; 8] = [8; 8];

    fn roundtrip(message: LocalCapabilityMessage) {
        assert_eq!(
            LocalCapabilityMessage::decode(&message.encode().unwrap()),
            Ok(message)
        );
    }

    #[test]
    fn key_hint_messages_contain_only_version_nonce_and_optional_pubkey() {
        let request = LocalKeyHint::Request { nonce: 42 };
        let response = LocalKeyHint::Response {
            nonce: 42,
            pubkey: KEY,
        };
        let request_wire = request.encode();
        let response_wire = response.encode();

        assert_eq!(request_wire.len(), LOCAL_KEY_HINT_REQUEST_BYTES);
        assert_eq!(response_wire.len(), LOCAL_KEY_HINT_RESPONSE_BYTES);
        assert_eq!(LocalKeyHint::decode(&request_wire), Some(request));
        assert_eq!(LocalKeyHint::decode(&response_wire), Some(response));
        assert_eq!(&response_wire[9..], KEY);

        let mut wrong_version = request_wire;
        wrong_version[0] = LOCAL_KEY_HINT_VERSION + 1;
        assert_eq!(LocalKeyHint::decode(&wrong_version), None);
        assert_eq!(LocalKeyHint::decode(&response_wire[..40]), None);
    }

    #[test]
    fn capability_messages_roundtrip() {
        roundtrip(LocalCapabilityMessage::Announce {
            process_epoch: EPOCH,
            revision: 9,
            capabilities: vec![
                LocalInstanceCapability::service("hashtree/1", 300).with_priority(4),
                LocalInstanceCapability::role("compute.gpu/1"),
            ],
        });
        roundtrip(LocalCapabilityMessage::Roster {
            anchor_epoch: EPOCH,
            revision: 3,
            providers: vec![LocalCapabilityProvider {
                pubkey: KEY,
                process_epoch: [9; 8],
                capabilities: vec![LocalInstanceCapability::service("hashtree/1", 300)],
            }],
        });
        roundtrip(LocalCapabilityMessage::Announce {
            process_epoch: EPOCH,
            revision: 10,
            capabilities: vec![],
        });
    }

    #[test]
    fn capability_decode_is_strict_and_bounded() {
        let base = LocalCapabilityMessage::Announce {
            process_epoch: EPOCH,
            revision: 1,
            capabilities: vec![LocalInstanceCapability::role("x")],
        }
        .encode()
        .unwrap();
        assert!(LocalCapabilityMessage::decode(&base[..base.len() - 1]).is_err());
        let mut wire = base.clone();
        wire.push(0);
        assert!(LocalCapabilityMessage::decode(&wire).is_err());
        for (offset, value) in [(0, 2), (1, 9), (18, 17), (19, 65), (20, 0xff), (21, 2)] {
            let mut wire = base.clone();
            wire[offset] = value;
            assert!(LocalCapabilityMessage::decode(&wire).is_err());
        }
        assert!(
            LocalCapabilityMessage::decode(&vec![0; LOCAL_CAPABILITY_MAX_MESSAGE_BYTES + 1])
                .is_err()
        );
        let long = LocalCapabilityMessage::Announce {
            process_epoch: EPOCH,
            revision: 1,
            capabilities: vec![LocalInstanceCapability::role(
                "x".repeat(LOCAL_CAPABILITY_MAX_NAME_BYTES + 1),
            )],
        };
        assert!(long.encode().is_err());
        let many = LocalCapabilityMessage::Announce {
            process_epoch: EPOCH,
            revision: 1,
            capabilities: vec![LocalInstanceCapability::role("x"); LOCAL_CAPABILITY_MAX_COUNT + 1],
        };
        assert!(many.encode().is_err());
    }

    #[test]
    fn maximum_declared_roster_fits_one_fsp_service_payload() {
        let capability = LocalInstanceCapability::role("x".repeat(LOCAL_CAPABILITY_MAX_NAME_BYTES));
        let provider = LocalCapabilityProvider {
            pubkey: KEY,
            process_epoch: EPOCH,
            capabilities: vec![capability; LOCAL_CAPABILITY_MAX_COUNT],
        };
        let message = LocalCapabilityMessage::Roster {
            anchor_epoch: EPOCH,
            revision: 1,
            providers: vec![provider; LOCAL_CAPABILITY_MAX_PROVIDERS],
        };
        let wire = message.encode().expect("declared maxima must encode");
        assert_eq!(wire.len(), LOCAL_CAPABILITY_MAX_MESSAGE_BYTES);
        assert!(
            wire.len() <= crate::proto::fsp_wire::fsp_service_datagram_max_body_len(),
            "declared roster maxima must fit FSP"
        );
        assert_eq!(LocalCapabilityMessage::decode(&wire), Ok(message));
    }
}
