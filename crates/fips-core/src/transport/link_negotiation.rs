#[cfg(feature = "webrtc-transport")]
use crate::NodeAddr;
#[cfg(feature = "webrtc-transport")]
use serde::de::DeserializeOwned;
#[cfg(feature = "webrtc-transport")]
use serde::{Deserialize, Serialize};

pub(crate) const LINK_NEGOTIATION_SERVICE_PORT: u16 = 257;
#[cfg(feature = "webrtc-transport")]
pub(crate) const LINK_NEGOTIATION_VERSION: u32 = 1;

#[cfg(feature = "webrtc-transport")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LinkNegotiationKind {
    Offer,
    Answer,
    Candidate,
    Reject,
}

#[cfg(feature = "webrtc-transport")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkNegotiationMessage<T = serde_json::Value> {
    pub(crate) version: u32,
    pub(crate) negotiation_id: String,
    pub(crate) link_type: String,
    pub(crate) kind: LinkNegotiationKind,
    pub(crate) created_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) payload: T,
}

#[cfg(feature = "webrtc-transport")]
impl LinkNegotiationMessage {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub(crate) fn validate(&self, now_ms: u64) -> Result<(), String> {
        if self.version != LINK_NEGOTIATION_VERSION {
            return Err("unsupported link-negotiation version".into());
        }
        if self.negotiation_id.is_empty() || self.link_type.is_empty() {
            return Err("missing link-negotiation identity".into());
        }
        if self.expires_at_ms < now_ms || self.created_at_ms > now_ms.saturating_add(60_000) {
            return Err("link negotiation is expired or future-dated".into());
        }
        Ok(())
    }

    pub(crate) fn typed_payload<T: DeserializeOwned>(
        self,
    ) -> Result<LinkNegotiationMessage<T>, String> {
        let payload = serde_json::from_value(self.payload).map_err(|error| error.to_string())?;
        Ok(LinkNegotiationMessage {
            version: self.version,
            negotiation_id: self.negotiation_id,
            link_type: self.link_type,
            kind: self.kind,
            created_at_ms: self.created_at_ms,
            expires_at_ms: self.expires_at_ms,
            payload,
        })
    }
}

#[cfg(feature = "webrtc-transport")]
pub(crate) struct OutboundLinkNegotiation {
    pub(crate) recipient: NodeAddr,
    pub(crate) payload: Vec<u8>,
}

#[cfg(all(test, feature = "webrtc-transport"))]
mod tests {
    use super::*;

    #[test]
    fn generic_envelope_roundtrips_without_allocating_an_fsp_message_type() {
        let message = LinkNegotiationMessage {
            version: LINK_NEGOTIATION_VERSION,
            negotiation_id: "abc".into(),
            link_type: "webrtc".into(),
            kind: LinkNegotiationKind::Offer,
            created_at_ms: 10,
            expires_at_ms: 20,
            payload: serde_json::json!({"sdp": "offer"}),
        };
        let encoded = serde_json::to_vec(&message).unwrap();
        let decoded = LinkNegotiationMessage::decode(&encoded).unwrap();

        assert_eq!(LINK_NEGOTIATION_SERVICE_PORT, 257);
        assert_eq!(decoded.link_type, "webrtc");
        assert!(decoded.validate(15).is_ok());
    }
}
