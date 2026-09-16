//! Authenticated route quotation wire records.
use super::*;
use crate::ledger::node_addr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRequest {
    #[serde(with = "peer_identity")]
    pub destination: PeerIdentity,
    #[serde(with = "node_addrs")]
    pub ancestors: Vec<NodeAddr>,
    /// One deadline for the whole recursive request, not a new timeout per hop.
    pub deadline_unix: u64,
    /// Monitoring can reuse an unchanged unexpired offer without growing history.
    #[serde(default, skip_serializing_if = "is_false")]
    pub reuse_unchanged: bool,
    /// Optional route-wide byte ceiling for an explicitly bounded trial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_max_units: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOffer {
    /// A quota-limited trial cannot be renewed automatically without re-selection.
    #[serde(default, skip_serializing_if = "is_false")]
    pub trial: bool,
    #[serde(default, skip_serializing_if = "BillingBasis::is_legacy")]
    pub billing: BillingBasis,
    pub id: String,
    #[serde(with = "node_addr")]
    pub buyer: NodeAddr,
    #[serde(with = "node_addr")]
    pub provider: NodeAddr,
    #[serde(with = "peer_identity")]
    pub destination: PeerIdentity,
    #[serde(with = "node_addr")]
    pub next_hop: NodeAddr,
    /// Provider through final destination; descriptive, not a delivery proof.
    #[serde(with = "node_addrs")]
    pub path: Vec<NodeAddr>,
    pub price: BytePrice,
    pub expires_unix: u64,
    pub max_units: u64,
    pub mint_url: String,
    pub receiver_pubkey_hex: String,
    pub capacity_sat: u64,
    pub grace_msat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuoteResponse {
    Offer { offer: Box<RouteOffer> },
    Rejected,
}

mod node_addrs {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        addresses: &[NodeAddr],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        addresses
            .iter()
            .map(|a| *a.as_bytes())
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<NodeAddr>, D::Error> {
        Vec::<[u8; 16]>::deserialize(deserializer)
            .map(|v| v.into_iter().map(NodeAddr::from_bytes).collect())
    }
}

mod peer_identity {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        peer: &PeerIdentity,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        peer.npub().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PeerIdentity, D::Error> {
        let value = String::deserialize(deserializer)?;
        PeerIdentity::from_npub(&value).map_err(serde::de::Error::custom)
    }
}
