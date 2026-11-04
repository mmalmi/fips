use super::ConfigError;
use crate::PeerIdentity;
use serde::{Deserialize, Serialize};

/// Explicit application policy for authenticated neighbors on every carrier.
/// Defaults preserve ordinary discovery and transport admission.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAdmissionConfig {
    /// Admit only identities in the current configured peer list, including on
    /// local, BLE and operator WebSocket connections.
    #[serde(default)]
    pub configured_only: bool,
    /// Always reject these identities, including configured peers.
    #[serde(default)]
    pub denied_npubs: Vec<String>,
}

impl PeerAdmissionConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        for npub in &self.denied_npubs {
            PeerIdentity::from_npub(npub).map_err(|_| {
                ConfigError::Validation("peer_admission contains an invalid denied npub".into())
            })?;
        }
        Ok(())
    }

    pub(crate) fn denies(&self, peer: &PeerIdentity) -> bool {
        self.denies_address(peer.node_addr())
    }

    pub(crate) fn denies_address(&self, address: &crate::NodeAddr) -> bool {
        self.denied_npubs.iter().any(|npub| {
            PeerIdentity::from_npub(npub).is_ok_and(|denied| denied.node_addr() == address)
        })
    }
}
