//! Explicit local forwarding fees keyed by complete destination identities.
use fips_core::{NodeAddr, PeerIdentity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Overrides change future offers, never the prices of accepted contracts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DestinationFees(BTreeMap<String, u64>);

impl DestinationFees {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn resolve(
        &self,
        max_rate: u64,
        allow_free: bool,
    ) -> Result<BTreeMap<NodeAddr, u64>, String> {
        if self.0.len() > 64 {
            return Err("too many destination fee rules".into());
        }
        let mut fees = BTreeMap::new();
        for (npub, fee) in &self.0 {
            let peer = PeerIdentity::from_npub(npub)
                .map_err(|_| "destination fee requires a valid npub")?;
            if npub != &peer.npub()
                || *fee > max_rate
                || (*fee == 0 && !allow_free)
                || fees.insert(*peer.node_addr(), *fee).is_some()
            {
                return Err("invalid destination fee or incompatible billing basis".into());
            }
        }
        Ok(fees)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips_core::Identity;

    #[test]
    fn exact_destination_rules_preserve_zero_and_enforce_policy_bounds() {
        let identity = Identity::from_secret_bytes(&[1; 32]).unwrap();
        let rules: DestinationFees =
            serde_json::from_value(serde_json::json!({identity.npub():0})).unwrap();
        assert_eq!(rules.resolve(10, true).unwrap()[identity.node_addr()], 0);
        assert!(rules.resolve(10, false).is_err());
        let excessive: DestinationFees =
            serde_json::from_value(serde_json::json!({identity.npub():11})).unwrap();
        assert!(excessive.resolve(10, true).is_err());
        for invalid in [
            "192.168.1.1".to_owned(),
            identity.npub().to_uppercase(),
            "own-router".into(),
        ] {
            let rules: DestinationFees =
                serde_json::from_value(serde_json::json!({invalid:0})).unwrap();
            assert!(rules.resolve(10, true).is_err());
        }
        assert!(
            DestinationFees::default()
                .resolve(10, true)
                .unwrap()
                .is_empty()
        );
        let many = DestinationFees(
            (1..=65)
                .map(|n| (Identity::from_secret_bytes(&[n; 32]).unwrap().npub(), 1))
                .collect(),
        );
        assert!(many.resolve(10, true).is_err());
    }
}
