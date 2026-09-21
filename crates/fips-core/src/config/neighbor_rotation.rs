//! Optional exploration when all authenticated neighbor slots are occupied.

use serde::{Deserialize, Serialize};

/// Replace an idle, unconfigured neighbor only after a fresh Noise exchange.
/// Omit `node.neighbor_rotation` to retain existing neighbors at capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NeighborRotationConfig {
    /// Minimum peer age and time without application demand before replacement.
    pub idle_secs: u64,
    /// Node-wide minimum interval between candidate attempts and replacements.
    pub interval_secs: u64,
}

impl Default for NeighborRotationConfig {
    fn default() -> Self {
        Self {
            idle_secs: 30,
            interval_secs: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_is_opt_in_with_positive_defaults() {
        assert!(crate::Config::new().node.neighbor_rotation.is_none());
        let policy: NeighborRotationConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(policy.idle_secs, 30);
        assert_eq!(policy.interval_secs, 10);
        let mut config = crate::Config::new();
        config.node.neighbor_rotation = Some(policy);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_idle_or_interval_is_rejected() {
        for (idle_secs, interval_secs) in [(0, 1), (1, 0)] {
            let mut config = crate::Config::new();
            config.node.neighbor_rotation = Some(NeighborRotationConfig {
                idle_secs,
                interval_secs,
            });
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("neighbor_rotation"));
        }
    }
}
