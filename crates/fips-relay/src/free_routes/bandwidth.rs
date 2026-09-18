//! Optional local limits shared by every negotiated free-data grant.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeBandwidthPolicy {
    pub global_bytes_per_second: u32,
    pub global_burst_bytes: u32,
    pub peer_bytes_per_second: u32,
    pub peer_burst_bytes: u32,
}

impl FreeBandwidthPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.global_bytes_per_second == 0
            || self.peer_bytes_per_second == 0
            || self.peer_bytes_per_second > self.global_bytes_per_second
            || self.peer_burst_bytes < crate::unpaid_budget::MIN_CHARGE
            || self.peer_burst_bytes > self.global_burst_bytes
        {
            return Err("invalid free bandwidth limits".into());
        }
        Ok(())
    }
}
