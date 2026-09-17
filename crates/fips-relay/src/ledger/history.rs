//! Constant-size evidence for routes whose closed accounting has been retired.
use super::{Contract, Usage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredRouteEvidence {
    /// Agreements through this expiry cannot be installed again, even if the
    /// local clock moves backward. Channel identity and payments remain live.
    pub through_unix: u64,
    pub contracts: u64,
    pub units: Usage,
    pub reserved_msat: u64,
    pub submitted_msat: u64,
}

impl RetiredRouteEvidence {
    pub(crate) fn merged(self, other: Self) -> Option<Self> {
        Some(Self {
            through_unix: self.through_unix.max(other.through_unix),
            contracts: self.contracts.checked_add(other.contracts)?,
            units: Usage {
                reserved_units: self
                    .units
                    .reserved_units
                    .checked_add(other.units.reserved_units)?,
                submitted_units: self
                    .units
                    .submitted_units
                    .checked_add(other.units.submitted_units)?,
                unconfirmed_units: self
                    .units
                    .unconfirmed_units
                    .checked_add(other.units.unconfirmed_units)?,
            },
            reserved_msat: self.reserved_msat.checked_add(other.reserved_msat)?,
            submitted_msat: self.submitted_msat.checked_add(other.submitted_msat)?,
        })
    }

    pub(crate) fn added(self, contract: &Contract, usage: Usage) -> Option<Self> {
        Some(Self {
            through_unix: self.through_unix.max(contract.expires_unix),
            contracts: self.contracts.checked_add(1)?,
            units: Usage {
                reserved_units: self
                    .units
                    .reserved_units
                    .checked_add(usage.reserved_units)?,
                submitted_units: self
                    .units
                    .submitted_units
                    .checked_add(usage.submitted_units)?,
                unconfirmed_units: self
                    .units
                    .unconfirmed_units
                    .checked_add(usage.unconfirmed_units)?,
            },
            // Round each contract exactly as before retirement. Summing bytes
            // first would lose both differing tariffs and per-contract rounding.
            reserved_msat: self
                .reserved_msat
                .checked_add(contract.price.amount_due_msat(usage.reserved_units)?)?,
            submitted_msat: self
                .submitted_msat
                .checked_add(contract.price.amount_due_msat(usage.submitted_units)?)?,
        })
    }

    pub(crate) fn rejects(self, expiry: u64) -> bool {
        self.contracts != 0 && expiry <= self.through_unix
    }

    pub(crate) fn valid(self, channel_expiry: u64) -> bool {
        if self.contracts == 0 {
            return self == Self::default();
        }
        self.through_unix <= channel_expiry
            && self
                .units
                .submitted_units
                .checked_add(self.units.unconfirmed_units)
                == Some(self.units.reserved_units)
            && self.submitted_msat <= self.reserved_msat
    }

    pub(crate) fn recovered(saved: Option<Self>, modern: bool, expiry: u64) -> Option<Self> {
        match saved {
            Some(value) if value.valid(expiry) && (modern || value == Self::default()) => {
                Some(value)
            }
            None if !modern => Some(Self::default()),
            _ => None,
        }
    }
}

/// Exact closed prefix, persisted by the controller before cross-store cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RouteRetirementPlan {
    pub channel: String,
    pub through_unix: u64,
    pub contracts: Vec<Contract>,
    pub before: RetiredRouteEvidence,
    pub after: RetiredRouteEvidence,
}
