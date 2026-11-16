use super::RenewalPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerPolicy {
    /// Additional operator-trusted issuers for incoming sat channels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_receive_mints: Vec<String>,
    pub mint_url: String,
    pub channel_capacity_sat: u64,
    /// Bounds unresolved reservations and actual wallet debits. Confirmed local
    /// wallet refund recovery releases the channel's locked capital.
    pub max_locked_sat: u64,
    /// Maximum token reserve, rounding and wallet fees above channel capacity.
    pub max_funding_overhead_sat: u64,
    /// Lifetime wallet debits minus verified refunds, including pending reservations.
    pub max_wallet_spend_sat: u64,
    /// Funding lifetime for new channels; service ends halfway, at most 12 hours.
    #[serde(default = "ControllerPolicy::default_channel_lifetime_secs")]
    pub channel_lifetime_secs: u64,
    pub renewal: Option<RenewalPolicy>,
}

impl ControllerPolicy {
    pub(crate) fn receiving_mints(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.mint_url).chain(&self.additional_receive_mints)
    }

    pub(crate) fn accepts_mint(&self, mint: &str) -> bool {
        self.receiving_mints().any(|allowed| allowed == mint)
    }

    pub(crate) fn receive_only(&self) -> bool {
        self.max_wallet_spend_sat == 0 && self.max_locked_sat == 0
    }
}
