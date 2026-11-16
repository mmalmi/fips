use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PriceSelectionPolicy {
    pub feedback_timeout_ms: u64,
    pub retry_after_ms: u64,
    pub trial_max_units: u64,
    pub min_improvement_percent: u8,
    pub max_loss_percent: u8,
    pub max_rtt_ms: u64,
}

impl Default for PriceSelectionPolicy {
    fn default() -> Self {
        Self {
            feedback_timeout_ms: 15_000,
            retry_after_ms: 60_000,
            trial_max_units: 32_768,
            min_improvement_percent: 10,
            max_loss_percent: 25,
            max_rtt_ms: 5_000,
        }
    }
}

impl PriceSelectionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !(1_000..=60_000).contains(&self.feedback_timeout_ms)
            || !(self.feedback_timeout_ms..=3_600_000).contains(&self.retry_after_ms)
            || !(4_096..=1_048_576).contains(&self.trial_max_units)
            || self.min_improvement_percent > 50
            || self.max_loss_percent > 90
            || !(1..=60_000).contains(&self.max_rtt_ms)
        {
            return Err("invalid price selection policy".into());
        }
        Ok(())
    }
}
