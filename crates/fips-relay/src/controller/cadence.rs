//! Ephemeral scheduling hints; durable accounting remains the authorization source.
use super::*;
use tokio::time::Instant;

pub(super) const SCAN_INTERVAL: Duration = Duration::from_millis(50);
const RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_RECHECK_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PaymentCadence {
    /// Target maximum age of new priced usage before an eligible payment is scheduled.
    pub max_delay_ms: u64,
    /// Pay earlier at this fraction of grace left after reported crash loss.
    pub unpaid_percent: u8,
}

impl Default for PaymentCadence {
    fn default() -> Self {
        Self {
            max_delay_ms: 500,
            unpaid_percent: 50,
        }
    }
}

impl PaymentCadence {
    pub fn validate(&self) -> Result<(), String> {
        if !(50..=10_000).contains(&self.max_delay_ms) || !(1..=75).contains(&self.unpaid_percent) {
            return Err("payment cadence requires 50–10000 ms and 1–75% of grace".into());
        }
        Ok(())
    }

    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Default)]
pub(super) struct ChannelSchedule {
    acknowledged_msat: Option<u64>,
    observed_authorized_msat: u64,
    observed_evidence_msat: u64,
    reported_loss_msat: u64,
    dirty_since: Option<Instant>,
    newer_usage_since: Option<Instant>,
    retry_at: Option<Instant>,
    unclaimed: Option<UnclaimedUsage>,
}

struct UnclaimedUsage {
    evidence_msat: u64,
    delay: Duration,
    check_at: Instant,
}

impl ChannelSchedule {
    fn observe(&mut self, now: Instant, evidence_msat: u64, authorized_sat: u64) -> u64 {
        if evidence_msat > self.observed_evidence_msat {
            self.dirty_since.get_or_insert(now);
        }
        self.observed_evidence_msat = evidence_msat;
        self.observed_authorized_msat = authorized_sat.saturating_mul(1_000);
        evidence_msat.max(self.observed_authorized_msat)
    }

    pub(super) fn observe_in_flight(
        &mut self,
        now: Instant,
        evidence_msat: u64,
        authorized_sat: u64,
        started_evidence_msat: u64,
    ) {
        self.observe(now, evidence_msat, authorized_sat);
        if evidence_msat > started_evidence_msat {
            self.newer_usage_since.get_or_insert(now);
        }
    }

    pub(super) fn due(
        &mut self,
        now: Instant,
        evidence_msat: u64,
        authorized_sat: u64,
        grace_msat: u64,
        policy: &PaymentCadence,
    ) -> bool {
        let liability = self.observe(now, evidence_msat, authorized_sat);
        if let Some(when) = self.retry_at {
            return now >= when;
        }
        // One reconciliation after creation/restart also retries durable signed
        // balances whose reply was lost. No financial fact lives in this cache.
        let Some(paid) = self.acknowledged_msat else {
            return true;
        };
        let debt = liability.saturating_sub(paid);
        if debt == 0 {
            // Rounded credit can cover new usage without erasing its age.
            self.unclaimed = None;
            return false;
        }
        if let Some(unclaimed) = &self.unclaimed
            && evidence_msat == unclaimed.evidence_msat
            && authorized_sat.saturating_mul(1_000) <= paid
        {
            return now >= unclaimed.check_at;
        }
        self.unclaimed = None;
        let since = *self.dirty_since.get_or_insert(now);
        let grace = grace_msat.saturating_sub(self.reported_loss_msat);
        let threshold =
            ((u128::from(grace) * u128::from(policy.unpaid_percent)) / 100).max(1) as u64;
        debt >= threshold || now.duration_since(since) >= Duration::from_millis(policy.max_delay_ms)
    }

    pub(super) fn acknowledge(
        &mut self,
        now: Instant,
        evidence_msat: u64,
        paid_msat: u64,
        lost_msat: u64,
    ) {
        // Lost or delayed forwarding can leave local sends above the provider's
        // claim. Recheck unchanged evidence less often without forgiving it;
        // a late claim must remain payable even if no new traffic arrives.
        self.unclaimed = (evidence_msat > paid_msat).then(|| {
            let delay = self
                .unclaimed
                .as_ref()
                .filter(|old| {
                    old.evidence_msat == evidence_msat && self.acknowledged_msat == Some(paid_msat)
                })
                .map_or(RETRY_DELAY, |old| (old.delay * 2).min(MAX_RECHECK_DELAY));
            UnclaimedUsage {
                evidence_msat,
                delay,
                check_at: now + delay,
            }
        });
        self.acknowledged_msat = Some(paid_msat);
        // A validated loss report only narrows this volatile scheduling hint.
        self.reported_loss_msat = self.reported_loss_msat.max(lost_msat);
        // Acknowledged usage cannot age newer sends. Keep their first observed
        // time, including usage covered temporarily by the rounded balance.
        let newer = self.newer_usage_since.take();
        if self.observed_authorized_msat <= paid_msat && evidence_msat <= paid_msat {
            self.dirty_since = if self.observed_evidence_msat <= evidence_msat {
                None
            } else {
                newer.or(self.dirty_since)
            };
        }
        self.retry_at = None;
    }

    pub(super) fn failed(&mut self, now: Instant) {
        self.unclaimed = None;
        self.newer_usage_since = None;
        self.retry_at = Some(now + RETRY_DELAY);
    }
}

#[cfg(test)]
#[path = "cadence_tests.rs"]
mod tests;
