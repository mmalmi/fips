//! Keep service admission and immutable mint refund deadlines distinct.
use super::*;

impl ControllerPolicy {
    pub const DEFAULT_CHANNEL_LIFETIME_SECS: u64 = 24 * 60 * 60;

    pub(super) fn default_channel_lifetime_secs() -> u64 {
        Self::DEFAULT_CHANNEL_LIFETIME_SECS
    }

    pub(super) fn service_lifetime_secs(&self) -> u64 {
        (self.channel_lifetime_secs / 2).min(Self::DEFAULT_CHANNEL_LIFETIME_SECS / 2)
    }
}

impl FundingIntent {
    pub(super) fn refund_deadline(&self) -> Result<u64, String> {
        crate::ledger::refund_deadline(self.expires_unix, self.refund_after_unix)
            .ok_or_else(|| "refund deadline overflow".into())
    }

    pub(super) fn valid_deadlines(&self, policy: &ControllerPolicy) -> bool {
        let lifetime = if self.refund_after_unix.is_some() {
            policy.service_lifetime_secs()
        } else {
            policy.channel_lifetime_secs
        };
        self.expires_unix > self.created_unix
            && self.created_unix.checked_add(lifetime) == Some(self.expires_unix)
            && self
                .refund_deadline()
                .is_ok_and(|refund| refund > self.expires_unix)
            && self.refund_after_unix.is_none_or(|refund| {
                self.created_unix.checked_add(policy.channel_lifetime_secs) == Some(refund)
            })
    }

    pub(super) fn matches_refund_deadline(&self, payment: &CashuSpilmanPayment) -> bool {
        self.refund_deadline().is_ok_and(|refund| {
            payment
                .params
                .as_ref()
                .and_then(|p| p["expiry_timestamp"].as_u64())
                == Some(refund)
        })
    }
}

impl Controller {
    pub(super) fn validate_channel_deadlines(j: &Journal) -> Result<(), String> {
        let explicit = j.funding.values().any(|f| f.refund_after_unix.is_some())
            || j.incoming
                .values()
                .map(|i| &i.channel)
                .chain(j.buyer_settlements.values().map(|s| &s.channel))
                .chain(j.seller_settlements.values().map(|s| &s.channel))
                .chain(j.history.iter().flat_map(|h| h.sellers.values()))
                .any(|c| c.refund_after_unix.is_some());
        if explicit && j.version & journal::FUNDING_DEADLINES_VERSION == 0 {
            return Err("explicit refund deadlines require their journal format fence".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
