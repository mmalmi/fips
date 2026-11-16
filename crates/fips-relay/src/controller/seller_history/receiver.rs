//! Bind the SDK's original close values to the application's released reports.
use super::*;

pub(super) fn valid_history(r: &ReceiverHistory, t: &Totals, policy: &ControllerPolicy) -> bool {
    if r.validate().is_err() || r.totals.len() > 1 + policy.additional_receive_mints.len()
        || !t.refund_deadline().is_some_and(|expiry| r.expires_through_unix <= expiry)
        || r.totals.iter().any(|s| s.unit != "sat" || !policy.accepts_mint(&s.mint)) {
        return false;
    }
    // The SDK retains a separate row per issuer. The controller's sat totals
    // bound the sum across those rows, including any historic pre-SDK reports.
    fn sum<T>(rows: &[T], field: impl Fn(&T) -> u64) -> u128 {
        rows.iter().map(|row| u128::from(field(row))).sum()
    }
    let value = sum(&r.totals, |s| s.value_after_stage1);
    let receiver = sum(&r.totals, |s| s.receiver_sum);
    let sender = sum(&r.totals, |s| s.sender_sum);
    sum(&r.totals, |s| s.channels) <= u128::from(t.accounting.channels)
        && sum(&r.totals, |s| s.capacity) <= u128::from(t.accounting.capacity_sat)
        && sum(&r.totals, |s| s.signed_amount) <= u128::from(t.signed_sat)
        && sum(&r.totals, |s| s.closed_amount) <= u128::from(t.paid_sat)
        && value <= u128::from(t.value_sat)
        && receiver <= u128::from(t.paid_sat) + u128::from(t.receiver_fee_reserve_sat)
        && sender <= u128::from(t.returned_sat)
        && value.checked_sub(receiver + sender).is_some_and(|fee| fee <= u128::from(t.fee_sat))
}

impl Plan {
    pub(super) fn attach_receiver(
        &mut self,
        j: &mut Journal,
        r: ReceiverPlan,
    ) -> Result<(), String> {
        r.validate()?;
        let h = j.history.as_mut().unwrap().seller.as_mut().unwrap();
        if h.totals != self.before
            || self
                .before
                .receiver
                .as_ref()
                .map_or(r.accounting.before != ReceiverHistory::default(), |old| {
                    old != &r.accounting.before
                })
        {
            return Err("receiver retirement history does not match controller".into());
        }
        self.before.receiver = Some(r.accounting.before.clone());
        self.after.receiver = Some(r.accounting.after.clone());
        self.receiver = Some(r);
        h.totals.receiver = self.before.receiver.clone();
        j.advance_history_version(6);
        j.version |= journal::RECEIVER_PROOF_RELEASE_VERSION;
        self.validate_receiver(j)
    }

    pub(super) fn validate_receiver(&self, j: &Journal) -> Result<(), String> {
        let Some(r) = &self.receiver else {
            return if j.history_version() < 6
                && self.before.receiver.is_none()
                && self.after.receiver.is_none()
            {
                Ok(())
            } else {
                Err("receiver retirement intent missing".into())
            };
        };
        r.validate()?;
        if j.history_version() != 6
            || j.version & journal::RECEIVER_PROOF_RELEASE_VERSION == 0
            || self.before.receiver.as_ref() != Some(&r.accounting.before)
            || self.after.receiver.as_ref() != Some(&r.accounting.after)
            || r.accounting.channels.len() != self.ledger.channels.len()
        {
            return Err("receiver retirement snapshots changed".into());
        }
        for c in &self.ledger.channels {
            let saved = r
                .accounting
                .channels
                .iter()
                .find(|s| s.id == c.terms.id)
                .ok_or("receiver retirement channel missing")?;
            let report = j
                .seller_settlements
                .get(&c.terms.id)
                .and_then(|s| s.report.as_ref())
                .ok_or("receiver retirement report missing")?;
            let t = &saved.totals;
            if c.terms.refund_deadline() != Some(saved.expires_unix)
                || t.mint != c.terms.mint_url
                || t.unit != "sat"
                || t.capacity != c.terms.capacity_sat
                || t.signed_amount != report.signed_sat
                || t.closed_amount != report.paid_sat
                || Some(t.receiver_sum) != report.receiver_value_sat()
                || t.sender_sum != report.refunded_sat
                || t.value_after_stage1 != report.value_after_stage1_sat
            {
                return Err("receiver retirement differs from original settlement".into());
            }
        }
        Ok(())
    }
}
