//! Bind the SDK's original close values to the application's released reports.
use super::*;

pub(super) fn valid_history(r: &ReceiverHistory, t: &Totals, mint: &str) -> bool {
    r.validate().is_ok()
        && r.totals.len() <= 1
        && t.accounting
            .expires_through_unix
            .checked_add(60)
            .is_some_and(|expiry| r.expires_through_unix <= expiry)
        && r.totals.first().is_none_or(|s| {
            s.mint == mint
                && s.unit == "sat"
                && s.channels <= t.accounting.channels
                && s.capacity <= t.accounting.capacity_sat
                && s.closed_amount <= t.paid_sat
                && s.value_after_stage1 <= t.value_sat
                && t.paid_sat
                    .checked_add(t.receiver_fee_reserve_sat)
                    .is_some_and(|v| s.receiver_sum <= v)
                && s.sender_sum <= t.returned_sat
                && s.value_after_stage1
                    .checked_sub(s.receiver_sum)
                    .and_then(|v| v.checked_sub(s.sender_sum))
                    .is_some_and(|v| v <= t.fee_sat)
        })
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
                .map_or(r.before != ReceiverHistory::default(), |old| {
                    old != &r.before
                })
        {
            return Err("receiver retirement history does not match controller".into());
        }
        self.before.receiver = Some(r.before.clone());
        self.after.receiver = Some(r.after.clone());
        self.receiver = Some(r);
        h.totals.receiver = self.before.receiver.clone();
        j.advance_history_version(6);
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
            || self.before.receiver.as_ref() != Some(&r.before)
            || self.after.receiver.as_ref() != Some(&r.after)
            || r.channels.len() != self.ledger.channels.len()
        {
            return Err("receiver retirement snapshots changed".into());
        }
        for c in &self.ledger.channels {
            let saved = r
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
            if c.terms.expires_unix.checked_add(60) != Some(saved.expires_unix)
                || t.mint != c.terms.mint_url
                || t.unit != "sat"
                || t.capacity != c.terms.capacity_sat
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
