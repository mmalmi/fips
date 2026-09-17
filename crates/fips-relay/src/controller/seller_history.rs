//! Retain seller debt and settlement totals after the buyer releases its report.
use super::*;
use crate::ledger::channel_history::{History as LedgerHistory, Plan as LedgerPlan};

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct SellerHistory {
    totals: Totals,
    pending: Option<Plan>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Totals {
    accounting: LedgerHistory,
    value_sat: u64,
    paid_sat: u64,
    returned_sat: u64,
    fee_sat: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Plan {
    before: Totals,
    after: Totals,
    ledger: LedgerPlan,
}

impl SellerHistory {
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }
}

impl Totals {
    fn valid(&self) -> bool {
        self.accounting.valid(MAX_CHANNELS)
            && self.accounting.capacity_sat <= self.value_sat
            && self
                .paid_sat
                .checked_add(self.returned_sat)
                .and_then(|n| n.checked_add(self.fee_sat))
                == Some(self.value_sat)
            && self.paid_sat as u128 * 1000 == self.accounting.usage.paid_msat as u128
            && (self.accounting.channels != 0 || *self == Self::default())
    }

    fn added(&self, report: &SettlementReport) -> Result<Self, String> {
        Ok(Self {
            accounting: self.accounting.clone(),
            value_sat: add(self.value_sat, report.value_after_stage1_sat)?,
            paid_sat: add(self.paid_sat, report.paid_sat)?,
            returned_sat: add(self.returned_sat, report.refunded_sat)?,
            fee_sat: add(self.fee_sat, report.fee_sat)?,
        })
    }
}

fn completed(j: &Journal, sale: &SellerSettlement, timestamp: u64) -> bool {
    sale.released
        && sale.report.is_some()
        && sale
            .channel
            .expires_unix
            .checked_add(60)
            .is_some_and(|e| e < timestamp)
        && !j.incoming.values().any(|i| i.channel.id == sale.channel.id)
}

impl Plan {
    fn validate(&self, j: &Journal) -> Result<(), String> {
        self.ledger
            .validate(MAX_CHANNELS)
            .map_err(|e| e.to_string())?;
        if !self.before.valid()
            || !self.after.valid()
            || self.before.accounting != self.ledger.before
            || self.after.accounting != self.ledger.after
            || j.history
                .as_ref()
                .and_then(|h| h.seller.as_ref())
                .map(|h| &h.totals)
                != Some(&self.before)
        {
            return Err("invalid seller retirement totals".into());
        }
        let mut after = self.before.clone();
        for c in &self.ledger.channels {
            let s = j
                .seller_settlements
                .get(&c.terms.id)
                .ok_or("retiring sale missing")?;
            if s.channel != c.terms
                || !completed(j, s, u64::MAX)
                || s.report.as_ref().unwrap().paid_sat as u128 * 1000 != c.usage.paid_msat as u128
            {
                return Err("retiring sale changed".into());
            }
            after = after.added(s.report.as_ref().unwrap())?;
        }
        after.accounting = self.ledger.after.clone();
        if after != self.after {
            return Err("retired seller settlement changed".into());
        }
        Ok(())
    }

    fn finish(&self, j: &mut Journal) {
        let h = j.history.as_mut().unwrap();
        for c in &self.ledger.channels {
            j.seller_settlements.remove(&c.terms.id);
            h.sellers.remove(&c.terms.id);
        }
        let h = h.seller.as_mut().unwrap();
        h.totals = self.after.clone();
        h.pending = None;
    }
}

impl Controller {
    pub(super) fn validate_seller_history(j: &Journal) -> Result<(), String> {
        let Some(h) = j.history.as_ref().and_then(|h| h.seller.as_ref()) else {
            return if j.version < 5 {
                Ok(())
            } else {
                Err("missing seller history".into())
            };
        };
        if j.version != 5 || !h.totals.valid() {
            return Err("invalid seller history".into());
        }
        if let Some(p) = &h.pending {
            let history = j.history.as_ref().unwrap();
            if history.routes_pending() || history.channels.as_ref().is_some_and(|h| h.pending()) {
                return Err("conflicting seller retirement".into());
            }
            p.validate(j)?;
            let mut projected = j.clone();
            p.finish(&mut projected);
            Self::validate_journal(&projected, &projected.policy, projected.local)?;
        }
        Ok(())
    }
}

impl Store {
    pub(super) fn retire_sales(
        &mut self,
        seller: &DurableRelay,
        timestamp: u64,
    ) -> Result<usize, String> {
        self.prepare_sales(seller, timestamp)?;
        self.resume_sales(seller)
    }

    fn prepare_sales(&mut self, seller: &DurableRelay, timestamp: u64) -> Result<(), String> {
        if !self.ready {
            return Err("controller journal suspended".into());
        }
        if !self.journal.history.as_ref().is_some_and(History::pending) {
            let ids: Vec<_> = self
                .journal
                .seller_settlements
                .iter()
                .filter(|(_, s)| completed(&self.journal, s, timestamp))
                .map(|(id, _)| id.clone())
                .collect();
            if !ids.is_empty() {
                let ledger = seller
                    .channel_retirement_plan(&ids, timestamp)
                    .map_err(|e| e.to_string())?;
                let before = self
                    .journal
                    .history
                    .as_ref()
                    .and_then(|h| h.seller.as_ref())
                    .map(|h| h.totals.clone())
                    .unwrap_or_default();
                let mut after = before.clone();
                for id in &ids {
                    after = after
                        .added(self.journal.seller_settlements[id].report.as_ref().unwrap())?;
                }
                after.accounting = ledger.after.clone();
                let mut j = self.journal.clone();
                j.version = 5;
                let h = j.history.get_or_insert_with(History::default);
                h.channels
                    .get_or_insert_with(channel_history::ChannelHistory::default);
                h.seller.get_or_insert_with(SellerHistory::default).pending = Some(Plan {
                    before,
                    after,
                    ledger,
                });
                Controller::validate_journal(&j, &j.policy, j.local)?;
                self.journal = j;
                self.persist()?;
            }
        }
        Ok(())
    }

    pub(super) fn resume_sales(&mut self, seller: &DurableRelay) -> Result<usize, String> {
        if !self.ready {
            return Err("controller journal suspended".into());
        }
        let Some(p) = self
            .journal
            .history
            .as_ref()
            .and_then(|h| h.seller.as_ref())
            .and_then(|h| h.pending.clone())
        else {
            return Ok(0);
        };
        p.validate(&self.journal)?;
        seller
            .retire_channels(&p.ledger)
            .map_err(|e| e.to_string())?;
        let mut j = self.journal.clone();
        p.finish(&mut j);
        Controller::validate_journal(&j, &j.policy, j.local)?;
        self.journal = j;
        self.persist()?;
        Ok(p.ledger.channels.len())
    }
}

fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b).ok_or("seller retirement overflow".into())
}

#[cfg(test)]
mod tests;
