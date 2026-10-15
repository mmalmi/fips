//! Retain seller debt and settlement totals after release or immutable expiry.
use super::channel_history::with_store;
use super::*;
use crate::ledger::channel_history::{History as LedgerHistory, Plan as LedgerPlan};
use cashu_service::{
    CashuSpilmanReceiverHistory as ReceiverHistory, CashuSpilmanReceiverRetirement as ReceiverPlan,
};
use std::borrow::BorrowMut;

mod receiver;

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct SellerHistory {
    totals: Totals,
    pending: Option<Plan>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Totals {
    accounting: LedgerHistory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refund_through_unix: Option<u64>,
    value_sat: u64,
    signed_sat: u64,
    paid_sat: u64,
    #[serde(default)]
    receiver_fee_reserve_sat: u64,
    returned_sat: u64,
    fee_sat: u64,
    #[serde(default)]
    receiver: Option<ReceiverHistory>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Plan {
    before: Totals,
    after: Totals,
    ledger: LedgerPlan,
    #[serde(default)]
    receiver: Option<ReceiverPlan>,
}

impl SellerHistory {
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }
}

impl Totals {
    fn refund_deadline(&self) -> Option<u64> {
        crate::ledger::refund_deadline(
            self.accounting.expires_through_unix,
            self.refund_through_unix,
        )
    }

    fn valid(&self, mint: &str) -> bool {
        self.accounting.valid(MAX_CHANNELS)
            && self
                .refund_deadline()
                .is_some_and(|refund| refund >= self.accounting.expires_through_unix)
            && self.accounting.capacity_sat <= self.value_sat
            && self
                .paid_sat
                .checked_add(self.receiver_fee_reserve_sat)
                .and_then(|n| n.checked_add(self.returned_sat))
                .and_then(|n| n.checked_add(self.fee_sat))
                == Some(self.value_sat)
            && self.paid_sat <= self.signed_sat
            && self.signed_sat as u128 * 1000 == self.accounting.usage.paid_msat as u128
            && self
                .receiver
                .as_ref()
                .is_none_or(|r| receiver::valid_history(r, self, mint))
            && (self.accounting.channels != 0
                || *self
                    == Self {
                        receiver: self.receiver.clone(),
                        ..Self::default()
                    })
    }

    fn added(&self, report: &SettlementReport, channel: &ChannelTerms) -> Result<Self, String> {
        Ok(Self {
            accounting: self.accounting.clone(),
            refund_through_unix: if self.refund_through_unix.is_some()
                || channel.refund_after_unix.is_some()
            {
                Some(
                    self.refund_deadline()
                        .ok_or("retired refund overflow")?
                        .max(channel.refund_deadline().ok_or("channel refund overflow")?),
                )
            } else {
                None
            },
            value_sat: add(self.value_sat, report.value_after_stage1_sat)?,
            signed_sat: add(self.signed_sat, report.signed_sat)?,
            paid_sat: add(self.paid_sat, report.paid_sat)?,
            receiver_fee_reserve_sat: add(
                self.receiver_fee_reserve_sat,
                report.receiver_fee_reserve_sat,
            )?,
            returned_sat: add(self.returned_sat, report.refunded_sat)?,
            fee_sat: add(self.fee_sat, report.fee_sat)?,
            receiver: self.receiver.clone(),
        })
    }
}

fn completed(j: &Journal, sale: &SellerSettlement, timestamp: u64) -> bool {
    // After the immutable refund deadline the buyer can recover directly from
    // the mint's signed outputs. Its absence need not retain this report forever.
    sale.report.is_some()
        && sale
            .channel
            .refund_deadline()
            .is_some_and(|e| e < timestamp)
        && !j.incoming.values().any(|i| i.channel.id == sale.channel.id)
}

impl Plan {
    fn validate(&self, j: &Journal) -> Result<(), String> {
        self.ledger
            .validate(MAX_CHANNELS)
            .map_err(|e| e.to_string())?;
        if !self.before.valid(&j.policy.mint_url)
            || !self.after.valid(&j.policy.mint_url)
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
                || s.report.as_ref().unwrap().signed_sat as u128 * 1000 != c.usage.paid_msat as u128
            {
                return Err("retiring sale changed".into());
            }
            after = after.added(s.report.as_ref().unwrap(), &s.channel)?;
        }
        after.accounting = self.ledger.after.clone();
        self.validate_receiver(j)?;
        after.receiver = self.after.receiver.clone();
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
        if j.version & journal::RECEIVER_PROOF_RELEASE_VERSION != 0 && j.history_version() != 6 {
            return Err("receiver proof release requires receiver history".into());
        }
        let Some(h) = j.history.as_ref().and_then(|h| h.seller.as_ref()) else {
            return if j.history_version() < 5 {
                Ok(())
            } else {
                Err("missing seller history".into())
            };
        };
        if !matches!(j.history_version(), 5 | 6)
            || !h.totals.valid(&j.policy.mint_url)
            || (h.totals.refund_through_unix.is_some()
                && j.version & journal::FUNDING_DEADLINES_VERSION == 0)
            || (j.history_version() == 6) != h.totals.receiver.is_some()
        {
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
        shared: &Mutex<impl BorrowMut<Store>>,
        seller: &DurableRelay,
        timestamp: u64,
        mut prepare: impl FnMut(&[String]) -> Result<ReceiverPlan, String>,
        mut retire: impl FnMut(&ReceiverPlan) -> Result<ReceiverHistory, String>,
    ) -> Result<usize, String> {
        Self::prepare_sales(shared, seller, timestamp, &mut prepare)?;
        Self::resume_sales(shared, seller, &mut prepare, &mut retire)
    }

    fn prepare_sales(
        shared: &Mutex<impl BorrowMut<Store>>,
        seller: &DurableRelay,
        timestamp: u64,
        mut prepare: impl FnMut(&[String]) -> Result<ReceiverPlan, String>,
    ) -> Result<(), String> {
        let selected = with_store(shared, |store| {
            if !store.ready {
                return Err("controller journal suspended".into());
            }
            if store.journal.history.as_ref().is_some_and(History::pending) {
                return Ok(None);
            }
            // One admitted payout fits the SDK handoff; retire the oldest owner first.
            let ids: Vec<_> = store
                .journal
                .seller_settlements
                .iter()
                .filter(|(_, s)| completed(&store.journal, s, timestamp))
                .min_by_key(|(id, s)| (s.channel.refund_deadline(), *id))
                .map(|(id, _)| id.clone())
                .into_iter()
                .collect();
            if ids.is_empty() {
                return Ok(None);
            }
            let ledger = seller
                .channel_retirement_plan(&ids, timestamp)
                .map_err(|e| e.to_string())?;
            let before = store
                .journal
                .history
                .as_ref()
                .and_then(|h| h.seller.as_ref())
                .map(|h| h.totals.clone())
                .unwrap_or_default();
            let mut after = before.clone();
            for id in &ids {
                after = after.added(
                    store.journal.seller_settlements[id]
                        .report
                        .as_ref()
                        .unwrap(),
                    &store.journal.seller_settlements[id].channel,
                )?;
            }
            after.accounting = ledger.after.clone();
            Ok(Some((
                ids,
                Plan {
                    before,
                    after,
                    ledger,
                    receiver: None,
                },
            )))
        })?;
        if let Some((ids, plan)) = selected {
            // An ineligible payout must not leave an unfulfillable intent.
            let receiver = prepare(&ids)?;
            with_store(shared, |store| {
                store.ensure_ready()?;
                store.save_sale_plan(plan, receiver).map(|_| ())
            })?;
        }
        Ok(())
    }

    pub(super) fn resume_sales(
        shared: &Mutex<impl BorrowMut<Store>>,
        seller: &DurableRelay,
        mut prepare: impl FnMut(&[String]) -> Result<ReceiverPlan, String>,
        mut retire: impl FnMut(&ReceiverPlan) -> Result<ReceiverHistory, String>,
    ) -> Result<usize, String> {
        let pending = with_store(shared, |store| {
            if !store.ready {
                return Err("controller journal suspended".into());
            }
            let plan = store
                .journal
                .history
                .as_ref()
                .and_then(|h| h.seller.as_ref())
                .and_then(|h| h.pending.clone());
            if let Some(p) = &plan {
                p.validate(&store.journal)?;
            }
            Ok(plan)
        })?;
        let Some(mut p) = pending else {
            return Ok(0);
        };
        if p.receiver.is_none() {
            // Upgrade saved intents before the ledger can discard their IDs.
            let ids = p
                .ledger
                .channels
                .iter()
                .map(|c| c.terms.id.clone())
                .collect::<Vec<_>>();
            let receiver = prepare(&ids)?;
            p = with_store(shared, |store| {
                store.check_sale_plan(&p)?;
                store.save_sale_plan(p, receiver)
            })?;
        }
        seller
            .retire_channels(&p.ledger)
            .map_err(|e| e.to_string())?;
        let receiver = p
            .receiver
            .as_ref()
            .ok_or("receiver retirement intent missing")?;
        if retire(receiver)? != receiver.accounting.after {
            return Err("receiver retirement result changed".into());
        }
        with_store(shared, |store| {
            store.check_sale_plan(&p)?;
            let mut j = store.journal.clone();
            p.finish(&mut j);
            Controller::validate_journal(&j, &j.policy, j.local)?;
            store.journal = j;
            store.persist()?;
            Ok(p.ledger.channels.len())
        })
    }

    fn check_sale_plan(&self, plan: &Plan) -> Result<(), String> {
        if !self.ready
            || self
                .journal
                .history
                .as_ref()
                .and_then(|h| h.seller.as_ref())
                .and_then(|h| h.pending.as_ref())
                != Some(plan)
        {
            return Err("seller retirement intent changed".into());
        }
        plan.validate(&self.journal)
    }

    fn save_sale_plan(&mut self, mut plan: Plan, receiver: ReceiverPlan) -> Result<Plan, String> {
        let mut j = self.journal.clone();
        let h = j.history.get_or_insert_with(History::default);
        h.channels
            .get_or_insert_with(channel_history::ChannelHistory::default);
        h.seller.get_or_insert_with(SellerHistory::default);
        plan.attach_receiver(&mut j, receiver)?;
        j.history.as_mut().unwrap().seller.as_mut().unwrap().pending = Some(plan.clone());
        Controller::validate_journal(&j, &j.policy, j.local)?;
        self.journal = j;
        self.persist()?;
        Ok(plan)
    }
}

fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b).ok_or("seller retirement overflow".into())
}

#[cfg(test)]
mod tests;
