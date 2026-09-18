//! Completed outgoing channels: one recoverable buyer/wallet/controller handoff.
use super::*;
use crate::buyer::channel_history::Plan as BuyerPlan;
use cashu_service::{CashuRequestSequence, CashuSpilmanRetiredHistory};
use sha2::{Digest, Sha256};

mod selection;
#[cfg(test)]
mod tests;

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct ChannelHistory {
    pub totals: Totals,
    pending: Option<Plan>,
}

/// Requested token amounts are SDK-owned; actual debits include all mint fees.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Totals {
    pub through: u64,
    pub channels: u64,
    pub capacity_sat: u64,
    pub signed_sat: u64,
    pub refund_sat: u64,
    pub cost: cashu_service::CashuSendCost,
    pub expires_through_unix: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Plan {
    before: Totals,
    after: Totals,
    funding: Vec<String>,
    buyer: BuyerPlan,
}

pub(super) fn scope(j: &Journal) -> String {
    // Stable application scope, independent of neighbors, sessions and channels.
    format!("{:x}", Sha256::digest(j.epoch.as_bytes()))
}

pub(super) fn sequence(j: &Journal, id: &str) -> Option<u64> {
    CashuRequestSequence::from_request_id(id)
        .ok()
        .flatten()
        .filter(|s| s.scope() == scope(j))
        .map(|s| s.number())
}

impl ChannelHistory {
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }
}

impl Totals {
    fn valid(&self) -> bool {
        if self.channels == 0 {
            return *self == Self::default();
        }
        self.channels <= self.through
            && self.channels <= self.capacity_sat
            && self.signed_sat <= self.capacity_sat
            && self.capacity_sat <= self.cost.token_amount_sat
            && self
                .cost
                .token_amount_sat
                .checked_add(self.cost.swap_fee_sat)
                == Some(self.cost.wallet_debit_sat)
            && self.refund_sat <= self.cost.wallet_debit_sat
            && self.expires_through_unix != 0
    }

    fn matches(&self, sdk: &CashuSpilmanRetiredHistory, mint: &str) -> bool {
        sdk.send.mint_url == mint
            && sdk.send.through == self.through
            && sdk.send.requests == self.channels
            && sdk.capacity_sat == self.capacity_sat
            && sdk.signed_sat == self.signed_sat
            && sdk.refund_sat == self.refund_sat
            && sdk.send.cost == self.cost
            && sdk.expires_through_unix == self.expires_through_unix
    }
}

impl Plan {
    fn validate(&self, j: &Journal) -> Result<(), String> {
        self.buyer.validate().map_err(|e| e.to_string())?;
        if !self.before.valid()
            || !self.after.valid()
            || self.funding.is_empty()
            || self.funding.len() > MAX_CHANNELS
            || self.after.through >= j.next_funding
            || self.after.through <= self.before.through
            || j.history
                .as_ref()
                .and_then(|h| h.channels.as_ref())
                .map(|h| &h.totals)
                != Some(&self.before)
        {
            return Err("invalid channel retirement prefix".into());
        }
        let mut after = self.before.clone();
        let mut terms = BTreeMap::new();
        let mut previous = self.before.through;
        for id in &self.funding {
            let n = sequence(j, id).ok_or("retirement funding identity changed")?;
            if n <= previous || n > self.after.through {
                return Err("unordered retirement prefix".into());
            }
            previous = n;
            let f = j.funding.get(id).ok_or("retiring funding missing")?;
            let funded =
                selection::completed(j, f, u64::MAX).ok_or("retiring channel unfinished")?;
            let signed = j.buyer_settlements[&funded.terms.id].final_signed_sat()?;
            terms.insert(funded.terms.id.clone(), (&funded.terms, signed));
            after = selection::accumulate(j, after, f)?;
        }
        if j.funding.keys().any(|id| {
            sequence(j, id).is_some_and(|n| n <= self.after.through) && !self.funding.contains(id)
        }) || after != self.after
            || terms.len() != self.funding.len()
            || self.buyer.terms().count() != terms.len()
            || self.buyer.never_installed().any(|t| {
                j.buyer_settlements
                    .get(&t.id)
                    .is_none_or(|s| s.kind != SettlementKind::Expiry || !s.terminal())
                    || j.history.as_ref().is_some_and(|h| h.buyers.contains(&t.id))
            })
            || self
                .buyer
                .terms()
                .any(|(t, signed)| terms.get(&t.id) != Some(&(t, signed)))
        {
            return Err("channel retirement accounting changed".into());
        }
        Ok(())
    }

    fn finish(&self, j: &mut Journal) -> Result<(), String> {
        for id in &self.funding {
            let funded = j
                .funding
                .remove(id)
                .and_then(|f| f.funded)
                .ok_or("retiring funding missing")?;
            j.buyer_settlements.remove(&funded.terms.id);
            j.history.as_mut().unwrap().buyers.remove(&funded.terms.id);
        }
        let h = j.history.as_mut().unwrap().channels.as_mut().unwrap();
        h.totals = self.after.clone();
        h.pending = None;
        Ok(())
    }
}

impl Controller {
    pub(super) fn validate_channel_history(j: &Journal) -> Result<(), String> {
        let history = j.history.as_ref().and_then(|h| h.channels.as_ref());
        let Some(h) = history else {
            return if j.history_version() < 4 {
                Ok(())
            } else {
                Err("missing channel history".into())
            };
        };
        if !matches!(j.history_version(), 4..=6)
            || !h.totals.valid()
            || h.totals.through >= j.next_funding
            || j.funding
                .keys()
                .any(|id| sequence(j, id).is_some_and(|n| n <= h.totals.through))
        {
            return Err("invalid retired channel history".into());
        }
        if let Some(p) = &h.pending {
            if j.history.as_ref().unwrap().routes_pending()
                || j.history
                    .as_ref()
                    .unwrap()
                    .seller
                    .as_ref()
                    .is_some_and(|h| h.pending())
            {
                return Err("conflicting retirement intents".into());
            }
            p.validate(j)?;
            let mut projected = j.clone();
            p.finish(&mut projected)?;
            Self::validate_journal(&projected, &projected.policy, projected.local)?;
        }
        Ok(())
    }

    /// Finish an existing intent before any funding recovery can consult removed
    /// SDK records. The wallet guard survives cancellation of the async caller.
    pub(super) async fn retire_channels(&self, select: bool) -> Result<usize, String> {
        let guard = self.wallet.clone().lock_owned().await;
        let store = self.store.clone();
        let buyer = self.services.buyer.clone();
        let seller = self.services.seller.clone();
        let directory = self.services.wallet_directory.clone();
        let control = self.services.payment_control.clone();
        let runtime = tokio::runtime::Handle::current();
        blocking(move || {
            let _guard = guard;
            let mut store = store.lock().map_err(|_| "controller state poisoned")?;
            let timestamp = now()?;
            let mut prepare = |ids: &[String]| {
                runtime.block_on(control.receiver_retirement_plan(&directory, ids, timestamp))
            };
            let mut retire = |plan: &cashu_service::CashuSpilmanReceiverRetirement| {
                runtime.block_on(control.retire_receiver(&directory, plan))
            };
            let mut count = store.resume_sales(&seller, &mut prepare, &mut retire)?;
            if select {
                store.prepare_channel_retirement(&buyer, timestamp)?;
            }
            count += store.resume_channel_retirement(&buyer, |scope, through| {
                runtime
                    .block_on(cashu_service::retire_cashu_spilman_wallet_channels(
                        &directory, scope, through,
                    ))
                    .map_err(|e| e.to_string())
            })?;
            if select {
                count += store.retire_sales(&seller, timestamp, &mut prepare, &mut retire)?;
            }
            Ok(count)
        })
        .await
    }
}

impl Store {
    fn prepare_channel_retirement(
        &mut self,
        buyer: &BuyerAuthorizer,
        timestamp: u64,
    ) -> Result<(), String> {
        if !self.ready {
            return Err("controller journal suspended".into());
        }
        if self.journal.history.as_ref().is_some_and(History::pending) {
            return Ok(());
        }
        let Some(plan) = selection::select(&self.journal, buyer, timestamp)? else {
            return Ok(());
        };
        let mut j = self.journal.clone();
        j.advance_history_version(4);
        j.history
            .get_or_insert_with(History::default)
            .channels
            .get_or_insert_with(ChannelHistory::default)
            .pending = Some(plan);
        Controller::validate_journal(&j, &j.policy, j.local)?;
        self.journal = j;
        self.persist()
    }

    fn resume_channel_retirement(
        &mut self,
        buyer: &BuyerAuthorizer,
        retire: impl FnOnce(&str, u64) -> Result<CashuSpilmanRetiredHistory, String>,
    ) -> Result<usize, String> {
        if !self.ready {
            return Err("controller journal suspended".into());
        }
        let Some(plan) = self
            .journal
            .history
            .as_ref()
            .and_then(|h| h.channels.as_ref())
            .and_then(|h| h.pending.clone())
        else {
            return Ok(0);
        };
        plan.validate(&self.journal)?;
        buyer
            .retire_channels(&plan.buyer)
            .map_err(|e| e.to_string())?;
        let result = retire(&scope(&self.journal), plan.after.through)?;
        if !plan.after.matches(&result, &self.journal.policy.mint_url) {
            return Err("retired wallet evidence differs from controller".into());
        }
        let mut j = self.journal.clone();
        plan.finish(&mut j)?;
        Controller::validate_journal(&j, &j.policy, j.local)?;
        self.journal = j;
        self.persist()?;
        Ok(plan.funding.len())
    }
}
