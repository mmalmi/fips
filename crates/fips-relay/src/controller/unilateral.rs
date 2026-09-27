//! Recover original channel funds independently after service and wallet expiry.
use super::*;
use cashu_service::{
    refund_expired_cashu_spilman_channel, restore_streaming_route_cashu_spilman_refund,
};

impl Controller {
    fn used_funding(j: &Journal, id: &str) -> bool {
        j.outgoing.values().any(|o| o.purchase.channel.id == id)
            || j.history.as_ref().is_some_and(|h| h.buyers.contains(id))
    }

    fn expired_funding(
        j: &Journal,
        intent: &FundingIntent,
        timestamp: u64,
    ) -> Result<Funded, String> {
        let funded = intent.funded.as_ref().ok_or("funding remains uncertain")?;
        if j.funding.get(&intent.id) != Some(intent)
            || intent
                .expires_unix
                .checked_add(60)
                .is_none_or(|e| e >= timestamp)
            || funded.opening.balance != 0
            || (!Self::used_funding(j, &funded.terms.id)
                && !Self::funding_exclusively_withdrawn(j, intent))
        {
            return Err("funded channel is unexpired or its withdrawal is unresolved".into());
        }
        Ok(funded.clone())
    }

    pub(super) fn validate_expiry_settlement(
        j: &Journal,
        id: &str,
        s: &BuyerSettlement,
    ) -> Result<(), String> {
        let funded = j
            .funding
            .values()
            .find(|f| {
                f.provider == s.provider && f.funded.as_ref().is_some_and(|v| v.terms == s.channel)
            })
            .and_then(|f| f.funded.as_ref())
            .ok_or("expiry funding missing")?;
        if j.version & journal::EXPIRY_RECOVERY_VERSION == 0
            || id != s.channel.id
            || funded.opening.balance != 0
            || s.usage
                .is_some_and(|u| !settlement::valid_usage(&s.channel, u))
            || s.payment
                .as_ref()
                .is_some_and(|p| p.channel_id != id || p.balance > s.channel.capacity_sat)
            || s.report.as_ref().is_some_and(|r| {
                s.payment.as_ref().is_none_or(|p| {
                    !settlement::valid_report(&s.channel, r, p.balance)
                        || r.value_after_stage1_sat > funded.wallet_cost.token_amount_sat
                })
            })
            || (s.released && (!s.refunded || s.report.is_none()))
            || s.refunded != s.wallet_refund_sat.is_some()
            || s.wallet_refund_sat
                .is_some_and(|n| n > funded.wallet_cost.token_amount_sat)
            || (s.refunded && Self::used_funding(j, id) && s.payment.is_none())
            || s.wallet_refund_sat
                .is_some_and(|amount| s.report.as_ref().is_some_and(|r| r.refunded_sat != amount))
        {
            return Err("invalid unilateral expiry evidence".into());
        }
        Ok(())
    }

    pub(super) async fn recover_expired_sales(&self) -> Result<(), String> {
        let snapshot = self.snapshot().await?;
        let timestamp = now()?;
        let mut channels = snapshot
            .history
            .as_ref()
            .map(|h| h.sellers.clone())
            .unwrap_or_default();
        for incoming in snapshot.incoming.values() {
            channels.insert(incoming.channel.id.clone(), incoming.channel.clone());
        }
        let mut first_error = None;
        for (id, channel) in channels {
            if timestamp <= channel.expires_unix
                || snapshot
                    .seller_settlements
                    .get(&id)
                    .is_some_and(|s| s.report.is_some())
                || self.services.seller.channel_terms(&id).as_ref() != Some(&channel)
            {
                continue;
            }
            let Some(_claim) = self.settlement_claim(&id) else {
                continue;
            };
            let result = async {
                self.seal_sale(channel).await?;
                self.finish_sale(&id).await
            }
            .await;
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) async fn recover_expired_funding(&self) -> Result<(), String> {
        let snapshot = self.snapshot().await?;
        let timestamp = now()?;
        let mut first_error = None;
        for intent in snapshot.funding.values().filter(|f| f.funded.is_some()) {
            let funded = intent.funded.as_ref().unwrap();
            if snapshot
                .buyer_settlements
                .get(&funded.terms.id)
                .is_some_and(BuyerSettlement::terminal)
                || Self::expiry_funding(&snapshot, intent, timestamp).is_err()
            {
                continue;
            }
            let _channel = self.channel_work(&funded.terms.id)?.lock_owned().await;
            if let Err(error) = self.refund_expired_funding(intent).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn refund_expired_funding(&self, intent: &FundingIntent) -> Result<(), String> {
        let store = self.store.clone();
        let buyer = self.services.buyer.clone();
        let expected = intent.clone();
        let channel = blocking(move || {
            store
                .lock()
                .map_err(|_| "controller state poisoned")?
                .prepare_expiry_refund(&buyer, &expected, now()?)
        })
        .await?;
        let saved = self.snapshot().await?.buyer_settlements[&channel.id].clone();
        if saved.refunded {
            return Ok(());
        }
        if saved.payment.is_none()
            && self
                .services
                .buyer
                .expiry_authorization(intent.provider, &channel)
                .map_err(|e| e.to_string())?
                .is_some()
        {
            let buyer = self.services.buyer.clone();
            let directory = self.services.wallet_directory.clone();
            let provider = intent.provider;
            let id = channel.id.clone();
            let payment = blocking(move || {
                let signer = FileSpilmanPaymentSigner::load(&directory)?;
                buyer
                    .reproduce_payment(&signer, provider, &id, now()?)
                    .map_err(|e| e.to_string())
            })
            .await?;
            self.change(move |j| {
                let current = j
                    .buyer_settlements
                    .get_mut(&payment.channel_id)
                    .ok_or("expiry intent missing")?;
                if current.kind != SettlementKind::Expiry || current.payment.is_some() {
                    return Err("expiry authorization changed".into());
                }
                current.payment = Some(payment);
                Ok(())
            })
            .await?;
        }
        let wallet_guard = self.wallet.clone().lock_owned().await;
        let directory = self.services.wallet_directory.clone();
        let terms = channel.clone();
        let runtime = tokio::runtime::Handle::current();
        let result = blocking(move || {
            let _wallet = wallet_guard;
            runtime
                .block_on(async {
                    if saved.report.is_some() {
                        restore_streaming_route_cashu_spilman_refund(&directory, &terms.id).await
                    } else {
                        refund_expired_cashu_spilman_channel(&directory, &terms.id).await
                    }
                })
                .map_err(|e| e.to_string())
        })
        .await?;
        if !result.complete
            || result.channel_id != channel.id
            || result.mint_url != channel.mint_url
            || result.unit != "sat"
        {
            return Err("unilateral mint refund incomplete or mismatched".into());
        }
        let amount = result
            .total_recovered_amount_sat
            .ok_or("unilateral refund total missing")?;
        let expected = intent.clone();
        self.change(move |j| Self::finish_expiry_refund(j, &expected, &channel, amount))
            .await
    }

    fn retained_expiry_funding(j: &Journal, intent: &FundingIntent) -> Result<Funded, String> {
        if j.funding.get(&intent.id) != Some(intent) {
            return Err("expiry funding changed".into());
        }
        let funded = intent.funded.as_ref().ok_or("funding remains uncertain")?;
        let saved = j
            .buyer_settlements
            .get(&funded.terms.id)
            .ok_or("expiry intent missing")?;
        if saved.kind != SettlementKind::Expiry
            || saved.provider != intent.provider
            || saved.channel != funded.terms
        {
            return Err("expiry intent changed".into());
        }
        Self::validate_expiry_settlement(j, &funded.terms.id, saved)?;
        Ok(funded.clone())
    }

    fn expiry_funding(
        j: &Journal,
        intent: &FundingIntent,
        timestamp: u64,
    ) -> Result<Funded, String> {
        let funded = intent.funded.as_ref().ok_or("funding remains uncertain")?;
        if j.buyer_settlements
            .get(&funded.terms.id)
            .is_some_and(|s| s.kind == SettlementKind::Expiry)
        {
            // The durable expiry intent already fenced funding and local channel
            // installation. Later unrelated selections cannot erase its result.
            Self::retained_expiry_funding(j, intent)
        } else {
            Self::expired_funding(j, intent, timestamp)
        }
    }

    pub(super) fn finish_expiry_refund(
        j: &mut Journal,
        intent: &FundingIntent,
        channel: &ChannelTerms,
        amount: u64,
    ) -> Result<(), String> {
        let funded = Self::retained_expiry_funding(j, intent)?;
        if channel != &funded.terms || amount > funded.wallet_cost.token_amount_sat {
            return Err("unilateral refund exceeds or mismatches original funding".into());
        }
        let settlement = j
            .buyer_settlements
            .get_mut(&channel.id)
            .ok_or("expiry intent missing")?;
        if settlement
            .wallet_refund_sat
            .is_some_and(|old| old != amount)
        {
            return Err("expiry outcome changed".into());
        }
        settlement.wallet_refund_sat = Some(amount);
        settlement.refunded = true;
        Self::retire_refunded_purchases(j, &channel.id)
    }
}

impl Store {
    pub(super) fn prepare_expiry_refund(
        &mut self,
        buyer: &BuyerAuthorizer,
        expected: &FundingIntent,
        timestamp: u64,
    ) -> Result<ChannelTerms, String> {
        self.ensure_ready()?;
        let funded = Controller::expiry_funding(&self.journal, expected, timestamp)?;
        if Controller::used_funding(&self.journal, &funded.terms.id) {
            let authorized = buyer
                .expiry_authorization(expected.provider, &funded.terms)
                .map_err(|e| e.to_string())?
                .ok_or("used buyer channel missing")?;
            if self
                .journal
                .buyer_settlements
                .get(&funded.terms.id)
                .and_then(|s| s.payment.as_ref())
                .is_some_and(|p| p.balance != authorized)
            {
                return Err("expiry payment differs from retained authorization".into());
            }
        } else {
            buyer
                .unused_channel(expected.provider, &funded.terms)
                .map_err(|e| e.to_string())?;
        }
        let channel = funded.terms;
        if self
            .journal
            .buyer_settlements
            .get(&channel.id)
            .is_some_and(|s| s.kind == SettlementKind::Cooperative)
        {
            self.change(|j| {
                j.version |= journal::EXPIRY_RECOVERY_VERSION;
                j.buyer_settlements.get_mut(&channel.id).unwrap().kind = SettlementKind::Expiry;
                Ok(())
            })?;
        }
        if !self.journal.buyer_settlements.contains_key(&channel.id) {
            self.change(|j| {
                if j.buyer_settlements.len() >= MAX_CHANNELS {
                    return Err("buyer settlement history full".into());
                }
                j.version |= journal::EXPIRY_RECOVERY_VERSION;
                j.buyer_settlements.insert(
                    channel.id.clone(),
                    BuyerSettlement {
                        kind: SettlementKind::Expiry,
                        provider: expected.provider,
                        channel: channel.clone(),
                        usage: None,
                        payment: None,
                        report: None,
                        released: false,
                        refunded: false,
                        wallet_refund_sat: None,
                    },
                );
                Ok(())
            })?;
        }
        if buyer.authorized_sat(&channel.id).is_some()
            && let Err(error) = buyer.close_channel(&channel.id)
        {
            self.ready = false;
            return Err(error.to_string());
        }
        Ok(channel)
    }
}
