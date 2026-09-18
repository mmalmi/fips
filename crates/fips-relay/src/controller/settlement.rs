//! Recoverable channel closure. No bearer proofs are returned over control RPC.

use super::*;
use crate::{buyer::BuyerError, ledger::ChannelUsage};
use cashu_service::{import_payment_proofs, restore_streaming_route_cashu_spilman_refund};

mod state;
pub use state::SettlementReport;
pub(super) use state::{BuyerSettlement, SellerSettlement, SettlementKind};
use state::{valid_report, valid_usage};

impl Controller {
    pub(super) fn settlement_claim(&self, id: &str) -> Option<AcceptGuard<'_>> {
        let id = format!("settle/{id}");
        if !self.accepting.lock().ok()?.insert(id.clone()) {
            return None;
        }
        Some(AcceptGuard {
            claims: &self.accepting,
            id,
        })
    }

    pub(super) async fn handle_seal(
        &self,
        peer: PeerIdentity,
        id: &str,
    ) -> Result<ControllerResponse, String> {
        let state = self.snapshot().await?;
        let channel = state
            .incoming
            .values()
            .find(|i| i.channel.id == id)
            .map(|i| i.channel.clone())
            .or_else(|| {
                state
                    .history
                    .as_ref()
                    .and_then(|h| h.sellers.get(id))
                    .cloned()
            })
            .ok_or("unknown sale channel")?;
        if peer.node_addr() != &channel.buyer {
            return Err("wrong settlement buyer".into());
        }
        let Some(_claim) = self.settlement_claim(id) else {
            return Ok(ControllerResponse::Pending);
        };
        let saved = channel.clone();
        self.change(move |j| {
            for incoming in j.incoming.values_mut().filter(|i| i.channel.id == saved.id) {
                incoming.phase = Phase::Stopped;
            }
            if !j.seller_settlements.contains_key(&saved.id) {
                if j.seller_settlements.len() >= MAX_CHANNELS {
                    return Err("seller settlement history full".into());
                }
                j.seller_settlements.insert(
                    saved.id.clone(),
                    SellerSettlement {
                        channel: saved,
                        usage: None,
                        payment: None,
                        report: None,
                        released: false,
                    },
                );
            }
            Ok(())
        })
        .await?;
        let state = self.snapshot().await?;
        for incoming in state.incoming.values().filter(|i| i.channel.id == id) {
            self.services.quotes.stop_reusing(&incoming.offer.id)?;
        }
        if let Some(usage) = state.seller_settlements[id].usage {
            return Ok(ControllerResponse::Sealed {
                channel_id: id.into(),
                usage,
            });
        }
        let seller = self.services.seller.clone();
        let channel_id = id.to_string();
        let usage =
            blocking(move || seller.seal_channel(&channel_id).map_err(|e| e.to_string())).await?;
        let channel_id = id.to_string();
        self.change(move |j| {
            j.seller_settlements
                .get_mut(&channel_id)
                .ok_or("seal intent missing")?
                .usage = Some(usage);
            Ok(())
        })
        .await?;
        Ok(ControllerResponse::Sealed {
            channel_id: id.into(),
            usage,
        })
    }

    pub(super) async fn handle_settle(
        &self,
        peer: PeerIdentity,
        id: &str,
        payment: CashuSpilmanPayment,
    ) -> Result<ControllerResponse, String> {
        let state = self.snapshot().await?;
        let sale = state
            .seller_settlements
            .get(id)
            .ok_or("seal sale before settlement")?;
        if peer.node_addr() != &sale.channel.buyer
            || sale.usage.is_none()
            || payment.channel_id != id
        {
            return Err("wrong settlement buyer or channel".into());
        }
        let Some(_claim) = self.settlement_claim(id) else {
            return Ok(ControllerResponse::Pending);
        };
        if let Some(old) = &sale.payment {
            if old.balance != payment.balance {
                return Err("final settlement balance already fixed".into());
            }
        } else {
            let control = self.services.payment_control.clone();
            let seller = self.services.seller.clone();
            let terms = sale.channel.clone();
            let signed = payment.clone();
            blocking(move || {
                let credit = control.verify_funding(&terms, peer, &signed)?;
                seller
                    .apply_verified_balance(&terms.id, credit.paid_msat)
                    .map_err(|e| e.to_string())
            })
            .await?;
            let channel_id = id.to_string();
            self.change(move |j| {
                j.seller_settlements
                    .get_mut(&channel_id)
                    .ok_or("sale seal missing")?
                    .payment = Some(payment);
                Ok(())
            })
            .await?;
        }
        Ok(ControllerResponse::Settled {
            report: self.finish_sale(id).await?,
        })
    }

    // Caller owns settlement_claim. Mint close and proof import are idempotent;
    // the upstream receiver and wallet retain recovery state before our report.
    async fn finish_sale(&self, id: &str) -> Result<SettlementReport, String> {
        let sale = self
            .snapshot()
            .await?
            .seller_settlements
            .get(id)
            .cloned()
            .ok_or("sale missing")?;
        if let Some(report) = sale.report {
            return Ok(report);
        }
        let payment = sale.payment.ok_or("final signed payment missing")?;
        let control = self.services.payment_control.clone();
        let directory = self.services.wallet_directory.clone();
        let wallet_guard = self.wallet.clone().lock_owned().await;
        let runtime = tokio::runtime::Handle::current();
        let report = blocking(move || {
            let _wallet = wallet_guard;
            runtime.block_on(async move {
                let closed = control.close_at_mint(&sale.channel.id).await?;
                let report = SettlementReport::from_close(&closed)?;
                if closed.mint_url != sale.channel.mint_url
                    || closed.unit != "sat"
                    || closed.closed_amount != payment.balance
                    || !valid_report(&sale.channel, &report, payment.balance)
                {
                    return Err("mint close does not match final agreement".into());
                }
                if closed.receiver_sum != 0 {
                    import_payment_proofs(
                        &directory,
                        &sale.channel.mint_url,
                        "sat",
                        &closed.receiver_proofs_json,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                }
                Ok(report)
            })
        })
        .await?;
        let saved = report.clone();
        self.change(move |j| {
            let sale = j
                .seller_settlements
                .get_mut(&saved.channel_id)
                .ok_or("sale missing")?;
            sale.report = Some(saved);
            Ok(())
        })
        .await?;
        Ok(report)
    }

    pub(super) async fn settlement_request(
        &self,
        peer: PeerIdentity,
        request: ControllerRequest,
    ) -> Result<ControllerResponse, String> {
        let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err("settlement pending; durable intent retained".into());
            }
            let response = self.services.acceptance.request(peer, body.clone()).await?;
            let response =
                serde_json::from_slice(&response).map_err(|_| "invalid settlement response")?;
            match response {
                ControllerResponse::Pending => tokio::time::sleep(Duration::from_millis(250)).await,
                ControllerResponse::Rejected => return Err("neighbor rejected settlement".into()),
                response => return Ok(response),
            }
        }
    }

    /// Freeze an accepted purchase, deliver its final authorized balance,
    /// redeem the seller's payout and recover the buyer's unused funding.
    pub async fn settle_channel(&self, id: &str) -> Result<SettlementReport, String> {
        let _channel = self.channel_work(id)?.lock_owned().await;
        self.settle_purchase(id, false).await
    }

    pub(super) async fn settle_purchase(
        &self,
        id: &str,
        recovery_only: bool,
    ) -> Result<SettlementReport, String> {
        let channel_id = id.to_string();
        let mut purchase = self
            .change(move |j| {
                if let Some(old) = j.buyer_settlements.get(&channel_id) {
                    if old.kind == SettlementKind::Expiry {
                        return Err("unilateral recovery has no provider settlement report".into());
                    }
                    return Ok(old.clone());
                }
                if recovery_only {
                    Self::check_recovery_settlement(j, &channel_id)?;
                }
                if j.buyer_settlements.len() >= MAX_CHANNELS {
                    return Err("buyer settlement history full".into());
                }
                let (provider, channel) = Self::settlement_terms(j, &channel_id)?;
                let settlement = BuyerSettlement {
                    kind: SettlementKind::Cooperative,
                    provider,
                    channel,
                    usage: None,
                    payment: None,
                    report: None,
                    released: false,
                    refunded: false,
                    wallet_refund_sat: None,
                };
                j.buyer_settlements.insert(channel_id, settlement.clone());
                Ok(settlement)
            })
            .await?;
        if purchase.refunded {
            self.release_settlement(id).await?;
            return purchase.report.ok_or("settlement report missing".into());
        }
        if purchase.usage.is_none() {
            let peer = self.neighbor(purchase.provider).await?;
            let response = self
                .settlement_request(
                    peer,
                    ControllerRequest::Seal {
                        channel_id: id.into(),
                    },
                )
                .await?;
            let ControllerResponse::Sealed { channel_id, usage } = response else {
                return Err("provider did not seal channel".into());
            };
            if channel_id != id || !valid_usage(&purchase.channel, usage) {
                return Err("invalid final usage".into());
            }
            purchase.usage = Some(usage);
            let saved = purchase.clone();
            self.change(move |j| {
                j.buyer_settlements.insert(saved.channel.id.clone(), saved);
                Ok(())
            })
            .await?;
        }
        if purchase.payment.is_none() {
            let wallet_guard = self.wallet.clone().lock_owned().await;
            let directory = self.services.wallet_directory.clone();
            let buyer = self.services.buyer.clone();
            let saved = purchase.clone();
            let payment = blocking(move || {
                let _wallet = wallet_guard;
                buyer
                    .close_channel(&saved.channel.id)
                    .map_err(|e| e.to_string())?;
                let signer = FileSpilmanPaymentSigner::load(&directory)?;
                let supported = saved
                    .usage
                    .ok_or("final usage missing")?
                    .submitted_msat
                    .min(
                        buyer
                            .evidence_msat(&saved.channel.id)
                            .ok_or("final buyer evidence missing")?,
                    );
                match buyer.sign_claim(
                    &signer,
                    saved.provider,
                    &saved.channel.id,
                    supported,
                    now()?,
                ) {
                    Ok(_)
                    | Err(BuyerError::Budget | BuyerError::Expired | BuyerError::UnearnedClaim) => {
                        // Reproduce the highest durably authorized balance with
                        // funding attached. A budget/evidence/expiry rejection
                        // cannot add an obligation just to close the channel.
                        buyer
                            .reproduce_payment(&signer, saved.provider, &saved.channel.id, now()?)
                            .map_err(|e| e.to_string())
                    }
                    Err(error) => Err(error.to_string()),
                }
            })
            .await?;
            purchase.payment = Some(payment);
            let saved = purchase.clone();
            self.change(move |j| {
                j.buyer_settlements.insert(saved.channel.id.clone(), saved);
                Ok(())
            })
            .await?;
        }
        if purchase.report.is_none() {
            let peer = self.neighbor(purchase.provider).await?;
            let payment = purchase.payment.clone().ok_or("final payment missing")?;
            let response = self
                .settlement_request(
                    peer,
                    ControllerRequest::Settle {
                        channel_id: id.into(),
                        payment: Box::new(payment.clone()),
                    },
                )
                .await?;
            let ControllerResponse::Settled { report } = response else {
                return Err("provider did not settle channel".into());
            };
            if !valid_report(&purchase.channel, &report, payment.balance) {
                return Err("invalid provider settlement report".into());
            }
            purchase.report = Some(report);
            let saved = purchase.clone();
            self.change(move |j| {
                j.buyer_settlements.insert(saved.channel.id.clone(), saved);
                Ok(())
            })
            .await?;
        }
        let report = purchase.report.clone().ok_or("settlement report missing")?;
        let wallet_guard = self.wallet.clone().lock_owned().await;
        let directory = self.services.wallet_directory.clone();
        let terms = purchase.channel.clone();
        let expected_refund = report.refunded_sat;
        let runtime = tokio::runtime::Handle::current();
        let verified_refund = blocking(move || {
            let _wallet = wallet_guard;
            runtime.block_on(async move {
                let refund = restore_streaming_route_cashu_spilman_refund(&directory, &terms.id)
                    .await
                    .map_err(|e| e.to_string())?;
                if !refund.complete
                    || refund.channel_id != terms.id
                    || refund.mint_url != terms.mint_url
                    || refund.unit != "sat"
                    || refund.total_recovered_amount_sat != Some(expected_refund)
                {
                    return Err("mint refund incomplete or mismatched".into());
                }
                Ok(expected_refund)
            })
        })
        .await?;
        purchase.refunded = true;
        purchase.wallet_refund_sat = Some(verified_refund);
        self.change(move |j| {
            let channel = purchase.channel.id.clone();
            j.buyer_settlements
                .insert(purchase.channel.id.clone(), purchase);
            Self::retire_refunded_purchases(j, &channel)?;
            Ok(())
        })
        .await?;
        self.release_settlement(id).await?;
        Ok(report)
    }

    pub(super) fn settlement_channels(j: &Journal) -> HashSet<String> {
        let mut ids: HashSet<_> = j
            .outgoing
            .values()
            .filter(|o| o.accepted || j.recovery_only.contains(&o.offer.id))
            .map(|o| o.purchase.channel.id.clone())
            .collect();
        ids.extend(
            j.buyer_settlements
                .iter()
                .filter(|(_, s)| s.kind == SettlementKind::Cooperative)
                .map(|(id, _)| id.clone()),
        );
        if let Some(history) = &j.history {
            ids.extend(history.buyers.iter().cloned());
        }
        ids
    }

    pub async fn settle_all(&self) -> Result<Vec<SettlementReport>, String> {
        self.pause_route_refresh().await?;
        self.pause_renewals().await?;
        {
            let _work = self.route_work.lock().await;
            self.change(|j| {
                for change in j.route_changes.values_mut() {
                    change.paused = true;
                }
                Ok(())
            })
            .await?;
        }
        let snapshot = self.snapshot().await?;
        let ids = Self::settlement_channels(&snapshot);
        let mut reports = Vec::new();
        let mut first_error = None;
        for id in ids {
            match self.settle_channel(&id).await {
                Ok(report) => reports.push(report),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(reports), Err)
    }

    pub async fn locked_capital_sat(&self) -> Result<u64, String> {
        Ok(self.funding_budget().await?.locked_sat)
    }

    pub(super) async fn resume_settlements(&self) -> Result<(), String> {
        let snapshot = self.snapshot().await?;
        let mut first_error = None;
        for (id, sale) in snapshot.seller_settlements {
            if sale.payment.is_some() && sale.report.is_none() {
                let Some(_claim) = self.settlement_claim(&id) else {
                    continue;
                };
                if let Err(error) = self.finish_sale(&id).await {
                    first_error.get_or_insert(error);
                }
            }
        }
        for (id, purchase) in snapshot.buyer_settlements {
            if purchase.kind == SettlementKind::Cooperative
                && (!purchase.refunded || !purchase.released)
                && (purchase.report.is_some() || self.neighbor(purchase.provider).await.is_ok())
                && let Err(error) = self.settle_channel(&id).await
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
