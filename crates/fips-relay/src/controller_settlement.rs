//! Recoverable channel closure. No bearer proofs are returned over control RPC.

use super::*;
use crate::{buyer::BuyerError, ledger::ChannelUsage};
use cashu_service::{import_payment_proofs, restore_streaming_route_cashu_spilman_refund};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReport {
    pub channel_id: String,
    pub paid_sat: u64,
    pub refunded_sat: u64,
    pub fee_sat: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct BuyerSettlement {
    #[serde(with = "node_addr")]
    provider: NodeAddr,
    channel: ChannelTerms,
    usage: Option<ChannelUsage>,
    payment: Option<CashuSpilmanPayment>,
    report: Option<SettlementReport>,
    pub(super) refunded: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct SellerSettlement {
    channel: ChannelTerms,
    usage: Option<ChannelUsage>,
    payment: Option<CashuSpilmanPayment>,
    report: Option<SettlementReport>,
}

fn valid_usage(channel: &ChannelTerms, usage: ChannelUsage) -> bool {
    channel.capacity_sat.checked_mul(1_000).is_some_and(|cap| {
        usage.paid_msat <= cap
            && usage.reserved_msat <= cap
            && usage.submitted_msat <= usage.reserved_msat
            && usage.lost_msat <= usage.reserved_msat - usage.submitted_msat
    })
}

fn valid_report(channel: &ChannelTerms, report: &SettlementReport, paid: u64) -> bool {
    report.channel_id == channel.id
        && report.paid_sat == paid
        && report
            .paid_sat
            .checked_add(report.refunded_sat)
            .and_then(|n| n.checked_add(report.fee_sat))
            == Some(channel.capacity_sat)
}

impl Controller {
    pub(super) fn validate_settlements(j: &Journal) -> Result<(), String> {
        if j.buyer_settlements.len() > MAX_CHANNELS || j.seller_settlements.len() > MAX_CHANNELS {
            return Err("settlement history capacity".into());
        }
        for (id, s) in &j.buyer_settlements {
            if id != &s.channel.id
                || !j.funding.values().any(|f| {
                    f.provider == s.provider
                        && f.funded.as_ref().is_some_and(|f| f.terms == s.channel)
                })
                || s.usage.is_some_and(|u| !valid_usage(&s.channel, u))
                || s.payment.as_ref().is_some_and(|p| {
                    s.usage.is_none() || p.channel_id != *id || p.balance > s.channel.capacity_sat
                })
                || s.report.as_ref().is_some_and(|r| {
                    s.payment
                        .as_ref()
                        .is_none_or(|p| !valid_report(&s.channel, r, p.balance))
                })
                || (s.refunded && s.report.is_none())
            {
                return Err("invalid buyer settlement".into());
            }
        }
        for (id, s) in &j.seller_settlements {
            if id != &s.channel.id
                || !j.incoming.values().any(|i| i.channel == s.channel)
                || j.incoming
                    .values()
                    .any(|i| i.channel.id == *id && i.phase != Phase::Stopped)
                || s.usage.is_some_and(|u| !valid_usage(&s.channel, u))
                || s.payment.as_ref().is_some_and(|p| {
                    s.usage.is_none() || p.channel_id != *id || p.balance > s.channel.capacity_sat
                })
                || s.report.as_ref().is_some_and(|r| {
                    s.payment
                        .as_ref()
                        .is_none_or(|p| !valid_report(&s.channel, r, p.balance))
                })
            {
                return Err("invalid seller settlement".into());
            }
        }
        Ok(())
    }

    fn settlement_claim(&self, id: &str) -> Option<AcceptGuard<'_>> {
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
                    },
                );
            }
            Ok(())
        })
        .await?;
        let state = self.snapshot().await?;
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
                let total = closed
                    .receiver_sum
                    .checked_add(closed.sender_sum)
                    .ok_or("close value overflow")?;
                let report = SettlementReport {
                    channel_id: closed.channel_id,
                    paid_sat: closed.receiver_sum,
                    refunded_sat: closed.sender_sum,
                    fee_sat: sale
                        .channel
                        .capacity_sat
                        .checked_sub(total)
                        .ok_or("close exceeds funding")?,
                };
                if closed.mint_url != sale.channel.mint_url
                    || closed.unit != "sat"
                    || closed.closed_amount != payment.balance
                    || !valid_report(&sale.channel, &report, payment.balance)
                {
                    return Err("mint close does not match final agreement".into());
                }
                if report.paid_sat != 0 {
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

    async fn settlement_request(
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
        let _maintenance = self.maintenance.lock().await;
        self.settle_purchase(id).await
    }

    async fn settle_purchase(&self, id: &str) -> Result<SettlementReport, String> {
        let channel_id = id.to_string();
        let mut purchase = self
            .change(move |j| {
                if let Some(old) = j.buyer_settlements.get(&channel_id) {
                    return Ok(old.clone());
                }
                if j.buyer_settlements.len() >= MAX_CHANNELS {
                    return Err("buyer settlement history full".into());
                }
                let bought = j
                    .outgoing
                    .values()
                    .find(|o| o.accepted && o.purchase.channel.id == channel_id)
                    .ok_or("recover purchase acceptance before settlement")?;
                let settlement = BuyerSettlement {
                    provider: bought.purchase.provider,
                    channel: bought.purchase.channel.clone(),
                    usage: None,
                    payment: None,
                    report: None,
                    refunded: false,
                };
                j.buyer_settlements.insert(channel_id, settlement.clone());
                Ok(settlement)
            })
            .await?;
        if purchase.refunded {
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
                match buyer.sign_claim(
                    &signer,
                    saved.provider,
                    &saved.channel.id,
                    saved.usage.ok_or("final usage missing")?.submitted_msat,
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
        blocking(move || {
            let _wallet = wallet_guard;
            runtime.block_on(async move {
                let refund = restore_streaming_route_cashu_spilman_refund(&directory, &terms.id)
                    .await
                    .map_err(|e| e.to_string())?;
                if !refund.complete
                    || refund.channel_id != terms.id
                    || refund.mint_url != terms.mint_url
                    || refund.unit != "sat"
                    || (refund.recovered_amount_sat != 0
                        && refund.recovered_amount_sat != expected_refund)
                {
                    return Err("mint refund incomplete or mismatched".into());
                }
                Ok(())
            })
        })
        .await?;
        purchase.refunded = true;
        self.change(move |j| {
            j.buyer_settlements
                .insert(purchase.channel.id.clone(), purchase);
            Ok(())
        })
        .await?;
        Ok(report)
    }

    pub async fn settle_all(&self) -> Result<Vec<SettlementReport>, String> {
        self.pause_renewals().await?;
        let snapshot = self.snapshot().await?;
        let mut ids: HashSet<_> = snapshot
            .outgoing
            .values()
            .filter(|o| o.accepted)
            .map(|o| o.purchase.channel.id.clone())
            .collect();
        ids.extend(snapshot.buyer_settlements.keys().cloned());
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
        let snapshot = self.snapshot().await?;
        snapshot
            .funding
            .values()
            .filter(|f| {
                !f.funded.as_ref().is_some_and(|f| {
                    snapshot
                        .buyer_settlements
                        .get(&f.terms.id)
                        .is_some_and(|s| s.refunded)
                })
            })
            .try_fold(0u64, |sum, f| sum.checked_add(f.capacity_sat))
            .ok_or("capital overflow".into())
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
            if !purchase.refunded
                && let Err(error) = self.settle_channel(&id).await
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
