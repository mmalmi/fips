//! Fund adjacent purchases and authorize cumulative outgoing payments.
use super::*;
use cashu_service::CashuWalletService;
use std::num::NonZeroU32;

/// CDK HTTP pacing for wallet-backed channel opening, per destination origin.
/// Configure only within the mint operator's limits; this grants no spending authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingRequestBudget {
    pub burst: NonZeroU32,
    pub requests_per_minute: NonZeroU32,
}

impl Controller {
    /// Set local channel-funding HTTP pacing. Omission retains CDK's defaults.
    /// This runtime setting neither changes saved financial terms nor configures
    /// separate Spilman settlement/refund clients. Reapply it after loading.
    pub fn with_funding_request_budget(mut self, budget: Option<FundingRequestBudget>) -> Self {
        self.funding_request_budget = budget;
        self
    }

    pub async fn open_route(&self, destination: PeerIdentity) -> Result<RouteAccess, String> {
        self.authorize_source_selection(destination).await?;
        let offer = self.services.quotes.request_route(destination).await?;
        if offer.price.msat == 0 {
            self.activate_source_route(&offer).await?;
            return Ok(RouteAccess::Free(offer));
        }
        self.purchase_offer(offer).await.map(RouteAccess::Paid)
    }
    /// Explicit application authorization for this destination under local price
    /// and lifetime spending caps. Merely receiving data never calls this method.
    pub async fn buy_route(&self, destination: PeerIdentity) -> Result<Purchase, String> {
        self.authorize_source_selection(destination).await?;
        let offer = self.services.quotes.request_route(destination).await?;
        self.purchase_offer(offer).await
    }

    pub(super) async fn fund(&self, offer: &RouteOffer) -> Result<(String, Funded), String> {
        let funding = self.fund_inner(offer);
        tokio::pin!(funding);
        loop {
            tokio::select! {
                result = &mut funding => return result,
                _ = tokio::time::sleep(refresh::REFRESH_RECHECK) => {
                    // Wallet recovery may be waiting on this same operation.
                    // Persist withdrawal before ending the routing wait. The
                    // blocking wallet worker retains ownership until it ends;
                    // recovery must still reconcile its original funding intent.
                    self.withdraw_disconnected_purchases().await?;
                    if Self::offer_paused(&self.snapshot().await?, &offer.id) {
                        return Err("route change paused".into());
                    }
                }
            }
        }
    }

    async fn fund_inner(&self, offer: &RouteOffer) -> Result<(String, Funded), String> {
        let snapshot = self.snapshot().await?;
        if Self::offer_paused(&snapshot, &offer.id) {
            return Err("route change paused".into());
        }
        if offer.buyer != *self.services.endpoint.node_addr()
            || offer.mint_url != self.policy.mint_url
            || offer.expires_unix <= now()?
        {
            return Err("unapproved funding destination or mint".into());
        }
        let provider = offer.provider;
        // Existing funded accounts need only local accounting. New funding
        // still obtains wallet ownership before reserving capital or an ID.
        let reusable = snapshot.funding.values().any(|f| {
            f.provider == provider && f.funded.is_some() && !Self::funding_released(&snapshot, f)
        });
        drop(snapshot);
        let wallet_guard = if reusable {
            None
        } else {
            Some(self.wallet.clone().lock_owned().await)
        };
        let may_fund = wallet_guard.is_some();
        let receiver = offer.receiver_pubkey_hex.clone();
        let capacity = self.policy.channel_capacity_sat.min(offer.capacity_sat);
        let grace = offer
            .grace_msat
            .min(capacity.checked_mul(1_000).ok_or("capacity overflow")?);
        let created = now()?;
        let saved_offer = offer.clone();
        let f = self
            .change(move |j| {
                Self::check_purchase(j, &saved_offer, None)?;
                if let Some(f) = j
                    .funding
                    .values()
                    .find(|f| f.provider == provider && !Self::funding_released(j, f))
                {
                    if f.funded.is_none() && !may_fund {
                        return Err("funding changed before wallet ownership".into());
                    }
                    if f.receiver_pubkey_hex != receiver
                        || f.capacity_sat > capacity
                        || f.grace_msat > grace
                        || f.expires_unix <= created
                    {
                        return Err(
                            "existing channel needs explicit renewal or reconciliation".into()
                        );
                    }
                    return Ok(f.clone());
                }
                if !may_fund {
                    return Err("funding changed before wallet ownership".into());
                }
                if j.funding.len() >= MAX_CHANNELS {
                    return Err("funding history capacity".into());
                }
                let id = cashu_service::CashuRequestSequence::new(
                    channel_history::scope(j),
                    j.next_funding,
                )
                .map_err(|e| e.to_string())?
                .request_id();
                j.advance_history_version(4);
                j.version |= journal::FUNDING_DEADLINES_VERSION;
                j.history
                    .get_or_insert_with(History::default)
                    .channels
                    .get_or_insert_with(channel_history::ChannelHistory::default);
                j.next_funding = j
                    .next_funding
                    .checked_add(1)
                    .ok_or("funding sequence exhausted")?;
                let f = FundingIntent {
                    id: id.clone(),
                    provider,
                    receiver_pubkey_hex: receiver,
                    capacity_sat: capacity,
                    max_wallet_debit_sat: capacity
                        .checked_add(j.policy.max_funding_overhead_sat)
                        .ok_or("funding cost overflow")?,
                    grace_msat: grace,
                    created_unix: created,
                    expires_unix: created
                        .checked_add(j.policy.service_lifetime_secs())
                        .ok_or("expiry overflow")?,
                    refund_after_unix: Some(
                        created
                            .checked_add(j.policy.channel_lifetime_secs)
                            .ok_or("expiry overflow")?,
                    ),
                    funded: None,
                    reclaim: None,
                };
                j.funding.insert(id, f.clone());
                Ok(f)
            })
            .await?;
        let funded = if let Some(funded) = f.funded.clone() {
            funded
        } else {
            let wallet_guard = wallet_guard.ok_or("unfunded channel needs wallet ownership")?;
            let request = f.wallet_request(&self.policy)?;
            let directory = self.services.wallet_directory.clone();
            let runtime = tokio::runtime::Handle::current();
            let budget = self.funding_request_budget;
            // The upstream wallet's file-store future is intentionally !Send.
            // Drive it entirely on one blocking worker, keeping the native node
            // loop free and retaining the idempotent intent if its reply is lost.
            let (opened, _wallet) = blocking(move || {
                let opened = runtime.block_on(async move {
                    let wallet = CashuWalletService::open_existing_file_backed(&directory)
                        .await
                        .map_err(|e| e.to_string())?;
                    if let Some(budget) = budget {
                        wallet
                            .set_request_budget(
                                budget.burst.get(),
                                budget.requests_per_minute.get(),
                            )
                            .map_err(|e| e.to_string())?;
                    }
                    wallet
                        .open_streaming_route_cashu_spilman_channel(request)
                        .await
                        .map_err(|e| e.to_string())
                });
                // A cancelled async caller must not release wallet ownership
                // while this blocking operation is still running.
                Ok((opened, wallet_guard))
            })
            .await?;
            let opened = opened?;
            let funded =
                f.funded_channel(*self.services.endpoint.node_addr(), &self.policy, opened)?;
            let saved = funded.clone();
            let intent = f.clone();
            self.change(move |j| Self::record_funding(j, intent, saved))
                .await?;
            funded
        };
        let buyer = self.services.buyer.clone();
        let saved_offer = offer.clone();
        let funding_id = f.id.clone();
        let recorded = funded.clone();
        let store = self.store.clone();
        blocking(move || {
            let store = store.lock().map_err(|_| "controller state poisoned")?;
            store.ensure_ready()?;
            Self::install_funded_channel(
                &store.journal,
                &buyer,
                &saved_offer,
                &funding_id,
                &recorded,
            )
        })
        .await?;
        Ok((f.id, funded))
    }

    pub(super) fn install_funded_channel(
        j: &Journal,
        buyer: &BuyerAuthorizer,
        offer: &RouteOffer,
        funding_id: &str,
        funded: &Funded,
    ) -> Result<(), String> {
        if j.requested.get(&offer.id) != Some(offer)
            || j.funding
                .get(funding_id)
                .is_none_or(|f| f.provider != offer.provider || f.funded.as_ref() != Some(funded))
        {
            return Err("funded purchase changed".into());
        }
        Self::check_purchase(j, offer, Some(&funded.terms.id))?;
        buyer
            .accept_channel(offer.provider, funded.terms.clone(), 0)
            .map_err(|e| e.to_string())
    }

    pub(super) async fn purchase_offer(&self, offer: RouteOffer) -> Result<Purchase, String> {
        self.purchase(offer, None).await
    }

    pub(super) async fn purchase_watched_offer(
        &self,
        offer: RouteOffer,
        watch: WatchedRoute,
    ) -> Result<Purchase, String> {
        self.purchase(offer, Some(watch)).await
    }

    async fn purchase(
        &self,
        offer: RouteOffer,
        watch: Option<WatchedRoute>,
    ) -> Result<Purchase, String> {
        if offer.price.msat == 0 {
            return Err("free route needs no payment channel; use open_route".into());
        }
        self.services.quotes.free.accept(&offer)?;
        let peer = self.neighbor(offer.provider).await?;
        self.prepare_changed_route(&offer, watch.as_ref()).await?;
        let snapshot = self.snapshot().await?;
        let existing = snapshot
            .outgoing
            .values()
            .find(|o| {
                Self::routing_eligible(&snapshot, o)
                    && o.purchase.provider == offer.provider
                    && o.purchase.contract.destination == *offer.destination.node_addr()
            })
            .cloned();
        if let Some(existing) = existing {
            if self
                .snapshot()
                .await?
                .buyer_settlements
                .contains_key(&existing.purchase.channel.id)
            {
                let fresh = offer.clone();
                let expected = watch.clone();
                self.change(move |j| {
                    Self::reopen_refunded_route(j, &existing, fresh.clone())?;
                    Self::reserve_watched_offer(j, expected.as_ref(), &fresh)
                })
                .await?;
            } else {
                Self::check_purchase(
                    &self.snapshot().await?,
                    &existing.offer,
                    Some(&existing.purchase.channel.id),
                )?;
                if existing.purchase.contract.expires_unix <= now()?
                    || existing.offer.price != offer.price
                    || existing.offer.billing != offer.billing
                    || existing.offer.next_hop != offer.next_hop
                    || existing.offer.path != offer.path
                    || existing.offer.max_units != offer.max_units
                    || existing.offer.trial != offer.trial
                {
                    return Err("existing route needs explicit replacement".into());
                }
                if let Some(expected) = watch {
                    let saved = existing.clone();
                    self.change(move |j| {
                        let current = j
                            .outgoing
                            .get(&saved.purchase.contract.id)
                            .ok_or("purchase intent missing")?;
                        if current.offer != saved.offer || current.purchase != saved.purchase {
                            return Err("purchase intent changed".into());
                        }
                        Self::check_purchase(j, &saved.offer, Some(&saved.purchase.channel.id))?;
                        Self::reserve_watched_offer(j, Some(&expected), &saved.offer)
                    })
                    .await?;
                }
                if existing.accepted {
                    self.activate_source_route(&existing.offer).await?;
                    return Ok(existing.purchase);
                }
                self.ensure_buyer_purchase(&existing.purchase).await?;
                return self.send_accept(peer, existing).await;
            }
        }
        let offer = self
            .change(move |j| {
                let reserved = Self::reserve_purchase(j, offer.clone())?;
                Self::reserve_watched_offer(j, watch.as_ref(), &reserved)?;
                Ok(reserved)
            })
            .await?;
        let (funding_id, funded) = self.fund(&offer).await?;
        let contract = contract_from_offer(&offer, &funded.terms)?;
        let record = Outgoing {
            offer,
            funding_id,
            purchase: Purchase {
                provider: *peer.node_addr(),
                channel: funded.terms,
                contract,
            },
            accepted: false,
            retired: false,
        };
        let saved = record.clone();
        let record = self
            .change(move |j| Self::record_purchase(j, saved))
            .await?;
        self.ensure_buyer_purchase(&record.purchase).await?;
        self.send_accept(peer, record).await
    }

    /// A fresh purchase can replace a fully refunded, explicitly closed route.
    /// Keep the old account evidence, and persist the new authorization in the
    /// same mutation that retires its predecessor, before touching the wallet.
    pub(super) fn reopen_refunded_route(
        j: &mut Journal,
        previous: &Outgoing,
        fresh: RouteOffer,
    ) -> Result<(), String> {
        let old = j
            .outgoing
            .get(&previous.purchase.contract.id)
            .ok_or("closed purchase missing")?;
        if old.purchase != previous.purchase || old.offer != previous.offer {
            return Err("closed purchase changed".into());
        }
        if fresh.id == old.offer.id
            || fresh.expires_unix <= now()?
            || !renewal::same_service(&old.offer, &fresh)
        {
            return Err("repurchase requires a fresh offer for the same service".into());
        }
        if old.retired {
            // Another purchase already advanced this route. The common
            // requested-offer path below reconciles the winning authorization.
            return Ok(());
        }
        if !old.accepted
            || !j
                .buyer_settlements
                .get(&old.purchase.channel.id)
                .is_some_and(|s| s.refunded)
        {
            return Err("previous channel refund incomplete".into());
        }
        if j.renewals
            .get(&old.purchase.channel.id)
            .is_some_and(|r| !r.is_completed())
        {
            return Err("channel replacement already in progress".into());
        }
        if j.requested.contains_key(&fresh.id)
            || j.requested.values().any(|o| {
                o.id != old.offer.id
                    && o.provider == fresh.provider
                    && o.destination.node_addr() == fresh.destination.node_addr()
            })
        {
            return Err("repurchase authorization conflict".into());
        }
        let old_offer = old.offer.id.clone();
        j.outgoing
            .get_mut(&previous.purchase.contract.id)
            .unwrap()
            .retired = true;
        j.requested.remove(&old_offer);
        j.requested.insert(fresh.id.clone(), fresh);
        Ok(())
    }

    pub(super) fn install_buyer_purchase(
        j: &Journal,
        buyer: &BuyerAuthorizer,
        purchase: &Purchase,
    ) -> Result<(), String> {
        let saved = j
            .outgoing
            .get(&purchase.contract.id)
            .ok_or("purchase intent missing")?;
        if saved.purchase != *purchase {
            return Err("purchase intent changed".into());
        }
        Self::check_purchase(j, &saved.offer, Some(&purchase.channel.id))?;
        buyer
            .accept_channel(purchase.provider, purchase.channel.clone(), 0)
            .map_err(|e| e.to_string())?;
        buyer
            .accept_quote(purchase.contract.clone())
            .map_err(|e| e.to_string())
    }

    pub(super) async fn ensure_buyer_purchase(&self, purchase: &Purchase) -> Result<(), String> {
        let buyer = self.services.buyer.clone();
        let purchase = purchase.clone();
        let store = self.store.clone();
        blocking(move || {
            let store = store.lock().map_err(|_| "controller state poisoned")?;
            store.ensure_ready()?;
            Self::install_buyer_purchase(&store.journal, &buyer, &purchase)
        })
        .await
    }

    pub(super) async fn opening_payment(
        &self,
        channel: &ChannelTerms,
        provider: NodeAddr,
    ) -> Result<CashuSpilmanPayment, String> {
        let buyer = self.services.buyer.clone();
        let directory = self.services.wallet_directory.clone();
        let id = channel.id.clone();
        blocking(move || {
            // The signer serializes its channel store and enforces its closing
            // fence; reproducing existing credit never opens the cash wallet.
            let signer = FileSpilmanPaymentSigner::load(&directory)?;
            buyer
                .reproduce_payment(&signer, provider, &id, now()?)
                .map_err(|e| e.to_string())
        })
        .await
    }

    pub(super) async fn send_accept(
        &self,
        peer: PeerIdentity,
        record: Outgoing,
    ) -> Result<Purchase, String> {
        if Self::offer_paused(&self.snapshot().await?, &record.offer.id) {
            return Err("route change paused".into());
        }
        let payment = self
            .opening_payment(&record.purchase.channel, record.purchase.provider)
            .await?;
        let body = serde_json::to_vec(&ControllerRequest::Accept {
            offer_id: record.offer.id.clone(),
            channel: record.purchase.channel.clone(),
            payment: Box::new(payment),
            replaces: self.replaces_for(&record.offer).await?,
        })
        .map_err(|e| e.to_string())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err("acceptance deadline; durable request retained".into());
            }
            Self::check_purchase(
                &self.snapshot().await?,
                &record.offer,
                Some(&record.purchase.channel.id),
            )?;
            let bytes = self.services.acceptance.request(peer, body.clone()).await?;
            match serde_json::from_slice::<ControllerResponse>(&bytes)
                .map_err(|_| "invalid acceptance response")?
            {
                ControllerResponse::Accepted { purchase } => {
                    if *purchase != record.purchase {
                        return Err("provider changed accepted terms".into());
                    }
                    let id = record.purchase.contract.id.clone();
                    if !self
                        .change(move |j| Self::finish_acceptance(j, &id))
                        .await?
                    {
                        return Err("purchase closed before acceptance completed".into());
                    }
                    self.activate_source_route(&record.offer).await?;
                    return Ok(*purchase);
                }
                ControllerResponse::Pending => tokio::time::sleep(Duration::from_millis(250)).await,
                ControllerResponse::Rejected => {
                    return Err("provider rejected purchase; intent retained".into());
                }
                _ => return Err("unexpected acceptance response".into()),
            }
        }
    }
}
