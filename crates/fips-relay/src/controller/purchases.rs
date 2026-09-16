//! Fund adjacent purchases and authorize cumulative outgoing payments.
use super::*;

impl Controller {
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
        if Self::offer_paused(&self.snapshot().await?, &offer.id) {
            return Err("route change paused".into());
        }
        if offer.buyer != *self.services.endpoint.node_addr()
            || offer.mint_url != self.policy.mint_url
            || offer.expires_unix <= now()?
        {
            return Err("unapproved funding destination or mint".into());
        }
        let wallet_guard = self.wallet.clone().lock_owned().await;
        let provider = offer.provider;
        let receiver = offer.receiver_pubkey_hex.clone();
        let capacity = self.policy.channel_capacity_sat.min(offer.capacity_sat);
        let grace = offer
            .grace_msat
            .min(capacity.checked_mul(1_000).ok_or("capacity overflow")?);
        let created = now()?;
        let f = self
            .change(move |j| {
                if let Some(f) = j
                    .funding
                    .values()
                    .find(|f| f.provider == provider && !Self::funding_released(j, f))
                {
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
                let locked = j
                    .funding
                    .values()
                    .filter(|f| {
                        !f.funded.as_ref().is_some_and(|f| {
                            j.buyer_settlements
                                .get(&f.terms.id)
                                .is_some_and(|s| s.refunded)
                        })
                    })
                    .try_fold(0u64, |sum, f| sum.checked_add(f.capacity_sat))
                    .ok_or("capital overflow")?;
                if j.funding.len() >= MAX_CHANNELS
                    || locked
                        .checked_add(capacity)
                        .is_none_or(|total| total > j.policy.max_locked_sat)
                {
                    return Err("working capital exhausted".into());
                }
                let id = format!("{}-{}", j.epoch, j.next_funding);
                j.next_funding = j
                    .next_funding
                    .checked_add(1)
                    .ok_or("funding sequence exhausted")?;
                let f = FundingIntent {
                    id: id.clone(),
                    provider,
                    receiver_pubkey_hex: receiver,
                    capacity_sat: capacity,
                    grace_msat: grace,
                    created_unix: created,
                    expires_unix: created
                        .checked_add(j.policy.channel_lifetime_secs)
                        .ok_or("expiry overflow")?,
                    funded: None,
                };
                j.funding.insert(id, f.clone());
                Ok(f)
            })
            .await?;
        let funded = if let Some(funded) = f.funded.clone() {
            funded
        } else {
            let request = StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                mint_url: self.policy.mint_url.clone(),
                receiver_pubkey_hex: f.receiver_pubkey_hex.clone(),
                capacity_sat: f.capacity_sat,
                expiry_unix: f.expires_unix.checked_add(60).ok_or("expiry overflow")?,
                max_amount_per_output: 0,
                unit: "sat".into(),
                opening_paid_msat: 0,
                keyset_id: None,
                keyset_info_json: None,
                client_request_id: Some(f.id.clone()),
                route_created_at_unix: Some(f.created_unix),
            };
            let directory = self.services.wallet_directory.clone();
            let runtime = tokio::runtime::Handle::current();
            // The upstream wallet's file-store future is intentionally !Send.
            // Drive it entirely on one blocking worker, keeping the native node
            // loop free and retaining the idempotent intent if its reply is lost.
            let (opened, _wallet) = blocking(move || {
                let opened = runtime.block_on(async move {
                    open_streaming_route_cashu_spilman_channel_from_wallet(&directory, request)
                        .await
                        .map_err(|e| e.to_string())
                });
                // A cancelled async caller must not release wallet ownership
                // while this blocking operation is still running.
                Ok((opened, wallet_guard))
            })
            .await?;
            let opened = opened?;
            let funded = Funded {
                terms: ChannelTerms {
                    id: opened.channel.channel_id,
                    buyer: *self.services.endpoint.node_addr(),
                    mint_url: self.policy.mint_url.clone(),
                    expires_unix: f.expires_unix,
                    capacity_sat: f.capacity_sat,
                    grace_msat: f.grace_msat,
                },
                opening: opened.channel.payment,
            };
            let saved = funded.clone();
            let id = f.id.clone();
            self.change(move |j| {
                j.funding
                    .get_mut(&id)
                    .ok_or("funding intent missing")?
                    .funded = Some(saved);
                Ok(())
            })
            .await?;
            funded
        };
        let buyer = self.services.buyer.clone();
        let terms = funded.terms.clone();
        blocking(move || {
            buyer
                .accept_channel(provider, terms, 0)
                .map_err(|e| e.to_string())
        })
        .await?;
        Ok((f.id, funded))
    }

    pub(super) async fn purchase_offer(&self, offer: RouteOffer) -> Result<Purchase, String> {
        if offer.price.msat == 0 {
            return Err("free route needs no payment channel; use open_route".into());
        }
        self.services.quotes.free.accept(&offer)?;
        let peer = self.neighbor(offer.provider).await?;
        self.prepare_changed_route(&offer).await?;
        let existing = self
            .snapshot()
            .await?
            .outgoing
            .values()
            .find(|o| {
                !o.retired
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
                self.change(move |j| Self::reopen_refunded_route(j, &existing, fresh))
                    .await?;
            } else {
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
                if let Some(old) = j.requested.values().find(|old| {
                    old.provider == offer.provider
                        && old.destination.node_addr() == offer.destination.node_addr()
                }) {
                    if old.price != offer.price
                        || old.next_hop != offer.next_hop
                        || old.billing != offer.billing
                        || old.path != offer.path
                        || old.max_units != offer.max_units
                        || old.trial != offer.trial
                    {
                        return Err("pending route needs explicit replacement".into());
                    }
                    return Ok(old.clone());
                }
                if j.requested.len() >= MAX_ROUTES {
                    return Err("requested route capacity".into());
                }
                if j.requested.contains_key(&offer.id) {
                    return Err("conflicting requested offer identity".into());
                }
                j.requested.insert(offer.id.clone(), offer.clone());
                Ok(offer)
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
            .change(move |j| {
                if let Some(old) = j.outgoing.values().find(|o| {
                    !o.retired
                        && o.purchase.provider == saved.purchase.provider
                        && o.purchase.contract.destination == saved.purchase.contract.destination
                }) {
                    if old.offer.price != saved.offer.price
                        || old.offer.billing != saved.offer.billing
                        || old.offer.next_hop != saved.offer.next_hop
                        || old.offer.path != saved.offer.path
                        || old.offer.max_units != saved.offer.max_units
                        || old.offer.trial != saved.offer.trial
                    {
                        return Err("conflicting concurrent route purchase".into());
                    }
                    return Ok(old.clone());
                }
                if j.outgoing.len() >= MAX_ROUTES {
                    return Err("outgoing route capacity".into());
                }
                j.outgoing
                    .insert(saved.purchase.contract.id.clone(), saved.clone());
                Ok(saved)
            })
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

    pub(super) async fn ensure_buyer_purchase(&self, purchase: &Purchase) -> Result<(), String> {
        let buyer = self.services.buyer.clone();
        let purchase = purchase.clone();
        blocking(move || {
            buyer
                .accept_channel(purchase.provider, purchase.channel, 0)
                .map_err(|e| e.to_string())?;
            buyer
                .accept_quote(purchase.contract)
                .map_err(|e| e.to_string())
        })
        .await
    }

    pub(super) async fn opening_payment(
        &self,
        channel: &ChannelTerms,
        provider: NodeAddr,
    ) -> Result<CashuSpilmanPayment, String> {
        let wallet_guard = self.wallet.clone().lock_owned().await;
        let buyer = self.services.buyer.clone();
        let directory = self.services.wallet_directory.clone();
        let id = channel.id.clone();
        blocking(move || {
            let _wallet = wallet_guard;
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
            let bytes = self.services.acceptance.request(peer, body.clone()).await?;
            match serde_json::from_slice::<ControllerResponse>(&bytes)
                .map_err(|_| "invalid acceptance response")?
            {
                ControllerResponse::Accepted { purchase } => {
                    if *purchase != record.purchase {
                        return Err("provider changed accepted terms".into());
                    }
                    let id = record.purchase.contract.id.clone();
                    self.change(move |j| {
                        j.outgoing
                            .get_mut(&id)
                            .ok_or("purchase intent missing")?
                            .accepted = true;
                        Ok(())
                    })
                    .await?;
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
