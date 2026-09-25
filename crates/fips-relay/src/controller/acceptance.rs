//! Verify upstream funding and activate agreed onward service.
use super::*;

impl Controller {
    pub async fn handle(&self, peer: PeerIdentity, body: &[u8]) -> ControllerResponse {
        match self.handle_inner(peer, body).await {
            Ok(response) => response,
            Err(error) => {
                *self.last_error.lock().unwrap() = Some(error);
                ControllerResponse::Rejected
            }
        }
    }

    pub(super) async fn handle_inner(
        &self,
        peer: PeerIdentity,
        body: &[u8],
    ) -> Result<ControllerResponse, String> {
        if body.len() > MAX_RECORD_BYTES {
            return Err("oversized acceptance".into());
        }
        let (offer_id, channel, payment, replaces) =
            match serde_json::from_slice(body).map_err(|_| "invalid acceptance")? {
                ControllerRequest::Accept {
                    offer_id,
                    channel,
                    payment,
                    replaces,
                } => (offer_id, channel, payment, replaces),
                ControllerRequest::StopRoute { contract_id } => {
                    return self.handle_stop_route(peer, &contract_id).await;
                }
                ControllerRequest::Seal { channel_id } => {
                    return self.handle_seal(peer, &channel_id).await;
                }
                ControllerRequest::ReleaseSettlement { channel_id } => {
                    return self.handle_release_settlement(peer, &channel_id).await;
                }
                ControllerRequest::Settle {
                    channel_id,
                    payment,
                } => return self.handle_settle(peer, &channel_id, *payment).await,
            };
        if channel.buyer != *peer.node_addr() || channel.mint_url != self.policy.mint_url {
            return Err("wrong upstream payer or mint".into());
        }
        let state = self.snapshot().await?;
        if state.selling_stopped {
            return Err("controller stopped selling".into());
        }
        if state.seller_settlements.contains_key(&channel.id) {
            return Err("channel already sealed for settlement".into());
        }
        let old = state
            .incoming
            .values()
            .find(|i| i.offer.id == offer_id && i.channel.id == channel.id)
            .cloned();
        let (offer, downstream, contract) = if let Some(old) = &old {
            if old.channel != channel || old.phase == Phase::Stopped || old.replaces != replaces {
                return Err("closed or changed upstream agreement".into());
            }
            (
                old.offer.clone(),
                old.downstream.clone(),
                old.contract.clone(),
            )
        } else {
            let offer = self.services.quotes.retained_offer(peer, &offer_id)?;
            let contract = self.services.quotes.bind_offer(peer, &offer_id, &channel)?;
            let downstream = self.services.quotes.downstream_offer(peer, &offer_id)?;
            (offer, downstream, contract)
        };
        let _claim = {
            let mut claims = self.accepting.lock().unwrap();
            if !claims.insert(contract.id.clone()) {
                return Ok(ControllerResponse::Pending);
            }
            AcceptGuard {
                claims: &self.accepting,
                id: contract.id.clone(),
            }
        };
        if contract.expires_unix <= now()?
            || self
                .services
                .endpoint
                .resolve_next_hop(offer.destination, Some(channel.buyer))
                .await
                .map_err(|e| e.to_string())?
                .is_none_or(|p| p.node_addr() != &offer.next_hop)
        {
            return Err("accepted route expired or changed".into());
        }
        if old.as_ref().is_some_and(|i| i.phase == Phase::Active) {
            return Ok(ControllerResponse::Accepted {
                purchase: Box::new(Purchase {
                    provider: *self.services.endpoint.node_addr(),
                    channel,
                    contract,
                }),
            });
        }
        let incoming = Incoming {
            offer,
            downstream,
            channel: channel.clone(),
            contract: contract.clone(),
            verified_paid_msat: 0,
            phase: Phase::Prepared,
            replacement_retired: false,
            replaces,
        };
        self.services.payment_control.prepare_funding().await?;
        let payments = self.services.payment_control.clone();
        let wallet_guard = self.wallet.clone().lock_owned().await;
        // Keep the admission owner through receiver persistence and the journal
        // commit, so another acceptance cannot take the last route slot.
        let (incoming, wallet_guard) = self
            .change(move |j| {
                let incoming = Self::admit_incoming(j, incoming, |terms| {
                    payments
                        .verify_funding(terms, peer, &payment)
                        .map(|c| c.paid_msat)
                })?;
                Ok((incoming, wallet_guard))
            })
            .await?;
        drop(wallet_guard);
        self.activate(incoming).await?;
        Ok(ControllerResponse::Accepted {
            purchase: Box::new(Purchase {
                provider: *self.services.endpoint.node_addr(),
                channel,
                contract,
            }),
        })
    }

    fn admit_incoming(
        j: &mut Journal,
        mut saved: Incoming,
        verify: impl FnOnce(&ChannelTerms) -> Result<u64, String>,
    ) -> Result<Incoming, String> {
        Self::check_incoming(j, &saved)?;
        saved.verified_paid_msat = verify(&saved.channel)?;
        if !j.incoming.contains_key(&saved.contract.id) {
            if let Some(previous) = &saved.replaces {
                j.incoming
                    .get_mut(previous)
                    .ok_or("replacement route missing")?
                    .phase = Phase::Stopped;
            }
            j.incoming.insert(saved.contract.id.clone(), saved.clone());
        }
        Ok(saved)
    }

    fn check_incoming(j: &Journal, saved: &Incoming) -> Result<(), String> {
        if saved
            .downstream
            .as_ref()
            .is_some_and(|d| Self::provider_reclaiming(j, d.provider))
        {
            return Err("onward funding is being reclaimed".into());
        }
        if j.selling_stopped || Self::retired_offer(j, &saved.offer) {
            return Err("controller stopped selling".into());
        }
        if j.seller_settlements.contains_key(&saved.channel.id) {
            return Err("channel already sealed for settlement".into());
        }
        if let Some(old) = j.incoming.get(&saved.contract.id) {
            if old.channel != saved.channel
                || old.contract != saved.contract
                || old.replaces != saved.replaces
                || old.phase == Phase::Stopped
            {
                return Err("upstream binding conflict".into());
            }
            return Ok(());
        }
        if j.incoming.len() >= MAX_ROUTES
            || j.incoming.values().any(|i| {
                i.phase != Phase::Stopped
                    && saved.replaces.as_ref() != Some(&i.contract.id)
                    && i.channel.buyer == saved.channel.buyer
                    && i.contract.destination == saved.contract.destination
            })
        {
            return Err("upstream route capacity or conflict".into());
        }
        if let Some(previous) = &saved.replaces {
            let old = j
                .incoming
                .get(previous)
                .ok_or("replacement route missing")?;
            if previous == &saved.contract.id
                || old.channel.buyer != saved.channel.buyer
                || old.contract.destination != saved.contract.destination
            {
                return Err("replacement route ownership conflict".into());
            }
        }
        Ok(())
    }

    pub(super) async fn activate(&self, incoming: Incoming) -> Result<(), String> {
        let _paid_route = self.services.quotes.free.paid_guard(&incoming.offer)?;
        self.check_prepared_route(&incoming).await?;
        let seller = self.services.seller.clone();
        let terms = incoming.channel.clone();
        let paid = incoming.verified_paid_msat;
        let replaces = incoming.replaces.clone();
        blocking(move || {
            if let Some(previous) = replaces
                && seller.usage(&previous).is_some()
            {
                seller
                    .close_contract(&previous)
                    .map_err(|e| e.to_string())?;
            }
            if let Some(old) = seller.channel_terms(&terms.id) {
                if old != terms {
                    return Err("retained channel terms differ".into());
                }
                let previous = seller
                    .channel_usage(&terms.id)
                    .ok_or("channel disappeared")?
                    .paid_msat;
                seller
                    .apply_verified_balance(&terms.id, paid.max(previous))
                    .map_err(|e| e.to_string())
            } else {
                seller
                    .open_channel_verified(terms, paid)
                    .map_err(|e| e.to_string())
            }
        })
        .await?;
        if let Some(downstream) = incoming.downstream.clone() {
            self.check_prepared_route(&incoming).await?;
            if downstream.price.msat == 0 {
                self.services.quotes.free.accept(&downstream)?;
            } else {
                self.purchase_offer(downstream).await?;
            }
        }
        // Onward service is accepted before any upstream data receives credit.
        self.check_prepared_route(&incoming).await?;
        let seller = self.services.seller.clone();
        let store = self.store.clone();
        blocking(move || {
            store
                .lock()
                .map_err(|_| "controller state poisoned")?
                .install_incoming_contract(&seller, &incoming, now()?)
        })
        .await
    }

    pub(super) async fn check_prepared_route(&self, incoming: &Incoming) -> Result<(), String> {
        if incoming.contract.expires_unix <= now()?
            || self
                .snapshot()
                .await?
                .incoming
                .get(&incoming.contract.id)
                .is_none_or(|i| i.phase != Phase::Prepared)
        {
            return Err("prepared route expired or stopped".into());
        }
        if self
            .services
            .endpoint
            .resolve_next_hop(incoming.offer.destination, Some(incoming.channel.buyer))
            .await
            .map_err(|e| e.to_string())?
            .is_none_or(|p| p.node_addr() != &incoming.contract.next_hop)
        {
            return Err("prepared native route changed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
