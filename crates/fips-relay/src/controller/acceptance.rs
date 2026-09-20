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
        self.services.payment_control.prepare_funding().await?;
        let payments = self.services.payment_control.clone();
        let terms = channel.clone();
        let credit = blocking(move || payments.verify_funding(&terms, peer, &payment)).await?;
        let incoming = Incoming {
            offer,
            downstream,
            channel: channel.clone(),
            contract: contract.clone(),
            verified_paid_msat: credit.paid_msat,
            phase: Phase::Prepared,
            replacement_retired: false,
            replaces,
        };
        let saved = incoming.clone();
        self.change(move |j| {
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
                    .get_mut(previous)
                    .ok_or("replacement route missing")?;
                if previous == &saved.contract.id
                    || old.channel.buyer != saved.channel.buyer
                    || old.contract.destination != saved.contract.destination
                {
                    return Err("replacement route ownership conflict".into());
                }
                old.phase = Phase::Stopped;
            }
            j.incoming.insert(saved.contract.id.clone(), saved);
            Ok(())
        })
        .await?;
        self.activate(incoming).await?;
        Ok(ControllerResponse::Accepted {
            purchase: Box::new(Purchase {
                provider: *self.services.endpoint.node_addr(),
                channel,
                contract,
            }),
        })
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
        let contract = incoming.contract.clone();
        blocking(move || seller.add_contract(contract).map_err(|e| e.to_string())).await?;
        let id = incoming.contract.id;
        self.change(move |j| {
            let entry = j.incoming.get_mut(&id).ok_or("acceptance intent missing")?;
            if entry.phase == Phase::Stopped {
                return Err("acceptance was stopped".into());
            }
            entry.phase = Phase::Active;
            Ok(())
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
