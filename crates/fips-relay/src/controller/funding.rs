//! Restore original wallet funding independently of routing authorization.
use super::*;
use cashu_service::{
    CashuSpilmanFundingReclaim, StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    StreamingRouteOpenCashuSpilmanChannelFromWalletResult,
    reclaim_abandoned_cashu_spilman_wallet_funding, restore_cashu_spilman_wallet_funding,
};

impl FundingIntent {
    pub(super) fn wallet_request(
        &self,
        policy: &ControllerPolicy,
    ) -> Result<StreamingRouteOpenCashuSpilmanChannelFromWalletRequest, String> {
        Ok(StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
            mint_url: policy.mint_url.clone(),
            receiver_pubkey_hex: self.receiver_pubkey_hex.clone(),
            capacity_sat: self.capacity_sat,
            max_total_amount_sat: Some(self.max_wallet_debit_sat),
            expiry_unix: self.expires_unix.checked_add(60).ok_or("expiry overflow")?,
            max_amount_per_output: 0,
            unit: "sat".into(),
            opening_paid_msat: 0,
            keyset_id: None,
            keyset_info_json: None,
            client_request_id: Some(self.id.clone()),
            route_created_at_unix: Some(self.created_unix),
        })
    }

    pub(super) fn funded_channel(
        &self,
        local: NodeAddr,
        policy: &ControllerPolicy,
        result: StreamingRouteOpenCashuSpilmanChannelFromWalletResult,
    ) -> Result<Funded, String> {
        let opened = result.channel;
        if opened.mint_url != policy.mint_url
            || opened.capacity_sat != self.capacity_sat
            || opened.receiver_pubkey_hex != self.receiver_pubkey_hex
            || opened.unit != "sat"
        {
            return Err("wallet funding differs from approved channel".into());
        }
        let funded = Funded {
            wallet_operation_id: result.wallet_send.operation_id,
            wallet_cost: result
                .wallet_cost
                .ok_or("wallet funding cost unavailable")?,
            terms: ChannelTerms {
                id: opened.channel_id,
                buyer: local,
                mint_url: policy.mint_url.clone(),
                expires_unix: self.expires_unix,
                capacity_sat: self.capacity_sat,
                grace_msat: self.grace_msat,
            },
            opening: opened.payment,
        };
        self.validate_cost(&funded)?;
        Ok(funded)
    }
}

impl Controller {
    /// Restore the original opening, or reclaim its original send after all
    /// routing owners withdraw. Neither path can start replacement funding.
    /// Uncertain records keep their reservation and gain no route permission.
    pub(super) async fn recover_funding(&self) -> Result<(), String> {
        let mut first_error = None;
        for id in self
            .snapshot()
            .await?
            .funding
            .into_values()
            .filter(|intent| intent.funded.is_none() && intent.reclaimed().is_none())
            .map(|intent| intent.id)
        {
            if let Err(error) = self.recover_funding_intent(&id).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn recover_funding_intent(&self, id: &str) -> Result<(), String> {
        let wallet_guard = self.wallet.clone().lock_owned().await;
        // A live purchase may have completed while we waited for wallet ownership.
        let snapshot = self.snapshot().await?;
        let intent = snapshot
            .funding
            .get(id)
            .cloned()
            .ok_or("funding intent missing")?;
        if intent.funded.is_some() || intent.reclaimed().is_some() {
            return Ok(());
        }
        let request = intent.wallet_request(&self.policy)?;
        let directory = self.services.wallet_directory.clone();
        let runtime = tokio::runtime::Handle::current();
        let (opened, wallet_guard) = blocking(move || {
            let opened = runtime
                .block_on(restore_cashu_spilman_wallet_funding(&directory, &request))
                .map_err(|e| e.to_string());
            // Retain ownership until the blocking SDK call finishes, even when
            // the async recovery worker is cancelled.
            Ok((opened, wallet_guard))
        })
        .await?;
        let opened = match opened {
            Ok(opened) => opened,
            // The SDK's reclaim fence deliberately rejects restore-only calls.
            // Its reclaim API still validates the exact request and rejects
            // existing openings; our Pending marker alone proves neither.
            Err(_) if matches!(intent.reclaim, Some(FundingReclaim::Pending)) => None,
            Err(error) => return Err(error),
        };
        if let Some(opened) = opened {
            let funded =
                intent.funded_channel(*self.services.endpoint.node_addr(), &self.policy, opened)?;
            self.change(move |j| Self::record_restored_funding(j, intent, funded))
                .await?;
        } else if Self::abandoned_funding(&snapshot, &intent) {
            // Recheck under the store lock, then retain this fence even if the
            // SDK or mint cannot yet prove the original send's terminal outcome.
            let expected = intent.clone();
            let intent = self
                .change(move |j| Self::prepare_funding_reclaim(j, &expected))
                .await?;
            let request = intent.wallet_request(&self.policy)?;
            let directory = self.services.wallet_directory.clone();
            let runtime = tokio::runtime::Handle::current();
            let (result, _wallet) = blocking(move || {
                let result = runtime
                    .block_on(reclaim_abandoned_cashu_spilman_wallet_funding(
                        &directory, &request,
                    ))
                    .map_err(|e| e.to_string());
                Ok((result, wallet_guard))
            })
            .await?;
            if let CashuSpilmanFundingReclaim::Reclaimed {
                wallet_operation_id,
                wallet_cost,
                recovered_amount_sat,
            } = result?
            {
                let result = ReclaimedFunding {
                    wallet_operation_id,
                    wallet_cost,
                    recovered_amount_sat,
                };
                self.change(move |j| Self::record_funding_reclaim(j, &intent, result))
                    .await?;
            }
        }
        Ok(())
    }

    pub(super) fn record_funding(
        j: &mut Journal,
        mut intent: FundingIntent,
        funded: Funded,
    ) -> Result<(), String> {
        if intent.reclaim.is_some() {
            return Err("ordinary funding cannot replace a reclaim disposition".into());
        }
        intent.validate_cost(&funded)?;
        let current = j
            .funding
            .get_mut(&intent.id)
            .ok_or("funding intent missing")?;
        if current
            .funded
            .as_ref()
            .is_some_and(|saved| saved != &funded)
        {
            return Err("conflicting funded channel".into());
        }
        intent.funded = current.funded.clone();
        if current != &intent {
            return Err("funding intent changed".into());
        }
        current.funded = Some(funded);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::transition_tests::{fixture, reload};
    use super::*;

    #[test]
    fn recording_recovered_funding_is_durable_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let (mut store, _) = fixture(&root.path().join("controller"));
        let funded = store.journal.funding["test-1"].funded.clone().unwrap();
        store
            .change(|j| {
                j.outgoing.clear();
                j.funding.get_mut("test-1").unwrap().funded = None;
                // Expiry of routing authorization cannot prevent recording
                // funding which the wallet already committed.
                j.requested.values_mut().for_each(|o| o.expires_unix = 1);
                Ok(())
            })
            .unwrap();
        let intent = store.journal.funding["test-1"].clone();
        for _ in 0..2 {
            store = reload(store);
            store
                .change(|j| Controller::record_funding(j, intent.clone(), funded.clone()))
                .unwrap();
            assert!(store.journal.funding["test-1"].funded.as_ref() == Some(&funded));
            assert!(store.journal.outgoing.is_empty());
            assert_eq!(store.journal.requested["old-offer"].expires_unix, 1);
            assert_eq!(store.journal.next_funding, 2);
        }
        reload(store);
    }

    #[test]
    fn recovery_cannot_overwrite_funding_or_change_its_durable_intent() {
        let root = tempfile::tempdir().unwrap();
        let (mut store, _) = fixture(&root.path().join("controller"));
        let mut intent = store.journal.funding["test-1"].clone();
        let funded = intent.funded.take().unwrap();
        let before = serde_json::to_value(&store.journal).unwrap();
        for mutation in 0..5 {
            let mut intent = intent.clone();
            let mut funded = funded.clone();
            match mutation {
                0 => funded.terms.id = "other-channel".into(),
                1 => funded.opening.balance = 1,
                2 => intent.receiver_pubkey_hex = format!("02{}", "22".repeat(32)),
                3 => intent.expires_unix += 1,
                _ => intent.id = "missing".into(),
            }
            assert!(
                store
                    .change(|j| Controller::record_funding(j, intent, funded))
                    .is_err()
            );
            assert!(serde_json::to_value(&store.journal).unwrap() == before);
            store = reload(store);
        }
    }
}
