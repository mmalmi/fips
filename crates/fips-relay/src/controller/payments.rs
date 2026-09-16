//! Schedule and exchange cumulative payments using the existing authorization gate.
use super::cadence::ChannelSchedule;
use super::*;

impl Controller {
    pub async fn flush_payments(&self) -> Result<(), String> {
        let _maintenance = self.maintenance.lock().await;
        self.pay_current_usage().await
    }

    pub(super) async fn pay_current_usage(&self) -> Result<(), String> {
        let mut seen = HashSet::new();
        let mut first_error = None;
        for purchase in self.purchases().await? {
            if !seen.insert(purchase.channel.id.clone()) {
                continue;
            }
            if let Err(error) = self.pay_channel(purchase).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) async fn pay_channel(
        &self,
        purchase: Purchase,
    ) -> Result<crate::ledger::ChannelUsage, String> {
        let peer = self.neighbor(purchase.provider).await?;
        let response = self
            .services
            .payments
            .request(
                peer,
                serde_json::to_vec(&PaymentRequest::Usage {
                    channel_id: purchase.channel.id.clone(),
                })
                .map_err(|e| e.to_string())?,
            )
            .await?;
        let PaymentResponse::Status { channel_id, usage } =
            serde_json::from_slice(&response).map_err(|_| "invalid usage response")?
        else {
            return Err("provider rejected usage".into());
        };
        if channel_id != purchase.channel.id {
            return Err("usage response changed channel".into());
        }
        let prior = self
            .services
            .buyer
            .authorized_sat(&channel_id)
            .ok_or("buyer channel missing")?;
        // A crash can lose a local submission that the provider retained.
        // Pay the supported portion of its cumulative claim; rejecting the
        // entire claim would also prevent payment for every later known send.
        // Controller purchases approve no advance. The strict authorizer still
        // enforces provider identity, evidence, capacity and lifetime limits.
        let supported = usage.submitted_msat.min(
            self.services
                .buyer
                .evidence_msat(&channel_id)
                .ok_or("buyer channel evidence missing")?,
        );
        if usage.paid_msat / 1_000 >= supported.div_ceil(1_000) && usage.paid_msat / 1_000 >= prior
        {
            return Ok(usage);
        }
        let payment = {
            let wallet_guard = self.wallet.clone().lock_owned().await;
            let buyer = self.services.buyer.clone();
            let directory = self.services.wallet_directory.clone();
            let id = channel_id.clone();
            blocking(move || {
                let _wallet = wallet_guard;
                let signer = FileSpilmanPaymentSigner::load(&directory)?;
                buyer
                    .sign_claim(&signer, purchase.provider, &id, supported, now()?)
                    .map_err(|e| e.to_string())
            })
            .await?
        };
        let expected = payment.balance * 1_000;
        let response = self
            .services
            .payments
            .request(
                peer,
                serde_json::to_vec(&PaymentRequest::Update {
                    channel_id: channel_id.clone(),
                    payment,
                })
                .map_err(|e| e.to_string())?,
            )
            .await?;
        match serde_json::from_slice::<PaymentResponse>(&response)
            .map_err(|_| "invalid payment response")?
        {
            PaymentResponse::Status {
                channel_id: id,
                usage,
            } if id == channel_id && usage.paid_msat >= expected => Ok(usage),
            _ => Err("provider did not accept signed balance".into()),
        }
    }
}

impl Controller {
    pub(super) async fn pay_due_usage(
        &self,
        schedules: &mut BTreeMap<String, ChannelSchedule>,
        policy: &PaymentCadence,
    ) -> Result<(), String> {
        let _maintenance = self.maintenance.lock().await;
        let purchases = self.purchases().await?;
        let active: HashSet<_> = purchases.iter().map(|p| p.channel.id.clone()).collect();
        schedules.retain(|id, _| active.contains(id));
        let mut seen = HashSet::new();
        let mut error = None;
        for purchase in purchases {
            let id = purchase.channel.id.clone();
            if !seen.insert(id.clone()) {
                continue;
            }
            let evidence = self
                .services
                .buyer
                .evidence_msat(&id)
                .ok_or("buyer evidence missing")?;
            let authorized = self
                .services
                .buyer
                .authorized_sat(&id)
                .ok_or("buyer channel missing")?;
            let schedule = schedules.entry(id).or_default();
            if !schedule.due(
                tokio::time::Instant::now(),
                evidence,
                authorized,
                purchase.channel.grace_msat,
                policy,
            ) {
                continue;
            }
            match self.pay_channel(purchase).await {
                Ok(usage) => schedule.acknowledge(usage.paid_msat),
                Err(reason) => {
                    schedule.failed(tokio::time::Instant::now());
                    error.get_or_insert(reason);
                }
            }
        }
        error.map_or(Ok(()), Err)
    }
}
