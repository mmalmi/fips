//! Schedule and exchange cumulative payments using the existing authorization gate.
use super::cadence::ChannelSchedule;
use super::*;
use crate::ledger::ChannelUsage;
use crate::measurements::{Operation, measure};

type PaymentResult = Result<Option<ChannelUsage>, String>;

impl Controller {
    /// Serialize financial transitions for this channel without holding other
    /// neighbors behind a network await. Weak entries do not retain history.
    pub(super) fn channel_work(&self, id: &str) -> Result<Arc<AsyncMutex<()>>, String> {
        let mut channels = self
            .channel_work
            .lock()
            .map_err(|_| "channel work poisoned")?;
        channels.retain(|_, work| work.strong_count() > 0);
        if let Some(work) = channels.get(id).and_then(Weak::upgrade) {
            return Ok(work);
        }
        if channels.len() >= MAX_CHANNELS {
            return Err("channel work capacity exhausted".into());
        }
        let work = Arc::new(AsyncMutex::new(()));
        channels.insert(id.into(), Arc::downgrade(&work));
        Ok(work)
    }

    pub async fn flush_payments(&self) -> Result<(), String> {
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

    pub(super) async fn pay_channel(&self, purchase: Purchase) -> PaymentResult {
        let _channel = self.channel_work(&purchase.channel.id)?.lock_owned().await;
        // A task can have waited behind settlement or a route replacement.
        // Never sign from an active-purchase snapshot taken before that wait.
        if !self
            .purchases()
            .await?
            .iter()
            .any(|p| p.channel == purchase.channel)
        {
            return Ok(None);
        }
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
            return Ok(Some(usage));
        }
        let payment = {
            let wallet_guard = self.wallet.clone().lock_owned().await;
            let buyer = self.services.buyer.clone();
            let directory = self.services.wallet_directory.clone();
            let id = channel_id.clone();
            blocking(move || {
                let _wallet = wallet_guard;
                measure(Operation::PaymentSign, || {
                    let signer = FileSpilmanPaymentSigner::load(&directory)?;
                    buyer
                        .sign_claim(&signer, purchase.provider, &id, supported, now()?)
                        .map_err(|e| e.to_string())
                })
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
            } if id == channel_id && usage.paid_msat >= expected => Ok(Some(usage)),
            _ => Err("provider did not accept signed balance".into()),
        }
    }
}

#[derive(Default)]
struct ChannelPayment {
    schedule: ChannelSchedule,
    job: Option<JoinHandle<PaymentResult>>,
    #[cfg(feature = "measurements")]
    progress: Option<Arc<Mutex<super::payment_progress::ScheduleProgress>>>,
}

impl ChannelPayment {
    async fn finish(&mut self) -> Result<(), String> {
        let Some(job) = self.job.as_mut() else {
            return Ok(());
        };
        let result = job.await.map_err(|e| e.to_string()).and_then(|r| r);
        self.job = None;
        #[cfg(feature = "measurements")]
        if let Some(progress) = &self.progress {
            progress.lock().unwrap().finished(
                result
                    .as_ref()
                    .ok()
                    .and_then(|usage| usage.as_ref())
                    .map(|usage| usage.paid_msat),
            );
        }
        match result {
            Ok(Some(usage)) => {
                self.schedule.acknowledge(usage.paid_msat);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => {
                self.schedule.failed(tokio::time::Instant::now());
                Err(error)
            }
        }
    }
}

#[cfg(test)]
#[path = "payment_workers_tests.rs"]
mod tests;

impl Drop for ChannelPayment {
    fn drop(&mut self) {
        if let Some(job) = &self.job {
            job.abort();
        }
        #[cfg(feature = "measurements")]
        if let Some(progress) = &self.progress {
            progress.lock().unwrap().finished(None);
        }
    }
}

/// At most one exchange per saved channel, including retired in-flight work.
/// A slow network request never holds up scanning or completing another channel.
#[derive(Default)]
pub(super) struct PaymentWorkers {
    channels: BTreeMap<String, ChannelPayment>,
}

impl PaymentWorkers {
    pub(super) async fn tick(
        &mut self,
        controller: &Arc<Controller>,
        policy: &PaymentCadence,
    ) -> Result<(), String> {
        let purchases = controller.purchases().await?;
        let active: HashSet<_> = purchases.iter().map(|p| p.channel.id.clone()).collect();
        let mut error = None;
        for channel in self.channels.values_mut() {
            if channel.job.as_ref().is_some_and(JoinHandle::is_finished)
                && let Err(reason) = channel.finish().await
            {
                error.get_or_insert(reason);
            }
        }
        self.channels
            .retain(|id, work| active.contains(id) || work.job.is_some());
        let mut seen = HashSet::new();
        for purchase in purchases {
            let id = purchase.channel.id.clone();
            if !seen.insert(id.clone()) {
                continue;
            }
            if !self.channels.contains_key(&id) && self.channels.len() >= MAX_CHANNELS {
                error.get_or_insert_with(|| "payment worker capacity exhausted".into());
                continue;
            }
            let work = self.channels.entry(id.clone()).or_default();
            #[cfg(feature = "measurements")]
            if work.progress.is_none() {
                work.progress = controller.payment_progress.track(&id);
            }
            if work.job.is_some() {
                continue;
            }
            let (Some(evidence), Some(authorized)) = (
                controller.services.buyer.evidence_msat(&id),
                controller.services.buyer.authorized_sat(&id),
            ) else {
                error.get_or_insert_with(|| "buyer channel or evidence missing".into());
                continue;
            };
            if !work.schedule.due(
                tokio::time::Instant::now(),
                evidence,
                authorized,
                purchase.channel.grace_msat,
                policy,
            ) {
                continue;
            }
            let payer = controller.clone();
            #[cfg(feature = "measurements")]
            if let Some(progress) = &work.progress {
                progress.lock().unwrap().started();
            }
            work.job = Some(tokio::spawn(
                async move { payer.pay_channel(purchase).await },
            ));
        }
        error.map_or(Ok(()), Err)
    }

    pub(super) async fn drain(&mut self) -> Result<(), String> {
        let mut error = None;
        for channel in self.channels.values_mut() {
            if let Err(reason) = channel.finish().await {
                error.get_or_insert(reason);
            }
        }
        error.map_or(Ok(()), Err)
    }
}
