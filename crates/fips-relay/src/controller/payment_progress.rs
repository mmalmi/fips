//! Volatile measurement state; it cannot authorize or persist a payment.
use super::*;
use std::collections::BTreeSet;

/// Time spent in the current scheduler phase, measured with a monotonic clock.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct PendingPayment {
    pub stage: PaymentStage,
    pub elapsed_ms: u64,
}

/// A status observation, not an atomic financial snapshot or a delivery receipt.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct PaymentProgress {
    pub evidence_msat: u64,
    pub authorized_sat: u64,
    /// Unknown until this scheduler harvests a successful provider response.
    pub acknowledged_msat: Option<u64>,
    /// Includes completed jobs whose result has not yet been harvested.
    pub in_flight: bool,
    pub pending: Option<PendingPayment>,
    /// Latest failed exchange since this scheduler started, retained after recovery.
    /// Contains no error text, payment material, or durable financial authority.
    pub last_failure_stage: Option<PaymentStage>,
}

#[derive(Default)]
pub(super) struct ScheduleProgress {
    pub(super) acknowledged_msat: Option<u64>,
    pub(super) last_failure_stage: Option<PaymentStage>,
    pending: Option<(PaymentStage, tokio::time::Instant)>,
}

impl ScheduleProgress {
    pub(super) fn started(&mut self) {
        self.pending = Some((PaymentStage::Scheduled, tokio::time::Instant::now()));
    }

    pub(super) fn in_flight(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn stage(&mut self, stage: PaymentStage) {
        if self.in_flight() {
            self.pending = Some((stage, tokio::time::Instant::now()));
        }
    }

    pub(super) fn pending(&self) -> Option<PendingPayment> {
        self.pending.map(|(stage, since)| PendingPayment {
            stage,
            elapsed_ms: u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    pub(super) fn finished(
        &mut self,
        acknowledged_msat: Option<u64>,
        failure: Option<PaymentStage>,
    ) {
        self.acknowledged_msat = acknowledged_msat;
        self.pending = None;
        if failure.is_some() {
            self.last_failure_stage = failure;
        }
    }
}

type ProgressHandle = Arc<Mutex<ScheduleProgress>>;

#[derive(Default)]
pub(super) struct ProgressRegistry {
    channels: Mutex<BTreeMap<String, Weak<Mutex<ScheduleProgress>>>>,
}

impl ProgressRegistry {
    pub(super) fn track(&self, id: &str) -> Option<ProgressHandle> {
        let mut channels = self.channels.lock().ok()?;
        channels.retain(|_, progress| progress.strong_count() > 0);
        if channels.len() >= MAX_CHANNELS || channels.contains_key(id) {
            return None;
        }
        let progress = Arc::new(Mutex::new(ScheduleProgress::default()));
        channels.insert(id.to_owned(), Arc::downgrade(&progress));
        Some(progress)
    }

    fn sample(&self, buyer: &BuyerAuthorizer, id: &str) -> Result<PaymentProgress, String> {
        let progress = self
            .channels
            .lock()
            .map_err(|_| "payment progress poisoned")?
            .get(id)
            .and_then(Weak::upgrade);
        let progress = progress
            .as_ref()
            .map(|progress| progress.lock().map_err(|_| "payment progress poisoned"))
            .transpose()?;
        Ok(PaymentProgress {
            evidence_msat: buyer
                .evidence_msat(id)
                .ok_or("buyer channel evidence missing")?,
            authorized_sat: buyer.authorized_sat(id).ok_or("buyer channel missing")?,
            acknowledged_msat: progress.as_ref().and_then(|p| p.acknowledged_msat),
            in_flight: progress.as_ref().is_some_and(|p| p.in_flight()),
            pending: progress.as_ref().and_then(|p| p.pending()),
            last_failure_stage: progress.as_ref().and_then(|p| p.last_failure_stage),
        })
    }
}

impl Controller {
    /// Read current buyer evidence even when the scheduler has not scanned it.
    /// Missing/dropped schedulers remain unknown, including after restart.
    pub async fn payment_progress(&self) -> Result<BTreeMap<String, PaymentProgress>, String> {
        let channels: BTreeSet<_> = self
            .purchases()
            .await?
            .into_iter()
            .map(|purchase| purchase.channel.id)
            .collect();
        if channels.len() > MAX_CHANNELS {
            return Err("payment progress channel capacity exceeded".into());
        }
        channels
            .into_iter()
            .map(|id| {
                let progress = self.payment_progress.sample(&self.services.buyer, &id)?;
                Ok((id, progress))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
