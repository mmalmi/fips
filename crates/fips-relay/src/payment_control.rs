//! Payment control for locally approved neighbor agreements.
//!
//! Approval/price discovery is deliberately separate. A wire request cannot
//! choose its price, payer, free allowance, destination, or next provider.

use crate::{
    control_transport::IncomingRequest,
    durable::DurableRelay,
    ledger::{ChannelTerms, ChannelUsage, Contract},
    measurements::{Operation, measure},
    payment::process_payment,
};
use cashu_service::{CashuSpilmanPayment, CashuSpilmanPaymentReceiver};
use fips_core::PeerIdentity;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
mod keysets;
mod retirement;

#[derive(Debug, Clone)]
pub struct ApprovedAgreement {
    pub channel: ChannelTerms,
    pub quotes: Vec<Contract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaymentRequest {
    Open {
        channel_id: String,
        payment: CashuSpilmanPayment,
    },
    Update {
        channel_id: String,
        payment: CashuSpilmanPayment,
    },
    Usage {
        channel_id: String,
    },
    StopForwarding {
        channel_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaymentResponse {
    Status {
        channel_id: String,
        usage: ChannelUsage,
    },
    Rejected,
}

pub struct PaymentControl<R> {
    receiver: R,
    ledger: Arc<DurableRelay>,
    approved: BTreeMap<String, ApprovedAgreement>,
    keysets: Option<keysets::KeysetRefresh>,
}

impl PaymentControl<cashu_service::FileSpilmanPaymentReceiver> {
    pub fn with_keyset_refresh(
        mut self,
        directory: std::path::PathBuf,
        config: cashu_service::FileSpilmanPaymentReceiverConfig,
    ) -> Self {
        self.keysets = Some(keysets::KeysetRefresh::new(directory, config));
        self
    }

    pub(crate) async fn prepare_funding(&self) -> Result<(), String> {
        if let Some(refresh) = &self.keysets {
            refresh.prepare(self.receiver.receiver_pubkey_hex()).await?;
        }
        Ok(())
    }
    pub(crate) async fn close_at_mint(
        &self,
        channel_id: &str,
    ) -> Result<cashu_service::CashuSpilmanReceiverCloseResult, String> {
        self.receiver.close_cashu_spilman_channel(channel_id).await
    }
}

impl<R: CashuSpilmanPaymentReceiver<String>> PaymentControl<R> {
    /// Verify and durably retain authenticated funding before a trusted runtime
    /// commits its own working capital. This alone does not activate forwarding.
    pub(crate) fn verify_funding(
        &self,
        channel: &ChannelTerms,
        peer: PeerIdentity,
        payment: &CashuSpilmanPayment,
    ) -> Result<crate::payment::VerifiedCredit, String> {
        process_payment(&self.receiver, channel, peer, payment, true)
    }
    /// Static approvals support the Open request. The automatic controller can
    /// instead install verified bindings in the durable ledger; subsequent
    /// usage, payment and stop requests use those same immutable terms.
    pub fn new(
        receiver: R,
        ledger: Arc<DurableRelay>,
        agreements: Vec<ApprovedAgreement>,
    ) -> Result<Self, String> {
        if agreements.len() > 16 {
            return Err("too many neighbor agreements".into());
        }
        let mut approved = BTreeMap::new();
        let mut quote_count = 0usize;
        for agreement in agreements {
            if agreement.quotes.is_empty()
                || agreement.quotes.len() > 32
                || agreement
                    .quotes
                    .iter()
                    .any(|q| q.channel_id != agreement.channel.id)
                || approved.contains_key(&agreement.channel.id)
            {
                return Err("invalid or duplicate approved agreement".into());
            }
            quote_count += agreement.quotes.len();
            if quote_count > 32
                || ledger
                    .channel_terms(&agreement.channel.id)
                    .is_some_and(|old| old != agreement.channel)
                || agreement
                    .quotes
                    .iter()
                    .any(|q| ledger.contract(&q.id).is_some_and(|old| &old != q))
            {
                return Err(
                    "agreement conflicts with retained accounting or exceeds capacity".into(),
                );
            }
            // Reuse accounting validation before accepting any funding. This
            // private scratch ledger is never attached to a native endpoint.
            let check = crate::ledger::RelayLedger::new(crate::ledger::Limits::default());
            check
                .open_channel_verified(agreement.channel.clone(), 0)
                .map_err(|e| e.to_string())?;
            for quote in &agreement.quotes {
                check
                    .add_contract(quote.clone())
                    .map_err(|e| e.to_string())?;
            }
            approved.insert(agreement.channel.id.clone(), agreement);
        }
        Ok(Self {
            receiver,
            ledger,
            approved,
            keysets: None,
        })
    }

    /// Performs validation and durable I/O; never call on the native node loop.
    pub fn handle(&self, peer: PeerIdentity, body: &[u8]) -> PaymentResponse {
        if body.len() > crate::control_transport::MAX_RECORD_BYTES {
            return PaymentResponse::Rejected;
        }
        let Ok(request) = serde_json::from_slice::<PaymentRequest>(body) else {
            return PaymentResponse::Rejected;
        };
        let operation = match request {
            PaymentRequest::Open { .. } => Operation::PaymentOpen,
            PaymentRequest::Update { .. } => Operation::PaymentUpdate,
            PaymentRequest::Usage { .. } => Operation::PaymentUsage,
            PaymentRequest::StopForwarding { .. } => Operation::PaymentStop,
        };
        measure(operation, || {
            self.handle_inner(peer, request)
                .unwrap_or(PaymentResponse::Rejected)
        })
    }

    fn handle_inner(
        &self,
        peer: PeerIdentity,
        request: PaymentRequest,
    ) -> Result<PaymentResponse, String> {
        let id = match &request {
            PaymentRequest::Open { channel_id, .. }
            | PaymentRequest::Update { channel_id, .. }
            | PaymentRequest::Usage { channel_id }
            | PaymentRequest::StopForwarding { channel_id } => channel_id,
        };
        let terms = self
            .ledger
            .channel_terms(id)
            .or_else(|| self.approved.get(id).map(|a| a.channel.clone()))
            .ok_or("agreement missing")?;
        if peer.node_addr() != &terms.buyer {
            return Err("wrong buyer".into());
        }
        match &request {
            PaymentRequest::Open { payment, .. } => {
                let approved = self
                    .approved
                    .get(id)
                    .ok_or("opening requires a preapproved agreement")?;
                let credit =
                    process_payment(&self.receiver, &approved.channel, peer, payment, true)?;
                if self.ledger.channel_usage(id).is_none() {
                    self.ledger
                        .open_channel_verified(approved.channel.clone(), credit.paid_msat)
                        .map_err(|e| e.to_string())?;
                } else {
                    self.ledger
                        .apply_verified_balance(id, credit.paid_msat)
                        .map_err(|e| e.to_string())?;
                }
                for quote in &approved.quotes {
                    self.ledger
                        .add_contract(quote.clone())
                        .map_err(|e| e.to_string())?;
                }
            }
            PaymentRequest::Update { payment, .. } => {
                if self.ledger.channel_usage(id).is_none() {
                    return Err("channel not opened".into());
                }
                let credit = process_payment(&self.receiver, &terms, peer, payment, false)?;
                self.ledger
                    .apply_verified_balance(id, credit.paid_msat)
                    .map_err(|e| e.to_string())?;
            }
            PaymentRequest::Usage { .. } => {}
            PaymentRequest::StopForwarding { .. } => {
                self.ledger.close_channel(id).map_err(|e| e.to_string())?;
            }
        }
        let usage = self
            .ledger
            .checkpoint()
            .map_err(|e| e.to_string())?
            .get(id)
            .copied()
            .ok_or("channel not opened")?;
        Ok(PaymentResponse::Status {
            channel_id: id.clone(),
            usage,
        })
    }
}

/// Serialized controller processing keeps crypto and fsync on a blocking
/// worker. The TCP transport continues driving bounded streams while it runs.
pub struct PaymentServer {
    task: JoinHandle<()>,
    stopping: tokio::sync::watch::Sender<bool>,
}

impl PaymentServer {
    pub async fn stop(mut self) {
        let _ = self.stopping.send(true);
        let _ = (&mut self.task).await;
    }

    pub fn start<R: CashuSpilmanPaymentReceiver<String> + Send + Sync + 'static>(
        control: PaymentControl<R>,
        incoming: mpsc::Receiver<IncomingRequest>,
    ) -> Self {
        Self::start_shared(Arc::new(control), incoming)
    }

    pub fn start_shared<R: CashuSpilmanPaymentReceiver<String> + Send + Sync + 'static>(
        control: Arc<PaymentControl<R>>,
        mut incoming: mpsc::Receiver<IncomingRequest>,
    ) -> Self {
        let (stopping, mut stop) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                let request = tokio::select! {
                    biased;
                    _ = stop.changed() => break,
                    request = incoming.recv() => {
                        let Some(request) = request else { break; };
                        request
                    }
                };
                let handler = Arc::clone(&control);
                let result = tokio::task::spawn_blocking(move || {
                    handler.handle(request.peer, &request.body)
                })
                .await;
                if let Ok(reply) = result {
                    let _ = request
                        .respond
                        .send(serde_json::to_vec(&reply).expect("serializable payment response"));
                }
            }
        });
        Self { task, stopping }
    }
}

impl Drop for PaymentServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
