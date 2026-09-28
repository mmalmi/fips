//! Cumulative payments for neighbor agreements admitted by the controller.
//!
//! Approval/price discovery is deliberately separate. A wire request cannot
//! choose its price, payer, free allowance, destination, or next provider.

use crate::{
    control_transport::IncomingRequest,
    durable::DurableRelay,
    ledger::{ChannelTerms, ChannelUsage},
    measurements::{Operation, measure},
    payment::process_payment,
};
use cashu_service::{CashuSpilmanPayment, FileSpilmanPaymentReceiver};
use fips_core::PeerIdentity;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
mod keysets;
mod retirement;
mod wallet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaymentRequest {
    Update {
        channel_id: String,
        payment: CashuSpilmanPayment,
    },
    Usage {
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

pub struct PaymentControl {
    receiver: FileSpilmanPaymentReceiver,
    wallet_directory: PathBuf,
    wallet: Arc<tokio::sync::Mutex<()>>,
    ledger: Arc<DurableRelay>,
    keysets: Option<keysets::KeysetRefresh>,
}

impl PaymentControl {
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

    /// The controller installs verified bindings in the durable ledger;
    /// usage and payment requests use those same immutable terms.
    /// Keep the paired wallet directory for the receiver's complete lifetime.
    pub fn new(
        receiver: FileSpilmanPaymentReceiver,
        wallet_directory: PathBuf,
        ledger: Arc<DurableRelay>,
    ) -> Self {
        Self {
            receiver,
            wallet_directory,
            wallet: Arc::new(tokio::sync::Mutex::new(())),
            ledger,
            keysets: None,
        }
    }

    /// Performs validation and durable I/O; call from a Tokio blocking worker.
    pub fn handle(&self, peer: PeerIdentity, body: &[u8]) -> PaymentResponse {
        if body.len() > crate::control_transport::MAX_RECORD_BYTES {
            return PaymentResponse::Rejected;
        }
        let Ok(request) = serde_json::from_slice::<PaymentRequest>(body) else {
            return PaymentResponse::Rejected;
        };
        let operation = match request {
            PaymentRequest::Update { .. } => Operation::PaymentUpdate,
            PaymentRequest::Usage { .. } => Operation::PaymentUsage,
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
            PaymentRequest::Update { channel_id, .. } | PaymentRequest::Usage { channel_id } => {
                channel_id
            }
        };
        let terms = self.ledger.channel_terms(id).ok_or("agreement missing")?;
        if peer.node_addr() != &terms.buyer {
            return Err("wrong buyer".into());
        }
        match &request {
            PaymentRequest::Update { payment, .. } => {
                if self.ledger.channel_usage(id).is_none() {
                    return Err("channel not opened".into());
                }
                let credit = self.verify_existing(&terms, peer, payment)?;
                self.ledger
                    .apply_verified_balance(id, credit.paid_msat)
                    .map_err(|e| e.to_string())?;
            }
            PaymentRequest::Usage { .. } => {}
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

    pub fn start_shared(
        control: Arc<PaymentControl>,
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
