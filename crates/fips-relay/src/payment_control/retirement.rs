//! Local SDK handoff, called while the controller holds its wallet owner guard.
use super::*;
use cashu_service::{
    CashuSpilmanReceiverHistory, CashuSpilmanReceiverRetirement, CashuWalletService,
    FileSpilmanPaymentReceiver,
};
use std::path::Path;

impl PaymentControl<FileSpilmanPaymentReceiver> {
    pub(crate) async fn receiver_retirement_plan(
        &self,
        directory: &Path,
        ids: &[String],
        timestamp: u64,
    ) -> Result<CashuSpilmanReceiverRetirement, String> {
        let wallet = CashuWalletService::open_file_backed(directory)
            .await
            .map_err(|e| e.to_string())?;
        self.receiver
            .prepare_retirement(&wallet, ids, timestamp)
            .await
    }

    pub(crate) async fn retire_receiver(
        &self,
        directory: &Path,
        plan: &CashuSpilmanReceiverRetirement,
    ) -> Result<CashuSpilmanReceiverHistory, String> {
        let wallet = CashuWalletService::open_file_backed(directory)
            .await
            .map_err(|e| e.to_string())?;
        self.receiver.retire_channels(&wallet, plan).await
    }
}
