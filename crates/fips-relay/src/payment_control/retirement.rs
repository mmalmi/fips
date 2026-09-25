//! Local SDK handoff, called while the controller holds its wallet owner guard.
use super::*;
use cashu_service::{CashuSpilmanReceiverHistory, CashuSpilmanReceiverRetirement};

impl PaymentControl {
    pub(crate) async fn receiver_retirement_plan(
        &self,
        ids: &[String],
        timestamp: u64,
    ) -> Result<CashuSpilmanReceiverRetirement, String> {
        let wallet = self.open_wallet().await?;
        self.receiver
            .prepare_retirement(&wallet, ids, timestamp)
            .await
    }

    pub(crate) async fn retire_receiver(
        &self,
        plan: &CashuSpilmanReceiverRetirement,
    ) -> Result<CashuSpilmanReceiverHistory, String> {
        let wallet = self.open_wallet().await?;
        self.receiver.retire_channels(&wallet, plan).await
    }
}
