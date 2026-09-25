//! Pair receiver funding and payouts with the controller's original wallet.
use super::*;
use cashu_service::{
    CashuSpilmanPaymentReceiver, CashuSpilmanPaymentReceiverValidation, CashuWalletService,
};
use std::path::Path;

impl PaymentControl {
    pub(crate) fn wallet_directory(&self) -> &Path {
        &self.wallet_directory
    }

    pub(crate) fn wallet_owner(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.wallet.clone()
    }

    /// Called on a blocking worker with the wallet owner held, before committing
    /// onward capital or forwarding credit. Reuse all ordinary agreement checks.
    pub(crate) fn verify_funding(
        &self,
        channel: &ChannelTerms,
        peer: PeerIdentity,
        payment: &CashuSpilmanPayment,
    ) -> Result<crate::payment::VerifiedCredit, String> {
        process_payment(&WalletReceiver(self), channel, peer, payment, true)
    }

    pub(crate) fn verify_existing(
        &self,
        channel: &ChannelTerms,
        peer: PeerIdentity,
        payment: &CashuSpilmanPayment,
    ) -> Result<crate::payment::VerifiedCredit, String> {
        if !self.receiver.has_funding(&channel.id) {
            return Err("original receiver funding missing".into());
        }
        process_payment(&self.receiver, channel, peer, payment, false)
    }

    pub(super) async fn open_wallet(&self) -> Result<CashuWalletService, String> {
        CashuWalletService::open_file_backed(&self.wallet_directory)
            .await
            .map_err(|e| e.to_string())
    }

    // Settlement and retirement use the same wallet owner as initial admission.
    pub(crate) async fn import_wallet_payout(&self, id: &str) -> Result<(), String> {
        let wallet = self.open_wallet().await?;
        self.receiver
            .import_wallet_payout(&wallet, id)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

// This adapter is used only for initial funding on bounded blocking workers.
// Recurring payments use the original funding without reopening the wallet.
struct WalletReceiver<'a>(&'a PaymentControl);

impl CashuSpilmanPaymentReceiver<String> for WalletReceiver<'_> {
    fn validate_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &String,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        tokio::runtime::Handle::current().block_on(async {
            let wallet = self.0.open_wallet().await?;
            self.0
                .receiver
                .validate_cashu_spilman_payment_with_wallet(&wallet, payment, context)
                .await
        })
    }

    fn process_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &String,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        self.0
            .receiver
            .process_cashu_spilman_payment(payment, context)
    }
}

#[cfg(test)]
mod tests;
