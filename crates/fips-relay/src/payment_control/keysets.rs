//! Fetch mint keys only when paid funding is requested, never to start free service.
use cashu_service::{
    CashuSpilmanPayment, FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig,
};
use std::{path::PathBuf, time::Duration};
use tokio::{sync::Mutex, time::Instant};

pub(super) struct KeysetRefresh {
    directory: PathBuf,
    config: FileSpilmanPaymentReceiverConfig,
    last: Mutex<Option<(Instant, Result<(), String>)>>,
}

impl KeysetRefresh {
    pub(super) fn new(directory: PathBuf, config: FileSpilmanPaymentReceiverConfig) -> Self {
        Self {
            directory,
            config,
            last: Mutex::new(None),
        }
    }

    pub(super) async fn prepare(
        &self,
        receiver: &FileSpilmanPaymentReceiver,
        payment: &CashuSpilmanPayment,
    ) -> Result<(), String> {
        // Known funding must not wait behind another request's mint lookup.
        if receiver.has_funding_keyset(payment)? {
            return Ok(());
        }
        let mut last = self.last.lock().await;
        // Concurrent requests for the same new keys share the completed refresh.
        if receiver.has_funding_keyset(payment)? {
            return Ok(());
        }
        if let Some((until, result)) = &*last
            && *until > Instant::now()
        {
            result.clone()?;
            tokio::time::sleep_until(*until).await;
        }
        // This is refresh of an owned receiver, never lazy initialization after
        // losing a key or database. The library load API can otherwise recreate it.
        for name in ["spilman-receiver-key.json", "spilman-receiver.sqlite"] {
            if !std::fs::symlink_metadata(self.directory.join(name))
                .is_ok_and(|m| m.is_file() && m.len() > 0)
            {
                return Err("required receiver state missing during key refresh".into());
            }
        }
        // The library writes keysets to the shared receiver SQLite store;
        // its already-loaded receiver reads that store for every validation.
        // Do not replace financial state or waive signature verification.
        // Allow bounded mesh bootstrap to fetch keys while leaving time for the
        // acceptance response inside the control transport's 30-second request.
        let result = match tokio::time::timeout(
            Duration::from_secs(20),
            FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                &self.directory,
                self.config.clone(),
            ),
        )
        .await
        {
            Ok(Ok(refreshed))
                if refreshed.receiver_pubkey_hex() == receiver.receiver_pubkey_hex() =>
            {
                Ok(())
            }
            Ok(Ok(_)) => Err("payment receiver identity changed during key refresh".into()),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("mint key refresh deadline".into()),
        };
        // Missing or invented keysets cannot drive an unbounded refresh rate.
        *last = Some((Instant::now() + Duration::from_secs(1), result.clone()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cashu_service::simulation::{
        IssuerMode, LocalMint, MintProxy, PaymentNetwork, VirtualClock,
    };
    use std::sync::{Arc, atomic::Ordering};

    fn payment(mint: &str, keyset: &str) -> CashuSpilmanPayment {
        CashuSpilmanPayment {
            channel_id: "unknown".into(),
            balance: 0,
            signature: String::new(),
            params: Some(serde_json::json!({"mint": mint, "keyset_id": keyset})),
            funding_proofs: None,
        }
    }

    #[tokio::test]
    async fn refresh_never_recreates_a_lost_receiver_identity() {
        let root = tempfile::tempdir().unwrap();
        let config = FileSpilmanPaymentReceiverConfig::new(["http://127.0.0.1:9".to_owned()]);
        let receiver = FileSpilmanPaymentReceiver::load(root.path(), config.clone()).unwrap();
        let key = root.path().join("spilman-receiver-key.json");
        std::fs::remove_file(&key).unwrap();
        let refresh = KeysetRefresh::new(root.path().to_owned(), config);
        let payment = payment("http://127.0.0.1:9", "0000000000000000");
        assert!(
            refresh
                .prepare(&receiver, &payment)
                .await
                .unwrap_err()
                .contains("required receiver state missing")
        );
        assert!(!key.exists());
    }

    #[tokio::test]
    async fn known_keys_bypass_refresh_ownership_and_failed_lookups_are_paced() {
        let root = tempfile::tempdir().unwrap();
        let network = PaymentNetwork::new(926, 0, Arc::new(VirtualClock::new(1_800_000_000)));
        let mint = LocalMint::start(root.path(), network, "key-cache", IssuerMode::ClosedLoop)
            .await
            .unwrap();
        let proxy = MintProxy::start(mint.url()).await;
        let keys = mint
            .mint()
            .rotate_keyset(
                cashu::nuts::CurrencyUnit::Sat,
                (0..=20).map(|bit| 1u64 << bit).collect(),
                0,
                false,
                None,
            )
            .await
            .unwrap();
        let directory = root.path().join("receiver");
        let config = FileSpilmanPaymentReceiverConfig::new([proxy.url.clone()]);
        let receiver =
            FileSpilmanPaymentReceiver::load_with_keyset_refresh(&directory, config.clone())
                .await
                .unwrap();
        let refresh = KeysetRefresh::new(directory, config);
        let known = payment(&proxy.url, &keys.id.to_string());
        assert!(receiver.has_funding_keyset(&known).unwrap());
        let owner = refresh.last.lock().await;
        tokio::time::timeout(
            Duration::from_millis(200),
            refresh.prepare(&receiver, &known),
        )
        .await
        .expect("known keys must not wait for a mint refresh")
        .unwrap();
        drop(owner);

        let unknown = payment(&proxy.url, "0000000000000000");
        proxy
            .state
            .fail_next_keysets_reply
            .store(true, Ordering::SeqCst);
        assert!(refresh.prepare(&receiver, &unknown).await.is_err());
        assert!(!proxy.state.fail_next_keysets_reply.load(Ordering::SeqCst));
        proxy
            .state
            .fail_next_keysets_reply
            .store(true, Ordering::SeqCst);
        assert!(refresh.prepare(&receiver, &unknown).await.is_err());
        assert!(refresh.prepare(&receiver, &known).await.is_ok());
        let malformed = payment(&proxy.url, "invalid");
        assert!(refresh.prepare(&receiver, &malformed).await.is_err());
        assert!(proxy.state.fail_next_keysets_reply.load(Ordering::SeqCst));
        assert!(!receiver.has_funding(&known.channel_id));
    }
}
