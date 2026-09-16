//! Fetch mint keys only when paid funding is requested, never to start free service.
use cashu_service::{FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig};
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

    pub(super) async fn prepare(&self, identity: &str) -> Result<(), String> {
        let mut last = self.last.lock().await;
        if let Some((until, result)) = &*last
            && *until > Instant::now()
        {
            return result.clone();
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
        let result = match tokio::time::timeout(
            Duration::from_secs(10),
            FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                &self.directory,
                self.config.clone(),
            ),
        )
        .await
        {
            Ok(Ok(receiver)) if receiver.receiver_pubkey_hex() == identity => Ok(()),
            Ok(Ok(_)) => Err("payment receiver identity changed during key refresh".into()),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("mint key refresh deadline".into()),
        };
        let delay = if result.is_ok() {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(1)
        };
        *last = Some((Instant::now() + delay, result.clone()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refresh_never_recreates_a_lost_receiver_identity() {
        let root = tempfile::tempdir().unwrap();
        let config = FileSpilmanPaymentReceiverConfig::new(["http://127.0.0.1:9".to_owned()]);
        let receiver = FileSpilmanPaymentReceiver::load(root.path(), config.clone()).unwrap();
        let key = root.path().join("spilman-receiver-key.json");
        std::fs::remove_file(&key).unwrap();
        let refresh = KeysetRefresh::new(root.path().to_owned(), config);
        assert!(
            refresh
                .prepare(receiver.receiver_pubkey_hex())
                .await
                .unwrap_err()
                .contains("required receiver state missing")
        );
        assert!(!key.exists());
    }
}
