//! Offline administration of the existing relay wallet, never relay credit.
mod history;
#[cfg(test)]
mod tests;

use crate::{
    durable::{acquire_owner, write_private_journal},
    service::{RelayService, ServiceConfig, read_json},
};
use cashu::nuts::{CurrencyUnit, Token};
use cashu_service::{
    CashuSentPayment, CashuWalletSendRequest, CashuWalletService, load_mint_balance,
    normalize_mint_url, receive_payment_token,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WalletRequest {
    Balance,
    Import {
        token: String,
    },
    Export {
        id: u64,
        amount_sat: u64,
    },
    /// Release a prefix only after retaining its tokens elsewhere or collecting them.
    AcknowledgeExports {
        through: u64,
    },
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

pub(crate) fn private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path.parent().ok_or("missing parent")?;
    let mut file = tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    // Publish only complete, durable bytes; never replace a saved account.
    file.persist_noclobber(path).map_err(|e| e.to_string())?;
    File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

pub(crate) fn checked_token(token: &str, mint: &str) -> Result<(), String> {
    if token.len() > 64 * 1024 {
        return Err("token too large".into());
    }
    let parsed = Token::from_str(token).map_err(|_| "invalid Cashu token")?;
    let actual = parsed
        .mint_url()
        .map_err(|_| "token must contain one mint")?;
    if parsed.unit().unwrap_or_default() != CurrencyUnit::Sat
        || normalize_mint_url(&actual.to_string()).map_err(|_| "invalid token mint")?
            != normalize_mint_url(mint).map_err(|_| "invalid configured mint")?
    {
        return Err("token does not use the configured sat mint".into());
    }
    Ok(())
}

pub(crate) fn export_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_id(id) {
        return Err("invalid export id".into());
    }
    Ok(root.join("exports").join(format!("{id}.json")))
}

fn export_summary(path: &Path, payment: &CashuSentPayment) -> Value {
    json!({"path": path, "amount_sat": payment.amount_sat, "operation_id": payment.operation_id})
}

fn send_request(mint: String, request_id: String, amount_sat: u64) -> CashuWalletSendRequest {
    CashuWalletSendRequest {
        request_id,
        mint_url: mint,
        amount_sat,
        required_keyset_id: None,
        max_total_amount_sat: None,
        metadata: Default::default(),
    }
}

async fn check_cached(
    wallet: &CashuWalletService,
    request: CashuWalletSendRequest,
    cached: &CashuSentPayment,
) -> Result<(), String> {
    // Validation cannot start or recover an unfinished wallet send.
    let original = wallet
        .wallet_send_result(request)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("export is missing its original wallet result; reconcile before retrying")?;
    if *cached != original.payment {
        return Err(
            "export conflicts with its original wallet result; reconcile before retrying".into(),
        );
    }
    Ok(())
}

pub(crate) async fn export_payment(
    root: &Path,
    mint: &str,
    id: &str,
    amount: u64,
    request_id: String,
) -> Result<Value, String> {
    let path = export_path(root, id)?;
    let mint = normalize_mint_url(mint).map_err(|e| e.to_string())?;
    if amount == 0 {
        return Err("export amount must be positive".into());
    }
    let directory = root.join("exports");
    if !directory.try_exists().map_err(|e| e.to_string())? {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|e| e.to_string())?;
    }
    let cached = if path.try_exists().map_err(|e| e.to_string())? {
        let payment: CashuSentPayment = read_json(&path)?;
        if payment.amount_sat != amount || payment.mint_url != mint {
            return Err("export id already has different terms".into());
        }
        Some(payment)
    } else {
        None
    };
    // Older reservations do not identify an SDK request. Their absence of a
    // token cannot authorize a new send under the current request namespace.
    match std::fs::symlink_metadata(directory.join(format!("{id}.intent"))) {
        Ok(_) => return Err("export is pending; reconcile its original wallet operation".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let wallet = CashuWalletService::open_file_backed(&root.join("wallet"))
        .await
        .map_err(|e| e.to_string())?;
    // The SDK retains the original terms, coins and result before publication.
    // Keep this identity stable: a retry must never become another wallet send.
    let request = send_request(mint, request_id, amount);
    if let Some(cached) = cached {
        check_cached(&wallet, request, &cached).await?;
        return Ok(export_summary(&path, &cached));
    }
    let payment = wallet
        .send_payment_token_for_request(request)
        .await
        .map_err(|e| e.to_string())?
        .payment;
    write_private_journal(
        &directory,
        &format!("{id}.json"),
        &serde_json::to_vec(&payment).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(export_summary(&path, &payment))
}

/// The same exclusive root lock as the service prevents concurrent wallet use.
/// Import adds spendable tokens only; it never resets lifetime budgets, channel
/// capacity, buyer evidence, or seller allowance.
pub async fn offline_wallet(
    config: &ServiceConfig,
    command: WalletRequest,
) -> Result<Value, String> {
    RelayService::validate_stored_state(config)?;
    let _owner = acquire_owner(&config.state_directory).map_err(|e| e.to_string())?;
    RelayService::validate_stored_state(config)?;
    RelayService::check_wallet_capacity(config).await?;
    let mint = &config.terms.controller.mint_url;
    let wallet = config.state_directory.join("wallet");
    match command {
        WalletRequest::Balance => serde_json::to_value(
            load_mint_balance(&wallet, mint)
                .await
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string()),
        WalletRequest::Import { token } => {
            checked_token(&token, mint)?;
            serde_json::to_value(
                receive_payment_token(&wallet, &token)
                    .await
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        WalletRequest::Export { id, amount_sat } => {
            let request_id = history::prepare_export(&config.state_directory, mint, id).await?;
            export_payment(
                &config.state_directory,
                mint,
                &id.to_string(),
                amount_sat,
                request_id,
            )
            .await
        }
        WalletRequest::AcknowledgeExports { through } => {
            history::acknowledge(&config.state_directory, mint, through).await
        }
    }
}
