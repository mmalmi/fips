//! Offline administration of the existing relay wallet, never relay credit.

use crate::{
    durable::acquire_owner,
    service::{RelayService, ServiceConfig, read_json},
};
use cashu::nuts::{CurrencyUnit, Token};
use cashu_service::{
    CashuSentPayment, load_mint_balance, normalize_mint_url, receive_payment_token,
    send_payment_token,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WalletRequest {
    Balance,
    Import { token: String },
    Export { id: String, amount_sat: u64 },
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

pub(crate) fn private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(path.parent().ok_or("missing parent")?)
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

pub(crate) async fn export_payment(
    root: &Path,
    mint: &str,
    id: &str,
    amount: u64,
) -> Result<Value, String> {
    let path = export_path(root, id)?;
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
    if path.try_exists().map_err(|e| e.to_string())? {
        let payment: CashuSentPayment = read_json(&path)?;
        if payment.amount_sat != amount || payment.mint_url != mint {
            return Err("export id already has different terms".into());
        }
        return Ok(export_summary(&path, &payment));
    }
    // Reserve the id before the wallet operation. If interrupted before its
    // token is saved, fail closed; the Cashu activity/saga journal remains the
    // recovery source. Retrying must not produce another spend automatically.
    private_new(
        &directory.join(format!("{id}.intent")),
        &serde_json::to_vec(&json!({"amount_sat":amount,"mint":mint})).unwrap(),
    )
    .map_err(|_| {
        "export is pending or cannot be reserved; reconcile its wallet activity before retrying"
    })?;
    let payment = send_payment_token(&root.join("wallet"), mint, amount)
        .await
        .map_err(|e| e.to_string())?;
    private_new(
        &path,
        &serde_json::to_vec(&payment).map_err(|e| e.to_string())?,
    )?;
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
            export_payment(&config.state_directory, mint, &id, amount_sat).await
        }
    }
}
