//! An explicitly disposable, private CDK mint for hardware tests. The production
//! relay does not contain the simulated funding capability unless this feature
//! is selected. The mint API and local funding control are separate listeners.

use crate::{
    durable::write_private_journal,
    service::{read_json, read_record, write_record},
    wallet_tools::{checked_token, export_path, export_payment, private_new, valid_id},
};
use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview, receive_payment_token,
    simulation::{IssuerMode, LocalMint, MonotonicClock, PaymentNetwork},
};
use fips_core::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    task::{JoinHandle, JoinSet},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchConfig {
    pub state_directory: PathBuf,
    pub bind: SocketAddr,
    pub max_issued_sat: u64,
}

impl BenchConfig {
    pub fn read(path: &Path) -> Result<Self, String> {
        let config: Self = read_json(path)?;
        config.validate()?;
        Ok(config)
    }
    fn socket(&self) -> PathBuf {
        self.state_directory.join("control.sock")
    }
    fn validate(&self) -> Result<(), String> {
        let private = match self.bind.ip() {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
        };
        if !private
            || !self.state_directory.is_absolute()
            || self.socket().as_os_str().len() > 100
            || self.max_issued_sat == 0
            || self.max_issued_sat > 10_000_000
        {
            return Err("test mint requires a private/loopback bind, absolute private state path and bounded test issuance".into());
        }
        Ok(())
    }
}

struct WallClock {
    unix: u64,
    start: Instant,
}
impl MonotonicClock for WallClock {
    fn now(&self) -> u64 {
        self.unix.saturating_add(self.start.elapsed().as_secs())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BenchRequest {
    Issue { id: String, amount_sat: u64 },
    Collect { token: String },
    Report,
}

pub struct BenchMint {
    config: BenchConfig,
    url: String,
    network: PaymentNetwork,
    _mint: LocalMint,
    proxy: JoinHandle<()>,
    issued: BTreeMap<String, u64>,
}

impl BenchMint {
    pub async fn start(config: BenchConfig) -> Result<Self, String> {
        config.validate()?;
        // Simulation keeps its Lightning network state in memory. Never imply
        // a fresh process can safely resume it from only the mint SQLite file.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&config.state_directory)
            .map_err(
                |_| "test mint requires a new directory; existing runs are never reset or resumed",
            )?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let entropy = Identity::generate();
        let seed = u64::from_le_bytes(entropy.node_addr().as_bytes()[..8].try_into().unwrap());
        let network = PaymentNetwork::new(
            seed,
            0,
            Arc::new(WallClock {
                unix: now,
                start: Instant::now(),
            }),
        );
        let mint = LocalMint::start(
            &config.state_directory,
            network.clone(),
            "hardware-bench",
            IssuerMode::ClosedLoop,
        )
        .await
        .map_err(|e| e.to_string())?;
        let backend: SocketAddr = mint
            .url()
            .strip_prefix("http://")
            .ok_or("invalid local mint URL")?
            .parse()
            .map_err(|_| "invalid local mint address")?;
        let listener = TcpListener::bind(config.bind)
            .await
            .map_err(|e| e.to_string())?;
        let url = format!(
            "http://{}",
            listener.local_addr().map_err(|e| e.to_string())?
        );
        // Fixed loopback upstream only. No client-provided proxy destinations.
        let proxy = tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept(), if jobs.len() < 32 => {
                        let Ok((mut incoming, _)) = connection else { break; };
                        jobs.spawn(async move {
                            let _ = tokio::time::timeout(Duration::from_secs(45), async {
                                let mut upstream = TcpStream::connect(backend).await?;
                                tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await
                            }).await;
                        });
                    }
                    _ = jobs.join_next(), if !jobs.is_empty() => {}
                }
            }
        });
        let service = Self {
            config,
            url,
            network,
            _mint: mint,
            proxy,
            issued: BTreeMap::new(),
        };
        load_mint_balance(&service.config.state_directory.join("wallet"), &service.url)
            .await
            .map_err(|e| e.to_string())?;
        load_mint_balance(
            &service.config.state_directory.join("collected"),
            &service.url,
        )
        .await
        .map_err(|e| e.to_string())?;
        private_new(&service.config.state_directory.join("ready.json"), &serde_json::to_vec(&json!({"test_only":true,"url":service.url,"max_issued_sat":service.config.max_issued_sat})).unwrap())?;
        Ok(service)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn handle(&mut self, request: BenchRequest) -> Result<Value, String> {
        match request {
            BenchRequest::Issue { id, amount_sat } => {
                if !valid_id(&id) || amount_sat == 0 {
                    return Err("invalid test grant".into());
                }
                if let Some(prior) = self.issued.get(&id) {
                    if *prior != amount_sat {
                        return Err("grant id has different terms".into());
                    }
                    if !export_path(&self.config.state_directory, &id)?
                        .try_exists()
                        .map_err(|e| e.to_string())?
                    {
                        return Err(
                            "grant is pending; inspect this isolated run before proceeding".into(),
                        );
                    }
                    return export_payment(
                        &self.config.state_directory,
                        &self.url,
                        &id,
                        amount_sat,
                    )
                    .await;
                }
                let reserved: u64 = self.issued.values().sum();
                if self.issued.len() >= 64
                    || amount_sat > self.config.max_issued_sat.saturating_sub(reserved)
                {
                    return Err("test issuance limit reached".into());
                }
                self.issued.insert(id.clone(), amount_sat);
                write_private_journal(
                    &self.config.state_directory,
                    "grants.json",
                    &serde_json::to_vec(&self.issued).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let wallet = self.config.state_directory.join("wallet");
                let quote = create_topup_quote(&wallet, &self.url, amount_sat)
                    .await
                    .map_err(|e| e.to_string())?;
                self.network
                    .orchestrator_funding()
                    .settle_external(&quote.payment_request)
                    .map_err(|e| e.to_string())?;
                let overview = load_wallet_overview(&wallet, true)
                    .await
                    .map_err(|e| e.to_string())?;
                if !overview.warnings.is_empty() {
                    return Err("test funding reconciliation has warnings".into());
                }
                export_payment(&self.config.state_directory, &self.url, &id, amount_sat).await
            }
            BenchRequest::Collect { token } => {
                checked_token(&token, &self.url)?;
                serde_json::to_value(
                    receive_payment_token(&self.config.state_directory.join("collected"), &token)
                        .await
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())
            }
            BenchRequest::Report => {
                let collected =
                    load_mint_balance(&self.config.state_directory.join("collected"), &self.url)
                        .await
                        .map_err(|e| e.to_string())?;
                let accounting = self.network.accounting().map_err(|e| e.to_string())?;
                Ok(
                    json!({"test_only":true,"url":self.url,"issued_sat":self.issued.values().sum::<u64>(),
                    "collected_sat":collected.balance_sat,"external_funding_sat":accounting.external_funding_sat,
                    "total_accounted_sat":accounting.total_accounted_sat,"conserved":accounting.is_conserved()}),
                )
            }
        }
    }

    pub async fn serve(mut self, stop: impl Future<Output = ()>) -> Result<(), String> {
        let socket = self.config.socket();
        let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        tokio::pin!(stop);
        loop {
            let connection = tokio::select! {
                _ = &mut stop => break,
                connection = listener.accept() => connection,
            };
            let (mut stream, _) = connection.map_err(|e| e.to_string())?;
            // Serial funding commands keep issuance and wallet ownership simple.
            // The independent HTTP proxy continues servicing every router.
            let result = match tokio::time::timeout(
                Duration::from_secs(5),
                read_record(&mut stream, 64 * 1024),
            )
            .await
            {
                Ok(Ok(bytes)) => match serde_json::from_slice(&bytes) {
                    Ok(request) => self.handle(request).await,
                    Err(_) => Err("invalid test-mint request".into()),
                },
                _ => Err("test-mint request timed out or exceeded its limit".into()),
            };
            let response = match result {
                Ok(ok) => json!({"ok":ok}),
                Err(error) => json!({"error":error}),
            };
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                write_record(&mut stream, &serde_json::to_vec(&response).unwrap()),
            )
            .await;
        }
        drop(listener);
        std::fs::remove_file(socket).map_err(|e| e.to_string())?;
        self.shutdown().await;
        Ok(())
    }

    pub async fn shutdown(mut self) {
        self.proxy.abort();
        let _ = (&mut self.proxy).await;
    }
}
impl Drop for BenchMint {
    fn drop(&mut self) {
        self.proxy.abort();
    }
}

pub async fn request(config: &BenchConfig, request: &BenchRequest) -> Result<Value, String> {
    let mut stream = UnixStream::connect(config.socket())
        .await
        .map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    if bytes.len() > 64 * 1024 {
        return Err("test-mint request too large".into());
    }
    write_record(&mut stream, &bytes).await?;
    let response = read_record(&mut stream, 64 * 1024).await?;
    let mut value: Value =
        serde_json::from_slice(&response).map_err(|_| "invalid test-mint response")?;
    if let Some(error) = value.get("error") {
        return Err(error.as_str().unwrap_or("test-mint request failed").into());
    }
    value
        .get_mut("ok")
        .map(Value::take)
        .ok_or("invalid test-mint response".into())
}
