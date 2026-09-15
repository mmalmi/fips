//! Foreground customer lifecycle shared by the phone shell and integration tests.
//! Payment, forwarding, persistence and settlement remain in RelayService.
mod profile;
pub use profile::CustomerProfile;

use crate::{
    durable::acquire_owner,
    service::{AdminRequest, RelayService, ServiceConfig, read_json, request},
    wallet_tools::{WalletRequest, offline_wallet, private_new},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::File,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};
use tokio::{sync::oneshot, task::JoinHandle};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustomerCommand {
    Preview { profile: CustomerProfile },
    Setup { profile: CustomerProfile },
    Start,
    Status,
    Import { token: String },
    Balance,
    Buy,
    Send { payload: String },
    Finish,
    Stop,
    Export { id: String, amount_sat: u64 },
}

struct Running {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), String>>,
}

pub struct CustomerClient {
    root: PathBuf,
    profile: Option<CustomerProfile>,
    running: Option<Running>,
    _owner: File,
}

impl CustomerClient {
    /// The caller supplies its app-private directory, never a path from a profile.
    pub fn open(root: &Path) -> Result<Self, String> {
        if !root.is_absolute() || root.join("state/control.sock").as_os_str().len() > 100 {
            return Err(
                "customer storage must be an absolute private directory with a short socket path"
                    .into(),
            );
        }
        let owner = acquire_owner(root).map_err(|e| e.to_string())?;
        let profile_file = root.join("profile.json");
        let profile = if profile_file.try_exists().map_err(|e| e.to_string())? {
            let profile: CustomerProfile = read_json(&profile_file)?;
            profile.validate()?;
            Some(profile)
        } else {
            if root.join("state").try_exists().map_err(|e| e.to_string())? {
                return Err(
                    "customer profile is missing; existing account requires recovery".into(),
                );
            }
            None
        };
        Ok(Self {
            root: root.to_path_buf(),
            profile,
            running: None,
            _owner: owner,
        })
    }

    fn config(&self) -> Result<ServiceConfig, String> {
        self.profile
            .as_ref()
            .map(|p| p.config(&self.root))
            .ok_or("set up the test account first".into())
    }

    // Wallet/service futures are large in debug builds. Keep them off the Java
    // caller's small stack; this allocation is per UI action, never per packet.
    pub fn execute(
        &mut self,
        command: CustomerCommand,
    ) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + '_>> {
        Box::pin(async move {
            use CustomerCommand::*;
            match command {
                Preview { profile } => {
                    profile.validate()?;
                    Ok(json!({"entry_ip":profile.entry_address.ip(),"profile":profile}))
                }
                Setup { profile } => self.setup(profile).await,
                Start => {
                    self.start().await?;
                    self.status().await
                }
                Status => self.status().await,
                Import { token } => self.wallet(WalletRequest::Import { token }).await,
                Balance => self.wallet(WalletRequest::Balance).await,
                Export { id, amount_sat } => {
                    self.wallet(WalletRequest::Export { id, amount_sat }).await
                }
                Stop => {
                    self.stop().await?;
                    self.status().await
                }
                Buy => {
                    let profile = self
                        .profile
                        .as_ref()
                        .ok_or("set up the test account first")?;
                    self.control(&AdminRequest::Watch {
                        destination: profile.destination_npub.clone(),
                        max_rate_msat_per_kib: profile.max_rate_msat_per_kib,
                    })
                    .await
                }
                Send { payload } => {
                    let destination = self
                        .profile
                        .as_ref()
                        .ok_or("set up the test account first")?
                        .destination_npub
                        .clone();
                    self.control(&AdminRequest::Send {
                        destination,
                        payload,
                    })
                    .await
                }
                Finish => {
                    self.control(&AdminRequest::Settle).await?;
                    self.stop().await?;
                    self.wallet(WalletRequest::Balance).await
                }
            }
        })
    }

    async fn setup(&mut self, profile: CustomerProfile) -> Result<Value, String> {
        profile.validate()?;
        if let Some(saved) = &self.profile {
            if saved != &profile {
                return Err("saved test profile and spending limits cannot be replaced".into());
            }
            return self.status().await;
        }
        private_new(
            &self.root.join("profile.json"),
            &serde_json::to_vec(&profile).map_err(|e| e.to_string())?,
        )?;
        self.profile = Some(profile);
        RelayService::initialize(self.config()?).await?;
        self.status().await
    }

    async fn start(&mut self) -> Result<(), String> {
        if let Some(running) = &self.running {
            if running.stop.is_none() {
                return Err("customer service is still stopping".into());
            }
            if !running.task.is_finished() {
                return Ok(());
            }
            self.stop().await?;
        }
        let config = self.config()?;
        let service = RelayService::load(config.clone()).await?;
        let (stop, recv) = oneshot::channel::<()>();
        self.running = Some(Running {
            stop: Some(stop),
            task: tokio::spawn(service.serve(async {
                let _ = recv.await;
            })),
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if request(&config, &AdminRequest::Status).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "customer service did not become ready".to_string())
    }

    async fn stop(&mut self) -> Result<(), String> {
        let Some(running) = self.running.as_mut() else {
            return Ok(());
        };
        if let Some(stop) = running.stop.take() {
            let _ = stop.send(());
        }
        let outcome = tokio::time::timeout(Duration::from_secs(60), &mut running.task)
            .await
            .map_err(|_| {
                "customer service is still stopping; its account remains locked".to_string()
            })?;
        self.running = None;
        outcome.map_err(|_| "customer service task failed".to_string())?
    }

    async fn control(&self, command: &AdminRequest) -> Result<Value, String> {
        if self
            .running
            .as_ref()
            .is_none_or(|r| r.stop.is_none() || r.task.is_finished())
        {
            return Err("connect the customer service first".into());
        }
        request(&self.config()?, command).await
    }

    async fn wallet(&self, command: WalletRequest) -> Result<Value, String> {
        if self.running.is_some() {
            return Err("stop the customer service before using its wallet".into());
        }
        offline_wallet(&self.config()?, command).await
    }

    async fn status(&self) -> Result<Value, String> {
        let Some(profile) = &self.profile else {
            return Ok(json!({"configured":false,"running":false}));
        };
        let manifest: Value = read_json(&self.root.join("state/service.json"))?;
        let relay = if self.running.is_some() {
            self.control(&AdminRequest::Status).await?
        } else {
            Value::Null
        };
        Ok(
            json!({"configured":true,"running":self.running.is_some(),"npub":manifest["npub"],"profile":profile,"relay":relay}),
        )
    }
}

impl Drop for CustomerClient {
    fn drop(&mut self) {
        if let Some(running) = &mut self.running
            && let Some(stop) = running.stop.take()
        {
            let _ = stop.send(());
        }
    }
}
