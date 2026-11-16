//! Run the opt-in Cashu mint beside the relay. Keep the exact exported TCP
//! listener reserved across child restarts so another process cannot inherit
//! the mint URL when Core Lightning or the helper is temporarily unavailable.
use super::{LocalMintConfig, ServiceConfig};
use std::{
    net::TcpListener,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::oneshot,
    task::JoinHandle,
};

pub(super) const SERVICE_PORT: u16 = 44_745;

fn helper() -> Result<Command, String> {
    let path = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name("cashu-service-mint");
    let mut cmd = Command::new(path);
    cmd.kill_on_drop(true);
    Ok(cmd)
}

pub(super) async fn initialize(root: &Path, config: &LocalMintConfig) -> Result<(), String> {
    let status = helper()?
        .arg("init")
        .arg(root.join("mint"))
        .arg(config.mode())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .await
        .map_err(|e| {
            format!("start the cashu-service-mint helper installed beside the relay: {e}")
        })?;
    if !status.success() {
        return Err(format!("initialize local mint: {status}"));
    }
    Ok(())
}

struct Launcher {
    listener: TcpListener,
    directory: PathBuf,
    config: LocalMintConfig,
}

impl Launcher {
    async fn spawn(&self) -> Result<(Child, tokio::net::UnixStream), String> {
        let (host, worker) = UnixStream::pair().map_err(|e| e.to_string())?;
        host.set_nonblocking(true).map_err(|e| e.to_string())?;
        let mut host = tokio::net::UnixStream::from_std(host).map_err(|e| e.to_string())?;
        let listener = self.listener.try_clone().map_err(|e| e.to_string())?;
        let mut child = helper()?
            .arg("serve-managed")
            .arg(&self.directory)
            .arg(&self.config.cln_socket)
            .arg(self.config.mode())
            .stdin(Stdio::from(OwnedFd::from(listener)))
            .stdout(Stdio::from(OwnedFd::from(worker)))
            .spawn()
            .map_err(|e| format!("start cashu-service-mint: {e}"))?;
        if !matches!(
            tokio::time::timeout(Duration::from_secs(20), host.read_u8()).await,
            Ok(Ok(b'R'))
        ) {
            drop(host);
            let status = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Err(format!(
                "local mint did not start its Lightning monitor ({status:?})"
            ));
        }
        Ok((child, host))
    }
}

pub(crate) struct ManagedMint {
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), String>>,
}

impl ManagedMint {
    pub(super) async fn start(
        service: &ServiceConfig,
        config: &LocalMintConfig,
    ) -> Result<Self, String> {
        let address = crate::mint_mesh::local_address(&service.terms.controller.mint_url)?;
        let launcher = Launcher {
            listener: TcpListener::bind(address)
                .map_err(|e| format!("reserve local mint listener: {e}"))?,
            config: config.clone(),
            directory: service.state_directory.join("mint"),
        };
        let mut running = launcher.spawn().await?;
        let (stop, mut signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let (mut child, control) = running;
                tokio::select! {
                    _ = &mut signal => {
                        drop(control);
                        let status = tokio::time::timeout(Duration::from_secs(12), child.wait()).await
                            .map_err(|_| "local mint shutdown timed out")?.map_err(|e| e.to_string())?;
                        return if status.success() { Ok(()) } else { Err(format!("local mint shutdown: {status}")) };
                    }
                    status = child.wait() => tracing::warn!(?status, "local mint stopped; reconnecting"),
                }
                drop(control);
                // Never spin a failing Lightning node; permit prompt service shutdown.
                let mut delay = 1;
                loop {
                    tokio::select! {
                        _ = &mut signal => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
                    }
                    let attempt = tokio::select! {
                        _ = &mut signal => return Ok(()),
                        attempt = launcher.spawn() => attempt
                    };
                    match attempt {
                        Ok(child) => {
                            running = child;
                            break;
                        }
                        Err(error) => tracing::warn!(%error, "local mint restart failed"),
                    }
                    delay = (delay * 2).min(30);
                }
            }
        });
        Ok(Self { stop, task })
    }

    pub(super) async fn shutdown(self) -> Result<(), String> {
        let _ = self.stop.send(());
        self.task.await.map_err(|e| e.to_string())?
    }
}
