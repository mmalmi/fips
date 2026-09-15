#[cfg(unix)]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    if let Err(error) = run().await {
        eprintln!("fips-relay: {error}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
async fn run() -> Result<(), String> {
    use fips_relay::service::{AdminRequest, RelayService, ServiceConfig, native_request, request};
    use std::{io::Read, path::Path};
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: fips-relay <init|run|ctl|native|wallet> <config.json>; ctl/native/wallet read one JSON request from stdin"
                .into(),
        );
    }
    let config = ServiceConfig::read(Path::new(&args[2]))?;
    match args[1].as_str() {
        "init" => println!("{}", RelayService::initialize(config).await?),
        "run" => {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|e| e.to_string())?;
            let service = RelayService::load(config).await?;
            service
                .serve(async move {
                    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
                })
                .await?;
        }
        "ctl" | "native" => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 16 * 1024 {
                return Err("control request too large".into());
            }
            let value = if args[1] == "native" {
                let command =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid native control JSON")?;
                native_request(&config, &command).await?
            } else {
                let command: AdminRequest =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid control JSON")?;
                request(&config, &command).await?
            };
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|e| e.to_string())?
            );
        }
        "wallet" => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 64 * 1024 {
                return Err("wallet request too large".into());
            }
            let command = serde_json::from_slice(&bytes).map_err(|_| "invalid wallet JSON")?;
            let result = fips_relay::wallet_tools::offline_wallet(&config, command).await?;
            println!(
                "{}",
                serde_json::to_string(&result).map_err(|e| e.to_string())?
            );
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("fips-relay service requires Unix sockets");
    std::process::exit(1);
}
