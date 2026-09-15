#[cfg(unix)]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter("warn")
        .init();
    if let Err(error) = run().await {
        eprintln!("fips-relay-test-mint: {error}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
async fn run() -> Result<(), String> {
    use fips_relay::testbench::{BenchConfig, BenchMint, request};
    use std::{io::Read, path::Path};
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: fips-relay-test-mint <run|ctl> <config.json>; ctl reads one JSON request from stdin".into());
    }
    let config = BenchConfig::read(Path::new(&args[2]))?;
    match args[1].as_str() {
        "run" => {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|e| e.to_string())?;
            let mint = BenchMint::start(config).await?;
            println!("{}", serde_json::json!({"test_only":true,"url":mint.url()}));
            mint.serve(async move {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            })
            .await
        }
        "ctl" => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 64 * 1024 {
                return Err("test-mint request too large".into());
            }
            let command = serde_json::from_slice(&bytes).map_err(|_| "invalid test-mint JSON")?;
            println!("{}", request(&config, &command).await?);
            Ok(())
        }
        _ => Err("unknown test-mint command".into()),
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("test-mint service requires Unix sockets");
    std::process::exit(1);
}
