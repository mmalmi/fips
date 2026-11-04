//! Process fixture intentionally uses only the published .117 public API.
//! Compile this unchanged file with either core revision for mixed-version tests.
use fips_core::{Config, FipsEndpoint};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compat_router_process() {
    let Some(path) = std::env::var_os("FIPS_COMPAT_ROUTER_CONFIG") else {
        return;
    };
    let config: Config = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .unwrap();
    std::fs::write(
        std::env::var_os("FIPS_COMPAT_ROUTER_READY").unwrap(),
        endpoint.npub(),
    )
    .unwrap();
    let stop = std::path::PathBuf::from(std::env::var_os("FIPS_COMPAT_ROUTER_STOP").unwrap());
    while !stop.exists() {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    endpoint.shutdown().await.unwrap();
}
