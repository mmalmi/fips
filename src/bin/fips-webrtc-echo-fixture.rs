//! Local test fixture for TypeScript/Rust WebRTC interop.
//!
//! Starts a Rust FIPS endpoint with only the WebRTC transport enabled, publishes
//! its advert on the supplied local Nostr relay, and echoes endpoint-data bytes
//! back to the sender.

use clap::Parser;
use fips::config::{NostrDiscoveryPolicy, TransportInstances};
use fips::{Config, FipsEndpoint, Identity, IdentityConfig, WebRtcConfig};
use serde_json::json;
use std::io::Write;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser, Debug)]
#[command(name = "fips-webrtc-echo-fixture", about = "FIPS WebRTC echo fixture")]
struct Args {
    /// Nostr relay URL used for WebRTC adverts and gift-wrapped signals.
    #[arg(long)]
    relay: String,

    /// Hex or nsec secret key for the fixture identity.
    #[arg(long)]
    secret: String,

    /// Discovery application scope.
    #[arg(long, default_value = "fips-overlay-v1")]
    app: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    let identity = Identity::from_secret_str(&args.secret)?;
    let pubkey_hex = hex::encode(identity.pubkey_full().serialize());

    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(args.secret.clone()),
        persistent: false,
    };
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.advert_relays = vec![args.relay.clone()];
    config.node.discovery.nostr.dm_relays = vec![args.relay.clone()];
    config.node.discovery.nostr.stun_servers = Vec::new();
    config.node.discovery.nostr.app = args.app.clone();
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        advertise_on_nostr: Some(true),
        auto_connect: Some(false),
        accept_connections: Some(true),
        connect_timeout_ms: Some(15_000),
        ice_gather_timeout_ms: Some(1_500),
        signal_relays: Some(vec![args.relay.clone()]),
        stun_servers: Some(Vec::new()),
        ..Default::default()
    });

    let endpoint = FipsEndpoint::builder()
        .config(config)
        .discovery_scope(args.app)
        .without_system_tun()
        .bind()
        .await?;

    println!(
        "{}",
        json!({
            "type": "ready",
            "npub": endpoint.npub(),
            "pubkeyHex": pubkey_hex,
        })
    );
    std::io::stdout().flush()?;

    while let Some(message) = endpoint.recv().await {
        if let Some(source_npub) = message.source_npub {
            let len = message.data.len();
            endpoint.send(source_npub, message.data).await?;
            println!("{}", json!({ "type": "echo", "bytes": len }));
            std::io::stdout().flush()?;
        }
    }

    Ok(())
}
