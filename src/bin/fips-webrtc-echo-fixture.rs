//! Local test fixture for TypeScript/Rust WebRTC interop.
//!
//! Starts a Rust FIPS endpoint with a WebSocket seed listener and WebRTC
//! transport, then echoes endpoint-data bytes back to the sender.

use clap::Parser;
use fips::config::{TransportInstances, WebSocketConfig};
use fips::{Config, FipsEndpoint, Identity, IdentityConfig, WebRtcConfig};
use serde_json::json;
use std::io::Write;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser, Debug)]
#[command(name = "fips-webrtc-echo-fixture", about = "FIPS WebRTC echo fixture")]
struct Args {
    /// Plain-WS listener address for the seed transport.
    #[arg(long, default_value = "127.0.0.1:0")]
    websocket_bind: String,

    /// Optional public WSS URL advertised separately from the bind address.
    #[arg(long)]
    websocket_public_url: Option<String>,

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
    config.node.discovery.nostr.enabled = false;
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        advertise_on_nostr: Some(false),
        auto_connect: Some(false),
        accept_connections: Some(true),
        connect_timeout_ms: Some(15_000),
        ice_gather_timeout_ms: Some(1_500),
        stun_servers: Some(Vec::new()),
        ..Default::default()
    });
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        bind_addr: Some(args.websocket_bind),
        public_url: args.websocket_public_url,
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

    let mut messages = Vec::with_capacity(32);
    while endpoint.recv_batch_into(&mut messages, 32).await.is_some() {
        for message in messages.drain(..) {
            let len = message.data.len();
            endpoint
                .send_batch_to_peer(message.source_peer, vec![message.data.into_vec()])
                .await?;
            println!("{}", json!({ "type": "echo", "bytes": len }));
            std::io::stdout().flush()?;
        }
    }

    Ok(())
}
