//! Loopback transit for testing old clients against a newer routing core.
//! Prints one ready JSON line, accepts {"peers":[{"npub":...,"udp_addresses":[...]}]},
//! acknowledges updates with {"updated":true}, and shuts down on stdin EOF.
use fips_core::config::{NostrDiscoveryPolicy, PeerConfig, RoutingMode, TransportInstances};
use fips_core::{Config, FipsEndpoint, UdpConfig};
use serde::Deserialize;
use std::io::{BufRead, Write};

#[derive(Deserialize)]
struct Command {
    peers: Vec<Peer>,
}

#[derive(Deserialize)]
struct Peer {
    npub: String,
    udp_addresses: Vec<std::net::SocketAddr>,
}

fn output(value: serde_json::Value) {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{value}").unwrap();
    stdout.flush().unwrap();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scope = std::env::args().nth(1).expect("fixture discovery scope");
    let mut config = Config::new();
    config.node.identity.persistent = false;
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.limits.max_peers = 18;
    config.node.limits.max_links = 36;
    config.node.limits.max_connections = 36;
    config.node.limits.max_pending_inbound = 72;
    config.node.control.enabled = false;
    config.tun.enabled = false;
    config.dns.enabled = false;
    config.node.system_files_enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.node.discovery.nostr.open_discovery_max_pending = 0;
    config.node.discovery.nostr.share_local_candidates = false;
    config.node.discovery.nostr.app = scope.clone();
    config.node.discovery.nostr.advert_relays.clear();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        advertise_on_nostr: Some(true),
        public: Some(false),
        outbound_only: Some(false),
        accept_connections: Some(true),
        ..UdpConfig::default()
    });
    config.transports.tcp = TransportInstances::Single(Default::default());
    assert_eq!(config.node.discovery.forward_min_interval_secs, 2);
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .discovery_scope(scope)
        .without_system_tun()
        .packet_channel_capacity(1024)
        .bind()
        .await?;
    output(serde_json::json!({
        "npub": endpoint.npub(),
        "udpAddress": endpoint.bound_udp_listen_addrs().await?[0].to_string(),
        "forwardMinIntervalSecs": 2,
        "maxPeers": 18,
    }));
    let (sender, mut commands) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if sender.blocking_send(line).is_err() {
                break;
            }
        }
    });
    while let Some(line) = commands.recv().await {
        let command: Command = serde_json::from_str(&line?)?;
        assert!(command.peers.len() <= 18);
        let mut peers = Vec::new();
        for peer in command.peers {
            assert_eq!(peer.udp_addresses.len(), 1);
            let addr = peer.udp_addresses[0];
            assert!(addr.ip().is_loopback());
            peers.push(PeerConfig::new(&peer.npub, "udp", addr.to_string()));
        }
        endpoint.update_peers(peers).await?;
        output(serde_json::json!({"updated": true}));
    }
    endpoint.shutdown().await?;
    Ok(())
}
