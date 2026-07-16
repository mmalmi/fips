//! Active end-to-end health probe for a Nostr-discovered FIPS WebRTC peer.

use clap::Parser;
use fips::config::{
    NostrDiscoveryPolicy, NostrRelayConfig, PeerAddress, PeerConfig, TransportInstances,
};
use fips::nostr_relay_adapter::NostrRelayAdapter;
use fips::{Config, FipsEndpoint, PeerIdentity, WebRtcConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, timeout_at};
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;

const DEFAULT_TIMEOUT_SECONDS: u64 = 25;
const PING_INTERVAL: Duration = Duration::from_secs(1);
const PEER_POLL_INTERVAL: Duration = Duration::from_millis(100);
// `RTCPeerConnection::close` completes after scheduling parts of SCTP/DTLS/ICE
// teardown on the Tokio runtime. A short-lived probe that exits immediately can
// kill those tasks before the remote daemon observes the terminal close, leaving
// one gathered UDP socket set behind per probe.
const TERMINAL_WEBRTC_CLEANUP_SETTLE: Duration = Duration::from_millis(250);

#[derive(Parser, Debug)]
#[command(
    name = "fips-health-probe",
    about = "Probe a Nostr-discovered FIPS peer over WebRTC and FSP"
)]
struct Args {
    /// Target FIPS identity. The probe does not have a built-in target.
    #[arg(long, alias = "target")]
    target_npub: String,

    /// Nostr relay used for adverts and the initial FIPS relay path. Repeat or comma-separate.
    #[arg(long, value_delimiter = ',')]
    relay: Vec<String>,

    /// Nostr discovery application namespace.
    #[arg(long, default_value = "fips-overlay-v1")]
    app: String,

    /// Total bind, discovery, handshake, and echo timeout.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS)]
    timeout_seconds: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    match run(args).await {
        Ok(success) => println!(
            "fips-health-probe: healthy target={} transport=webrtc rtt_ms={}",
            success.target_npub,
            success.rtt.as_millis()
        ),
        Err(error) => {
            eprintln!("fips-health-probe: unhealthy: {error}");
            std::process::exit(1);
        }
    }
}

struct ProbeSuccess {
    target_npub: String,
    rtt: Duration,
}

async fn run(args: Args) -> Result<ProbeSuccess, String> {
    if args.timeout_seconds == 0 {
        return Err("--timeout-seconds must be greater than zero".to_string());
    }
    let target = PeerIdentity::from_npub(args.target_npub.trim())
        .map_err(|error| format!("invalid target npub: {error}"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout_seconds);
    let identity_secret = std::env::var("FIPS_HEALTH_SECRET")
        .ok()
        .map(|secret| secret.trim().to_string())
        .filter(|secret| !secret.is_empty());
    let config = probe_config(
        &target,
        &args.relay,
        &args.app,
        args.timeout_seconds,
        identity_secret.as_deref(),
    );
    let relay_urls = config.node.discovery.nostr.advert_relays.clone();
    let target_npub = target.npub();

    let endpoint = Arc::new(
        timeout_at(
            deadline,
            FipsEndpoint::builder()
                .config(config)
                .without_system_tun()
                .bind(),
        )
        .await
        .map_err(|_| "timed out starting ephemeral FIPS endpoint".to_string())?
        .map_err(|error| format!("could not start ephemeral FIPS endpoint: {error}"))?,
    );
    let relay_adapter = NostrRelayAdapter::start(Arc::clone(&endpoint), &relay_urls)
        .await
        .map_err(|error| format!("could not start FIPS relay adapter: {error}"))?;

    let probe_result = match timeout_at(deadline, probe_target(&endpoint, target)).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "target {target_npub} did not complete WebRTC/FMP/FSP echo within {}s",
            args.timeout_seconds
        )),
    };
    if let Some(adapter) = relay_adapter {
        adapter.stop().await;
    }
    let shutdown_result = endpoint.shutdown().await;
    settle_terminal_webrtc_cleanup().await;
    if let Err(error) = shutdown_result {
        return Err(format!(
            "probe completed but endpoint shutdown failed: {error}"
        ));
    }

    probe_result.map(|rtt| ProbeSuccess { target_npub, rtt })
}

async fn settle_terminal_webrtc_cleanup() {
    tokio::time::sleep(TERMINAL_WEBRTC_CLEANUP_SETTLE).await;
}

fn probe_config(
    target: &PeerIdentity,
    relays: &[String],
    app: &str,
    timeout_secs: u64,
    identity_secret: Option<&str>,
) -> Config {
    let mut config = Config::new();
    config.node.identity.persistent = false;
    config.node.identity.nsec = identity_secret.map(ToOwned::to_owned);
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = false;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.node.discovery.nostr.app = app.to_string();
    config.node.discovery.nostr.share_local_candidates = false;
    config.node.retry.max_retries = timeout_secs.max(1).min(u64::from(u32::MAX)) as u32;
    config.node.retry.base_interval_secs = 1;
    config.node.retry.max_backoff_secs = 1;
    if !relays.is_empty() {
        config.node.discovery.nostr.advert_relays = relays.to_vec();
    }

    let connect_timeout_ms = timeout_secs.saturating_mul(1_000).clamp(1_000, 15_000);
    config.transports.webrtc = TransportInstances::Single(WebRtcConfig {
        advertise_on_nostr: Some(false),
        auto_connect: Some(true),
        accept_connections: Some(false),
        max_connections: Some(1),
        connect_timeout_ms: Some(connect_timeout_ms),
        ice_gather_timeout_ms: Some(5_000),
        ..Default::default()
    });
    config.transports.nostr_relay = TransportInstances::Single(NostrRelayConfig::default());
    config.peers = vec![PeerConfig {
        npub: target.npub(),
        addresses: vec![
            PeerAddress::with_priority(
                "webrtc",
                hex::encode(target.pubkey_full().serialize()),
                100,
            ),
            PeerAddress::with_priority("nostr_relay", target.npub(), 250),
        ],
        // The first WebRTC offer can precede relay-carrier authentication on
        // a freshly started or busy daemon. Keep retrying the direct upgrade
        // after the relay fallback becomes active.
        auto_reconnect: true,
        discovery_fallback_transit: false,
        ..Default::default()
    }];
    config
}

async fn probe_target(endpoint: &FipsEndpoint, target: PeerIdentity) -> Result<Duration, String> {
    wait_for_authenticated_webrtc(endpoint, target).await?;

    let nonce = Uuid::new_v4().into_bytes().to_vec();
    let started = Instant::now();
    let mut ping_tick = tokio::time::interval(PING_INTERVAL);
    ping_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut messages = Vec::with_capacity(8);

    loop {
        tokio::select! {
            _ = ping_tick.tick() => endpoint
                .send_batch_to_peer(target, vec![nonce.clone()])
                .await
                .map_err(|error| format!("FSP echo send failed: {error}"))?,
            received = endpoint.recv_batch_into(&mut messages, 8) => {
                received.ok_or_else(|| {
                    "ephemeral endpoint closed before receiving FSP echo".to_string()
                })?;
                if messages.drain(..).any(|message| {
                    message.source_peer.node_addr() == target.node_addr()
                        && message.data.as_slice() == nonce.as_slice()
                }) {
                    return Ok(started.elapsed());
                }
            }
        }
    }
}

async fn wait_for_authenticated_webrtc(
    endpoint: &FipsEndpoint,
    target: PeerIdentity,
) -> Result<(), String> {
    let mut poll = tokio::time::interval(PEER_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        poll.tick().await;
        let peers = endpoint
            .peers()
            .await
            .map_err(|error| format!("peer state query failed: {error}"))?;
        if let Some(peer) = peers
            .iter()
            .find(|peer| peer.node_addr == *target.node_addr() && peer.connected)
            && peer.transport_type.as_deref() == Some("webrtc")
        {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn successful_probe_keeps_runtime_alive_for_detached_terminal_cleanup() {
        let cleanup_finished = Arc::new(AtomicBool::new(false));
        let cleanup_flag = Arc::clone(&cleanup_finished);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            cleanup_flag.store(true, Ordering::SeqCst);
        });

        settle_terminal_webrtc_cleanup().await;

        assert!(
            cleanup_finished.load(Ordering::SeqCst),
            "the short-lived probe must not exit while detached WebRTC cleanup is pending"
        );
    }

    #[test]
    fn probe_config_is_targeted_and_bootstraps_webrtc_over_relay() {
        let target_identity = fips::Identity::generate();
        let target = PeerIdentity::from_pubkey_full(target_identity.pubkey_full());
        let target_npub = target.npub();
        let relay = "wss://relay.example".to_string();
        let config = probe_config(&target, std::slice::from_ref(&relay), "health", 20, None);

        assert!(!config.node.identity.persistent);
        assert!(!config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::ConfiguredOnly
        );
        assert_eq!(config.node.discovery.nostr.advert_relays, vec![relay]);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].npub, target_npub);
        assert_eq!(config.peers[0].addresses.len(), 2);
        assert_eq!(config.peers[0].addresses[0].transport, "webrtc");
        assert_eq!(
            config.peers[0].addresses[0].addr,
            hex::encode(target_identity.pubkey_full().serialize())
        );
        assert_eq!(config.peers[0].addresses[1].transport, "nostr_relay");
        assert_eq!(config.peers[0].addresses[1].addr, target_npub);
        assert!(
            config.peers[0].auto_reconnect,
            "relay bootstrap must keep retrying the direct WebRTC upgrade"
        );
        assert!(config.transports.udp.is_empty());
        assert!(!config.transports.nostr_relay.is_empty());
        let TransportInstances::Single(webrtc) = config.transports.webrtc else {
            panic!("probe must configure exactly one WebRTC transport");
        };
        assert!(webrtc.auto_connect());
        assert!(!webrtc.accept_connections());
        assert!(!webrtc.advertise_on_nostr());
    }

    #[test]
    fn configured_health_secret_makes_probe_identity_stable() {
        let target_identity = fips::Identity::generate();
        let target = PeerIdentity::from_pubkey_full(target_identity.pubkey_full());
        let probe_identity = fips::Identity::generate();
        let secret = hex::encode(probe_identity.keypair().secret_bytes());
        let config = probe_config(&target, &[], "health", 20, Some(&secret));

        assert_eq!(config.node.identity.nsec.as_deref(), Some(secret.as_str()));
        let resolved = fips::Identity::from_secret_str(
            config.node.identity.nsec.as_deref().expect("health secret"),
        )
        .expect("configured health identity must resolve");
        assert_eq!(resolved.npub(), probe_identity.npub());
    }
}
