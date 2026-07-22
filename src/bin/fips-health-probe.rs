//! Active end-to-end health probe for a WSS-seeded FIPS WebRTC peer.

use clap::Parser;
use fips::config::{PeerAddress, PeerConfig, TransportInstances, WebSocketConfig};
use fips::{Config, FipsEndpoint, PeerIdentity, WebRtcConfig};
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, timeout_at};
use tracing_subscriber::{EnvFilter, fmt};

const ICMPV6_NEXT_HEADER: u8 = 58;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const IPV6_HEADER_LEN: usize = 40;
const ICMPV6_HEADER_LEN: usize = 8;
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
    about = "Probe a WSS-seeded FIPS peer over WebRTC and FSP"
)]
struct Args {
    /// Target FIPS identity. The probe does not have a built-in target.
    #[arg(long, alias = "target")]
    target_npub: String,

    /// WSS seed URL for the target. Repeat or comma-separate.
    #[arg(long = "seed-url", value_delimiter = ',', required = true)]
    seed_urls: Vec<String>,

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
        &args.seed_urls,
        args.timeout_seconds,
        identity_secret.as_deref(),
    );
    let target_npub = target.npub();

    let endpoint = timeout_at(
        deadline,
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind(),
    )
    .await
    .map_err(|_| "timed out starting ephemeral FIPS endpoint".to_string())?
    .map_err(|error| format!("could not start ephemeral FIPS endpoint: {error}"))?;
    let probe_result = match timeout_at(deadline, probe_target(&endpoint, target)).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "target {target_npub} did not complete WebRTC/FMP/FSP echo within {}s",
            args.timeout_seconds
        )),
    };
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
    seed_urls: &[String],
    timeout_secs: u64,
    identity_secret: Option<&str>,
) -> Config {
    let mut config = Config::new();
    config.node.identity.persistent = false;
    config.node.identity.nsec = identity_secret.map(ToOwned::to_owned);
    config.node.discovery.nostr.enabled = false;
    config.node.retry.max_retries = timeout_secs.max(1).min(u64::from(u32::MAX)) as u32;
    config.node.retry.base_interval_secs = 1;
    config.node.retry.max_backoff_secs = 1;
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
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        seed_urls: seed_urls.to_vec(),
        max_connections: Some(seed_urls.len().max(1)),
        ..Default::default()
    });
    config.peers = vec![PeerConfig {
        npub: target.npub(),
        addresses: vec![
            PeerAddress::with_priority(
                "webrtc",
                hex::encode(target.pubkey_full().serialize()),
                100,
            ),
            PeerAddress::with_priority("websocket", seed_urls[0].clone(), 200),
        ],
        // Keep retrying the direct upgrade after the WSS adjacency is active.
        auto_reconnect: true,
        discovery_fallback_transit: false,
        ..Default::default()
    }];
    config
}

async fn probe_target(endpoint: &FipsEndpoint, target: PeerIdentity) -> Result<Duration, String> {
    wait_for_authenticated_webrtc(endpoint, target).await?;

    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let identifier = u16::from_be_bytes([nonce[0], nonce[1]]);
    let sequence = u16::from_be_bytes([nonce[2], nonce[3]]);
    let request = build_echo_request(
        endpoint.address().to_ipv6(),
        target.address().to_ipv6(),
        identifier,
        sequence,
        &nonce,
    );
    let started = Instant::now();
    let mut ping_tick = tokio::time::interval(PING_INTERVAL);
    ping_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ping_tick.tick() => endpoint
                .send_ip_packet(request.clone())
                .await
                .map_err(|error| format!("FSP echo send failed: {error}"))?,
            delivered = endpoint.recv_ip_packet() => {
                let delivered = delivered.ok_or_else(|| {
                    "ephemeral endpoint closed before receiving FSP echo".to_string()
                })?;
                if delivered.source_node_addr == *target.node_addr()
                    && echo_reply_matches(
                        &delivered.packet,
                        target.address().to_ipv6(),
                        endpoint.address().to_ipv6(),
                        identifier,
                        sequence,
                        &nonce,
                    )
                {
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
        if peers
            .iter()
            .any(|peer| is_authenticated_webrtc_peer(peer, &target))
        {
            return Ok(());
        }
    }
}

fn is_authenticated_webrtc_peer(
    peer: &fips::endpoint::FipsEndpointPeer,
    target: &PeerIdentity,
) -> bool {
    // Peer snapshots only contain authenticated node peers. A newly promoted
    // alternate path may not yet have a post-handshake receive sample, so its
    // liveness-oriented `connected` flag remains false until the first FMP/FSP
    // packet. Start the echo at promotion; the echo itself proves liveness.
    peer.node_addr == *target.node_addr() && peer.transport_type.as_deref() == Some("webrtc")
}

fn build_echo_request(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = ICMPV6_HEADER_LEN + payload.len();
    let mut packet = vec![0u8; IPV6_HEADER_LEN + icmp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    packet[6] = ICMPV6_NEXT_HEADER;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40] = ICMPV6_ECHO_REQUEST;
    packet[44..46].copy_from_slice(&identifier.to_be_bytes());
    packet[46..48].copy_from_slice(&sequence.to_be_bytes());
    packet[48..].copy_from_slice(payload);
    let checksum = icmpv6_checksum(&packet[40..], source, destination);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn echo_reply_matches(
    packet: &[u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> bool {
    if packet.len() != IPV6_HEADER_LEN + ICMPV6_HEADER_LEN + payload.len()
        || packet[0] >> 4 != 6
        || packet[6] != ICMPV6_NEXT_HEADER
        || packet[8..24] != source.octets()
        || packet[24..40] != destination.octets()
        || packet[40] != ICMPV6_ECHO_REPLY
        || packet[41] != 0
        || packet[44..46] != identifier.to_be_bytes()
        || packet[46..48] != sequence.to_be_bytes()
        || packet[48..] != *payload
    {
        return false;
    }
    let stored = u16::from_be_bytes([packet[42], packet[43]]);
    icmpv6_checksum(&packet[40..], source, destination) == stored
}

fn icmpv6_checksum(message: &[u8], source: Ipv6Addr, destination: Ipv6Addr) -> u16 {
    let mut sum = 0u64;
    add_words(&mut sum, &source.octets());
    add_words(&mut sum, &destination.octets());
    sum += message.len() as u64;
    sum += u64::from(ICMPV6_NEXT_HEADER);
    for (index, chunk) in message.chunks(2).enumerate() {
        if index == 1 {
            continue;
        }
        sum += if chunk.len() == 2 {
            u64::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        } else {
            u64::from(chunk[0]) << 8
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn add_words(sum: &mut u64, bytes: &[u8]) {
    for chunk in bytes.chunks_exact(2) {
        *sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
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
    fn probe_config_is_targeted_and_bootstraps_webrtc_over_websocket() {
        let target_identity = fips::Identity::generate();
        let target = PeerIdentity::from_pubkey_full(target_identity.pubkey_full());
        let target_npub = target.npub();
        let seed = "wss://seed.example/fips".to_string();
        let config = probe_config(&target, std::slice::from_ref(&seed), 20, None);

        assert!(!config.node.identity.persistent);
        assert!(!config.node.discovery.nostr.enabled);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].npub, target_npub);
        assert_eq!(config.peers[0].addresses.len(), 2);
        assert_eq!(config.peers[0].addresses[0].transport, "webrtc");
        assert_eq!(
            config.peers[0].addresses[0].addr,
            hex::encode(target_identity.pubkey_full().serialize())
        );
        assert_eq!(config.peers[0].addresses[1].transport, "websocket");
        assert_eq!(config.peers[0].addresses[1].addr, seed);
        assert!(
            config.peers[0].auto_reconnect,
            "WSS bootstrap must keep retrying the direct WebRTC upgrade"
        );
        assert!(config.transports.udp.is_empty());
        assert!(!config.transports.websocket.is_empty());
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
        let config = probe_config(
            &target,
            &["wss://seed.example/fips".into()],
            20,
            Some(&secret),
        );

        assert_eq!(config.node.identity.nsec.as_deref(), Some(secret.as_str()));
        let resolved = fips::Identity::from_secret_str(
            config.node.identity.nsec.as_deref().expect("health secret"),
        )
        .expect("configured health identity must resolve");
        assert_eq!(resolved.npub(), probe_identity.npub());
    }

    fn reply_for(request: &[u8]) -> Vec<u8> {
        let mut reply = request.to_vec();
        let source: [u8; 16] = request[8..24].try_into().unwrap();
        let destination: [u8; 16] = request[24..40].try_into().unwrap();
        reply[8..24].copy_from_slice(&destination);
        reply[24..40].copy_from_slice(&source);
        reply[40] = ICMPV6_ECHO_REPLY;
        reply[42..44].fill(0);
        let checksum = icmpv6_checksum(
            &reply[40..],
            Ipv6Addr::from(destination),
            Ipv6Addr::from(source),
        );
        reply[42..44].copy_from_slice(&checksum.to_be_bytes());
        reply
    }

    #[test]
    fn echo_match_requires_exact_reply_identity_and_payload() {
        let source = "fd00::1".parse().unwrap();
        let destination = "fd00::2".parse().unwrap();
        let payload = b"functional-fsp-probe";
        let request = build_echo_request(source, destination, 7, 9, payload);
        let mut reply = reply_for(&request);

        assert!(echo_reply_matches(
            &reply,
            destination,
            source,
            7,
            9,
            payload
        ));
        reply[48] ^= 1;
        assert!(!echo_reply_matches(
            &reply,
            destination,
            source,
            7,
            9,
            payload
        ));
    }
}
