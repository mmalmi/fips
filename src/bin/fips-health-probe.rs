//! Active end-to-end health probe for a WSS-seeded FIPS WebRTC peer.

use clap::Parser;
use fips::config::{PeerAddress, PeerConfig, TransportInstances, WebSocketConfig};
use fips::{Config, FipsEndpoint, PeerIdentity, WebRtcConfig};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, timeout_at};
use tracing_subscriber::prelude::*;
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
    let pipeline = PipelineTrace::default();
    let setup = SetupTrace::default();
    let _ = tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(EnvFilter::from_default_env()),
        )
        .with(
            pipeline
                .clone()
                .with_filter(tracing_subscriber::filter::filter_fn(
                    pipeline_event_enabled,
                )),
        )
        .with(
            setup
                .clone()
                .with_filter(tracing_subscriber::filter::filter_fn(
                    pipeline_event_enabled,
                )),
        )
        .try_init();

    match run(args, &pipeline, &setup).await {
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

// Observe existing local-node events only: fixed counters/timings, never event
// fields, identities, packet contents or free-form errors. No library API or
// packet-path behavior changes are required to distinguish FSP setup progress.
const PIPELINE_EVENTS: [&str; 16] = [
    "Session initiation started",
    "SessionSetup processed (XK), SessionAck sent, awaiting msg3",
    "Session established (initiator, XK)",
    "Session established (responder, XK)",
    "Resent session handshake",
    "Session handshake resend failed",
    "Session handshake timed out, removing",
    "Session handshake resend budget exhausted",
    "Failed to process Noise XK msg2 in SessionAck",
    "SessionAck for unknown session",
    "SessionAck but session not in Initiating state",
    "Failed to send SessionMsg3",
    "SessionSetup rate limited",
    "Session table full, refusing new session",
    "Failed to deliver packet to external app sink",
    "SessionMsg3 for unknown session",
];

struct PipelineCounters {
    started: Instant,
    counts: [u32; 16],
    first_ms: [u64; 16],
    last_ms: [u64; 16],
}

#[derive(Clone)]
struct PipelineTrace(Arc<Mutex<PipelineCounters>>);

fn pipeline_event_enabled(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_event()
        && metadata.target().starts_with("fips_core::")
        && *metadata.level() <= tracing::Level::DEBUG
}

impl Default for PipelineTrace {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(PipelineCounters {
            started: Instant::now(),
            counts: [0; 16],
            first_ms: [0; 16],
            last_ms: [0; 16],
        })))
    }
}

#[derive(Default)]
struct PipelineField(Option<usize>);

impl tracing::field::Visit for PipelineField {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let message = format!("{value:?}");
            self.0 = PIPELINE_EVENTS.iter().position(|item| *item == message);
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PipelineTrace {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut field = PipelineField::default();
        event.record(&mut field);
        let Some(index) = field.0 else { return };
        let mut counters = self.0.lock().unwrap();
        let elapsed = counters.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        if counters.counts[index] == 0 {
            counters.first_ms[index] = elapsed;
        }
        counters.counts[index] = counters.counts[index].saturating_add(1);
        counters.last_ms[index] = elapsed;
    }
}

impl std::fmt::Display for PipelineTrace {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let counters = self.0.lock().unwrap();
        let list = |values: &[u64; 16]| {
            values
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join("/")
        };
        let counts = counters.counts.map(u64::from);
        write!(
            out,
            "counts={},first_ms={},last_ms={}",
            list(&counts),
            list(&counters.first_ms),
            list(&counters.last_ms)
        )
    }
}

const SETUP_ATTEMPT_LIMIT: usize = 8;
const SETUP_EVENT_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupEvent {
    FspDeferred,
    OfferQueued,
    AnswerReceived,
    AnswerApplied,
    ChannelOpen,
    PendingTimeout,
    OutboundOfferFailed,
    InboundAnswerFailed,
    ApplyAnswerFailed,
    ConnectionFailed,
    AuthToEcho,
}

impl SetupEvent {
    fn label(self) -> &'static str {
        match self {
            Self::FspDeferred => "fsp_deferred",
            Self::OfferQueued => "offer_queued",
            Self::AnswerReceived => "answer_received",
            Self::AnswerApplied => "answer_applied",
            Self::ChannelOpen => "channel_open",
            Self::PendingTimeout => "pending_timeout",
            Self::OutboundOfferFailed => "outbound_offer_failed",
            Self::InboundAnswerFailed => "inbound_answer_failed",
            Self::ApplyAnswerFailed => "apply_answer_failed",
            Self::ConnectionFailed => "connection_failed",
            Self::AuthToEcho => "auth_to_echo",
        }
    }
}

#[derive(Default)]
struct SetupTimeline {
    // Same monotonic origin/deadline as bind, authentication and echo.
    clock: Option<(tokio::time::Instant, tokio::time::Instant)>,
    // Transient equality keys only; never formatted into diagnostic output.
    // Ordinals correlate observed IDs, not target identity or auth ownership.
    attempts: Vec<String>,
    events: Vec<(u64, SetupEvent, Option<usize>)>,
    attempt_overflow: bool,
    event_overflow: bool,
    auth_to_echo: Option<(u64, u64)>,
}

#[derive(Clone, Default)]
struct SetupTrace(Arc<Mutex<SetupTimeline>>);

fn setup_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

impl SetupTimeline {
    fn record(
        &mut self,
        event: SetupEvent,
        negotiation: Option<String>,
        now: tokio::time::Instant,
    ) {
        let Some((started, deadline)) = self.clock else {
            return;
        };
        let elapsed = setup_ms(now.saturating_duration_since(started));
        if event == SetupEvent::AuthToEcho {
            // Preserve the direct milestone even if earlier events filled the timeline.
            self.auth_to_echo = Some((elapsed, setup_ms(deadline.saturating_duration_since(now))));
        }
        let attempt = negotiation.filter(|id| !id.is_empty()).and_then(|id| {
            if let Some(index) = self.attempts.iter().position(|known| *known == id) {
                Some(index + 1)
            } else if self.attempts.len() < SETUP_ATTEMPT_LIMIT {
                self.attempts.push(id);
                Some(self.attempts.len())
            } else {
                self.attempt_overflow = true;
                None
            }
        });
        if self.events.len() < SETUP_EVENT_LIMIT {
            self.events.push((elapsed, event, attempt));
        } else {
            self.event_overflow = true;
        }
    }
}

impl SetupTrace {
    fn begin(&self, started: tokio::time::Instant, deadline: tokio::time::Instant) {
        self.0.lock().unwrap().clock = Some((started, deadline));
    }

    fn auth_to_echo(&self) {
        // The authenticated peer snapshot has no negotiation ID; keep it unbound.
        let mut timeline = self.0.lock().unwrap();
        timeline.record(SetupEvent::AuthToEcho, None, tokio::time::Instant::now());
    }
}

// Read only a named field, with bounded formatting. A first pass classifies the
// fixed message; only recognized events may read kind/stage/negotiation. Other
// fields (addresses, SDP, errors, certificates, etc.) are never formatted.
struct SetupField {
    name: &'static str,
    value: String,
    overflow: bool,
}

impl std::fmt::Write for SetupField {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        if self.value.len() + value.len() > 96 {
            self.overflow = true;
            return Err(std::fmt::Error);
        }
        self.value.push_str(value);
        Ok(())
    }
}

impl tracing::field::Visit for SetupField {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == self.name {
            let _ = std::fmt::Write::write_str(self, value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == self.name {
            use std::fmt::Write;
            let _ = write!(self, "{value:?}");
        }
    }
}

fn setup_field(event: &tracing::Event<'_>, name: &'static str) -> Option<String> {
    let mut field = SetupField {
        name,
        value: String::new(),
        overflow: false,
    };
    event.record(&mut field);
    (!field.overflow).then_some(field.value)
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SetupTrace {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let Some(message) = setup_field(event, "message") else {
            return;
        };
        let kind = match message.as_str() {
            "Deferring mesh traversal signal until end-to-end session is established" => {
                SetupEvent::FspDeferred
            }
            "WebRTC offer sent" => SetupEvent::OfferQueued,
            // This event precedes signal validation; it is not answer acceptance.
            "WebRTC signal received" if setup_field(event, "kind").as_deref() == Some("Answer") => {
                SetupEvent::AnswerReceived
            }
            "WebRTC answer applied" => SetupEvent::AnswerApplied,
            "WebRTC data channel open" => SetupEvent::ChannelOpen,
            "WebRTC connection failed" | "WebRTC negotiation failed" => {
                match setup_field(event, "stage").as_deref() {
                    Some("pending-before-data-channel-open") => SetupEvent::PendingTimeout,
                    Some("outbound-offer-before-data-channel-open") => {
                        SetupEvent::OutboundOfferFailed
                    }
                    Some("inbound-answer-before-data-channel-open") => {
                        SetupEvent::InboundAnswerFailed
                    }
                    Some("apply-answer-before-data-channel-open") => SetupEvent::ApplyAnswerFailed,
                    _ => SetupEvent::ConnectionFailed,
                }
            }
            _ => return,
        };
        // These events have no negotiation association. Never infer one from
        // recency, peer address, or the most recent successful answer.
        let negotiation = if matches!(kind, SetupEvent::FspDeferred | SetupEvent::ChannelOpen) {
            None
        } else {
            setup_field(event, "negotiation")
        };
        let mut timeline = self.0.lock().unwrap();
        timeline.record(kind, negotiation, tokio::time::Instant::now());
    }
}

impl std::fmt::Display for SetupTrace {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let timeline = self.0.lock().unwrap();
        let scalar = |value: Option<u64>| value.map_or_else(|| "unknown".into(), |v| v.to_string());
        write!(
            out,
            "v=1,end_ms={},attempts={},attempt_overflow={},event_overflow={},auth_ms={},echo_budget_ms={},events=",
            scalar(
                timeline
                    .clock
                    .map(|(started, _)| setup_ms(started.elapsed()))
            ),
            timeline.attempts.len(),
            timeline.attempt_overflow,
            timeline.event_overflow,
            scalar(timeline.auth_to_echo.map(|(elapsed, _)| elapsed)),
            scalar(timeline.auth_to_echo.map(|(_, budget)| budget))
        )?;
        for (index, (elapsed, kind, attempt)) in timeline.events.iter().enumerate() {
            if index != 0 {
                write!(out, "/")?;
            }
            write!(
                out,
                "{elapsed}:{}:{}",
                kind.label(),
                attempt.map_or_else(|| "unbound".into(), |v| v.to_string())
            )?;
        }
        Ok(())
    }
}

// Kept outside the timed future so cancellation cannot erase a pending query.
// Observes only the existing peer-snapshot loop and emits no peer data.
// Carrier flags are cumulative ever-seen values, not the latest snapshot state.
// The successful-snapshot age measures query completion, not carrier recency.
#[derive(Default)]
struct InitialAuthProgress {
    snapshots_started: u32,
    snapshots_completed: u32,
    snapshot_errors: u32,
    last_snapshot_error: Option<&'static str>,
    snapshot_started_at: Option<Instant>,
    max_snapshot_elapsed: Duration,
    last_successful_snapshot_at: Option<Instant>,
    target_websocket_seen: Option<bool>,
    target_webrtc_seen: Option<bool>,
}

impl InitialAuthProgress {
    fn start_snapshot(&mut self) {
        self.snapshots_started += 1;
        self.snapshot_started_at = Some(Instant::now());
    }

    fn complete_snapshot(&mut self, result: Result<Option<&str>, &fips::FipsEndpointError>) {
        self.snapshots_completed += 1;
        if let Some(started) = self.snapshot_started_at.take() {
            self.max_snapshot_elapsed = self.max_snapshot_elapsed.max(started.elapsed());
        }
        match result {
            Ok(transport) => {
                self.last_successful_snapshot_at = Some(Instant::now());
                self.target_websocket_seen = Some(
                    self.target_websocket_seen.unwrap_or(false) || transport == Some("websocket"),
                );
                self.target_webrtc_seen =
                    Some(self.target_webrtc_seen.unwrap_or(false) || transport == Some("webrtc"));
            }
            Err(error) => {
                self.snapshot_errors += 1;
                self.last_snapshot_error = Some(match error {
                    fips::FipsEndpointError::Timeout { .. } => "timeout",
                    fips::FipsEndpointError::Closed => "closed",
                    _ => "other",
                });
            }
        }
    }
}

impl std::fmt::Display for InitialAuthProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flag = |value| match value {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        };
        let successful_age = self.last_successful_snapshot_at.map_or_else(
            || "unknown".to_string(),
            |at| at.elapsed().as_millis().to_string(),
        );
        write!(
            f,
            "snapshots_started={},snapshots_completed={},snapshot_errors={},last_snapshot_error={},max_snapshot_ms={},pending_snapshot_ms={},last_successful_snapshot_age_ms={},target_websocket_seen={},target_webrtc_seen={}",
            self.snapshots_started,
            self.snapshots_completed,
            self.snapshot_errors,
            self.last_snapshot_error.unwrap_or("none"),
            self.max_snapshot_elapsed.as_millis(),
            self.snapshot_started_at
                .map_or(0, |at| at.elapsed().as_millis()),
            successful_age,
            flag(self.target_websocket_seen),
            flag(self.target_webrtc_seen),
        )
    }
}

// Kept outside the timed future, as with authentication progress. A completed
// send means local submission only, not delivery; no packet contents are kept.
#[derive(Default)]
struct EchoProgress {
    started_at: Option<Instant>,
    sends_started: u32,
    sends_completed: u32,
    send_errors: u32,
    send_started_at: Option<Instant>,
    max_send_elapsed: Duration,
    received_packets: u64,
    target_packets: u64,
}

impl EchoProgress {
    fn start_send(&mut self) {
        self.sends_started += 1;
        self.send_started_at = Some(Instant::now());
    }

    fn complete_send(&mut self, succeeded: bool) {
        self.sends_completed += 1;
        self.send_errors += u32::from(!succeeded);
        if let Some(started) = self.send_started_at.take() {
            self.max_send_elapsed = self.max_send_elapsed.max(started.elapsed());
        }
    }
}

impl std::fmt::Display for EchoProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let now = Instant::now();
        write!(
            f,
            "elapsed_ms={},sends_started={},sends_completed={},send_errors={},max_send_ms={},pending_send_ms={},received_packets={},target_packets={}",
            self.started_at
                .map_or(0, |at| now.saturating_duration_since(at).as_millis()),
            self.sends_started,
            self.sends_completed,
            self.send_errors,
            self.max_send_elapsed.as_millis(),
            self.send_started_at
                .map_or(0, |at| now.saturating_duration_since(at).as_millis()),
            self.received_packets,
            self.target_packets
        )
    }
}

async fn run(
    args: Args,
    pipeline: &PipelineTrace,
    setup: &SetupTrace,
) -> Result<ProbeSuccess, String> {
    if args.timeout_seconds == 0 {
        return Err("--timeout-seconds must be greater than zero".to_string());
    }
    let target = PeerIdentity::from_npub(args.target_npub.trim())
        .map_err(|error| format!("invalid target npub: {error}"))?;
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(args.timeout_seconds);
    setup.begin(started, deadline);
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
    let mut phase = "webrtc_authentication";
    let mut auth_progress = InitialAuthProgress::default();
    let mut echo_progress = EchoProgress::default();
    let probe_result = match timeout_at(
        deadline,
        probe_target(
            &endpoint,
            target,
            &mut phase,
            &mut auth_progress,
            &mut echo_progress,
            setup,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!(
            "target {target_npub} did not complete WebRTC/FMP/FSP echo within {}s; phase={phase}",
            args.timeout_seconds
        )),
    };
    let probe_result = probe_result.map_err(|error| {
        format_probe_failure(error, phase, &auth_progress, &echo_progress, pipeline)
    });
    // Snapshot before shutdown/cleanup. Preserve the existing final-result format.
    eprintln!("fips-health-phase-summary: setup_progress=[{setup}]");
    let shutdown_result = endpoint.shutdown().await;
    settle_terminal_webrtc_cleanup().await;
    finish_probe_result(probe_result, shutdown_result).map(|rtt| ProbeSuccess { target_npub, rtt })
}

fn format_probe_failure(
    error: String,
    phase: &str,
    auth_progress: &InitialAuthProgress,
    echo_progress: &EchoProgress,
    pipeline: &PipelineTrace,
) -> String {
    if phase == "webrtc_authentication" {
        // WebRTC negotiation uses FIPS sessions before the echo begins.
        // These local events distinguish session setup from remote delivery.
        format!("{error}; auth_progress=[{auth_progress}]; pipeline_progress=[{pipeline}]")
    } else {
        format!("{error}; echo_progress=[{echo_progress}]; pipeline_progress=[{pipeline}]")
    }
}

fn finish_probe_result(
    probe_result: Result<Duration, String>,
    shutdown_result: Result<(), fips::FipsEndpointError>,
) -> Result<Duration, String> {
    match (probe_result, shutdown_result) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(format!(
            "probe completed but endpoint shutdown failed: {error}"
        )),
        (Err(probe_error), Err(error)) => {
            Err(format!("{probe_error}; endpoint shutdown failed: {error}"))
        }
    }
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

async fn probe_target(
    endpoint: &FipsEndpoint,
    target: PeerIdentity,
    phase: &mut &'static str,
    auth_progress: &mut InitialAuthProgress,
    echo_progress: &mut EchoProgress,
    setup: &SetupTrace,
) -> Result<Duration, String> {
    wait_for_authenticated_webrtc(endpoint, target, auth_progress).await?;
    *phase = "fsp_echo";
    setup.auth_to_echo();
    echo_progress.started_at = Some(Instant::now());

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
            _ = ping_tick.tick() => {
                echo_progress.start_send();
                let result = endpoint.send_ip_packet(request.clone()).await;
                echo_progress.complete_send(result.is_ok());
                result.map_err(|error| format!("FSP echo send failed: {error}"))?;
            },
            delivered = endpoint.recv_ip_packet() => {
                let delivered = delivered.ok_or_else(|| {
                    "ephemeral endpoint closed before receiving FSP echo".to_string()
                })?;
                echo_progress.received_packets += 1;
                echo_progress.target_packets +=
                    u64::from(delivered.source_node_addr == *target.node_addr());
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
    progress: &mut InitialAuthProgress,
) -> Result<(), String> {
    let mut poll = tokio::time::interval(PEER_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        poll.tick().await;
        progress.start_snapshot();
        let snapshot = endpoint.peers().await;
        progress.complete_snapshot(snapshot.as_ref().map(|peers| {
            peers
                .iter()
                .find(|peer| peer.node_addr == *target.node_addr())
                .and_then(|peer| peer.transport_type.as_deref())
        }));
        let peers = snapshot.map_err(|error| format!("peer state query failed: {error}"))?;
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

    #[test]
    fn pipeline_trace_sanitizes_and_bounds_existing_events() {
        struct PrivateField;
        impl std::fmt::Debug for PrivateField {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("private event fields must not even be formatted")
            }
        }
        let trace = PipelineTrace::default();
        let subscriber = tracing_subscriber::registry().with(trace.clone().with_filter(
            tracing_subscriber::filter::filter_fn(pipeline_event_enabled),
        ));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "fips_core::node::handlers::session", private = ?PrivateField,
                "Session initiation started");
            tracing::debug!(target: "fips_core::node::handlers::session", "private-unknown-message");
            tracing::debug!(target: "unrelated::module", "Session initiation started");
        });
        assert_eq!(trace.0.lock().unwrap().counts[0], 1);
        trace.0.lock().unwrap().counts[0] = u32::MAX;
        let subscriber = tracing_subscriber::registry().with(trace.clone().with_filter(
            tracing_subscriber::filter::filter_fn(pipeline_event_enabled),
        ));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "fips_core::node::handlers::session", "Session initiation started");
        });
        let snapshot = trace.to_string();
        assert_eq!(trace.0.lock().unwrap().counts[0], u32::MAX);
        assert!(snapshot.len() < 800);
        assert!(!snapshot.contains("private"));
        assert!(!snapshot.contains("session"));
    }

    #[test]
    fn pipeline_trace_distinguishes_session_start_from_completion() {
        let trace = PipelineTrace::default();
        let subscriber = tracing_subscriber::registry().with(trace.clone().with_filter(
            tracing_subscriber::filter::filter_fn(pipeline_event_enabled),
        ));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "fips_core::node::handlers::session", "Session initiation started");
            tracing::debug!(target: "fips_core::node::handlers::session", "Session initiation started");
            tracing::info!(target: "fips_core::node::handlers::session", "Session established (initiator, XK)");
        });
        let counters = trace.0.lock().unwrap();
        assert_eq!(counters.counts[0], 2);
        assert_eq!(counters.counts[2], 1);
        assert_eq!(counters.counts.iter().sum::<u32>(), 3);
        assert!(counters.last_ms[0] >= counters.first_ms[0]);
    }

    #[test]
    fn setup_timeline_separates_failed_attempt_from_late_authentication() {
        let trace = SetupTrace::default();
        let start = tokio::time::Instant::now() - Duration::from_secs(25);
        trace.begin(start, start + Duration::from_secs(25));
        {
            let mut timeline = trace.0.lock().unwrap();
            for (ms, kind, attempt) in [
                (3_000, SetupEvent::OfferQueued, Some("first-private-id")),
                (18_000, SetupEvent::PendingTimeout, Some("first-private-id")),
                (19_000, SetupEvent::OfferQueued, Some("second-private-id")),
                (24_000, SetupEvent::AnswerApplied, Some("second-private-id")),
                (24_500, SetupEvent::ChannelOpen, None),
                (24_505, SetupEvent::AuthToEcho, None),
            ] {
                timeline.record(
                    kind,
                    attempt.map(str::to_string),
                    start + Duration::from_millis(ms),
                );
            }
            assert_eq!(
                timeline
                    .events
                    .iter()
                    .map(|entry| entry.2)
                    .collect::<Vec<_>>(),
                vec![Some(1), Some(1), Some(2), Some(2), None, None]
            );
            assert!(
                timeline
                    .events
                    .windows(2)
                    .all(|pair| pair[0].0 <= pair[1].0)
            );
            assert_eq!(timeline.auth_to_echo, Some((24_505, 495)));
        }
        let summary = trace.to_string();
        assert!(summary.contains("auth_ms=24505,echo_budget_ms=495"));
        assert!(summary.contains("18000:pending_timeout:1/19000:offer_queued:2"));
        assert!(summary.ends_with("24500:channel_open:unbound/24505:auth_to_echo:unbound"));
        assert!(!summary.contains("private"));
    }

    #[test]
    fn setup_observer_allowlists_events_without_formatting_private_fields() {
        struct PrivateField;
        impl std::fmt::Debug for PrivateField {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("unrelated private fields must not be formatted")
            }
        }
        #[derive(Debug)]
        enum SignalKind {
            Offer,
            Answer,
        }
        let trace = SetupTrace::default();
        let start = tokio::time::Instant::now();
        trace.begin(start, start + Duration::from_secs(25));
        let subscriber = tracing_subscriber::registry().with(trace.clone().with_filter(
            tracing_subscriber::filter::filter_fn(pipeline_event_enabled),
        ));
        tracing::subscriber::with_default(subscriber, || {
            let id = "private-negotiation";
            tracing::debug!(target: "fips_core::transport", negotiation = %id,
                remote_addr = ?PrivateField, sdp = ?PrivateField, "WebRTC offer sent");
            tracing::debug!(target: "fips_core::transport", kind = ?SignalKind::Offer,
                negotiation = ?PrivateField, "WebRTC signal received");
            tracing::debug!(target: "fips_core::transport", kind = ?SignalKind::Answer,
                negotiation = %id, sender = ?PrivateField, "WebRTC signal received");
            tracing::debug!(target: "fips_core::transport", negotiation = %id,
                error = ?PrivateField, "WebRTC answer applied");
            tracing::debug!(target: "fips_core::transport", negotiation = ?PrivateField,
                remote_addr = ?PrivateField, "WebRTC data channel open");
            tracing::debug!(target: "fips_core::node", peer = ?PrivateField,
                "Deferring mesh traversal signal until end-to-end session is established");
            tracing::warn!(target: "fips_core::transport", negotiation = %id,
                stage = "pending-before-data-channel-open", rtc = ?PrivateField,
                reason = ?PrivateField, "WebRTC connection failed");
            tracing::debug!(target: "fips_core::transport", negotiation = ?PrivateField,
                kind = ?PrivateField, "unknown event");
            tracing::debug!(target: "unrelated", negotiation = ?PrivateField, "WebRTC offer sent");
        });
        let timeline = trace.0.lock().unwrap();
        assert_eq!(
            timeline
                .events
                .iter()
                .map(|entry| (entry.1, entry.2))
                .collect::<Vec<_>>(),
            vec![
                (SetupEvent::OfferQueued, Some(1)),
                (SetupEvent::AnswerReceived, Some(1)),
                (SetupEvent::AnswerApplied, Some(1)),
                (SetupEvent::ChannelOpen, None),
                (SetupEvent::FspDeferred, None),
                (SetupEvent::PendingTimeout, Some(1)),
            ]
        );
        drop(timeline);
        assert!(!trace.to_string().contains("private"));
    }

    #[test]
    fn setup_observer_bounds_field_reads_and_sanitizes_failure_stages() {
        let trace = SetupTrace::default();
        let start = tokio::time::Instant::now();
        trace.begin(start, start + Duration::from_secs(25));
        let subscriber = tracing_subscriber::registry().with(trace.clone().with_filter(
            tracing_subscriber::filter::filter_fn(pipeline_event_enabled),
        ));
        tracing::subscriber::with_default(subscriber, || {
            for stage in [
                "outbound-offer-before-data-channel-open",
                "inbound-answer-before-data-channel-open",
                "apply-answer-before-data-channel-open",
                "private-unknown-stage",
            ] {
                tracing::warn!(target: "fips_core::transport", stage, negotiation = %"one-private-id",
                    "WebRTC negotiation failed");
            }
            let oversized = "x".repeat(97);
            tracing::debug!(target: "fips_core::transport", negotiation = %oversized, "WebRTC offer sent");
        });
        let timeline = trace.0.lock().unwrap();
        assert_eq!(timeline.attempts.len(), 1);
        assert_eq!(
            timeline
                .events
                .iter()
                .map(|entry| entry.1)
                .collect::<Vec<_>>(),
            vec![
                SetupEvent::OutboundOfferFailed,
                SetupEvent::InboundAnswerFailed,
                SetupEvent::ApplyAnswerFailed,
                SetupEvent::ConnectionFailed,
                SetupEvent::OfferQueued,
            ]
        );
        assert_eq!(timeline.events.last().unwrap().2, None);
        drop(timeline);
        let summary = trace.to_string();
        assert!(!summary.contains("private"));
        assert!(!summary.contains("xxx"));
    }

    #[test]
    fn setup_caps_keep_known_ordinals_and_auth_milestone_after_overflow() {
        let trace = SetupTrace::default();
        let start = tokio::time::Instant::now();
        trace.begin(start, start + Duration::from_secs(25));
        {
            let mut timeline = trace.0.lock().unwrap();
            for index in 0..9 {
                timeline.record(
                    SetupEvent::OfferQueued,
                    Some(format!("private-{index}")),
                    start,
                );
            }
            assert_eq!(timeline.attempts.len(), SETUP_ATTEMPT_LIMIT);
            assert!(timeline.attempt_overflow);
            assert_eq!(timeline.events[8].2, None);
            timeline.record(SetupEvent::PendingTimeout, Some("private-0".into()), start);
            assert_eq!(timeline.events[9].2, Some(1));
            for _ in 0..SETUP_EVENT_LIMIT {
                timeline.record(SetupEvent::FspDeferred, None, start);
            }
            timeline.record(
                SetupEvent::AuthToEcho,
                None,
                start + Duration::from_secs(26),
            );
            assert_eq!(timeline.events.len(), SETUP_EVENT_LIMIT);
            assert!(timeline.event_overflow);
            assert_eq!(timeline.auth_to_echo, Some((26_000, 0)));
        }
        let summary = trace.to_string();
        assert!(summary.contains("attempts=8,attempt_overflow=true,event_overflow=true"));
        assert!(summary.contains("auth_ms=26000,echo_budget_ms=0"));
        assert!(summary.len() < 4096);
        assert!(!summary.contains("private"));
    }

    #[test]
    fn authentication_failure_includes_existing_pipeline_progress() {
        let pipeline = PipelineTrace::default();
        let subscriber = tracing_subscriber::registry().with(pipeline.clone().with_filter(
            tracing_subscriber::filter::filter_fn(pipeline_event_enabled),
        ));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "fips_core::node::handlers::session", "Session initiation started");
            tracing::info!(target: "fips_core::node::handlers::session", "Session established (initiator, XK)");
        });
        let mut auth = InitialAuthProgress::default();
        auth.start_snapshot();
        auth.complete_snapshot(Ok(Some("websocket")));
        let error = format_probe_failure(
            "probe deadline; phase=webrtc_authentication".to_string(),
            "webrtc_authentication",
            &auth,
            &EchoProgress::default(),
            &pipeline,
        );
        assert!(error.contains("target_websocket_seen=true,target_webrtc_seen=false"));
        assert!(error.contains("; pipeline_progress=[counts=1/0/1/0/0/0/0/0/0/0/0/0/0/0/0/0,"));
        assert!(!error.contains("echo_progress="));
        assert_eq!(error.matches("pipeline_progress=").count(), 1);
        let retained_error =
            finish_probe_result(Err(error.clone()), Err(fips::FipsEndpointError::Closed))
                .unwrap_err();
        assert!(retained_error.starts_with(&error));
        assert!(retained_error.contains("; endpoint shutdown failed: "));
    }
    use std::net::Ipv6Addr;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn cancelled_echo_send_remains_pending_in_failure_progress() {
        let mut progress = EchoProgress::default();
        progress.started_at = Some(Instant::now());
        let result = tokio::time::timeout(Duration::from_millis(10), async {
            progress.start_send();
            std::future::pending::<()>().await;
            progress.complete_send(true);
        })
        .await;
        assert!(result.is_err());
        assert_eq!(progress.sends_started, 1);
        assert_eq!(progress.sends_completed, 0);
        assert_eq!(progress.send_errors, 0);
        assert!(progress.send_started_at.is_some());
        assert!(
            progress
                .to_string()
                .contains("sends_started=1,sends_completed=0")
        );
    }

    #[test]
    fn completed_echo_send_is_not_delivery_or_reply_proof() {
        let mut progress = EchoProgress::default();
        progress.start_send();
        progress.complete_send(true);
        assert_eq!(progress.sends_completed, 1);
        assert!(progress.send_started_at.is_none());
        assert_eq!(progress.received_packets, 0);
        assert_eq!(progress.target_packets, 0);
        progress.start_send();
        progress.complete_send(false);
        assert_eq!(progress.sends_started, 2);
        assert_eq!(progress.sends_completed, 2);
        assert_eq!(progress.send_errors, 1);
    }

    #[test]
    fn echo_failure_progress_contains_only_static_counts_and_timings() {
        assert_eq!(
            EchoProgress::default().to_string(),
            "elapsed_ms=0,sends_started=0,sends_completed=0,send_errors=0,max_send_ms=0,pending_send_ms=0,received_packets=0,target_packets=0"
        );
    }

    #[test]
    fn echo_progress_survives_shutdown_failure_without_changing_success() {
        let error = format!(
            "phase=fsp_echo; echo_progress=[{}]",
            EchoProgress::default()
        );
        let expected = format!(
            "{error}; endpoint shutdown failed: {}",
            fips::FipsEndpointError::Closed
        );
        assert_eq!(
            finish_probe_result(Err(error), Err(fips::FipsEndpointError::Closed)),
            Err(expected)
        );
        let rtt = Duration::from_millis(5);
        assert_eq!(finish_probe_result(Ok(rtt), Ok(())), Ok(rtt));
    }

    #[tokio::test]
    async fn cancelled_peer_snapshot_remains_pending_in_failure_progress() {
        let mut progress = InitialAuthProgress::default();
        let result = tokio::time::timeout(Duration::from_millis(10), async {
            progress.start_snapshot();
            std::future::pending::<()>().await;
            progress.complete_snapshot(Ok(None));
        })
        .await;

        assert!(result.is_err());
        assert_eq!(progress.snapshots_started, 1);
        assert_eq!(progress.snapshots_completed, 0);
        assert!(progress.snapshot_started_at.is_some());
        assert_eq!(progress.target_websocket_seen, None);
        assert_eq!(progress.target_webrtc_seen, None);
        let summary = progress.to_string();
        assert!(summary.contains("snapshots_started=1,snapshots_completed=0"));
        assert!(summary.contains("target_websocket_seen=unknown,target_webrtc_seen=unknown"));
    }

    #[test]
    fn completed_snapshot_and_target_carrier_progress_are_separate() {
        let mut progress = InitialAuthProgress::default();
        progress.start_snapshot();
        progress.complete_snapshot(Ok(None));
        assert_eq!(progress.snapshots_completed, 1);
        assert!(progress.snapshot_started_at.is_none());
        assert_eq!(progress.target_websocket_seen, Some(false));
        assert_eq!(progress.target_webrtc_seen, Some(false));

        progress.start_snapshot();
        progress.complete_snapshot(Ok(Some("websocket")));
        assert_eq!(progress.target_websocket_seen, Some(true));
        assert_eq!(progress.target_webrtc_seen, Some(false));
        progress.start_snapshot();
        progress.complete_snapshot(Ok(Some("webrtc")));
        assert_eq!(progress.target_websocket_seen, Some(true));
        assert_eq!(progress.target_webrtc_seen, Some(true));
        assert!(progress.last_successful_snapshot_at.is_some());
    }

    #[test]
    fn initial_auth_failure_progress_has_only_static_counts_and_flags() {
        let progress = InitialAuthProgress::default();
        let summary = progress.to_string();
        assert_eq!(
            summary,
            "snapshots_started=0,snapshots_completed=0,snapshot_errors=0,last_snapshot_error=none,max_snapshot_ms=0,pending_snapshot_ms=0,last_successful_snapshot_age_ms=unknown,target_websocket_seen=unknown,target_webrtc_seen=unknown"
        );
    }

    #[test]
    fn typed_snapshot_errors_do_not_claim_target_absence() {
        for (error, class) in [
            (
                fips::FipsEndpointError::Timeout {
                    operation: "peer snapshot",
                },
                "timeout",
            ),
            (fips::FipsEndpointError::Closed, "closed"),
        ] {
            let mut progress = InitialAuthProgress::default();
            progress.start_snapshot();
            progress.complete_snapshot(Err(&error));
            assert_eq!(progress.snapshots_started, 1);
            assert_eq!(progress.snapshots_completed, 1);
            assert_eq!(progress.snapshot_errors, 1);
            assert_eq!(progress.last_snapshot_error, Some(class));
            assert_eq!(progress.target_websocket_seen, None);
            assert_eq!(progress.target_webrtc_seen, None);
            assert!(progress.last_successful_snapshot_at.is_none());
            assert!(progress.snapshot_started_at.is_none());
        }
    }

    #[test]
    fn authentication_progress_survives_a_shutdown_failure() {
        let progress = InitialAuthProgress::default();
        let probe_error = format!("phase=webrtc_authentication; auth_progress=[{progress}]");
        let shutdown_error = fips::FipsEndpointError::Closed;
        let expected = format!("{probe_error}; endpoint shutdown failed: {shutdown_error}");
        assert_eq!(
            finish_probe_result(Err(probe_error), Err(shutdown_error)),
            Err(expected)
        );
    }

    #[test]
    fn successful_probe_result_and_cleanup_failure_remain_unchanged() {
        let rtt = Duration::from_millis(7);
        assert_eq!(finish_probe_result(Ok(rtt), Ok(())), Ok(rtt));
        let shutdown_error = fips::FipsEndpointError::Closed;
        let expected = format!("probe completed but endpoint shutdown failed: {shutdown_error}");
        assert_eq!(
            finish_probe_result(Ok(rtt), Err(shutdown_error)),
            Err(expected)
        );
        assert_eq!(
            finish_probe_result(Err("echo failed".to_string()), Ok(())),
            Err("echo failed".to_string())
        );
    }

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
