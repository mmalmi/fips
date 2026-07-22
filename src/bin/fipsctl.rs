//! fipsctl — FIPS control client
//!
//! Connects to the FIPS daemon's control socket, sends commands, and
//! pretty-prints the JSON response.
//!
//! On Unix, uses a Unix domain socket for local IPC.
//! On Windows, uses a TCP connection to localhost.

use clap::{Parser, Subcommand, ValueEnum};
use fips::config::{write_key_file, write_pub_file};
use fips::upper::hosts::HostMap;
use fips::version;
use fips::{Identity, encode_nsec};
use nostr_sdk::prelude::{Client, Event, Keys};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// FIPS control client
#[derive(Parser, Debug)]
#[command(
    name = "fipsctl",
    version = version::short_version(),
    long_version = version::long_version(),
    about = "Control a running FIPS daemon"
)]
struct Cli {
    /// Control socket path override
    #[arg(short = 's', long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show node information
    Show {
        #[command(subcommand)]
        what: ShowCommands,
    },
    /// Show peer ACL information
    Acl {
        #[command(subcommand)]
        what: AclCommands,
    },
    /// Generate a new FIPS identity keypair
    Keygen {
        /// Output directory for fips.key and fips.pub
        #[arg(short = 'd', long = "dir", default_value_os_t = default_key_dir())]
        dir: PathBuf,
        /// Overwrite existing key files
        #[arg(short = 'f', long = "force")]
        force: bool,
        /// Print nsec and npub to stdout instead of writing files
        #[arg(short = 's', long = "stdout")]
        stdout: bool,
    },
    /// Connect to a peer
    Connect {
        /// Peer identifier: npub (bech32) or hostname from /etc/fips/hosts
        peer: String,
        /// Transport address (e.g., "192.168.1.1:2121")
        address: String,
        /// Transport type: udp, tcp, tor, ethernet
        transport: String,
    },
    /// Disconnect a peer
    Disconnect {
        /// Peer identifier: npub (bech32) or hostname from /etc/fips/hosts
        peer: String,
    },
    /// Query historical node statistics
    Stats {
        #[command(subcommand)]
        what: StatsCommands,
    },
    /// Export local machine-generated peer ratings
    Ratings {
        #[command(subcommand)]
        what: RatingsCommands,
    },
}

#[derive(Subcommand, Debug)]
enum StatsCommands {
    /// List available history metrics
    List,
    /// List peers tracked in the stats history
    Peers,
    /// Fetch a time-series window for a metric
    History {
        /// Metric name (see `fipsctl stats list`). Node-level metrics
        /// need no `--peer`; per-peer metrics require it.
        metric: String,
        /// Peer npub (bech32) or hostname from /etc/fips/hosts for
        /// per-peer metrics
        #[arg(long)]
        peer: Option<String>,
        /// Window duration — `<N>s`, `<N>m`, `<N>h`
        #[arg(long, default_value = "10m")]
        window: String,
        /// Sample resolution — `1s` (fast ring) or `1m` (slow ring)
        #[arg(long, default_value = "1s")]
        granularity: String,
        /// Render a Unicode block sparkline instead of JSON
        #[arg(long)]
        plot: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RatingsCommands {
    /// Export current peer health as social-graph rating JSON
    Export {
        /// Rating scope to write into each record
        #[arg(long, default_value = "fips.peer")]
        scope: String,
        /// Export records or signed Nostr fact events
        #[arg(long, value_enum, default_value_t = RatingExportFormat::Records)]
        format: RatingExportFormat,
        /// Output file. Defaults to stdout.
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    /// Publish signed local peer-rating fact events to Nostr relays
    Publish {
        /// Rating scope to publish
        #[arg(long, default_value = "fips.peer")]
        scope: String,
        /// Relay URL to publish to. Can be supplied more than once.
        #[arg(long = "relay", required = true)]
        relays: Vec<String>,
        /// Repeat publishing every N seconds until interrupted. Defaults to one-shot.
        #[arg(long = "interval-secs", value_parser = clap::value_parser!(u64).range(1..))]
        interval_secs: Option<u64>,
        /// Print machine-readable publish results.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum RatingExportFormat {
    Records,
    Events,
}

impl RatingExportFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Records => "records",
            Self::Events => "events",
        }
    }
}

#[derive(Subcommand, Debug)]
enum ShowCommands {
    /// Node status overview
    Status,
    /// Authenticated peers
    Peers,
    /// Active links
    Links,
    /// Spanning tree state
    Tree,
    /// End-to-end sessions
    Sessions,
    /// Bloom filter state
    Bloom,
    /// MMP metrics summary
    Mmp,
    /// Accepted Nostr WoT trust scores used by open discovery
    DiscoveryTrust,
    /// Coordinate cache stats
    Cache,
    /// Pending handshake connections
    Connections,
    /// Transport instances
    Transports,
    /// Routing table summary
    Routing,
    /// Identity cache entries (known node pubkeys)
    IdentityCache,
}

#[derive(Subcommand, Debug)]
enum AclCommands {
    /// Loaded peer ACL state
    Show,
}

impl ShowCommands {
    fn command_name(&self) -> &'static str {
        match self {
            ShowCommands::Status => "show_status",
            ShowCommands::Peers => "show_peers",
            ShowCommands::Links => "show_links",
            ShowCommands::Tree => "show_tree",
            ShowCommands::Sessions => "show_sessions",
            ShowCommands::Bloom => "show_bloom",
            ShowCommands::Mmp => "show_mmp",
            ShowCommands::DiscoveryTrust => "show_discovery_trust",
            ShowCommands::Cache => "show_cache",
            ShowCommands::Connections => "show_connections",
            ShowCommands::Transports => "show_transports",
            ShowCommands::Routing => "show_routing",
            ShowCommands::IdentityCache => "show_identity_cache",
        }
    }
}

impl AclCommands {
    fn command_name(&self) -> &'static str {
        match self {
            AclCommands::Show => "show_acl",
        }
    }
}

fn default_socket_path() -> PathBuf {
    fips::config::default_control_path()
}

#[cfg(unix)]
type ControlStream = std::os::unix::net::UnixStream;

#[cfg(windows)]
type ControlStream = std::net::TcpStream;

#[cfg(unix)]
fn connect_control_stream(socket_path: &Path) -> Result<ControlStream, String> {
    ControlStream::connect(socket_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "cannot connect to {}: {}\n\
                 Hint: add your user to the 'fips' group: sudo usermod -aG fips $USER\n\
                 Then log out and back in for the change to take effect.",
                socket_path.display(),
                e
            )
        } else {
            format!(
                "cannot connect to {}: {}\nIs the FIPS daemon running?",
                socket_path.display(),
                e
            )
        }
    })
}

#[cfg(windows)]
fn connect_control_stream(socket_path: &Path) -> Result<ControlStream, String> {
    let port_str = socket_path.to_string_lossy();
    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("warning: invalid port '{}', using default 21210", port_str);
            21210
        }
    };
    let addr = format!("127.0.0.1:{port}");

    ControlStream::connect(&addr).map_err(|e| {
        format!(
            "cannot connect to {}: {}\nIs the FIPS daemon running?",
            addr, e
        )
    })
}

/// Send a JSON request to the control socket and return the response.
///
/// On Unix, connects via Unix domain socket. On Windows, connects via TCP.
fn send_request(socket_path: &Path, request_json: &str) -> Result<serde_json::Value, String> {
    let mut stream = connect_control_stream(socket_path)?;

    let timeout = Duration::from_secs(5);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    exchange_request(&mut stream, request_json)
}

fn exchange_request(
    stream: &mut ControlStream,
    request_json: &str,
) -> Result<serde_json::Value, String> {
    stream
        .write_all(request_json.as_bytes())
        .map_err(|e| format!("failed to send request: {e}"))?;
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let reader = BufReader::new(stream);
    let line = reader
        .lines()
        .next()
        .ok_or("no response from daemon")?
        .map_err(|e| format!("failed to read response: {e}"))?;

    serde_json::from_str(&line).map_err(|e| format!("invalid response JSON: {e}"))
}

/// Build a request JSON string for a simple command (no params).
fn build_query(command: &str) -> String {
    format!("{{\"command\":\"{command}\"}}\n")
}

/// Build a request JSON string for a command with params.
fn build_command(command: &str, params: serde_json::Value) -> String {
    let req = serde_json::json!({"command": command, "params": params});
    format!("{}\n", serde_json::to_string(&req).unwrap())
}

fn response_error(value: &serde_json::Value) -> Option<&str> {
    (value.get("status").and_then(|v| v.as_str()) == Some("error")).then(|| {
        value
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error")
    })
}

/// Print a control socket response, handling error status.
fn print_response(value: &serde_json::Value) {
    if let Some(msg) = response_error(value) {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }

    let output = if let Some(data) = value.get("data") {
        serde_json::to_string_pretty(data)
    } else {
        serde_json::to_string_pretty(value)
    };
    println!("{}", output.unwrap_or_else(|_| format!("{value}")));
}

fn export_peer_ratings(
    socket_path: &Path,
    scope: &str,
    format: RatingExportFormat,
    output: Option<&Path>,
) -> Result<(), String> {
    let export = fetch_peer_rating_export(socket_path, scope, format)?;
    let rendered =
        serde_json::to_string_pretty(&export).map_err(|e| format!("failed to encode JSON: {e}"))?;

    if let Some(path) = output {
        std::fs::write(path, rendered)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

fn fetch_peer_rating_export(
    socket_path: &Path,
    scope: &str,
    format: RatingExportFormat,
) -> Result<serde_json::Value, String> {
    let scope = scope.trim();
    if scope.is_empty() {
        return Err("rating scope cannot be empty".to_string());
    }

    let response = send_request(
        socket_path,
        &build_command(
            "show_peer_ratings",
            serde_json::json!({
                "scope": scope,
                "format": format.as_str(),
            }),
        ),
    )?;
    control_response_data(&response, "show_peer_ratings").cloned()
}

fn publish_peer_ratings(
    socket_path: &Path,
    scope: &str,
    relays: &[String],
    interval_secs: Option<u64>,
    json_output: bool,
) -> Result<(), String> {
    if let Some(interval_secs) = interval_secs {
        loop {
            publish_peer_ratings_once(socket_path, scope, relays, json_output)?;
            std::thread::sleep(Duration::from_secs(interval_secs));
        }
    }

    publish_peer_ratings_once(socket_path, scope, relays, json_output)
}

fn publish_peer_ratings_once(
    socket_path: &Path,
    scope: &str,
    relays: &[String],
    json_output: bool,
) -> Result<(), String> {
    if relays.is_empty() {
        return Err("at least one relay is required".to_string());
    }
    let export = fetch_peer_rating_export(socket_path, scope, RatingExportFormat::Events)?;
    let events = peer_rating_events_from_export(&export)?;
    let report = publish_peer_rating_events_to_relays(&events, relays)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| format!("failed to encode publish report: {e}"))?
        );
    } else {
        println!("rating_events: {}", events.len());
        println!("relays: {}", relays.join(", "));
        for event in report
            .get("events")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
        {
            let event_id = event
                .get("event_id")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let success = event
                .get("success_count")
                .and_then(|value| value.as_u64())
                .unwrap_or_default();
            let failed = event
                .get("failed_count")
                .and_then(|value| value.as_u64())
                .unwrap_or_default();
            println!("event: {event_id} published={success} failed={failed}");
        }
    }
    Ok(())
}

fn peer_rating_events_from_export(export: &serde_json::Value) -> Result<Vec<Event>, String> {
    let events = export
        .get("events")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "peer rating export did not include events array".to_string())?;
    events
        .iter()
        .map(|value| {
            let event: Event = serde_json::from_value(value.clone())
                .map_err(|e| format!("failed to decode rating event: {e}"))?;
            event
                .verify()
                .map_err(|e| format!("rating event signature verification failed: {e}"))?;
            Ok(event)
        })
        .collect()
}

fn publish_peer_rating_events_to_relays(
    events: &[Event],
    relays: &[String],
) -> Result<serde_json::Value, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start async runtime: {e}"))?;

    runtime.block_on(async {
        let client = Client::new(Keys::generate());
        for relay in relays {
            client
                .add_relay(relay)
                .await
                .map_err(|e| format!("failed to add relay {relay}: {e}"))?;
        }
        client.connect().await;
        let mut published = Vec::with_capacity(events.len());
        for event in events {
            let output = client
                .send_event_to(relays.to_vec(), event)
                .await
                .map_err(|e| format!("failed to publish rating event {}: {e}", event.id))?;
            let failed = output
                .failed
                .iter()
                .map(|(relay, error)| {
                    serde_json::json!({
                        "relay": relay.to_string(),
                        "error": error,
                    })
                })
                .collect::<Vec<_>>();
            published.push(serde_json::json!({
                "event_id": output.val.to_string(),
                "success_count": output.success.len(),
                "failed_count": output.failed.len(),
                "success_relays": output.success.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "failed_relays": failed,
            }));
        }
        client.disconnect().await;
        Ok(serde_json::json!({
            "type": "fips_peer_rating_publish",
            "event_count": events.len(),
            "relay_count": relays.len(),
            "relays": relays,
            "events": published,
        }))
    })
}

fn control_response_data<'a>(
    response: &'a serde_json::Value,
    command: &str,
) -> Result<&'a serde_json::Value, String> {
    if let Some(msg) = response_error(response) {
        return Err(format!("{command} failed: {msg}"));
    }
    response
        .get("data")
        .ok_or_else(|| format!("{command} response did not include data"))
}

/// Default directory for keygen output.
fn default_key_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/fips")
    }
    #[cfg(windows)]
    {
        dirs::config_dir()
            .map(|d| d.join("fips"))
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData\\fips"))
    }
}

/// Check if `address` is an IPv6 literal in `fd00::/8` (FIPS mesh ULA range).
///
/// Handles three common syntaxes:
///   - bare IPv6:          `fd9d:...`
///   - bracketed + port:   `[fd9d:...]:2121`
///   - bare IPv6 + port:   `fd9d:...:2121` (ambiguous; accepted if tail is numeric)
fn is_fips_mesh_address(address: &str) -> bool {
    let is_ula = |a: &Ipv6Addr| a.octets()[0] == 0xfd;

    if let Ok(a) = address.parse::<Ipv6Addr>() {
        return is_ula(&a);
    }
    if let Ok(sa) = address.parse::<SocketAddrV6>() {
        return is_ula(sa.ip());
    }
    if let Some((host, port)) = address.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
        && !port.is_empty()
    {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(a) = host.parse::<Ipv6Addr>() {
            return is_ula(&a);
        }
    }
    false
}

/// Reject `fd00::/8` addresses for transports that expect a reachable network endpoint.
///
/// FIPS mesh ULAs are derived from npubs and only make sense as destinations
/// inside an already-established mesh — they are not valid udp/tcp/ethernet
/// transport endpoints. Without this check the CLI echoes success while the
/// daemon rejects the bind with EAFNOSUPPORT (issue #61).
fn validate_connect_address(address: &str, transport: &str) -> Result<(), String> {
    let checked = matches!(transport, "udp" | "tcp" | "ethernet");
    if checked && is_fips_mesh_address(address) {
        return Err(format!(
            "'{address}' is a FIPS mesh address (fd00::/8), not a reachable {transport} endpoint.\n\
             Provide the peer's routable IP/hostname and port (e.g., '192.0.2.1:2121' or 'peer.example.com:2121')."
        ));
    }
    Ok(())
}

/// Resolve a peer identifier to an npub.
///
/// If the identifier starts with "npub1", it's returned as-is.
/// Otherwise, it's looked up as a hostname in the hosts file.
fn resolve_peer(peer: &str) -> String {
    if peer.starts_with("npub1") {
        return peer.to_string();
    }

    let hosts = HostMap::load_hosts_file(Path::new(fips::upper::hosts::DEFAULT_HOSTS_PATH));
    match hosts.lookup_npub(peer) {
        Some(npub) => npub.to_string(),
        None => {
            eprintln!("error: unknown host '{peer}'");
            eprintln!(
                "Not found in {} and not an npub.",
                fips::upper::hosts::DEFAULT_HOSTS_PATH
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Commands that don't require a running daemon
    if let Commands::Keygen { dir, force, stdout } = &cli.command {
        let identity = Identity::generate();
        let nsec = encode_nsec(&identity.keypair().secret_key());
        let npub = identity.npub();

        if *stdout {
            println!("{nsec}");
            println!("{npub}");
            return;
        }

        let key_path = dir.join("fips.key");
        let pub_path = dir.join("fips.pub");

        if key_path.exists() && !force {
            eprintln!("error: key file already exists: {}", key_path.display());
            eprintln!("Use --force to overwrite.");
            std::process::exit(1);
        }

        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("error: cannot create directory {}: {e}", dir.display());
            std::process::exit(1);
        }

        if let Err(e) = write_key_file(&key_path, &nsec) {
            eprintln!("error: failed to write key file: {e}");
            std::process::exit(1);
        }

        if let Err(e) = write_pub_file(&pub_path, &npub) {
            eprintln!("error: failed to write pub file: {e}");
            std::process::exit(1);
        }

        eprintln!("{npub}");
        eprintln!("Key files written to: {}/", dir.display());
        eprintln!();
        eprintln!("NOTE: Set 'node.identity.persistent: true' in fips.yaml");
        eprintln!("      or these keys will be overwritten on next daemon start.");
        return;
    }

    let socket_path = cli.socket.unwrap_or_else(default_socket_path);

    if let Commands::Ratings { what } = &cli.command {
        match what {
            RatingsCommands::Export {
                scope,
                format,
                output,
            } => {
                if let Err(e) = export_peer_ratings(&socket_path, scope, *format, output.as_deref())
                {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            RatingsCommands::Publish {
                scope,
                relays,
                interval_secs,
                json,
            } => {
                if let Err(e) =
                    publish_peer_ratings(&socket_path, scope, relays, *interval_secs, *json)
                {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        return;
    }

    let request = match &cli.command {
        Commands::Show { what } => build_query(what.command_name()),
        Commands::Acl { what } => build_query(what.command_name()),
        Commands::Connect {
            peer,
            address,
            transport,
        } => {
            if let Err(e) = validate_connect_address(address, transport) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
            let npub = resolve_peer(peer);
            build_command(
                "connect",
                serde_json::json!({
                    "npub": npub,
                    "address": address,
                    "transport": transport,
                }),
            )
        }
        Commands::Disconnect { peer } => {
            let npub = resolve_peer(peer);
            build_command("disconnect", serde_json::json!({"npub": npub}))
        }
        Commands::Stats { what } => match what {
            StatsCommands::List => build_query("show_stats_list"),
            StatsCommands::Peers => build_query("show_stats_peers"),
            StatsCommands::History {
                metric,
                peer,
                window,
                granularity,
                ..
            } => {
                let mut params = serde_json::json!({
                    "metric": metric,
                    "window": window,
                    "granularity": granularity,
                });
                if let Some(p) = peer {
                    let resolved = resolve_peer(p);
                    params["peer"] = serde_json::json!(resolved);
                }
                build_command("show_stats_history", params)
            }
        },
        Commands::Keygen { .. } | Commands::Ratings { .. } => unreachable!(),
    };

    let value = match send_request(&socket_path, &request) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if let Commands::Stats {
        what: StatsCommands::History {
            plot: true, metric, ..
        },
    } = &cli.command
    {
        print_plot(&value, metric);
    } else {
        print_response(&value);
    }
}

/// Render the response as a Unicode block sparkline plot.
fn print_plot(value: &serde_json::Value, metric: &str) {
    if let Some(msg) = response_error(value) {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }

    let Some(data) = value.get("data") else {
        eprintln!("error: no data in response");
        std::process::exit(1);
    };

    let values: Vec<f64> = data
        .get("values")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|v| v.as_f64().unwrap_or(f64::NAN)).collect())
        .unwrap_or_default();
    let unit = data.get("unit").and_then(|v| v.as_str()).unwrap_or("");
    let granularity_seconds = data
        .get("granularity_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    if values.is_empty() {
        println!("{metric}: no data yet");
        return;
    }

    let (min, max) = values
        .iter()
        .filter(|v| !v.is_nan())
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
            (lo.min(v), hi.max(v))
        });
    let (min, max) = if min.is_finite() {
        (min, max)
    } else {
        (0.0, 0.0)
    };
    let last = values
        .iter()
        .rev()
        .find(|v| !v.is_nan())
        .copied()
        .unwrap_or(f64::NAN);
    let width_secs = (values.len() as u64) * granularity_seconds;
    let gap_count = values.iter().filter(|v| v.is_nan()).count();

    println!(
        "{metric} ({unit}) — {n} samples @ {g}s = {w}s window{gap}",
        n = values.len(),
        g = granularity_seconds,
        w = width_secs,
        gap = if gap_count > 0 {
            format!(" ({gap_count} gaps)")
        } else {
            String::new()
        },
    );
    let last_str = if last.is_nan() {
        "-".to_string()
    } else {
        format!("{last:.3}")
    };
    println!("  min={min:.3} max={max:.3} last={last_str}");
    println!("  {}", sparkline(&values, min, max));
}

/// Render a slice of values as Unicode block characters.
///
/// Uses eight discrete levels: `▁▂▃▄▅▆▇█`. Constant series and empty
/// inputs render as a single-level line (`▄`).
fn sparkline(values: &[f64], min: f64, max: f64) -> String {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let range = max - min;
    values
        .iter()
        .map(|&v| {
            if v.is_nan() {
                ' '
            } else if !range.is_finite() || range <= 0.0 {
                BLOCKS[3]
            } else {
                let norm = ((v - min) / range).clamp(0.0, 1.0);
                let idx = (norm * (BLOCKS.len() as f64 - 1.0)).round() as usize;
                BLOCKS[idx.min(BLOCKS.len() - 1)]
            }
        })
        .collect()
}

#[cfg(test)]
include!("fipsctl/tests.rs");
