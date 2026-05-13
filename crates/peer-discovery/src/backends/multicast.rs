//! Raw UDP multicast discovery backend.
//!
//! An alternative to mDNS for the LAN tier. Distinguishing properties:
//!
//! * No platform mDNS responder dependency (cleaner on Windows, more
//!   predictable on Linux).
//! * Per-interface multicast fan-out so multi-homed hosts (Wi-Fi +
//!   Ethernet, Hyper-V/WSL/Tailscale virtual adapters) actually reach peers
//!   on every L2 segment they're attached to. The interface enumeration
//!   approach is taken from nostr-vpn's `lan_pairing.rs`, which earned its
//!   complexity in production on Windows multi-NIC hosts.
//! * Periodic re-announce + application-layer stale detection: peers that
//!   stop announcing within `stale_after` are reported as `Down` even if no
//!   explicit withdrawal was sent (covers crashes and network partitions).
//! * One JSON datagram per announce, versioned. Generic enough that
//!   nostr-vpn's invite-broadcast use case fits inside [`ServiceAd::txt`].
//!
//! Default multicast group `239.255.74.74:38912` is administratively-scoped
//! and a deliberate sibling of nostr-vpn's `239.255.73.73:38911` so the two
//! protocols don't interfere on the same LAN.

use crate::{
    Discovery, DiscoveryError, DiscoveryHandle, DiscoveredPeer, LocalPeer, PeerEvent, PeerId,
    ServiceAd, ServiceTag,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;

const SOURCE: &str = "multicast";
const ENVELOPE_VERSION: u8 = 1;
const DEFAULT_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 74, 74);
const DEFAULT_PORT: u16 = 38_912;
const DEFAULT_ANNOUNCE_EVERY: Duration = Duration::from_secs(3);
const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(15);
const RECV_TIMEOUT: Duration = Duration::from_millis(250);
const RECV_BUF: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct MulticastConfig {
    pub group: Ipv4Addr,
    pub port: u16,
    pub announce_every: Duration,
    /// A peer is reported `Down` if no announcement is received within this
    /// window. Set to at least 3× `announce_every` to tolerate one or two
    /// missed packets without false-negative churn.
    pub stale_after: Duration,
    /// If `Some`, only join multicast on these interface addresses.
    /// Defaults to every non-loopback IPv4 interface plus an `INADDR_ANY`
    /// baseline.
    pub interfaces: Option<Vec<Ipv4Addr>>,
    /// Drop our own packets at the socket layer. Always recommended; the
    /// `id`-based filter is a backstop.
    pub disable_loopback: bool,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            group: DEFAULT_GROUP,
            port: DEFAULT_PORT,
            announce_every: DEFAULT_ANNOUNCE_EVERY,
            stale_after: DEFAULT_STALE_AFTER,
            interfaces: None,
            disable_loopback: false,
        }
    }
}

pub struct MulticastDiscovery {
    config: MulticastConfig,
}

impl MulticastDiscovery {
    pub fn new(config: MulticastConfig) -> Arc<Self> {
        Arc::new(Self { config })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    v: u8,
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    ts: u64,
    services: Vec<ServiceAd>,
}

#[async_trait]
impl Discovery for MulticastDiscovery {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn start(
        self: Arc<Self>,
        local: LocalPeer,
        watch: Vec<ServiceTag>,
        events: mpsc::Sender<PeerEvent>,
    ) -> Result<DiscoveryHandle, DiscoveryError> {
        let socket = bind_socket(&self.config).map_err(|e| DiscoveryError::Start {
            backend: SOURCE,
            source: Box::new(e),
        })?;
        let interfaces = resolve_interfaces(&self.config);
        join_groups(&socket, self.config.group, &interfaces);

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let runtime = tokio::runtime::Handle::current();
        let cfg = self.config.clone();
        let local_id = local.id;

        let thread: JoinHandle<()> = std::thread::Builder::new()
            .name("pd-multicast".into())
            .spawn(move || {
                run_loop(
                    &socket,
                    &cfg,
                    &interfaces,
                    &local,
                    &watch,
                    &events,
                    &runtime,
                    &stop_thread,
                    local_id,
                );
            })
            .map_err(|e| DiscoveryError::Start {
                backend: SOURCE,
                source: Box::new(e),
            })?;

        let thread_handle = Mutex::new(Some(thread));
        Ok(DiscoveryHandle::new(move || {
            stop.store(true, Ordering::Relaxed);
            if let Some(t) = thread_handle.lock().unwrap().take() {
                let _ = t.join();
            }
        }))
    }
}

fn bind_socket(config: &MulticastConfig) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin")
    ))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.port).into())?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(RECV_TIMEOUT))?;
    socket.set_multicast_loop_v4(!config.disable_loopback)?;
    socket.set_multicast_ttl_v4(1)?;
    Ok(socket)
}

fn resolve_interfaces(config: &MulticastConfig) -> Vec<Ipv4Addr> {
    if let Some(explicit) = &config.interfaces {
        return explicit.clone();
    }
    let mut out = Vec::new();
    for iface in netdev::get_interfaces() {
        if iface.is_loopback() {
            continue;
        }
        for net in &iface.ipv4 {
            let addr = net.addr();
            if addr.is_loopback() || addr.is_unspecified() || addr.is_link_local() {
                continue;
            }
            out.push(addr);
        }
    }
    out
}

fn join_groups(socket: &UdpSocket, group: Ipv4Addr, interfaces: &[Ipv4Addr]) {
    // Default-interface join — covers single-NIC hosts and the loopback
    // self-test path where `interfaces` may be empty.
    let _ = socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED);
    for iface in interfaces {
        // Duplicate joins return EADDRINUSE on some platforms — harmless.
        let _ = socket.join_multicast_v4(&group, iface);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_loop(
    socket: &UdpSocket,
    cfg: &MulticastConfig,
    interfaces: &[Ipv4Addr],
    local: &LocalPeer,
    watch: &[ServiceTag],
    events: &mpsc::Sender<PeerEvent>,
    runtime: &tokio::runtime::Handle,
    stop: &AtomicBool,
    local_id: PeerId,
) {
    let target = SocketAddrV4::new(cfg.group, cfg.port);
    let mut next_announce = Instant::now();
    let mut next_stale_sweep = Instant::now() + cfg.stale_after;
    let mut buf = vec![0u8; RECV_BUF];
    let mut known: HashMap<PeerId, KnownPeer> = HashMap::new();
    let local_id_hex = hex::encode(local_id);

    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= next_announce {
            send_announce(socket, target, interfaces, local, &local_id_hex);
            next_announce = now + cfg.announce_every;
        }

        match socket.recv_from(&mut buf) {
            Ok((len, _src)) => {
                if let Some((id, env)) = parse_envelope(&buf[..len], local_id) {
                    let services = filter_services(env.services, watch);
                    if services.is_empty() && !watch.is_empty() {
                        continue;
                    }
                    let peer = DiscoveredPeer {
                        id,
                        services: services.clone(),
                        source: SOURCE,
                        seen_at: SystemTime::now(),
                        display_name: env.name,
                    };
                    let was_known = known
                        .insert(
                            id,
                            KnownPeer {
                                services: services.clone(),
                                last_seen: now,
                            },
                        )
                        .is_some();
                    let event = if was_known {
                        PeerEvent::Updated(peer)
                    } else {
                        PeerEvent::Up(peer)
                    };
                    let tx = events.clone();
                    runtime.spawn(async move {
                        let _ = tx.send(event).await;
                    });
                }
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => {
                tracing::warn!(error = %e, "multicast recv failed; exiting loop");
                break;
            }
        }

        if Instant::now() >= next_stale_sweep {
            sweep_stale(&mut known, cfg.stale_after, events, runtime);
            next_stale_sweep = Instant::now() + cfg.stale_after;
        }
    }
}

struct KnownPeer {
    #[allow(dead_code)]
    services: Vec<ServiceAd>,
    last_seen: Instant,
}

fn send_announce(
    socket: &UdpSocket,
    target: SocketAddrV4,
    interfaces: &[Ipv4Addr],
    local: &LocalPeer,
    local_id_hex: &str,
) {
    let env = Envelope {
        v: ENVELOPE_VERSION,
        id: local_id_hex.to_string(),
        name: local.display_name.clone(),
        ts: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        services: local.services.clone(),
    };
    let Ok(payload) = serde_json::to_vec(&env) else {
        return;
    };
    if payload.len() > RECV_BUF {
        tracing::warn!(
            bytes = payload.len(),
            "multicast announce too large; dropping"
        );
        return;
    }

    let sock_ref = SockRef::from(socket);
    let _ = sock_ref.set_multicast_if_v4(&Ipv4Addr::UNSPECIFIED);
    let _ = socket.send_to(&payload, target);

    for iface in interfaces {
        let _ = sock_ref.set_multicast_if_v4(iface);
        let _ = socket.send_to(&payload, target);
    }
}

fn parse_envelope(payload: &[u8], local_id: PeerId) -> Option<(PeerId, Envelope)> {
    let env: Envelope = serde_json::from_slice(payload).ok()?;
    if env.v != ENVELOPE_VERSION {
        return None;
    }
    let bytes = hex::decode(env.id.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    if id == local_id {
        return None;
    }
    Some((id, env))
}

fn filter_services(services: Vec<ServiceAd>, watch: &[ServiceTag]) -> Vec<ServiceAd> {
    if watch.is_empty() {
        return services;
    }
    services
        .into_iter()
        .filter(|ad| watch.iter().any(|w| w == &ad.tag))
        .collect()
}

fn sweep_stale(
    known: &mut HashMap<PeerId, KnownPeer>,
    stale_after: Duration,
    events: &mpsc::Sender<PeerEvent>,
    runtime: &tokio::runtime::Handle,
) {
    let now = Instant::now();
    let mut to_remove = Vec::new();
    for (id, peer) in known.iter() {
        if now.duration_since(peer.last_seen) >= stale_after {
            to_remove.push(*id);
        }
    }
    for id in to_remove {
        known.remove(&id);
        let tx = events.clone();
        runtime.spawn(async move {
            let _ = tx
                .send(PeerEvent::Down {
                    id,
                    source: SOURCE,
                })
                .await;
        });
    }
}
