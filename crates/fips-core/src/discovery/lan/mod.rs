//! LAN peer discovery via mDNS / DNS-SD (RFC 6762 / RFC 6763).
//!
//! Publishes a `_fips._udp.local.` service advert carrying our `npub` and
//! optional discovery scope on the local link, and concurrently browses for the
//! same service type to learn peers reachable on the same broadcast
//! domain. Active scans resolve peers in a few seconds without any Nostr-relay
//! roundtrip, STUN observation, or NAT traversal; scans repeat every minute so
//! discovery remains available offline without a permanent mobile CPU tax.
//!
//! ## Trust model
//!
//! mDNS adverts are unauthenticated: anyone on the LAN can multicast a
//! TXT carrying `npub=...`. Identity is still proven end-to-end by the
//! Noise IK handshake the Node initiates against the observed endpoint
//! — a spoofed advert with another peer's npub fails the handshake and
//! is silently dropped. Treat the mDNS advert as a routing hint, not as
//! identity. LAN discovery is link-local mDNS only. It is not a Nostr advert
//! and does not leave the broadcast domain unless the operator's LAN bridges
//! mDNS.
//!
//! ## Scope filtering
//!
//! When a `discovery_scope` is configured, the advert carries it in a
//! `scope=<name>` TXT entry and the browser only surfaces peers with a
//! matching scope. Nodes on the same physical LAN but configured for
//! different mesh networks don't cross-feed each other.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mdns_sd::{IfKind, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::Identity;

/// DNS-SD service type for the FIPS LAN advert. RFC 6763 §4.1.2: must
/// end with `.local.`. The `_udp` is the IP transport, not the upper
/// protocol — both UDP and TCP FIPS endpoints announce under the same
/// service type because the link-layer punch/handshake travels over UDP
/// either way.
pub const SERVICE_TYPE: &str = "_fips._udp.local.";

// Keep address-auto adverts responsive to interface changes without mdns-sd's
// five-second network scan keeping mobile packet tunnels awake.
const IP_CHECK_INTERVAL_SECS: u32 = 30;
// mdns-sd queries at 0, 1, and 3 seconds within this window. All nodes then
// close their multicast sockets and reconvene on the next wall-clock minute.
const BROWSE_WINDOW: Duration = Duration::from_secs(5);
const BROWSE_PERIOD_MS: u128 = 60_000;

/// TXT key carrying the bech32-encoded npub of the publishing node.
pub const TXT_KEY_NPUB: &str = "npub";

/// TXT key carrying the publishing node's `discovery_scope`, if any.
pub const TXT_KEY_SCOPE: &str = "scope";

/// TXT key carrying the FIPS protocol version (matches the Nostr advert
/// `PROTOCOL_VERSION`).
pub const TXT_KEY_VERSION: &str = "v";

#[derive(Debug, Error)]
pub enum LanDiscoveryError {
    #[error("mDNS daemon init failed: {0}")]
    Daemon(String),
    #[error("mDNS register failed: {0}")]
    Register(String),
    #[error("mDNS browse failed: {0}")]
    Browse(String),
    #[error("no advertised UDP port — start a UDP transport first")]
    NoAdvertisedPort,
    #[error("LAN discovery disabled in config")]
    Disabled,
}

/// A peer we learned about via mDNS. Identity is unverified at this
/// point; the Node initiates a Noise IK handshake against `addr` to
/// confirm `npub` actually controls the matching private key.
#[derive(Debug, Clone)]
pub struct LanDiscoveredPeer {
    pub npub: String,
    pub scope: Option<String>,
    pub addr: SocketAddr,
    pub observed_at: Instant,
}

/// Browser-side events surfaced by `LanDiscovery::drain_events`.
#[derive(Debug, Clone)]
pub enum LanEvent {
    Discovered(LanDiscoveredPeer),
}

/// Runtime configuration for the mDNS responder + browser.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LanDiscoveryConfig {
    /// Master switch. Default: `true` — we already publish identity on
    /// Nostr relays; the marginal leak from also multicasting on the LAN
    /// is zero, while the latency win is large for same-LAN peers.
    #[serde(default = "LanDiscoveryConfig::default_enabled")]
    pub enabled: bool,
    /// Overridable service type, primarily so integration tests can run
    /// multiple isolated services on the same loopback interface.
    #[serde(default = "LanDiscoveryConfig::default_service_type")]
    pub service_type: String,
    /// Optional application/network scope carried in the LAN-only TXT
    /// record. Browsers that set a scope ignore adverts for other scopes.
    ///
    /// This is intentionally separate from Nostr discovery's public `app`
    /// tag so applications can keep relay-visible adverts generic while
    /// still isolating LAN discovery per private network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Default for LanDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            service_type: Self::default_service_type(),
            scope: None,
        }
    }
}

impl LanDiscoveryConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_service_type() -> String {
        SERVICE_TYPE.to_string()
    }
}

/// Running mDNS responder + browser bound to the node's UDP advert port.
pub struct LanDiscovery {
    daemon: ServiceDaemon,
    own_npub: String,
    instance_fullname: String,
    events_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<LanEvent>>,
    event_pump: tokio::task::JoinHandle<()>,
    #[cfg(test)]
    browse_paused: Arc<AtomicBool>,
}

impl LanDiscovery {
    /// Start the mDNS responder and browser.
    ///
    /// `advertised_port` is the UDP port the operational UDP transport
    /// is bound to — peers receiving our advert will initiate Noise IK
    /// against that port. `scope` mirrors the Nostr discovery scope and
    /// is used to filter the browser stream.
    pub async fn start(
        identity: &Identity,
        scope: Option<String>,
        advertised_port: u16,
        config: LanDiscoveryConfig,
    ) -> Result<Arc<Self>, LanDiscoveryError> {
        if !config.enabled {
            return Err(LanDiscoveryError::Disabled);
        }
        if advertised_port == 0 {
            return Err(LanDiscoveryError::NoAdvertisedPort);
        }

        let daemon = ServiceDaemon::new().map_err(|e| LanDiscoveryError::Daemon(e.to_string()))?;
        daemon
            .set_ip_check_interval(IP_CHECK_INTERVAL_SECS)
            .map_err(|e| LanDiscoveryError::Daemon(e.to_string()))?;

        let npub = identity.npub();
        // mDNS DNS labels are capped at 63 bytes. 16 bech32 chars of npub
        // give 80 bits of effective entropy — collisions on a single LAN
        // are vanishingly unlikely. Prefixed for human-readable logs.
        let label_npub = &npub[..16.min(npub.len())];
        let instance_name = format!("fips-{label_npub}");
        let host_name = format!("{instance_name}.local.");

        let mut props: HashMap<String, String> = HashMap::new();
        props.insert(TXT_KEY_NPUB.to_string(), npub.clone());
        if let Some(s) = scope.as_deref()
            && !s.is_empty()
        {
            props.insert(TXT_KEY_SCOPE.to_string(), s.to_string());
        }
        props.insert(
            TXT_KEY_VERSION.to_string(),
            super::nostr::PROTOCOL_VERSION.to_string(),
        );

        // host_ipv4 is set to "127.0.0.1" *and* enable_addr_auto() is
        // called: the loopback seed makes the advert resolve for
        // same-host peers (and same-host integration tests) while the
        // auto-flag still appends every non-loopback interface address
        // mdns-sd discovers. Belt-and-braces because addr_auto alone
        // skips loopback by default on some platforms.
        let service_info = ServiceInfo::new(
            &config.service_type,
            &instance_name,
            &host_name,
            "127.0.0.1",
            advertised_port,
            Some(props),
        )
        .map_err(|e| LanDiscoveryError::Register(e.to_string()))?
        .enable_addr_auto();

        let instance_fullname = service_info.get_fullname().to_string();

        daemon
            .register(service_info)
            .map_err(|e| LanDiscoveryError::Register(e.to_string()))?;

        let browse_rx = daemon
            .browse(&config.service_type)
            .map_err(|e| LanDiscoveryError::Browse(e.to_string()))?;

        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        let own_npub = npub.clone();
        let scope_filter = scope.clone().filter(|s| !s.is_empty());
        let browse_daemon = daemon.clone();
        let service_type = config.service_type.clone();
        #[cfg(test)]
        let browse_paused = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let event_pump_browse_paused = Arc::clone(&browse_paused);
        let event_pump = tokio::spawn(async move {
            let mut browse_rx = browse_rx;
            loop {
                let window = tokio::time::sleep(BROWSE_WINDOW);
                tokio::pin!(window);
                loop {
                    let event = tokio::select! {
                        event = browse_rx.recv_async() => match event {
                            Ok(event) => event,
                            Err(_) => return,
                        },
                        () = &mut window => break,
                    };
                    match event {
                        ServiceEvent::ServiceResolved(info) => {
                            let mut peer_npub: Option<String> = None;
                            let mut peer_scope: Option<String> = None;
                            for prop in info.get_properties().iter() {
                                match prop.key() {
                                    TXT_KEY_NPUB => {
                                        peer_npub = Some(prop.val_str().to_string());
                                    }
                                    TXT_KEY_SCOPE => {
                                        peer_scope = Some(prop.val_str().to_string());
                                    }
                                    _ => {}
                                }
                            }
                            let Some(peer_npub) = peer_npub else {
                                debug!(
                                    instance = info.get_fullname(),
                                    "lan: skip advert without npub TXT"
                                );
                                continue;
                            };
                            if peer_npub == own_npub {
                                // Our own advert echoed back on a loopback
                                // or multi-homed interface.
                                continue;
                            }
                            if scope_filter.is_some() && scope_filter != peer_scope {
                                debug!(
                                    npub = %short(&peer_npub),
                                    their_scope = ?peer_scope,
                                    our_scope = ?scope_filter,
                                    "lan: skip cross-scope advert"
                                );
                                continue;
                            }
                            let port = info.get_port();
                            if port == 0 {
                                continue;
                            }
                            let observed_at = Instant::now();
                            // mdns-sd may report multiple interface IPs for
                            // a multi-homed responder. Surface all routable
                            // candidates — the Node side filters/dedups and
                            // only dials addresses compatible with an active
                            // UDP socket family. IPv6 link-local addresses
                            // require an interface scope; preserve it when
                            // mdns-sd provides one, and skip unusable
                            // scope-less link-local records.
                            for scoped in info.get_addresses() {
                                let Some(addr) = socket_addr_from_scoped_ip(scoped, port) else {
                                    debug!(
                                        npub = %short(&peer_npub),
                                        addr = %scoped.to_ip_addr(),
                                        "lan: skip scope-less IPv6 link-local advert"
                                    );
                                    continue;
                                };
                                if events_tx
                                    .send(LanEvent::Discovered(LanDiscoveredPeer {
                                        npub: peer_npub.clone(),
                                        scope: peer_scope.clone(),
                                        addr,
                                        observed_at,
                                    }))
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            debug!(fullname = %fullname, "lan: service removed");
                        }
                        other => {
                            debug!(?other, "lan: mDNS event");
                        }
                    }
                }
                if let Err(error) = browse_daemon.stop_browse(&service_type) {
                    warn!(%error, "lan: stop mDNS browse failed");
                    return;
                }
                if let Err(error) = browse_daemon.disable_interface(IfKind::All) {
                    warn!(%error, "lan: suspend mDNS interfaces failed");
                    return;
                }
                #[cfg(test)]
                event_pump_browse_paused.store(true, Ordering::Release);
                tokio::time::sleep(next_browse_window_delay()).await;
                #[cfg(test)]
                event_pump_browse_paused.store(false, Ordering::Release);
                if let Err(error) = browse_daemon.enable_interface(IfKind::All) {
                    warn!(%error, "lan: resume mDNS interfaces failed");
                    return;
                }
                browse_rx = match browse_daemon.browse(&service_type) {
                    Ok(receiver) => receiver,
                    Err(error) => {
                        warn!(%error, "lan: restart mDNS browse failed");
                        return;
                    }
                };
            }
        });

        info!(
            instance = %instance_fullname,
            port = advertised_port,
            scope = ?scope,
            "lan: mDNS discovery started"
        );
        Ok(Arc::new(Self {
            daemon,
            own_npub: npub,
            instance_fullname,
            events_rx: Mutex::new(events_rx),
            event_pump,
            #[cfg(test)]
            browse_paused,
        }))
    }

    /// Bech32 npub published by this node.
    pub fn own_npub(&self) -> &str {
        &self.own_npub
    }

    /// Drain pending browser events. Called once per Node tick.
    pub async fn drain_events(&self) -> Vec<LanEvent> {
        let mut rx = self.events_rx.lock().await;
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        events
    }

    /// Tear down the responder, browser, and event pump.
    pub async fn shutdown(self: &Arc<Self>) {
        if let Err(e) = self.daemon.unregister(&self.instance_fullname) {
            warn!(error = %e, "lan: unregister failed");
        }
        if let Err(e) = self.daemon.shutdown() {
            warn!(error = %e, "lan: daemon shutdown failed");
        }
        self.event_pump.abort();
    }
}

fn next_browse_window_delay() -> Duration {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    browse_window_delay_at(now_ms)
}

fn browse_window_delay_at(now_ms: u128) -> Duration {
    Duration::from_millis((BROWSE_PERIOD_MS - now_ms % BROWSE_PERIOD_MS) as u64)
}

fn short(npub: &str) -> &str {
    let end = 16.min(npub.len());
    &npub[..end]
}

fn socket_addr_from_scoped_ip(scoped: &ScopedIp, port: u16) -> Option<SocketAddr> {
    match scoped {
        ScopedIp::V4(v4) => Some(SocketAddr::V4(SocketAddrV4::new(*v4.addr(), port))),
        ScopedIp::V6(v6) => {
            let ip = *v6.addr();
            let scope_id = v6.scope_id().index;
            if ipv6_is_unicast_link_local(ip) && scope_id == 0 {
                return None;
            }
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))
        }
        _ => None,
    }
}

fn ipv6_is_unicast_link_local(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests;
