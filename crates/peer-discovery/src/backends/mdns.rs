//! mDNS (Bonjour-style) discovery backend.
//!
//! Each [`ServiceAd`] in the local peer's description is registered as one
//! mDNS service of type `_<sanitized-tag>._<proto>.local.`, where the proto
//! comes from the first UDP/TCP address in the ad. Watched tags become
//! browse subscriptions on the same name. Peer identity travels in the TXT
//! record as `id=<hex>`; the rest of the ad's TXT entries are forwarded
//! verbatim under a `t.<key>` prefix.
//!
//! Limitations:
//!
//! * One port per service (the first matching UDP/TCP address wins). Other
//!   addresses in the ad are not advertised; backends with their own
//!   transports can carry them out-of-band.
//! * Tags must sanitize to a non-empty mDNS service label (`[a-z0-9-]`,
//!   1..=15 chars). Longer or non-conforming tags are clamped.
//! * No `Updated` events: every re-resolve re-emits `Up`. Consumers should
//!   treat duplicate `Up`s as a refresh.

use crate::{
    Discovery, DiscoveryError, DiscoveryHandle, DiscoveredPeer, LocalPeer, PeerEvent, PeerId,
    ServiceAd, ServiceAddr, ServiceTag,
};
use async_trait::async_trait;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

const SOURCE: &str = "mdns";
const ID_KEY: &str = "id";
const NAME_KEY: &str = "name";
const TXT_PREFIX: &str = "t.";
const MAX_LABEL_LEN: usize = 15;

#[derive(Clone, Debug, Default)]
pub struct MdnsConfig {
    /// Daemon listen port for the local mDNS responder. `None` lets the OS
    /// pick. Useful in tests to confine traffic to a non-multicast loopback
    /// setup.
    pub mdns_port: Option<u16>,
    /// Optional override for the mDNS instance label. Defaults to a label
    /// derived from the first six hex chars of the peer id.
    pub instance_label: Option<String>,
}

pub struct MdnsDiscovery {
    config: MdnsConfig,
}

impl MdnsDiscovery {
    pub fn new(config: MdnsConfig) -> Arc<Self> {
        Arc::new(Self { config })
    }
}

#[async_trait]
impl Discovery for MdnsDiscovery {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn start(
        self: Arc<Self>,
        local: LocalPeer,
        watch: Vec<ServiceTag>,
        events: mpsc::Sender<PeerEvent>,
    ) -> Result<DiscoveryHandle, DiscoveryError> {
        let daemon = match self.config.mdns_port {
            Some(port) => ServiceDaemon::new_with_port(port),
            None => ServiceDaemon::new(),
        }
        .map_err(|e| DiscoveryError::Start {
            backend: SOURCE,
            source: Box::new(e),
        })?;

        let local_id_hex = hex::encode(local.id);
        let instance_label = self
            .config
            .instance_label
            .clone()
            .unwrap_or_else(|| format!("pd-{}", &local_id_hex[..12.min(local_id_hex.len())]));

        let mut registered: Vec<String> = Vec::new();
        for ad in &local.services {
            let Some((proto, port)) = primary_proto_port(ad) else {
                tracing::debug!(tag = %ad.tag, "mdns: skipping advertise (no UDP/TCP addr)");
                continue;
            };
            let Some(label) = sanitize_label(&ad.tag) else {
                tracing::warn!(tag = %ad.tag, "mdns: skipping advertise (tag has no valid label)");
                continue;
            };
            let service_type = format!("_{label}._{proto}.local.");

            let mut props: HashMap<String, String> = HashMap::new();
            props.insert(ID_KEY.into(), local_id_hex.clone());
            if let Some(name) = &local.display_name {
                props.insert(NAME_KEY.into(), name.clone());
            }
            for (k, v) in &ad.txt {
                props.insert(format!("{TXT_PREFIX}{k}"), v.clone());
            }

            let host_name = format!("{instance_label}.local.");
            let info = ServiceInfo::new(
                &service_type,
                &instance_label,
                &host_name,
                "",
                port,
                Some(props),
            )
            .map(|i| i.enable_addr_auto())
            .map_err(|e| DiscoveryError::Start {
                backend: SOURCE,
                source: Box::new(e),
            })?;

            let fullname = info.get_fullname().to_string();
            daemon.register(info).map_err(|e| DiscoveryError::Start {
                backend: SOURCE,
                source: Box::new(e),
            })?;
            registered.push(fullname);
        }

        let local_id = local.id;
        let known: Arc<Mutex<HashMap<String, PeerId>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut browse_threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let mut browse_types: Vec<String> = Vec::new();

        let watched_tags: Vec<(ServiceTag, String, &'static str)> = watch
            .iter()
            .filter_map(|tag| sanitize_label(tag).map(|l| (tag.clone(), l)))
            .flat_map(|(tag, label)| {
                ["udp", "tcp"]
                    .into_iter()
                    .map(move |proto| (tag.clone(), label.clone(), proto))
            })
            .collect();

        for (tag, label, proto) in watched_tags {
            let service_type = format!("_{label}._{proto}.local.");
            let receiver = daemon
                .browse(&service_type)
                .map_err(|e| DiscoveryError::Start {
                    backend: SOURCE,
                    source: Box::new(e),
                })?;
            browse_types.push(service_type.clone());

            let events_tx = events.clone();
            let known = Arc::clone(&known);
            let runtime = tokio::runtime::Handle::current();
            let proto_static = proto;
            let thread = std::thread::Builder::new()
                .name(format!("pd-mdns-{label}"))
                .spawn(move || {
                    while let Ok(event) = receiver.recv() {
                        let mapped = map_event(event, &tag, proto_static, local_id, &known);
                        for ev in mapped {
                            let tx = events_tx.clone();
                            runtime.spawn(async move {
                                let _ = tx.send(ev).await;
                            });
                        }
                    }
                })
                .map_err(|e| DiscoveryError::Start {
                    backend: SOURCE,
                    source: Box::new(e),
                })?;
            browse_threads.push(thread);
        }

        let daemon_for_drop = daemon.clone();
        Ok(DiscoveryHandle::new(move || {
            for ty in &browse_types {
                let _ = daemon_for_drop.stop_browse(ty);
            }
            for fullname in &registered {
                let _ = daemon_for_drop.unregister(fullname);
            }
            let _ = daemon_for_drop.shutdown();
            // Threads exit when their receivers close after shutdown.
            for t in browse_threads.drain(..) {
                drop(t);
            }
        }))
    }
}

fn primary_proto_port(ad: &ServiceAd) -> Option<(&'static str, u16)> {
    for addr in &ad.addrs {
        match addr {
            ServiceAddr::Udp(s) => return Some(("udp", s.port())),
            ServiceAddr::Tcp(s) => return Some(("tcp", s.port())),
            _ => continue,
        }
    }
    None
}

/// Lower-case alphanumeric + hyphen, leading-letter, max 15 chars. Returns
/// `None` if no valid label can be constructed.
fn sanitize_label(tag: &str) -> Option<String> {
    let mut out = String::with_capacity(tag.len().min(MAX_LABEL_LEN));
    let mut prev_hyphen = false;
    for c in tag.chars().flat_map(char::to_lowercase) {
        if out.len() == MAX_LABEL_LEN {
            break;
        }
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_hyphen = false;
        } else if !prev_hyphen && !out.is_empty() {
            out.push('-');
            prev_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() || !out.chars().next().unwrap().is_ascii_alphabetic() {
        return None;
    }
    Some(out)
}

fn map_event(
    event: ServiceEvent,
    tag: &ServiceTag,
    proto: &'static str,
    local_id: PeerId,
    known: &Mutex<HashMap<String, PeerId>>,
) -> Vec<PeerEvent> {
    match event {
        ServiceEvent::ServiceResolved(svc) => {
            let id_hex = match svc.get_property_val_str(ID_KEY) {
                Some(s) if !s.trim().is_empty() => s.trim().to_string(),
                _ => return Vec::new(),
            };
            let Some(remote_id) = decode_peer_id(&id_hex) else {
                return Vec::new();
            };
            if remote_id == local_id {
                return Vec::new();
            }

            let port = svc.get_port();
            let mut addrs: Vec<ServiceAddr> = Vec::new();
            for ip in svc.get_addresses() {
                let socket = SocketAddr::new(ip.to_ip_addr(), port);
                addrs.push(match proto {
                    "tcp" => ServiceAddr::Tcp(socket),
                    _ => ServiceAddr::Udp(socket),
                });
            }
            if addrs.is_empty() {
                return Vec::new();
            }

            let mut txt = std::collections::BTreeMap::new();
            for prop in svc.get_properties().iter() {
                if let Some(rest) = prop.key().strip_prefix(TXT_PREFIX) {
                    let val = prop.val_str();
                    if !val.is_empty() {
                        txt.insert(rest.to_string(), val.to_string());
                    }
                }
            }
            let display_name = svc
                .get_property_val_str(NAME_KEY)
                .map(str::to_string)
                .filter(|s| !s.is_empty());

            known
                .lock()
                .unwrap()
                .insert(svc.get_fullname().to_string(), remote_id);

            vec![PeerEvent::Up(DiscoveredPeer {
                id: remote_id,
                services: vec![ServiceAd {
                    tag: tag.clone(),
                    addrs,
                    txt,
                }],
                source: SOURCE,
                seen_at: SystemTime::now(),
                display_name,
            })]
        }
        ServiceEvent::ServiceRemoved(_, fullname) => {
            let removed = known.lock().unwrap().remove(&fullname);
            removed
                .map(|id| {
                    vec![PeerEvent::Down {
                        id,
                        source: SOURCE,
                    }]
                })
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

fn decode_peer_id(hex_str: &str) -> Option<PeerId> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(id)
}
