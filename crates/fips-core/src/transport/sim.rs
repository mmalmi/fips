//! In-memory simulated transport for production-backed simulations.
//!
//! The transport itself is deliberately small: it exposes a UDP-like,
//! connectionless packet interface to `Node`, while a shared `SimNetwork`
//! decides whether and when a packet reaches the destination. This lets
//! simulations exercise the real FIPS handshakes, sessions, tree routing, and
//! forwarding code without binding OS sockets.

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::SimTransportConfig;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Default in-memory link used when no per-link override is configured.
pub const DEFAULT_SIM_LINK: SimLink = SimLink {
    latency_ms: 1,
    throughput_mbps: 10_000.0,
    loss_probability: 0.0,
    up: true,
};

/// Simulated bidirectional link properties.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SimLink {
    /// One-way propagation latency.
    pub latency_ms: u64,
    /// Serialization bandwidth in megabits per second.
    pub throughput_mbps: f64,
    /// Independent packet drop probability in `[0.0, 1.0]`.
    pub loss_probability: f64,
    /// Whether the link is currently usable.
    pub up: bool,
}

impl Default for SimLink {
    fn default() -> Self {
        DEFAULT_SIM_LINK
    }
}

/// Per-node simulated behavior.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SimNodeBehavior {
    /// Whether the node can send and receive transport packets.
    pub up: bool,
    /// Independent egress packet drop probability. `1.0` models a blackhole
    /// forwarder that receives but never forwards.
    pub egress_loss_probability: f64,
}

impl Default for SimNodeBehavior {
    fn default() -> Self {
        Self {
            up: true,
            egress_loss_probability: 0.0,
        }
    }
}

/// Cumulative network counters.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SimNetworkStats {
    pub packets_sent: u64,
    pub packets_delivered: u64,
    pub packets_dropped_loss: u64,
    pub packets_dropped_egress: u64,
    pub packets_dropped_down: u64,
    pub packets_dropped_no_route: u64,
    pub bytes_sent: u64,
    pub bytes_delivered: u64,
}

impl SimNetworkStats {
    /// Saturating counter delta since an earlier snapshot.
    pub fn delta_since(&self, before: &Self) -> Self {
        Self {
            packets_sent: self.packets_sent.saturating_sub(before.packets_sent),
            packets_delivered: self
                .packets_delivered
                .saturating_sub(before.packets_delivered),
            packets_dropped_loss: self
                .packets_dropped_loss
                .saturating_sub(before.packets_dropped_loss),
            packets_dropped_egress: self
                .packets_dropped_egress
                .saturating_sub(before.packets_dropped_egress),
            packets_dropped_down: self
                .packets_dropped_down
                .saturating_sub(before.packets_dropped_down),
            packets_dropped_no_route: self
                .packets_dropped_no_route
                .saturating_sub(before.packets_dropped_no_route),
            bytes_sent: self.bytes_sent.saturating_sub(before.bytes_sent),
            bytes_delivered: self.bytes_delivered.saturating_sub(before.bytes_delivered),
        }
    }
}

#[derive(Clone)]
struct EndpointEntry {
    transport_id: TransportId,
    packet_tx: PacketTx,
}

struct SimNetworkInner {
    endpoints: HashMap<String, EndpointEntry>,
    links: HashMap<(String, String), SimLink>,
    node_behaviors: HashMap<String, SimNodeBehavior>,
    link_queues: HashMap<(String, String), Instant>,
    default_link: SimLink,
    rng: StdRng,
    stats: SimNetworkStats,
}

/// Shared in-memory packet network.
#[derive(Clone)]
pub struct SimNetwork {
    inner: Arc<Mutex<SimNetworkInner>>,
}

impl SimNetwork {
    /// Create a deterministic simulated network.
    pub fn new(seed: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimNetworkInner {
                endpoints: HashMap::new(),
                links: HashMap::new(),
                node_behaviors: HashMap::new(),
                link_queues: HashMap::new(),
                default_link: SimLink::default(),
                rng: StdRng::seed_from_u64(seed),
                stats: SimNetworkStats::default(),
            })),
        }
    }

    /// Set the fallback link used when no explicit link is configured.
    pub fn set_default_link(&self, link: SimLink) {
        self.inner.lock().expect("sim network lock").default_link = sanitize_link(link);
    }

    /// Configure a bidirectional link between two simulated addresses.
    pub fn set_link(&self, a: impl Into<String>, b: impl Into<String>, link: SimLink) {
        let mut inner = self.inner.lock().expect("sim network lock");
        inner
            .links
            .insert(link_key(a.into(), b.into()), sanitize_link(link));
    }

    /// Change only the up/down state of a configured link.
    pub fn set_link_up(&self, a: impl Into<String>, b: impl Into<String>, up: bool) {
        let mut inner = self.inner.lock().expect("sim network lock");
        let key = link_key(a.into(), b.into());
        let mut link = inner.links.get(&key).copied().unwrap_or(inner.default_link);
        link.up = up;
        inner.links.insert(key, link);
    }

    /// Configure node-level behavior.
    pub fn set_node_behavior(&self, addr: impl Into<String>, behavior: SimNodeBehavior) {
        self.inner
            .lock()
            .expect("sim network lock")
            .node_behaviors
            .insert(addr.into(), sanitize_node_behavior(behavior));
    }

    /// Change only the up/down state of a node.
    pub fn set_node_up(&self, addr: impl Into<String>, up: bool) {
        let mut inner = self.inner.lock().expect("sim network lock");
        let entry = inner.node_behaviors.entry(addr.into()).or_default();
        entry.up = up;
    }

    /// Change only node egress packet loss.
    pub fn set_node_egress_loss(&self, addr: impl Into<String>, probability: f64) {
        let mut inner = self.inner.lock().expect("sim network lock");
        let entry = inner.node_behaviors.entry(addr.into()).or_default();
        entry.egress_loss_probability = probability.clamp(0.0, 1.0);
    }

    /// Return a cumulative stats snapshot.
    pub fn stats(&self) -> SimNetworkStats {
        self.inner.lock().expect("sim network lock").stats.clone()
    }

    fn register_endpoint(&self, addr: String, transport_id: TransportId, packet_tx: PacketTx) {
        let mut inner = self.inner.lock().expect("sim network lock");
        inner.node_behaviors.entry(addr.clone()).or_default();
        inner.endpoints.insert(
            addr,
            EndpointEntry {
                transport_id,
                packet_tx,
            },
        );
    }

    fn unregister_endpoint(&self, addr: &str) {
        self.inner
            .lock()
            .expect("sim network lock")
            .endpoints
            .remove(addr);
    }

    async fn send(
        &self,
        source: &str,
        dest: &TransportAddr,
        data: Vec<u8>,
    ) -> Result<usize, TransportError> {
        let dest = dest
            .as_str()
            .ok_or_else(|| TransportError::InvalidAddress("sim address must be UTF-8".into()))?
            .to_string();
        let bytes = data.len();

        let decision = {
            let mut inner = self.inner.lock().expect("sim network lock");
            inner.stats.packets_sent += 1;
            inner.stats.bytes_sent += bytes as u64;

            let source_behavior = inner
                .node_behaviors
                .get(source)
                .copied()
                .unwrap_or_default();
            let dest_behavior = inner.node_behaviors.get(&dest).copied().unwrap_or_default();

            if !source_behavior.up || !dest_behavior.up {
                inner.stats.packets_dropped_down += 1;
                return Ok(bytes);
            }

            if inner.rng.random::<f64>() < source_behavior.egress_loss_probability {
                inner.stats.packets_dropped_egress += 1;
                return Ok(bytes);
            }

            let key = link_key(source.to_string(), dest.clone());
            let link = inner.links.get(&key).copied().unwrap_or(inner.default_link);
            if !link.up {
                inner.stats.packets_dropped_down += 1;
                return Ok(bytes);
            }

            if inner.rng.random::<f64>() < link.loss_probability {
                inner.stats.packets_dropped_loss += 1;
                return Ok(bytes);
            }

            let Some(endpoint) = inner.endpoints.get(&dest).cloned() else {
                inner.stats.packets_dropped_no_route += 1;
                return Ok(bytes);
            };

            let now = Instant::now();
            let available_at = inner.link_queues.entry(key).or_insert(now);
            let serialization = serialization_delay(bytes, link.throughput_mbps);
            let queue_delay = available_at.saturating_duration_since(now);
            *available_at = (*available_at).max(now) + serialization;
            let delay = queue_delay + Duration::from_millis(link.latency_ms) + serialization;

            DeliveryDecision {
                endpoint,
                source: TransportAddr::from_string(source),
                data,
                delay,
            }
        };

        let network = self.clone();
        tokio::spawn(async move {
            if !decision.delay.is_zero() {
                tokio::time::sleep(decision.delay).await;
            }
            let delivered_bytes = decision.data.len() as u64;
            let packet = ReceivedPacket::new(
                decision.endpoint.transport_id,
                decision.source,
                decision.data,
            );
            if decision.endpoint.packet_tx.send(packet).is_ok() {
                let mut inner = network.inner.lock().expect("sim network lock");
                inner.stats.packets_delivered += 1;
                inner.stats.bytes_delivered += delivered_bytes;
            } else {
                let mut inner = network.inner.lock().expect("sim network lock");
                inner.stats.packets_dropped_no_route += 1;
            }
        });

        Ok(bytes)
    }
}

struct DeliveryDecision {
    endpoint: EndpointEntry,
    source: TransportAddr,
    data: Vec<u8>,
    delay: Duration,
}

static SIM_NETWORKS: OnceLock<Mutex<HashMap<String, SimNetwork>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, SimNetwork>> {
    SIM_NETWORKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a simulated network so `SimTransport` instances can attach to it.
pub fn register_sim_network(name: impl Into<String>, network: SimNetwork) {
    registry()
        .lock()
        .expect("sim registry lock")
        .insert(name.into(), network);
}

/// Remove a simulated network registration.
pub fn unregister_sim_network(name: &str) -> Option<SimNetwork> {
    registry().lock().expect("sim registry lock").remove(name)
}

fn lookup_sim_network(name: &str) -> Option<SimNetwork> {
    registry()
        .lock()
        .expect("sim registry lock")
        .get(name)
        .cloned()
}

/// In-memory UDP-like transport.
pub struct SimTransport {
    transport_id: TransportId,
    name: Option<String>,
    config: SimTransportConfig,
    state: TransportState,
    packet_tx: PacketTx,
    network: Option<SimNetwork>,
    local_addr: Option<String>,
    delivery_tasks: Vec<JoinHandle<()>>,
}

impl SimTransport {
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: SimTransportConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            packet_tx,
            network: None,
            local_addr: None,
            delivery_tasks: Vec::new(),
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn stats(&self) -> Option<SimNetworkStats> {
        self.network.as_ref().map(SimNetwork::stats)
    }

    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;
        let network_name = self.config.network().to_string();
        let network = lookup_sim_network(&network_name).ok_or_else(|| {
            TransportError::StartFailed(format!("sim network '{}' is not registered", network_name))
        })?;
        let addr = self
            .config
            .addr
            .clone()
            .or_else(|| self.name.clone())
            .ok_or_else(|| {
                TransportError::StartFailed(
                    "sim transport requires an addr or named instance".to_string(),
                )
            })?;

        network.register_endpoint(addr.clone(), self.transport_id, self.packet_tx.clone());
        self.network = Some(network);
        self.local_addr = Some(addr);
        self.state = TransportState::Up;
        Ok(())
    }

    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        if let (Some(network), Some(addr)) = (&self.network, &self.local_addr) {
            network.unregister_endpoint(addr);
        }
        for task in self.delivery_tasks.drain(..) {
            task.abort();
        }
        self.network = None;
        self.local_addr = None;
        self.state = TransportState::Down;
        Ok(())
    }

    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        if data.len() > self.config.mtu() as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        let source = self
            .local_addr
            .as_deref()
            .ok_or(TransportError::NotStarted)?;
        let network = self.network.as_ref().ok_or(TransportError::NotStarted)?;
        network.send(source, addr, data.to_vec()).await
    }
}

impl Transport for SimTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::SIM
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for sim transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for sim transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for sim transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }

    fn auto_connect(&self) -> bool {
        self.config.auto_connect()
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }
}

fn link_key(a: String, b: String) -> (String, String) {
    if a <= b { (a, b) } else { (b, a) }
}

fn serialization_delay(bytes: usize, throughput_mbps: f64) -> Duration {
    if throughput_mbps <= 0.0 || !throughput_mbps.is_finite() {
        return Duration::from_secs(1);
    }
    let bits = bytes as f64 * 8.0;
    Duration::from_secs_f64(bits / (throughput_mbps * 1_000_000.0))
}

fn sanitize_link(mut link: SimLink) -> SimLink {
    link.loss_probability = link.loss_probability.clamp(0.0, 1.0);
    if !link.throughput_mbps.is_finite() || link.throughput_mbps <= 0.0 {
        link.throughput_mbps = 1.0;
    }
    link
}

fn sanitize_node_behavior(mut behavior: SimNodeBehavior) -> SimNodeBehavior {
    behavior.egress_loss_probability = behavior.egress_loss_probability.clamp(0.0, 1.0);
    behavior
}
