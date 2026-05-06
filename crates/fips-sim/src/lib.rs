//! Production-backed simulation tools for FIPS routing evaluation.
//!
//! `fips-sim` starts real `FipsEndpoint` nodes and runs them over the
//! in-memory `sim` transport from `fips-core`. The simulator controls topology,
//! latency, bandwidth, packet loss, blackhole/flaky peers, and churn while the
//! actual FIPS handshake, tree, discovery, session, and forwarding code handles
//! routing.

pub use fips_core::config::RoutingMode;

use fips_core::config::{PeerConfig, SimTransportConfig, TransportInstances};
use fips_core::{
    Config, FipsEndpoint, FipsEndpointError, Identity, IdentityConfig, SimLink, SimNetwork,
    SimNetworkStats, SimNodeBehavior, register_sim_network, unregister_sim_network,
};
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::time::Duration;
use tokio::time::Instant;

/// Topology generator used by the production simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyProfile {
    /// Regional mesh with a small set of stronger backbone links.
    Standard,
    /// Uniform random mesh with less structured link quality.
    RandomMesh,
}

/// Misbehaving peer and churn mix.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AdversaryConfig {
    /// Fraction of nodes that blackhole egress after the clean baseline phase.
    pub blackhole_fraction: f64,
    /// Fraction of nodes that probabilistically drop egress after baseline.
    pub flaky_fraction: f64,
    /// Drop probability used by flaky nodes.
    pub flaky_drop_probability: f64,
    /// Fraction of nodes marked down after baseline.
    pub churned_node_fraction: f64,
    /// Fraction of links marked down after baseline.
    pub churned_link_fraction: f64,
}

impl Default for AdversaryConfig {
    fn default() -> Self {
        Self {
            blackhole_fraction: 0.06,
            flaky_fraction: 0.06,
            flaky_drop_probability: 0.30,
            churned_node_fraction: 0.04,
            churned_link_fraction: 0.05,
        }
    }
}

/// Simulation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimConfig {
    /// Number of production FIPS nodes to start.
    pub node_count: usize,
    /// Target number of undirected topology edges.
    pub target_edges: usize,
    /// Endpoint-data probes per phase.
    pub route_probe_count: usize,
    /// Chunked stream transfers per phase.
    pub stream_probe_count: usize,
    /// Bytes per stream transfer.
    pub stream_size_bytes: usize,
    /// Endpoint payload bytes per stream chunk.
    pub chunk_size_bytes: usize,
    /// Random seed for topology, identities, roles, and traffic pairs.
    pub seed: u64,
    /// Initial settling time before clean traffic starts.
    pub convergence_wait_ms: u64,
    /// Settling time after impairments are applied.
    pub reconvergence_wait_ms: u64,
    /// Per-probe delivery timeout.
    pub delivery_timeout_ms: u64,
    /// Per-stream delivery timeout.
    pub stream_timeout_ms: u64,
    /// Topology shape.
    pub topology: TopologyProfile,
    /// Production FIPS routing mode used by all nodes.
    pub routing_mode: RoutingMode,
    /// Misbehavior and churn mix applied after the clean baseline phase.
    pub adversary: AdversaryConfig,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            node_count: 64,
            target_edges: 160,
            route_probe_count: 32,
            stream_probe_count: 8,
            stream_size_bytes: 256 * 1024,
            chunk_size_bytes: 1024,
            seed: 42,
            convergence_wait_ms: 2_500,
            reconvergence_wait_ms: 1_500,
            delivery_timeout_ms: 4_000,
            stream_timeout_ms: 8_000,
            topology: TopologyProfile::Standard,
            routing_mode: RoutingMode::Tree,
            adversary: AdversaryConfig::default(),
        }
    }
}

/// Whole simulation report.
#[derive(Debug, Clone, Serialize)]
pub struct ProductionSimReport {
    pub config: SimConfig,
    pub topology: TopologyStats,
    pub behavior_counts: BTreeMap<String, usize>,
    pub baseline: PhaseReport,
    pub impaired: PhaseReport,
}

/// Side-by-side report for original FIPS routing and the reply-learned mode.
#[derive(Debug, Clone, Serialize)]
pub struct RoutingComparisonReport {
    pub original: ProductionSimReport,
    pub ours: ProductionSimReport,
}

/// Topology summary.
#[derive(Debug, Clone, Serialize)]
pub struct TopologyStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub avg_degree: f64,
    pub min_degree: usize,
    pub max_degree: usize,
    pub backbone_links: usize,
    pub regional_links: usize,
    pub long_haul_links: usize,
    pub avg_latency_ms: f64,
    pub avg_loss_probability: f64,
    pub min_throughput_mbps: f64,
    pub max_throughput_mbps: f64,
    pub root_node_addr: String,
}

/// One traffic phase.
#[derive(Debug, Clone, Serialize)]
pub struct PhaseReport {
    pub label: &'static str,
    pub route_probes: ProbeStats,
    pub streams: StreamStats,
    pub network: SimNetworkStats,
    pub elapsed_ms: u64,
}

/// Endpoint-data probe stats.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProbeStats {
    pub attempted: usize,
    pub delivered: usize,
    pub failed_send: usize,
    pub timed_out: usize,
    pub success_rate: f64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
}

/// Chunked endpoint stream stats.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StreamStats {
    pub streams: usize,
    pub completed: usize,
    pub failed: usize,
    pub success_rate: f64,
    pub stream_size_bytes: usize,
    pub chunk_size_bytes: usize,
    pub chunks_sent: usize,
    pub chunks_delivered: usize,
    pub chunks_lost: usize,
    pub chunk_loss_rate: f64,
    pub avg_completion_ms: f64,
    pub p95_completion_ms: f64,
    pub avg_throughput_mbps: f64,
    pub p95_throughput_mbps: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Honest,
    Blackhole,
    Flaky,
    Churned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkClass {
    Backbone,
    Regional,
    LongHaul,
}

#[derive(Clone)]
struct NodeSpec {
    index: usize,
    secret_hex: String,
    npub: String,
    node_addr: fips_core::NodeAddr,
    sim_addr: String,
    role: NodeRole,
    region: usize,
    backbone: bool,
}

#[derive(Clone)]
struct EdgeSpec {
    a: usize,
    b: usize,
    link: SimLink,
    class: LinkClass,
    churned: bool,
}

/// Production-backed FIPS simulator.
pub struct Simulation {
    config: SimConfig,
    nodes: Vec<NodeSpec>,
    edges: Vec<EdgeSpec>,
    adjacency: HashMap<usize, Vec<usize>>,
    network_id: String,
}

impl Simulation {
    /// Build a deterministic production simulation.
    pub fn new(config: SimConfig) -> Self {
        assert!(config.node_count >= 2, "node_count must be at least 2");
        assert!(
            config.chunk_size_bytes > 64,
            "chunk_size_bytes must leave room for simulator headers"
        );

        let mut rng = StdRng::seed_from_u64(config.seed);
        let roles = assign_roles(config.node_count, config.adversary, &mut rng);
        let backbone_nodes = choose_backbone_nodes(config.node_count, &mut rng);
        let mut nodes = Vec::with_capacity(config.node_count);

        for (index, role) in roles.iter().copied().enumerate().take(config.node_count) {
            let (identity, secret_hex) = deterministic_identity(config.seed, index);
            nodes.push(NodeSpec {
                index,
                secret_hex,
                npub: identity.npub(),
                node_addr: *identity.node_addr(),
                sim_addr: format!("node-{index}"),
                role,
                region: index % 4,
                backbone: backbone_nodes.contains(&index),
            });
        }

        let mut edges = generate_edges(&config, &nodes, &mut rng);
        mark_churned_links(&mut edges, config.adversary.churned_link_fraction, &mut rng);
        let adjacency = build_adjacency(config.node_count, &edges);
        let network_id = format!("fips-sim-{}-{}", config.seed, rand::random::<u64>());

        Self {
            config,
            nodes,
            edges,
            adjacency,
            network_id,
        }
    }

    /// Run the clean baseline phase, apply impairments, then run the impaired
    /// phase. All traffic uses real FIPS endpoint data over the production
    /// session and forwarding stack.
    pub async fn run(&self) -> Result<ProductionSimReport, SimError> {
        let network = SimNetwork::new(self.config.seed ^ 0x51_4d_4e_45_54);
        for edge in &self.edges {
            network.set_link(
                self.nodes[edge.a].sim_addr.clone(),
                self.nodes[edge.b].sim_addr.clone(),
                edge.link,
            );
        }
        register_sim_network(self.network_id.clone(), network.clone());

        let mut endpoints = match self.start_endpoints().await {
            Ok(endpoints) => endpoints,
            Err(error) => {
                unregister_sim_network(&self.network_id);
                return Err(error);
            }
        };

        tokio::time::sleep(Duration::from_millis(self.config.convergence_wait_ms)).await;
        let baseline = self.run_phase("baseline", &endpoints, &network, 0).await;

        self.apply_impairments(&network);
        tokio::time::sleep(Duration::from_millis(self.config.reconvergence_wait_ms)).await;
        let impaired = self.run_phase("impaired", &endpoints, &network, 1).await;

        let mut shutdown_error = None;
        while let Some(endpoint) = endpoints.pop() {
            if let Err(error) = endpoint.shutdown().await {
                shutdown_error = Some(error);
            }
        }
        unregister_sim_network(&self.network_id);
        if let Some(error) = shutdown_error {
            return Err(error.into());
        }

        Ok(ProductionSimReport {
            config: self.config.clone(),
            topology: self.topology_stats(),
            behavior_counts: self.behavior_counts(),
            baseline,
            impaired,
        })
    }

    /// Convenience JSON report.
    pub async fn report_json(&self) -> Result<serde_json::Value, SimError> {
        Ok(serde_json::to_value(self.run().await?).expect("simulation report serializes"))
    }

    async fn start_endpoints(&self) -> Result<Vec<FipsEndpoint>, SimError> {
        let mut endpoints = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            match FipsEndpoint::builder()
                .config(self.node_config(node))
                .without_system_tun()
                .packet_channel_capacity(8192)
                .bind()
                .await
            {
                Ok(endpoint) => endpoints.push(endpoint),
                Err(error) => {
                    while let Some(endpoint) = endpoints.pop() {
                        let _ = endpoint.shutdown().await;
                    }
                    return Err(error.into());
                }
            }
        }
        Ok(endpoints)
    }

    fn node_config(&self, node: &NodeSpec) -> Config {
        let mut config = Config::new();
        config.node.identity = IdentityConfig {
            nsec: Some(node.secret_hex.clone()),
            persistent: false,
        };
        config.node.limits.max_connections = self.config.node_count + 32;
        config.node.limits.max_peers = self.config.node_count + 32;
        config.node.limits.max_links = self.config.node_count + 32;
        config.node.limits.max_pending_inbound = self.config.node_count * 16;
        config.node.rate_limit.handshake_burst = 10_000;
        config.node.rate_limit.handshake_rate = 10_000.0;
        config.node.rate_limit.handshake_timeout_secs = 8;
        config.node.rate_limit.handshake_resend_interval_ms = 100;
        config.node.rate_limit.handshake_max_resends = 20;
        config.node.retry.base_interval_secs = 1;
        config.node.retry.max_retries = 20;
        config.node.retry.max_backoff_secs = 4;
        config.node.discovery.attempt_timeouts_secs = vec![1, 1, 2];
        config.node.discovery.forward_min_interval_secs = 0;
        config.node.tree.announce_min_interval_ms = 25;
        config.node.tree.parent_hysteresis = 0.0;
        config.node.tree.hold_down_secs = 0;
        config.node.tree.reeval_interval_secs = 1;
        config.node.routing.mode = self.config.routing_mode;
        config.node.heartbeat_interval_secs = 1;
        config.node.link_dead_timeout_secs = 4;
        config.tun.enabled = false;
        config.dns.enabled = false;
        config.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(self.network_id.clone()),
            addr: Some(node.sim_addr.clone()),
            mtu: Some(1280),
            auto_connect: Some(false),
            accept_connections: Some(true),
        });
        config.peers = self
            .adjacency
            .get(&node.index)
            .into_iter()
            .flat_map(|neighbors| neighbors.iter())
            .map(|neighbor| {
                let peer = &self.nodes[*neighbor];
                PeerConfig::new(peer.npub.clone(), "sim", peer.sim_addr.clone())
                    .with_alias(format!("node-{}", peer.index))
            })
            .collect();
        config
    }

    async fn run_phase(
        &self,
        label: &'static str,
        endpoints: &[FipsEndpoint],
        network: &SimNetwork,
        phase_index: u64,
    ) -> PhaseReport {
        let before = network.stats();
        let start = Instant::now();
        let route_probes = self.run_route_probes(label, endpoints, phase_index).await;
        let streams = self.run_streams(label, endpoints, phase_index).await;
        let network_delta = network.stats().delta_since(&before);

        PhaseReport {
            label,
            route_probes,
            streams,
            network: network_delta,
            elapsed_ms: start.elapsed().as_millis() as u64,
        }
    }

    async fn run_route_probes(
        &self,
        label: &'static str,
        endpoints: &[FipsEndpoint],
        phase_index: u64,
    ) -> ProbeStats {
        let eligible = self.eligible_endpoint_indices();
        if eligible.len() < 2 || self.config.route_probe_count == 0 {
            return ProbeStats::default();
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed ^ 0x70_52_4f_42_45 ^ phase_index);
        let mut latencies = Vec::new();
        let mut failed_send = 0usize;
        let mut timed_out = 0usize;

        for probe in 0..self.config.route_probe_count {
            let (src, dst) = pick_pair(&eligible, &mut rng);
            let request = fixed_payload(
                format!("fips-sim|probe|{label}|{probe}|{src}|{dst}|").as_bytes(),
                192,
            );
            let reply = fixed_payload(
                format!("fips-sim|probe-reply|{label}|{probe}|{dst}|{src}|").as_bytes(),
                192,
            );
            let start = Instant::now();
            match endpoints[src]
                .send(self.nodes[dst].npub.clone(), request.clone())
                .await
            {
                Ok(()) => {
                    let timeout = Duration::from_millis(self.config.delivery_timeout_ms);
                    if !recv_exact(&endpoints[dst], &request, timeout).await {
                        timed_out += 1;
                        continue;
                    }

                    if endpoints[dst]
                        .send(self.nodes[src].npub.clone(), reply.clone())
                        .await
                        .is_err()
                    {
                        failed_send += 1;
                        continue;
                    }

                    if recv_exact(&endpoints[src], &reply, timeout).await {
                        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
                    } else {
                        timed_out += 1;
                    }
                }
                Err(_) => failed_send += 1,
            }
        }

        probe_stats(
            self.config.route_probe_count,
            failed_send,
            timed_out,
            latencies,
        )
    }

    async fn run_streams(
        &self,
        label: &'static str,
        endpoints: &[FipsEndpoint],
        phase_index: u64,
    ) -> StreamStats {
        let eligible = self.eligible_endpoint_indices();
        if eligible.len() < 2 || self.config.stream_probe_count == 0 {
            return StreamStats {
                stream_size_bytes: self.config.stream_size_bytes,
                chunk_size_bytes: self.config.chunk_size_bytes,
                ..StreamStats::default()
            };
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed ^ 0x53_54_52_45_41_4d ^ phase_index);
        let mut completions = Vec::new();
        let mut throughputs = Vec::new();
        let mut chunks_sent = 0usize;
        let mut chunks_delivered = 0usize;

        for stream in 0..self.config.stream_probe_count {
            let (src, dst) = pick_pair(&eligible, &mut rng);
            let warmup = fixed_payload(
                format!("fips-sim|stream-request|{label}|{stream}|{src}|{dst}|").as_bytes(),
                192,
            );
            let chunks = make_stream_payloads(
                label,
                stream,
                dst,
                src,
                self.config.stream_size_bytes,
                self.config.chunk_size_bytes,
            );

            let start = Instant::now();
            if endpoints[src]
                .send(self.nodes[dst].npub.clone(), warmup.clone())
                .await
                .is_err()
            {
                continue;
            }
            let warmup_timeout = Duration::from_millis(self.config.delivery_timeout_ms);
            if !recv_exact(&endpoints[dst], &warmup, warmup_timeout).await {
                continue;
            }

            chunks_sent += chunks.len();
            let mut expected = chunks.iter().cloned().collect::<HashSet<_>>();
            for chunk in &chunks {
                let _ = endpoints[dst]
                    .send(self.nodes[src].npub.clone(), chunk.clone())
                    .await;
            }

            let timeout = Duration::from_millis(self.config.stream_timeout_ms);
            let delivered = recv_payload_set(&endpoints[src], &mut expected, timeout).await;
            chunks_delivered += delivered;
            if expected.is_empty() {
                let completion_ms = start.elapsed().as_secs_f64() * 1000.0;
                completions.push(completion_ms);
                let throughput_mbps =
                    (self.config.stream_size_bytes as f64 * 8.0) / completion_ms / 1000.0;
                throughputs.push(throughput_mbps);
            }
        }

        let completed = completions.len();
        let failed = self.config.stream_probe_count.saturating_sub(completed);
        let chunks_lost = chunks_sent.saturating_sub(chunks_delivered);
        StreamStats {
            streams: self.config.stream_probe_count,
            completed,
            failed,
            success_rate: rate(completed, self.config.stream_probe_count),
            stream_size_bytes: self.config.stream_size_bytes,
            chunk_size_bytes: self.config.chunk_size_bytes,
            chunks_sent,
            chunks_delivered,
            chunks_lost,
            chunk_loss_rate: rate(chunks_lost, chunks_sent),
            avg_completion_ms: mean(&completions),
            p95_completion_ms: percentile(completions.clone(), 0.95),
            avg_throughput_mbps: mean(&throughputs),
            p95_throughput_mbps: percentile(throughputs, 0.95),
        }
    }

    fn apply_impairments(&self, network: &SimNetwork) {
        for node in &self.nodes {
            match node.role {
                NodeRole::Honest => {}
                NodeRole::Blackhole => network.set_node_egress_loss(node.sim_addr.clone(), 1.0),
                NodeRole::Flaky => network.set_node_egress_loss(
                    node.sim_addr.clone(),
                    self.config.adversary.flaky_drop_probability,
                ),
                NodeRole::Churned => {
                    network.set_node_behavior(
                        node.sim_addr.clone(),
                        SimNodeBehavior {
                            up: false,
                            egress_loss_probability: 0.0,
                        },
                    );
                }
            }
        }
        for edge in &self.edges {
            if edge.churned {
                network.set_link_up(
                    self.nodes[edge.a].sim_addr.clone(),
                    self.nodes[edge.b].sim_addr.clone(),
                    false,
                );
            }
        }
    }

    fn eligible_endpoint_indices(&self) -> Vec<usize> {
        let honest = self
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Honest)
            .map(|node| node.index)
            .collect::<Vec<_>>();
        if honest.len() >= 2 {
            honest
        } else {
            (0..self.nodes.len()).collect()
        }
    }

    fn behavior_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for node in &self.nodes {
            let key = match node.role {
                NodeRole::Honest => "honest",
                NodeRole::Blackhole => "blackhole",
                NodeRole::Flaky => "flaky",
                NodeRole::Churned => "churned",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }

    fn topology_stats(&self) -> TopologyStats {
        let mut degrees = vec![0usize; self.nodes.len()];
        let mut backbone_links = 0usize;
        let mut regional_links = 0usize;
        let mut long_haul_links = 0usize;
        let mut latencies = Vec::new();
        let mut losses = Vec::new();
        let mut throughputs = Vec::new();

        for edge in &self.edges {
            degrees[edge.a] += 1;
            degrees[edge.b] += 1;
            match edge.class {
                LinkClass::Backbone => backbone_links += 1,
                LinkClass::Regional => regional_links += 1,
                LinkClass::LongHaul => long_haul_links += 1,
            }
            latencies.push(edge.link.latency_ms as f64);
            losses.push(edge.link.loss_probability);
            throughputs.push(edge.link.throughput_mbps);
        }

        let root = self
            .nodes
            .iter()
            .map(|node| node.node_addr)
            .min()
            .expect("non-empty topology");

        TopologyStats {
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            avg_degree: self.edges.len() as f64 * 2.0 / self.nodes.len() as f64,
            min_degree: degrees.iter().copied().min().unwrap_or(0),
            max_degree: degrees.iter().copied().max().unwrap_or(0),
            backbone_links,
            regional_links,
            long_haul_links,
            avg_latency_ms: mean(&latencies),
            avg_loss_probability: mean(&losses),
            min_throughput_mbps: throughputs.iter().copied().fold(f64::INFINITY, f64::min),
            max_throughput_mbps: throughputs.iter().copied().fold(0.0, f64::max),
            root_node_addr: root.to_string(),
        }
    }
}

/// Run the same deterministic scenario once with original tree routing and once
/// with reply-learned routing.
pub async fn compare_original_vs_ours(
    mut config: SimConfig,
) -> Result<RoutingComparisonReport, SimError> {
    config.routing_mode = RoutingMode::Tree;
    let original = Simulation::new(config.clone()).run().await?;

    config.routing_mode = RoutingMode::ReplyLearned;
    let ours = Simulation::new(config).run().await?;

    Ok(RoutingComparisonReport { original, ours })
}

/// Simulation failure.
#[derive(Debug)]
pub enum SimError {
    Endpoint(FipsEndpointError),
}

impl fmt::Display for SimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimError::Endpoint(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SimError {}

impl From<FipsEndpointError> for SimError {
    fn from(value: FipsEndpointError) -> Self {
        Self::Endpoint(value)
    }
}

fn assign_roles(node_count: usize, adversary: AdversaryConfig, rng: &mut StdRng) -> Vec<NodeRole> {
    let mut indices = (0..node_count).collect::<Vec<_>>();
    shuffle(&mut indices, rng);

    let blackholes = fraction_count(node_count, adversary.blackhole_fraction);
    let flaky = fraction_count(node_count, adversary.flaky_fraction);
    let churned = fraction_count(node_count, adversary.churned_node_fraction);
    let mut roles = vec![NodeRole::Honest; node_count];
    let mut cursor = 0usize;

    for _ in 0..blackholes {
        if let Some(index) = indices.get(cursor) {
            roles[*index] = NodeRole::Blackhole;
            cursor += 1;
        }
    }
    for _ in 0..flaky {
        if let Some(index) = indices.get(cursor) {
            roles[*index] = NodeRole::Flaky;
            cursor += 1;
        }
    }
    for _ in 0..churned {
        if let Some(index) = indices.get(cursor) {
            roles[*index] = NodeRole::Churned;
            cursor += 1;
        }
    }
    roles
}

fn choose_backbone_nodes(node_count: usize, rng: &mut StdRng) -> HashSet<usize> {
    let count = (node_count / 8).clamp(2, node_count);
    let mut indices = (0..node_count).collect::<Vec<_>>();
    shuffle(&mut indices, rng);
    indices.into_iter().take(count).collect()
}

fn generate_edges(config: &SimConfig, nodes: &[NodeSpec], rng: &mut StdRng) -> Vec<EdgeSpec> {
    let mut edges = Vec::new();
    let mut seen = HashSet::new();

    for node in 1..nodes.len() {
        let peer = rng.random_range(0..node);
        push_edge(
            node,
            peer,
            nodes,
            rng,
            config.topology,
            &mut seen,
            &mut edges,
        );
    }

    let max_edges = nodes.len() * (nodes.len() - 1) / 2;
    let target = config.target_edges.clamp(nodes.len() - 1, max_edges);
    let mut attempts = 0usize;
    while edges.len() < target && attempts < target * 100 {
        attempts += 1;
        let (a, b) = match config.topology {
            TopologyProfile::Standard => pick_standard_edge(nodes, rng),
            TopologyProfile::RandomMesh => {
                let a = rng.random_range(0..nodes.len());
                let mut b = rng.random_range(0..nodes.len() - 1);
                if b >= a {
                    b += 1;
                }
                (a, b)
            }
        };
        push_edge(a, b, nodes, rng, config.topology, &mut seen, &mut edges);
    }

    edges
}

fn pick_standard_edge(nodes: &[NodeSpec], rng: &mut StdRng) -> (usize, usize) {
    let roll = rng.random::<f64>();
    if roll < 0.20 {
        let backbone = nodes
            .iter()
            .filter(|node| node.backbone)
            .map(|node| node.index)
            .collect::<Vec<_>>();
        if backbone.len() >= 2 {
            return pick_pair(&backbone, rng);
        }
    }

    if roll < 0.75 {
        let region = rng.random_range(0..4);
        let regional = nodes
            .iter()
            .filter(|node| node.region == region)
            .map(|node| node.index)
            .collect::<Vec<_>>();
        if regional.len() >= 2 {
            return pick_pair(&regional, rng);
        }
    }

    let a = rng.random_range(0..nodes.len());
    let mut b = rng.random_range(0..nodes.len() - 1);
    if b >= a {
        b += 1;
    }
    (a, b)
}

fn push_edge(
    a: usize,
    b: usize,
    nodes: &[NodeSpec],
    rng: &mut StdRng,
    profile: TopologyProfile,
    seen: &mut HashSet<(usize, usize)>,
    edges: &mut Vec<EdgeSpec>,
) {
    if a == b {
        return;
    }
    let key = if a < b { (a, b) } else { (b, a) };
    if !seen.insert(key) {
        return;
    }
    let class = classify_edge(&nodes[a], &nodes[b], profile);
    edges.push(EdgeSpec {
        a: key.0,
        b: key.1,
        link: generate_link(class, rng, profile),
        class,
        churned: false,
    });
}

fn classify_edge(a: &NodeSpec, b: &NodeSpec, profile: TopologyProfile) -> LinkClass {
    match profile {
        TopologyProfile::RandomMesh => LinkClass::Regional,
        TopologyProfile::Standard if a.backbone && b.backbone => LinkClass::Backbone,
        TopologyProfile::Standard if a.region == b.region => LinkClass::Regional,
        TopologyProfile::Standard => LinkClass::LongHaul,
    }
}

fn generate_link(class: LinkClass, rng: &mut StdRng, profile: TopologyProfile) -> SimLink {
    if profile == TopologyProfile::RandomMesh {
        return SimLink {
            latency_ms: 5 + rng.random_range(0..60),
            throughput_mbps: 25.0 + rng.random::<f64>().powf(1.2) * 975.0,
            loss_probability: rng.random::<f64>().powf(2.0) * 0.015,
            up: true,
        };
    }

    match class {
        LinkClass::Backbone => SimLink {
            latency_ms: 15 + rng.random_range(0..90),
            throughput_mbps: 5_000.0 + rng.random::<f64>().powf(0.6) * 35_000.0,
            loss_probability: 0.00005 + rng.random::<f64>().powf(2.0) * 0.001,
            up: true,
        },
        LinkClass::Regional => SimLink {
            latency_ms: 2 + rng.random_range(0..25),
            throughput_mbps: 100.0 + rng.random::<f64>().powf(0.9) * 4_900.0,
            loss_probability: 0.0005 + rng.random::<f64>().powf(1.5) * 0.006,
            up: true,
        },
        LinkClass::LongHaul => SimLink {
            latency_ms: 65 + rng.random_range(0..170),
            throughput_mbps: 10.0 + rng.random::<f64>().powf(1.7) * 390.0,
            loss_probability: 0.004 + rng.random::<f64>().powf(1.2) * 0.035,
            up: true,
        },
    }
}

fn mark_churned_links(edges: &mut [EdgeSpec], fraction: f64, rng: &mut StdRng) {
    let count = fraction_count(edges.len(), fraction);
    let mut indices = (0..edges.len()).collect::<Vec<_>>();
    shuffle(&mut indices, rng);
    for index in indices.into_iter().take(count) {
        edges[index].churned = true;
    }
}

fn build_adjacency(node_count: usize, edges: &[EdgeSpec]) -> HashMap<usize, Vec<usize>> {
    let mut adjacency = HashMap::new();
    for node in 0..node_count {
        adjacency.insert(node, Vec::new());
    }
    for edge in edges {
        adjacency
            .get_mut(&edge.a)
            .expect("node exists")
            .push(edge.b);
        adjacency
            .get_mut(&edge.b)
            .expect("node exists")
            .push(edge.a);
    }
    adjacency
}

fn deterministic_identity(seed: u64, index: usize) -> (Identity, String) {
    let mut rng =
        StdRng::seed_from_u64(seed ^ (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    loop {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        if let Ok(identity) = Identity::from_secret_bytes(&secret) {
            return (identity, hex::encode(secret));
        }
    }
}

async fn recv_exact(endpoint: &FipsEndpoint, expected: &[u8], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        match tokio::time::timeout(remaining, endpoint.recv()).await {
            Ok(Some(message)) if message.data == expected => return true,
            Ok(Some(_)) => continue,
            _ => return false,
        }
    }
}

async fn recv_payload_set(
    endpoint: &FipsEndpoint,
    expected: &mut HashSet<Vec<u8>>,
    timeout: Duration,
) -> usize {
    let deadline = Instant::now() + timeout;
    let mut delivered = 0usize;
    while !expected.is_empty() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match tokio::time::timeout(remaining, endpoint.recv()).await {
            Ok(Some(message)) => {
                if expected.remove(&message.data) {
                    delivered += 1;
                }
            }
            _ => break,
        }
    }
    delivered
}

fn make_stream_payloads(
    label: &str,
    stream: usize,
    src: usize,
    dst: usize,
    stream_size: usize,
    chunk_size: usize,
) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    let mut remaining = stream_size;
    let mut chunk = 0usize;
    while remaining > 0 {
        let size = remaining.min(chunk_size);
        let header = format!("fips-sim|stream|{label}|{stream}|{src}|{dst}|{chunk}|");
        payloads.push(fixed_payload(header.as_bytes(), size));
        remaining -= size;
        chunk += 1;
    }
    payloads
}

fn fixed_payload(prefix: &[u8], size: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size);
    payload.extend_from_slice(prefix);
    payload.truncate(size);
    while payload.len() < size {
        payload.push((payload.len() % 251) as u8);
    }
    payload
}

fn probe_stats(
    attempted: usize,
    failed_send: usize,
    timed_out: usize,
    latencies: Vec<f64>,
) -> ProbeStats {
    let delivered = latencies.len();
    ProbeStats {
        attempted,
        delivered,
        failed_send,
        timed_out,
        success_rate: rate(delivered, attempted),
        avg_latency_ms: mean(&latencies),
        p50_latency_ms: percentile(latencies.clone(), 0.50),
        p95_latency_ms: percentile(latencies, 0.95),
    }
}

fn pick_pair(indices: &[usize], rng: &mut StdRng) -> (usize, usize) {
    let src_pos = rng.random_range(0..indices.len());
    let mut dst_pos = rng.random_range(0..indices.len() - 1);
    if dst_pos >= src_pos {
        dst_pos += 1;
    }
    (indices[src_pos], indices[dst_pos])
}

fn shuffle(values: &mut [usize], rng: &mut StdRng) {
    for i in (1..values.len()).rev() {
        let j = rng.random_range(0..=i);
        values.swap(i, j);
    }
}

fn fraction_count(total: usize, fraction: f64) -> usize {
    ((total as f64 * fraction.clamp(0.0, 1.0)).round() as usize).min(total)
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn percentile(mut values: Vec<f64>, percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let index = ((values.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).round() as usize;
    values[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn production_sim_uses_real_endpoints_over_sim_transport() {
        let report = Simulation::new(SimConfig {
            node_count: 18,
            target_edges: 44,
            route_probe_count: 6,
            stream_probe_count: 2,
            stream_size_bytes: 8 * 1024,
            chunk_size_bytes: 512,
            convergence_wait_ms: 1_500,
            reconvergence_wait_ms: 800,
            delivery_timeout_ms: 3_000,
            stream_timeout_ms: 4_000,
            adversary: AdversaryConfig {
                blackhole_fraction: 0.10,
                flaky_fraction: 0.10,
                flaky_drop_probability: 0.35,
                churned_node_fraction: 0.05,
                churned_link_fraction: 0.10,
            },
            ..SimConfig::default()
        })
        .run()
        .await
        .expect("production simulation should run");

        assert_eq!(report.topology.node_count, 18);
        assert!(report.topology.edge_count >= 17);
        assert!(report.baseline.network.packets_sent > 0);
        assert!(report.baseline.route_probes.delivered > 0);
        assert!(report.impaired.network.packets_sent > 0);
    }
}
