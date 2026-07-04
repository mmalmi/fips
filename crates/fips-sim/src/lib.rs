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

mod progress;
mod topology;
mod traffic;
mod util;
mod wot;

use progress::{ProgressReporter, ProgressSession};
use topology::*;
use traffic::*;
use util::*;
pub use wot::*;

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
    /// Fire-and-forget background endpoint packets per phase.
    pub background_packet_count: usize,
    /// Payload bytes per background packet.
    pub background_payload_bytes: usize,
    /// Virtual spacing between background packet sends.
    pub background_send_interval_ms: u64,
    /// Wall-clock interval for progress reports written to stderr. Zero disables progress.
    pub progress_interval_ms: u64,
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
            stream_size_bytes: 1024 * 1024,
            chunk_size_bytes: 1024,
            background_packet_count: 0,
            background_payload_bytes: 512,
            background_send_interval_ms: 1,
            progress_interval_ms: 0,
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
    pub background: BackgroundTrafficStats,
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
    pub setup_delivered: usize,
    pub setup_failed_send: usize,
    pub setup_timed_out: usize,
    pub stream_size_bytes: usize,
    pub chunk_size_bytes: usize,
    pub chunks_attempted: usize,
    pub chunks_sent: usize,
    pub chunks_send_failed: usize,
    pub chunks_delivered: usize,
    pub chunks_lost: usize,
    pub chunk_delivery_rate: f64,
    pub chunk_loss_rate: f64,
    pub bytes_attempted: usize,
    pub bytes_delivered: usize,
    pub avg_delivered_mbps: f64,
    pub p95_delivered_mbps: f64,
}

/// Fire-and-forget background packet traffic.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BackgroundTrafficStats {
    pub attempted: usize,
    pub sent: usize,
    pub failed_send: usize,
    pub payload_bytes: usize,
    pub send_interval_ms: u64,
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
        let progress_session = ProgressSession::start(&self.config, self.edges.len());
        let progress = progress_session.reporter();

        progress.stage("registering-links");
        let network = SimNetwork::new(self.config.seed ^ 0x51_4d_4e_45_54);
        for edge in &self.edges {
            network.set_link(
                self.nodes[edge.a].sim_addr.clone(),
                self.nodes[edge.b].sim_addr.clone(),
                edge.link,
            );
        }
        register_sim_network(self.network_id.clone(), network.clone());

        let mut endpoints = match self.start_endpoints(&progress).await {
            Ok(endpoints) => endpoints,
            Err(error) => {
                unregister_sim_network(&self.network_id);
                return Err(error);
            }
        };

        progress.stage("converging");
        tokio::time::sleep(Duration::from_millis(self.config.convergence_wait_ms)).await;
        let baseline = self
            .run_phase("baseline", &endpoints, &network, 0, &progress)
            .await;

        progress.stage("applying-impairments");
        self.apply_impairments(&network);
        progress.stage("reconverging");
        tokio::time::sleep(Duration::from_millis(self.config.reconvergence_wait_ms)).await;
        let impaired = self
            .run_phase("impaired", &endpoints, &network, 1, &progress)
            .await;

        progress.stage("shutting-down");
        let mut shutdown_error = None;
        while let Some(endpoint) = endpoints.pop() {
            if let Err(error) = endpoint.shutdown().await {
                shutdown_error = Some(error);
            }
        }
        unregister_sim_network(&self.network_id);
        progress.stage("done");
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

    async fn start_endpoints(
        &self,
        progress: &ProgressReporter,
    ) -> Result<Vec<FipsEndpoint>, SimError> {
        progress.start_endpoints(self.nodes.len());
        let mut endpoints = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            match FipsEndpoint::builder()
                .config(self.node_config(node))
                .without_system_tun()
                .packet_channel_capacity(8192)
                .bind()
                .await
            {
                Ok(endpoint) => {
                    endpoints.push(endpoint);
                    progress.endpoint_started(endpoints.len());
                }
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
        progress: &ProgressReporter,
    ) -> PhaseReport {
        progress.start_phase(label, &self.config);
        let before = network.stats();
        let start = Instant::now();
        let measured = async {
            let route_probes = self
                .run_route_probes(label, endpoints, phase_index, progress)
                .await;
            let streams = self
                .run_streams(label, endpoints, phase_index, progress)
                .await;
            (route_probes, streams)
        };
        let background = self.run_background_traffic(label, endpoints, phase_index, progress);
        let ((route_probes, streams), background) = tokio::join!(measured, background);
        let network_delta = network.stats().delta_since(&before);

        PhaseReport {
            label,
            route_probes,
            streams,
            background,
            network: network_delta,
            elapsed_ms: start.elapsed().as_millis() as u64,
        }
    }

    async fn run_route_probes(
        &self,
        label: &'static str,
        endpoints: &[FipsEndpoint],
        phase_index: u64,
        progress: &ProgressReporter,
    ) -> ProbeStats {
        progress.stage("route-probes");
        let eligible = self.eligible_endpoint_indices();
        if eligible.len() < 2 || self.config.route_probe_count == 0 {
            return ProbeStats::default();
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed ^ 0x70_52_4f_42_45 ^ phase_index);
        let mut latencies = Vec::new();
        let mut failed_send = 0usize;
        let mut timed_out = 0usize;

        for probe in 0..self.config.route_probe_count {
            progress.route_attempted();
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
                        progress.route_timed_out();
                        continue;
                    }

                    if endpoints[dst]
                        .send(self.nodes[src].npub.clone(), reply.clone())
                        .await
                        .is_err()
                    {
                        failed_send += 1;
                        progress.route_failed_send();
                        continue;
                    }

                    if recv_exact(&endpoints[src], &reply, timeout).await {
                        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
                        progress.route_delivered();
                    } else {
                        timed_out += 1;
                        progress.route_timed_out();
                    }
                }
                Err(_) => {
                    failed_send += 1;
                    progress.route_failed_send();
                }
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
        progress: &ProgressReporter,
    ) -> StreamStats {
        progress.stage("streams");
        let eligible = self.eligible_endpoint_indices();
        if eligible.len() < 2 || self.config.stream_probe_count == 0 {
            return StreamStats {
                stream_size_bytes: self.config.stream_size_bytes,
                chunk_size_bytes: self.config.chunk_size_bytes,
                ..StreamStats::default()
            };
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed ^ 0x53_54_52_45_41_4d ^ phase_index);
        let mut delivered_mbps = Vec::new();
        let mut setup_delivered = 0usize;
        let mut setup_failed_send = 0usize;
        let mut setup_timed_out = 0usize;
        let mut chunks_attempted = 0usize;
        let mut chunks_sent = 0usize;
        let mut chunks_send_failed = 0usize;
        let mut chunks_delivered = 0usize;
        let mut bytes_attempted = 0usize;
        let mut bytes_delivered = 0usize;

        for stream in 0..self.config.stream_probe_count {
            progress.stream_started();
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

            if endpoints[src]
                .send(self.nodes[dst].npub.clone(), warmup.clone())
                .await
                .is_err()
            {
                setup_failed_send += 1;
                progress.stream_setup_failed_send();
                continue;
            }
            let warmup_timeout = Duration::from_millis(self.config.delivery_timeout_ms);
            if !recv_exact(&endpoints[dst], &warmup, warmup_timeout).await {
                setup_timed_out += 1;
                progress.stream_setup_timed_out();
                continue;
            }
            setup_delivered += 1;
            progress.stream_setup_delivered();

            let start = Instant::now();
            chunks_attempted += chunks.len();
            progress.chunks_attempted(chunks.len());
            bytes_attempted += chunks.iter().map(Vec::len).sum::<usize>();
            let mut expected = HashSet::new();
            for chunk in &chunks {
                match endpoints[dst]
                    .send(self.nodes[src].npub.clone(), chunk.clone())
                    .await
                {
                    Ok(()) => {
                        chunks_sent += 1;
                        progress.chunk_sent();
                        expected.insert(chunk.clone());
                    }
                    Err(_) => {
                        chunks_send_failed += 1;
                        progress.chunk_send_failed();
                    }
                }
            }

            let timeout = Duration::from_millis(self.config.stream_timeout_ms);
            let (delivered, delivered_bytes) =
                recv_payload_set(&endpoints[src], &mut expected, timeout).await;
            chunks_delivered += delivered;
            progress.chunks_delivered(delivered);
            bytes_delivered += delivered_bytes;

            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            if elapsed_ms > 0.0 {
                delivered_mbps.push((delivered_bytes as f64 * 8.0) / elapsed_ms / 1000.0);
            }
        }

        let chunks_lost = chunks_attempted.saturating_sub(chunks_delivered);
        StreamStats {
            streams: self.config.stream_probe_count,
            setup_delivered,
            setup_failed_send,
            setup_timed_out,
            stream_size_bytes: self.config.stream_size_bytes,
            chunk_size_bytes: self.config.chunk_size_bytes,
            chunks_attempted,
            chunks_sent,
            chunks_send_failed,
            chunks_delivered,
            chunks_lost,
            chunk_delivery_rate: rate(chunks_delivered, chunks_attempted),
            chunk_loss_rate: rate(chunks_lost, chunks_attempted),
            bytes_attempted,
            bytes_delivered,
            avg_delivered_mbps: mean(&delivered_mbps),
            p95_delivered_mbps: percentile(delivered_mbps, 0.95),
        }
    }

    async fn run_background_traffic(
        &self,
        label: &'static str,
        endpoints: &[FipsEndpoint],
        phase_index: u64,
        progress: &ProgressReporter,
    ) -> BackgroundTrafficStats {
        let eligible = self.eligible_endpoint_indices();
        if eligible.len() < 2 || self.config.background_packet_count == 0 {
            return BackgroundTrafficStats {
                attempted: self.config.background_packet_count,
                payload_bytes: self.config.background_payload_bytes,
                send_interval_ms: self.config.background_send_interval_ms,
                ..BackgroundTrafficStats::default()
            };
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed ^ 0x42_47_54_52_41_46 ^ phase_index);
        let mut sent = 0usize;
        let mut failed_send = 0usize;

        for packet in 0..self.config.background_packet_count {
            progress.background_attempted();
            let (src, dst) = pick_pair(&eligible, &mut rng);
            let payload = fixed_payload(
                format!("fips-sim|background|{label}|{packet}|{src}|{dst}|").as_bytes(),
                self.config.background_payload_bytes,
            );

            match endpoints[src]
                .send(self.nodes[dst].npub.clone(), payload)
                .await
            {
                Ok(()) => {
                    sent += 1;
                    progress.background_sent();
                }
                Err(_) => {
                    failed_send += 1;
                    progress.background_failed_send();
                }
            }

            if self.config.background_send_interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(
                    self.config.background_send_interval_ms,
                ))
                .await;
            } else if packet % 128 == 0 {
                tokio::task::yield_now().await;
            }
        }

        BackgroundTrafficStats {
            attempted: self.config.background_packet_count,
            sent,
            failed_send,
            payload_bytes: self.config.background_payload_bytes,
            send_interval_ms: self.config.background_send_interval_ms,
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
