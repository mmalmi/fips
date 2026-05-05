//! Fast simulation tools for FIPS tree and routing strategy evaluation.
//!
//! The simulator is intentionally smaller than the Docker chaos harness. It
//! models the FIPS spanning-tree coordinate rule and greedy forwarding rule
//! directly so strategy sweeps can compare behavior under honest,
//! malicious, and misbehaving peers without live transports.

use fips_core::NodeAddr;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Parent/routing strategy under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    /// Current FIPS v1 behavior: smallest visible root, transitive ancestry
    /// trust, then effective-depth parent selection.
    CurrentFips,
    /// Proposed hardening model: accept the same FIPS coordinate shape, but
    /// require every ancestry hop to be a real node linked by a real edge.
    /// This approximates a future link-attested ancestry chain.
    VerifiedAncestry,
    /// Private-mesh / allowlisted-root model: only follow the configured root.
    /// The simulator pins this to the smallest honest endpoint in the run.
    PinnedRoot,
    /// Discovery/data flood model: first contact floods to all peers, then
    /// caches next hops only after a reply/proof returns on the reverse path.
    /// This is closer to Reticulum's discover/cache/revalidate pattern than
    /// to FIPS tree-coordinate routing.
    ReplyLearnedFlood,
}

impl RoutingStrategy {
    fn label(self) -> &'static str {
        match self {
            RoutingStrategy::CurrentFips => "current_fips",
            RoutingStrategy::VerifiedAncestry => "verified_ancestry",
            RoutingStrategy::PinnedRoot => "pinned_root",
            RoutingStrategy::ReplyLearnedFlood => "reply_learned_flood",
        }
    }
}

/// Adversarial and misbehavior mix for a simulation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AdversaryConfig {
    /// Fraction of nodes with honestly advertised but ground-low node_addr.
    ///
    /// This models identity grinding against "smallest node_addr wins".
    pub root_grinder_fraction: f64,
    /// Fraction of nodes that advertise a phantom all-zero root in their
    /// ancestry. Current FIPS v1 accepts this from an authenticated direct
    /// peer because non-direct ancestry is transitively trusted.
    pub phantom_root_fraction: f64,
    /// Fraction of nodes that drop all transit traffic.
    pub blackhole_fraction: f64,
    /// Fraction of nodes that probabilistically drop transit traffic.
    pub flaky_fraction: f64,
    /// Drop probability for flaky nodes.
    pub flaky_drop_probability: f64,
}

impl Default for AdversaryConfig {
    fn default() -> Self {
        Self {
            root_grinder_fraction: 0.0,
            phantom_root_fraction: 0.0,
            blackhole_fraction: 0.0,
            flaky_fraction: 0.0,
            flaky_drop_probability: 0.25,
        }
    }
}

/// Simulation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimConfig {
    /// Number of simulated nodes.
    pub node_count: usize,
    /// Number of undirected topology edges. A random spanning tree is created
    /// first, then extra edges are added up to this target.
    pub target_edges: usize,
    /// Number of honest-endpoint route probes per strategy.
    pub route_probe_count: usize,
    /// Random seed for reproducible topology, roles, and probes.
    pub seed: u64,
    /// Maximum synchronous convergence rounds.
    pub max_convergence_rounds: usize,
    /// Random extra cost added to each link in `[0, link_cost_jitter]`.
    pub link_cost_jitter: f64,
    /// Attack and misbehavior mix.
    pub adversary: AdversaryConfig,
    /// Strategies to compare. Empty means all built-in strategies.
    pub strategies: Vec<RoutingStrategy>,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            node_count: 80,
            target_edges: 180,
            route_probe_count: 500,
            seed: 42,
            max_convergence_rounds: 64,
            link_cost_jitter: 0.25,
            adversary: AdversaryConfig::default(),
            strategies: vec![
                RoutingStrategy::CurrentFips,
                RoutingStrategy::VerifiedAncestry,
                RoutingStrategy::PinnedRoot,
                RoutingStrategy::ReplyLearnedFlood,
            ],
        }
    }
}

/// Whole comparison output for one shared topology.
#[derive(Debug, Clone, Serialize)]
pub struct ComparisonReport {
    pub config: SimConfig,
    pub topology: TopologyStats,
    pub pinned_root: String,
    pub behavior_counts: BTreeMap<String, usize>,
    pub strategies: Vec<StrategyReport>,
}

/// Per-strategy output.
#[derive(Debug, Clone, Serialize)]
pub struct StrategyReport {
    pub strategy: RoutingStrategy,
    pub strategy_label: &'static str,
    pub convergence_rounds: usize,
    pub converged: bool,
    pub tree: TreeStats,
    pub routing: RoutingStats,
}

/// Static topology statistics.
#[derive(Debug, Clone, Serialize)]
pub struct TopologyStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub avg_degree: f64,
    pub min_degree: usize,
    pub max_degree: usize,
}

/// Tree-state statistics after convergence.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TreeStats {
    pub honest_endpoint_count: usize,
    pub honest_on_fake_root: usize,
    pub honest_on_malicious_root: usize,
    pub honest_with_malicious_parent: usize,
    pub root_capture_rate: f64,
    pub malicious_parent_rate: f64,
    pub avg_honest_depth: f64,
    pub max_honest_depth: usize,
    pub distinct_roots: usize,
}

/// Route-probe statistics.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RoutingStats {
    pub probes: usize,
    pub delivered: usize,
    pub delivered_without_reply: usize,
    pub no_route: usize,
    pub loops: usize,
    pub ttl_expired: usize,
    pub dropped_by_blackhole: usize,
    pub dropped_by_flaky: usize,
    pub reply_failures: usize,
    pub success_rate: f64,
    pub p50_hops: usize,
    pub p95_hops: usize,
    pub max_hops: usize,
    pub avg_hops: f64,
    pub routes_with_malicious_transit: usize,
    pub discovery_floods: usize,
    pub learned_route_attempts: usize,
    pub transmissions: usize,
    pub avg_transmissions_per_probe: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityBehavior {
    Honest,
    RootGrinder,
    PhantomRoot,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ForwardBehavior {
    Honest,
    Blackhole,
    Flaky { drop_probability: f64 },
}

#[derive(Debug, Clone)]
struct NodeSpec {
    addr: NodeAddr,
    identity: IdentityBehavior,
    forward: ForwardBehavior,
    neighbors: Vec<(usize, f64)>,
}

impl NodeSpec {
    fn is_honest_endpoint(&self) -> bool {
        self.identity == IdentityBehavior::Honest && self.forward == ForwardBehavior::Honest
    }

    fn is_malicious_or_misbehaving(&self) -> bool {
        self.identity != IdentityBehavior::Honest || self.forward != ForwardBehavior::Honest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeState {
    parent: Option<usize>,
    root: NodeAddr,
    coord: Vec<NodeAddr>,
}

#[derive(Debug, Clone)]
struct Advertisement {
    from: usize,
    parent_addr: NodeAddr,
    root: NodeAddr,
    coord: Vec<NodeAddr>,
}

#[derive(Debug, Clone)]
struct StrategyRun {
    states: Vec<NodeState>,
    views: Vec<HashMap<usize, Vec<NodeAddr>>>,
    convergence_rounds: usize,
    converged: bool,
}

/// In-process FIPS strategy simulator.
#[derive(Debug, Clone)]
pub struct Simulation {
    config: SimConfig,
    nodes: Vec<NodeSpec>,
    edges: Vec<(usize, usize)>,
    addr_to_index: HashMap<NodeAddr, usize>,
    pinned_root: NodeAddr,
}

impl Simulation {
    /// Build a deterministic topology and behavior assignment.
    pub fn new(config: SimConfig) -> Self {
        assert!(config.node_count > 0, "node_count must be > 0");
        let mut rng = StdRng::seed_from_u64(config.seed);

        let identity_behaviors = assign_identity_behaviors(config.node_count, config.adversary);
        let forward_behaviors = assign_forward_behaviors(config.node_count, config.adversary);

        let mut nodes = Vec::with_capacity(config.node_count);
        for index in 0..config.node_count {
            let addr = match identity_behaviors[index] {
                IdentityBehavior::RootGrinder => addr_from_rank((index + 1) as u128),
                IdentityBehavior::Honest | IdentityBehavior::PhantomRoot => {
                    addr_from_rank(1_000_000 + index as u128)
                }
            };
            nodes.push(NodeSpec {
                addr,
                identity: identity_behaviors[index],
                forward: forward_behaviors[index],
                neighbors: Vec::new(),
            });
        }

        let edges = generate_connected_edges(config.node_count, config.target_edges, &mut rng);
        for &(a, b) in &edges {
            let cost = 1.0 + rng.random::<f64>() * config.link_cost_jitter.max(0.0);
            nodes[a].neighbors.push((b, cost));
            nodes[b].neighbors.push((a, cost));
        }

        let addr_to_index = nodes
            .iter()
            .enumerate()
            .map(|(idx, node)| (node.addr, idx))
            .collect::<HashMap<_, _>>();

        let pinned_root = nodes
            .iter()
            .filter(|node| node.is_honest_endpoint())
            .map(|node| node.addr)
            .min()
            .or_else(|| nodes.iter().map(|node| node.addr).min())
            .expect("non-empty node set");

        Self {
            config,
            nodes,
            edges,
            addr_to_index,
            pinned_root,
        }
    }

    /// Run all configured strategies against the same generated scenario.
    pub fn run(&self) -> ComparisonReport {
        let strategies = if self.config.strategies.is_empty() {
            vec![
                RoutingStrategy::CurrentFips,
                RoutingStrategy::VerifiedAncestry,
                RoutingStrategy::PinnedRoot,
                RoutingStrategy::ReplyLearnedFlood,
            ]
        } else {
            self.config.strategies.clone()
        };

        let reports = strategies
            .into_iter()
            .map(|strategy| self.run_strategy(strategy))
            .collect();

        ComparisonReport {
            config: self.config.clone(),
            topology: self.topology_stats(),
            pinned_root: self.pinned_root.to_string(),
            behavior_counts: self.behavior_counts(),
            strategies: reports,
        }
    }

    /// Run one strategy against the generated scenario.
    pub fn run_strategy(&self, strategy: RoutingStrategy) -> StrategyReport {
        let run = self.converge(strategy);
        let tree = self.tree_stats(&run.states);
        let routing = self.routing_stats(&run.states, &run.views, strategy);

        StrategyReport {
            strategy,
            strategy_label: strategy.label(),
            convergence_rounds: run.convergence_rounds,
            converged: run.converged,
            tree,
            routing,
        }
    }

    /// JSON value for callers that want hashtree-sim style reporting.
    pub fn report_json(&self) -> serde_json::Value {
        serde_json::to_value(self.run()).expect("comparison report serializes")
    }

    fn topology_stats(&self) -> TopologyStats {
        let degrees = self
            .nodes
            .iter()
            .map(|node| node.neighbors.len())
            .collect::<Vec<_>>();
        let node_count = self.nodes.len();
        let edge_count = self.edges.len();
        let avg_degree = if node_count == 0 {
            0.0
        } else {
            (edge_count * 2) as f64 / node_count as f64
        };
        TopologyStats {
            node_count,
            edge_count,
            avg_degree,
            min_degree: degrees.iter().copied().min().unwrap_or(0),
            max_degree: degrees.iter().copied().max().unwrap_or(0),
        }
    }

    fn behavior_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for node in &self.nodes {
            let identity = match node.identity {
                IdentityBehavior::Honest => "identity_honest",
                IdentityBehavior::RootGrinder => "identity_root_grinder",
                IdentityBehavior::PhantomRoot => "identity_phantom_root",
            };
            let forward = match node.forward {
                ForwardBehavior::Honest => "forward_honest",
                ForwardBehavior::Blackhole => "forward_blackhole",
                ForwardBehavior::Flaky { .. } => "forward_flaky",
            };
            *counts.entry(identity.to_string()).or_insert(0) += 1;
            *counts.entry(forward.to_string()).or_insert(0) += 1;
        }
        counts
    }

    fn initial_states(&self) -> Vec<NodeState> {
        self.nodes
            .iter()
            .map(|node| NodeState {
                parent: None,
                root: node.addr,
                coord: vec![node.addr],
            })
            .collect()
    }

    fn converge(&self, strategy: RoutingStrategy) -> StrategyRun {
        if strategy == RoutingStrategy::ReplyLearnedFlood {
            return StrategyRun {
                states: self.initial_states(),
                views: vec![HashMap::new(); self.nodes.len()],
                convergence_rounds: 0,
                converged: true,
            };
        }

        let mut states = self.initial_states();
        let mut views = vec![HashMap::new(); self.nodes.len()];
        let mut converged = false;
        let mut convergence_rounds = 0;

        for round in 0..self.config.max_convergence_rounds {
            let adverts = self.advertisements(&states);
            let mut next_states = states.clone();
            let mut next_views = vec![HashMap::new(); self.nodes.len()];

            for index in 0..self.nodes.len() {
                let decision = self.choose_parent(strategy, index, &adverts);
                next_views[index] = decision.accepted_coords;
                match decision.parent {
                    Some((parent, parent_coord)) => {
                        let mut coord = Vec::with_capacity(parent_coord.len() + 1);
                        coord.push(self.nodes[index].addr);
                        coord.extend(parent_coord);
                        let root = *coord.last().expect("coord is non-empty");
                        next_states[index] = NodeState {
                            parent: Some(parent),
                            root,
                            coord,
                        };
                    }
                    None => {
                        next_states[index] = NodeState {
                            parent: None,
                            root: self.nodes[index].addr,
                            coord: vec![self.nodes[index].addr],
                        };
                    }
                }
            }

            convergence_rounds = round + 1;
            if next_states == states {
                converged = true;
                views = next_views;
                break;
            }
            states = next_states;
            views = next_views;
        }

        if !converged {
            let adverts = self.advertisements(&states);
            views = (0..self.nodes.len())
                .map(|index| {
                    self.choose_parent(strategy, index, &adverts)
                        .accepted_coords
                })
                .collect();
        }

        StrategyRun {
            states,
            views,
            convergence_rounds,
            converged,
        }
    }

    fn advertisements(&self, states: &[NodeState]) -> Vec<Advertisement> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| match node.identity {
                IdentityBehavior::PhantomRoot => Advertisement {
                    from: index,
                    parent_addr: fake_root(),
                    root: fake_root(),
                    coord: vec![node.addr, fake_root()],
                },
                IdentityBehavior::Honest | IdentityBehavior::RootGrinder => {
                    let state = &states[index];
                    Advertisement {
                        from: index,
                        parent_addr: state
                            .parent
                            .map(|parent| self.nodes[parent].addr)
                            .unwrap_or(node.addr),
                        root: state.root,
                        coord: state.coord.clone(),
                    }
                }
            })
            .collect()
    }

    fn choose_parent(
        &self,
        strategy: RoutingStrategy,
        local: usize,
        adverts: &[Advertisement],
    ) -> ParentDecision {
        let mut accepted = HashMap::new();
        let local_addr = self.nodes[local].addr;

        for &(peer, _) in &self.nodes[local].neighbors {
            let advert = &adverts[peer];
            if self.accept_advert(strategy, local, advert) {
                accepted.insert(peer, advert.coord.clone());
            }
        }

        let target_root = match strategy {
            RoutingStrategy::PinnedRoot => {
                if local_addr == self.pinned_root {
                    return ParentDecision {
                        parent: None,
                        accepted_coords: accepted,
                    };
                }
                self.pinned_root
            }
            RoutingStrategy::CurrentFips
            | RoutingStrategy::VerifiedAncestry
            | RoutingStrategy::ReplyLearnedFlood => {
                let smallest_peer_root = accepted.values().filter_map(|coord| coord.last()).min();
                let smallest_visible = smallest_peer_root
                    .copied()
                    .map(|root| root.min(local_addr))
                    .unwrap_or(local_addr);
                if local_addr <= smallest_visible {
                    return ParentDecision {
                        parent: None,
                        accepted_coords: accepted,
                    };
                }
                smallest_visible
            }
        };

        let mut best: Option<(usize, Vec<NodeAddr>, f64, NodeAddr)> = None;
        for &(peer, cost) in &self.nodes[local].neighbors {
            let Some(coord) = accepted.get(&peer) else {
                continue;
            };
            if coord.last().copied() != Some(target_root) {
                continue;
            }
            if coord.contains(&local_addr) {
                continue;
            }

            let effective_depth = coord.len().saturating_sub(1) as f64 + cost;
            let peer_addr = self.nodes[peer].addr;
            let better = match &best {
                None => true,
                Some((_, _, best_depth, best_addr)) => {
                    effective_depth < *best_depth
                        || (effective_depth == *best_depth && peer_addr < *best_addr)
                }
            };
            if better {
                best = Some((peer, coord.clone(), effective_depth, peer_addr));
            }
        }

        ParentDecision {
            parent: best.map(|(peer, coord, _, _)| (peer, coord)),
            accepted_coords: accepted,
        }
    }

    fn accept_advert(
        &self,
        strategy: RoutingStrategy,
        _local: usize,
        advert: &Advertisement,
    ) -> bool {
        if !self.structurally_valid_advert(advert) {
            return false;
        }

        match strategy {
            RoutingStrategy::CurrentFips => true,
            RoutingStrategy::PinnedRoot => advert.root == self.pinned_root,
            RoutingStrategy::VerifiedAncestry => self.link_attested_ancestry(advert),
            RoutingStrategy::ReplyLearnedFlood => true,
        }
    }

    fn structurally_valid_advert(&self, advert: &Advertisement) -> bool {
        if advert.coord.is_empty() {
            return false;
        }
        if advert.coord[0] != self.nodes[advert.from].addr {
            return false;
        }
        if advert.coord.last().copied() != Some(advert.root) {
            return false;
        }
        let Some(minimum) = advert.coord.iter().min() else {
            return false;
        };
        if *minimum != advert.root {
            return false;
        }
        if advert.coord.len() == 1 {
            advert.parent_addr == self.nodes[advert.from].addr
        } else {
            advert.coord.get(1).copied() == Some(advert.parent_addr)
        }
    }

    fn link_attested_ancestry(&self, advert: &Advertisement) -> bool {
        let mut seen = HashSet::new();
        let mut indices = Vec::with_capacity(advert.coord.len());
        for addr in &advert.coord {
            if !seen.insert(*addr) {
                return false;
            }
            let Some(index) = self.addr_to_index.get(addr).copied() else {
                return false;
            };
            indices.push(index);
        }

        for pair in indices.windows(2) {
            if !self.has_edge(pair[0], pair[1]) {
                return false;
            }
        }
        true
    }

    fn has_edge(&self, a: usize, b: usize) -> bool {
        self.nodes[a]
            .neighbors
            .iter()
            .any(|(neighbor, _)| *neighbor == b)
    }

    fn tree_stats(&self, states: &[NodeState]) -> TreeStats {
        let mut stats = TreeStats::default();
        let mut total_depth = 0usize;
        let mut roots = HashSet::new();

        for (index, node) in self.nodes.iter().enumerate() {
            roots.insert(states[index].root);
            if !node.is_honest_endpoint() {
                continue;
            }

            stats.honest_endpoint_count += 1;
            total_depth += states[index].coord.len().saturating_sub(1);
            stats.max_honest_depth = stats
                .max_honest_depth
                .max(states[index].coord.len().saturating_sub(1));

            match self.addr_to_index.get(&states[index].root).copied() {
                None => stats.honest_on_fake_root += 1,
                Some(root_idx) => {
                    if self.nodes[root_idx].is_malicious_or_misbehaving() {
                        stats.honest_on_malicious_root += 1;
                    }
                }
            }

            if let Some(parent) = states[index].parent
                && self.nodes[parent].is_malicious_or_misbehaving()
            {
                stats.honest_with_malicious_parent += 1;
            }
        }

        if stats.honest_endpoint_count > 0 {
            stats.root_capture_rate = (stats.honest_on_fake_root + stats.honest_on_malicious_root)
                as f64
                / stats.honest_endpoint_count as f64;
            stats.malicious_parent_rate =
                stats.honest_with_malicious_parent as f64 / stats.honest_endpoint_count as f64;
            stats.avg_honest_depth = total_depth as f64 / stats.honest_endpoint_count as f64;
        }
        stats.distinct_roots = roots.len();
        stats
    }

    fn routing_stats(
        &self,
        states: &[NodeState],
        views: &[HashMap<usize, Vec<NodeAddr>>],
        strategy: RoutingStrategy,
    ) -> RoutingStats {
        if strategy == RoutingStrategy::ReplyLearnedFlood {
            return self.reply_learned_routing_stats(strategy);
        }

        let endpoints = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.is_honest_endpoint())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        let mut stats = RoutingStats::default();
        if endpoints.len() < 2 || self.config.route_probe_count == 0 {
            return stats;
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed ^ strategy_seed(strategy));
        let mut delivered_hops = Vec::new();

        for _ in 0..self.config.route_probe_count {
            let src_pos = rng.random_range(0..endpoints.len());
            let mut dst_pos = rng.random_range(0..endpoints.len() - 1);
            if dst_pos >= src_pos {
                dst_pos += 1;
            }
            let src = endpoints[src_pos];
            let dst = endpoints[dst_pos];

            stats.probes += 1;
            let probe = self.simulate_route(states, views, src, dst, &mut rng);
            stats.transmissions += probe.transmissions;
            match probe.result {
                RouteResult::Delivered {
                    hops,
                    malicious_transit,
                } => {
                    stats.delivered += 1;
                    delivered_hops.push(hops);
                    if malicious_transit {
                        stats.routes_with_malicious_transit += 1;
                    }
                }
                RouteResult::UnconfirmedDelivery {
                    hops,
                    malicious_transit,
                } => {
                    stats.delivered_without_reply += 1;
                    delivered_hops.push(hops);
                    if malicious_transit {
                        stats.routes_with_malicious_transit += 1;
                    }
                }
                RouteResult::NoRoute => stats.no_route += 1,
                RouteResult::Loop => stats.loops += 1,
                RouteResult::TtlExpired => stats.ttl_expired += 1,
                RouteResult::Blackholed => stats.dropped_by_blackhole += 1,
                RouteResult::FlakyDrop => stats.dropped_by_flaky += 1,
            }
        }

        if stats.probes > 0 {
            stats.success_rate = stats.delivered as f64 / stats.probes as f64;
            stats.avg_transmissions_per_probe = stats.transmissions as f64 / stats.probes as f64;
        }
        if !delivered_hops.is_empty() {
            delivered_hops.sort_unstable();
            stats.p50_hops = percentile_usize(&delivered_hops, 0.50);
            stats.p95_hops = percentile_usize(&delivered_hops, 0.95);
            stats.max_hops = delivered_hops.last().copied().unwrap_or(0);
            stats.avg_hops =
                delivered_hops.iter().sum::<usize>() as f64 / delivered_hops.len() as f64;
        }
        stats
    }

    fn reply_learned_routing_stats(&self, strategy: RoutingStrategy) -> RoutingStats {
        let endpoints = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.is_honest_endpoint())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        let mut stats = RoutingStats::default();
        if endpoints.len() < 2 || self.config.route_probe_count == 0 {
            return stats;
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed ^ strategy_seed(strategy));
        let mut learned_routes = LearnedRouteTable::new();
        let mut delivered_hops = Vec::new();

        for _ in 0..self.config.route_probe_count {
            let src_pos = rng.random_range(0..endpoints.len());
            let mut dst_pos = rng.random_range(0..endpoints.len() - 1);
            if dst_pos >= src_pos {
                dst_pos += 1;
            }
            let src = endpoints[src_pos];
            let dst = endpoints[dst_pos];

            stats.probes += 1;
            let probe = self.simulate_reply_learned_probe(&mut learned_routes, src, dst, &mut rng);

            stats.transmissions += probe.transmissions;
            if probe.discovery_flood {
                stats.discovery_floods += 1;
            }
            if probe.learned_route_attempt {
                stats.learned_route_attempts += 1;
            }
            if probe.reply_failure {
                stats.reply_failures += 1;
            }

            match probe.result {
                RouteResult::Delivered {
                    hops,
                    malicious_transit,
                } => {
                    stats.delivered += 1;
                    delivered_hops.push(hops);
                    if malicious_transit {
                        stats.routes_with_malicious_transit += 1;
                    }
                }
                RouteResult::UnconfirmedDelivery {
                    hops,
                    malicious_transit,
                } => {
                    stats.delivered_without_reply += 1;
                    delivered_hops.push(hops);
                    if malicious_transit {
                        stats.routes_with_malicious_transit += 1;
                    }
                }
                RouteResult::NoRoute => stats.no_route += 1,
                RouteResult::Loop => stats.loops += 1,
                RouteResult::TtlExpired => stats.ttl_expired += 1,
                RouteResult::Blackholed => stats.dropped_by_blackhole += 1,
                RouteResult::FlakyDrop => stats.dropped_by_flaky += 1,
            }
        }

        if stats.probes > 0 {
            stats.success_rate = stats.delivered as f64 / stats.probes as f64;
            stats.avg_transmissions_per_probe = stats.transmissions as f64 / stats.probes as f64;
        }
        if !delivered_hops.is_empty() {
            delivered_hops.sort_unstable();
            stats.p50_hops = percentile_usize(&delivered_hops, 0.50);
            stats.p95_hops = percentile_usize(&delivered_hops, 0.95);
            stats.max_hops = delivered_hops.last().copied().unwrap_or(0);
            stats.avg_hops =
                delivered_hops.iter().sum::<usize>() as f64 / delivered_hops.len() as f64;
        }
        stats
    }

    fn simulate_reply_learned_probe(
        &self,
        learned_routes: &mut LearnedRouteTable,
        src: usize,
        dst: usize,
        rng: &mut StdRng,
    ) -> ReplyLearnedProbe {
        let mut probe = ReplyLearnedProbe::default();

        if learned_routes.contains_key(&(src, dst)) {
            probe.learned_route_attempt = true;
            let attempt = self.follow_learned_route(learned_routes, src, dst, rng);
            probe.transmissions += attempt.transmissions;

            match attempt.result {
                PathResult::Delivered(path) => {
                    let reply = self.confirm_reply(&path.nodes, rng);
                    probe.transmissions += reply.transmissions;
                    if reply.confirmed {
                        learn_path(learned_routes, &path.nodes);
                        probe.result = RouteResult::Delivered {
                            hops: path.hops(),
                            malicious_transit: path.malicious_transit,
                        };
                        return probe;
                    }

                    probe.reply_failure = true;
                    invalidate_path(learned_routes, &path.nodes, dst);
                    let result = RouteResult::UnconfirmedDelivery {
                        hops: path.hops(),
                        malicious_transit: path.malicious_transit,
                    };
                    if reply.dropped_by_blackhole || reply.dropped_by_flaky {
                        probe.result = self
                            .flood_after_failed_learned_route(
                                learned_routes,
                                src,
                                dst,
                                rng,
                                &mut probe,
                            )
                            .unwrap_or(result);
                    } else {
                        probe.result = result;
                    }
                    return probe;
                }
                PathResult::NoRoute | PathResult::Loop | PathResult::TtlExpired => {
                    learned_routes.remove(&(src, dst));
                }
                PathResult::Blackholed | PathResult::FlakyDrop => {
                    learned_routes.remove(&(src, dst));
                }
            }
        }

        probe.result = self
            .flood_after_failed_learned_route(learned_routes, src, dst, rng, &mut probe)
            .unwrap_or(RouteResult::NoRoute);
        probe
    }

    fn flood_after_failed_learned_route(
        &self,
        learned_routes: &mut LearnedRouteTable,
        src: usize,
        dst: usize,
        rng: &mut StdRng,
        probe: &mut ReplyLearnedProbe,
    ) -> Option<RouteResult> {
        probe.discovery_flood = true;
        let flood = self.flood_discover_confirmed_path(src, dst, rng);
        probe.transmissions += flood.transmissions;
        if flood.reply_failures > 0 {
            probe.reply_failure = true;
        }

        if let Some(path) = flood.confirmed_path {
            learn_path(learned_routes, &path.nodes);
            return Some(RouteResult::Delivered {
                hops: path.hops(),
                malicious_transit: path.malicious_transit,
            });
        }

        if let Some(path) = flood.unconfirmed_path {
            return Some(RouteResult::UnconfirmedDelivery {
                hops: path.hops(),
                malicious_transit: path.malicious_transit,
            });
        }

        if flood.dropped_by_blackhole {
            Some(RouteResult::Blackholed)
        } else if flood.dropped_by_flaky {
            Some(RouteResult::FlakyDrop)
        } else {
            None
        }
    }

    fn follow_learned_route(
        &self,
        learned_routes: &LearnedRouteTable,
        src: usize,
        dst: usize,
        rng: &mut StdRng,
    ) -> LearnedPathAttempt {
        let ttl = self.nodes.len().saturating_mul(2).max(1);
        let mut visited = HashSet::new();
        let mut current = src;
        let mut path = vec![src];
        let mut transmissions = 0;
        let mut malicious_transit = false;
        visited.insert(current);

        for _ in 0..=ttl {
            if current == dst {
                return LearnedPathAttempt {
                    result: PathResult::Delivered(RoutedPath {
                        nodes: path,
                        malicious_transit,
                    }),
                    transmissions,
                };
            }

            if current != src {
                match self.nodes[current].forward {
                    ForwardBehavior::Honest => {}
                    ForwardBehavior::Blackhole => {
                        return LearnedPathAttempt {
                            result: PathResult::Blackholed,
                            transmissions,
                        };
                    }
                    ForwardBehavior::Flaky { drop_probability } => {
                        if rng.random::<f64>() < drop_probability {
                            return LearnedPathAttempt {
                                result: PathResult::FlakyDrop,
                                transmissions,
                            };
                        }
                    }
                }
                if self.nodes[current].is_malicious_or_misbehaving() {
                    malicious_transit = true;
                }
            }

            let next = if self.has_edge(current, dst) {
                dst
            } else {
                let Some(next) = learned_routes.get(&(current, dst)).copied() else {
                    return LearnedPathAttempt {
                        result: PathResult::NoRoute,
                        transmissions,
                    };
                };
                if !self.has_edge(current, next) {
                    return LearnedPathAttempt {
                        result: PathResult::NoRoute,
                        transmissions,
                    };
                }
                next
            };

            transmissions += 1;
            if !visited.insert(next) {
                return LearnedPathAttempt {
                    result: PathResult::Loop,
                    transmissions,
                };
            }
            path.push(next);
            current = next;
        }

        LearnedPathAttempt {
            result: PathResult::TtlExpired,
            transmissions,
        }
    }

    fn flood_discover_confirmed_path(
        &self,
        src: usize,
        dst: usize,
        rng: &mut StdRng,
    ) -> FloodAttempt {
        let ttl = self.nodes.len().max(1);
        let mut attempt = FloodAttempt::default();
        let mut queue = VecDeque::new();
        let mut processed = HashSet::new();
        queue.push_back(vec![src]);

        while let Some(path) = queue.pop_front() {
            if path.len().saturating_sub(1) > ttl {
                continue;
            }

            let current = *path.last().expect("flood path is non-empty");
            if !processed.insert(current) {
                continue;
            }

            if current != src && current != dst {
                match self.nodes[current].forward {
                    ForwardBehavior::Honest => {}
                    ForwardBehavior::Blackhole => {
                        attempt.dropped_by_blackhole = true;
                        continue;
                    }
                    ForwardBehavior::Flaky { drop_probability } => {
                        if rng.random::<f64>() < drop_probability {
                            attempt.dropped_by_flaky = true;
                            continue;
                        }
                    }
                }
            }

            if current == dst {
                let routed_path = RoutedPath {
                    malicious_transit: self.path_has_malicious_transit(&path),
                    nodes: path,
                };
                let reply = self.confirm_reply(&routed_path.nodes, rng);
                attempt.transmissions += reply.transmissions;
                if reply.confirmed {
                    attempt.confirmed_path = Some(routed_path);
                    break;
                }

                attempt.reply_failures += 1;
                attempt.unconfirmed_path = Some(routed_path);
                if reply.dropped_by_blackhole {
                    attempt.dropped_by_blackhole = true;
                }
                if reply.dropped_by_flaky {
                    attempt.dropped_by_flaky = true;
                }
                continue;
            }

            let previous = path
                .len()
                .checked_sub(2)
                .and_then(|index| path.get(index))
                .copied();
            for &(neighbor, _) in &self.nodes[current].neighbors {
                if Some(neighbor) == previous {
                    continue;
                }

                attempt.transmissions += 1;
                if processed.contains(&neighbor) || path.contains(&neighbor) {
                    continue;
                }

                let mut next_path = path.clone();
                next_path.push(neighbor);
                queue.push_back(next_path);
            }
        }

        attempt
    }

    fn confirm_reply(&self, path: &[usize], rng: &mut StdRng) -> ReplyAttempt {
        let mut attempt = ReplyAttempt {
            confirmed: true,
            transmissions: 0,
            dropped_by_blackhole: false,
            dropped_by_flaky: false,
        };
        if path.len() < 2 {
            return attempt;
        }

        let dst = *path.last().expect("path is non-empty");
        for index in (1..path.len()).rev() {
            let current = path[index];
            if current != dst {
                match self.nodes[current].forward {
                    ForwardBehavior::Honest => {}
                    ForwardBehavior::Blackhole => {
                        attempt.confirmed = false;
                        attempt.dropped_by_blackhole = true;
                        return attempt;
                    }
                    ForwardBehavior::Flaky { drop_probability } => {
                        if rng.random::<f64>() < drop_probability {
                            attempt.confirmed = false;
                            attempt.dropped_by_flaky = true;
                            return attempt;
                        }
                    }
                }
            }
            attempt.transmissions += 1;
        }

        attempt
    }

    fn path_has_malicious_transit(&self, path: &[usize]) -> bool {
        path.iter()
            .skip(1)
            .take(path.len().saturating_sub(2))
            .any(|node| self.nodes[*node].is_malicious_or_misbehaving())
    }

    fn simulate_route(
        &self,
        states: &[NodeState],
        views: &[HashMap<usize, Vec<NodeAddr>>],
        src: usize,
        dst: usize,
        rng: &mut StdRng,
    ) -> RouteProbeAttempt {
        let ttl = self.nodes.len().saturating_mul(2).max(1);
        let mut visited = HashSet::new();
        let mut current = src;
        let mut malicious_transit = false;
        visited.insert(current);

        for hops in 0..=ttl {
            if current == dst {
                return RouteProbeAttempt {
                    result: RouteResult::Delivered {
                        hops,
                        malicious_transit,
                    },
                    transmissions: hops,
                };
            }

            if current != src {
                match self.nodes[current].forward {
                    ForwardBehavior::Honest => {}
                    ForwardBehavior::Blackhole => {
                        return RouteProbeAttempt {
                            result: RouteResult::Blackholed,
                            transmissions: hops,
                        };
                    }
                    ForwardBehavior::Flaky { drop_probability } => {
                        if rng.random::<f64>() < drop_probability {
                            return RouteProbeAttempt {
                                result: RouteResult::FlakyDrop,
                                transmissions: hops,
                            };
                        }
                    }
                }
                if self.nodes[current].is_malicious_or_misbehaving() {
                    malicious_transit = true;
                }
            }

            let Some(next) = self.next_hop(states, views, current, dst) else {
                return RouteProbeAttempt {
                    result: RouteResult::NoRoute,
                    transmissions: hops,
                };
            };
            if visited.contains(&next) {
                return RouteProbeAttempt {
                    result: RouteResult::Loop,
                    transmissions: hops + 1,
                };
            }
            visited.insert(next);
            current = next;
        }

        RouteProbeAttempt {
            result: RouteResult::TtlExpired,
            transmissions: ttl,
        }
    }

    fn next_hop(
        &self,
        states: &[NodeState],
        views: &[HashMap<usize, Vec<NodeAddr>>],
        current: usize,
        dst: usize,
    ) -> Option<usize> {
        if self.has_edge(current, dst) {
            return Some(dst);
        }

        let dest_coord = &states[dst].coord;
        let my_coord = &states[current].coord;
        let my_distance = tree_distance(my_coord, dest_coord)?;

        let mut best: Option<(usize, usize, NodeAddr)> = None;
        for (&peer, peer_coord) in &views[current] {
            let distance = tree_distance(peer_coord, dest_coord).unwrap_or(usize::MAX);
            if distance >= my_distance {
                continue;
            }
            let peer_addr = self.nodes[peer].addr;
            let better = match best {
                None => true,
                Some((_, best_distance, best_addr)) => {
                    distance < best_distance || (distance == best_distance && peer_addr < best_addr)
                }
            };
            if better {
                best = Some((peer, distance, peer_addr));
            }
        }
        best.map(|(peer, _, _)| peer)
    }
}

#[derive(Debug)]
struct ParentDecision {
    parent: Option<(usize, Vec<NodeAddr>)>,
    accepted_coords: HashMap<usize, Vec<NodeAddr>>,
}

type LearnedRouteTable = HashMap<(usize, usize), usize>;

#[derive(Debug)]
struct ReplyLearnedProbe {
    result: RouteResult,
    transmissions: usize,
    discovery_flood: bool,
    learned_route_attempt: bool,
    reply_failure: bool,
}

impl Default for ReplyLearnedProbe {
    fn default() -> Self {
        Self {
            result: RouteResult::NoRoute,
            transmissions: 0,
            discovery_flood: false,
            learned_route_attempt: false,
            reply_failure: false,
        }
    }
}

#[derive(Debug)]
struct LearnedPathAttempt {
    result: PathResult,
    transmissions: usize,
}

#[derive(Debug)]
enum PathResult {
    Delivered(RoutedPath),
    NoRoute,
    Loop,
    TtlExpired,
    Blackholed,
    FlakyDrop,
}

#[derive(Debug, Clone)]
struct RoutedPath {
    nodes: Vec<usize>,
    malicious_transit: bool,
}

impl RoutedPath {
    fn hops(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }
}

#[derive(Debug, Default)]
struct FloodAttempt {
    confirmed_path: Option<RoutedPath>,
    unconfirmed_path: Option<RoutedPath>,
    transmissions: usize,
    dropped_by_blackhole: bool,
    dropped_by_flaky: bool,
    reply_failures: usize,
}

#[derive(Debug)]
struct ReplyAttempt {
    confirmed: bool,
    transmissions: usize,
    dropped_by_blackhole: bool,
    dropped_by_flaky: bool,
}

#[derive(Debug)]
struct RouteProbeAttempt {
    result: RouteResult,
    transmissions: usize,
}

#[derive(Debug)]
enum RouteResult {
    Delivered {
        hops: usize,
        malicious_transit: bool,
    },
    UnconfirmedDelivery {
        hops: usize,
        malicious_transit: bool,
    },
    NoRoute,
    Loop,
    TtlExpired,
    Blackholed,
    FlakyDrop,
}

/// Run several simulation configs and return one comparison report per config.
pub fn run_parameter_sweep(configs: &[SimConfig]) -> Vec<ComparisonReport> {
    configs
        .iter()
        .cloned()
        .map(|config| Simulation::new(config).run())
        .collect()
}

fn learn_path(learned_routes: &mut LearnedRouteTable, path: &[usize]) {
    if path.len() < 2 {
        return;
    }

    let src = path[0];
    let dst = *path.last().expect("path is non-empty");
    for pair in path.windows(2) {
        learned_routes.insert((pair[0], dst), pair[1]);
        learned_routes.insert((pair[1], src), pair[0]);
    }
}

fn invalidate_path(learned_routes: &mut LearnedRouteTable, path: &[usize], dst: usize) {
    for pair in path.windows(2) {
        if learned_routes.get(&(pair[0], dst)).copied() == Some(pair[1]) {
            learned_routes.remove(&(pair[0], dst));
        }
    }
}

fn assign_identity_behaviors(n: usize, adversary: AdversaryConfig) -> Vec<IdentityBehavior> {
    let root_grinders = fraction_count(n, adversary.root_grinder_fraction);
    let phantom_roots = fraction_count(n, adversary.phantom_root_fraction);
    (0..n)
        .map(|index| {
            if index < root_grinders {
                IdentityBehavior::RootGrinder
            } else if index < root_grinders + phantom_roots {
                IdentityBehavior::PhantomRoot
            } else {
                IdentityBehavior::Honest
            }
        })
        .collect()
}

fn assign_forward_behaviors(n: usize, adversary: AdversaryConfig) -> Vec<ForwardBehavior> {
    let blackholes = fraction_count(n, adversary.blackhole_fraction);
    let flaky = fraction_count(n, adversary.flaky_fraction);
    (0..n)
        .map(|index| {
            if index < blackholes {
                ForwardBehavior::Blackhole
            } else if index < blackholes + flaky {
                ForwardBehavior::Flaky {
                    drop_probability: adversary.flaky_drop_probability.clamp(0.0, 1.0),
                }
            } else {
                ForwardBehavior::Honest
            }
        })
        .collect()
}

fn fraction_count(n: usize, fraction: f64) -> usize {
    ((n as f64 * fraction.clamp(0.0, 1.0)).round() as usize).min(n)
}

fn addr_from_rank(rank: u128) -> NodeAddr {
    NodeAddr::from_bytes(rank.to_be_bytes())
}

fn fake_root() -> NodeAddr {
    NodeAddr::from_bytes([0u8; 16])
}

fn generate_connected_edges(
    n: usize,
    target_edges: usize,
    rng: &mut StdRng,
) -> Vec<(usize, usize)> {
    if n <= 1 {
        return Vec::new();
    }

    let target_edges = target_edges.max(n - 1).min(n * (n - 1) / 2);
    let mut edges = Vec::with_capacity(target_edges);
    let mut adj = vec![vec![false; n]; n];
    let mut connected = vec![false; n];
    connected[0] = true;
    let mut connected_count = 1;

    while connected_count < n {
        let from = rng.random_range(0..n);
        if !connected[from] {
            continue;
        }
        let to = rng.random_range(0..n);
        if connected[to] || from == to {
            continue;
        }
        edges.push((from, to));
        adj[from][to] = true;
        adj[to][from] = true;
        connected[to] = true;
        connected_count += 1;
    }

    let mut attempts = 0usize;
    while edges.len() < target_edges && attempts < target_edges * 20 {
        attempts += 1;
        let a = rng.random_range(0..n);
        let b = rng.random_range(0..n);
        if a == b || adj[a][b] {
            continue;
        }
        edges.push((a, b));
        adj[a][b] = true;
        adj[b][a] = true;
    }

    edges
}

fn tree_distance(a: &[NodeAddr], b: &[NodeAddr]) -> Option<usize> {
    if a.is_empty() || b.is_empty() || a.last() != b.last() {
        return None;
    }
    let common = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(left, right)| left == right)
        .count();
    let lca_depth_from_root = common.checked_sub(1)?;
    let a_depth = a.len() - 1;
    let b_depth = b.len() - 1;
    Some((a_depth - lca_depth_from_root) + (b_depth - lca_depth_from_root))
}

fn percentile_usize(sorted: &[usize], percentile: f64) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let p = percentile.clamp(0.0, 1.0);
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn strategy_seed(strategy: RoutingStrategy) -> u64 {
    match strategy {
        RoutingStrategy::CurrentFips => 0xF1F5_0001,
        RoutingStrategy::VerifiedAncestry => 0xF1F5_0002,
        RoutingStrategy::PinnedRoot => 0xF1F5_0003,
        RoutingStrategy::ReplyLearnedFlood => 0xF1F5_0004,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_for(report: &ComparisonReport, strategy: RoutingStrategy) -> &StrategyReport {
        report
            .strategies
            .iter()
            .find(|candidate| candidate.strategy == strategy)
            .expect("strategy report")
    }

    #[test]
    fn honest_network_routes_with_current_strategy() {
        let config = SimConfig {
            node_count: 40,
            target_edges: 90,
            route_probe_count: 250,
            seed: 11,
            adversary: AdversaryConfig::default(),
            strategies: vec![RoutingStrategy::CurrentFips],
            ..SimConfig::default()
        };

        let report = Simulation::new(config).run();
        let current = report_for(&report, RoutingStrategy::CurrentFips);

        assert!(current.converged, "tree should converge");
        assert_eq!(current.tree.root_capture_rate, 0.0);
        assert!(
            current.routing.success_rate >= 0.98,
            "expected near-perfect honest routing, got {:.3}",
            current.routing.success_rate
        );
    }

    #[test]
    fn phantom_root_attack_is_exposed_by_strategy_comparison() {
        let config = SimConfig {
            node_count: 60,
            target_edges: 140,
            route_probe_count: 500,
            seed: 21,
            adversary: AdversaryConfig {
                phantom_root_fraction: 0.08,
                blackhole_fraction: 0.08,
                ..AdversaryConfig::default()
            },
            strategies: vec![
                RoutingStrategy::CurrentFips,
                RoutingStrategy::VerifiedAncestry,
                RoutingStrategy::PinnedRoot,
            ],
            ..SimConfig::default()
        };

        let report = Simulation::new(config).run();
        let current = report_for(&report, RoutingStrategy::CurrentFips);
        let verified = report_for(&report, RoutingStrategy::VerifiedAncestry);
        let pinned = report_for(&report, RoutingStrategy::PinnedRoot);

        assert!(
            current.tree.honest_on_fake_root > 0,
            "current FIPS should expose phantom-root capture in this scenario"
        );
        assert_eq!(
            verified.tree.honest_on_fake_root, 0,
            "verified ancestry should reject phantom roots"
        );
        assert_eq!(
            pinned.tree.honest_on_fake_root, 0,
            "pinned root should reject phantom roots"
        );
        assert!(
            verified.routing.success_rate >= current.routing.success_rate,
            "verified ancestry should not route worse than current under phantom roots"
        );
        assert!(
            pinned.routing.success_rate >= current.routing.success_rate,
            "pinned root should not route worse than current under phantom roots"
        );
    }

    #[test]
    fn root_grinding_remains_gameable_without_root_membership() {
        let config = SimConfig {
            node_count: 60,
            target_edges: 140,
            route_probe_count: 500,
            seed: 31,
            adversary: AdversaryConfig {
                root_grinder_fraction: 0.05,
                blackhole_fraction: 0.05,
                ..AdversaryConfig::default()
            },
            strategies: vec![
                RoutingStrategy::CurrentFips,
                RoutingStrategy::VerifiedAncestry,
                RoutingStrategy::PinnedRoot,
            ],
            ..SimConfig::default()
        };

        let report = Simulation::new(config).run();
        let current = report_for(&report, RoutingStrategy::CurrentFips);
        let verified = report_for(&report, RoutingStrategy::VerifiedAncestry);
        let pinned = report_for(&report, RoutingStrategy::PinnedRoot);

        assert!(
            current.tree.honest_on_malicious_root > 0,
            "smallest-root strategy should be vulnerable to ground low node_addr"
        );
        assert!(
            verified.tree.honest_on_malicious_root > 0,
            "ancestry validation alone cannot reject an honestly advertised grinder root"
        );
        assert_eq!(
            pinned.tree.honest_on_malicious_root, 0,
            "pinned root should avoid grinder-root capture"
        );
        assert!(
            pinned.routing.success_rate >= current.routing.success_rate,
            "pinned root should improve or preserve routing under grinder blackholes"
        );
    }

    #[test]
    fn reply_learned_flood_uses_reply_confirmed_routes() {
        let config = SimConfig {
            node_count: 60,
            target_edges: 140,
            route_probe_count: 500,
            seed: 41,
            adversary: AdversaryConfig {
                root_grinder_fraction: 0.04,
                phantom_root_fraction: 0.08,
                blackhole_fraction: 0.05,
                flaky_fraction: 0.05,
                flaky_drop_probability: 0.20,
            },
            strategies: vec![RoutingStrategy::ReplyLearnedFlood],
            ..SimConfig::default()
        };

        let report = Simulation::new(config).run();
        let reply_learned = report_for(&report, RoutingStrategy::ReplyLearnedFlood);

        assert_eq!(
            reply_learned.tree.root_capture_rate, 0.0,
            "reply-learned flooding should not depend on a tree root"
        );
        assert!(
            reply_learned.routing.discovery_floods > 0,
            "first-contact routes should use discovery floods"
        );
        assert!(
            reply_learned.routing.learned_route_attempts > 0,
            "successful replies should populate the learned route cache"
        );
        assert!(
            reply_learned.routing.success_rate >= 0.75,
            "expected most bidirectional probes to confirm, got {:.3}",
            reply_learned.routing.success_rate
        );
        assert!(
            reply_learned.routing.avg_transmissions_per_probe > reply_learned.routing.avg_hops,
            "flood discovery should expose bandwidth cost beyond route hop count"
        );
    }
}
