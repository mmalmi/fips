use super::*;

pub(super) fn assign_roles(
    node_count: usize,
    adversary: AdversaryConfig,
    rng: &mut StdRng,
) -> Vec<NodeRole> {
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

pub(super) fn choose_backbone_nodes(node_count: usize, rng: &mut StdRng) -> HashSet<usize> {
    let count = (node_count / 8).clamp(2, node_count);
    let mut indices = (0..node_count).collect::<Vec<_>>();
    shuffle(&mut indices, rng);
    indices.into_iter().take(count).collect()
}

pub(super) fn generate_edges(
    config: &SimConfig,
    nodes: &[NodeSpec],
    rng: &mut StdRng,
) -> Vec<EdgeSpec> {
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

pub(super) fn pick_standard_edge(nodes: &[NodeSpec], rng: &mut StdRng) -> (usize, usize) {
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

pub(super) fn push_edge(
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

pub(super) fn classify_edge(a: &NodeSpec, b: &NodeSpec, profile: TopologyProfile) -> LinkClass {
    match profile {
        TopologyProfile::RandomMesh => LinkClass::Regional,
        TopologyProfile::Standard if a.backbone && b.backbone => LinkClass::Backbone,
        TopologyProfile::Standard if a.region == b.region => LinkClass::Regional,
        TopologyProfile::Standard => LinkClass::LongHaul,
    }
}

pub(super) fn generate_link(
    class: LinkClass,
    rng: &mut StdRng,
    profile: TopologyProfile,
) -> SimLink {
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

pub(super) fn mark_churned_links(edges: &mut [EdgeSpec], fraction: f64, rng: &mut StdRng) {
    let count = fraction_count(edges.len(), fraction);
    let mut indices = (0..edges.len()).collect::<Vec<_>>();
    shuffle(&mut indices, rng);
    for index in indices.into_iter().take(count) {
        edges[index].churned = true;
    }
}

pub(super) fn build_adjacency(node_count: usize, edges: &[EdgeSpec]) -> HashMap<usize, Vec<usize>> {
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
