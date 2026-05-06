# fips-sim

Production-backed in-process simulation for FIPS routing behavior.

This crate starts real `FipsEndpoint` nodes and connects them with the
`fips-core` in-memory `sim` transport. The simulator controls topology,
latency, bandwidth, packet loss, blackhole/flaky peers, and churn, but routing
itself is the production FIPS handshake, tree, discovery, session, and
forwarding code.

The example binary runs under Tokio's paused clock. Simulated link latency,
convergence waits, delivery timeouts, and the production routing/discovery
timers that use FIPS' shared clock advance virtual time instead of wall-clock
time.

```rust
use fips_sim::{AdversaryConfig, RoutingMode, SimConfig, Simulation, TopologyProfile};

let report = Simulation::new(SimConfig {
    node_count: 72,
    target_edges: 190,
    route_probe_count: 40,
    stream_probe_count: 10,
    stream_size_bytes: 256 * 1024,
    topology: TopologyProfile::Standard,
    routing_mode: RoutingMode::Tree,
    adversary: AdversaryConfig {
        blackhole_fraction: 0.06,
        flaky_fraction: 0.06,
        flaky_drop_probability: 0.30,
        churned_node_fraction: 0.04,
        churned_link_fraction: 0.06,
    },
    ..SimConfig::default()
})
.run()
.await?;
```

Run the standard production mesh scenario:

```sh
cargo run -p fips-sim --example production_mesh
```

Run a 1000-node comparison of original tree routing and reply-learned routing:

```sh
cargo run -p fips-sim --example production_mesh -- \
  --compare --nodes 1000 --route-probes 100 --stream-probes 8 --summary-only
```

The default topology is a regional mesh with stronger backbone links and weaker
long-haul links. Reports include clean baseline and impaired phases, endpoint
probe delivery, chunked stream completion, throughput, packet loss, link/node
churn drops, blackhole/flaky egress drops, topology mix, latency, loss, and
throughput distribution.

The old analytical routing-strategy model was removed. This crate no longer
pretends to implement alternate routing protocols in parallel with FIPS; it
measures what the production stack actually does under controlled simulated
network conditions.
