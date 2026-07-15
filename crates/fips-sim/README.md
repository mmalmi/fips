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

Run the deterministic open-discovery WoT admission scenario:

```sh
cargo run -p fips-sim --example wot_admission
```

The WoT admission report models the control-plane exchange around open
discovery: a 100+ node decentralized inv/want pubsub graph, local bootstrap from
1-3 known FIPS entry nodes, signed peer-advert discovery, an initially empty
rating history, local rating publication only after peers prove good or bad in
probe/degradation observations, untrusted rating-spam rejection, integer trust
scores, newcomer probe slots, and final admission ordering. Historic lookup is
represented as a normal Nostr filter over signed rating facts, including kind
`7368` and `#i=["fips.peer"]`, matching the hashtree stored-index query surface.
Production `fips-core` tests cover the matching signed kind 7368 rating import
and open-discovery enqueue path.

The example prints wall-clock progress to stderr every 10 seconds. Use
`--progress-interval-ms N` to change the interval, or `--no-progress` for
machine-only output.

Run a 1000-node comparison of original tree routing and reply-learned routing:

```sh
cargo run -p fips-sim --example production_mesh -- \
  --compare --nodes 1000 --route-probes 1000 --stream-probes 8 \
  --stream-bytes 8388608 --background-packets 50000 --summary-only
```

The default topology is a regional mesh with stronger backbone links and weaker
long-haul links. Reports include clean baseline and impaired phases, endpoint
probe delivery, stream setup counts, chunk-level stream packet delivery/loss, delivered goodput,
background traffic volume, link/node churn drops, blackhole/flaky egress drops,
topology mix, latency, loss, and throughput distribution.

`stream_setup` is the number of stream warmup packets that reached the chosen
destination before chunk sending began. It is a path/session readiness metric,
not a whole-stream completion metric; large-stream quality is represented by
chunk delivery, chunk loss, and delivered goodput.

The old analytical routing-strategy model was removed. This crate no longer
pretends to implement alternate routing protocols in parallel with FIPS; it
measures what the production stack actually does under controlled simulated
network conditions.
