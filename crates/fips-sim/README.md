# fips-sim

Fast in-process simulation for FIPS routing strategy comparison.

This crate is intentionally lighter than `testing/chaos`: it does not start
containers or sockets. It models FIPS tree coordinates and greedy forwarding
directly, then compares strategies under honest, malicious, and misbehaving
peers.

```rust
use fips_sim::{AdversaryConfig, SimConfig, Simulation};

let report = Simulation::new(SimConfig {
    node_count: 100,
    target_edges: 240,
    route_probe_count: 1_000,
    adversary: AdversaryConfig {
        root_grinder_fraction: 0.03,
        phantom_root_fraction: 0.05,
        blackhole_fraction: 0.08,
        flaky_fraction: 0.05,
        flaky_drop_probability: 0.30,
    },
    ..SimConfig::default()
})
.run();
```

Run the built-in comparison example:

```sh
cargo run -p fips-sim --example compare_routing_strategies
```

Built-in strategies:

- `current_fips`: current smallest-root, transitive-ancestry FIPS v1 behavior.
- `verified_ancestry`: proposed hardening model that rejects phantom ancestry
  by requiring every ancestry hop to correspond to a real topology edge.
- `pinned_root`: private-mesh model where nodes only follow a configured root
  identity. In the simulator this is the smallest honest endpoint.
- `reply_learned_flood`: Reticulum-like discovery model where first contact
  floods through peers and a next-hop route is cached only after a reply/proof
  returns on the reverse path.

The simulator reports root capture, malicious parent selection, route success,
unconfirmed deliveries, reply failures, discovery floods, learned route
attempts, total transmissions, blackhole/flaky drops, loops, no-route failures,
and hop percentiles.
