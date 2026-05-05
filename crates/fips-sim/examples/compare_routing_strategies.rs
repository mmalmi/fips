use fips_sim::{AdversaryConfig, RoutingStrategy, SimConfig, Simulation};

fn main() {
    let config = SimConfig {
        node_count: 100,
        target_edges: 240,
        route_probe_count: 1_000,
        stream_probe_count: 150,
        stream_size_bytes: 64 * 1024 * 1024,
        max_multipath_routes: 3,
        seed: 42,
        adversary: AdversaryConfig {
            root_grinder_fraction: 0.03,
            phantom_root_fraction: 0.05,
            blackhole_fraction: 0.08,
            flaky_fraction: 0.05,
            flaky_drop_probability: 0.30,
        },
        strategies: vec![
            RoutingStrategy::CurrentFips,
            RoutingStrategy::VerifiedAncestry,
            RoutingStrategy::PinnedRoot,
            RoutingStrategy::ReplyLearnedFlood,
            RoutingStrategy::ReplyLearnedMultipath,
        ],
        ..SimConfig::default()
    };

    let report = Simulation::new(config).run();

    println!(
        "strategy,packet_success,stream_success,stream_mbps,stream_p95_ms,avg_routes,root_capture,mal_parent,fake_root,mal_root,blackhole,flaky,reply_fail,no_route,loops,p95_hops,floods,learned,avg_tx"
    );
    for strategy in &report.strategies {
        println!(
            "{},{:.3},{:.3},{:.1},{:.1},{:.2},{:.3},{:.3},{},{},{},{},{},{},{},{},{},{},{:.1}",
            strategy.strategy_label,
            strategy.routing.success_rate,
            strategy.streams.success_rate,
            strategy.streams.avg_throughput_mbps,
            strategy.streams.p95_completion_ms,
            strategy.streams.avg_routes_per_stream,
            strategy.tree.root_capture_rate,
            strategy.tree.malicious_parent_rate,
            strategy.tree.honest_on_fake_root,
            strategy.tree.honest_on_malicious_root,
            strategy.routing.dropped_by_blackhole,
            strategy.routing.dropped_by_flaky,
            strategy.routing.reply_failures,
            strategy.routing.no_route,
            strategy.routing.loops,
            strategy.routing.p95_hops,
            strategy.routing.discovery_floods,
            strategy.routing.learned_route_attempts,
            strategy.routing.avg_transmissions_per_probe,
        );
    }

    println!(
        "\n{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );
}
