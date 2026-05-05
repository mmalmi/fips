use fips_sim::{AdversaryConfig, SimConfig, Simulation, TopologyProfile};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let report = Simulation::new(SimConfig {
        node_count: 72,
        target_edges: 190,
        route_probe_count: 40,
        stream_probe_count: 10,
        stream_size_bytes: 256 * 1024,
        chunk_size_bytes: 1024,
        seed: 42,
        topology: TopologyProfile::Standard,
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
    .await
    .expect("simulation runs");

    println!(
        "phase,probe_success,probe_p95_ms,stream_success,stream_mbps,chunk_loss,packets_sent,packets_delivered,loss_drops,egress_drops,down_drops,no_route_drops"
    );
    for phase in [&report.baseline, &report.impaired] {
        println!(
            "{},{:.3},{:.1},{:.3},{:.1},{:.3},{},{},{},{},{},{}",
            phase.label,
            phase.route_probes.success_rate,
            phase.route_probes.p95_latency_ms,
            phase.streams.success_rate,
            phase.streams.avg_throughput_mbps,
            phase.streams.chunk_loss_rate,
            phase.network.packets_sent,
            phase.network.packets_delivered,
            phase.network.packets_dropped_loss,
            phase.network.packets_dropped_egress,
            phase.network.packets_dropped_down,
            phase.network.packets_dropped_no_route,
        );
    }

    println!(
        "\n{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );
}
