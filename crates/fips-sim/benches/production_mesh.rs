use fips_sim::{AdversaryConfig, RoutingMode, SimConfig, Simulation, TopologyProfile};

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build benchmark runtime");

    runtime.block_on(async {
        tokio::time::pause();
        run("original", RoutingMode::Tree).await;
        run("ours", RoutingMode::ReplyLearned).await;
    });
}

async fn run(label: &str, routing_mode: RoutingMode) {
    let started = std::time::Instant::now();
    let report = Simulation::new(SimConfig {
        node_count: 1000,
        target_edges: 3000,
        route_probe_count: 1000,
        stream_probe_count: 8,
        stream_size_bytes: 8 * 1024 * 1024,
        chunk_size_bytes: 1024,
        background_packet_count: 50_000,
        background_payload_bytes: 512,
        background_send_interval_ms: 1,
        delivery_timeout_ms: 4_000,
        stream_timeout_ms: 12_000,
        topology: TopologyProfile::Standard,
        routing_mode,
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
    .expect("production mesh benchmark simulation runs");

    for phase in [&report.baseline, &report.impaired] {
        println!(
            "bench={label},mode={},phase={},probe_delivery={:.3},probe_p95_ms={:.1},chunk_delivery={:.3},chunk_loss={:.3},stream_mbps={:.1},bg_sent={},packets_sent={},packets_delivered={},wall_s={:.1}",
            report.config.routing_mode,
            phase.label,
            phase.route_probes.success_rate,
            phase.route_probes.p95_latency_ms,
            phase.streams.chunk_delivery_rate,
            phase.streams.chunk_loss_rate,
            phase.streams.avg_delivered_mbps,
            phase.background.sent,
            phase.network.packets_sent,
            phase.network.packets_delivered,
            started.elapsed().as_secs_f64(),
        );
    }
}
