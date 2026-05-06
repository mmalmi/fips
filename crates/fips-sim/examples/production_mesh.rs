use fips_sim::{
    AdversaryConfig, ProductionSimReport, RoutingComparisonReport, RoutingMode, SimConfig,
    Simulation, TopologyProfile,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tokio::time::pause();
    let (config, compare, json_only, summary_only) = parse_args();

    if compare {
        let mut original_config = config.clone();
        original_config.routing_mode = RoutingMode::Tree;
        eprintln!("running original tree routing...");
        let original = Simulation::new(original_config)
            .run()
            .await
            .expect("original simulation runs");
        if !json_only {
            print_report("original", &original);
        }

        let mut ours_config = config;
        ours_config.routing_mode = RoutingMode::ReplyLearned;
        eprintln!("running reply-learned routing...");
        let ours = Simulation::new(ours_config)
            .run()
            .await
            .expect("reply-learned simulation runs");
        if !json_only {
            print_report("ours", &ours);
        }

        let report = RoutingComparisonReport { original, ours };
        if !summary_only {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("report serializes")
            );
        }
    } else {
        let report = Simulation::new(config)
            .run()
            .await
            .expect("simulation runs");
        if !json_only {
            print_report("run", &report);
        }
        if !summary_only {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("report serializes")
            );
        }
    }
}

fn parse_args() -> (SimConfig, bool, bool, bool) {
    let mut config = SimConfig {
        node_count: 72,
        target_edges: 190,
        route_probe_count: 200,
        stream_probe_count: 8,
        stream_size_bytes: 1024 * 1024,
        chunk_size_bytes: 1024,
        background_packet_count: 2_000,
        background_payload_bytes: 512,
        background_send_interval_ms: 1,
        progress_interval_ms: 10_000,
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
    };
    let mut compare = false;
    let mut json_only = false;
    let mut summary_only = false;
    let mut target_edges_set = false;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--compare" => compare = true,
            "--json-only" => json_only = true,
            "--summary-only" => summary_only = true,
            "--nodes" => config.node_count = parse_next(&mut args, "--nodes"),
            "--edges" => {
                config.target_edges = parse_next(&mut args, "--edges");
                target_edges_set = true;
            }
            "--route-probes" => config.route_probe_count = parse_next(&mut args, "--route-probes"),
            "--stream-probes" => {
                config.stream_probe_count = parse_next(&mut args, "--stream-probes")
            }
            "--stream-bytes" => config.stream_size_bytes = parse_next(&mut args, "--stream-bytes"),
            "--chunk-bytes" => config.chunk_size_bytes = parse_next(&mut args, "--chunk-bytes"),
            "--background-packets" => {
                config.background_packet_count = parse_next(&mut args, "--background-packets")
            }
            "--background-bytes" => {
                config.background_payload_bytes = parse_next(&mut args, "--background-bytes")
            }
            "--background-interval-ms" => {
                config.background_send_interval_ms =
                    parse_next(&mut args, "--background-interval-ms")
            }
            "--progress-interval-ms" => {
                config.progress_interval_ms = parse_next(&mut args, "--progress-interval-ms")
            }
            "--no-progress" => config.progress_interval_ms = 0,
            "--convergence-wait-ms" => {
                config.convergence_wait_ms = parse_next(&mut args, "--convergence-wait-ms")
            }
            "--reconvergence-wait-ms" => {
                config.reconvergence_wait_ms = parse_next(&mut args, "--reconvergence-wait-ms")
            }
            "--delivery-timeout-ms" => {
                config.delivery_timeout_ms = parse_next(&mut args, "--delivery-timeout-ms")
            }
            "--stream-timeout-ms" => {
                config.stream_timeout_ms = parse_next(&mut args, "--stream-timeout-ms")
            }
            "--seed" => config.seed = parse_next(&mut args, "--seed"),
            "--mode" => {
                let mode = args.next().expect("--mode requires tree or reply_learned");
                config.routing_mode = match mode.as_str() {
                    "tree" => RoutingMode::Tree,
                    "reply_learned" => RoutingMode::ReplyLearned,
                    _ => panic!("unknown --mode {mode}; expected tree or reply_learned"),
                };
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => panic!("unknown argument {arg}; run with --help"),
        }
    }

    if !target_edges_set && config.node_count != 72 {
        config.target_edges = config.node_count.saturating_mul(3);
    }

    if summary_only {
        json_only = false;
    }

    (config, compare, json_only, summary_only)
}

fn parse_next<T>(args: &mut std::iter::Peekable<impl Iterator<Item = String>>, flag: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    args.next()
        .unwrap_or_else(|| panic!("{flag} requires a value"))
        .parse::<T>()
        .unwrap_or_else(|error| panic!("invalid value for {flag}: {error}"))
}

fn print_help() {
    println!(
        "usage: cargo run -p fips-sim --example production_mesh -- [--compare] [--nodes N] [--edges N] [--route-probes N] [--stream-probes N] [--stream-bytes N] [--background-packets N] [--progress-interval-ms N|--no-progress] [--mode tree|reply_learned] [--delivery-timeout-ms N] [--stream-timeout-ms N] [--json-only|--summary-only]"
    );
}

fn print_report(label: &str, report: &ProductionSimReport) {
    println!(
        "run={},mode={},nodes={},edges={},avg_degree={:.2},backbone_links={},regional_links={},long_haul_links={}",
        label,
        report.config.routing_mode,
        report.topology.node_count,
        report.topology.edge_count,
        report.topology.avg_degree,
        report.topology.backbone_links,
        report.topology.regional_links,
        report.topology.long_haul_links,
    );
    println!(
        "run,mode,phase,probe_success,probe_delivered,probe_failed_send,probe_timed_out,probe_p95_ms,stream_setup,chunk_delivery,chunk_loss,stream_mbps,bg_sent,bg_failed,packets_sent,packets_delivered,loss_drops,egress_drops,down_drops,no_route_drops"
    );
    for phase in [&report.baseline, &report.impaired] {
        println!(
            "{},{},{},{:.3},{},{},{},{:.1},{},{:.3},{:.3},{:.1},{},{},{},{},{},{},{},{}",
            label,
            report.config.routing_mode,
            phase.label,
            phase.route_probes.success_rate,
            phase.route_probes.delivered,
            phase.route_probes.failed_send,
            phase.route_probes.timed_out,
            phase.route_probes.p95_latency_ms,
            phase.streams.setup_delivered,
            phase.streams.chunk_delivery_rate,
            phase.streams.chunk_loss_rate,
            phase.streams.avg_delivered_mbps,
            phase.background.sent,
            phase.background.failed_send,
            phase.network.packets_sent,
            phase.network.packets_delivered,
            phase.network.packets_dropped_loss,
            phase.network.packets_dropped_egress,
            phase.network.packets_dropped_down,
            phase.network.packets_dropped_no_route,
        );
    }
}
