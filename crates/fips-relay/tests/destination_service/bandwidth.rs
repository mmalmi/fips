//! Exercise configured free-data limits through the running service and native relay.
use super::*;
use fips_relay::{
    free_routes::FreeBandwidthPolicy,
    probe::{ReceiveProbe, SendProbe},
};

const PEER_BURST: u64 = 4_096;
const GLOBAL_BURST: u64 = 6_144;
const BURST_PACKETS: u32 = 16;

fn count(state: &Value, field: &str) -> u64 {
    state[field]
        .as_u64()
        .unwrap_or_else(|| panic!("missing free-bandwidth counter {field}: {state}"))
}

async fn middle_bandwidth(bench: &Bench) -> Value {
    let state = request(&bench.configs[2], &AdminRequest::Status)
        .await
        .unwrap();
    let free = &state["free_routes"];
    let bandwidth = free["bandwidth"].clone();
    assert!(
        bandwidth.is_object(),
        "configured service omitted free-bandwidth state"
    );
    assert_eq!(free["admitted_packets"], bandwidth["admitted_packets"]);
    assert_eq!(
        free["admitted_session_bytes"],
        bandwidth["admitted_session_bytes"]
    );
    assert!(count(&bandwidth, "charged_units") >= count(&bandwidth, "admitted_session_bytes"));
    assert_eq!(count(&bandwidth, "peer_capacity_denied"), 0);
    bandwidth
}

async fn burst(bench: &Bench, source: usize, destination: usize, id: u128) -> Value {
    let before = middle_bandwidth(bench).await;
    let previous_attempts = count(&before, "admitted_packets") + count(&before, "rate_denied");
    let stream_id = format!("{id:032x}");
    request(
        &bench.configs[destination],
        &AdminRequest::ReceiveProbe {
            probe: ReceiveProbe {
                source: bench.npubs[source].clone(),
                stream_id: stream_id.clone(),
                packet_count: BURST_PACKETS,
                payload_bytes: 1_000,
                measure_one_way_latency: false,
            },
        },
    )
    .await
    .unwrap();
    let sent = request(
        &bench.configs[source],
        &AdminRequest::SendProbe {
            probe: SendProbe {
                destination: bench.npubs[destination].clone(),
                stream_id,
                packet_count: BURST_PACKETS,
                payload_bytes: 1_000,
                packets_per_second: 1_000,
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(sent["probe"]["submitted_packets"], BURST_PACKETS);
    assert!(sent["probe"]["stopped_reason"].is_null());

    let mut observed = Value::Null;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            observed = middle_bandwidth(bench).await;
            // Session reports may also traverse this relay. Require at least
            // the offered burst's attempts rather than an exact packet delta.
            if count(&observed, "admitted_packets") + count(&observed, "rate_denied")
                >= previous_attempts + u64::from(BURST_PACKETS)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("relay did not observe the burst: {before} -> {observed}"));
    assert!(count(&observed, "rate_denied") > count(&before, "rate_denied"));
    observed
}

async fn reverse_delivery(bench: &Bench) {
    let opened = request(
        &bench.configs[4],
        &AdminRequest::Buy {
            destination: bench.npubs[0].clone(),
        },
    )
    .await
    .unwrap();
    assert!(opened["purchase"].is_null());
    assert_eq!(opened["free_route"]["price"]["msat"], 0);
    // The forward delivery has already established this bidirectional session.
    let payload = format!("reverse free delivery {}", "x".repeat(900));
    let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    request(
        &bench.configs[4],
        &AdminRequest::Send {
            destination: bench.npubs[0].clone(),
            payload,
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let state = request(&bench.configs[0], &AdminRequest::Status)
                .await
                .unwrap();
            if state["received"]["last_sha256"] == digest {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a fresh neighbor must retain free allowance after the first neighbor is denied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_free_bandwidth_bounds_neighbors_and_node_without_financial_state() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mint = OfflineMint::start().await;
        // Start before any service can initialize its bucket. Rates are one
        // session-envelope byte per second; elapsed time gives a conservative
        // refill bound without assuming an exact wall-clock execution speed.
        let started = tokio::time::Instant::now();
        let mut bench = Bench::start_configured(
            std::array::from_fn(|_| mint.url.clone()),
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [0; 5],
            },
            None,
            |index, config| {
                if index == 2 {
                    config.free_bandwidth = Some(FreeBandwidthPolicy {
                        global_bytes_per_second: 1,
                        global_burst_bytes: GLOBAL_BURST as u32,
                        peer_bytes_per_second: 1,
                        peer_burst_bytes: PEER_BURST as u32,
                    });
                }
            },
        )
        .await;
        let original: Vec<_> = bench.configs.iter().map(monetary_journals).collect();
        let opened = bench.open(4).await;
        assert!(opened["purchase"].is_null());
        assert_eq!(opened["free_route"]["price"]["msat"], 0);
        bench.deliver(4, "within first neighbor's allowance").await;
        let first = burst(&bench, 0, 4, 1).await;
        let refill = started.elapsed().as_secs() + 1;
        assert_eq!(count(&first, "tracked_peers"), 1);
        assert!(
            count(&first, "charged_units") <= PEER_BURST + refill,
            "{first}"
        );
        assert_unfunded(&bench, &original).await;
        mint.assert_unused();

        reverse_delivery(&bench).await;
        let both = burst(&bench, 4, 0, 2).await;
        let refill = started.elapsed().as_secs() + 1;
        assert_eq!(count(&both, "tracked_peers"), 2);
        assert!(
            count(&both, "charged_units") > PEER_BURST + refill,
            "both neighbors must receive service: {both}"
        );
        assert!(
            count(&both, "charged_units") <= GLOBAL_BURST + refill,
            "{both}"
        );
        assert_unfunded(&bench, &original).await;
        mint.assert_unused();
        bench.stop().await;
        mint.assert_unused();
    })
    .await
    .expect("configured free-bandwidth service deadline");
}
