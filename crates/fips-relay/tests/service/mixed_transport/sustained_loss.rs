//! The router's finite loss/renewal workload on ordinary daemon receive loops.
use super::*;
use fips_relay::service::native_request;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const PACKETS: u32 = 42_000;
const RATE: u32 = 140;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "five-minute ordinary UDP loss, renewal and rekey qualification"]
async fn sustained_udp_loss_keeps_renewing_paid_neighbors_live() {
    lifecycle::run(SecondHop::Udp, lifecycle::Workload::SustainedLoss).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "five-minute raw Ethernet qualification; needs fresh network namespace, ip and nft"]
async fn sustained_ethernet_loss_keeps_discovered_paid_neighbors_live() {
    lifecycle::run(SecondHop::Ethernet, lifecycle::Workload::SustainedLoss).await;
}

pub(super) async fn exercise(bench: &mut MixedBench) {
    bench.set_stage("sustained-carrier-setup");
    bench.assert_carriers().await;
    for (source, destination) in [(0, 2), (2, 0)] {
        request(
            &bench.configs[source],
            &AdminRequest::Buy {
                destination: bench.npubs[destination].clone(),
            },
        )
        .await
        .unwrap();
    }
    bench.deliver_bidirectional([0, 2]).await;
    let mut probes = Vec::new();
    for (source, destination) in [(0, 2), (2, 0)] {
        probes.push(
            bench
                .prepare_timed_probe(source, destination, PACKETS, 1_000, RATE, Some(300))
                .await,
        );
    }
    bench.enable_loss(true);
    bench.set_stage("sustained-carrier-loss");
    let started = tokio::time::Instant::now();
    let sent = async {
        let (a, b) = tokio::join!(
            bench.submit_probe(0, probes[0].clone()),
            bench.submit_probe(2, probes[1].clone())
        );
        assert!(a["probe"]["elapsed_us"].as_u64().unwrap() >= 299_000_000);
        assert!(b["probe"]["elapsed_us"].as_u64().unwrap() >= 299_000_000);
    };
    let observe = async {
        let mut observed = Observations::default();
        while started.elapsed() < Duration::from_secs(303) {
            observed.sample(bench, started).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        observed.report();
        observed
    };
    let ((), observed) = tokio::join!(sent, observe);
    bench.enable_loss(false);
    let counts = bench.loss_counts();
    let states = bench.states().await;
    let delivery: Vec<_> = [0, 2].into_iter().enumerate().map(|(direction, destination)| {
        let probe = states[destination]["probe"].clone();
        let received = probe["unique_packets"].as_u64().unwrap();
        let (frames, dropped) = counts[direction];
        eprintln!("sustained carrier: destination={destination} received={received} frames={frames} dropped={dropped}");
        (probe, received, frames, dropped)
    }).collect();
    // Preserve both receiver totals before any delivery or link assertion fails.
    for (probe, received, frames, dropped) in delivery {
        assert_eq!(probe["invalid_packets"], 0);
        assert_eq!(probe["duplicate_packets"], 0);
        assert_eq!(probe["unique_bytes"], received * 1_000);
        let expected_drops = if bench.second_hop_kind() == "ethernet" {
            frames.div_ceil(20)
        } else {
            frames / 20
        };
        assert!(dropped > 0 && dropped == expected_drops);
        assert!(received >= u64::from(PACKETS) * 9 / 10);
        assert!(
            u64::from(PACKETS) - received <= dropped,
            "loss exceeds injected carrier frames"
        );
    }
    observed.validate();
    bench.deliver_bidirectional([0, 2]).await;
}

#[derive(PartialEq, serde::Serialize)]
struct Neighbor {
    connected: bool,
    link: Option<u64>,
    epoch: Option<String>,
}

#[derive(Default)]
struct Observations {
    epochs: BTreeMap<(usize, usize), BTreeSet<String>>,
    links: BTreeMap<(usize, usize), BTreeSet<u64>>,
    previous: BTreeMap<(usize, usize), Neighbor>,
    channels: [BTreeSet<String>; 2],
    disconnected: usize,
    samples: usize,
}

impl Observations {
    async fn sample(&mut self, bench: &MixedBench, started: tokio::time::Instant) {
        let begin_us = started.elapsed().as_micros();
        let wall_unix_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let states = bench.states().await;
        let delivered =
            [0, 2].map(|node| states[node]["probe"]["unique_packets"].as_u64().unwrap());
        let drops: Vec<_> = bench
            .loss_counts()
            .into_iter()
            .map(|(_, drops)| drops)
            .collect();
        let counts_before = self.channels.each_ref().map(BTreeSet::len);
        for (direction, source) in [0, 2].into_iter().enumerate() {
            for p in states[source]["purchases"].as_array().unwrap() {
                self.channels[direction].insert(p["channel"]["id"].as_str().unwrap().to_owned());
            }
            let budget: FundingBudget =
                serde_json::from_value(states[source]["funding_budget"].clone()).unwrap();
            assert!(budget.exposure_sat <= 128 && budget.locked_sat <= 64);
        }
        let counts = self.channels.each_ref().map(BTreeSet::len);
        for (node, state) in states.iter().enumerate() {
            let report = native_request(&bench.configs[node], &json!({"command":"show_peers"}))
                .await
                .unwrap();
            for (remote, npub) in bench.npubs.iter().enumerate() {
                if node.abs_diff(remote) != 1 {
                    continue;
                }
                let service_peer = state["peers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["npub"] == *npub);
                let native_peer = report["data"]["peers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["npub"] == *npub);
                let peer = Neighbor {
                    connected: service_peer.is_some_and(|p| p["connected"] == true),
                    link: native_peer.and_then(|p| p["link_id"].as_u64()),
                    epoch: native_peer
                        .and_then(|p| p["our_session_index"].as_str())
                        .map(str::to_owned),
                };
                self.disconnected += usize::from(!peer.connected);
                if let Some(index) = &peer.epoch {
                    self.epochs
                        .entry((node, remote))
                        .or_default()
                        .insert(index.clone());
                }
                if let Some(link) = peer.link {
                    self.links.entry((node, remote)).or_default().insert(link);
                }
                if self.previous.get(&(node, remote)) != Some(&peer) {
                    eprintln!(
                        "sustained carrier event {}",
                        json!({"kind":"neighbor", "node":node, "remote":remote,
                        "begin_us":begin_us, "end_us":started.elapsed().as_micros(), "wall_unix_us":wall_unix_us,
                        "peer":&peer, "delivered":delivered, "drops":drops})
                    );
                    self.previous.insert((node, remote), peer);
                }
            }
        }
        if counts != counts_before || self.samples.is_multiple_of(10) {
            eprintln!(
                "sustained carrier event {}",
                json!({"kind":"progress", "begin_us":begin_us,
                "end_us":started.elapsed().as_micros(), "wall_unix_us":wall_unix_us,
                "channels":counts, "delivered":delivered, "drops":drops})
            );
        }
        self.samples += 1;
    }

    fn report(&self) {
        eprintln!(
            "sustained carrier: samples={} disconnected={} channels={:?} link_counts={:?} epoch_counts={:?}",
            self.samples,
            self.disconnected,
            self.channels.each_ref().map(BTreeSet::len),
            self.links.values().map(BTreeSet::len).collect::<Vec<_>>(),
            self.epochs.values().map(BTreeSet::len).collect::<Vec<_>>()
        );
    }

    fn validate(&self) {
        assert_eq!(
            self.disconnected, 0,
            "paid neighbor disappeared during continuous traffic"
        );
        assert_eq!(self.links.len(), 4);
        // Authenticated direct refresh may replace a local carrier handle.
        // Keep those changes as diagnostics; peer identity, delivery and
        // financial bounds determine continuity through renewal.
        assert_eq!(self.epochs.len(), 4);
        assert!(
            self.epochs.values().all(|v| v.len() >= 3),
            "two normal key rotations per edge"
        );
        assert!(
            self.channels.iter().all(|v| v.len() >= 4),
            "three expiry renewals per direction"
        );
    }
}
