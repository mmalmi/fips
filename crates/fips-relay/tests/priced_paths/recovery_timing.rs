//! Separate native recovery observations from a complete-batch confirmation rule.
use super::*;
use fips_core::FipsEndpointServiceReceiver;
use fips_relay::{control_transport::ControlStatistics, controller::Purchase};
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use tokio::time::Instant;

#[path = "recovery_timing/checks.rs"]
mod checks;

const PACKETS: usize = 128;
const BATCH: usize = 32;
const PAYLOAD: usize = 256;
const MAGIC: &[u8] = b"recovery-timing";
const PACING: Duration = Duration::from_millis(500);
const FEEDBACK: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_edge_loss_separates_recovery_from_batch_confirmation() {
    tokio::time::timeout(
        Duration::from_secs(180),
        run(0, Scenario::RecoveryTiming, 116),
    )
    .await
    .expect("recovery timeline and original financial closure deadline");
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Agreement {
    id: String,
    channel: String,
    provider: usize,
    quota: u64,
}

fn agreement(purchase: &Purchase, peers: &[PeerIdentity]) -> Agreement {
    Agreement {
        id: purchase.contract.id.clone(),
        channel: purchase.channel.id.clone(),
        provider: peers
            .iter()
            .position(|p| *p.node_addr() == purchase.provider)
            .unwrap(),
        quota: purchase.contract.max_units,
    }
}

#[derive(Debug, Serialize)]
struct Sent {
    sequence: usize,
    started_at_ms: u64,
    submitted_at_ms: u64,
    // Only batch starts sample selection; the stream itself never restarts.
    batch_agreement: Option<Agreement>,
}

#[derive(Debug, Serialize)]
struct Received {
    observed_at_ms: u64,
    enqueued_at_ms: u64,
}

#[derive(Debug, Serialize)]
struct Observation {
    started_at_ms: u64,
    finished_at_ms: u64,
    agreement: Option<Agreement>,
    working: bool,
    details: Value,
}

fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap()
}

fn payload(sequence: usize) -> Vec<u8> {
    let mut data = vec![0xa7; PAYLOAD];
    data[..8].copy_from_slice(&(sequence as u64).to_le_bytes());
    data[8..8 + MAGIC.len()].copy_from_slice(MAGIC);
    data
}

async fn send_stream(
    node: &FipsEndpoint,
    controller: &Controller,
    peers: &[PeerIdentity],
    started: Instant,
) -> Vec<Sent> {
    let mut sent = Vec::with_capacity(PACKETS);
    for sequence in 0..PACKETS {
        tokio::time::sleep_until(started + PACING * sequence as u32).await;
        let batch_agreement = if sequence % BATCH == 0 {
            let purchases = controller.purchases().await.unwrap();
            assert!(purchases.len() <= 1);
            purchases.first().map(|p| agreement(p, peers))
        } else {
            None
        };
        let started_at_ms = elapsed(started);
        node.send_datagram(peers[3], 44_740, 44_740, payload(sequence))
            .await
            .unwrap();
        sent.push(Sent {
            sequence,
            started_at_ms,
            submitted_at_ms: elapsed(started),
            batch_agreement,
        });
    }
    sent
}

struct Driver<'a> {
    nodes: &'a [Arc<FipsEndpoint>],
    peers: &'a [PeerIdentity],
    controllers: &'a [Arc<Controller>],
    services: &'a [ControllerServices],
    root: &'a Path,
    evidence: mobility::Evidence,
    quotes: Arc<ControlStatistics>,
}

impl Driver<'_> {
    async fn sample(&mut self, started: Instant) -> Observation {
        let began = elapsed(started);
        let next = mobility::Evidence::read(self.root, &self.controllers[0]).await;
        next.follows(&self.evidence);
        self.evidence = next;
        let watches = self.controllers[0].watched_routes().await.unwrap();
        assert_eq!(
            watches.len(),
            1,
            "one original Watch controls the whole stream"
        );
        assert!(!watches[0].paused);
        assert_eq!(watches[0].destination, self.peers[3].npub());
        assert_eq!(watches[0].max_rate_msat_per_kib, 192);
        let pending = !serde_json::to_value(&watches[0]).unwrap()["pending"].is_null();
        let before = self.controllers[0].purchases().await.unwrap();
        assert!(before.len() <= 1);
        let quality = self.nodes[0]
            .source_route_quality(self.peers[3], FEEDBACK)
            .await
            .unwrap();
        let after = self.controllers[0].purchases().await.unwrap();
        assert!(after.len() <= 1);
        let selected = after.first();
        let provider = selected.map(|p| {
            self.peers
                .iter()
                .position(|peer| *peer.node_addr() == p.provider)
                .unwrap()
        });
        if let Some(purchase) = selected {
            assert!(matches!(provider, Some(1 | 2)));
            assert_eq!(purchase.channel.capacity_sat, 64);
            assert_eq!(purchase.contract.price.per_bytes, 1024);
            assert_eq!(
                purchase.contract.price.msat,
                if provider == Some(1) { 128 } else { 160 }
            );
            assert!(matches!(purchase.contract.max_units, 32_768 | 131_072));
        }
        let (authorized, evidence, credit) = selected.map_or((0, 0, 0), |p| {
            (
                self.services[0]
                    .buyer
                    .authorized_sat(&p.channel.id)
                    .unwrap(),
                self.services[0].buyer.evidence_msat(&p.channel.id).unwrap(),
                self.services[provider.unwrap()]
                    .seller
                    .channel_usage(&p.channel.id)
                    .unwrap()
                    .paid_msat,
            )
        });
        let source_peers = self.nodes[0].peers().await.unwrap();
        for index in [1, 2] {
            assert!(
                source_peers
                    .iter()
                    .any(|p| { p.node_addr == *self.peers[index].node_addr() && p.connected }),
                "the source adjacency must survive the remote edge cut"
            );
        }
        let cheap_egress_connected = self.nodes[1]
            .peers()
            .await
            .unwrap()
            .iter()
            .any(|p| p.node_addr == *self.peers[3].node_addr() && p.connected);
        assert!(
            self.nodes[2]
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| { p.node_addr == *self.peers[3].node_addr() && p.connected }),
            "the alternative edge was never cut"
        );
        let native_provider = quality
            .next_hop
            .and_then(|hop| self.peers.iter().position(|p| *p.node_addr() == hop));
        let qualified = quality.receiver_reports_enabled
            && quality.has_recent_delivery_feedback
            && !quality.delivery_feedback_timed_out
            && quality
                .loss_rate
                .is_some_and(|v| v.is_finite() && (0.0..=0.25).contains(&v))
            && quality
                .rtt_ms
                .is_some_and(|v| v.is_finite() && (0.0..=5000.0).contains(&v))
            && quality
                .goodput_bps
                .is_some_and(|v| v.is_finite() && v > 0.0);
        let working = before == after
            && !pending
            && provider == Some(2)
            && native_provider == Some(2)
            && qualified
            && selected.is_some_and(|p| p.contract.max_units > 32_768)
            && authorized > 0
            && evidence > 0
            && credit >= evidence.max(authorized * 1000);
        Observation {
            started_at_ms: began,
            finished_at_ms: elapsed(started),
            agreement: selected.map(|p| agreement(p, self.peers)),
            working,
            details: json!({
                "selection_stable": before == after, "watch_pending": pending,
                "native_provider": native_provider, "feedback_recent": quality.has_recent_delivery_feedback,
                "feedback_timed_out": quality.delivery_feedback_timed_out,
                "rtt_ms": quality.rtt_ms, "loss_rate": quality.loss_rate, "goodput_bps": quality.goodput_bps,
                "native_sent_packets": quality.sent_packets, "native_sent_bytes": quality.sent_bytes,
                "provider_credited_msat": credit, "authorized_sat": authorized,
                "evidence_msat": evidence, "cheap_egress_connected": cheap_egress_connected,
                "quote_requests_started": self.quotes.snapshot().requests_started,
                "controller_errors": errors(self.controllers),
            }),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    network: &SimNetwork,
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    controllers: &[Arc<Controller>],
    services: &[ControllerServices],
    receiver: &mut FipsEndpointServiceReceiver,
    first: &Purchase,
    root: &Path,
    quotes: Arc<ControlStatistics>,
) {
    let mut driver = Driver {
        nodes,
        peers,
        controllers,
        services,
        root,
        quotes,
        evidence: mobility::Evidence::read(root, &controllers[0]).await,
    };
    assert_eq!(
        Scenario::RecoveryTiming.selection_policy(),
        PriceSelectionPolicy::default()
    );
    assert_eq!(first.contract.price.msat, 128);
    let initial = nodes[0]
        .source_route_quality(peers[3], FEEDBACK)
        .await
        .unwrap();
    assert!(initial.has_recent_delivery_feedback);
    assert_eq!(initial.next_hop, Some(*peers[1].node_addr()));
    let wire_before = network.stats();
    let started = Instant::now();
    let started_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let observe = async {
        let mut received = BTreeMap::new();
        let mut observations = Vec::new();
        let mut cut = None;
        let mut batch = Vec::new();
        let mut ticker = tokio::time::interval(Duration::from_millis(250));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let until = started + Duration::from_secs(70);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break,
                _ = ticker.tick() => observations.push(driver.sample(started).await),
                count = receiver.recv_batch_into(&mut batch, 32) => {
                    assert!(count.is_some(), "destination receiver remains open");
                    for message in &batch {
                        let data = message.data.as_slice();
                        if data.len() != PAYLOAD || &data[8..8 + MAGIC.len()] != MAGIC {
                            continue; // Previous setup traffic is outside the numbered stream.
                        }
                        assert_eq!(message.source_peer.node_addr(), peers[0].node_addr());
                        let sequence = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
                        assert!(sequence < PACKETS);
                        assert_eq!(data, payload(sequence).as_slice());
                        assert!(received.insert(sequence, Received {
                            observed_at_ms: elapsed(started), enqueued_at_ms: message.enqueued_at_ms,
                        }).is_none(), "numbered payloads are never replayed or duplicated");
                        if cut.is_none() {
                            assert_eq!(controllers[0].purchases().await.unwrap(), vec![first.clone()]);
                            cut = Some(elapsed(started));
                            // Keep both source links and all processes intact.
                            network.set_link_up("1", "3", false);
                        }
                    }
                }
            }
        }
        (
            cut.expect("a real numbered delivery must precede the cut"),
            received,
            observations,
        )
    };
    let (sent, (cut, received, observations)) = tokio::join!(
        send_stream(&nodes[0], &controllers[0], peers, started),
        observe,
    );
    let wire = network.stats().delta_since(&wire_before);
    assert!(
        wire.packets_dropped_down > 0,
        "the edge cut must drop actual carrier traffic"
    );
    let result = checks::summarize(&sent, &received, &observations, cut);
    eprintln!(
        "recovery timeline {}",
        json!({
            "started_unix_ms": started_unix_ms, "cut_at_ms": cut,
            "sent": sent, "received": received,
            "observations": observations, "result": result, "wire": wire,
            "claim": "observed delivery/quality/provider-credit timing; no isolated trigger attribution",
        })
    );
    assert!(
        result.is_ok(),
        "recovery timeline did not prove delivery, payment and confirmation"
    );
    let budget = controllers[0].funding_budget().await.unwrap();
    assert_eq!(budget.wallet_debited_sat, 128);
    assert_eq!(budget.locked_sat, 128);
    assert_eq!(budget.wallet_refunded_sat, 0);
    let history = controllers[0].purchase_history().await.unwrap();
    let channels: std::collections::BTreeSet<_> = history.iter().map(|p| &p.channel.id).collect();
    assert_eq!(channels.len(), 2, "one original channel per provider");
    assert!(
        history
            .iter()
            .any(|p| p.provider == *peers[2].node_addr() && p.contract.max_units == 32_768),
        "replacement starts with its bounded trial"
    );
    for controller in &controllers[1..] {
        assert!(controller.purchase_history().await.unwrap().is_empty());
    }
    // The shared fixture reloads and settles these same channels, then verifies
    // conservation of all 259 test sats; no timeline-specific financial replay.
}
