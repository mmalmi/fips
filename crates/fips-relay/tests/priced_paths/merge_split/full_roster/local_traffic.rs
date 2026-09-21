//! Independently offered local demand during slow cross-mesh/payment checks.
use super::*;
use fips_core::{FipsEndpointServiceDatagram, FipsEndpointServiceReceiver};
use std::sync::Mutex;
use tokio::{sync::oneshot, task::JoinHandle};

const PORT: u16 = 44_749;
const MAX_PACKETS: usize = 128;
const MAX_GAP_MS: u64 = 5_000; // Below the fixture's 10-second idle threshold.

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    offered: usize,
    submitted: usize,
    delivered: usize,
    duplicates: usize,
    last_offered_ms: u64,
    last_delivered_ms: u64,
    max_offered_gap_ms: u64,
    max_delivered_gap_ms: u64,
}

#[derive(Debug, Default)]
struct Progress {
    streams: [Counts; 2],
    error: Option<String>,
}

pub(super) struct LocalTraffic {
    start: Instant,
    progress: Arc<Mutex<Progress>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl LocalTraffic {
    pub(super) async fn start(bench: &Bench) -> Self {
        let receivers = [
            bench.nodes[2]
                .register_service_receiver(PORT)
                .await
                .unwrap(),
            bench.nodes[3]
                .register_service_receiver(PORT)
                .await
                .unwrap(),
        ];
        let nodes = [bench.nodes[0].clone(), bench.nodes[5].clone()];
        let sources = [bench.peers[0], bench.peers[5]];
        let destinations = [bench.peers[2], bench.peers[3]];
        let progress = Arc::new(Mutex::new(Progress::default()));
        let (stop, stopped) = oneshot::channel();
        let start = Instant::now();
        let task = tokio::spawn(run(
            nodes,
            sources,
            destinations,
            receivers,
            progress.clone(),
            start,
            stopped,
        ));
        Self {
            start,
            progress,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub(super) fn failure(&self) -> Option<String> {
        let elapsed = self.start.elapsed().as_millis() as u64;
        let progress = self.progress.lock().unwrap();
        if progress.error.is_some() {
            return Some(format!("local demand pump failed: {progress:?}"));
        }
        for stream in progress.streams {
            if stream.offered > MAX_PACKETS || stream.delivered > stream.offered {
                return Some(format!("local demand count bound failed: {progress:?}"));
            }
            if stream.max_offered_gap_ms > MAX_GAP_MS || stream.max_delivered_gap_ms > MAX_GAP_MS {
                return Some(format!(
                    "local demand must progress while cross-mesh checks wait: {progress:?}"
                ));
            }
            if elapsed.saturating_sub(stream.last_offered_ms) > MAX_GAP_MS
                || elapsed.saturating_sub(stream.last_delivered_ms) > MAX_GAP_MS
            {
                return Some(format!(
                    "local demand paused during acceptance at {elapsed}ms: {progress:?}"
                ));
            }
        }
        None
    }

    pub(super) fn check(&self) {
        let failure = self.failure();
        assert!(failure.is_none(), "{}", failure.unwrap_or_default());
    }

    pub(super) async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let task = self.task.as_mut().unwrap();
        match tokio::time::timeout(Duration::from_secs(3), &mut *task).await {
            Ok(result) => result.expect("local demand pump task"),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("local demand pump did not stop within its bounded drain");
            }
        }
        self.task.take();
        self.check();
        let progress = self.progress.lock().unwrap();
        eprintln!(
            "full-roster independent local demand: elapsed_ms={} {progress:?}",
            self.start.elapsed().as_millis()
        );
        assert!(progress.streams.iter().all(|stream| stream.offered > 0
            && stream.offered == stream.submitted
            && stream.delivered > 0));
    }
}

impl Drop for LocalTraffic {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            // A surrounding assertion can unwind before normal stop/join. Do
            // not leave a detached sender spending from the fixture's channels.
            task.abort();
            if let Ok(progress) = self.progress.lock() {
                eprintln!(
                    "full-roster local demand interrupted at {}ms: {progress:?}",
                    self.start.elapsed().as_millis(),
                );
            }
        }
    }
}

fn record(
    batch: &mut Vec<FipsEndpointServiceDatagram>,
    source: PeerIdentity,
    direction: usize,
    seen: &mut [bool; MAX_PACKETS],
    progress: &Mutex<Progress>,
    start: Instant,
) {
    for message in batch.drain(..) {
        let bytes = message.data.as_slice();
        let seq = bytes
            .first()
            .map_or(MAX_PACKETS, |value| usize::from(*value));
        let mut progress = progress.lock().unwrap();
        if message.source_peer.node_addr() != source.node_addr()
            || bytes.len() != 900
            || bytes[1..].iter().any(|&byte| byte != 210 + direction as u8)
            || seq >= progress.streams[direction].offered
        {
            progress.error = Some(format!(
                "invalid local demand payload on stream {direction}"
            ));
            continue;
        }
        let stream = &mut progress.streams[direction];
        if seen[seq] {
            stream.duplicates += 1;
            continue;
        }
        seen[seq] = true;
        let elapsed = start.elapsed().as_millis() as u64;
        stream.max_delivered_gap_ms = stream
            .max_delivered_gap_ms
            .max(elapsed.saturating_sub(stream.last_delivered_ms));
        stream.last_delivered_ms = elapsed;
        stream.delivered += 1;
    }
}

async fn run(
    nodes: [Arc<FipsEndpoint>; 2],
    sources: [PeerIdentity; 2],
    destinations: [PeerIdentity; 2],
    receivers: [FipsEndpointServiceReceiver; 2],
    progress: Arc<Mutex<Progress>>,
    start: Instant,
    mut stop: oneshot::Receiver<()>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut seen = [[false; MAX_PACKETS]; 2];
    let mut batches = [Vec::new(), Vec::new()];
    let [left, right] = &mut batches;
    let mut next = 0;
    let mut draining = None;
    loop {
        tokio::select! {
            _ = &mut stop, if draining.is_none() => {
                draining = Some(Instant::now() + Duration::from_secs(1));
            }
            _ = tokio::time::sleep_until(draining.unwrap_or(start + Duration::from_secs(130))) => break,
            _ = tick.tick(), if draining.is_none() => {
                if next == MAX_PACKETS {
                    progress.lock().unwrap().error = Some("finite local workload exhausted".into());
                    break;
                }
                for direction in 0..2 {
                    let mut payload = vec![210 + direction as u8; 900];
                    payload[0] = next as u8;
                    {
                        let mut progress = progress.lock().unwrap();
                        let stream = &mut progress.streams[direction];
                        let elapsed = start.elapsed().as_millis() as u64;
                        stream.max_offered_gap_ms = stream.max_offered_gap_ms
                            .max(elapsed.saturating_sub(stream.last_offered_ms));
                        stream.last_offered_ms = elapsed;
                        stream.offered += 1;
                    }
                    let submitted = tokio::time::timeout(Duration::from_millis(500),
                        nodes[direction].send_datagram(destinations[direction], PORT, PORT, payload)).await;
                    let mut progress = progress.lock().unwrap();
                    match submitted {
                        Ok(Ok(())) => progress.streams[direction].submitted += 1,
                        _ => {
                            progress.error = Some(format!("local stream {direction} submission failed"));
                            return;
                        }
                    }
                }
                next += 1;
            }
            result = receivers[0].recv_batch_into(left, 64) => {
                if result.is_none() {
                    progress.lock().unwrap().error = Some("local receiver 0 closed".into());
                    break;
                }
                record(left, sources[0], 0, &mut seen[0], &progress, start);
            }
            result = receivers[1].recv_batch_into(right, 64) => {
                if result.is_none() {
                    progress.lock().unwrap().error = Some("local receiver 1 closed".into());
                    break;
                }
                record(right, sources[1], 1, &mut seen[1], &progress, start);
            }
        }
    }
}

fn fields(value: &Value, names: &[&str]) -> Value {
    names
        .iter()
        .map(|&name| (name.to_owned(), value[name].clone()))
        .collect()
}

/// One failure-only snapshot of public native state, never wallet records.
/// Query intervals are observations after failure, not packet-event timestamps.
pub(super) async fn capture_failure(
    root: &Path,
    identities: &[PeerIdentity],
    gates: &[Arc<Gate>],
    controllers: &[Arc<Controller>],
    buyer: &BuyerAuthorizer,
) {
    let start = Instant::now();
    eprintln!(
        "full-roster failure controller errors: {:?}",
        errors(controllers)
    );
    for watch in controllers[0]
        .watched_routes()
        .await
        .unwrap()
        .into_iter()
        .take(8)
    {
        let watch = serde_json::to_value(watch).unwrap();
        let mut summary = fields(
            &watch,
            &[
                "destination",
                "paused",
                "selected_trial",
                "max_rate_msat_per_kib",
            ],
        );
        summary["pending"] = if watch["pending"].is_object() {
            let mut pending = fields(
                &watch["pending"],
                &["id", "trial", "expires_unix", "max_units"],
            );
            let used = pending["id"]
                .as_str()
                .and_then(|id| buyer.observed_units(id));
            pending["observed_units"] = serde_json::json!(used);
            pending["remaining_units"] = serde_json::json!(used.and_then(|used| {
                pending["max_units"]
                    .as_u64()
                    .map(|max| max.saturating_sub(used))
            }));
            pending
        } else {
            Value::Null
        };
        summary["last_error"] = serde_json::json!(controllers[0].last_error());
        eprintln!("full-roster failure node=0 watch={summary}");
    }
    let eligible = controllers[0].purchases().await.unwrap();
    for purchase in controllers[0]
        .purchase_history()
        .await
        .unwrap()
        .into_iter()
        .take(16)
    {
        let used = buyer.observed_units(&purchase.contract.id);
        let summary = serde_json::json!({
            "destination": identities.iter().position(|peer| *peer.node_addr() == purchase.contract.destination),
            "provider": identities.iter().position(|peer| *peer.node_addr() == purchase.provider),
            "contract": purchase.contract.id,
            "eligible": eligible.iter().any(|current| current.contract.id == purchase.contract.id),
            "max_units": purchase.contract.max_units,
            "observed_units": used,
            "remaining_units": used.map(|used| purchase.contract.max_units.saturating_sub(used)),
            "expires_unix": purchase.contract.expires_unix,
        });
        eprintln!("full-roster failure node=0 purchase={summary}");
    }
    for (node, gate) in gates.iter().enumerate().take(3) {
        eprintln!(
            "full-roster failure node={node} refused={} dropped={}",
            gate.refused.load(Ordering::Relaxed),
            gate.dropped.load(Ordering::Relaxed)
        );
        for command in [
            "show_tree",
            "show_peers",
            "show_sessions",
            "show_cache",
            "show_routing",
        ] {
            let before_ms = start.elapsed().as_millis();
            let value = native_query(root, node, command).await;
            let selected = match command {
                "show_tree" => {
                    let mut selected = fields(
                        &value,
                        &[
                            "root",
                            "parent",
                            "depth",
                            "declaration_sequence",
                            "my_coords",
                        ],
                    );
                    selected["peers"] = value["peers"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .take(4)
                        .map(|peer| {
                            fields(
                                peer,
                                &["node_addr", "root", "depth", "declaration_sequence"],
                            )
                        })
                        .collect();
                    selected
                }
                "show_peers" => value["peers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .take(4)
                    .map(|peer| {
                        let mut selected = fields(
                            peer,
                            &[
                                "node_addr",
                                "connectivity",
                                "link_id",
                                "authenticated_at_ms",
                                "tree_announce_pending",
                                "last_tree_announce_sent_ms",
                            ],
                        );
                        selected["srtt_ms"] = peer["mmp"]["srtt_ms"].clone();
                        selected
                    })
                    .collect(),
                "show_sessions" => value["sessions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|session| {
                        identities[..3].iter().any(|peer| {
                            session["remote_addr"].as_str()
                                == Some(peer.node_addr().to_string().as_str())
                        })
                    })
                    .take(3)
                    .map(|session| {
                        let mut selected = fields(
                            session,
                            &[
                                "remote_addr",
                                "state",
                                "session_start_ms",
                                "resend_count",
                                "current_k_bit",
                                "is_draining",
                            ],
                        );
                        selected["packets_sent"] = session["stats"]["packets_sent"].clone();
                        selected["packets_recv"] = session["stats"]["packets_recv"].clone();
                        selected
                    })
                    .collect(),
                "show_cache" => value["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|entry| {
                        identities[..3].iter().any(|peer| {
                            entry["node_addr"].as_str()
                                == Some(peer.node_addr().to_string().as_str())
                        })
                    })
                    .take(3)
                    .map(|entry| fields(entry, &["node_addr", "coords"]))
                    .collect(),
                "show_routing" => fields(&value, &["forwarding", "error_signals"]),
                _ => unreachable!(),
            };
            eprintln!(
                "full-roster failure node={node} command={command} query_ms=[{before_ms},{}] state={selected}",
                start.elapsed().as_millis()
            );
        }
    }
}
