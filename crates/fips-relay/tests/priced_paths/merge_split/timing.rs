//! Bounded passive observations; query spans are not exact protocol event times.
use super::*;
use serde_json::json;
use std::path::PathBuf;
use tokio::{sync::oneshot, task::JoinSet};

pub(super) struct Timing {
    pub(super) origin: Instant,
    stop: oneshot::Sender<()>,
    task: JoinSet<Trace>,
}

struct Probe {
    root: PathBuf,
    peers: Vec<PeerIdentity>,
    controllers: Vec<Arc<Controller>>,
}

#[derive(Default)]
struct Trace {
    last: BTreeMap<(usize, &'static str), (u64, Value)>,
    changes: Vec<Value>,
    rounds: u64,
    max_round_us: u64,
    max_round_gap_us: u64,
    last_round_us: Option<u64>,
}

fn micros(origin: Instant) -> u64 {
    origin.elapsed().as_micros().try_into().unwrap()
}

fn select(value: Option<&Value>, fields: &[&str]) -> Value {
    value.map_or(Value::Null, |value| {
        fields
            .iter()
            .map(|&field| (field.to_owned(), value[field].clone()))
            .collect()
    })
}

impl Trace {
    fn record(&mut self, node: usize, kind: &'static str, span: [u64; 2], state: Value) {
        assert!(span[1] >= span[0]);
        let previous = self.last.insert((node, kind), (span[0], state.clone()));
        if previous.as_ref().is_some_and(|(_, old)| *old == state) {
            return;
        }
        assert!(
            self.changes.len() < 4096,
            "bounded contact timing observations"
        );
        self.changes.push(json!({
            "node": node, "kind": kind, "query_us": span, "state": state,
            // The old value was read somewhere inside the previous query.
            // Its start is a conservative lower bound, not its response time.
            "change_bracket_us": previous.map(|(before, _)| [before, span[1]]),
        }));
    }
}

impl Probe {
    fn address(&self, node: usize) -> String {
        self.peers[node].node_addr().to_string()
    }

    fn node_index(&self, address: &Value) -> Option<usize> {
        if address.is_null() {
            return None;
        }
        Some(
            (0..self.peers.len())
                .find(|&i| address.as_str() == Some(self.address(i).as_str()))
                .unwrap(),
        )
    }

    async fn native(&self, node: usize, command: &str, origin: Instant) -> ([u64; 2], Value) {
        let before = micros(origin);
        let value = native_query(&self.root, node, command).await;
        ([before, micros(origin)], value)
    }

    async fn sample(&self, trace: &mut Trace, origin: Instant) {
        let started = micros(origin);
        if let Some(previous) = trace.last_round_us.replace(started) {
            trace.max_round_gap_us = trace.max_round_gap_us.max(started - previous);
        }
        for (node, remote) in [(2, 3), (3, 2), (0, 1), (1, 2), (4, 3), (5, 4)] {
            let (span, peers) = self.native(node, "show_peers", origin).await;
            let peer = peers["peers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|peer| peer["node_addr"] == self.address(remote));
            let mut state = select(peer, &["connectivity", "link_id", "authenticated_at_ms"]);
            if let Some(peer) = peer {
                state["srtt_ms"] = peer["mmp"]["srtt_ms"].clone();
            }
            let kind = if matches!(node, 2 | 3) {
                "bridge"
            } else {
                "neighbor"
            };
            trace.record(node, kind, span, state);
            let announcements: Vec<_> = peers["peers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|peer| {
                    json!({"peer": self.node_index(&peer["node_addr"]),
                    "pending": peer["tree_announce_pending"],
                    "last_sent_ms": peer["last_tree_announce_sent_ms"]})
                })
                .collect();
            trace.record(node, "announcements", span, json!(announcements));

            let (span, tree) = self.native(node, "show_tree", origin).await;
            let remote_tree = tree["peers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|peer| peer["node_addr"] == self.address(remote));
            trace.record(
                node,
                "tree",
                span,
                json!({
                    "root": self.node_index(&tree["root"]),
                    "parent": self.node_index(&tree["parent"]),
                    "depth": tree["depth"], "sequence": tree["declaration_sequence"],
                    "coords": tree["my_coords"].as_array().unwrap().iter()
                        .map(|address| self.node_index(address)).collect::<Vec<_>>(),
                    "remote_root": remote_tree.and_then(|peer| self.node_index(&peer["root"])),
                    "remote_depth": remote_tree.map(|peer| &peer["depth"]),
                    "remote_sequence": remote_tree.map(|peer| &peer["declaration_sequence"]),
                }),
            );
            let (span, routing) = self.native(node, "show_routing", origin).await;
            trace.record(
                node,
                "forwarding",
                span,
                json!({
                    "forwarding": routing["forwarding"], "errors": routing["error_signals"],
                }),
            );
            let (span, cache) = self.native(node, "show_cache", origin).await;
            let mut entries: Vec<_> = cache["entries"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|entry| {
                    let destination = self.node_index(&entry["node_addr"])?;
                    matches!(destination, 0 | 5).then(|| {
                        json!({
                            "destination": destination,
                            "coords": entry["coords"].as_array().unwrap().iter()
                                .map(|address| self.node_index(address)).collect::<Vec<_>>(),
                        })
                    })
                })
                .collect();
            entries.sort_by_key(|entry| entry["destination"].as_u64());
            trace.record(node, "endpoint_coords", span, json!(entries));
        }
        for (node, remote) in [(0, 5), (5, 0)] {
            let (span, sessions) = self.native(node, "show_sessions", origin).await;
            let session = sessions["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|session| session["remote_addr"] == self.address(remote));
            let mut state = select(
                session,
                &[
                    "state",
                    "session_start_ms",
                    "resend_count",
                    "current_k_bit",
                    "is_draining",
                ],
            );
            if let Some(session) = session {
                state["packets_sent"] = session["stats"]["packets_sent"].clone();
                state["packets_recv"] = session["stats"]["packets_recv"].clone();
            }
            trace.record(node, "session", span, state);

            let before = micros(origin);
            let watch = self.controllers[node]
                .watched_routes()
                .await
                .unwrap()
                .into_iter()
                .find(|watch| watch.destination == self.peers[remote].npub())
                .unwrap();
            let watch = serde_json::to_value(watch).unwrap();
            trace.record(
                node,
                "watch",
                [before, micros(origin)],
                json!({
                    "paused": watch["paused"], "selected_trial": watch["selected_trial"],
                    "pending": select(watch["pending"].as_object().map(|_| &watch["pending"]),
                        &["id", "trial", "expires_unix", "max_units"]),
                }),
            );

            let before = micros(origin);
            let mut purchases = self.controllers[node]
                .purchases()
                .await
                .unwrap()
                .into_iter()
                .filter(|purchase| purchase.contract.destination == *self.peers[remote].node_addr())
                .map(|purchase| {
                    json!({"contract": purchase.contract.id,
                    "channel": purchase.channel.id, "expires_unix": purchase.contract.expires_unix,
                    "max_units": purchase.contract.max_units})
                })
                .collect::<Vec<_>>();
            purchases.sort_by(|a, b| a["contract"].as_str().cmp(&b["contract"].as_str()));
            // Eligible purchases are not a claim about the currently used path.
            trace.record(
                node,
                "eligible_purchases",
                [before, micros(origin)],
                json!(purchases),
            );
        }
        trace.rounds += 1;
        assert!(trace.rounds <= 2048, "bounded contact timing rounds");
        trace.max_round_us = trace.max_round_us.max(micros(origin) - started);
    }
}

impl Timing {
    pub(super) async fn start(bench: &Bench) -> Self {
        let probe = Probe {
            root: bench.root.path().into(),
            peers: bench.peers.clone(),
            controllers: bench.controllers.clone(),
        };
        let origin = Instant::now();
        let mut trace = Trace::default();
        // Establish the disconnected baseline before the first returning contact.
        probe.sample(&mut trace, origin).await;
        for node in [2, 3] {
            assert!(trace.last[&(node, "bridge")].1.is_null());
        }
        let (stop, mut stopped) = oneshot::channel();
        let mut task = JoinSet::new();
        task.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = interval.tick() => probe.sample(&mut trace, origin).await,
                }
            }
            probe.sample(&mut trace, origin).await;
            trace
        });
        Self { origin, stop, task }
    }

    pub(super) fn mark(&self, name: &str) {
        eprintln!(
            "brief timing marker {}",
            json!({"name": name, "observed_us": micros(self.origin)})
        );
    }

    pub(super) async fn finish(mut self) {
        let _ = self.stop.send(());
        let trace = self.task.join_next().await.unwrap().unwrap();
        for node in [2, 3] {
            let bridge = &trace.last[&(node, "bridge")].1;
            assert_eq!(bridge["connectivity"], "connected");
            assert!(bridge["srtt_ms"].as_f64().is_some_and(|rtt| rtt > 0.0));
        }
        assert_eq!(
            trace.last[&(2, "tree")].1["root"],
            trace.last[&(3, "tree")].1["root"]
        );
        for node in [0, 5] {
            assert_eq!(trace.last[&(node, "session")].1["state"], "established");
            assert!(
                !trace.last[&(node, "eligible_purchases")]
                    .1
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
        eprintln!(
            "brief timing summary {}",
            json!({"rounds": trace.rounds,
            "max_round_us": trace.max_round_us, "max_round_gap_us": trace.max_round_gap_us,
            "changes": trace.changes.len()})
        );
        for change in trace.changes {
            eprintln!("brief timing observation {change}");
        }
    }
}
