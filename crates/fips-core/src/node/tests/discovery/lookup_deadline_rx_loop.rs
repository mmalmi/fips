//! Real lookup retries must not wait for the next coarse maintenance tick.
//!
//! No manual lookup maintenance, synthetic timestamps, or changed retry limits.
use super::*;
use crate::node::NodeEndpointControlCommand;
use crate::node::tests::spanning_tree::{TestNode, make_test_node};
use futures::FutureExt;
use serde_json::{Value, json};
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;

#[test]
fn native_lookup_retry_just_after_tick_uses_its_recorded_deadline() {
    run(50);
}

#[test]
fn native_lookup_retry_just_before_tick_uses_its_recorded_deadline() {
    run(850);
}

fn run(phase_ms: u64) {
    super::super::session::run_large_stack_async_test("lookup-deadline", move || async move {
        let mut bench = Bench::start().await;
        let result = AssertUnwindSafe(bench.exercise(phase_ms))
            .catch_unwind()
            .await;
        bench.stop().await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

struct Bench {
    root: tempfile::TempDir,
    peers: Vec<PeerIdentity>,
    addrs: Vec<TransportAddr>,
    started: Vec<Instant>,
    controls: Vec<mpsc::Sender<NodeEndpointControlCommand>>,
    tasks: JoinSet<()>,
    stops: Vec<oneshot::Sender<()>>,
    drop_source_inbound: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
}

impl Bench {
    async fn start() -> Self {
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        // Source 0 is the genuine root, relay 1 its child, target 2 the leaf.
        // Source's ancestry therefore cannot itself supply target coordinates.
        nodes.sort_by_key(|node| *node.node.node_addr());
        let mut bench = Self {
            root: tempfile::tempdir().unwrap(),
            peers: nodes
                .iter()
                .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
                .collect(),
            addrs: nodes.iter().map(|node| node.addr.clone()).collect(),
            started: Vec::new(),
            controls: Vec::new(),
            tasks: JoinSet::new(),
            stops: Vec::new(),
            drop_source_inbound: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        for (index, test) in nodes.into_iter().enumerate() {
            let TestNode {
                mut node,
                mut packet_rx,
                tun_outbound_tx,
                ..
            } = test;
            node.config.node.rate_limit = Config::new().node.rate_limit;
            node.config.node.discovery.lan.enabled = false;
            node.config.node.control.socket_path =
                bench.socket(index).to_string_lossy().into_owned();
            assert_eq!(node.config.node.tick_interval_secs, 1);
            assert_eq!(
                node.config.node.discovery.attempt_timeouts_secs,
                [1, 2, 4, 8]
            );
            assert_eq!(node.config.node.discovery.forward_min_interval_secs, 2);
            let (control_tx, control_rx) = mpsc::channel(8);
            node.endpoint_control_rx = Some(control_rx);
            bench.controls.push(control_tx);

            if index == 0 {
                let (tx, rx) = packet_channel(256);
                let drop_inbound = bench.drop_source_inbound.clone();
                let dropped = bench.dropped.clone();
                let relay_addr = bench.addrs[1].clone();
                // Withhold real encrypted return traffic, without inspecting or
                // changing Noise state. Outgoing requests continue normally.
                bench.tasks.spawn(async move {
                    while let Some(packet) = packet_rx.recv().await {
                        if packet.remote_addr == relay_addr && drop_inbound.load(Ordering::Acquire)
                        {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        } else if tx.send(packet).is_err() {
                            break;
                        }
                    }
                });
                node.packet_rx = Some(rx);
            } else {
                node.packet_rx = Some(packet_rx);
            }
            node.state = NodeState::Running;
            let (stop, mut stopped) = oneshot::channel();
            bench.stops.push(stop);
            let (ready, started) = oneshot::channel();
            bench.tasks.spawn(async move {
                let _tun_guard = tun_outbound_tx;
                ready.send(Instant::now()).unwrap();
                tokio::select! {
                    result = node.run_rx_loop() => panic!("RX loop ended: {result:?}"),
                    _ = &mut stopped => {}
                }
                node.stop().await.unwrap();
            });
            bench.started.push(started.await.unwrap());
        }
        bench
    }

    fn socket(&self, node: usize) -> std::path::PathBuf {
        self.root.path().join(format!("{node}.sock"))
    }

    async fn request(&self, node: usize, command: &str, params: Value) -> Value {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut socket = UnixStream::connect(self.socket(node)).await.unwrap();
            let mut data =
                serde_json::to_vec(&json!({"command": command, "params": params})).unwrap();
            data.push(b'\n');
            socket.write_all(&data).await.unwrap();
            let mut line = String::new();
            BufReader::new(socket).read_line(&mut line).await.unwrap();
            let reply: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(reply["status"], "ok", "{reply}");
            reply["data"].clone()
        })
        .await
        .expect("bounded control response")
    }

    async fn routing(&self, node: usize) -> Value {
        self.request(node, "show_routing", Value::Null).await
    }

    fn pending<'a>(&self, routing: &'a Value) -> Option<&'a Value> {
        let target = self.peers[2].node_addr().to_string();
        routing["pending_lookups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|lookup| lookup["target"] == target)
    }

    async fn owners(&self) -> Vec<Value> {
        let mut owners = Vec::new();
        for (node, remote) in [(0, 1), (1, 0), (1, 2), (2, 1)] {
            let state = self.request(node, "show_peers", Value::Null).await;
            let peer = state["peers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|peer| peer["node_addr"] == self.peers[remote].node_addr().to_string())
                .expect("authenticated chain remains connected");
            assert!(peer["our_session_index"].is_string());
            owners.push(json!([
                peer["link_id"],
                peer["authenticated_at_ms"],
                peer["our_session_index"],
                peer["current_k_bit"],
            ]));
        }
        owners
    }

    async fn resolve(&self) -> Option<PeerIdentity> {
        let (response_tx, response_rx) = oneshot::channel();
        self.controls[0]
            .send(NodeEndpointControlCommand::ResolveNextHop {
                destination: self.peers[2],
                previous_hop: None,
                response_tx,
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), response_rx)
            .await
            .expect("bounded route query")
            .unwrap()
    }

    async fn exercise(&self, phase_ms: u64) {
        let startup_deadline = Instant::now() + Duration::from_secs(3);
        while (0..3).any(|node| !self.socket(node).exists()) {
            assert!(Instant::now() < startup_deadline, "control sockets start");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for (from, to) in [(1, 0), (2, 1)] {
            self.request(
                from,
                "connect",
                json!({
                    "npub": self.peers[to].npub(),
                    "address": self.addrs[to].to_string(), "transport": "udp"
                }),
            )
            .await;
        }
        let setup_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut converged = true;
            for node in 0..3 {
                let tree = self.request(node, "show_tree", Value::Null).await;
                converged &= tree["root"] == self.peers[0].node_addr().to_string();
            }
            let bloom = self.request(0, "show_bloom", Value::Null).await;
            let subtree_advertised = bloom["peer_filters"].as_array().unwrap().iter().any(|p| {
                p["peer"] == self.peers[1].node_addr().to_string()
                    && p["has_filter"] == true
                    && p["estimated_count"].as_f64().is_some_and(|n| n >= 1.5)
            });
            if converged && subtree_advertised {
                break;
            }
            assert!(
                Instant::now() < setup_deadline,
                "native tree/Bloom convergence: {bloom}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let owners = self.owners().await;
        let source_before = self.routing(0).await;
        let relay_before = self.routing(1).await;
        assert!(self.pending(&source_before).is_none());
        assert_eq!(source_before["coord_cache_entries"], 0);
        let initiated = source_before["discovery"]["req_initiated"]
            .as_u64()
            .unwrap();
        let relay_received = relay_before["discovery"]["req_received"].as_u64().unwrap();
        let forwarded_responses = relay_before["discovery"]["resp_forwarded"]
            .as_u64()
            .unwrap();

        // As in first_rtt.rs, startup phase is nominal: maintenance can reset
        // after an overrun. The acceptance check uses the actual recorded due
        // time, never an assumed tick timestamp or fabricated lookup entry.
        let next_second = self.started[0].elapsed().as_secs() + 1;
        let scheduled =
            self.started[0] + Duration::from_secs(next_second) + Duration::from_millis(phase_ms);
        tokio::time::sleep_until(scheduled).await;
        assert!(
            scheduled.elapsed() < Duration::from_millis(50),
            "late phase driver"
        );
        self.drop_source_inbound.store(true, Ordering::Release);
        assert!(
            self.resolve().await.is_none(),
            "first query needs real discovery"
        );
        let original = self.routing(0).await;
        let pending = self.pending(&original).expect("first lookup was admitted");
        assert_eq!(pending["attempt"], 1);
        let initiated_ms = pending["initiated_ms"].as_u64().unwrap();
        let last_sent_ms = pending["last_sent_ms"].as_u64().unwrap();
        let due_ms = last_sent_ms + 1_000;
        assert_eq!(original["discovery"]["req_initiated"], initiated + 1);

        // A forwarded response, zero accepted responses, and a closed receive
        // gate establish actual loss, rather than an unreachable-target timer.
        let first_response_deadline = Instant::now() + Duration::from_millis(500);
        loop {
            let relay = self.routing(1).await;
            if relay["discovery"]["resp_forwarded"].as_u64().unwrap() > forwarded_responses {
                assert_eq!(relay["discovery"]["req_received"], relay_received + 1);
                break;
            }
            assert!(
                Instant::now() < first_response_deadline,
                "first real response: {relay}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let retry_deadline = Instant::now() + Duration::from_secs(3);
        let observed_retry_ms = loop {
            let relay = self.routing(1).await;
            let observed_ms = Node::now_ms();
            let received = relay["discovery"]["req_received"].as_u64().unwrap();
            if received == relay_received + 2 {
                break observed_ms;
            }
            assert_eq!(received, relay_received + 1, "no extra discovery cycle");
            assert!(
                Instant::now() < retry_deadline,
                "retry must reach live relay: {relay}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let retried = self.routing(0).await;
        let pending = self.pending(&retried).unwrap();
        assert_eq!(pending["attempt"], 2);
        assert_eq!(pending["initiated_ms"], initiated_ms);
        assert!(pending["last_sent_ms"].as_u64().unwrap() >= due_ms);
        assert_eq!(
            retried["discovery"]["resp_accepted"],
            source_before["discovery"]["resp_accepted"]
        );
        assert!(self.dropped.load(Ordering::Relaxed) > 0);
        self.drop_source_inbound.store(false, Ordering::Release);

        // Default 2s transit forwarding protection can suppress the 1s retry.
        // The next ordinary allowed response must finish without manual retry,
        // reopening the lookup, or changing its authenticated FMP owners.
        let completion_deadline = Instant::now() + Duration::from_secs(6);
        let finished = loop {
            let state = self.routing(0).await;
            if self.pending(&state).is_none() {
                break state;
            }
            assert!(
                Instant::now() < completion_deadline,
                "normal response recovery: {state}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(
            finished["discovery"]["resp_accepted"].as_u64().unwrap(),
            source_before["discovery"]["resp_accepted"]
                .as_u64()
                .unwrap()
                + 1
        );
        assert_eq!(
            finished["discovery"]["resp_timed_out"],
            source_before["discovery"]["resp_timed_out"]
        );
        assert_eq!(finished["coord_cache_entries"], 1);
        assert_eq!(
            self.resolve().await.map(|peer| *peer.node_addr()),
            Some(*self.peers[1].node_addr())
        );
        assert_eq!(
            self.owners().await,
            owners,
            "lookup retry preserves real FMP owners"
        );
        eprintln!(
            "native lookup deadline {}",
            json!({
                "nominal_phase_ms": phase_ms,
                "initiated_ms": initiated_ms,
                "first_last_sent_ms": last_sent_ms,
                "retry_due_ms": due_ms,
                "retry_observed_by_ms": observed_retry_ms,
                "lateness_upper_ms": observed_retry_ms.saturating_sub(due_ms),
                "dropped_return_frames": self.dropped.load(Ordering::Relaxed),
                "final_attempts": finished["discovery"]["req_initiated"],
            })
        );
        // Includes query/loopback latency; no millisecond-level scheduler claim.
        // On the coarse baseline, the +50ms case should be about 950ms late.
        assert!(
            observed_retry_ms.saturating_sub(due_ms) <= 350,
            "real lookup retry waited for coarse maintenance: due={due_ms}, observed={observed_retry_ms}"
        );
    }

    async fn stop(&mut self) {
        self.drop_source_inbound.store(false, Ordering::Release);
        for stop in self.stops.drain(..) {
            let _ = stop.send(());
        }
        while let Some(result) = self.tasks.join_next().await {
            result.unwrap();
        }
    }
}
