//! A new, better root must become measured while a short contact is useful.
use super::*;
use futures::FutureExt;
use serde_json::{Value, json};
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::Instant;

#[test]
fn live_udp_new_root_is_measured_between_maintenance_ticks() {
    run(false);
}

#[test]
fn live_udp_new_root_is_measured_during_a_half_second_contact() {
    run(true);
}

fn run(cut: bool) {
    super::super::session::run_large_stack_async_test("first-link-rtt", move || async move {
        for phase_ms in [50, 850] {
            let mut bench = Bench::start(cut).await;
            let result = AssertUnwindSafe(bench.encounter(phase_ms, cut))
                .catch_unwind()
                .await;
            bench.stop().await;
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
    });
}

struct Bench {
    root: tempfile::TempDir,
    peers: Vec<PeerIdentity>,
    addrs: Vec<TransportAddr>,
    started: Vec<Instant>,
    tasks: JoinSet<()>,
    stops: Vec<oneshot::Sender<()>>,
    contact: Arc<Contact>,
}

struct Contact {
    up: AtomicBool,
    cut_us: AtomicU64,
    dropped: AtomicU64,
}

impl Bench {
    async fn start(cut: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        nodes.sort_by_key(|node| *node.node.node_addr());
        let mut bench = Self {
            root,
            peers: nodes
                .iter()
                .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
                .collect(),
            addrs: nodes.iter().map(|node| node.addr.clone()).collect(),
            started: Vec::new(),
            tasks: JoinSet::new(),
            stops: Vec::new(),
            contact: Arc::new(Contact {
                up: AtomicBool::new(true),
                cut_us: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
        };
        for (index, test) in nodes.into_iter().enumerate() {
            let TestNode {
                mut node,
                mut packet_rx,
                tun_outbound_tx,
                ..
            } = test;
            // Use the ordinary RX loop and timers; no synthetic tick or RTT seed.
            node.config.node.rate_limit = Config::new().node.rate_limit;
            node.config.node.discovery.lan.enabled = false;
            node.config.node.control.socket_path =
                bench.socket(index).to_string_lossy().into_owned();
            assert_eq!(node.config.node.tick_interval_secs, 1);
            if cut {
                let (tx, rx) = packet_channel(256);
                let contact = bench.contact.clone();
                let remote = match index {
                    0 => Some(bench.addrs[2].clone()),
                    2 => Some(bench.addrs[0].clone()),
                    _ => None,
                };
                // Drop real received datagrams on only the encountered edge.
                bench.tasks.spawn(async move {
                    while let Some(packet) = packet_rx.recv().await {
                        if remote.as_ref() == Some(&packet.remote_addr)
                            && !contact.up.load(Ordering::Relaxed)
                        {
                            contact.dropped.fetch_add(1, Ordering::Relaxed);
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
        for index in 0..3 {
            let until = Instant::now() + Duration::from_secs(2);
            while !bench.socket(index).exists() {
                assert!(Instant::now() < until, "control socket startup");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
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

    async fn connect(&self, from: usize, to: usize) {
        self.request(from, "connect", json!({
            "npub": self.peers[to].npub(), "address": self.addrs[to].to_string(), "transport": "udp"
        })).await;
    }

    async fn state(&self, node: usize, remote: usize) -> Value {
        // Read the tree first: an adoption observed here must have an RTT by
        // the later peer read. The inverse order can straddle first-RTT adoption.
        let tree = self.request(node, "show_tree", Value::Null).await;
        let peers = self.request(node, "show_peers", Value::Null).await;
        let address = self.peers[remote].node_addr().to_string();
        let peer = peers["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["node_addr"] == address);
        let declaration = tree["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["node_addr"] == address);
        json!({
            "link": peer.map(|peer| &peer["link_id"]),
            "authenticated_at_ms": peer.map(|peer| &peer["authenticated_at_ms"]),
            "srtt_ms": peer.map(|peer| &peer["mmp"]["srtt_ms"]),
            "remote_root": declaration.map(|peer| &peer["root"]),
            "root": tree["root"], "parent": tree["parent"],
        })
    }

    async fn encounter(&mut self, phase_ms: u64, cut: bool) {
        self.connect(2, 1).await;
        let old_root = self.peers[1].node_addr().to_string();
        let until = Instant::now() + Duration::from_secs(10);
        let original = loop {
            let state = self.state(2, 1).await;
            if state["root"] == old_root && state["srtt_ms"].as_f64().is_some_and(|v| v > 0.0) {
                break state;
            }
            assert!(Instant::now() < until, "measured original parent: {state}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(original["parent"], old_root);
        // Vary the nominal phase against RX-loop startup. The loop can reset
        // its maintenance timer after an overrun; this is not a tick observation.
        let next_second = self.started[2].elapsed().as_secs() + 1;
        let scheduled =
            self.started[2] + Duration::from_secs(next_second) + Duration::from_millis(phase_ms);
        tokio::time::sleep_until(scheduled).await;
        let start = Instant::now();
        let overshoot = start.duration_since(scheduled);
        assert!(
            overshoot < Duration::from_millis(50),
            "encounter driver was late: {overshoot:?}"
        );
        eprintln!(
            "first link RTT nominal_phase_ms={phase_ms} actual_startup_phase_ms={} overshoot_us={}",
            start.duration_since(self.started[2]).as_millis() % 1000,
            overshoot.as_micros()
        );
        if cut {
            let contact = self.contact.clone();
            self.tasks.spawn(async move {
                tokio::time::sleep_until(start + Duration::from_millis(500)).await;
                contact.up.store(false, Ordering::Relaxed);
                contact
                    .cut_us
                    .store(start.elapsed().as_micros() as u64, Ordering::Relaxed);
            });
        }
        self.connect(2, 0).await;
        let new_root = self.peers[0].node_addr().to_string();
        let mut previous = Value::Null;
        let mut previous_start = 0;
        let mut saw_announcement = false;
        let until = start + Duration::from_secs(6);
        let adopted = loop {
            let before = start.elapsed().as_micros() as u64;
            let state = self.state(2, 0).await;
            let after = start.elapsed().as_micros() as u64;
            if state != previous {
                eprintln!(
                    "first link RTT {}",
                    json!({"phase_ms": phase_ms, "cut": cut, "change_bracket_us": [previous_start, after], "query_us": [before, after], "state": state})
                );
                previous = state.clone();
            }
            previous_start = before;
            saw_announcement |= state["remote_root"] == new_root;
            if state["srtt_ms"].is_null() {
                assert_eq!(
                    state["root"], old_root,
                    "unmeasured neighbor bypassed a measured parent"
                );
            }
            if state["root"] == new_root {
                assert!(state["srtt_ms"].as_f64().is_some_and(|v| v > 0.0));
                assert!(saw_announcement);
                break start.elapsed();
            }
            assert!(
                Instant::now() < until,
                "new root never became eligible: {state}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let retained = self.state(2, 1).await;
        assert_eq!(retained["link"], original["link"]);
        assert_eq!(
            retained["authenticated_at_ms"],
            original["authenticated_at_ms"]
        );
        eprintln!("first link RTT phase={phase_ms} cut={cut} adopted={adopted:?}");
        assert!(
            adopted < Duration::from_millis(750),
            "new root waited for coarse maintenance: {adopted:?}"
        );
        if cut {
            tokio::time::sleep_until(start + Duration::from_millis(1500)).await;
            let cut_us = self.contact.cut_us.load(Ordering::Relaxed);
            assert!(
                (450_000..600_000).contains(&cut_us),
                "actual contact duration {cut_us}us"
            );
            assert!(
                adopted.as_micros() < u128::from(cut_us),
                "adoption after contact ended"
            );
            assert!(
                self.contact.dropped.load(Ordering::Relaxed) > 0,
                "carrier cut must discard real traffic"
            );
            let retained = self.state(2, 1).await;
            assert_eq!(retained["link"], original["link"]);
            assert!(retained["srtt_ms"].as_f64().is_some_and(|v| v > 0.0));
            eprintln!(
                "first link RTT contact phase={phase_ms} duration_us={cut_us} dropped={}",
                self.contact.dropped.load(Ordering::Relaxed)
            );
        }
    }

    async fn stop(&mut self) {
        for stop in self.stops.drain(..) {
            let _ = stop.send(());
        }
        while let Some(result) = self.tasks.join_next().await {
            result.unwrap();
        }
    }
}
