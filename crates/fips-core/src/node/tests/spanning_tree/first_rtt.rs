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

mod cold_contact;
mod repair_state;

type PacketObserver = Box<dyn FnMut(&ReceivedPacket, bool) + Send>;

#[test]
fn live_udp_new_root_is_measured_between_maintenance_ticks() {
    run(Case::Measured);
}

#[test]
fn live_udp_new_root_is_measured_during_a_half_second_contact() {
    run(Case::BriefMeasured);
}

#[test]
fn live_udp_neighbors_learn_both_routes_during_a_short_contact() {
    run(Case::Bidirectional);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Measured,
    BriefMeasured,
    Bidirectional,
}

impl Case {
    fn contact_ms(self) -> Option<u64> {
        match self {
            Self::Measured => None,
            Self::BriefMeasured => Some(500),
            Self::Bidirectional => Some(750),
        }
    }
}

fn run(case: Case) {
    super::super::session::run_large_stack_async_test("first-link-rtt", move || async move {
        for phase_ms in [50, 850] {
            let mut bench = Bench::start(case.contact_ms().is_some()).await;
            let result = AssertUnwindSafe(bench.encounter(phase_ms, case))
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
    outbound: Vec<crate::upper::tun::TunOutboundTx>,
    contact: Arc<Contact>,
}

struct Contact {
    up: AtomicBool,
    cut_us: AtomicU64,
    dropped: AtomicU64,
}

impl Bench {
    async fn start(cut: bool) -> Self {
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        nodes.sort_by_key(|node| *node.node.node_addr());
        Self::start_nodes(nodes, cut, true, Vec::new()).await
    }

    async fn start_nodes(
        nodes: Vec<TestNode>,
        cut: bool,
        initially_up: bool,
        observers: Vec<Option<PacketObserver>>,
    ) -> Self {
        let mut bench = Self {
            root: tempfile::tempdir().unwrap(),
            peers: nodes
                .iter()
                .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
                .collect(),
            addrs: nodes.iter().map(|node| node.addr.clone()).collect(),
            started: Vec::new(),
            tasks: JoinSet::new(),
            stops: Vec::new(),
            outbound: Vec::new(),
            contact: Arc::new(Contact {
                up: AtomicBool::new(initially_up),
                cut_us: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
        };
        let mut observers = observers.into_iter();
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
            assert_eq!(node.config.node.tree.announce_min_interval_ms, 500);
            if cut {
                let (tx, rx) = packet_channel(256);
                let contact = bench.contact.clone();
                let mut observer = observers.next().flatten();
                let remote = match index {
                    0 => Some(bench.addrs[2].clone()),
                    2 => Some(bench.addrs[0].clone()),
                    _ => None,
                };
                // Drop real received datagrams on only the encountered edge.
                bench.tasks.spawn(async move {
                    while let Some(packet) = packet_rx.recv().await {
                        let encountered = remote.as_ref() == Some(&packet.remote_addr);
                        let delivered = !encountered || contact.up.load(Ordering::Relaxed);
                        if encountered && let Some(observer) = &mut observer {
                            observer(&packet, delivered);
                        }
                        if !delivered {
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
            bench.outbound.push(tun_outbound_tx.clone());
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
        let tree = self.tree_snapshot(node, remote).await;
        self.with_peer_metadata(node, remote, tree).await
    }

    async fn tree_snapshot(&self, node: usize, remote: usize) -> Value {
        let tree = self.request(node, "show_tree", Value::Null).await;
        let address = self.peers[remote].node_addr().to_string();
        let declaration = tree["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["node_addr"] == address);
        json!({
            "remote_root": declaration.map(|peer| &peer["root"]),
            "remote_parent": declaration.map(|peer| &peer["parent"]),
            "remote_sequence": declaration.map(|peer| &peer["declaration_sequence"]),
            "remote_coords": declaration.map(|peer| &peer["coords"]),
            "root": tree["root"], "parent": tree["parent"],
            "sequence": tree["declaration_sequence"], "coords": tree["my_coords"],
            "rate_limited": tree["stats"]["rate_limited"],
        })
    }

    async fn with_peer_metadata(&self, node: usize, remote: usize, mut tree: Value) -> Value {
        let peers = self.request(node, "show_peers", Value::Null).await;
        let address = self.peers[remote].node_addr().to_string();
        let peer = peers["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["node_addr"] == address);
        for (field, value) in [
            ("link", peer.map(|peer| &peer["link_id"])),
            (
                "authenticated_at_ms",
                peer.map(|peer| &peer["authenticated_at_ms"]),
            ),
            ("index", peer.map(|peer| &peer["our_session_index"])),
            ("srtt_ms", peer.map(|peer| &peer["mmp"]["srtt_ms"])),
            (
                "announce_pending",
                peer.map(|peer| &peer["tree_announce_pending"]),
            ),
            (
                "last_announce_ms",
                peer.map(|peer| &peer["last_tree_announce_sent_ms"]),
            ),
        ] {
            tree[field] = value.cloned().unwrap_or(Value::Null);
        }
        tree
    }

    async fn encounter(&mut self, phase_ms: u64, case: Case) {
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
        if let Some(contact_ms) = case.contact_ms() {
            let contact = self.contact.clone();
            self.tasks.spawn(async move {
                tokio::time::sleep_until(start + Duration::from_millis(contact_ms)).await;
                contact
                    .cut_us
                    .store(start.elapsed().as_micros() as u64, Ordering::Relaxed);
                contact.up.store(false, Ordering::Release);
            });
        }
        self.connect(2, 0).await;
        let new_root = self.peers[0].node_addr().to_string();
        let mut previous = Value::Null;
        let mut previous_start = 0;
        let mut saw_announcement = false;
        let mut saw_deferred_update = false;
        let mut last_announces = [None; 2];
        let mut link_epochs = [const { None }; 2];
        let mut adopted = None;
        let until = start + Duration::from_secs(6);
        let ready = loop {
            let before = start.elapsed().as_micros() as u64;
            let state = self.state(2, 0).await;
            let other = if case == Case::Bidirectional {
                Some(self.state(0, 2).await)
            } else {
                None
            };
            let after = start.elapsed().as_micros() as u64;
            let observation = json!({"child": state, "parent": other});
            if observation != previous {
                eprintln!(
                    "first link RTT {}",
                    json!({"phase_ms": phase_ms, "case": format!("{case:?}"), "change_bracket_us": [previous_start, after], "query_us": [before, after], "state": observation})
                );
                previous = observation;
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
                adopted.get_or_insert(start.elapsed());
                if other.is_none() {
                    break start.elapsed();
                }
            }
            if let Some(other) = &other {
                for (index, current) in [&state, other].into_iter().enumerate() {
                    if let Some(sent) = current["last_announce_ms"]
                        .as_u64()
                        .filter(|&sent| sent > 0)
                    {
                        if let Some(previous) = last_announces[index] {
                            assert!(
                                sent == previous || sent >= previous + 500,
                                "per-peer announcement rate limit"
                            );
                        }
                        last_announces[index] = Some(sent);
                    }
                    if !current["link"].is_null() {
                        let epoch = json!([current["link"], current["authenticated_at_ms"]]);
                        assert_eq!(
                            *link_epochs[index].get_or_insert(epoch.clone()),
                            epoch,
                            "contact changed authenticated link"
                        );
                    }
                }
                saw_deferred_update |= state["root"] == new_root
                    && state["announce_pending"] == true
                    && state["rate_limited"].as_u64().unwrap()
                        > original["rate_limited"].as_u64().unwrap()
                    && !Self::learned(other, &state);
                if adopted.is_some() && Self::learned(other, &state) && Self::learned(&state, other)
                {
                    break start.elapsed();
                }
                if !self.contact.up.load(Ordering::Acquire) {
                    let cut_us = self.checked_cut_us(case.contact_ms().unwrap());
                    assert!(
                        saw_deferred_update,
                        "missing rate-limited update premise: {state}; {other}"
                    );
                    panic!(
                        "contact ended at {cut_us}us before both routes were learned: {state}; {other}"
                    );
                }
            }
            assert!(
                Instant::now() < until,
                "new root never became eligible: {state}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let adopted = adopted.unwrap();
        let retained = self.state(2, 1).await;
        assert_eq!(retained["link"], original["link"]);
        assert_eq!(
            retained["authenticated_at_ms"],
            original["authenticated_at_ms"]
        );
        eprintln!(
            "first link RTT phase={phase_ms} case={case:?} adopted={adopted:?} ready={ready:?}"
        );
        assert!(
            adopted < Duration::from_millis(750),
            "new root waited for coarse maintenance: {adopted:?}"
        );
        if let Some(contact_ms) = case.contact_ms() {
            tokio::time::sleep_until(start + Duration::from_millis(1500)).await;
            let cut_us = self.checked_cut_us(contact_ms);
            assert!(
                ready.as_micros() < u128::from(cut_us),
                "route readiness after contact ended"
            );
            if case == Case::Bidirectional {
                assert!(
                    saw_deferred_update,
                    "exercise must defer an updated child declaration"
                );
            }
            self.assert_cut_discards_traffic().await;
            let retained = self.state(2, 1).await;
            assert_eq!(retained["link"], original["link"]);
            assert!(retained["srtt_ms"].as_f64().is_some_and(|v| v > 0.0));
            eprintln!(
                "first link RTT contact phase={phase_ms} duration_us={cut_us} dropped={}",
                self.contact.dropped.load(Ordering::Relaxed)
            );
        }
    }

    async fn assert_cut_discards_traffic(&self) {
        // A quiet connected peer need not emit maintenance traffic within this
        // observation window. Send through the real RX loop after the cut to
        // exercise the carrier without changing the contact or readiness bounds.
        let before = self.contact.dropped.load(Ordering::Relaxed);
        let packet = super::super::session::build_ipv6_packet(
            &crate::FipsAddress::from_node_addr(self.peers[2].node_addr()),
            &crate::FipsAddress::from_node_addr(self.peers[0].node_addr()),
            b"traffic after the short contact ended",
        );
        self.outbound[2].try_send(packet).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while self.contact.dropped.load(Ordering::Relaxed) == before {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("carrier cut must discard real traffic");
    }

    fn checked_cut_us(&self, contact_ms: u64) -> u64 {
        let cut_us = self.contact.cut_us.load(Ordering::Relaxed);
        assert!(
            ((contact_ms - 50) * 1000..(contact_ms + 100) * 1000).contains(&cut_us),
            "actual contact duration {cut_us}us"
        );
        cut_us
    }

    fn learned(observer: &Value, remote: &Value) -> bool {
        observer["remote_root"] == remote["root"]
            && observer["remote_parent"] == remote["parent"]
            && observer["remote_sequence"] == remote["sequence"]
            && observer["remote_coords"] == remote["coords"]
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
