//! Distinguish declaration content from RX dispatch timing in a 400 ms contact.
use super::*;
use crate::node::wire::{CommonPrefix, PHASE_ESTABLISHED};
use crate::protocol::LinkMessageType;
use std::sync::Mutex;

mod observation;
use observation::Sample;

#[test]
fn live_udp_authenticated_cold_contact_learns_current_declarations_in_400ms() {
    super::super::super::session::run_large_stack_async_test("cold-tree-contact", || async {
        let mut outcomes = Vec::new();
        for phase_ms in [50, 850] {
            let (nodes, trace, observers) = prepared_nodes().await;
            let mut bench = Bench::start_nodes(nodes, true, false, observers).await;
            let result = AssertUnwindSafe(observe_contact(&mut bench, &trace, phase_ms))
                .catch_unwind()
                .await;
            let omitted = {
                let trace = trace.lock().unwrap();
                eprintln!(
                    "cold tree contact {}",
                    json!({
                        "phase_ms": phase_ms, "frames": trace.frames, "states": trace.states,
                        "omitted": trace.omitted,
                    })
                );
                trace.omitted
            };
            bench.stop().await;
            assert_eq!(omitted, 0, "bounded chronology must be complete");
            match result {
                Ok(ready) => outcomes.push((phase_ms, ready)),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        assert!(
            outcomes.iter().all(|(_, ready)| *ready),
            "both signed declarations must be learned during the original 400 ms opening: {outcomes:?}"
        );
    });
}

struct Trace {
    start: Instant,
    frames: Vec<Value>,
    states: Vec<Value>,
    omitted: usize,
}

impl Trace {
    fn frame(&mut self, frame: Value) {
        if self.frames.len() < 128 {
            self.frames.push(frame);
        } else {
            self.omitted += 1;
        }
    }

    fn state(&mut self, state: Value) {
        if self.states.len() < 64 {
            self.states.push(state);
        } else {
            self.omitted += 1;
        }
    }
}

async fn dial(nodes: &mut [TestNode], from: usize, to: usize) {
    let remote = nodes[to].addr.clone();
    let identity = PeerIdentity::from_pubkey_full(nodes[to].node.identity().pubkey_full());
    let source = &mut nodes[from];
    source
        .node
        .initiate_connection(source.transport_id, remote, identity)
        .await
        .unwrap();
}

fn measured(node: &TestNode, peer: &NodeAddr) -> bool {
    node.node
        .dataplane_fmp_link_metrics(peer, std::time::Instant::now())
        .and_then(|metrics| metrics.srtt_ms)
        .is_some_and(|rtt| rtt > 0.0)
}

async fn prepared_nodes() -> (
    Vec<TestNode>,
    Arc<Mutex<Trace>>,
    Vec<Option<PacketObserver>>,
) {
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];
    nodes.sort_by_key(|node| *node.node.node_addr());
    // Handshake setup dispatches only genuine UDP packets through the ordinary
    // handlers. No peer, coordinate, RTT, signed declaration, or deadline is
    // installed by the fixture. All cut/reopen timing uses the real RX loops.
    let setup = AssertUnwindSafe(async {
        for node in &mut nodes {
            node.node.config.node.rate_limit = Config::new().node.rate_limit;
            node.node.config.node.discovery.lan.enabled = false;
            assert_eq!(node.node.config.node.tree.announce_min_interval_ms, 500);
        }
        dial(&mut nodes, 2, 1).await;
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            process_available_packets(&mut nodes).await;
            for node in &mut nodes {
                node.node.check_mmp_reports().await;
                node.node.send_pending_tree_announces().await;
            }
            let root = nodes[1].node.node_addr();
            if nodes[2].node.tree_state().root() == root
                && measured(&nodes[2], root)
                && nodes[1]
                    .node
                    .tree_state()
                    .peer_coords(nodes[2].node.node_addr())
                    .is_some_and(|coords| coords.root_id() == root)
            {
                break;
            }
            assert!(Instant::now() < until, "measured original parent setup");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        dial(&mut nodes, 2, 0).await;
        let until = Instant::now() + Duration::from_secs(2);
        // Stop at the same boundary as the paid brief fixture: both native
        // adjacency owners exist, but the new root is not yet measured/adopted.
        // Queued bootstrap frames are then lost by the physical contact gate.
        'handshake: loop {
            for index in [0, 2] {
                if let Ok(packet) = nodes[index].packet_rx.try_recv() {
                    process_dataplane_packet(&mut nodes[index], packet).await;
                }
                if nodes[0].node.get_peer(nodes[2].node.node_addr()).is_some()
                    && nodes[2].node.get_peer(nodes[0].node.node_addr()).is_some()
                {
                    break 'handshake;
                }
            }
            assert!(Instant::now() < until, "real bridge handshake setup");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(nodes[2].node.tree_state().root(), nodes[1].node.node_addr());
        assert_eq!(nodes[0].node.tree_state().root(), nodes[0].node.node_addr());
        assert!(measured(&nodes[2], nodes[1].node.node_addr()));
        assert!(
            !measured(&nodes[2], nodes[0].node.node_addr()),
            "cut must precede the new root's first RTT sample"
        );
        for (local, remote) in [(0, 2), (2, 0)] {
            let active = nodes[local]
                .node
                .get_peer(nodes[remote].node.node_addr())
                .unwrap();
            let reverse = nodes[remote]
                .node
                .get_peer(nodes[local].node.node_addr())
                .unwrap();
            assert!(active.can_send());
            assert_eq!(active.our_index(), reverse.their_index());
            assert_eq!(active.their_index(), reverse.our_index());
            assert_eq!(
                active.remote_epoch(),
                Some(nodes[remote].node.startup_epoch)
            );
        }
    })
    .catch_unwind()
    .await;
    if let Err(panic) = setup {
        cleanup_nodes(&mut nodes).await;
        std::panic::resume_unwind(panic);
    }
    let trace = Arc::new(Mutex::new(Trace {
        start: Instant::now(),
        frames: Vec::new(),
        states: Vec::new(),
        omitted: 0,
    }));
    let mut observers = Vec::new();
    for (index, remote) in [(0, Some(2)), (1, None), (2, Some(0))] {
        observers
            .push(remote.map(|remote| {
                packet_observer(&nodes[index], &nodes[remote], index, trace.clone())
            }));
    }
    (nodes, trace, observers)
}

fn packet_observer(
    receiver: &TestNode,
    sender: &TestNode,
    receiver_index: usize,
    trace: Arc<Mutex<Trace>>,
) -> PacketObserver {
    let peer = receiver.node.get_peer(sender.node.node_addr()).unwrap();
    let cipher = peer.noise_session().unwrap().recv_cipher_clone().unwrap();
    let pubkey = peer.pubkey();
    // Decrypt a COPY with a read-only cipher clone. Never advance the live
    // replay window/counters, re-encrypt a frame, or expose cipher/key material.
    Box::new(move |packet, delivered| {
        let wire = packet.data.as_slice();
        if CommonPrefix::parse(wire).unwrap().phase != PHASE_ESTABLISHED {
            return;
        }
        let header = crate::dataplane::FmpWireHeader::parse_encrypted(wire).unwrap();
        let offset = usize::from(header.ciphertext_offset());
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
        let mut ciphertext = wire[offset..].to_vec();
        let plaintext = cipher
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(&wire[..offset]),
                &mut ciphertext,
            )
            .unwrap();
        let kind = LinkMessageType::from_byte(plaintext[4]).unwrap();
        if !matches!(
            kind,
            LinkMessageType::TreeAnnounce | LinkMessageType::ReceiverReport
        ) {
            return;
        }
        let declaration = if kind == LinkMessageType::TreeAnnounce {
            let announce = TreeAnnounce::decode(&plaintext[5..]).unwrap();
            announce.declaration.verify(&pubkey).unwrap();
            announce.validate_semantics().unwrap();
            json!({"root": announce.ancestry.root_id().to_string(),
                "parent": announce.declaration.parent_id().to_string(),
                "sequence": announce.declaration.sequence()})
        } else {
            Value::Null
        };
        let mut trace = trace.lock().unwrap();
        let elapsed_us = trace.start.elapsed().as_micros() as u64;
        trace.frame(json!({"received_by": receiver_index, "at_us": elapsed_us,
            "received_ms": packet.timestamp_ms, "observed_ms": Node::now_ms(),
            "delivered": delivered, "kind": format!("{kind:?}"),
            "counter": header.counter(),
            "wire_timestamp_ms": u32::from_le_bytes(plaintext[..4].try_into().unwrap()),
            "declaration": declaration}));
    })
}

fn owner(state: &Value) -> Value {
    assert!(!state["link"].is_null());
    json!([state["link"], state["authenticated_at_ms"], state["index"]])
}

async fn observe_contact(bench: &mut Bench, trace: &Arc<Mutex<Trace>>, phase_ms: u64) -> bool {
    let initial = [bench.state(0, 2).await, bench.state(2, 0).await];
    let original = bench.state(2, 1).await;
    let old_root = bench.peers[1].node_addr().to_string();
    let root = bench.peers[0].node_addr().to_string();
    assert_eq!(initial[1]["root"], old_root);
    assert!(initial[1]["srtt_ms"].is_null());
    assert!(original["srtt_ms"].as_f64().is_some_and(|rtt| rtt > 0.0));
    trace
        .lock()
        .unwrap()
        .state(json!({"cut": initial, "original": original}));
    // As in first_rtt's existing cases, vary the nominal maintenance phase.
    // Timers run normally throughout the down interval; no state is reset.
    let scheduled = bench.started[2] + Duration::from_secs(1) + Duration::from_millis(phase_ms);
    tokio::time::sleep_until(scheduled).await;
    let open = Instant::now();
    let deadline = open + Duration::from_millis(400);
    let open_ms = Node::now_ms();
    assert!(open.duration_since(scheduled) < Duration::from_millis(50));
    bench.contact.up.store(true, Ordering::Release);
    let contact = bench.contact.clone();
    bench.tasks.spawn(async move {
        tokio::time::sleep_until(deadline).await;
        contact
            .cut_us
            .store(open.elapsed().as_micros() as u64, Ordering::Relaxed);
        contact.up.store(false, Ordering::Release);
    });
    let mut ready_at = None;
    let mut previous = Value::Null;
    let mut last_sent = initial
        .each_ref()
        .map(|state| state["last_announce_ms"].as_u64().unwrap());
    // Observe the deferred flight after the cut too, without reopening it or
    // counting post-cut repair as short-contact success.
    while open.elapsed() < Duration::from_millis(950) {
        // Query both nodes together; each state() still reads tree before peers.
        let sample = Sample::read(bench.state(0, 2), bench.state(2, 0)).await;
        let before = sample.started.duration_since(open).as_micros() as u64;
        let after = sample.completed.duration_since(open).as_micros() as u64;
        let states = &sample.states;
        for (index, state) in states.iter().enumerate() {
            assert_eq!(
                owner(state),
                owner(&initial[index]),
                "same authenticated bridge owner"
            );
            let sent = state["last_announce_ms"].as_u64().unwrap();
            assert!(
                sent == last_sent[index] || sent >= last_sent[index] + 500,
                "tree send limit must remain 500 ms"
            );
            last_sent[index] = sent;
        }
        let state = json!(states);
        if state != previous {
            let mut trace = trace.lock().unwrap();
            let absolute_us = trace.start.elapsed().as_micros() as u64;
            trace.state(
                json!({"at_us": absolute_us, "contact_query_us": [before, after], "peers": state}),
            );
            previous = state;
        }
        if bench.contact.up.load(Ordering::Acquire) && sample.learned_before(&root, deadline) {
            ready_at.get_or_insert(after);
        }
        sample.wait_next(deadline).await;
    }
    let cut_us = bench.checked_cut_us(400);
    let retained = bench.state(2, 1).await;
    assert_eq!(
        owner(&retained),
        owner(&original),
        "original measured parent retained"
    );
    assert!(bench.contact.dropped.load(Ordering::Relaxed) > 0);
    let mut trace = trace.lock().unwrap();
    let open_us = open.duration_since(trace.start).as_micros() as u64;
    trace.state(json!({"open_us": open_us, "open_ms": open_ms,
        "cut_contact_us": cut_us, "ready_contact_us": ready_at,
        "dropped": bench.contact.dropped.load(Ordering::Relaxed)}));
    ready_at.is_some_and(|ready| ready < cut_us)
}
