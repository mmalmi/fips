//! A queued original becomes routable when its destination becomes our root.
//! Real Noise, MMP, signed declarations and endpoint ingress are manually pumped;
//! only genuine encrypted declarations/filter replies are delayed. No synthetic
//! owner, coordinate, lookup response, clock, or pending-work mark is installed.
use super::*;
use crate::config::{SimTransportConfig, TransportInstances};
use crate::node::tests::sim_discovery::configured_discovering_node;
use crate::node::tests::spanning_tree::{process_dataplane_completions, process_dataplane_packet};
use crate::node::wire::{CommonPrefix, PHASE_ESTABLISHED};
use crate::protocol::{LinkMessageType, TreeAnnounce};
use crate::transport::ReceivedPacket;
use crate::{SimNetwork, register_sim_network, unregister_sim_network};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct DeniedSourceAllowance {
    destination: NodeAddr,
    attempts: AtomicUsize,
}

impl crate::node::OriginatedSessionObserver for DeniedSourceAllowance {
    fn prepare(
        &self,
        intent: &crate::node::OriginatedSessionIntent,
    ) -> crate::node::OriginatedSessionAdmission {
        if intent.destination == self.destination {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            crate::node::OriginatedSessionAdmission::Reject
        } else {
            crate::node::OriginatedSessionAdmission::Defer
        }
    }

    fn observe(&self, request: &crate::node::OriginatedSessionRequest<'_>) -> Option<u64> {
        assert_ne!(
            request.destination, self.destination,
            "denied source must not seal a record"
        );
        None
    }

    fn complete(&self, _: u64, _: crate::node::ForwardingOutcome) {
        panic!("no payment allowance was reserved");
    }
}

mod cancellation {
    //! Handler-level cancellation with a genuine captured declaration and carrier.
    //! The live RX loop is not simulated: the production completion dispatcher owns
    //! the real two-second send timeout. No fixture ingress wrapper is canceled.
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct Selected {
        destination: NodeAddr,
        envelopes: Mutex<Vec<(NodeAddr, Vec<u8>)>>,
    }

    impl crate::node::OriginatedSessionObserver for Selected {
        fn observe(&self, request: &crate::node::OriginatedSessionRequest<'_>) -> Option<u64> {
            if request.destination == self.destination && request.session_payload.len() >= 700 {
                self.envelopes
                    .lock()
                    .unwrap()
                    .push((request.next_hop, request.session_payload.to_vec()));
            }
            None
        }

        fn complete(&self, _: u64, _: crate::node::ForwardingOutcome) {
            panic!("passive evidence has no financial reservation");
        }
    }

    fn matches_selected(
        node: &TestNode,
        source: &NodeAddr,
        observed: &Selected,
        packet: &ReceivedPacket,
    ) -> bool {
        let Some(body) = plaintext(node, source, packet) else {
            return false;
        };
        if body.get(4) != Some(&LinkMessageType::SessionDatagram.to_byte()) {
            return false;
        }
        let datagram = SessionDatagram::decode(&body[5..]).unwrap();
        datagram.src_addr == *source
            && datagram.dest_addr == observed.destination
            && observed
                .envelopes
                .lock()
                .unwrap()
                .first()
                .is_some_and(|(_, envelope)| *envelope == datagram.payload)
    }

    // Temporarily inspect and return the exact objects synchronously. This neither
    // re-enqueues new payloads nor changes their original ages/order/capacity.
    fn ages(node: &mut Node, target: &NodeAddr) -> Vec<u64> {
        let Some(queue) = node.pending_session_traffic.take_endpoint_data(target) else {
            return Vec::new();
        };
        let batches = queue.into_pending_payloads();
        let ages = batches.iter().map(|batch| batch.enqueued_at_ms()).collect();
        node.pending_session_traffic
            .restore_endpoint_data(*target, batches);
        ages
    }

    pub(super) async fn exercise(
        nodes: &mut [TestNode],
        network: &SimNetwork,
        gate: &mut Gate,
        declaration: ReceivedPacket,
        endpoint: &mut EndpointEventReceiver,
        originals: &[Vec<u8>],
    ) {
        let source = *nodes[SOURCE].node.node_addr();
        let middle = *nodes[MIDDLE].node.node_addr();
        let target = *nodes[TARGET].node.node_addr();
        assert_eq!(originals.len(), 16);
        assert_eq!(
            nodes[SOURCE]
                .node
                .config
                .node
                .session
                .pending_packets_per_dest,
            16
        );
        let original_ages = ages(&mut nodes[SOURCE].node, &target);
        assert_eq!(original_ages.len(), 2, "two real endpoint ingress batches");

        // The ciphertext was captured on the installed authenticated carrier. Use
        // its unchanged plaintext in the normal signed TreeAnnounce handler so the
        // subsequent cancellation targets only the root wake dispatch, not a test
        // ingress wrapper that temporarily takes endpoint-channel ownership.
        let body = plaintext(&nodes[SOURCE], &middle, &declaration).unwrap();
        assert_eq!(body[4], LinkMessageType::TreeAnnounce.to_byte());
        nodes[SOURCE]
            .node
            .handle_tree_announce(&middle, &body[5..])
            .await;
        assert_eq!(*nodes[SOURCE].node.tree_state.root(), target);
        assert!(
            nodes[SOURCE]
                .node
                .coord_cache
                .get(&target, Node::now_ms())
                .is_none()
        );
        assert_eq!(nodes[SOURCE].node.pending_root_traffic, Some(target));
        assert_eq!(
            nodes[SOURCE]
                .node
                .pending_session_traffic
                .endpoint_data_for(&target)
                .unwrap()
                .len(),
            16
        );

        let observed = Arc::new(Selected {
            destination: target,
            envelopes: Mutex::new(Vec::new()),
        });
        nodes[SOURCE]
            .node
            .set_originated_session_observer(Some(observed.clone()));
        let source_address = nodes[SOURCE].addr.clone();
        let source_name = source_address.as_str().unwrap().to_string();
        network.set_node_send_completion_delay(&source_name, 60_000);
        let delivered_before = network.stats().packets_delivered;
        let began = tokio::time::Instant::now();
        let mut held = Vec::new();
        {
            let (source_nodes, remaining) = nodes.split_at_mut(1);
            let receiver = &mut remaining[0];
            let dispatch = source_nodes[0]
                .node
                .drain_deferred_dataplane_control_turns();
            let inspect = async {
                loop {
                    while let Ok(packet) = receiver.packet_rx.try_recv() {
                        let selected = packet.remote_addr == source_address
                            && matches_selected(receiver, &source, &observed, &packet);
                        assert!(held.len() < 32, "bounded actual-wire evidence");
                        held.push(packet);
                        if selected {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            };
            // Three seconds is only an outer test watchdog. The production turn's
            // unchanged two-second bound must cancel the 60-second completion wait.
            tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(dispatch, inspect);
            })
            .await
            .expect("production root-wake timeout returns after actual encrypted delivery");
        }
        assert!(
            began.elapsed() >= Duration::from_secs(2),
            "the production timeout, not mere send admission, ended the turn"
        );
        network.set_node_send_completion_delay(&source_name, 0);
        assert!(network.stats().packets_delivered > delivered_before);
        assert_eq!(
            observed.envelopes.lock().unwrap().len(),
            1,
            "only the front one-payload batch was selected"
        );
        assert_eq!(nodes[SOURCE].node.pending_root_traffic, Some(target));
        assert_eq!(
            nodes[SOURCE]
                .node
                .pending_session_traffic
                .endpoint_data_for(&target)
                .unwrap()
                .len(),
            15
        );
        assert_eq!(ages(&mut nodes[SOURCE].node, &target), original_ages[1..]);
        assert!(
            nodes[SOURCE].node.endpoint_data_rx.is_some(),
            "fixture channel ownership survives cancellation"
        );

        // Prove receipt of the selected original separately, with no source pump.
        // Held genuine frames enter ordinary ingress once; unvisited tail still
        // cannot be sent during this evidence phase.
        for packet in held {
            process_dataplane_packet(&mut nodes[MIDDLE], packet).await;
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                process_available_packets(&mut nodes[1..]).await;
                if let Ok(event) = endpoint.try_recv() {
                    endpoint.release_messages(event.messages.len());
                    assert_eq!(
                        expect_single_endpoint_data_event(event).payload.as_slice(),
                        originals[0]
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("selected original actually arrives before wake retry");
        assert_eq!(nodes[SOURCE].node.pending_root_traffic, Some(target));
        assert_eq!(
            nodes[SOURCE]
                .node
                .pending_session_traffic
                .endpoint_data_for(&target)
                .unwrap()
                .len(),
            15
        );
        let mut seen = BTreeSet::from([0usize]);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                // Same normal completion lane as the success case: no direct
                // flush, retry_pending_session_traffic, lookup timer or resubmission.
                drain(nodes, gate).await;
                while let Ok(event) = endpoint.try_recv() {
                    endpoint.release_messages(event.messages.len());
                    for message in event.messages {
                        let id = usize::from(message.payload.as_slice()[0]);
                        assert!(id < originals.len());
                        assert_eq!(message.payload.as_slice(), originals[id]);
                        assert!(
                            seen.insert(id),
                            "a canceled selected original must not replay"
                        );
                    }
                }
                if seen.len() == 16 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("retained root wake dispatches the untouched tail");
        assert_eq!(seen, (0..16).collect());
        assert_eq!(nodes[SOURCE].node.pending_root_traffic, None);
        assert!(
            !nodes[SOURCE]
                .node
                .pending_session_traffic
                .has_traffic_for(&target)
        );
        for _ in 0..3 {
            drain(nodes, gate).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(nodes[SOURCE].node.pending_root_traffic, None);
        assert_eq!(
            observed.envelopes.lock().unwrap().len(),
            16,
            "no selected-batch replay or empty-wake spin"
        );
        assert!(
            observed
                .envelopes
                .lock()
                .unwrap()
                .iter()
                .all(|(next, _)| *next == middle)
        );
        assert!(matches!(
            endpoint.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(
            nodes[SOURCE].node.dataplane.fsp_owner_next_hop(&target),
            Some(middle)
        );
    }
}

const SOURCE: usize = 0;
const MIDDLE: usize = 1;
const TARGET: usize = 2;
const ORIGINAL: &[u8] = b"queued before accepting the current root";

#[test]
fn queued_original_uses_new_current_root_without_redundant_lookup() {
    run(false, false);
}

#[test]
fn current_root_wake_cannot_bypass_denied_source_allowance() {
    run(true, false);
}

#[test]
fn canceled_current_root_wake_keeps_unvisited_originals_and_wake_owner() {
    run(false, true);
}

fn run(deny: bool, cancel: bool) {
    run_large_stack_async_test("queued-current-root", move || async move {
        let name = format!("queued-current-root-{}-{deny}-{cancel}", std::process::id());
        let network = SimNetwork::new(311);
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        let result = AssertUnwindSafe(async {
            for address in ["one", "two", "three"] {
                let mut config = Config::new();
                config.node.system_files_enabled = false;
                config.node.discovery.lan.enabled = false;
                config.node.discovery.nostr.enabled = false;
                config.node.discovery.local.enabled = false;
                config.transports.sim = TransportInstances::Single(SimTransportConfig {
                    network: Some(name.clone()),
                    addr: Some(address.to_string()),
                    auto_connect: Some(false),
                    ..Default::default()
                });
                nodes.push(configured_discovering_node(config, address).await);
            }
            // T is the eventual root; M is the source component's root while
            // T is genuinely disconnected. Identity ordering is not injected.
            nodes.sort_by_key(|node| std::cmp::Reverse(*node.node.node_addr()));
            exercise(&mut nodes, &network, deny, cancel).await;
        })
        .catch_unwind()
        .await;
        for node in &nodes {
            network.set_node_send_completion_delay(node.addr.as_str().unwrap(), 0);
        }
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[derive(Default)]
struct Gate {
    active: bool,
    hold_tree: bool,
    declarations: Vec<ReceivedPacket>,
    other: Vec<ReceivedPacket>,
    selected: Option<usize>,
}

// Read-only inspection of a genuine frame; normal ingress still performs the
// actual authentication/replay checks. Never print key/cipher material.
fn plaintext(receiver: &TestNode, sender: &NodeAddr, packet: &ReceivedPacket) -> Option<Vec<u8>> {
    let wire = packet.data.as_slice();
    if CommonPrefix::parse(wire)?.phase != PHASE_ESTABLISHED {
        return None;
    }
    let header = crate::dataplane::FmpWireHeader::parse_encrypted(wire).unwrap();
    let offset = usize::from(header.ciphertext_offset());
    let cipher = receiver
        .node
        .get_peer(sender)?
        .noise_session()?
        .recv_cipher_clone()?;
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
    let mut encrypted = wire[offset..].to_vec();
    Some(
        cipher
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(&wire[..offset]),
                &mut encrypted,
            )
            .unwrap()
            .to_vec(),
    )
}

async fn drain(nodes: &mut [TestNode], gate: &mut Gate) {
    let middle = *nodes[MIDDLE].node.node_addr();
    let target = *nodes[TARGET].node.node_addr();
    let middle_address = nodes[MIDDLE].addr.clone();
    for (index, node) in nodes.iter_mut().enumerate() {
        while let Ok(packet) = node.packet_rx.try_recv() {
            if gate.active
                && index == SOURCE
                && packet.remote_addr == middle_address
                && let Some(body) = plaintext(node, &middle, &packet)
            {
                let kind = body.get(4).copied();
                if gate.hold_tree && kind == Some(LinkMessageType::TreeAnnounce.to_byte()) {
                    let announce = TreeAnnounce::decode(&body[5..]).unwrap();
                    if *announce.ancestry.root_id() == target {
                        gate.selected = Some(gate.declarations.len());
                    }
                    assert!(gate.declarations.len() < 32, "bounded held declarations");
                    gate.declarations.push(packet);
                    continue;
                }
                if kind == Some(LinkMessageType::FilterAnnounce.to_byte())
                    || kind == Some(LinkMessageType::LookupResponse.to_byte())
                {
                    assert!(gate.other.len() < 32, "bounded held filter/lookup replies");
                    gate.other.push(packet);
                    continue;
                }
            }
            process_dataplane_packet(node, packet).await;
        }
        process_dataplane_completions(&mut node.node).await;
    }
}

async fn turn(nodes: &mut [TestNode], gate: &mut Gate) {
    drain(nodes, gate).await;
    for node in nodes.iter_mut() {
        node.node.check_mmp_reports().await;
        node.node.check_tree_state().await;
        node.node.send_pending_tree_announces().await;
        node.node.check_bloom_state().await;
        node.node.send_due_filter_announces().await;
    }
    drain(nodes, gate).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
}

async fn connect(nodes: &mut [TestNode], from: usize, to: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[to].node.identity().pubkey_full());
    let address = nodes[to].addr.clone();
    let transport = nodes[from].transport_id;
    nodes[from]
        .node
        .initiate_connection(transport, address, identity)
        .await
        .unwrap();
}

fn session_owner(node: &Node, destination: &NodeAddr) -> ([u8; 32], u64, u64) {
    let session = node.get_session(destination).unwrap();
    assert!(session.is_established());
    assert!(node.dataplane_has_fsp_owner(destination));
    (
        *session.handshake_hash().unwrap(),
        session.created_at(),
        session.session_start_ms(),
    )
}

fn source_carrier(nodes: &[TestNode]) -> (LinkId, Option<SessionIndex>, u64) {
    let peer = nodes[SOURCE]
        .node
        .get_peer(nodes[MIDDLE].node.node_addr())
        .unwrap();
    assert!(peer.can_send() && peer.is_healthy());
    (peer.link_id(), peer.our_index(), peer.session_generation())
}

fn resources(nodes: &[TestNode]) -> Vec<(usize, usize, usize)> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let expected = if index == MIDDLE { 2 } else { 1 };
            assert_eq!(node.node.peer_count(), expected);
            assert_eq!(node.node.connection_count(), 0);
            assert_eq!(node.node.link_count(), expected);
            assert_eq!(node.node.index_allocator.count(), expected);
            (
                node.node.peer_count(),
                node.node.link_count(),
                node.node.index_allocator.count(),
            )
        })
        .collect()
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, deny: bool, cancel: bool) {
    let peers = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect::<Vec<_>>();
    let source = *peers[SOURCE].node_addr();
    let middle = *peers[MIDDLE].node_addr();
    let target = *peers[TARGET].node_addr();
    let mut gate = Gate::default();
    for node in nodes.iter() {
        assert_eq!(node.node.config.node.routing.mode, RoutingMode::Tree);
        assert_eq!(node.node.config.node.tree.announce_min_interval_ms, 500);
        assert_eq!(node.node.config.node.bloom.update_debounce_ms, 500);
        assert_eq!(node.node.config.node.discovery.forward_min_interval_secs, 2);
        assert_eq!(
            node.node.config.node.discovery.attempt_timeouts_secs,
            [1, 2, 4, 8]
        );
        assert_eq!(node.node.config.node.session.pending_packets_per_dest, 16);
    }
    connect(nodes, SOURCE, MIDDLE).await;
    connect(nodes, MIDDLE, TARGET).await;
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            turn(nodes, &mut gate).await;
            if nodes.iter().all(|node| {
                *node.node.tree_state.root() == target && node.node.connection_count() == 0
            }) && nodes[SOURCE]
                .node
                .get_peer(&middle)
                .is_some_and(|peer| peer.may_reach(&target))
            {
                break;
            }
        }
    })
    .await
    .expect("real measured initial tree and propagated reachability");
    nodes[SOURCE]
        .node
        .set_endpoint_source_route(peers[TARGET], Some(peers[MIDDLE]))
        .unwrap();
    nodes[TARGET]
        .node
        .set_endpoint_source_route(peers[SOURCE], Some(peers[MIDDLE]))
        .unwrap();
    let source_endpoint = nodes[SOURCE]
        .node
        .attach_endpoint_data_io(if cancel { 16 } else { 8 })
        .unwrap();
    let mut target_endpoint = nodes[TARGET]
        .node
        .attach_endpoint_data_io(if cancel { 16 } else { 8 })
        .unwrap();
    send_endpoint_data_via_dataplane(
        &mut nodes[SOURCE].node,
        peers[TARGET],
        b"warm native FSP".to_vec(),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            turn(nodes, &mut gate).await;
            for node in nodes.iter_mut() {
                node.node.check_discovery_work(Node::now_ms()).await;
            }
            if let Ok(event) = target_endpoint.event_rx.try_recv() {
                target_endpoint
                    .event_rx
                    .release_messages(event.messages.len());
                assert_eq!(
                    expect_single_endpoint_data_event(event).payload.as_slice(),
                    b"warm native FSP"
                );
                break;
            }
        }
    })
    .await
    .expect("real end-to-end session and warm original delivery");
    drain_to_quiescence(nodes).await;
    let sessions = [
        session_owner(&nodes[SOURCE].node, &target),
        session_owner(&nodes[TARGET].node, &source),
    ];
    let carrier = source_carrier(nodes);

    // Both endpoints see a genuine authenticated departure, so no fabricated
    // owner removal or deadline is needed to split the three-node tree.
    let disconnect = crate::protocol::Disconnect::new(crate::protocol::DisconnectReason::Shutdown);
    nodes[MIDDLE]
        .node
        .send_dataplane_fmp_link_plaintext(&target, &disconnect.encode(), false)
        .await
        .unwrap();
    nodes[TARGET]
        .node
        .send_dataplane_fmp_link_plaintext(&middle, &disconnect.encode(), false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            turn(nodes, &mut gate).await;
            if nodes[MIDDLE].node.get_peer(&target).is_none()
                && nodes[TARGET].node.get_peer(&middle).is_none()
                && *nodes[SOURCE].node.tree_state.root() == middle
                && *nodes[MIDDLE].node.tree_state.root() == middle
                && !nodes[SOURCE]
                    .node
                    .get_peer(&middle)
                    .unwrap()
                    .may_reach(&target)
                && nodes[SOURCE]
                    .node
                    .coord_cache
                    .get(&target, Node::now_ms())
                    .is_none()
            {
                break;
            }
        }
    })
    .await
    .expect("real split invalidates coordinates and withdraws target reachability");
    assert_eq!(source_carrier(nodes), carrier);
    assert_eq!(session_owner(&nodes[SOURCE].node, &target), sessions[0]);
    assert_eq!(session_owner(&nodes[TARGET].node, &source), sessions[1]);

    // M learns T first; S cannot adopt T until it receives M's signed update.
    // Stage the real reconnect before offering the original so its ordinary
    // one-second first lookup deadline remains in the future during release.
    gate.active = true;
    gate.hold_tree = true;
    connect(nodes, MIDDLE, TARGET).await;
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            turn(nodes, &mut gate).await;
            if gate.selected.is_some()
                && *nodes[MIDDLE].node.tree_state.root() == target
                && nodes.iter().all(|node| node.node.connection_count() == 0)
            {
                break;
            }
        }
    })
    .await
    .expect("capture real current-root declaration after reciprocal Noise and RTT");
    assert_eq!(*nodes[SOURCE].node.tree_state.root(), middle);
    assert!(
        nodes[SOURCE]
            .node
            .coord_cache
            .get(&target, Node::now_ms())
            .is_none()
    );
    assert!(
        !nodes[SOURCE]
            .node
            .application_route_has_coordinates(&target, middle)
    );
    let bounds = resources(nodes);
    let originals = if cancel {
        (0..16).map(|id| vec![id; 700]).collect::<Vec<_>>()
    } else {
        vec![ORIGINAL.to_vec()]
    };
    // Default queue cap stays 16. A one-payload front batch leaves the second
    // 15-payload batch wholly unvisited when its completion is canceled.
    for payloads in [&originals[..1], &originals[1..]]
        .into_iter()
        .filter(|items| !items.is_empty())
    {
        source_endpoint
            .data_batch_tx
            .send_or_drop(
                crate::node::NodeEndpointDataBatch::from_payloads(
                    peers[TARGET],
                    payloads
                        .iter()
                        .cloned()
                        .map(|payload| {
                            crate::node::EndpointDataPayload::from_packet_payload(payload).unwrap()
                        })
                        .collect(),
                    None,
                )
                .unwrap(),
            )
            .unwrap();
    }
    process_available_packets(&mut nodes[..1]).await;
    assert_eq!(
        nodes[SOURCE]
            .node
            .pending_session_traffic
            .endpoint_data_for(&target)
            .map(|queue| queue.len()),
        Some(originals.len()),
        "the originals really queue before S accepts the new root"
    );
    assert!(matches!(
        target_endpoint.event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let lookup = nodes[SOURCE].node.pending_lookups.get(&target).unwrap();
    let lookup_clock = (lookup.initiated_ms, lookup.last_sent_ms, lookup.attempt);
    let lookup_due = lookup.deadline_ms(
        &nodes[SOURCE]
            .node
            .config
            .node
            .discovery
            .attempt_timeouts_secs,
    );
    // A pre-existing recovery request may already have selected a wire peer;
    // holding the new filter is not evidence about its earlier request history.
    // Root adoption must neither originate another request nor renew this clock.
    assert!(
        Node::now_ms() < lookup_due,
        "the current lookup attempt is still live before release"
    );
    let initiated = nodes[SOURCE].node.stats().discovery.req_initiated;
    let responses = nodes[SOURCE].node.stats().discovery.resp_accepted;

    // Install a legitimate admission rejection only after native FSP warmup
    // and the original's queue admission. It neither alters route eligibility
    // nor manufactures financial records or traffic to rescue the payload.
    let allowance = Arc::new(DeniedSourceAllowance {
        destination: target,
        attempts: AtomicUsize::new(0),
    });
    if deny {
        nodes[SOURCE]
            .node
            .set_originated_session_observer(Some(allowance.clone()));
    }
    let selected = gate.selected.take().unwrap();
    let declaration = gate.declarations.remove(selected);
    gate.hold_tree = false;
    if cancel {
        cancellation::exercise(
            nodes,
            network,
            &mut gate,
            declaration,
            &mut target_endpoint.event_rx,
            &originals,
        )
        .await;
        assert_eq!(
            nodes[SOURCE].node.stats().discovery.req_initiated,
            initiated
        );
        assert_eq!(
            nodes[SOURCE].node.stats().discovery.resp_accepted,
            responses
        );
        if let Some(pending) = nodes[SOURCE].node.pending_lookups.get(&target) {
            assert_eq!(
                (pending.initiated_ms, pending.last_sent_ms, pending.attempt),
                lookup_clock,
                "the two-second canceled send cannot renew the original lookup clock"
            );
        }
        assert_eq!(source_carrier(nodes), carrier);
        assert_eq!(resources(nodes), bounds);
        assert_eq!(session_owner(&nodes[SOURCE].node, &target), sessions[0]);
        assert_eq!(session_owner(&nodes[TARGET].node, &source), sessions[1]);
        assert_eq!(nodes[SOURCE].node.source_routes.get(&target), Some(&middle));
        return;
    }
    let released = tokio::time::Instant::now();
    process_dataplane_packet(&mut nodes[SOURCE], declaration).await;
    while *nodes[SOURCE].node.tree_state.root() != target {
        drain(nodes, &mut gate).await;
        assert!(
            released.elapsed() < Duration::from_millis(750),
            "normal encrypted ingress must accept the captured declaration"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        nodes[SOURCE]
            .node
            .coord_cache
            .get(&target, Node::now_ms())
            .is_none(),
        "the proof must not come from a lookup or copied cache entry"
    );
    assert!(
        nodes[SOURCE]
            .node
            .application_route_has_coordinates(&target, middle),
        "the accepted current root supplies its own local routing coordinate"
    );

    // Only ordinary packet/control/completion processing: no manual pending
    // retry, session flush, lookup tick, new payload, or fabricated wake-up.
    let mut received = 0;
    while received == 0 && released.elapsed() < Duration::from_millis(750) {
        drain(nodes, &mut gate).await;
        while let Ok(event) = target_endpoint.event_rx.try_recv() {
            target_endpoint
                .event_rx
                .release_messages(event.messages.len());
            for message in event.messages {
                assert_eq!(message.payload.as_slice(), ORIGINAL);
                received += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        received,
        usize::from(!deny),
        "root routing wakes admitted traffic without bypassing source allowance"
    );
    let rejected = allowance.attempts.load(Ordering::Relaxed);
    if deny {
        assert!(
            rejected > 0,
            "actual root wake must reach ordinary source admission"
        );
    }
    assert!(
        Node::now_ms() < lookup_due,
        "lookup timer did not rescue the original"
    );
    for _ in 0..3 {
        drain(nodes, &mut gate).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if deny {
        assert_eq!(
            allowance.attempts.load(Ordering::Relaxed),
            rejected,
            "ordinary completion drains must not spin on a rejected source allowance"
        );
    }
    assert!(
        matches!(
            target_endpoint.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "no duplicate original"
    );
    assert_eq!(
        nodes[SOURCE].node.stats().discovery.req_initiated,
        initiated
    );
    assert_eq!(
        nodes[SOURCE].node.stats().discovery.resp_accepted,
        responses
    );
    if let Some(pending) = nodes[SOURCE].node.pending_lookups.get(&target) {
        assert_eq!(
            (pending.initiated_ms, pending.last_sent_ms, pending.attempt),
            lookup_clock,
            "root adoption cannot renew the lookup ladder"
        );
    }
    assert!(
        !nodes[SOURCE]
            .node
            .pending_session_traffic
            .has_traffic_for(&target)
    );
    assert_eq!(nodes[SOURCE].node.source_routes.get(&target), Some(&middle));
    assert_eq!(
        nodes[SOURCE].node.dataplane.fsp_owner_next_hop(&target),
        Some(middle)
    );
    assert_eq!(source_carrier(nodes), carrier);
    assert_eq!(resources(nodes), bounds);
    assert_eq!(session_owner(&nodes[SOURCE].node, &target), sessions[0]);
    assert_eq!(session_owner(&nodes[TARGET].node, &source), sessions[1]);
}
